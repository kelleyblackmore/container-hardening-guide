# 4. Container Deployment — All 11 Requirements

> DISA Container Image Creation and Deployment Guide V2R0.6, §3
> — full text: [`reference/`](../reference/DISA-Container-Image-Creation-and-Deployment-Guide-V2R0.6.md#3-container-deployment)

> While much of the container's security is built into the container image,
> there are security practices and settings that should be considered to protect
> the hosting system and the container platform from the container itself.

Reference implementation: [`k8s/deployment.yaml`](../k8s/deployment.yaml) and
[`k8s/networkpolicy.yaml`](../k8s/networkpolicy.yaml). Blocking checks:
[`scripts/check-k8s-policy.py`](../scripts/check-k8s-policy.py).

**The framing that matters:** section 2 protects the workload. Section 3 protects
the *node and the platform from the workload*. A perfectly hardened image
deployed with `privileged: true` is not secure, and nothing you do in a
Dockerfile can fix that.

---

## The backstop: Pod Security Admission

Before the individual requirements — most of section 3 is enforced in one place
if you set it up. Three labels on the namespace:

```yaml
metadata:
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

The `restricted` profile makes the API server **reject** pods that run as root,
use host namespaces, allow privilege escalation, request added capabilities,
skip seccomp, or run privileged. That is §2.2, §2.3, §2.12, §3.2, and §3.10
enforced at admission, for every pod in the namespace, including ones nobody
put in a repository.

What it does *not* cover, and you still have to specify per workload: resource
limits and requests (§3.5, §3.6), probes (§3.8, §3.9), read-only root filesystem
(§3.7 — `restricted` does not require it), PID limits (§3.3), and labels (§3.11).

`enforce` blocks. `audit` records to the audit log. `warn` prints in the user's
`kubectl` output. Set all three: warnings are what stop a developer being
surprised at deploy time.

---

## 3.1 — Must not mount the platform's registry endpoint

**SC-4 / CCI-001090**

> If a container can mount the socket, it can execute registry commands such as
> running images, deleting images, or pulling nefarious images into the registry.

Mounting `/var/run/docker.sock` is the classic container escape: the socket is
an unauthenticated root API to the daemon, and one API call starts a privileged
container with the host filesystem mounted. `containerd.sock` and `crio.sock`
are the same problem.

The Kubernetes analogue is the ServiceAccount token, auto-mounted at
`/var/run/secrets/kubernetes.io/serviceaccount`. It is a live API credential. If
the pod does not talk to the API, it should not have one.

**Implement**
```yaml
automountServiceAccountToken: false      # on the ServiceAccount and the pod spec
# and: no hostPath volume ending in .sock, anywhere, ever
```

**Verify**
```bash
python3 scripts/check-k8s-policy.py k8s/
kubectl get pods -A -o json | jq -r '
  .items[] | select(.spec.volumes[]?.hostPath.path? // "" | endswith(".sock"))
  | "\(.metadata.namespace)/\(.metadata.name)"'
```

---

## 3.2 — Must be limited in available system calls

**SC-4 / CCI-001090**

> The default SECCOMP profile provides a default security posture for running
> containers while providing wide application compatibility.

seccomp filters which syscalls the process may make. The runtime's default
profile blocks roughly 50 rarely used and historically dangerous ones —
`keyctl`, `add_key`, `userfaultfd`, `bpf`, `ptrace` against other processes,
`mount`, `kexec_load` — while keeping broad compatibility.

**Kubernetes does not apply it unless you ask.** Before the `seccompProfile`
field existed, pods ran `Unconfined` by default. Say it explicitly:

```yaml
securityContext:
  seccompProfile:
    type: RuntimeDefault
```

**Going further**: a `Localhost` profile is an allow-list of exactly the calls
your app makes. Build one by recording with `strace -f -c` or
`oci-seccomp-bpf-hook`, then allow-list. This is real work and it breaks on
every dependency upgrade — do it for a high-value, low-churn workload, not by
default. `RuntimeDefault` everywhere beats a perfect profile on one service.

**Verify**
```bash
kubectl get pod POD -o jsonpath='{.spec.securityContext.seccompProfile.type}'
# inside the container: Seccomp: 2 means filtered, 0 means disabled
grep Seccomp /proc/1/status
```

---

## 3.3 — Enable PIDs cgroups to limit resource usage

**SC-4 / CCI-001090**

A fork bomb in one container exhausts the node's process table and takes down
every other pod on it. The PID cgroup controller caps how many processes a
container may create.

**In Kubernetes this is a kubelet setting, not a pod field.** That surprises
people looking for a `spec.pidsLimit`:

```yaml
# kubelet configuration on each node
podPidsLimit: 1024
supportPodPidsLimit: true
```

With plain Docker: `docker run --pids-limit=100`.

The pod-side mitigation is a `ResourceQuota` capping pod count and memory, which
bounds the blast radius without capping PIDs directly. Both are in
[`k8s/deployment.yaml`](../k8s/deployment.yaml).

**Verify**
```bash
kubectl get --raw /api/v1/nodes/NODE/proxy/configz | jq '.kubeletconfig.podPidsLimit'
cat /sys/fs/cgroup/pids/pids.max        # inside the container
```

---

## 3.4 — Sensitive host directories must not be mounted

**SC-4 / CCI-001090**

> Examples on a Linux server of sensitive directories are /etc and /usr.

A `hostPath` mount punches through the mount namespace. `/etc` gives you the
node's `shadow` file and its kubelet credentials. `/` gives you the node.
`/var/lib/kubelet` gives you every secret mounted into every pod on that node.

**Implement** — no `hostPath` in the manifest at all. If you genuinely need node
storage, use a CSI driver or a `local` PersistentVolume with a defined scope,
and get the exception reviewed.

**Enforce** — Pod Security Admission `restricted` forbids `hostPath` outright.
A Kyverno or Gatekeeper policy can allow a reviewed allow-list.

**Verify**
```bash
python3 scripts/check-k8s-policy.py k8s/
kubectl get pods -A -o json | jq -r '
  .items[] | select(.spec.volumes[]?.hostPath) |
  "\(.metadata.namespace)/\(.metadata.name): \([.spec.volumes[]?.hostPath.path])"'
```

---

## 3.5 — Resource limits

**SC-5 (1) / CCI-001094**

> Without this limit, a container can use all available resources, starving
> other containers of needed resources, causing a Denial of Service (DoS)

```yaml
resources:
  limits:
    cpu: 500m
    memory: 128Mi
    ephemeral-storage: 256Mi
```

**The asymmetry matters.** Exceeding a *memory* limit gets the process
OOM-killed immediately. Exceeding a *CPU* limit only throttles — the kernel
gives you fewer slices. Some teams deliberately omit the CPU limit on
latency-sensitive services to avoid throttling and rely on requests plus a
namespace quota. That is a defensible engineering position and a documented
deviation from §3.5. Decide it consciously and write it down.

Do not forget `ephemeral-storage`: a container logging to its writable layer can
fill the node's disk and evict every pod on it.

---

## 3.6 — Resource requests

**SC-5 (2) / CCI-001095**

> Setting a container resource request limit allows the container platform to
> determine the best location for the container to execute.

Requests are what the scheduler reserves. They also set the pod's QoS class:

| Class | Condition | Eviction order |
|---|---|---|
| `Guaranteed` | limits == requests, for every resource | last |
| `Burstable` | requests set, limits higher or absent | middle |
| `BestEffort` | nothing set | **first** |

A pod with no requests is `BestEffort` and is the first thing killed under node
memory pressure. "No resources specified" is not neutral — it is the worst
setting.

**Make it enforceable** with a `LimitRange`, which rejects a pod submitted with
no resources block and applies defaults where they are missing. Without one,
"we set resource limits" is a code-review convention that fails the first time
somebody is in a hurry.

---

## 3.7 — Read-only root filesystem

**CM-5 (1) / CCI-001813**

> Any attempts to change the root filesystem are usually malicious in nature and
> can be prevented by making the root filesystem read-only.

```yaml
securityContext:
  readOnlyRootFilesystem: true
volumeMounts:
  - { name: tmp, mountPath: /tmp }
volumes:
  - name: tmp
    emptyDir: { medium: Memory, sizeLimit: 32Mi }
```

Grant writable paths explicitly, as `emptyDir` volumes. `medium: Memory` makes
them tmpfs, so the contents never touch node disk and vanish with the pod.
Always set `sizeLimit` — an unbounded memory-backed `emptyDir` counts against
node memory and can evict the node's other pods.

**When it breaks**, it breaks loudly and early, which is the point. Common
culprits: a language runtime writing to `/tmp` (mount it), a webserver wanting
`/var/run` for a PID file (mount it), and an app writing config on startup
(fix the app — that is exactly the mutable behaviour the control exists to stop).

**Verify** the image can actually run this way, in CI, before it reaches a
cluster:
```bash
docker run --read-only --tmpfs /tmp --cap-drop=ALL \
  --security-opt=no-new-privileges --user 1001:1001 IMG
```
That is `make verify`, and it is a step in [`ci.yml`](../.github/workflows/ci.yml).

---

## 3.8 — Liveness probe

**SC-5 / CCI-002385**

> A liveness probe checks for instances in which a container has run into a
> deadlock state. The container will appear as healthy from the process health
> check's point of view but will not be in a usable state.

```yaml
livenessProbe:
  httpGet: { path: /healthz, port: http }
  initialDelaySeconds: 5
  periodSeconds: 15
  failureThreshold: 3
```

**Failing liveness restarts the container.** So keep the probe cheap and
dependency-free. A liveness probe that checks the database means a database blip
restarts every replica you have simultaneously, turning a degradation into an
outage. Check *this process*, nothing downstream.

Use a `startupProbe` for slow-booting apps rather than a long
`initialDelaySeconds` — a long initial delay applies for the pod's whole
lifetime and delays detection of a genuine hang forever.

---

## 3.9 — Readiness probe

**SC-5 / CCI-002385**

> restarting does not always make the container healthy... The readiness probe
> can also be used to monitor if a container is overloaded, latency has
> increased, and the container needs to be shielded from additional workloads.

**Failing readiness removes the pod from the Service endpoints without killing
it.** Different action, different question:

| | Liveness | Readiness |
|---|---|---|
| Question | is this process wedged? | should it get traffic now? |
| Failure action | restart the container | remove from load balancing |
| Should it check dependencies? | **no** | yes, carefully |
| During startup | use a startupProbe | fail until warm |
| During shutdown | n/a | fail first, then drain |

This is the probe that may legitimately check a downstream dependency — a pod
that cannot reach its database should stop receiving requests without being
restarted in a loop.

---

## 3.10 — No access to OS kernel namespaces

**SC-4 / CCI-001090**

> When kernel namespaces are shared to containers, data can be shared directly
> between services bypassing security measures, allowing containers to elevate
> their privileges.

```yaml
hostPID: false
hostIPC: false
hostNetwork: false
```

What each one costs you if enabled:

| Field | Consequence |
|---|---|
| `hostPID` | see and signal every process on the node; read `/proc/<pid>/environ` of other workloads — including their secrets |
| `hostIPC` | read other workloads' shared memory segments |
| `hostNetwork` | the node's network stack: bypasses all NetworkPolicy, reaches node-local services (kubelet on 10250, cloud metadata on 169.254.169.254) |

They default to `false`. State them anyway, so a future edit that enables one is
a visible diff and not a silent addition.

The guide also names the **user** namespace. Kubernetes user namespace support
(`hostUsers: false`) maps container UIDs to unprivileged node UIDs, which
contains the damage when a workload does need root inside the container. Check
your cluster version and runtime before relying on it.

---

## 3.11 — Label selectors define execution location and type

**SC-39 / CCI-002530**

> Examples of labels include the type of service, such as management versus
> customer, or the type of data on which the container operates, such as HR
> versus Sales... Labeling the containers aids in the location of execution,
> reducing any data spillage or inadvertent resource sharing.

Labels are the identity everything else selects on: `NetworkPolicy`, quota,
admission policy, scheduling, and — in a multi-level environment — keeping
workloads of different classifications off the same node.

```yaml
labels:
  app.kubernetes.io/name: helloctr
  app.kubernetes.io/component: api
  data-classification: unclassified
  tier: application
```

Paired with placement:
```yaml
nodeSelector: { kubernetes.io/os: linux }
topologySpreadConstraints: [...]        # survive a node failure
# and, for real separation:
# tolerations + taints on nodes approved for a given classification
```

Note that `NetworkPolicy` selects on **labels, not IPs** — pod IPs are
ephemeral, labels are the stable identity. This is what makes §3.11 load-bearing
rather than decorative.

---

## Coverage summary

| § | Requirement | Where |
|---|---|---|
| 3.1 | No registry/socket endpoint mounted | `automountServiceAccountToken: false`, no `.sock` hostPath |
| 3.2 | Limited system calls | `seccompProfile: RuntimeDefault` |
| 3.3 | PID cgroup limits | kubelet `podPidsLimit` + `ResourceQuota` |
| 3.4 | No sensitive host mounts | no `hostPath`; PSA `restricted` |
| 3.5 | Resource limits | `resources.limits` + `LimitRange` |
| 3.6 | Resource requests | `resources.requests` + `LimitRange` |
| 3.7 | Read-only root filesystem | `readOnlyRootFilesystem: true` + tmpfs mounts |
| 3.8 | Liveness probe | `livenessProbe` (+ `startupProbe`) |
| 3.9 | Readiness probe | `readinessProbe` |
| 3.10 | No host namespaces | `hostPID/hostIPC/hostNetwork: false` |
| 3.11 | Label selectors | labels + `nodeSelector` + `NetworkPolicy` |

---

**Next:** [5. OpenSCAP and Tailoring Files](05-openscap-and-tailoring.md)
