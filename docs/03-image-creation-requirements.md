# 3. Container Image Creation — All 18 Requirements

> DISA Container Image Creation and Deployment Guide V2R0.6, §2

Each requirement below gives the IA control and CCI from the guide, what it
means, how it is implemented in this repository, and the command that proves it.

The guide's own framing (§2) is worth keeping in mind:

> It is important to note that this document signifies best practices for
> container creation and deployment, it is no replacement for a STIG or SRG.
> Furthermore, waivers may be required from the organization's security team in
> some cases where the requirement cannot be followed completely.

---

## 2.1 — SSH server daemon disabled

**CM-7 a / CCI-000381**

A container is a process, not a host. When packages, patches, or configuration
change, you build a new image. Logs go to stdout and are collected externally;
data lives on persistent volumes that are backed up outside the container. An
`sshd` inside an image is a second, unmonitored, unauthenticated-by-your-IdP way
in, and it exists to enable exactly the workflow (mutating a running container)
that the immutability model forbids.

**Implement** — [`harden/60-remove-attack-surface.sh`](../examples/hardened/harden/60-remove-attack-surface.sh)
removes the package if present and then *asserts* its absence, failing the build
if `sshd` exists.

**Verify**
```bash
docker run --rm --entrypoint /bin/bash IMG -c \
  'test ! -e /usr/sbin/sshd && ! rpm -q openssh-server && echo ok'
```

**Instead of SSH:** `kubectl exec` / `docker exec` for interactive inspection,
`kubectl debug` with an ephemeral container for images with no shell, and a log
pipeline for everything routine.

---

## 2.2 — Execute as a non-privileged user

**AC-6 (10) / CCI-002235**

Root in a container is root on the node the moment anything else goes wrong: a
`hostPath` mount, a shared namespace, a kernel escape, a misconfigured runtime.
Running unprivileged removes the first link in most of those chains.

**Implement** — a system account with a **fixed numeric UID**, `USER 1001:1001`
as the last instruction before the entrypoint. Numeric because Kubernetes'
`runAsNonRoot` admission check inspects the numeric UID.

```dockerfile
RUN groupadd --system --gid 1001 appuser \
 && useradd  --system --uid 1001 --gid 1001 --no-create-home --shell /sbin/nologin appuser
USER 1001:1001
```

**Verify**
```bash
docker inspect --format '{{.Config.User}}' IMG          # must be non-empty, non-zero
docker run --rm IMG id                                   # uid=1001
```

**Also enforce at deploy time** (§3): `runAsNonRoot: true`, `runAsUser: 1001`.
An image's `USER` can be overridden at run time; admission cannot.

**When the image is not yours:** if a vendor image insists on root, the guide
points at user namespace remapping to map the container's root to an
unprivileged host UID. That is a mitigation, not a fix — and it is the kind of
exception that needs a waiver.

---

## 2.3 — Remove setuid/setgid permissions from executables

**AC-6 (10) / CCI-002235**

Privilege escalation inside the container. `su`, `mount`, `chsh`, `pkexec`,
`newgrp`, `passwd` — every one is a documented path from "I have code execution
as the app user" to "I am root in this namespace".

**Implement**
```dockerfile
RUN find / -xdev -perm /6000 -type f -exec chmod ug-s {} + \
 && test -z "$(find / -xdev -perm /6000 -type f)"
```

**Verify**
```bash
docker run --rm --entrypoint /bin/bash IMG -c 'find / -xdev -perm /6000 -type f'
# must print nothing
```

**Pair with** `allowPrivilegeEscalation: false` at deploy time, which sets the
kernel's `no_new_privs` flag and blocks the transition even if a setuid binary
comes back.

---

## 2.4 — Build using commands with known outcomes

**CM-7 a / CCI-000381**

The guide singles out `ADD` versus `COPY`:

> The ADD instruction command can be used to put files into a container image and
> could potentially retrieve files from remote Uniform Resource Locators (URLs)
> to perform operations such as unpacking. By performing operations or tasks
> outside the simple task of copying a file, the ADD instruction introduces risks

and states the goal plainly:

> It is always good practice to ensure containers can be built without connection
> to the internet.

| Do | Do not |
|---|---|
| `COPY app/ /app/` | `ADD https://.../x.tar.gz /app/` |
| `COPY --from=build /out/app /app/app` | `RUN curl … \| bash` |
| vendored or proxy-served dependencies | `RUN git clone https://…` |
| `set -eux` in every `RUN` | relying on the default `sh -c` exit semantics |
| `SHELL ["/bin/bash","-o","pipefail","-c"]` | pipelines whose failures are swallowed |

`pipefail` matters more than it looks: under plain `sh -c`, `false | true`
succeeds, so a failing verification step on the left of a pipe silently passes
the build.

**Verify** — hadolint enforces the `ADD`/`COPY` rule (DL3020) and the pipefail
rule (DL4006):
```bash
make lint
```

---

## 2.5 — Expose only non-privileged ports

**CM-7 (1) (b) / CCI-001762**

Binding below 1024 requires root or `CAP_NET_BIND_SERVICE`. Wanting port 80 is
how images end up running as root. The guide's answer is to map at the platform:

> use the container platform to map the privileged port to the unprivileged port
> within the container, e.g., map port 80 to port 8080 within the container.

**Implement** — `EXPOSE 8080/tcp` in the image; in the `Service`,
`port: 80` → `targetPort: 8080`.

**Verify**
```bash
docker inspect --format '{{range $p,$_ := .Config.ExposedPorts}}{{$p}} {{end}}' IMG
```
CI asserts every exposed port is ≥ 1024.

---

## 2.6 — Build with a process health check

**SC-5 / CCI-002385**

> Short lived containers that do not require a health check can be submitted for
> a waiver.

**Implement**
```dockerfile
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/app/helloctr", "-healthcheck"]
```

Use the application's own probe flag. A `curl`-based check means shipping a
fetch tool for the attacker's benefit in order to test a port you already own.

**Verify**
```bash
docker inspect --format '{{.Config.Healthcheck.Test}}' IMG
docker inspect --format '{{.State.Health.Status}}' <running-container>
```

**Kubernetes ignores `HEALTHCHECK`.** Requirements §3.8 and §3.9 (liveness and
readiness probes) are the orchestrator-side equivalents, and they are separate
requirements, not substitutes.

---

## 2.7 — TLS 1.2 or higher for registry pulls

**SC-8 / CCI-002418**

Protect the image in transit. Registry traffic must be TLS 1.2+ (NIST SP
800-52r2).

**Implement / verify**
```bash
# never set insecure-registries in /etc/docker/daemon.json
openssl s_client -connect registry.example.mil:443 -tls1_2 </dev/null | head -20
```
Confirm no `--tls-verify=false`, no `insecure-registries`, no
`DOCKER_TLS_VERIFY=0` anywhere in your build tooling or CI configuration.

---

## 2.8 — Minimal cached layers

**SI-2 (6) / CCI-002617**

The subtle one. The guide:

> By using cached layers, the builder could potentially deny fresh updates to be
> included in later container image builds.

Two distinct problems:

1. **Cleanup in the wrong layer.** `RUN install` then `RUN clean` leaves the
   cache in the first layer. It still ships. Chain them into one `RUN`.
2. **Staleness.** A cached `dnf upgrade` layer is not invalidated by a CVE being
   published, so your "rebuild" reuses last month's packages.

**Implement**
```dockerfile
RUN dnf -y --refresh upgrade --security && dnf -y clean all && rm -rf /var/cache/dnf
```
```bash
docker build --no-cache --pull -t IMG .      # make rebuild — on a schedule
```

**Verify**
```bash
docker history IMG                                    # per-layer size and command
docker run --rm --entrypoint /bin/bash IMG -c 'du -sh /var/cache/dnf 2>/dev/null'
```

Note the tension with §2.4: fewer, denser layers help here but make each layer
harder to reason about. Optimise for *no cached package state and no orphaned
cleanup*, not for the lowest possible layer count.

---

## 2.9 — No confidential data in the build files

**CM-6 b / CCI-000366**

> Even if the data is deleted later, it can be retrieved from the container image
> history.

Both `docker history --no-trunc` and the layer tarballs give it back. See
[docs/01 §1.3](01-anatomy-of-a-container-image.md) for the mechanism.

**Implement**
- `ENV` holds a *path* to a secret, never a secret.
- Build-time secrets use BuildKit mounts, which never touch a layer:
  ```dockerfile
  RUN --mount=type=secret,id=token TOKEN="$(cat /run/secrets/token)" ./fetch.sh
  ```
- A `.dockerignore` that excludes `.git`, `.env`, `*.pem`, `.aws/`, `*.tfstate`.
- Copy named files rather than `COPY . .`.

**Verify**
```bash
docker history --no-trunc IMG | grep -Ei 'password|secret|token|api[_-]?key'
make scan-secrets        # TruffleHog over history, tree, and image layers
```

---

## 2.10 — Create from signed base images

**CM-5 (3) / CCI-001749**

**Implement / verify**
```bash
cosign verify <image> \
  --certificate-identity-regexp '.*' --certificate-oidc-issuer-regexp '.*'
skopeo inspect docker://<image> | jq '.Digest'
podman pull --signature-policy /etc/containers/policy.json <image>
```
Enforce it at admission with a policy engine (Sigstore policy-controller,
Kyverno `verifyImages`, Connaisseur) so an unsigned image cannot be deployed
even if it gets built.

---

## 2.11 — Create with verified packages

**CM-5 (3) / CCI-001749**

**Implement** — keep `gpgcheck=1` (the UBI default), never
`--nogpgcheck`/`--allow-unauthenticated`, and assert it:

```dockerfile
RUN unsigned="$(rpm -qa --qf '%{NAME} %{SIGPGP:pgpsig}%{SIGGPG:pgpsig}\n' \
                | grep -v '^gpg-pubkey ' | grep -v 'Key ID' | awk '{print $1}')"; \
    [ -z "$unsigned" ] || { echo "unsigned: $unsigned"; exit 1; }
```

Equivalents: `apt-get` with signed repos and no `--allow-unauthenticated`; `npm
ci` against a lockfile with integrity hashes; `pip install --require-hashes`;
`go.sum` plus `GOFLAGS=-mod=readonly`.

---

## 2.12 — Only essential capabilities

**CM-7 a / CCI-000381**

> When container images become bloated with unnecessary software, the attack
> surface grows along with the need for subsequent security patch maintenance.
> This also negates the concept of containers being microservices.

Two readings, both correct, and you want both:

- **Software**: multi-stage builds, `install_weak_deps=0`, remove
  compilers/fetchers/network daemons.
- **Linux capabilities**: `capabilities.drop: [ALL]` at deploy time, adding back
  only what you can name and justify.

**Verify**
```bash
docker run --rm --entrypoint /bin/bash IMG -c 'rpm -qa | wc -l'
docker run --rm --entrypoint /bin/bash IMG -c 'command -v gcc curl wget nc git'
grep -A3 'capabilities' k8s/deployment.yaml
```

---

## 2.13 — Only the ports the service uses

**CM-7 (1) (b) / CCI-001762**

Exposing spare ports advertises services and versions to anyone who can scan the
pod network. One service per image, one port.

**Verify** — the exposed-ports check above, plus
[`k8s/networkpolicy.yaml`](../k8s/networkpolicy.yaml), which default-denies and
then permits exactly one port from exactly one labelled source.

---

## 2.14 — Build from a DoD-approved base image

**SC-8 (2) / CCI-002422**

> the hash of the container base image must be compared against the known hash
> from the trusted source.

**Implement** — pin by digest, not tag:
```dockerfile
FROM registry1.dso.mil/ironbank/redhat/ubi/ubi9@sha256:<digest>
```
```bash
make digests        # print the current digests for the bases used here
```
`.hadolint.yaml` sets `allowed-registries`, so a `FROM` outside the approved set
fails the lint (DL3026).

Approved sources and their priority: [docs/11](11-approved-sources.md).

---

## 2.15 — Remove images no longer in use

**SI-2 (6) / CCI-002617**

> tags can be manipulated to force a container image with known vulnerabilities
> to be used when a more secure image is available.

**Implement**
- Deploy by digest, not tag.
- Registry retention/GC policies that delete superseded tags (Harbor retention
  rules, Quay auto-prune, ECR lifecycle policies).
- Revoke and delete images with critical findings rather than leaving them
  pullable.

**Verify**
```bash
crane ls registry.example.mil/team/app
skopeo list-tags docker://registry.example.mil/team/app
```

---

## 2.16 — Implement any relevant STIG or SRG guidance

**CM-6 b / CCI-000366**

> In cases where a traditional STIG may not entirely apply for a scan of a
> container, or a container may need to run as root as an exception, a waiver
> will need to be approved.

This is the requirement that pulls in OpenSCAP. For a RHEL-family image, that is
the RHEL 9 STIG, minus the rules that are genuinely Not Applicable to a
container — recorded, with justifications, in
[`oscap/not-applicable.rules`](../oscap/not-applicable.rules) and rendered into a
tailoring file.

Applying an OS STIG does not discharge the *application* STIG or SRG. A web
server in a container still owes you the Web Server SRG; a database still owes
you the Database SRG.

**Implement / verify**
```bash
make stig      # baseline and tailored scans, ARF + HTML reports
```
Full walkthrough: [docs/05](05-openscap-and-tailoring.md) and
[docs/10](10-stig-a-container-walkthrough.md).

---

## 2.17 — Create from a trusted and approved source

**IA-5 (2) (a) / CCI-000185**

> Trusted sources must use valid registry certificates to sign their hosted
> images. Consumers of these images must verify the authenticity of signed
> container images when downloaded from the trusted source.

Note this is *verify*, not *hope*. Pulling from a trusted registry without
checking the signature satisfies the first half only.

**Verify** — `allowed-registries` in `.hadolint.yaml`, plus signature
verification at admission. See [docs/11](11-approved-sources.md).

---

## 2.18 — Clear of embedded credentials

**IA-5 (7) / CCI-002367**

> The credentials must be kept externally, fetched by the application, and not
> stored in the container image.

Distinct from §2.9: that one is about the *build files*, this one is about the
*image*. A credential can arrive without ever appearing in a Dockerfile — baked
into a config file you copied, left in a `.git` directory, or embedded in a
vendored dependency.

**Implement** — the application reads its secret from a file path supplied at
run time; the file comes from a mounted Kubernetes `Secret`, Vault, or an
External Secrets operator. Not from `ENV` (leaks via `/proc/<pid>/environ`,
crash dumps, and any logger that prints the environment on start-up).

**Verify**
```bash
make scan-secrets       # TruffleHog: git history, working tree, image layers
```
Details, and what to do when it finds one: [docs/07](07-trufflehog.md).

---

## Coverage summary

| § | Requirement | Enforced by |
|---|---|---|
| 2.1 | No SSH daemon | build assertion + CI |
| 2.2 | Non-privileged user | `USER 1001` + CI + `runAsNonRoot` |
| 2.3 | No setuid/setgid | build assertion + CI + `allowPrivilegeEscalation:false` |
| 2.4 | Known-outcome commands | hadolint DL3020/DL4006 |
| 2.5 | Non-privileged ports | CI port assertion |
| 2.6 | Health check | CI healthcheck assertion |
| 2.7 | TLS 1.2+ pulls | registry/daemon configuration |
| 2.8 | Minimal cached layers | single-`RUN` cleanup, `--no-cache` rebuilds |
| 2.9 | No secrets in build files | `.dockerignore`, BuildKit secrets, TruffleHog |
| 2.10 | Signed base images | cosign / skopeo + admission policy |
| 2.11 | Verified packages | `gpgcheck=1` + build assertion |
| 2.12 | Essential capabilities only | multi-stage, package removal, `drop: [ALL]` |
| 2.13 | Only required ports | CI port assertion + NetworkPolicy |
| 2.14 | Approved base image | digest pinning + `allowed-registries` |
| 2.15 | Remove superseded images | registry retention + deploy by digest |
| 2.16 | Apply STIG/SRG guidance | OpenSCAP + harden scripts |
| 2.17 | Trusted source | `allowed-registries` + signature verification |
| 2.18 | No embedded credentials | TruffleHog + external secret mounts |

Machine-readable version: [docs/compliance-matrix.md](compliance-matrix.md).

---

**Next:** [4. Deployment Requirements](04-deployment-requirements.md)
