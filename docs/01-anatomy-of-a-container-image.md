# 1. Anatomy of a Container Image

> DISA Container Image Creation and Deployment Guide V2R0.6, §1.2
> — full text: [`reference/`](../reference/DISA-Container-Image-Creation-and-Deployment-Guide-V2R0.6.md#12-technology)

You cannot harden a thing you cannot describe. This page describes the thing.

---

## 1.1 An image is not a running system

The guide's definition (§1.2.1) is worth reading slowly:

> A container image (i.e., image) is an immutable file that contains executable
> code that can run as an isolated process within a container platform... **The
> container image is not the executing process, but the immutable file.**

Three consequences that drive everything else in this repository:

1. **The image has no kernel.** It contains userspace: libraries, binaries,
   configuration. When it runs, it uses the host node's kernel. Every control
   that is really a *kernel* control — sysctls, FIPS mode, the bootloader,
   auditd, kernel modules — belongs to the node, not to your image. This is why
   most of a RHEL STIG is Not Applicable to a container, and why the answer file
   in [`oscap/not-applicable.rules`](../oscap/not-applicable.rules) exists.

2. **The image is immutable; the container is not.** You do not patch a running
   container. You build a new image and replace the container. This is the
   reasoning behind §2.1 (no SSH daemon) and §3.7 (read-only root filesystem):
   if changes only ever happen by rebuild, then a mechanism for changing a
   running container is not a feature, it is an attack surface.

3. **Everything in the image ships.** Every file, in every layer, to everyone
   who can pull it. Including the ones you deleted in a later layer.

---

## 1.2 What is actually in an OCI image

An image is not one file. It is a small graph of content-addressed objects:

```
   MANIFEST  (application/vnd.oci.image.manifest.v1+json)
   ├── config          -> sha256:aaaa...   the image CONFIG (JSON)
   └── layers[]        -> sha256:bbbb...   layer 0   (tar, usually gzipped)
                          sha256:cccc...   layer 1
                          sha256:dddd...   layer 2
```

Three things to understand:

### The manifest
The list of the parts. Its own sha256 is the **image digest** —
`myimage@sha256:1234...`. This is what §2.14 means by comparing the hash of the
base image against the known hash from the trusted source, and what "pin by
digest" means in practice. A tag is a mutable pointer to a manifest; a digest
*is* the manifest.

### The config
A JSON document describing how to run the image. It is not a layer and it holds
no files, but it holds most of the settings section 2 cares about:

| Config field | Set by | Requirement |
|---|---|---|
| `User` | `USER` | §2.2 non-privileged user |
| `ExposedPorts` | `EXPOSE` | §2.5, §2.13 non-privileged ports only |
| `Healthcheck` | `HEALTHCHECK` | §2.6 process health check |
| `Env` | `ENV` | §2.9, §2.18 no embedded credentials |
| `Entrypoint` / `Cmd` | `ENTRYPOINT` / `CMD` | signal handling |
| `Labels` | `LABEL` | provenance and auditability |
| `rootfs.diff_ids` | the layers | integrity of the content |
| `history[]` | every instruction | **the build command line, verbatim** |

That last row is the one people are surprised by. `docker history --no-trunc`
prints the shell command of every `RUN`, and the value of every `ENV` and `ARG`.
This is why §2.9 says confidential data in build files "can be backtracked
easily by using native commands for the container platform".

Read the config yourself — you do not need a tool:

```bash
docker inspect --format '{{json .Config}}' localhost/helloctr:latest | jq
```

### The layers
Each layer is a tar archive of *filesystem changes* relative to the layer below.
Not a snapshot — a **diff**.

---

## 1.3 Layers, and why deletion does not delete

§1.2.2 of the guide:

> A container image layer is created when instructions within a configuration or
> build file are executed to create the image. Each image layer reflects a change
> made to the base image... image layers are read-only except for the last layer,
> which is read/write.

At runtime the layers are stacked by a union filesystem (overlayfs). Reads fall
through the stack top-down; writes go to a thin read-write layer created for the
container and thrown away when it dies.

**Deleting a file in a layer does not remove its bytes.** It writes a *whiteout
entry* — a marker that says "the file below is hidden". The file is still in the
lower layer, that layer is still in the manifest, and it still transfers on
every pull.

This one mechanic explains a family of requirements:

```dockerfile
# BROKEN. The credential is in layer N forever; layer N+1 only hides it.
COPY secrets.env /tmp/secrets.env      # layer N   <- 4 KB, contains the token
RUN  ./configure.sh && rm /tmp/secrets.env   # layer N+1 <- whiteout marker

# Anyone can retrieve it:
#   docker save img | tar -x && find . -name '*.tar' | xargs -n1 tar -tvf
```

Same mechanic, different symptom:

```dockerfile
# BROKEN (§2.8). The cache is in layer N; layer N+1 hides it. Image is still huge.
RUN dnf -y install foo      # layer N   <- 200 MB, includes /var/cache/dnf
RUN dnf clean all           # layer N+1 <- whiteout, reclaims nothing

# CORRECT. Created and removed inside the same diff, so it is never in a layer.
RUN dnf -y install foo && dnf clean all && rm -rf /var/cache/dnf
```

Prove it to yourself:

```bash
docker history --no-trunc localhost/helloctr:latest      # per-layer size + command
docker save localhost/helloctr:latest -o img.tar         # then unpack and look
```

---

## 1.4 Ordering: volatility increases downward

The guide (§1.2.2):

> This is often called the "application layer", because images are usually built
> with the application, the most volatile in the build process, installed last.

Layers are cached by content. When you rebuild, the builder reuses every layer up
to the first one that changed, and rebuilds everything from there down. So the
order of your instructions determines your build time:

```
   ┌──────────────────────────────┐
   │  base OS                     │  changes monthly     ← rarely rebuilt
   ├──────────────────────────────┤
   │  security patches            │  changes weekly
   ├──────────────────────────────┤
   │  runtime dependencies        │  changes per release
   ├──────────────────────────────┤
   │  hardening / config          │  changes per policy
   ├──────────────────────────────┤
   │  the application binary      │  changes every commit ← rebuilt constantly
   └──────────────────────────────┘
```

**And this is exactly where §2.8 bites.** The property that makes builds fast —
"do not rebuild a layer that did not change" — is the property that makes them
stale. Your `dnf upgrade` layer has not "changed" just because a CVE was
published, so the builder happily reuses last month's packages and your rebuild
is a no-op that produces a vulnerable image with today's date on it.

Fix it deliberately:

```bash
docker build --no-cache --pull -t myimage .    # make rebuild
```

`--no-cache` forces every layer to rebuild. `--pull` re-resolves the base tag so
an updated base is picked up. Run this on a schedule, not just on commit — see
[docs/09](09-devsecops-pipeline.md).

---

## 1.5 What the runtime adds

The image supplies the filesystem. Everything that makes it *contained* comes
from the kernel at run time, configured by the runtime and the orchestrator:

| Mechanism | What it isolates | Where it is configured |
|---|---|---|
| **Namespaces** | pid, net, mnt, ipc, uts, user | §3.10 — `hostPID/hostIPC/hostNetwork: false` |
| **cgroups** | cpu, memory, pids, io | §3.3, §3.5, §3.6 — `resources`, kubelet `podPidsLimit` |
| **Capabilities** | slices of root's power | §2.12 — `capabilities.drop: [ALL]` |
| **seccomp** | which syscalls are callable | §3.2 — `seccompProfile: RuntimeDefault` |
| **LSM** (SELinux/AppArmor) | mandatory access control | node configuration |
| **no_new_privs** | blocks setuid transitions | §2.3 — `allowPrivilegeEscalation: false` |

This is the reason the guide has two separate sections, and the reason this
repository has both a `Dockerfile` and a `k8s/` directory. **A perfectly
hardened image deployed with `privileged: true` is not secure.** A sloppy image
deployed under a restrictive Pod Security Standard is *contained*, but still
full of CVEs. You need both halves; neither substitutes for the other.

---

## 1.6 See it for yourself

```bash
make build
make inspect
```

`make inspect` reads the image config and the filesystem and prints the evidence
for each section 2 requirement — non-root user, non-privileged ports, health
check, no sshd, no setuid binaries, nothing credential-shaped in the history.
The same assertions run as a blocking gate in
[`.github/workflows/ci.yml`](../.github/workflows/ci.yml).

---

**Next:** [2. Layer-by-Layer Hardening](02-layer-by-layer-hardening.md) — what
belongs in each layer, and what to do at each one.
