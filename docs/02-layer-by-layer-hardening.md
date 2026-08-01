# 2. Layer-by-Layer Hardening

The reference implementation is [`examples/hardened/Dockerfile`](../examples/hardened/Dockerfile).
This page is the *why* behind each of its layer steps: what belongs in that
layer, what to do there, how to verify it, and what people get wrong.

Every step is tagged with the DISA requirement it satisfies. Full requirement
text is in [docs/03](03-image-creation-requirements.md).

---

## Layer map

```
  STAGE 1  BUILD ──────────────────────────────────────────────────────┐
   compiler, module cache, headers, git, test fixtures                 │  discarded
   ──────────────────────────────────────────────────── stage boundary ┘
                              │
                    only the binary crosses
                              ▼
  STAGE 2  RUNTIME
   ┌─────────────────────────────────────────────────────────────────┐
   │ STEP 1  base layer          approved, signed, digest-pinned     │  §2.10 §2.14 §2.17
   ├─────────────────────────────────────────────────────────────────┤
   │ STEP 2  metadata            OCI labels, provenance              │  auditability
   ├─────────────────────────────────────────────────────────────────┤
   │ STEP 3  patch + minimise    upgrade, remove, verify, clean      │  §2.8 §2.11 §2.12
   ├─────────────────────────────────────────────────────────────────┤
   │ STEP 4  OS hardening        STIG remediation scripts            │  §2.16
   ├─────────────────────────────────────────────────────────────────┤
   │ STEP 5  strip setuid/setgid                                     │  §2.3
   ├─────────────────────────────────────────────────────────────────┤
   │ STEP 6  non-root identity   fixed numeric UID, nologin shell    │  §2.2
   ├─────────────────────────────────────────────────────────────────┤
   │ STEP 7  application layer   COPY --from=build, mode 0555        │  §2.4
   ├─────────────────────────────────────────────────────────────────┤
   │ STEP 8  runtime config      ENV/EXPOSE/USER/HEALTHCHECK/ENTRY   │  §2.5 §2.6 §2.9 §2.13
   └─────────────────────────────────────────────────────────────────┘
```

---

## Stage 1 — the build stage

**What belongs here:** compilers, build tools, test dependencies, anything you
need to produce an artifact and nothing you need to run it.

**What to do:** produce exactly one artifact and let the stage be discarded.

A multi-stage build is the highest-leverage hardening move available, and it is
free. A Go toolchain image is ~800 MB and carries its own CVE feed. None of it
reaches production because none of it crosses the stage boundary. The same
applies to `npm ci --include=dev`, Maven, pip's build deps, and `make`.

**Verify:**
```bash
docker run --rm --entrypoint /bin/bash localhost/helloctr:latest -c 'command -v gcc go make git'
# should print nothing
```

**Common mistakes**
- Copying the whole build directory across (`COPY --from=build /src /app`) —
  that drags the source, the `.git` directory, and the test fixtures with it.
  Copy named artifacts.
- Forgetting that build *arguments* are still visible: `ARG GITHUB_TOKEN` in a
  discarded stage is safe, but `ARG` in the final stage lands in the config and
  in `docker history`. Use BuildKit secret mounts (§2.9).

---

## Layer step 1 — the base

**What to do:** choose an approved base, verify it, pin it by digest.

Priority order comes from Appendix A of the guide (see [docs/11](11-approved-sources.md)):
Iron Bank first, then a vendor's own repository, then public registries — the
last three all marked *untrusted*.

```dockerfile
# Tag: mutable. Someone can repoint it. Fine for a teaching repo.
FROM registry.access.redhat.com/ubi9/ubi:9.6

# Digest: content-addressed. Cannot be repointed. Use this for a release.
FROM registry.access.redhat.com/ubi9/ubi@sha256:<digest>
```

**Verify before you trust:**
```bash
skopeo inspect docker://registry.access.redhat.com/ubi9/ubi:9.6 | jq '.Digest,.Labels'
cosign verify <image> --certificate-identity-regexp ... --certificate-oidc-issuer ...
make digests        # print current digests for the bases this repo uses
```

### Choosing a base size — and being honest about the trade-off

| Base | Size | CVE surface | OpenSCAP STIG scannable | Debuggable |
|---|---|---|---|---|
| `ubi9/ubi` | ~200 MB | largest | **yes** — full RPM DB, shell, dnf | yes |
| `ubi9/ubi-minimal` | ~90 MB | smaller | partially — microdnf, fewer packages | limited |
| `ubi9/ubi-micro` | ~35 MB | small | mostly no — no package manager | barely |
| distroless / `scratch` | ~2–20 MB | smallest | **no** — there is no OS to scan | no |

This repository uses full `ubi9/ubi`, and that is a *deliberate teaching*
choice: the RHEL 9 STIG evaluates an RPM-managed operating system, so a
distroless image would leave nothing to demonstrate.

For a real service the honest answer is: **smaller is safer, but "unscannable"
is not the same as "compliant"**. If you ship distroless, you owe your assessor
a different evidence story — the STIG for the *application* technology (the
relevant SRG), an SBOM, and a documented statement that the OS STIG is Not
Applicable because there is no OS. Do not ship distroless and then claim a 100%
STIG score; you scored 100% of zero rules.

A practical middle path: harden and scan a full base image, publish it, then
build the application image `FROM` your scanned base and strip the package
manager in the child. You get the evidence from the parent and the reduced
surface in the child.

---

## Layer step 2 — metadata

**What to do:** OCI annotations describing what this is, where it came from, and
which commit built it.

```dockerfile
LABEL org.opencontainers.image.source="https://github.com/org/repo" \
      org.opencontainers.image.revision="$GIT_SHA" \
      org.opencontainers.image.created="$BUILD_DATE"
```

Not a security control on its own. It is what makes an incident answerable six
months later: *which commit produced the image running in prod?*

**Do not** put anything sensitive in a label. Labels are in the config, readable
with `docker inspect`, without running the image.

---

## Layer step 3 — patch and minimise

**What to do:** apply security updates, remove what the service does not need,
verify signatures, and clean up **in the same `RUN`**.

```dockerfile
RUN set -eux; \
    dnf -y --refresh upgrade --security --setopt=install_weak_deps=0 --nodocs; \
    dnf -y clean all; \
    rm -rf /var/cache/dnf /tmp/* /var/tmp/*
```

Line by line:

| Fragment | Why |
|---|---|
| `set -eux` | fail on first error; print each command. Without `-e` a failed install is a successful build. |
| `--refresh` | expire cached metadata so a cached layer cannot serve a stale package list (§2.8) |
| `upgrade --security` | apply security errata |
| `install_weak_deps=0` | do not silently pull in "recommended" packages (§2.12) |
| `--nodocs` | man pages and licences are not needed at runtime |
| `clean all` + `rm -rf` **in the same RUN** | otherwise the cache ships in a lower layer (§1.3) |

### Version pinning: the real trade-off

§2.4 wants builds with *known outcomes*, which argues for pinning every package
version. §2.15 wants old vulnerable versions gone, which argues against pinning,
because pins rot: six months later you are reinstalling a version with a known
CVE, on purpose, in a build that passes.

Pick one and be explicit:

- **Pin, and automate the bumps.** Renovate/Dependabot raise a PR when a pinned
  version is superseded. This is the strongest position and it costs you a
  weekly PR queue.
- **Do not pin, and pin the base by digest instead.** The base digest fixes the
  starting point; `upgrade --security` moves you forward from it. The build is
  reproducible *given the same repository state*, which is weaker but honest.

This repo takes the second path and says so in [`.hadolint.yaml`](../.hadolint.yaml),
where `DL3041` is ignored with the reasoning written out. What is not acceptable
is having no position and discovering it during an assessment.

**Verify:**
```bash
docker run --rm --entrypoint /bin/bash IMG -c 'rpm -qa | wc -l'    # package count
docker run --rm --entrypoint /bin/bash IMG -c 'dnf -q updateinfo list security' # outstanding errata
```

---

## Layer step 4 — OS hardening (the STIG layer)

**What to do:** apply the STIG settings that are actually applicable to an
image, as small, reviewable, single-purpose scripts.

See [`examples/hardened/harden/`](../examples/hardened/harden/): login.defs
password policy, shell umask, the DoD banner, account database permissions,
faillock, and attack-surface removal. Each script names the SSG rules it
implements.

**Why scripts and not `oscap --remediate`:** `--remediate` runs SSG's fix
scripts against the live filesystem. It is genuinely useful for *discovering*
what a fix looks like — run it, diff the filesystem, read the change. It is a
bad way to *build* an image:

- the changes are not in your Dockerfile, so they are not in code review, not
  reproducible, and invisible to anyone reading the repo;
- some fixes call `systemctl`, `grubby`, or `fips-mode-setup`, which fail or
  half-succeed in a container;
- a year later nobody can say why a file looks the way it does.

Take the fix, read it, write the deliberate version into a script. That is what
those scripts are.

---

## Layer step 5 — strip setuid/setgid

**What to do:**
```dockerfile
RUN find / -xdev -perm /6000 -type f -exec chmod ug-s {} + \
 && test -z "$(find / -xdev -perm /6000 -type f)"
```

A setuid-root binary is the ladder from "code execution as the app user" to
"root inside the container". `su`, `mount`, `chsh`, `pkexec`, `newgrp` — a base
image ships a dozen of them, and your service needs none.

Note the assertion on the second line. Do the thing, then *prove* the thing.

**This is one of two halves.** The deployment side is
`allowPrivilegeEscalation: false`, which sets `no_new_privs` so the kernel
refuses the setuid transition regardless. Do both: the image control holds on a
misconfigured platform, the platform control holds if a future rebuild
reintroduces a setuid binary.

---

## Layer step 6 — the non-root identity

**What to do:** create a system account with a **fixed numeric UID** and a
`nologin` shell, then `USER <uid>:<gid>` at the end.

```dockerfile
RUN groupadd --system --gid 1001 appuser \
 && useradd --system --uid 1001 --gid 1001 --no-create-home \
            --home-dir /app --shell /sbin/nologin appuser
...
USER 1001:1001
```

**Numeric, not a name.** Kubernetes' `runAsNonRoot: true` check inspects the
numeric UID in the image config. If `USER` names a user the kubelet cannot
resolve, admission can reject the pod with `container has runAsNonRoot and image
has non-numeric user`.

**Where to put `USER`:** as late as possible. Everything above it needs root
(patching, `chmod`, `useradd`). Everything below it runs unprivileged.

**Rootless does not mean harmless.** UID 1001 in the container is UID 1001 on
the node unless user namespace remapping is on. If that UID owns files on a
mounted volume, your "non-root" container has write access to them.

---

## Layer step 7 — the application layer

**What to do:**
```dockerfile
COPY --from=build --chown=1001:1001 --chmod=0555 /out/app /app/app
```

- `COPY`, never `ADD` (§2.4). `ADD` fetches URLs and auto-extracts archives —
  two unknown outcomes, and archive extraction can write outside the target.
- `--from=build` — from a stage, not the network.
- `--chown`/`--chmod` inline — a follow-up `RUN chown` would duplicate the whole
  binary in another layer.
- `0555` — read and execute, no write, for anyone. The app cannot rewrite itself.

**Put this last.** It is the most volatile content in the image, so every
rebuild after a code change reuses everything above it.

---

## Layer step 8 — runtime configuration

Metadata only — no filesystem content — but it is where several requirements live.

### `ENV` — configuration, never secrets (§2.9, §2.18)
`ENV` values are in the image config, in `docker history`, in `docker inspect`,
and in `/proc/<pid>/environ` for every process in the container. Set a *path* to
a secret, not the secret:

```dockerfile
ENV APP_SECRET_FILE=/run/secrets/app/token     # a path. The file is mounted.
```

Build-time secrets, when genuinely needed, use BuildKit mounts, which never
write to a layer:
```dockerfile
RUN --mount=type=secret,id=npmtoken \
    NPM_TOKEN="$(cat /run/secrets/npmtoken)" npm ci
```
```bash
docker build --secret id=npmtoken,env=NPM_TOKEN .
```

### `EXPOSE` — non-privileged ports only (§2.5, §2.13)
Ports below 1024 need root or `CAP_NET_BIND_SERVICE`. Listen on 8080 and let the
platform map 80 → 8080 (see the `Service` in
[`k8s/deployment.yaml`](../k8s/deployment.yaml)).

`EXPOSE` opens nothing. It is documentation that scanners and orchestrators
read. Actual reachability is `NetworkPolicy`.

### `HEALTHCHECK` — the process health check (§2.6)
```dockerfile
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/app/app", "-healthcheck"]
```
Call the app's own probe flag. A `curl`-based health check means shipping `curl`
— a fetch tool you just handed an attacker — to check a port you own.

**Kubernetes ignores `HEALTHCHECK` completely.** You still need it (DISA
requires it; Docker, Compose, Swarm, and Nomad honour it), and you *additionally*
need liveness and readiness probes (§3.8, §3.9).

### `ENTRYPOINT` — exec form, always
```dockerfile
ENTRYPOINT ["/app/app"]        # PID 1 is your process; it receives SIGTERM
CMD /app/app                   # PID 1 is /bin/sh, which does not forward signals
```
Shell form is why containers take the full termination grace period to die and
then get `SIGKILL`ed mid-request.

---

## Verify the whole thing

```bash
make build && make inspect      # assert each section 2 requirement
make verify                     # run it read-only, capless, non-root
```

---

**Next:** [3. Image Creation Requirements](03-image-creation-requirements.md) —
all eighteen, with CCIs and verification commands.
