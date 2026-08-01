# The Hardened Container — Line by Line

The image itself: [`Dockerfile`](Dockerfile). This page is the reading guide.

```bash
make build      # build it
make inspect    # prove each section 2 requirement against the built image
make verify     # run it read-only, no capabilities, non-root
make stig       # OpenSCAP DISA STIG evaluation
```

---

## What it is

A ~5 MB static Go HTTP service ([`app/main.go`](app/main.go)) on a full UBI 9
base. The application is deliberately boring — it exists so the image has
something real to run. What is worth reading is everything around it.

The app was written for the hardening, not the other way round:

| App design choice | Requirement it enables |
|---|---|
| listens on 8080 | §2.5, §2.13 — no privileged port, so no root, so no capability |
| `-healthcheck` flag | §2.6 — health check with no `curl` in the image |
| separate `/healthz` and `/readyz` | §3.8, §3.9 — liveness and readiness are different questions |
| writes nothing to disk | §3.7 — runs with a read-only root filesystem |
| reads its secret from a file path given at runtime | §2.9, §2.18 — nothing baked in |
| handles SIGTERM | clean drain instead of `SIGKILL` after the grace period |

**This is the part most write-ups skip.** Most of what makes a container easy to
harden is decided in the application, before anyone opens a Dockerfile. An app
that binds :80, writes its config on startup, and reads secrets from environment
variables cannot be hardened into compliance — it can only be waived into it.

---

## The two stages

```
STAGE 1  build      golang:1.26   compiler, module cache, headers   -> discarded
                         │
                    one binary crosses
                         ▼
STAGE 2  runtime    ubi9:9.6      the image you ship
```

The Go toolchain image is 1.2 GB and carries its own CVE feed. None of it
reaches production, because none of it crosses the stage boundary. This is the
highest-leverage line in the file and it costs nothing.

How much it costs to skip: [`examples/single-stage`](../single-stage/Dockerfile)
builds this same application in one stage instead of two, and the result is
~2.3x the size with the compiler, git, and your source code inside it, and 12
fixable HIGH CVEs against this image's 0. Run `make compare-stages` to measure
it, or read [docs/13](../../docs/13-multi-stage-builds.md).

---

## The eight layer steps

Each is tagged in the Dockerfile with the requirement it satisfies. Full
reasoning: [docs/02](../../docs/02-layer-by-layer-hardening.md).

| Step | What it does | Requirements |
|---|---|---|
| **1** Base | approved registry, pinned, verifiable | §2.10, §2.14, §2.17 |
| **2** Metadata | OCI labels — what this is and where it came from | auditability |
| **3** Patch & minimise | full `dnf upgrade`, remove remote-access packages, assert every RPM is signed, clean in the same `RUN` | §2.1, §2.8, §2.11, §2.12 |
| **4** OS hardening | the [`harden/`](harden/) scripts — STIG settings | §2.16 |
| **5** Strip setuid | `chmod ug-s` everything, then assert none remain | §2.3 |
| **6** Identity | system account, fixed numeric UID, `nologin` shell | §2.2 |
| **7** Application | `COPY --from=build --chmod=0555` — one file, mode 0555 | §2.4 |
| **8** Runtime config | `ENV`/`EXPOSE`/`USER`/`HEALTHCHECK`/`ENTRYPOINT` | §2.5, §2.6, §2.9, §2.13 |

### Details worth calling out

**`SHELL ["/bin/bash", "-o", "pipefail", "-c"]`** — under the default `sh -c`,
a pipeline reports the exit status of the *last* command, so `false | true`
succeeds. Without `pipefail`, a failing verification step on the left of a pipe
silently passes the build. That is how a broken check ships for six months.

**Assertions, not hopes.** Steps 3 and 5 do not just remove things, they *prove*
the removal and fail the build otherwise:

```dockerfile
# §2.1  - note the `if`, not `! rpm -q ...`. A negated command is exempt from
#         errexit, so `! rpm -q openssh-server` does NOT fail the build when the
#         package IS installed. shellcheck flags it as SC2251; hadolint runs
#         shellcheck over every RUN, which is how this one was caught here.
if rpm -q openssh-server >/dev/null 2>&1 || [ -x /usr/sbin/sshd ]; then exit 1; fi

# §2.11 - every installed RPM carries a signature, or the build stops
[ -z "$unsigned" ] || { echo "unsigned: $unsigned"; exit 1; }

# §2.3  - nothing setuid/setgid survives the strip
remaining="$(find / -xdev -perm /6000 -type f)"; [ -z "$remaining" ] || exit 1
```

A hardening step with no assertion is a comment.

**Cleanup in the same `RUN`.** `dnf clean all` in a *later* layer reclaims
nothing — the cache is in the earlier layer's diff and still ships. See
[docs/01 §1.3](../../docs/01-anatomy-of-a-container-image.md).

**`USER` is numeric.** Kubernetes' `runAsNonRoot: true` check inspects the
numeric UID in the image config. A named user the kubelet cannot resolve can get
the pod rejected at admission.

**`HEALTHCHECK` calls the app's own flag.** No `curl` in the image. And note that
Kubernetes ignores `HEALTHCHECK` entirely — the probes in
[`k8s/deployment.yaml`](../../k8s/deployment.yaml) are separate requirements
(§3.8, §3.9), not the same one expressed twice.

**`ENTRYPOINT` is exec form.** Shell form makes `/bin/sh` PID 1, and it does not
forward `SIGTERM`. The container then takes the full grace period to die and gets
`SIGKILL`ed mid-request.

---

## The hardening scripts

[`harden/`](harden/) — small, single-purpose, each naming the SSG rules it
implements:

| Script | Covers |
|---|---|
| [`10-login-defs.sh`](harden/10-login-defs.sh) | password ageing, length, `UMASK 077`, SHA512 hashing |
| [`20-umask-shell.sh`](harden/20-umask-shell.sh) | umask in `/etc/profile`, `bashrc`, `profile.d` |
| [`30-banner.sh`](harden/30-banner.sh) | the DoD notice and consent banner |
| [`40-file-permissions.sh`](harden/40-file-permissions.sh) | `shadow`/`gshadow`/`passwd`/`group` modes, no empty passwords, sticky bits |
| [`50-faillock.sh`](harden/50-faillock.sh) | account lockout policy |
| [`60-remove-attack-surface.sh`](harden/60-remove-attack-surface.sh) | remove network daemons and build tooling; **assert no sshd** |
| [`70-misc-stig.sh`](harden/70-misc-stig.sh) | `localpkg_gpgcheck`, root init file modes, `rootfiles`, `pam_wheel` for `su` |

`70-misc-stig.sh` exists because the **baseline scan** found those four, not
because anyone guessed. That is the loop the whole repository is built around:
`make stig` → read `results/baseline/failed-rules.txt` → fix or justify → repeat.
With all seven applied, the image scores 97% baseline / 100% tailored, and the
answer file deselects exactly the two rules that a container structurally cannot
satisfy.

They are written by hand rather than generated with `oscap --remediate`, because
remediation output is not reviewable, not reproducible, and silently
half-succeeds in a container when a fix calls `systemctl` or `grubby`. Reasoning:
[docs/02, layer step 4](../../docs/02-layer-by-layer-hardening.md).

Some of these are, honestly, of limited value inside a container — nothing reads
`/etc/issue` when there is no login session. They are here because they are two
lines each and shipping them is less work than writing the waiver. That keeps the
Not-Applicable list short, and a short N/A list is a defensible one.

---

## Deliberate choices you might disagree with

**Full `ubi9` rather than `ubi-minimal`, `ubi-micro`, or distroless.** A smaller
base is genuinely safer. This one is here because the RHEL 9 STIG evaluates an
RPM-managed operating system, and a distroless image would leave nothing to
demonstrate. If you ship distroless, you owe your assessor a different evidence
story — the application technology's SRG, an SBOM, and a written statement that
the OS STIG is Not Applicable because there is no OS. Do not ship distroless and
claim a 100% STIG score; you scored 100% of zero rules. See
[docs/02](../../docs/02-layer-by-layer-hardening.md) for the comparison table.

**`dnf` and `/bin/sh` are left in.** Removing the package manager is a real
technique — it stops an attacker installing tools — but it also blinds every SBOM
and CVE scanner and stops OpenSCAP evaluating most of the STIG. For an image that
has to be *scanned*, keep them. A defensible middle path: harden and scan a base
image, then strip in the application image built `FROM` it.

**RPM versions are not pinned.** §2.4 wants known outcomes; §2.15 wants old
vulnerable versions gone. Pins deliver the first and defeat the second, because
six months later you are reinstalling a version with a known CVE on purpose. The
position here is: digest-pin the base, run a full `dnf upgrade` every build,
rebuild weekly with `--no-cache`. Note *full* — `upgrade --security` is close to
a no-op on UBI and shipped 33 fixable HIGH CVEs before this was caught; the
reasoning is in the Dockerfile and in
[docs/02](../../docs/02-layer-by-layer-hardening.md). The reasoning is written into
[`.hadolint.yaml`](../../.hadolint.yaml) next to the `DL3041` ignore. If your
organisation requires pinning, delete that ignore and generate the pins from a
manifest.

**Tags rather than digests in `FROM`.** So the example keeps building for
readers. `make digests` prints what to pin. In a release build these are digests
and the registry is `registry1.dso.mil`.

---

## Compare it against the anti-pattern

[`../insecure/Dockerfile`](../insecure/Dockerfile) is the same idea built wrong,
with every line tagged with the requirement it violates.

```bash
make lint-insecure
```

Then count the violations documented in the file against what hadolint reported.
The gap is the argument for everything else in this repository.

---

**See also:** [docs/02](../../docs/02-layer-by-layer-hardening.md) ·
[docs/03](../../docs/03-image-creation-requirements.md) ·
[docs/10](../../docs/10-stig-a-container-walkthrough.md)
