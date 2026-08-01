# Compliance Matrix

Every requirement from the DISA Container Image Creation and Deployment Guide
V2R0.6, mapped to where it is implemented in this repository, how it is
verified, and which tool enforces it.

`CCI` and `IA Control` are taken from the guide itself.

---

## Section 2 — Container Image Creation

| § | Requirement | IA Control | CCI | Implemented in | Verified by | Gate |
|---|---|---|---|---|---|---|
| 2.1 | SSH server daemon disabled | CM-7 a | CCI-000381 | [`harden/60-remove-attack-surface.sh`](../examples/hardened/harden/60-remove-attack-surface.sh) | `test ! -e /usr/sbin/sshd` | CI `evidence` |
| 2.2 | Execute as non-privileged user | AC-6 (10) | CCI-002235 | [`Dockerfile`](../examples/hardened/Dockerfile) step 6, `USER 1001:1001` | `docker inspect .Config.User` | CI `evidence` + `runAsNonRoot` |
| 2.3 | Remove setuid/setgid permissions | AC-6 (10) | CCI-002235 | [`Dockerfile`](../examples/hardened/Dockerfile) step 5 | `find / -perm /6000` | CI `evidence` + `allowPrivilegeEscalation:false` |
| 2.4 | Commands with known outcomes | CM-7 a | CCI-000381 | `COPY` only, `set -eux`, `SHELL … pipefail` | hadolint DL3020, DL4006 | CI `lint` |
| 2.5 | Only non-privileged ports | CM-7 (1)(b) | CCI-001762 | `EXPOSE 8080`; Service 80→8080 | port ≥ 1024 assertion | CI `evidence` |
| 2.6 | Process health check | SC-5 | CCI-002385 | `HEALTHCHECK` → `-healthcheck` flag | `docker inspect .Config.Healthcheck` | CI `evidence` |
| 2.7 | TLS 1.2+ for registry pulls | SC-8 | CCI-002418 | registry / daemon configuration | `openssl s_client -tls1_2` | manual |
| 2.8 | Minimal cached layers | SI-2 (6) | CCI-002617 | single-`RUN` install+clean; `make rebuild` | `docker history` | CI `no-cache: true` |
| 2.9 | No confidential data in build files | CM-6 b | CCI-000366 | [`.dockerignore`](../examples/hardened/.dockerignore), BuildKit secrets | `docker history` grep + TruffleHog | CI `secrets`, `evidence` |
| 2.10 | Created from signed base images | CM-5 (3) | CCI-001749 | digest-pinned `FROM` | `cosign verify`, `skopeo inspect` | manual + admission |
| 2.11 | Created with verified packages | CM-5 (3) | CCI-001749 | `gpgcheck=1` + signature assertion in step 3 | build fails on unsigned RPM | build |
| 2.12 | Only essential capabilities | CM-7 a | CCI-000381 | [multi-stage build](13-multi-stage-builds.md), `install_weak_deps=0`, package removal | package count; `capabilities.drop: [ALL]` | CI + `check-k8s-policy.py` |
| 2.13 | Only required ports enabled | CM-7 (1)(b) | CCI-001762 | one `EXPOSE`; [`networkpolicy.yaml`](../k8s/networkpolicy.yaml) | exposed-port assertion | CI `evidence` |
| 2.14 | DoD-approved base image | SC-8 (2) | CCI-002422 | `ARG RUNTIME_IMAGE`, `make digests` | hadolint DL3026 `allowed-registries` | CI `lint` |
| 2.15 | Remove superseded images | SI-2 (6) | CCI-002617 | deploy by digest; registry retention | `crane ls` / `skopeo list-tags` | registry policy |
| 2.16 | Implement relevant STIG/SRG | CM-6 b | CCI-000366 | [`harden/`](../examples/hardened/harden/) + [`oscap/`](../oscap/) | OpenSCAP baseline + tailored | CI `stig` |
| 2.17 | Trusted and approved source | IA-5 (2)(a) | CCI-000185 | `allowed-registries` in [`.hadolint.yaml`](../.hadolint.yaml) | hadolint DL3026 + signature check | CI `lint` + admission |
| 2.18 | Clear of embedded credentials | IA-5 (7) | CCI-002367 | secret mounted at runtime from a `Secret` | TruffleHog over history/tree/layers | CI `secrets` |

---

## Section 3 — Container Deployment

| § | Requirement | IA Control | CCI | Implemented in | Verified by | Gate |
|---|---|---|---|---|---|---|
| 3.1 | No registry endpoint mounted | SC-4 | CCI-001090 | `automountServiceAccountToken: false`; no `.sock` mount | [`check-k8s-policy.py`](../scripts/check-k8s-policy.py) | CI `k8s-policy` |
| 3.2 | Limited system calls | SC-4 | CCI-001090 | `seccompProfile: RuntimeDefault` | `check-k8s-policy.py`; `/proc/1/status` | CI `k8s-policy` + PSA |
| 3.3 | PIDs cgroup limits | SC-4 | CCI-001090 | kubelet `podPidsLimit` + `ResourceQuota` | `pids.max` in the container | node config |
| 3.4 | No sensitive host mounts | SC-4 | CCI-001090 | no `hostPath` anywhere | `check-k8s-policy.py` | CI `k8s-policy` + PSA |
| 3.5 | Resource limits | SC-5 (1) | CCI-001094 | `resources.limits` + `LimitRange` | `check-k8s-policy.py` | CI `k8s-policy` |
| 3.6 | Resource requests | SC-5 (2) | CCI-001095 | `resources.requests` + `LimitRange` | `check-k8s-policy.py` | CI `k8s-policy` |
| 3.7 | Read-only root filesystem | CM-5 (1) | CCI-001813 | `readOnlyRootFilesystem: true` + tmpfs | `check-k8s-policy.py`; `make verify` | CI `k8s-policy` + `evidence` |
| 3.8 | Liveness probe | SC-5 | CCI-002385 | `livenessProbe` → `/healthz` | `check-k8s-policy.py` | CI `k8s-policy` |
| 3.9 | Readiness probe | SC-5 | CCI-002385 | `readinessProbe` → `/readyz` | `check-k8s-policy.py` | CI `k8s-policy` |
| 3.10 | No host kernel namespaces | SC-4 | CCI-001090 | `hostPID/hostIPC/hostNetwork: false` | `check-k8s-policy.py` | CI `k8s-policy` + PSA |
| 3.11 | Label selectors | SC-39 | CCI-002530 | labels + `nodeSelector` + NetworkPolicy | manifest review | CI `k8s-policy` |

---

## Section 4 — DevSecOps

| § | Stage | Implemented in |
|---|---|---|
| 4.3.1 | Coding and Testing | [`ci.yml`](../.github/workflows/ci.yml) `lint` |
| 4.3.2 | Building | `ci.yml` `build` (`no-cache`, `pull`) |
| 4.3.3 | Securing | `ci.yml` `secrets`, `vulnerability`, `evidence`; [`stig.yml`](../.github/workflows/stig.yml) |
| 4.3.4 | Publishing | [`.trivyignore`](../.trivyignore), [`not-applicable.rules`](../oscap/not-applicable.rules) + review |
| 4.3.5 | Releasing | not implemented — see [docs/09 §9.6](09-devsecops-pipeline.md) |
| 4.3.6 | Configuring | `ci.yml` `k8s-policy` |
| 4.3.7 | Monitoring | scheduled workflows in `ci.yml` and `stig.yml` |

---

## Tool coverage

Which tool answers which question. The gaps are the point — no single row covers
a meaningful fraction of the guide.

| Tool | Answers | Blind to |
|---|---|---|
| **hadolint** | is the build file well formed? | the image itself: CVEs, secrets, setuid, STIG |
| **TruffleHog** | is there a live credential in the history, tree, or layers? | CVEs, configuration, STIG |
| **Trivy** | known CVEs, secrets, misconfiguration, licences | STIG rules, image config assertions |
| **Grype + Syft** | known CVEs, and a durable SBOM | same |
| **OpenSCAP** | does the OS in the image meet the STIG? | CVEs, secrets, how it was built, how it is deployed |
| **kube-linter / check-k8s-policy** | do the manifests meet section 3? | anything about the image |
| **`docker inspect` assertions** | does the image config meet section 2? | file contents, CVEs |
| **Pod Security Admission** | is what is actually running compliant? | image contents |

---

**Back to:** [README](../README.md)
