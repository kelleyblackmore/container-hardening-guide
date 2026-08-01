# Container Hardening Guide

[![ci](https://github.com/kelleyblackmore/container-hardening-guide/actions/workflows/ci.yml/badge.svg)](https://github.com/kelleyblackmore/container-hardening-guide/actions/workflows/ci.yml)
[![stig](https://github.com/kelleyblackmore/container-hardening-guide/actions/workflows/stig.yml/badge.svg)](https://github.com/kelleyblackmore/container-hardening-guide/actions/workflows/stig.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**What a container image is actually made of, and how to harden it — layer by
layer, requirement by requirement — following the DISA *Container Image Creation
and Deployment Guide*, V2R0.6.**

Not a checklist. A working, annotated reference: a hardened container you can
build, an anti-pattern container you can scan, a full OpenSCAP STIG workflow with
a real tailoring file, hardened Kubernetes manifests, and a CI pipeline that
proves every claim instead of asserting it.

```bash
git clone https://github.com/kelleyblackmore/container-hardening-guide
cd container-hardening-guide
make install-tools     # hadolint, trivy, grype, syft, trufflehog
make build             # build the hardened image
make inspect           # assert each DISA section 2 requirement
make stig              # OpenSCAP STIG scan: baseline vs tailored
```

---

## Start here

| If you want to… | Read |
|---|---|
| understand what an image *is* — layers, manifest, config, why deletion doesn't delete | [1. Anatomy of a Container Image](docs/01-anatomy-of-a-container-image.md) |
| know what to do at each layer | [2. Layer-by-Layer Hardening](docs/02-layer-by-layer-hardening.md) |
| understand multi-stage builds — one Dockerfile, many `FROM`s | [13. Multi-Stage Builds](docs/13-multi-stage-builds.md) |
| look up one requirement | [3. Image Creation §2](docs/03-image-creation-requirements.md) · [4. Deployment §3](docs/04-deployment-requirements.md) |
| STIG a container end to end | [10. Walkthrough](docs/10-stig-a-container-walkthrough.md) |
| use OpenSCAP and write a tailoring file | [5. OpenSCAP and Tailoring](docs/05-openscap-and-tailoring.md) |
| use the scanners | [6. hadolint](docs/06-hadolint.md) · [7. TruffleHog](docs/07-trufflehog.md) · [8. Trivy & Grype](docs/08-trivy-and-grype.md) |
| build the pipeline | [9. DevSecOps Pipeline](docs/09-devsecops-pipeline.md) |
| handle what you can't fix | [12. Waivers and POA&Ms](docs/12-waivers-and-poam.md) |
| see the whole mapping at once | [Compliance Matrix](docs/compliance-matrix.md) |

---

## What's in here

```
examples/hardened/          the reference image — every line annotated with the
  Dockerfile                requirement it satisfies, in 8 numbered layer steps
  harden/                   STIG remediation scripts, each naming its SSG rules
  app/                      a small Go service designed to BE hardenable
  README.md                 line-by-line reading guide

examples/insecure/          the same idea built wrong — every line tagged with
  Dockerfile                the requirement it VIOLATES. Lint it, scan it.

examples/single-stage/      the same app built in ONE stage instead of two, so
  Dockerfile                the difference can be measured rather than asserted:
                            ~2.3x the size, 12 fixable CVEs vs 0, identical binary

oscap/                      the OpenSCAP workflow
  run-oscap.sh              baseline scan + tailored scan + diff
  Containerfile.scan        throwaway scanner layer (image + oscap + SCAP content)
  generate-tailoring.sh     builds the answer file, with justifications inline
  not-applicable.rules      every deselected rule, with a written reason
  tailoring/                a hand-written, fully annotated tailoring file

k8s/                        deployment hardening — §3.1 through §3.11
  deployment.yaml           PSA restricted, seccomp, caps dropped, read-only
                            root, limits/requests, probes, labels
  networkpolicy.yaml        default-deny, then exactly what the service needs

scripts/                    scan-vulns.sh, scan-secrets.sh, check-k8s-policy.py
.github/workflows/          ci.yml (lint→build→scan→assert), stig.yml (OpenSCAP)
docs/                       the thirteen chapters
reference/                  the DISA guide itself, so every [2.x] tag in this
                            repo resolves to the words it came from
```

---

## What it scores

`make stig` on the reference image, against the DISA RHEL 9 STIG profile:

```
                    BASELINE   TAILORED
pass                      69         69
fail                       2          0
notapplicable            412        412     automatic (CPE logic in the content)
notchecked                 1          1     no automated check - review by hand
notselected             1048       1050     +2 = the answer file
score                    97%       100%
```

The two rules the answer file deselects are the exact two that failed, and both
fail structurally: `configure_crypto_policy` needs the kernel in FIPS mode, and
`network_configure_name_resolution` writes a file the kubelet overwrites at
start-up. Nothing was deselected to move a number.

That delta is the thing to look at. A baseline failing 40 rules with an answer
file deselecting 40 rules also scores 100%, and means nothing.

---

## The idea

The DISA guide is 20 pages of requirements with no implementation. This
repository is the implementation, with the reasoning kept attached to the code.

Three things it tries to do differently:

**1. Every claim is checked, not asserted.** `make inspect` reads the built image
and proves each section 2 requirement — non-root user, no `sshd`, no setuid
binaries, non-privileged ports, a health check, nothing credential-shaped in the
layer history. The same assertions run as a blocking CI job. A hardening step
with no assertion is a comment.

**2. The trade-offs are written down.** Version-pin RPMs (reproducible) or don't
(not stale)? Full UBI (scannable) or distroless (smaller)? Keep the package
manager (SBOMs work) or strip it (fewer tools for an attacker)? Every one of
these has a defensible answer in both directions. This repo picks one, says which,
and explains what it costs — in the file where the decision lives.

**3. The gaps between tools are the subject, not an afterthought.** hadolint
can't see a CVE. Trivy can't see a STIG finding. OpenSCAP can't see a secret.
None of them can see how you deployed it. [The tool coverage
table](docs/compliance-matrix.md#tool-coverage) is about what each one is blind
to.

---

## The tooling, and what each one is for

| Tool | Question it answers | Doc |
|---|---|---|
| **hadolint** | is the build file well formed? | [docs/06](docs/06-hadolint.md) |
| **TruffleHog** | is there a live credential in the history, tree, or layers? | [docs/07](docs/07-trufflehog.md) |
| **Trivy** + **Grype** | known CVEs — run **both**, and diff them | [docs/08](docs/08-trivy-and-grype.md) |
| **Syft** | the SBOM everything else should hang off | [docs/08](docs/08-trivy-and-grype.md) |
| **OpenSCAP** | does the OS in the image meet the STIG? | [docs/05](docs/05-openscap-and-tailoring.md) |
| **kube-linter** + `check-k8s-policy.py` | do the manifests meet section 3? | [docs/04](docs/04-deployment-requirements.md) |

Running two CVE scanners is not belt-and-braces, it is the guide's own
instruction (§4.3.3: *"It is necessary to utilize more than one tool to scan
since results can differ"*). `scripts/scan-vulns.sh` diffs them and prints what
only one of them found — which is where the interesting findings are.

---

## Commands

```bash
make build          # build the hardened image
make rebuild        # --no-cache --pull  (§2.8, §2.15 — run this on a schedule)
make lint           # hadolint the hardened Dockerfile   (must pass)
make lint-insecure  # hadolint the anti-pattern          (findings expected)
make inspect        # assert every section 2 requirement against the image
make verify         # run it read-only, cap-drop=ALL, non-root
make scan-secrets   # TruffleHog: git history + working tree + image layers
make scan-vulns     # Trivy + Grype + Syft SBOM, with the scanner diff
make stig           # OpenSCAP: baseline scan, tailored scan, HTML + ARF
make scan-all       # all of the above
make digests        # print base image digests to pin (§2.14)
make compare-stages # build the app single-stage vs multi-stage, measure the gap
```

---

## Requirement coverage

All 18 image-creation requirements (§2) and all 11 deployment requirements (§3)
are implemented and mapped in the [compliance matrix](docs/compliance-matrix.md),
with IA control, CCI, the file that implements it, the command that verifies it,
and the CI job that gates it.

Section 4 (DevSecOps) is implemented as the two workflows, except for Publishing
and Releasing — this repo publishes nothing, so those are documented with the
cosign/attestation steps you would add rather than left as dead YAML.

---

## Caveats — read these

**This is a reference, not an accreditation.** It shows how to implement and
verify the guide's requirements. It does not make your image compliant, and it is
not a substitute for your organisation's process or your AO's judgement.

**Requirements outrank this repository.** Where anything here conflicts with the
DISA guide, a STIG, an SRG, or your local policy, those win. The guide is
explicit that it is "no replacement for a STIG or SRG".

**The OS STIG is not the whole job.** Applying the RHEL 9 STIG to a base image
does not discharge the SRG for the application inside it. A web server still owes
you the Web Server SRG; a database still owes you the Database SRG.

**Registries.** The examples build from `registry.access.redhat.com` so readers
without a Platform One account can run them. In a DoD build, the `FROM` lines and
the `allowed-registries` list in `.hadolint.yaml` become one entry:
`registry1.dso.mil`. See [docs/11](docs/11-approved-sources.md).

**`examples/insecure/` is deliberately vulnerable.** It installs an SSH server
and a port scanner and contains fake credential strings. It exists to be linted
and scanned. `make build-insecure` makes you wait five seconds and think about
it. Do not deploy it.

---

## Source

DISA, *Container Image Creation and Deployment Guide*, Version 2, Release 0.6,
02 November 2020. Distribution Statement A — approved for public release.

A text transcription is vendored at
[`reference/`](reference/DISA-Container-Image-Creation-and-Deployment-Guide-V2R0.6.md)
so every `[2.x]` and `[3.x]` tag in this repository resolves to the requirement
it came from without leaving the repo. It is a convenience copy — for an
assessment, use the official PDF from
[public.cyber.mil](https://public.cyber.mil/stigs/). See
[`reference/README.md`](reference/README.md) for provenance and caveats.

Related: [NIST SP 800-190](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf) ·
[NIST SP 800-52r2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf) ·
[DISA STIGs](https://public.cyber.mil/stigs/) ·
[SCAP Security Guide](https://github.com/ComplianceAsCode/content) ·
[Iron Bank](https://ironbank.dso.mil)

## License

MIT — see [LICENSE](LICENSE). The DISA guide it follows is public domain,
Distribution Statement A.
