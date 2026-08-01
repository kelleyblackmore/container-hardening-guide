# 10. How to STIG a Container — End-to-End Walkthrough

Everything else in this repository is reference material. This page is the
procedure: start with a container that has never been assessed, finish with an
image, an ARF, an answer file, and a set of decisions you can defend.

Prerequisites: `docker` (or `podman`), `make`, `bash`, ~5 GB of disk, and about
40 minutes the first time.

---

## Step 0 — Know which STIGs apply

"STIG a container" is not one task. Sort out the scope before you scan anything:

| Layer | Guidance | Whose job |
|---|---|---|
| The node OS | RHEL 9 STIG, Ubuntu STIG, ... | platform team |
| The container platform | Kubernetes STIG, OpenShift STIG | platform team |
| The container **image** | this guide (§2) + the OS STIG for the base | **you** |
| The **deployment** | this guide (§3) | **you** |
| The application inside | the technology's STIG or SRG (Web Server SRG, Database SRG, ASD STIG) | **you** |

Applying the RHEL 9 STIG to your base image does not discharge the Web Server
SRG for the nginx inside it. Both apply. Say so up front, because "we STIG'd the
container" meaning only the OS layer is how gaps get missed.

---

## Step 1 — Start from an approved base, and verify it

```bash
skopeo inspect docker://registry.access.redhat.com/ubi9/ubi:9.6 | jq '.Digest, .Labels'
make digests            # print the digest to pin
```

Verify the signature before you build on it (§2.10, §2.17):
```bash
cosign verify <image> --certificate-identity-regexp '.*' --certificate-oidc-issuer-regexp '.*'
# or, for Red Hat content, podman's signature policy:
podman pull --signature-policy /etc/containers/policy.json <image>
```

Pin by digest in the Dockerfile (§2.14). A tag is a mutable pointer; a digest is
the content.

Priority order for sources: [docs/11](11-approved-sources.md).

---

## Step 2 — Build, and lint the build file

```bash
make lint
make build
```

`make lint` runs hadolint with `allowed-registries` set, so a base outside the
approved set fails here rather than in an assessment ([docs/06](06-hadolint.md)).

---

## Step 3 — Baseline STIG scan: find out where you actually stand

```bash
make stig
```

That builds a throwaway scanner image (`FROM` your image + OpenSCAP + the SCAP
content) and runs the evaluation twice — baseline and tailored. Look at the
baseline first; it is the number an assessor would get.

```bash
cat results/baseline/summary.txt
open results/baseline/report.html          # xdg-open / start, per platform
cat results/baseline/failed-rules.txt
```

Expect several hundred rules to come back `notapplicable` automatically — that
is the CPE logic in the content correctly excluding bootloader, partition, and
kernel rules. On a base image that has had no hardening applied, expect dozens
of failures too.

### What this repository's image actually scores

Run against `examples/hardened`, which already has the `harden/` scripts applied:

```
                       BASELINE          TAILORED
pass                        69                69
fail                         2                 0
notapplicable              412               412      <- automatic (CPE logic)
notchecked                   1                 1      <- needs manual review
notselected               1048              1050      <- +2 = the answer file
score                      97%              100%
```

Read the delta, because it is the whole argument: the **only** two rules the
answer file deselects are the exact two that failed, and both fail for a
structural reason — `configure_crypto_policy` needs the kernel in FIPS mode, and
`network_configure_name_resolution` writes a file the kubelet overwrites at
start-up. Nothing was deselected to make a number go up.

That is what a defensible tailoring file looks like. If your baseline fails 40
rules and your answer file deselects 40 rules, nobody is going to believe the
100%, and they will be right not to.

Note also `notchecked: 1` — a rule with no automated check. It does not fail and
it does not pass; a human has to answer it in the checklist. Automated scanning
does not remove that obligation, it just narrows it to one item.

---

## Step 4 — Adjudicate every failure, one at a time

This is the actual work. For each rule in `failed-rules.txt`, exactly one of
three outcomes:

### (a) Fix it
Most findings are cheap: a file mode, a `login.defs` directive, a missing
config file. Read the rule's fix, then write the deliberate version into
[`examples/hardened/harden/`](../examples/hardened/harden/):

```bash
# what does the rule want?
oscap info --profile xccdf_org.ssgproject.content_profile_stig ssg-rhel9-ds.xml

# generate the official remediation for what failed, then READ it
docker run --rm --entrypoint bash localhost/helloctr-scan:latest -c \
  'oscap xccdf generate fix --result-id "" /scan/results/results-arf.xml' > /tmp/fix.sh
```

Do not paste `fix.sh` into your Dockerfile. Read it, understand it, and write a
small named script that does the same thing on purpose. That script is your
evidence six months from now when someone asks why `/etc/login.defs` looks like
that.

### (b) Mark it Not Applicable
Only when implementing it inside an image is **technically impossible or
meaningless** — the control belongs to the node, the kernel, or the
orchestrator. Add it to
[`oscap/not-applicable.rules`](../oscap/not-applicable.rules) with a
justification written above it:

```
# The audit daemon runs on the node and captures syscalls for every container on
# it. Running auditd inside an unprivileged container is not possible (it needs
# CAP_AUDIT_CONTROL and a netlink socket the namespace does not provide).
xccdf_org.ssgproject.content_rule_service_auditd_enabled
```

The justification is not paperwork. It is the artifact your assessor reads, and
it is injected into the generated answer file as an XML comment.

### (c) Accept the risk
When the rule *does* apply, you cannot fix it, and the reason is operational
rather than technical — a vendor image that must run as root, an application
that needs a capability. This is **not** an answer file entry. It is a waiver or
a POA&M and it goes to your AO: [docs/12](12-waivers-and-poam.md).

The distinction between (b) and (c) is the one that gets audited. Getting it
wrong in the convenient direction is how compliance automation loses its
credibility.

---

## Step 5 — Rebuild and rescan

```bash
make stig
diff <(sort results/baseline/failed-rules.txt) <(sort results/tailored/failed-rules.txt)
```

Iterate steps 4 and 5 until every remaining failure is one you have consciously
decided about. "Zero failures" is not the goal — *"zero unadjudicated failures"*
is.

---

## Step 6 — Assert the section 2 requirements

OpenSCAP evaluates the OS. It says nothing about the container-specific
requirements — non-root user, no sshd, non-privileged ports, health check.
Those are separate assertions:

```bash
make inspect
```

Which checks:

| Check | Requirement |
|---|---|
| `USER` is set and non-zero | §2.2 |
| every exposed port ≥ 1024 | §2.5, §2.13 |
| a `HEALTHCHECK` exists | §2.6 |
| no `sshd`, no `openssh-server` | §2.1 |
| no setuid/setgid files | §2.3 |
| nothing credential-shaped in the history | §2.9, §2.18 |

The same assertions run as a blocking CI job
([`ci.yml`](../.github/workflows/ci.yml), `evidence`).

---

## Step 7 — Scan for secrets and CVEs

```bash
make scan-secrets      # TruffleHog: git history, working tree, image layers
make scan-vulns        # Trivy + Grype + SBOM, with the scanner diff
```

Triage:
- **verified secret** → rotate it now, then clean up ([docs/07](07-trufflehog.md))
- **fixable HIGH/CRITICAL** → rebuild against patched packages
- **unfixed** → risk decision with an owner and an expiry ([docs/08](08-trivy-and-grype.md))

---

## Step 8 — Harden the deployment

The image is half the job.

```bash
python3 scripts/check-k8s-policy.py k8s/
kubectl apply -f k8s/
```

[`k8s/deployment.yaml`](../k8s/deployment.yaml) covers §3.1–§3.11: Pod Security
Admission `restricted`, no host namespaces, seccomp `RuntimeDefault`, dropped
capabilities, read-only root filesystem, resource limits and requests, liveness
and readiness probes, labels, and a default-deny NetworkPolicy.

Confirm the image actually runs under those restrictions *before* it reaches a
cluster:
```bash
make verify
```

---

## Step 9 — Package the evidence

What an assessor wants, and where it comes from:

| Artifact | Produced by |
|---|---|
| `results/tailored/results-arf.xml` | the STIG scan — import into STIG Viewer / eMASS |
| `results/tailored/report.html` | the human-readable scan report |
| `results/tailored/tailoring-*.xml` | the answer file, with justifications inline |
| `oscap/not-applicable.rules` | the reasoning behind every deselection |
| `results/vulns/sbom.cdx.json` | the SBOM |
| `results/vulns/trivy.json`, `grype.json` | CVE findings from two scanners |
| `.trivyignore` | accepted CVEs, with owner and expiry |
| the Dockerfile and hardening scripts | how the settings got there |
| waivers / POA&M | what you could not fix, and the plan |

Attach them to the image so the evidence travels with the artifact:
```bash
cosign attest --predicate results/tailored/results-arf.xml \
  --type https://disa.mil/stig/arf  IMAGE@sha256:<digest>
```

---

## Step 10 — Keep doing it

A STIG scan is a photograph. The image goes stale on its own:

- **weekly**: `make rebuild` (`--no-cache --pull`) then re-scan — most CVEs are
  fixed by an already-published patch;
- **weekly**: re-run the STIG evaluation; the SCAP content changes on its own
  cadence and a rule that passed last quarter can start failing;
- **on every change to the answer file**: review the delta between the baseline
  and tailored scores. A growing gap without a growing justification list is the
  signal to look closely.

Both scheduled jobs are in [`ci.yml`](../.github/workflows/ci.yml) and
[`stig.yml`](../.github/workflows/stig.yml).

---

## The whole thing, in commands

```bash
make lint          # 1. build file is well formed, base is approved
make build         # 2. build
make stig          # 3. baseline + tailored STIG evaluation
                   # 4. adjudicate: fix / N-A / waiver  (repeat 2-4)
make inspect       # 5. assert the section 2 requirements
make scan-secrets  # 6. TruffleHog
make scan-vulns    # 7. Trivy + Grype + SBOM
make verify        # 8. prove it runs read-only, capless, non-root
python3 scripts/check-k8s-policy.py k8s/    # 9. assert section 3
```

Or the lot: `make scan-all`.

---

**Next:** [11. Approved Sources](11-approved-sources.md) ·
[12. Waivers and POA&Ms](12-waivers-and-poam.md)
