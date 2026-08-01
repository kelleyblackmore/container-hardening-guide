# 8. Trivy and Grype — Vulnerability Scanning

DISA guide §4.3.3, on the Securing stage of the pipeline:

> The new container image is scanned by security tools such as Prisma, Anchore,
> and OpenScap to determine what vulnerabilities are within the container image.
> **It is necessary to utilize more than one tool to scan since results can
> differ.**

```bash
make scan-vulns          # trivy + grype + syft SBOM, and a diff of the two
```

---

## 8.1 Why the same image gets two different answers

A "vulnerability scan" is three steps, and the tools make different choices at
each one.

### Step 1 — inventory: what is installed?
Both read the RPM/dpkg/apk database and both parse language manifests
(`go.mod`, `package-lock.json`, `requirements.txt`, `pom.xml`). They diverge on
binaries with no manifest, vendored source, and statically linked dependencies.
Trivy is notably good at identifying Go binaries by their embedded build info;
Grype leans on Syft, which is a dedicated inventory tool.

### Step 2 — matching: which CVEs affect that inventory?
Where most of the divergence lives. Both start from NVD, but Grype uses the
Anchore feed and Trivy its own aggregated database, and each weighs the distro
security trackers (Red Hat OVAL, Debian, Alpine secdb, Ubuntu USN) differently.
Version-range comparison against a distro's backported patch is genuinely hard —
`openssl-3.0.7-24.el9` may or may not contain the fix depending on Red Hat's
backport, and only the vendor's OVAL knows.

### Step 3 — filtering: is it exploitable *here*?
Red Hat frequently marks a CVE "will not fix", "affects a code path not compiled
in", or "not affected". Trivy honours those OVAL statements aggressively, which
is why **Trivy often reports fewer findings than Grype on a UBI image**.

That is not Trivy being wrong. It is also not Grype being wrong. It is two
defensible readings of "does this apply".

**So: run both, diff them, and investigate what only one found.** That delta is
where the interesting findings are. Never pick the scanner with the prettiest
number — that is optimising the metric instead of the posture.

[`scripts/scan-vulns.sh`](../scripts/scan-vulns.sh) does the diff automatically.

---

## 8.2 Trivy

```bash
trivy image --severity HIGH,CRITICAL --ignore-unfixed myimage:tag

trivy image --format json  --output trivy.json  myimage:tag
trivy image --format sarif --output trivy.sarif myimage:tag   # GitHub code scanning

# other scanners in the same binary
trivy image --scanners vuln,secret,misconfig myimage:tag
trivy fs   .                    # source tree and lockfiles
trivy config k8s/               # misconfiguration in manifests
trivy sbom  sbom.cdx.json       # scan an SBOM instead of an image
```

### `--ignore-unfixed` is a policy decision, not a default

It hides findings with no vendor patch available.

- **For it:** you cannot remediate them by rebuilding, so in a gate whose purpose
  is "rebuild to fix this", they are noise.
- **Against it:** "no fix available" is precisely the situation that needs a
  compensating control and a documented risk decision — and hiding it means
  nobody makes one.

Use it in the merge gate. Do **not** use it in the weekly report. That is how
this repo is configured.

### Air-gapped operation
```bash
trivy image --download-db-only                       # on a connected host
trivy --cache-dir ./cache image --skip-db-update IMG # transfer, then scan offline
```

---

## 8.3 Grype and Syft

```bash
syft myimage:tag -o cyclonedx-json=sbom.cdx.json
grype sbom:sbom.cdx.json -o table

grype myimage:tag --only-fixed --fail-on high
grype myimage:tag -o sarif --file grype.sarif
```

### Scan the SBOM, not the image

This is the better pipeline shape and it is worth restructuring for:

1. Generate the SBOM **once**, at build time, from the image you actually built.
2. Attach it to the image as an attestation (`cosign attest`).
3. Re-scan **that SBOM** every day.

Because vulnerability data changes and your image does not, an image that was
clean on Friday can be vulnerable on Tuesday with no commit involved. Re-scanning
the SBOM finds that without a rebuild, without a pull, and even for an image you
no longer have locally. That is what §4.3.7 (Monitoring) is asking for.

### `.grype.yaml` ignore rules
```yaml
ignore:
  - vulnerability: CVE-2024-00000
    package:
      name: libfoo
```
Grype's ignore format differs from `.trivyignore`. Keep them in sync, or your
two scanners will disagree for reasons unrelated to their matching logic.

---

## 8.4 SBOMs

An SBOM is the inventory step, made durable and portable. Two formats:

| | CycloneDX | SPDX |
|---|---|---|
| Steward | OWASP | Linux Foundation / ISO 5962 |
| Strength | security use cases, VEX | licensing, provenance |
| Use | vulnerability workflows | compliance, legal |

Generate both — it costs nothing:
```bash
syft IMG -o cyclonedx-json=sbom.cdx.json -o spdx-json=sbom.spdx.json
```

Attach the SBOM to the image so it travels with it:
```bash
cosign attest --predicate sbom.cdx.json --type cyclonedx IMG@sha256:<digest>
```

**VEX** (Vulnerability Exploitability eXchange) is the machine-readable version
of "we looked at this CVE and it does not apply, here is why". It is the right
long-term home for the reasoning that currently lives in `.trivyignore`
comments, because it is structured, signed, and consumable by your customer's
scanner as well as your own.

---

## 8.5 Gating without training people to ignore the gate

| Stage | Gate | Rationale |
|---|---|---|
| Pre-commit | none | too slow, too noisy |
| PR | fixable CRITICAL | fast signal on what the author can act on |
| Merge to main | fixable HIGH + CRITICAL | the release bar |
| Nightly | everything, including unfixed | the real posture; feeds risk decisions |
| Pre-release | everything + manual review | the AO's evidence |

The failure mode to design against: a gate that fires on things the developer
cannot fix. It gets bypassed within two sprints, and then it is not a gate.
Gate on *fixable* findings; report the rest.

```bash
trivy image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 IMG
grype IMG --only-fixed --fail-on high
```

### Exceptions need an owner and an expiry

See [`.trivyignore`](../.trivyignore), which is deliberately empty and carries
the template instead:

```
CVE-2024-00000 exp:2026-09-01
# owner:   platform-team
# finding: heap overflow in libfoo's XML parser
# why:     Red Hat rates this Low and will not fix. libfoo is present only as a
#          transitive dependency of libbar; the XML entry point is not compiled
#          in (verified with nm -D) and the application never calls it.
# review:  Remove when libbar 2.x drops the dependency. JIRA PLAT-1234.
```

Without an expiry, an exception granted for "two weeks until upstream patches"
is still there three years later, hiding a CVE that has had a fix since 2023.
This is the "whitelist of findings" §4.3.4 describes — with the discipline that
makes it defensible instead of a place findings go to die.

---

## 8.6 Reducing findings honestly

Fewer packages, fewer CVEs. In order of effectiveness:

1. **Multi-stage builds** — the compiler and its dependency tree never ship.
2. **A smaller base** — `ubi9-minimal` over `ubi9`; distroless if you can accept
   the evidence trade-off ([docs/02](02-layer-by-layer-hardening.md)).
3. **`install_weak_deps=0` / `--no-install-recommends`** — do not install
   packages nobody asked for.
4. **Rebuild on a schedule** — most findings are fixed by an already-published
   patch. `make rebuild` (`--no-cache --pull`), weekly.
5. **Remove build tooling from the runtime image** — compilers, `curl`, `git`.

What does *not* count as reducing findings: adding them to the ignore file.

---

## 8.7 Also worth knowing

| Tool | Notes |
|---|---|
| **Trivy** | broadest coverage in one binary: vuln, secret, misconfig, licence, SBOM |
| **Grype** + **Syft** | best-in-class inventory; SBOM-first workflow |
| **Docker Scout** | integrated with Docker Desktop/Hub; good remediation advice |
| **Clair** | registry-side scanning; what Quay uses |
| **Anchore Enterprise** / **Prisma Cloud** | named in the DISA guide; policy engines with an audit trail |
| **ClamAV** | not a CVE scanner — malware. §4.3.2 puts it on dependencies before the build. |

---

**Next:** [9. The DevSecOps Pipeline](09-devsecops-pipeline.md)
