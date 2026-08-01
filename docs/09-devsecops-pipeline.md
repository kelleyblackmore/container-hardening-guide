# 9. The DevSecOps Pipeline

> DISA Container Image Creation and Deployment Guide V2R0.6, §4
> — full text: [`reference/`](../reference/DISA-Container-Image-Creation-and-Deployment-Guide-V2R0.6.md#4-devsecops)

Section 4 describes the process the controls live inside. It is deliberately not
prescriptive:

> Section 4 describes Development, Security and Operations (DevSecOps) in
> general, since each project will have different needs dependent on the service
> being developed. The guide does not give specific tasks or settings to
> implement.

This page maps its stages onto concrete jobs. The implementation is
[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) and
[`stig.yml`](../.github/workflows/stig.yml).

---

## 9.1 The stages

| Guide stage | § | What happens | In this repo |
|---|---|---|---|
| Coding & Testing | 4.3.1 | static analysis, code review, unit tests | `lint` job — hadolint, shellcheck |
| Building | 4.3.2 | controlled dependencies, AV scan, build, push to artifact repo | `build` job |
| Securing | 4.3.3 | **multiple** vulnerability scanners, findings triage | `secrets`, `vulnerability`, `evidence`, `stig` |
| Publishing | 4.3.4 | resolve findings, produce the whitelist, stage artifacts | `.trivyignore`, `not-applicable.rules` + review |
| Releasing | 4.3.5 | AO approval, sign, checksum, publish with artifacts | *not in this repo — described below* |
| Configuring | 4.3.6 | infrastructure as code, manifests through the same pipeline | `k8s-policy` job |
| Monitoring | 4.3.7 | continuous re-scan of the registry and running services | scheduled workflows |

This repository publishes nothing, so 4.3.4 and 4.3.5 are documented rather than
implemented. Everything else runs.

---

## 9.2 Coding and testing (4.3.1)

The contributor's job, before the pipeline sees anything:

```bash
make lint              # hadolint
make lint-shell        # shellcheck on the hardening scripts
python3 scripts/check-k8s-policy.py k8s/
```

Pre-commit is the cheapest place to catch a secret, a `:latest` tag, or an `ADD`
with a URL. Add hadolint and TruffleHog hooks and most of this never reaches CI.

The guide's point about **standards for contribution** matters more than the
tooling:

> To enable the Iron Bank pipeline to ingest the pull request (PR) from the
> contributor, standards are set for the form of the artifacts and what those
> artifacts are permitted to contain.

If your pipeline cannot state what an acceptable submission looks like, every PR
is a negotiation.

---

## 9.3 Building (4.3.2)

> Though the dependencies come from trusted sources, they are run through Clam
> AntiVirus (AV) to check for viruses and malware. Once the dependencies are
> determined to be secure, they are moved to the artifact repository and there is
> no need to reach outside the Iron Bank infrastructure for the build.

Two requirements hiding in that paragraph:

1. **Dependencies are scanned before the build, not after.** ClamAV is looking
   for malware, which is a different question from CVEs.
2. **The build does not reach the internet.** Dependencies come from an internal
   artifact repository that has already vetted them. This is §2.4's "ensure
   containers can be built without connection to the internet", made
   operational.

```yaml
- uses: docker/build-push-action@v6
  with:
    no-cache: true      # §2.8 - a cache hit is a layer that was not re-patched
    pull: true          # §2.15 - re-resolve the base so updates are picked up
```

`no-cache` in the security pipeline is not a performance regression to be
optimised away. A cache hit means those packages were **not** re-patched.

---

## 9.4 Securing (4.3.3)

Four independent scans, because they answer four different questions:

| Job | Question | Tool |
|---|---|---|
| `secrets` | is there a live credential in here? | TruffleHog |
| `vulnerability` | are there known CVEs? | Trivy **and** Grype |
| `evidence` | does the image meet the §2 requirements? | `docker inspect` assertions |
| `stig` | does the OS meet the STIG? | OpenSCAP |

The `evidence` job is the one people skip, and it is the cheapest and most
deterministic of the four. It catches the regressions a scanner never will:
somebody deleting the `USER` line, adding `EXPOSE 22`, or reintroducing a setuid
binary. Assertions, not scans — they either hold or they do not.

---

## 9.5 Publishing (4.3.4)

> Each vulnerability is either signed off by the Iron Bank CVE Approver, creating
> a whitelist of findings, or is resolved by the contributor.

The whitelist is the deliverable of this stage. In this repo it is
[`.trivyignore`](../.trivyignore) and
[`oscap/not-applicable.rules`](../oscap/not-applicable.rules), and the discipline
around both is the same:

- a written justification;
- a named owner;
- an expiry date;
- review by someone other than the author.

Note the separation of duties the guide builds in: the **contributor** proposes,
the **CVE Approver** signs off. One person cannot both introduce a finding and
excuse it. In a small team, that is what CODEOWNERS on those two files buys you.

---

## 9.6 Releasing (4.3.5) — not implemented here

> The first step in releasing the container image to the public is getting
> approval from the Authorizing Official (AO)... the image will be signed, and a
> checksum generated.

What the publish job looks like:

```yaml
publish:
  needs: [evidence, secrets, vulnerability]
  permissions:
    contents: read
    packages: write
    id-token: write            # keyless signing via OIDC
  steps:
    - uses: docker/build-push-action@v6
      id: push
      with:
        push: true
        tags: ghcr.io/org/app:${{ github.sha }}
        provenance: mode=max   # SLSA build provenance
        sbom: true             # attach an SBOM attestation
        # attestations require the OCI exporter - they cannot be produced
        # alongside `load: true`, which is why CI's build job turns them off

    - uses: sigstore/cosign-installer@v3
    # sign the DIGEST, never the tag - the tag can be moved afterwards
    - run: cosign sign --yes ghcr.io/org/app@${{ steps.push.outputs.digest }}
    - run: |
        cosign attest --yes --type cyclonedx --predicate sbom.cdx.json \
          ghcr.io/org/app@${{ steps.push.outputs.digest }}
        cosign attest --yes --type https://disa.mil/stig/arf \
          --predicate results/tailored/results-arf.xml \
          ghcr.io/org/app@${{ steps.push.outputs.digest }}
```

Three things worth stating explicitly:

- **Sign the digest, not the tag.** Signing `app:1.2.3` and then moving the tag
  produces a valid signature over different bytes.
- **Publish the artifacts alongside the image** — scan reports, the answer file,
  the whitelist, the README, the licences. §4.3.5 lists them for a reason: the
  evidence has to travel with the thing it describes.
- **Verify at admission**, or none of the above changes what runs. A signature
  nobody checks is a checksum with extra steps.

```yaml
# Kyverno - reject anything not signed by our identity
verifyImages:
  - imageReferences: ["ghcr.io/org/*"]
    attestors:
      - entries:
          - keyless:
              subject: "https://github.com/org/repo/.github/workflows/ci.yml@refs/heads/main"
              issuer: "https://token.actions.githubusercontent.com"
```

---

## 9.7 Configuring (4.3.6)

> By moving the code for the infrastructure through the pipeline with the
> container image, the infrastructure is also validated for security and
> function.

The manifests are code and go through the same review, the same linting, and the
same gates. That is the `k8s-policy` job: kube-linter (advisory), an explicit
assertion of the §3 requirements (blocking), and schema validation.

Advisory versus blocking is a deliberate split. Third-party linters change their
default check sets between releases, and a merge gate whose behaviour changes
when a tool auto-updates is a gate people learn to bypass. The blocking checks
are ours and they do not drift.

---

## 9.8 Monitoring (4.3.7)

> Performing continuous scans of the repository and running services allows new
> vulnerabilities or security risks to be quickly detected and addressed.

**This is the stage most pipelines skip, and it is the one that finds the most.**
Your image does not change; the vulnerability data does. An image that was clean
at release becomes vulnerable on its own.

Three scheduled jobs, none of which need a commit:

```yaml
on:
  schedule:
    - cron: '17 6 * * 1'     # weekly: re-scan the published image
    - cron: '43 5 * * 2'     # weekly: re-run the STIG evaluation
    # and: nightly rebuild with --no-cache --pull, then compare findings
```

Re-scan the **SBOM** rather than the image where you can — same answer, no pull,
and it works for images you no longer hold locally.

At the cluster, the same principle applies to what is actually running: Falco or
Tetragon for runtime behaviour, and an admission policy engine that keeps
enforcing after deploy time rather than only at it.

---

## 9.9 A minimum honest pipeline

If you implement nothing else from section 4:

1. `hadolint` on every PR — seconds, no infrastructure.
2. Two CVE scanners on every build, gating on **fixable** HIGH/CRITICAL.
3. TruffleHog over git history and image layers, gating on **verified**.
4. The `evidence` assertions — non-root, no sshd, no setuid, non-privileged
   ports, health check.
5. A **scheduled rebuild and re-scan**, at least weekly.
6. Pod Security Admission `restricted` on the namespace.

Items 4, 5, and 6 are the ones usually missing, and they are the cheapest three
on the list.

---

**Next:** [10. STIG a Container — Walkthrough](10-stig-a-container-walkthrough.md)
