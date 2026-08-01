# 5. OpenSCAP and the Tailoring (Answer) File

This is the tooling behind requirement **§2.16 — implement any STIG or SRG
guidance relevant to the container service**.

Run it:
```bash
make stig
```

---

## 5.1 The vocabulary, because the acronyms are half the difficulty

| Term | What it actually is |
|---|---|
| **SCAP** | Security Content Automation Protocol. An umbrella standard for machine-readable security policy. |
| **XCCDF** | The checklist language. Rules, groups, profiles, values. "What must be true." |
| **OVAL** | The check language. "Here is how to test whether it is true." |
| **Datastream** | One XML file bundling the XCCDF, OVAL, and CPE content. `ssg-rhel9-ds.xml`. |
| **Profile** | A named subset of the rules in a benchmark. `..._profile_stig` is the DISA STIG one. |
| **SSG** | SCAP Security Guide. The open-source project that publishes the content, shipped as the `scap-security-guide` RPM. |
| **Tailoring file** | A separate XCCDF document that modifies a profile — the "answer file". |
| **ARF** | Asset Reporting Format. The results bundle STIG Viewer and eMASS ingest. |
| **CPE** | Platform identifiers. How the content decides a rule cannot apply here. |
| **CCI** | Control Correlation Identifier. Ties a rule back to a NIST 800-53 control. |
| **STIG ID / V-ID** | DISA's identifier for a requirement, e.g. `RHEL-09-211010`, `V-257777`. |

Two sources of the same content, and you should know which you are using:

- **SSG / `scap-security-guide` RPM** — the upstream project's rendering of the
  STIG, updated frequently, includes automated remediation scripts. This is what
  `make stig` uses.
- **DISA's published SCAP benchmark** from <https://public.cyber.mil/stigs/scap/>
  — the authoritative content, released on DISA's cadence. This is what an
  assessor is most likely to run.

They track each other closely but not perfectly. If your assessment will use the
DISA benchmark, scan with the DISA benchmark. Pass `DATASTREAM=/path/to/it` to
[`oscap/scan.sh`](../oscap/scan.sh).

---

## 5.2 Two ways to scan an image

### (a) `oscap-podman` — scan the image from outside

```bash
sudo oscap-podman registry.access.redhat.com/ubi9/ubi:9.6 \
  xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_stig \
  --results-arf arf.xml --report report.html \
  /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml
```

Cleanest option — it mounts the image's filesystem and scans it offline, with no
scanner packages inside the image. Requires podman and `openscap-utils` on the
scanning host. `oscap-docker` is the equivalent for Docker but is
less maintained.

### (b) Scanner layer — `FROM` the image, install oscap, scan from inside

This is what this repo does ([`oscap/Containerfile.scan`](../oscap/Containerfile.scan)),
because it works identically under Docker, podman, and any CI runner, with no
privileged host access.

The cost, and you should note it in your report: the scanner packages are
present *during* the scan, which can shift a few "installed package" findings.
The scanner image is a throwaway artifact — it is never what you ship.

---

## 5.3 Reading the results

`make stig` produces, per run:

```
results/baseline/          the published profile, untouched
results/tailored/          the answer file applied
  ├── report.html          open this first
  ├── results-arf.xml      the artifact for STIG Viewer / eMASS
  ├── results-xccdf.xml    results only
  ├── summary.txt          counts + score
  └── failed-rules.txt     just the rule ids that failed
```

### Result values

| Value | Meaning | What to do |
|---|---|---|
| `pass` | check succeeded | nothing |
| `fail` | check failed | fix it, or justify it — those are the only two options |
| `notapplicable` | **OpenSCAP** decided the rule cannot apply (CPE logic) | nothing; this is automatic |
| `notselected` | **a human** deselected it via a tailoring file | be ready to defend it |
| `notchecked` | no automated check exists — manual review required | review it manually and record the result |
| `error` / `unknown` | the probe could not run | investigate; do not treat as a pass |
| `fixed` | remediation was applied and the recheck passed | verify it persisted |

`notapplicable` and `notselected` mean very different things and it is worth
being pedantic about it. The first is the content saying "this rule is about a
bootloader and you have no bootloader". The second is *you* saying so. Only the
second one requires you to have written down why.

### Exit codes — the thing that breaks everyone's first pipeline

```
0  every selected rule passed
1  oscap itself errored (bad profile id, missing datastream)   <- a real failure
2  the scan ran fine and at least one rule failed              <- normal
```

Treating `2` as failure means your pipeline is red from day one. Gate on the
score or on a specific set of rules instead. See
[`oscap/scan.sh`](../oscap/scan.sh) and
[`.github/workflows/stig.yml`](../.github/workflows/stig.yml).

### Useful one-liners

```bash
# list the profiles a datastream offers
oscap info /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml

# what does one rule actually check, and what is the fix?
oscap info --fetch-remote-resources --profile stig ssg-rhel9-ds.xml
oscap xccdf generate fix --profile stig --fix-type bash ssg-rhel9-ds.xml > fix.sh

# generate the remediation for exactly the rules that failed
oscap xccdf generate fix --result-id "" results-arf.xml > remediate-failures.sh
```

That last one is the useful workflow: scan, generate the fix for what failed,
**read it**, and hand-write the deliberate version into your hardening scripts.

---

## 5.4 The tailoring file — what it is and what it is not

A published profile is fixed content. Your assessor has the same copy. You do
not edit it. When a rule does not apply to your system, or your organisation has
approved a different value, you record that decision in a separate **XCCDF
Tailoring document** that *extends* the published profile.

Everyone calls it an "answer file". Same thing.

A tailoring file can do three things:

1. **Unselect a rule** → result becomes `notselected`, excluded from the score.
   This is how Not Applicable is expressed.
2. **Select a rule** the base profile left out — for a local policy stricter
   than the STIG.
3. **Change a value** (`refine-value` / `set-value`) — e.g. minimum password
   length 15 → 20.

**What it cannot do is make a failing rule pass.**

> Unselecting a rule you simply have not fixed is not tailoring. It is a
> risk-acceptance decision disguised as XML, and it hides the finding from your
> own dashboards as well as from your assessor.

A rule belongs in the answer file when implementing it inside a container image
is *technically impossible or meaningless* — the control belongs to the node, the
kernel, or the orchestrator. Everything else that you cannot fix in time is a
waiver or a POA&M: [docs/12](12-waivers-and-poam.md).

---

## 5.5 Generating the answer file

### The approach used here: a documented rule list + `autotailor`

The source of truth is a plain text file with a justification above each rule:
[`oscap/not-applicable.rules`](../oscap/not-applicable.rules).

```
# DNS resolver configuration. Inside a container /etc/resolv.conf is generated
# and bind-mounted at runtime by the container engine or by the kubelet...
xccdf_org.ssgproject.content_rule_network_configure_name_resolution
```

[`oscap/generate-tailoring.sh`](../oscap/generate-tailoring.sh) feeds those ids
to `autotailor` and then injects each justification back into the XML as a
comment above its `<select>` element, so the answer file is self-documenting when
an assessor opens it.

```bash
autotailor \
  -o tailoring.xml \
  -p xccdf_mil.disa.stig_profile_stig_container \
  --title "DISA RHEL 9 STIG - Container Tailored" \
  -u xccdf_org.ssgproject.content_rule_network_configure_name_resolution \
  -u xccdf_org.ssgproject.content_rule_configure_crypto_policy \
  /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml \
  xccdf_org.ssgproject.content_profile_stig
```

Why this way round: the justifications live in a reviewable text file that shows
up properly in a pull request diff, and the XML is generated, so the two cannot
drift apart. Reviewing a change to an answer file should be reviewing a change to
*the reasoning*.

### Alternative: SCAP Workbench (the GUI)

```bash
dnf install scap-workbench
scap-workbench /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml
```

Pick the profile → **Customize** → uncheck rules, edit values → save the
customisation as a tailoring file. Good for exploring the rule tree and reading
descriptions and fixes. Less good as a source of truth: the output is a blob of
XML in your repo whose diffs nobody can review.

### Alternative: write it by hand

Fully annotated example: [`oscap/tailoring/example-tailoring.xml`](../oscap/tailoring/example-tailoring.xml).
The skeleton:

```xml
<xccdf-1.2:Tailoring xmlns:xccdf-1.2="http://checklists.nist.gov/xccdf/1.2"
                     id="xccdf_mil.disa.stig_tailoring_container">
  <xccdf-1.2:benchmark href="/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml"/>
  <xccdf-1.2:version time="2026-08-01T00:00:00">1</xccdf-1.2:version>

  <xccdf-1.2:Profile id="xccdf_mil.disa.stig_profile_stig_container"
                     extends="xccdf_org.ssgproject.content_profile_stig">
    <xccdf-1.2:title override="true">DISA RHEL 9 STIG - Container Image</xccdf-1.2:title>

    <!-- Not Applicable: resolv.conf is injected by the kubelet at runtime. -->
    <xccdf-1.2:select idref="xccdf_org.ssgproject.content_rule_network_configure_name_resolution"
                      selected="false"/>

    <!-- Local policy is stricter than the STIG minimum of 15. -->
    <xccdf-1.2:refine-value idref="xccdf_org.ssgproject.content_value_var_password_pam_minlen"
                            selector="20"/>
  </xccdf-1.2:Profile>
</xccdf-1.2:Tailoring>
```

Validate before you trust it:
```bash
oscap xccdf validate tailoring.xml
oscap info tailoring.xml            # confirms the profile id you must pass
```

---

## 5.6 Scanning with the answer file

```bash
oscap xccdf eval \
  --profile xccdf_mil.disa.stig_profile_stig_container \
  --tailoring-file tailoring.xml \
  --results-arf results-arf.xml \
  --report report.html \
  /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml
```

**The mistake everyone makes once:** `--profile` must be the **new** id defined
*inside* the tailoring file, not the base profile it extends. Pass the base id
and oscap exits 1 with "profile not found" — or, worse in older versions, runs
the untailored profile and gives you results that look plausible and are wrong.

---

## 5.7 Baseline versus tailored, and why you run both

`make stig` runs the scan twice on purpose:

- **Baseline** — the published DISA profile, untouched. This is the number an
  assessor would get. It is the honest number.
- **Tailored** — the answer file applied.

The **delta between them is your Not Applicable list**, and it is exactly what
you will be asked to defend. Tracking both means:

- you always know what the unadjusted posture is;
- an answer file that grows shows up as a growing delta, in a diff, in a PR,
  rather than as a score that mysteriously improved.

Set a threshold on the tailored score only once you have a baseline you trust —
and treat any *drop* as a review trigger. A hard "100% or fail" gate on a RHEL
STIG applied to a container produces exactly one behaviour: people add rules to
the answer file until it goes green.

---

## 5.8 Feeding STIG Viewer and eMASS

The ARF (`results-arf.xml`) is the deliverable.

- **STIG Viewer** (<https://public.cyber.mil/stigs/srg-stig-tools/>): import the
  STIG `.xml`, then import the ARF to auto-populate the checklist and export a
  `.ckl`. Rules the scan could not check (`notchecked`) still need a manual
  answer and a comment.
- **eMASS**: ingests the ARF or the exported `.ckl` as assessment evidence.

Attach it to the image itself so the evidence travels with the artifact:
```bash
cosign attest --predicate results-arf.xml --type https://disa.mil/stig/arf \
  registry.example.mil/team/app@sha256:<digest>
```

---

## 5.9 Failure modes worth knowing about

| Symptom | Cause |
|---|---|
| `Profile not found` | passed the base profile id instead of the tailored one, or a typo in `-p` |
| Everything `notchecked` | the OVAL content did not load — usually a datastream/profile mismatch |
| Score improves with no change | the answer file grew. Diff `not-applicable.rules`. |
| Remediation "succeeds" but the rule still fails | the fix ran `systemctl`/`grubby` in a container and half-worked |
| Different results on the same image | scanner packages present in one run, or a different SSG content version |
| Hundreds of `notapplicable` | normal and correct — CPE logic excluding host-only rules |

---

## 5.10 What OpenSCAP does not tell you

It evaluates the **operating system inside the image** against an OS STIG. It
does not know about:

- CVEs in your application's dependencies → [Trivy and Grype](08-trivy-and-grype.md)
- credentials in the image or the git history → [TruffleHog](07-trufflehog.md)
- how the image was *built* → [hadolint](06-hadolint.md)
- how it is *deployed* → [section 3](04-deployment-requirements.md)
- the application technology's own STIG/SRG (web server, database, ...)

A green OpenSCAP score is one control passing, not a secure container.

---

**Next:** [6. hadolint](06-hadolint.md)
