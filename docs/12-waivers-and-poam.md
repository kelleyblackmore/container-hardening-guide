# 12. Waivers, POA&Ms, and Not Applicable

The DISA guide anticipates that you will not meet every requirement. It says so
three times:

> **§2:** waivers may be required from the organization's security team in some
> cases where the requirement cannot be followed completely.

> **§2.6:** Short lived containers that do not require a health check can be
> submitted for a waiver.

> **§2.16:** In cases where a traditional STIG may not entirely apply for a scan
> of a container, or a container may need to run as root as an exception, a
> waiver will need to be approved.

The requirement is not perfection. It is that every gap is **identified, decided
by someone with the authority to decide it, and written down**.

---

## 12.1 Three different things people call "an exception"

Getting these confused is the most common failure in container compliance, and
it is the one that gets audited.

| | **Not Applicable** | **Waiver / risk acceptance** | **POA&M** |
|---|---|---|---|
| Means | the control cannot apply here | it applies, we are not doing it | it applies, we will do it later |
| Because | technically impossible or meaningless | operational necessity | not done yet |
| Example | `grub2_password` — a container has no bootloader | a vendor image must run as root | 40 STIG findings, fixed over two sprints |
| Recorded in | the tailoring/answer file | a signed waiver | the POA&M, with dates |
| Approved by | the engineer, reviewed | the AO | the AO |
| Expires | no — it is a permanent property | yes | yes, by definition |
| Effect on the score | excluded (`notselected`) | still fails | still fails |

**The one rule:** a rule goes in the answer file **only** when implementing it
inside the container is technically impossible or meaningless. Everything else
that you are not doing is a waiver or a POA&M, and it stays visible in your
score.

Deselecting a rule you simply have not fixed is not tailoring. It removes the
finding from your dashboards as well as from your assessor's, which means the
next engineer inherits a system that looks compliant and is not. That is worse
than a red score, because a red score is at least true.

---

## 12.2 Not Applicable: how to write one

Format used in [`oscap/not-applicable.rules`](../oscap/not-applicable.rules).
The comment block above each rule is injected into the generated answer file as
an XML comment, so this text is what an assessor reads inside the artifact.

```
# The audit daemon runs on the node and captures syscalls for every container on
# it. Running auditd inside an unprivileged container is not possible: it needs
# CAP_AUDIT_CONTROL and a netlink socket the namespace does not provide, and if
# it did run it would produce duplicate, unattributable records. The control is
# satisfied at the node, which is assessed under the RHEL 9 STIG separately.
xccdf_org.ssgproject.content_rule_service_auditd_enabled
```

A good justification answers three questions:

1. **What does the rule require?** In your own words, not a copy of the title.
2. **Why can it not be done here?** The specific mechanism — the capability that
   is missing, the file the runtime overwrites, the kernel interface the
   namespace does not expose. "Not applicable to containers" is not a
   justification, it is a restatement.
3. **Where is the control satisfied instead?** Almost every N/A rule is
   applicable *somewhere* — the node, the orchestrator, the CNI. Say where, so
   the reviewer can go check that it is covered there.

A justification that would embarrass you if it were read aloud in an assessment
is a waiver wearing a costume.

---

## 12.3 Waiver: how to write one

A waiver is a decision to run with a known, unmitigated gap. Minimum content:

```markdown
## WAIVER-2026-001 — helloctr runs with CAP_NET_BIND_SERVICE

**Requirement:** DISA Container Guide V2R0.6 §2.5 — expose only non-privileged
ports. CCI-001762.

**System:** helloctr, registry.example.mil/team/helloctr, all environments.

**Gap:** the container binds TCP/443 directly and therefore requires
CAP_NET_BIND_SERVICE, rather than listening on 8443 and being mapped by the
platform.

**Why it cannot be met:** the service terminates TLS for a legacy client that
does not follow redirects and has a hardcoded port. Vendor EOL is 2027-Q2.

**Risk:** a compromise of the process could bind other privileged ports in the
container's network namespace. It cannot bind on the node — the namespace is not
shared (§3.10) — so the impact is limited to this pod's network namespace.

**Compensating controls:**
- capabilities.drop: [ALL], with only NET_BIND_SERVICE added back
- readOnlyRootFilesystem: true, runAsNonRoot: true
- NetworkPolicy restricts ingress to the ingress controller only
- seccompProfile: RuntimeDefault

**Duration:** approved to 2027-06-30, reviewed quarterly.

**Removal plan:** the legacy client is being replaced under PROJ-4412; when it
retires, the service moves to 8443 and the capability is dropped.

**Requested by:** platform-team · **Approved by:** <AO> · **Date:** 2026-08-01
```

The sections that matter most are **compensating controls** and **removal
plan**. A waiver with neither is a request to stop being asked.

---

## 12.4 POA&M

A Plan of Action and Milestones is for gaps you intend to close. What makes it
credible:

- one entry per finding, not one entry for "STIG findings";
- a named owner who knows they own it;
- a completion date that someone actually estimated;
- milestones for anything longer than a sprint;
- and it gets reviewed on a schedule, not rediscovered before an audit.

The mechanics matter less than the review cadence. A POA&M nobody reads is
indistinguishable from an undocumented gap, except that it took longer to
produce.

---

## 12.5 Where these live in this repository

| Type | File | Reviewed as |
|---|---|---|
| STIG rule Not Applicable | [`oscap/not-applicable.rules`](../oscap/not-applicable.rules) | a PR diff on the justification text |
| CVE accepted | [`.trivyignore`](../.trivyignore) | a PR diff, with owner and `exp:` |
| Deployment deviation | a comment in [`k8s/deployment.yaml`](../k8s/deployment.yaml) | manifest review |
| Lint rule ignored | [`.hadolint.yaml`](../.hadolint.yaml) | config review |

All four are plain text in version control, which gives you three things a
spreadsheet does not: a diff, an author, and a date. When an exception is added,
that is a reviewable change, not an edit nobody sees.

**Put `CODEOWNERS` on those files.** §4.3.4 builds in a separation of duties —
the contributor proposes a finding for the whitelist, the CVE Approver signs it
off. One person should not be able to both introduce a finding and excuse it.
In a small team, `CODEOWNERS` on the exception files is what buys you that.

---

## 12.6 Expiry, and why it is the important field

Every exception gets a date. Not because the risk changes on that date, but
because *nothing else forces a re-look*.

The failure mode is well documented and universal: an exception granted for "two
weeks until upstream patches" is still in the file three years later, hiding a
CVE that has had a fix since 2023. Nobody decided to keep it. Nobody decided
anything — that is the point.

```
CVE-2024-00000 exp:2026-09-01
```

Trivy honours `exp:` natively and the finding reappears when it lapses. For the
answer file and waivers, put the review date in the text and add a calendar
entry. A quarterly pass over all four files is thirty minutes and it is the
difference between a compliance posture and a compliance artifact.

---

## 12.7 The short version

- **Cannot possibly apply** → answer file, with a justification that names the
  mechanism and says where the control is satisfied instead.
- **Applies, not doing it** → waiver, with compensating controls and a removal
  plan, approved by the AO.
- **Applies, doing it later** → POA&M, with an owner and a date.
- **Everything** → in version control, with an expiry, reviewed by someone who
  did not write it.

A red score you can explain beats a green score you cannot.

---

**Back to:** [README](../README.md) · [compliance matrix](compliance-matrix.md)
