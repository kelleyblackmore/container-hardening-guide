# 6. hadolint — Linting the Build File

hadolint parses a Dockerfile into an AST, applies its own rules (`DL####`), and
runs ShellCheck (`SC####`) against the body of every `RUN`.

It is the cheapest control in this repository: sub-second, no network, no
daemon, no image required. Put it in your pre-commit hook.

**It is also the most limited.** hadolint reads *instructions*. It never sees the
image. It cannot tell you about a CVE, a secret in a base layer, a setuid binary
the base shipped, or a STIG finding. Section 5.3 of `make lint-insecure` exists
to make that concrete — run it and count how many of the documented violations
in the anti-pattern Dockerfile hadolint actually reports.

---

## 6.1 Install and run

```bash
make install-tools          # or:
brew install hadolint
docker run --rm -i hadolint/hadolint < Dockerfile

# this repo
make lint                   # hardened Dockerfile - must pass
make lint-insecure          # anti-pattern - findings are the expected output
```

```bash
hadolint --config .hadolint.yaml examples/hardened/Dockerfile
```

---

## 6.2 Configuration

[`.hadolint.yaml`](../.hadolint.yaml), annotated in full in the file itself. The
two settings that matter:

```yaml
failure-threshold: warning     # what causes a non-zero exit

allowed-registries:            # enforces requirement 2.17 at lint time
  - registry1.dso.mil
  - registry.access.redhat.com
```

`allowed-registries` is the one people miss. It turns "base images must come from
an approved source" from a policy sentence into a build failure (`DL3026`). In a
DoD pipeline this list has **one** entry.

### Ignoring rules

Every ignore needs a written reason in the file. An `.hadolint.yaml` with a long
unexplained ignore list is how a linter quietly stops linting.

This repo ignores exactly one rule, `DL3041` (pin RPM versions), with the
reasoning spelled out: pinning makes builds reproducible (§2.4) but makes them
rot (§2.15), and the position taken here is a digest-pinned base plus a full
`dnf upgrade` on every build. Agree or disagree — but the decision is written
down.

Inline suppression, when it is genuinely a one-off:
```dockerfile
# hadolint ignore=DL3008
RUN apt-get install -y --no-install-recommends somepkg
```

---

## 6.3 The rules that map to DISA requirements

| Rule | What it catches | Requirement |
|---|---|---|
| `DL3002` | last `USER` is root | §2.2 |
| `DL3006` | image referenced without a tag | §2.14 |
| `DL3007` | `:latest` tag | §2.14, §2.15 |
| `DL3026` | `FROM` outside `allowed-registries` | §2.17 |
| `DL3020` | `ADD` used for a local file | §2.4 |
| `DL3025` | `CMD`/`ENTRYPOINT` in shell form | signal handling |
| `DL3009` | apt lists not deleted | §2.8 |
| `DL3015` | no `--no-install-recommends` | §2.12 |
| `DL3059` | consecutive `RUN` instructions | §2.8 |
| `DL4006` | pipe in `RUN` without `pipefail` | §2.4 |
| `DL4001` | both `curl` and `wget` present | §2.12 |
| `DL3001` | `ssh`, `vim`, `shutdown`, `ps` in a `RUN` | §2.1, §2.12 |
| `SC2086` | unquoted variable | correctness |

`DL4006` deserves a note. Under the default `sh -c`, a pipeline reports the exit
status of the *last* command, so `false | true` succeeds. A failing verification
step on the left of a pipe silently passes the build. The fix is one line:

```dockerfile
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
```

---

## 6.4 What hadolint does not catch

Run `make lint-insecure` and compare its output to the violations documented in
[`examples/insecure/Dockerfile`](../examples/insecure/Dockerfile). hadolint finds
a fraction of them. It has no way to see:

| Miss | Why | Caught by |
|---|---|---|
| Secrets in `ENV`/`ARG` | it is syntactically valid | TruffleHog, Trivy secret scanner |
| CVEs in installed packages | it never resolves packages | Trivy, Grype |
| setuid binaries from the base | it never opens the image | `find -perm /6000` in CI |
| STIG findings | different domain entirely | OpenSCAP |
| Whether the base image is signed | no registry access | cosign |
| Deleted-but-still-in-a-layer files | no layer awareness | TruffleHog `docker` mode |
| Missing `HEALTHCHECK` | no rule for it | `docker inspect` assertion in CI |
| Whether the image runs read-only | it does not run anything | `make verify` |
| A **single-stage build** shipping the compiler | there is no rule for it | `make compare-stages`, [docs/13](13-multi-stage-builds.md) |

That last row is worth trying yourself:

```bash
hadolint --config .hadolint.yaml examples/single-stage/Dockerfile   # exits 0
```

[`examples/single-stage/Dockerfile`](../examples/single-stage/Dockerfile) passes
hadolint **cleanly**. It has a `USER`, a tagged base from an allowed registry, a
`HEALTHCHECK`, exec-form `ENTRYPOINT`, no `ADD`, no secrets — every rule
satisfied. It also produces an image roughly 2.3x the size of the hardened one,
containing the Go compiler, git, and your source code, with 12 fixable HIGH
CVEs.

A linter checks the instructions you wrote. It has no opinion about the
*architecture* of your build, and that is where most of the size and most of the
attack surface is decided.

The "Caught by" column above is the rest of the pipeline. hadolint is the first
gate, not the gate.

---

## 6.5 In a pipeline

Pre-commit:
```yaml
repos:
  - repo: https://github.com/hadolint/hadolint
    rev: v2.12.0
    hooks:
      - id: hadolint-docker
```

GitHub Actions — see [`ci.yml`](../.github/workflows/ci.yml). Two invocations,
deliberately:

- the hardened Dockerfile, **blocking**;
- the anti-pattern, **non-blocking**, with the output written to the job summary,
  because the interesting part is the gap between what it caught and what the
  file documents.

SARIF output for inline PR annotations:
```bash
hadolint --format sarif Dockerfile > hadolint.sarif
```

---

**Next:** [7. TruffleHog](07-trufflehog.md)
