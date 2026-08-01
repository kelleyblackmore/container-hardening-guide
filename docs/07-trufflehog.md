# 7. TruffleHog — Finding Embedded Credentials

Requirements **§2.9** (no confidential data in the build files) and **§2.18**
(clear of embedded credentials).

```bash
make scan-secrets
```

---

## 7.1 Why a dedicated tool

The obvious approach — grep for `password=` — fails in both directions. It misses
a base64 blob, a PEM body, and a 40-character hex API key. It also fires on every
`password` string in every test fixture and vendored library, which trains
everyone to ignore it.

TruffleHog runs ~800 **detectors**, each of which knows the *shape* of one
provider's credential, and then — this is the part that matters —
**verifies** it by calling that provider's API.

| Result | Meaning | Response |
|---|---|---|
| `verified` | the provider confirmed the credential **works** | an incident, right now |
| `unknown` | matched, but the provider could not be reached or has no verification endpoint | a human must look |
| `unverified` | matched, provider says it is dead | review — dead keys mean live ones are coming |

Verification is what makes the tool usable in a merge gate. A verified finding
has essentially no false positives, so blocking on it does not train people to
click through.

**Caveat:** verification makes outbound calls to the credential's provider. In a
classified or air-gapped environment that may be prohibited. Run with
verification off and triage `unknown` findings by hand — accepting that you have
lost the property that made the gate cheap.

---

## 7.2 The three surfaces

You have to scan all three, and most people scan one.

### 1. Git history
```bash
trufflehog git file://. --only-verified
```
Walks every commit on every branch. This is the scan that finds the credential
somebody committed in 2023 and "removed" in the next commit.

**A deleted file is still in the history.** `git log -p` hands it back. So does
any clone, any fork, and GitHub's API for a while even after a force-push.

Use `fetch-depth: 0` in CI. The default shallow checkout scans one commit and
reports clean.

### 2. Working tree
```bash
trufflehog filesystem . --only-verified --exclude-paths scripts/trufflehog-exclude.txt
```
Includes untracked and `.gitignore`d files — which is exactly where `.env`,
`kubeconfig`, and `terraform.tfvars` live. `.gitignore` keeps a file out of git;
it does not keep it out of the Docker build context.

### 3. Image layers
```bash
trufflehog docker --image docker://localhost/helloctr:latest --only-verified
```
Extracts every layer and scans each independently. This is the one that catches:

```dockerfile
COPY secrets.env /tmp/secrets.env         # layer N: the token is here
RUN ./configure.sh && rm /tmp/secrets.env # layer N+1: a whiteout marker
```

The final filesystem is clean. Layer N still contains the token and still ships
on every pull. See [docs/01 §1.3](01-anatomy-of-a-container-image.md).

Also scan the config, which layer scanning does not cover:
```bash
docker history --no-trunc IMG | grep -Ei 'password|secret|token|api[_-]?key'
docker inspect --format '{{json .Config.Env}}' IMG
```
`ENV` and `ARG` values live in the image config, not in a layer.

---

## 7.3 When it finds one

**Rotate first.** Everything else is cleanup.

1. **Rotate the credential at the provider.** Immediately, before you touch the
   repository. Assume anything pushed is compromised from the moment of the push
   — public repos are scraped by bots within seconds.
2. **Check the provider's audit log** for use you did not authorise.
3. *Then* clean the history — `git filter-repo` or BFG — and force-push, knowing
   that forks and existing clones still have it. This is hygiene, not
   remediation.
4. **Rebuild and republish** any image built from the affected commit.
5. **Fix the process** that let it in.

Rewriting history without rotating is the single most common mistake in this
area. It makes the finding disappear from your scan while leaving the credential
live.

---

## 7.4 Not putting them there in the first place

### Build-time secrets: BuildKit mounts
The secret is mounted into a tmpfs for one `RUN` and never written to a layer.

```dockerfile
RUN --mount=type=secret,id=npmtoken \
    NPM_TOKEN="$(cat /run/secrets/npmtoken)" npm ci
```
```bash
DOCKER_BUILDKIT=1 docker build --secret id=npmtoken,env=NPM_TOKEN .
```

Verify it worked:
```bash
docker history --no-trunc IMG | grep -i npmtoken     # should find nothing
```

Never use `ARG` for a secret. `ARG` values are in the image config and in
`docker history`, and they persist even if the variable is "unset" later.

### Run-time secrets: mounted files
```yaml
env:
  - name: APP_SECRET_FILE           # a PATH, not a secret
    value: /run/secrets/app/token
volumeMounts:
  - { name: app-secret, mountPath: /run/secrets/app, readOnly: true }
volumes:
  - name: app-secret
    secret: { secretName: helloctr-token, defaultMode: 0400 }
```

**Files, not environment variables.** Env vars leak through
`/proc/<pid>/environ` (readable by anything sharing the PID namespace), crash
dumps, `docker inspect`, and every logging library that dumps the environment on
start-up. A mounted file also rotates without a pod restart.

Kubernetes `Secret` objects are base64-encoded, not encrypted. Enable encryption
at rest on etcd, and for anything real use Vault, SOPS, Sealed Secrets, or an
External Secrets operator.

### Pre-commit
```yaml
repos:
  - repo: https://github.com/trufflesecurity/trufflehog
    rev: v3.63.0
    hooks:
      - id: trufflehog
        entry: trufflehog git file://. --since-commit HEAD --only-verified --fail
```
The cheapest place to catch it is before the commit exists.

---

## 7.5 Configuration in this repo

[`scripts/scan-secrets.sh`](../scripts/scan-secrets.sh) runs all three surfaces
and exits non-zero on any verified finding, with the incident-response steps
printed rather than a bare exit code.

[`scripts/trufflehog-exclude.txt`](../scripts/trufflehog-exclude.txt) has exactly
three entries, each justified. Keep it that way: an exclude file is how a secret
scanner gets switched off one directory at a time. The usual sequence is
"exclude the noisy directory" followed six months later by "the credential was in
the excluded directory".

**Never exclude** `.env*`, `config/`, `secrets/`, `charts/`, or `terraform/`.

### Note on this repository's own findings

[`examples/insecure/Dockerfile`](../examples/insecure/Dockerfile) deliberately
contains credential-shaped strings. They are inert placeholders, which is why CI
gates on `--only-verified` and reports the unverified detections separately in
the job summary. Gating on unverified findings in a repo that contains teaching
examples would fail every run and teach everyone to ignore the gate.

**Which is how this repository ran into push protection.** The first version of
that file used realistic dummy credentials in each provider's real format.
GitHub's push protection matched the Stripe key pattern and **rejected the
push** — the repository could not be created until the string was changed. The
credentials were fake and the intent was educational; neither mattered, because
the pattern matched.

Two things worth taking from that:

1. **Turn push protection on.** Settings → Code security → Push protection. It
   is server-side, it runs on every push including force-pushes, and it stops
   the credential before it is ever public — which is the only intervention that
   actually prevents an incident rather than responding to one.
2. **It is a pattern matcher, not a judge.** It blocks realistic fakes and it
   misses anything without a well-known shape: an internal PKI key, a database
   password, a bespoke HMAC secret. It is one layer. TruffleHog's verification,
   the git-history scan, and the image-layer scan cover different ground.

---

## 7.6 Complementary tools

| Tool | Angle |
|---|---|
| **TruffleHog** | ~800 detectors, live verification, git/filesystem/image/S3/GitHub org |
| **Gitleaks** | fast regex + entropy, easy custom rules, no verification |
| **Trivy** `--scanners secret` | already in your pipeline, catches the common shapes |
| **GitHub secret scanning** | server-side, notifies the *provider*, who may auto-revoke |
| **`docker history`** | the config surface no layer scanner reads |

Run more than one. Detector coverage differs, exactly as it does for CVE
scanners ([docs/08](08-trivy-and-grype.md)).

---

**Next:** [8. Trivy and Grype](08-trivy-and-grype.md)
