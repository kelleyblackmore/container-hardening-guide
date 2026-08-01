#!/usr/bin/env bash
# =============================================================================
# scan-secrets.sh - hunt for credentials with TruffleHog
# =============================================================================
# DISA requirements:
#   2.9  The container image must be created without confidential data in the
#        build files.
#   2.18 The container image must be clear of embedded credentials.
#
# THE THING PEOPLE GET WRONG
#
#   Deleting a secret does not remove it. Both git and container images are
#   append-only layer stacks. `rm secrets.env` in a later commit or a later
#   RUN adds a deletion record; the bytes are still in the earlier object and
#   still ship to everyone who clones or pulls. `docker history --no-trunc` and
#   `git log -p` will both hand the credential straight back.
#
#   So there are three surfaces, and you have to scan all three:
#     1. the working tree      - what a reviewer sees
#     2. the git history       - what an attacker with a clone sees
#     3. the built image       - what an attacker with a pull sees
#
#   And when you do find one: ROTATE IT. Rewriting history is cleanup, not
#   remediation. Assume anything committed is compromised from the moment of
#   the push.
#
# Usage:  ./scripts/scan-secrets.sh [target-image]
# Env:    ONLY_VERIFIED=true|false   OUT=results/secrets
# =============================================================================
set -euo pipefail

IMAGE="${1:-${IMAGE:-localhost/helloctr:latest}}"
OUT="${OUT:-results/secrets}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# --results / --only-verified controls how aggressive the reporting is.
#
#   verified   TruffleHog called the provider's API and the credential WORKS.
#              Near-zero false positives. This is what a merge gate should
#              block on - a verified finding is an active incident.
#   unknown    matched a detector, but the provider could not be reached or has
#              no verification endpoint. Needs a human.
#   unverified matched a detector and the provider said the credential is dead.
#              Still worth reviewing: dead credentials indicate a pattern of
#              committing live ones.
#
# Verification makes outbound network calls to the credential's provider. In a
# classified or air-gapped environment that may be prohibited - run with
# ONLY_VERIFIED=false and triage everything by hand.
ONLY_VERIFIED="${ONLY_VERIFIED:-true}"

mkdir -p "$OUT"
command -v trufflehog >/dev/null 2>&1 || {
  echo "!!! trufflehog not installed - see docs/07-trufflehog.md (make install-tools)" >&2
  exit 127
}

# shellcheck disable=SC2054  # the commas belong to trufflehog's --results value
RESULT_FLAG=(--results=verified,unknown)
# shellcheck disable=SC2054
[[ "$ONLY_VERIFIED" == "false" ]] && RESULT_FLAG=(--results=verified,unknown,unverified)

echo "### 1/3  git history ########################################"
# `git` mode walks every commit on every branch, not just the checked-out tree.
# This is the scan that finds the credential someone committed in 2023 and
# "removed" in the next commit. --since-commit narrows it once you have a clean
# baseline; run it unbounded the first time.
trufflehog git "file://$REPO_ROOT" \
  "${RESULT_FLAG[@]}" \
  --json > "$OUT/trufflehog-git.json" 2>"$OUT/trufflehog-git.log" || true
echo "==> $(wc -l < "$OUT/trufflehog-git.json" 2>/dev/null || echo 0) finding(s) -> $OUT/trufflehog-git.json"

echo
echo "### 2/3  working tree #######################################"
# `filesystem` mode scans files as they are on disk - including anything
# untracked and .gitignored, which is exactly where .env and kubeconfig live.
trufflehog filesystem "$REPO_ROOT" \
  "${RESULT_FLAG[@]}" \
  --exclude-paths "$REPO_ROOT/scripts/trufflehog-exclude.txt" \
  --json > "$OUT/trufflehog-fs.json" 2>"$OUT/trufflehog-fs.log" || true
echo "==> $(wc -l < "$OUT/trufflehog-fs.json" 2>/dev/null || echo 0) finding(s) -> $OUT/trufflehog-fs.json"

echo
echo "### 3/3  container image layers #############################"
# `docker` mode extracts every layer and scans each one independently. This is
# the mode that catches a secret that was ADDed in layer 3 and deleted in layer
# 7 - the file is gone from the final filesystem but present in the layer, and
# the layer is what gets distributed.
if docker image inspect "$IMAGE" >/dev/null 2>&1; then
  trufflehog docker --image "docker://$IMAGE" \
    "${RESULT_FLAG[@]}" \
    --json > "$OUT/trufflehog-image.json" 2>"$OUT/trufflehog-image.log" || true
  echo "==> $(wc -l < "$OUT/trufflehog-image.json" 2>/dev/null || echo 0) finding(s) -> $OUT/trufflehog-image.json"
else
  echo "(image $IMAGE not present locally - skipping; build it first with 'make build')"
fi

# ---------------------------------------------------------------------------
# Gate: any VERIFIED finding fails the build. A verified credential is live.
# ---------------------------------------------------------------------------
echo
verified=0
for f in "$OUT"/trufflehog-*.json; do
  [[ -f "$f" ]] || continue
  n=$(grep -c '"Verified":true' "$f" 2>/dev/null || true)
  verified=$(( verified + ${n:-0} ))
done

if (( verified > 0 )); then
  echo "############################################################"
  echo "  $verified VERIFIED credential(s) found."
  echo
  echo "  This is an incident, not a lint failure. In order:"
  echo "    1. ROTATE the credential at the provider. Now, before anything else."
  echo "    2. Check the provider's audit log for use you did not authorise."
  echo "    3. Then clean the history (git filter-repo / BFG) and rebuild."
  echo "    4. Then fix the process that let it in - pre-commit hook, BuildKit"
  echo "       secret mounts, a secrets manager. See docs/07-trufflehog.md."
  echo "############################################################"
  exit 1
fi

echo "==> no verified credentials found"
echo "    Note: 'no verified findings' is not 'no secrets'. Read the unknown"
echo "    findings in $OUT/ - a detector with no verification endpoint (an"
echo "    internal PKI key, a database password) can only ever be 'unknown'."
