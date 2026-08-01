#!/usr/bin/env bash
# =============================================================================
# run-oscap.sh - end-to-end OpenSCAP STIG workflow for the hardened image
# =============================================================================
#   1. build the hardened image                 (the deliverable)
#   2. build the scanner image                  (throwaway: image + oscap + SSG)
#   3. generate the tailoring / answer file     from oscap/not-applicable.rules
#   4. BASELINE scan   - no tailoring           -> results/baseline/
#   5. TAILORED scan   - answer file applied    -> results/tailored/
#
# Run the two scans and diff the summaries. The delta is exactly the set of
# rules a human decided were Not Applicable - which is the number your assessor
# will ask you to justify.
#
# Results come out with `docker cp` rather than a bind mount, so this behaves
# identically on Windows, macOS, and Linux (bind-mount UID mapping and SELinux
# labelling are the usual source of "works on my machine" here).
#
# Usage:  ./oscap/run-oscap.sh          (from the repo root)
#         RUNTIME=podman ./oscap/run-oscap.sh
# =============================================================================
set -euo pipefail

RUNTIME="${RUNTIME:-docker}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# --- Git Bash / MSYS on Windows ----------------------------------------------
# MSYS rewrites anything that looks like a POSIX path in an argument before the
# process sees it, which turns `ctr:/scan/results` into `ctr:C:/Program Files/...`
# and breaks every docker cp. Turning the rewriting off fixes the container-side
# paths but leaves the HOST-side ones as `/c/Users/...`, which docker.exe cannot
# resolve - so host paths go through cygpath. Both are no-ops on Linux and macOS.
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
host_path() {
  if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi
}

IMAGE_APP="${IMAGE_APP:-localhost/helloctr:latest}"
IMAGE_SCAN="${IMAGE_SCAN:-localhost/helloctr-scan:latest}"
RESULTS="$REPO_ROOT/results"
TAILOR_PROFILE="xccdf_mil.disa.stig_profile_stig_container"

cleanup_container() { "$RUNTIME" rm -f "$1" >/dev/null 2>&1 || true; }

echo "### 1/5  build the hardened image"
"$RUNTIME" build -f examples/hardened/Dockerfile -t "$IMAGE_APP" examples/hardened

echo "### 2/5  build the scanner image"
"$RUNTIME" build -f oscap/Containerfile.scan --build-arg BASE_IMAGE="$IMAGE_APP" -t "$IMAGE_SCAN" .

echo "### 3/5  generate the tailoring (answer) file"
cleanup_container ctr-tailor
"$RUNTIME" run --name ctr-tailor --entrypoint /usr/local/bin/generate-tailoring.sh "$IMAGE_SCAN" \
  /scan/oscap/not-applicable.rules /scan/results/tailoring-stig-container.xml
mkdir -p "$RESULTS/tailored"
"$RUNTIME" cp ctr-tailor:/scan/results/tailoring-stig-container.xml \
  "$(host_path "$RESULTS/tailored/tailoring-stig-container.xml")"
cleanup_container ctr-tailor
echo "==> answer file -> results/tailored/tailoring-stig-container.xml"

echo "### 4/5  BASELINE scan (published STIG profile, no tailoring)"
cleanup_container ctr-baseline
# `|| true`: oscap exits 2 when any rule fails, which is the expected outcome.
"$RUNTIME" run --name ctr-baseline "$IMAGE_SCAN" || true
mkdir -p "$RESULTS/baseline"
"$RUNTIME" cp ctr-baseline:/scan/results/. "$(host_path "$RESULTS/baseline")"
cleanup_container ctr-baseline

echo "### 5/5  TAILORED scan (answer file applied)"
cleanup_container ctr-tailored
# Regenerate and evaluate in the SAME container so the tailoring being used is
# provably the one that was just generated from not-applicable.rules.
"$RUNTIME" run --name ctr-tailored --entrypoint bash "$IMAGE_SCAN" -c "
  /usr/local/bin/generate-tailoring.sh \
      /scan/oscap/not-applicable.rules \
      /scan/results/tailoring-stig-container.xml
  TAILORING_FILE=/scan/results/tailoring-stig-container.xml \
  TAILORING_PROFILE=$TAILOR_PROFILE \
  REMEDIATE=false /usr/local/bin/scan.sh
" || true
"$RUNTIME" cp ctr-tailored:/scan/results/. "$(host_path "$RESULTS/tailored")"
cleanup_container ctr-tailored

echo
echo "############################  DONE  ############################"
echo "--- BASELINE (published profile) ---"
cat "$RESULTS/baseline/summary.txt" 2>/dev/null || echo "(no summary)"
echo
echo "--- TAILORED (answer file applied) ---"
cat "$RESULTS/tailored/summary.txt" 2>/dev/null || echo "(no summary)"
echo
echo "HTML reports (open in a browser):"
echo "  $RESULTS/baseline/report.html"
echo "  $RESULTS/tailored/report.html"
echo
echo "ARF for STIG Viewer / eMASS:"
echo "  $RESULTS/tailored/results-arf.xml"
