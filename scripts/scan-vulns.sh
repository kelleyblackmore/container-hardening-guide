#!/usr/bin/env bash
# =============================================================================
# scan-vulns.sh - CVE scan the image with BOTH Trivy and Grype, then diff them
# =============================================================================
# Section 4.3.3 of the DISA guide says it plainly: "It is necessary to utilize
# more than one tool to scan since results can differ." This script is that
# sentence, implemented.
#
# The two tools disagree more than you would expect, because a "vulnerability
# scan" is really three separate steps and they make different choices at each:
#
#   1. INVENTORY  - what is installed? Trivy and Grype both read the RPM/dpkg
#      database and both walk language manifests (go.mod, package-lock.json,
#      requirements.txt), but they disagree about binaries with no manifest,
#      vendored code, and statically linked dependencies.
#
#   2. MATCHING   - which CVEs affect that inventory? This is where most of the
#      divergence lives. Both consult NVD, but Grype leans on the Anchore feed
#      and Trivy on its own aggregated DB, and each weighs distro security
#      trackers (Red Hat OVAL, Debian, Alpine secdb) differently.
#
#   3. FILTERING  - is it actually exploitable here? Red Hat frequently marks a
#      CVE "will not fix" or "affects a code path not compiled in". Trivy
#      honours Red Hat's OVAL statements aggressively, which is why Trivy often
#      reports FEWER findings than Grype on a UBI image. That is not Trivy being
#      wrong. It is also not Grype being wrong.
#
# So: run both, diff them, and investigate what only one of them found. That
# delta is where the interesting findings are. Never pick the scanner with the
# prettiest number.
#
# Usage:  ./scripts/scan-vulns.sh [image]
# Env:    SEVERITY=HIGH,CRITICAL   IGNORE_UNFIXED=true   OUT=results/vulns
# =============================================================================
set -euo pipefail

IMAGE="${1:-${IMAGE:-localhost/helloctr:latest}}"
OUT="${OUT:-results/vulns}"
SEVERITY="${SEVERITY:-HIGH,CRITICAL}"
IGNORE_UNFIXED="${IGNORE_UNFIXED:-true}"

mkdir -p "$OUT"
echo "==> image    : $IMAGE"
echo "==> severity : $SEVERITY"
echo "==> results  : $OUT/"
echo

have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------
# TRIVY
# ---------------------------------------------------------------------------
# --ignore-unfixed is a policy decision, not a default. It hides findings with
# no vendor patch available. The argument for it: you cannot remediate them by
# rebuilding, so they are noise in a gate that exists to make you rebuild. The
# argument against: "no fix available" is exactly the situation that needs a
# compensating control and a risk decision, and hiding it means nobody makes
# one. Run WITH it in the merge gate, WITHOUT it in the weekly report.
# ---------------------------------------------------------------------------
if have trivy; then
  echo "### TRIVY ###################################################"
  # shellcheck disable=SC2054  # the commas belong to trivy's option values
  TRIVY_ARGS=(image --severity "$SEVERITY" --pkg-types os,library)
  [[ "$IGNORE_UNFIXED" == "true" ]] && TRIVY_ARGS+=(--ignore-unfixed)

  # Human-readable table for the log.
  trivy "${TRIVY_ARGS[@]}" --format table "$IMAGE" | tee "$OUT/trivy.txt" || true

  # JSON for tooling and for the diff below.
  trivy "${TRIVY_ARGS[@]}" --format json  --output "$OUT/trivy.json"  "$IMAGE" || true

  # SARIF so GitHub code scanning can render findings inline on the PR.
  trivy "${TRIVY_ARGS[@]}" --format sarif --output "$OUT/trivy.sarif" "$IMAGE" || true

  # Secret and misconfiguration scanning are separate Trivy scanners. Trivy's
  # secret detection is regex-based and lighter than TruffleHog's - it is a
  # useful second opinion, not a replacement. See docs/07-trufflehog.md.
  trivy image --scanners secret,misconfig --format table "$IMAGE" \
    | tee "$OUT/trivy-secret-misconfig.txt" || true
else
  echo "!!! trivy not installed - see docs/08-trivy-and-grype.md (make install-tools)"
fi
echo

# ---------------------------------------------------------------------------
# GRYPE
# ---------------------------------------------------------------------------
# Grype is Anchore's matcher. Its natural partner is Syft, which produces the
# SBOM. Scanning the SBOM instead of the image is the better pipeline shape:
# generate the SBOM once at build time, attach it to the image as an
# attestation, and re-scan that SBOM every day as new CVEs are published -
# without rebuilding or even pulling the image. That is how you find out on
# Tuesday that Friday's image became vulnerable overnight.
# ---------------------------------------------------------------------------
if have grype; then
  echo "### GRYPE ###################################################"
  GRYPE_ARGS=(--fail-on "" -o table)
  [[ "$IGNORE_UNFIXED" == "true" ]] && GRYPE_ARGS+=(--only-fixed)

  grype "$IMAGE" "${GRYPE_ARGS[@]}" | tee "$OUT/grype.txt" || true
  grype "$IMAGE" -o json  --file "$OUT/grype.json"  || true
  grype "$IMAGE" -o sarif --file "$OUT/grype.sarif" || true
else
  echo "!!! grype not installed - see docs/08-trivy-and-grype.md (make install-tools)"
fi
echo

# ---------------------------------------------------------------------------
# SBOM (Syft) - the artifact everything else should hang off
# ---------------------------------------------------------------------------
if have syft; then
  echo "### SYFT (SBOM) #############################################"
  syft "$IMAGE" -o cyclonedx-json="$OUT/sbom.cdx.json" -o spdx-json="$OUT/sbom.spdx.json" -q || true
  echo "==> SBOM: $OUT/sbom.cdx.json (CycloneDX), $OUT/sbom.spdx.json (SPDX)"
  # Scan the SBOM rather than the image - same answer, no image pull required,
  # and it works for an image you no longer have locally.
  if have grype; then
    grype "sbom:$OUT/sbom.cdx.json" -o table > "$OUT/grype-from-sbom.txt" 2>/dev/null || true
  fi
fi
echo

# ---------------------------------------------------------------------------
# DIFF - the part people skip, and the part that is actually informative
# ---------------------------------------------------------------------------
if [[ -f "$OUT/trivy.json" && -f "$OUT/grype.json" ]] && have python3; then
  echo "### SCANNER DISAGREEMENT ####################################"
  python3 - "$OUT/trivy.json" "$OUT/grype.json" <<'PY' | tee "$OUT/diff.txt"
import json, sys

def load(path, extract):
    try:
        with open(path, encoding="utf-8") as fh:
            return extract(json.load(fh))
    except Exception as exc:                      # noqa: BLE001
        print(f"  (could not parse {path}: {exc})")
        return set()

trivy = load(sys.argv[1], lambda d: {
    v["VulnerabilityID"]
    for res in (d.get("Results") or [])
    for v in (res.get("Vulnerabilities") or [])
})
grype = load(sys.argv[2], lambda d: {
    m["vulnerability"]["id"] for m in (d.get("matches") or [])
})

both = trivy & grype
print(f"  trivy only : {len(trivy - grype):4d}")
print(f"  grype only : {len(grype - trivy):4d}")
print(f"  both       : {len(both):4d}")
for label, ids in (("TRIVY ONLY", trivy - grype), ("GRYPE ONLY", grype - trivy)):
    if ids:
        print(f"\n  {label}:")
        for cve in sorted(ids):
            print(f"    {cve}")
print("\n  A CVE found by only one scanner is not automatically a false "
      "positive.\n  Look it up before you dismiss it.")
PY
fi

echo
echo "==> results in $OUT/"
