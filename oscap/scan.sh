#!/bin/bash
# =============================================================================
# scan.sh - run the DISA RHEL 9 STIG evaluation INSIDE the scanner container.
# =============================================================================
# Writes into /scan/results:
#   report.html        human-readable OpenSCAP report (open this first)
#   results-arf.xml    ARF - the machine-readable format STIG Viewer and eMASS
#                      ingest. This is the artifact your assessor wants.
#   results-xccdf.xml  XCCDF results only (smaller, easier to grep)
#   summary.txt        result counts and a pass percentage
#
# Environment knobs:
#   PROFILE            base profile   (default: ..._profile_stig)
#   DATASTREAM         SCAP datastream (default: auto-detect ssg-rhel9-ds.xml)
#   TAILORING_FILE     optional XCCDF tailoring ("answer") file
#   TAILORING_PROFILE  tailored profile id - REQUIRED when TAILORING_FILE is set
#   REMEDIATE          "true" applies SSG's remediation scripts, then re-checks.
#                      Useful for discovering what CAN be fixed; do not use it
#                      as your hardening mechanism - see the note at the bottom.
#
# oscap exit codes, which trip people up constantly:
#   0 = every selected rule passed
#   1 = oscap itself errored (bad datastream, bad profile id, ...)  <- real failure
#   2 = the scan ran fine and at least one rule failed              <- normal
# Treating 2 as a failure will break your pipeline on day one. Gate on the
# score or on a specific rule set instead - see .github/workflows/stig.yml.
# =============================================================================
set -uo pipefail

OUT="${OUT:-/scan/results}"
mkdir -p "$OUT"

# ---- locate the SSG RHEL 9 datastream ---------------------------------------
DATASTREAM="${DATASTREAM:-}"
if [[ -z "$DATASTREAM" ]]; then
  for c in \
    /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml \
    /usr/share/xml/scap/ssg/content/ssg-rhel9-ds-1.2.xml; do
    [[ -f "$c" ]] && DATASTREAM="$c" && break
  done
fi
if [[ -z "$DATASTREAM" || ! -f "$DATASTREAM" ]]; then
  echo "ERROR: no SSG RHEL 9 datastream found (ssg-rhel9-ds.xml)." >&2
  echo "       Install scap-security-guide, or pass DATASTREAM=/path/to/ds.xml" >&2
  exit 3
fi

DEFAULT_PROFILE="xccdf_org.ssgproject.content_profile_stig"
PROFILE="${PROFILE:-$DEFAULT_PROFILE}"

# With a tailoring file, the profile you evaluate is the NEW id defined inside
# the tailoring file, not the base profile it extends. Getting this wrong is
# the most common tailoring mistake: oscap exits 1 with "profile not found".
PROFILE_TO_USE="$PROFILE"
if [[ -n "${TAILORING_FILE:-}" ]]; then
  [[ -f "$TAILORING_FILE" ]] || { echo "ERROR: TAILORING_FILE '$TAILORING_FILE' not found" >&2; exit 4; }
  [[ -n "${TAILORING_PROFILE:-}" ]] || { echo "ERROR: TAILORING_PROFILE must be set when TAILORING_FILE is used" >&2; exit 4; }
  PROFILE_TO_USE="$TAILORING_PROFILE"
fi

echo "==> oscap      : $(oscap --version | head -1)"
echo "==> datastream : $DATASTREAM"
echo "==> profile    : $PROFILE_TO_USE"
[[ -n "${TAILORING_FILE:-}" ]] && echo "==> tailoring  : $TAILORING_FILE"

ARGS=(xccdf eval
  --profile "$PROFILE_TO_USE"
  --results-arf "$OUT/results-arf.xml"
  --results     "$OUT/results-xccdf.xml"
  --report      "$OUT/report.html")

[[ -n "${TAILORING_FILE:-}" ]] && ARGS+=(--tailoring-file "$TAILORING_FILE")
[[ "${REMEDIATE:-false}" == "true" ]] && { ARGS+=(--remediate); echo "==> remediation: ENABLED"; }

oscap "${ARGS[@]}" "$DATASTREAM"
rc=$?
echo "==> oscap exit code: $rc"
if [[ $rc -eq 1 ]]; then
  echo "ERROR: oscap reported an internal error" >&2
  exit 1
fi

# ---- summarise ---------------------------------------------------------------
# Counting <result> elements in the XCCDF output is crude but dependency-free.
# Result values and what they mean:
#   pass           the check succeeded
#   fail           the check failed - fix it, or justify it in the answer file
#   notapplicable  OpenSCAP itself decided the rule cannot apply (CPE logic).
#                  ~400 host-only rules land here automatically for a container.
#   notselected    a human deselected it - this is what the tailoring file does
#   notchecked     the rule has no automated check (manual review required)
#   error/unknown  the probe could not run; investigate, do not ignore
#   fixed          remediation was applied and the recheck passed
{
  echo "OpenSCAP DISA RHEL 9 STIG scan summary"
  echo "datastream : $DATASTREAM"
  echo "profile    : $PROFILE_TO_USE"
  echo "tailoring  : ${TAILORING_FILE:-<none>}"
  echo "remediate  : ${REMEDIATE:-false}"
  echo "----------------------------------------"
  for r in pass fail error unknown notapplicable notchecked notselected informational fixed; do
    n=$(grep -c "<result>$r</result>" "$OUT/results-xccdf.xml" 2>/dev/null)
    printf "%-14s %s\n" "$r" "${n:-0}"
  done
  echo "----------------------------------------"
  p=$(grep -c "<result>pass</result>" "$OUT/results-xccdf.xml" 2>/dev/null); p=${p:-0}
  f=$(grep -c "<result>fail</result>" "$OUT/results-xccdf.xml" 2>/dev/null); f=${f:-0}
  tot=$((p + f))
  if [[ $tot -gt 0 ]]; then
    printf "score (pass / pass+fail) : %s%%\n" "$(( 100 * p / tot ))"
  fi
} | tee "$OUT/summary.txt"

# ---- list the failures, so the log is actionable on its own ------------------
echo
echo "==> failed rules:"
grep -B4 "<result>fail</result>" "$OUT/results-xccdf.xml" 2>/dev/null \
  | grep -oE 'idref="[^"]+"' | sed 's/idref="/  /; s/"$//' | sort -u \
  | tee "$OUT/failed-rules.txt"
echo "==> $(wc -l < "$OUT/failed-rules.txt" 2>/dev/null || echo 0) failing rule(s)"

echo
echo "==> wrote $OUT/{report.html,results-arf.xml,results-xccdf.xml,summary.txt,failed-rules.txt}"

# -----------------------------------------------------------------------------
# A word on REMEDIATE=true.
#
# `oscap --remediate` runs SSG's bash fix scripts against the live filesystem.
# It is excellent for FINDING OUT what a fix looks like - run it, then diff the
# filesystem to see what changed. It is a poor way to BUILD a hardened image:
#   * the changes are not in your Dockerfile, so they are not reviewable, not
#     reproducible, and invisible in code review;
#   * some fixes call systemctl / grubby / fips-mode-setup and fail or, worse,
#     half-succeed inside a container;
#   * you cannot tell later WHY a file looks the way it does.
# Take the fix, read it, and write the deliberate version into
# examples/hardened/harden/. That is what those scripts are.
# -----------------------------------------------------------------------------
exit 0
