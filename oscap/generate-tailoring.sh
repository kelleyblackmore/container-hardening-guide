#!/bin/bash
# =============================================================================
# generate-tailoring.sh - build the XCCDF tailoring file (the "answer file")
# =============================================================================
# WHAT A TAILORING FILE IS
#
#   A SCAP profile (here: the DISA RHEL 9 STIG) is a fixed list of rules
#   published by DISA. You do not edit it - it is signed content and your
#   assessor has the same copy. When a rule does not apply to your system, or
#   your organisation has approved a different value, you record that decision
#   in a separate XCCDF *Tailoring* document that EXTENDS the published profile.
#
#   People call it an "answer file". Both names mean the same XML.
#
#   A tailoring file can do three things:
#     1. UNSELECT a rule       -> result becomes "notselected", excluded from
#                                 the score. This is how you mark Not Applicable.
#     2. SELECT a rule the base profile left out.
#     3. CHANGE a value (refine-value) -> e.g. password length 15 -> 20.
#
#   What it CANNOT do is make a failing rule pass. Unselecting a rule you simply
#   do not want to fix is not tailoring, it is fraud with extra XML. Every
#   unselect below has a written justification that goes into the checklist and
#   in front of a human. See docs/12-waivers-and-poam.md.
#
# HOW THIS SCRIPT WORKS
#
#   `autotailor` (from openscap-utils) generates a valid XCCDF 1.2 Tailoring
#   document from a base profile plus a list of rules to unselect. Writing the
#   XML by hand is possible - see oscap/tailoring/example-tailoring.xml for an
#   annotated hand-written one - but autotailor gets the namespaces and the
#   benchmark href right every time.
#
#   After autotailor runs, we inject each rule's justification as an XML comment
#   directly above its <select> element, so the answer file is self-documenting
#   when the assessor opens it.
#
# USAGE (inside the scanner container)
#   generate-tailoring.sh [RULES_LIST] [OUTPUT] [DATASTREAM] [BASE_PROFILE]
# =============================================================================
set -euo pipefail

RULES_LIST="${1:-/scan/oscap/not-applicable.rules}"
OUTPUT="${2:-/scan/results/tailoring-stig-container.xml}"
DATASTREAM="${3:-/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml}"
BASE_PROFILE="${4:-xccdf_org.ssgproject.content_profile_stig}"

# The id of the profile you are creating. It must be unique and it is the id
# you pass to `oscap xccdf eval --profile`. Convention: name it after the
# system it describes, not after "tailored" - the assessor reads this string.
NEW_PROFILE_ID="${NEW_PROFILE_ID:-xccdf_mil.disa.stig_profile_stig_container}"
NEW_PROFILE_TITLE="${NEW_PROFILE_TITLE:-DISA RHEL 9 STIG - Container Tailored (Not-Applicable rules deselected)}"

command -v autotailor >/dev/null 2>&1 || { echo "ERROR: autotailor not found (dnf install openscap-utils)" >&2; exit 2; }
[[ -f "$DATASTREAM" ]] || { echo "ERROR: datastream not found: $DATASTREAM" >&2; exit 3; }
[[ -f "$RULES_LIST" ]] || { echo "ERROR: rules list not found: $RULES_LIST" >&2; exit 4; }

mkdir -p "$(dirname "$OUTPUT")"

# Collect the rule ids: skip blank lines and comments, take the first field.
mapfile -t RULES < <(grep -vE '^\s*(#|$)' "$RULES_LIST" | awk '{print $1}')
echo "==> base profile : $BASE_PROFILE"
echo "==> new profile  : $NEW_PROFILE_ID"
echo "==> deselecting  : ${#RULES[@]} rule(s)"

# autotailor flags in the SSG versions shipped on RHEL/Rocky 9:
#   -u / --unselect-rule   rule id to deselect (repeatable)
#   -p / --new-profile-id  id of the profile being created
#   -o / --output          output path
#   --title                human-readable title
# Older builds accept ONLY the short forms. Use the short forms.
ARGS=()
for r in "${RULES[@]}"; do
  ARGS+=(-u "$r")
done

autotailor \
  -o "$OUTPUT" \
  -p "$NEW_PROFILE_ID" \
  --title "$NEW_PROFILE_TITLE" \
  "${ARGS[@]}" \
  "$DATASTREAM" \
  "$BASE_PROFILE"

# --- make the answer file self-documenting -----------------------------------
# Lift the comment block that precedes each rule id in the rules list and inject
# it as an XML comment above the matching <select> element. Best effort: the
# tailoring file autotailor produced is already valid, so a missing python3 only
# costs us the comments.
if command -v python3 >/dev/null 2>&1; then
python3 - "$RULES_LIST" "$OUTPUT" <<'PY' || echo "==> warning: justification injection skipped"
import re, sys
rules_path, xml_path = sys.argv[1], sys.argv[2]

# Build {rule_id: justification} from the comment block above each rule.
just, block = {}, []
for line in open(rules_path, encoding="utf-8"):
    s = line.strip()
    if s.startswith("#"):
        t = s.lstrip("# ").rstrip()
        if t and not t.startswith("---") and "TEMPLATE" not in t and "ACTIVE" not in t:
            block.append(t)
    elif not s:
        block = []
    else:
        just[s.split()[0]] = " ".join(block).strip()
        block = []

xml = open(xml_path, encoding="utf-8").read()

def repl(m):
    j = just.get(m.group("rid"), "")
    if not j:
        return m.group(0)
    j = j.replace("--", "—")  # '--' is illegal inside an XML comment
    return f'{m.group("indent")}<!-- Not Applicable: {j} -->\n{m.group(0)}'

xml = re.sub(
    r'(?P<indent>[ \t]*)(?P<sel><xccdf-1\.2:select idref="(?P<rid>[^"]+)" selected="false"\s*/>)',
    repl, xml)
open(xml_path, "w", encoding="utf-8").write(xml)
print(f"==> injected {len(just)} justification comment(s)")
PY
fi

echo "==> answer file written: $OUTPUT"
echo
echo "Use it with:"
echo "  oscap xccdf eval --profile $NEW_PROFILE_ID \\"
echo "        --tailoring-file $OUTPUT \\"
echo "        --results-arf results-arf.xml --report report.html \\"
echo "        $DATASTREAM"
