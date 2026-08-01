#!/bin/bash
# =============================================================================
# 30-banner.sh - DoD Notice and Consent Banner
# =============================================================================
# DISA Container Guide requirement: 2.16
#
# SSG rules satisfied:
#   xccdf_org.ssgproject.content_rule_banner_etc_issue
#
# The banner text is fixed by DoD policy. The scanner compares it after
# collapsing whitespace, so line wrapping does not matter, but the WORDS do -
# do not paraphrase, do not "improve" the punctuation.
#
# Is this meaningful inside a container? Honestly, no - there is no login
# session to display it to. It is cheap, it is a one-line file, and shipping it
# is less work than writing the waiver. That is the whole justification.
# =============================================================================
set -euo pipefail

echo "==> /etc/issue banner"

cat > /etc/issue <<'EOF'
You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.
EOF

chmod 0644 /etc/issue
chown root:root /etc/issue

# /etc/issue.net is the banner for network logins. There are none in this
# image (no sshd - requirement 2.1), but keeping the two files consistent
# avoids a scanner finding on the rule that compares them.
cp -f /etc/issue /etc/issue.net
chmod 0644 /etc/issue.net
chown root:root /etc/issue.net

echo "  wrote /etc/issue and /etc/issue.net"
