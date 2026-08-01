#!/bin/bash
# =============================================================================
# 20-umask-shell.sh - default umask for interactive and non-interactive shells
# =============================================================================
# DISA Container Guide requirement: 2.16
#
# SSG rules satisfied:
#   xccdf_org.ssgproject.content_rule_accounts_umask_etc_profile
#   xccdf_org.ssgproject.content_rule_accounts_umask_etc_bashrc
#   xccdf_org.ssgproject.content_rule_accounts_umask_etc_csh_cshrc
#
# umask 077 means anything the process creates is private to its own UID by
# default. In a container this matters most for files written into an emptyDir
# or a shared volume - without it, a sidecar running as a different UID can
# read whatever your app just wrote.
#
# Note that this only covers processes started through a shell. Your actual
# service is started by the ENTRYPOINT with no shell in between, so its umask
# is inherited from the container runtime (0022). If your app writes sensitive
# files, set the umask in the application itself - do not rely on this.
# =============================================================================
set -euo pipefail

# Rewrite EVERY umask assignment in the file, not just ones at the start of a
# line. This matters: RHEL's stock /etc/bashrc contains
#
#     [ `umask` -eq 0 ] && umask 022
#
# inside a conditional. Appending `umask 077` at the end of the file does not
# satisfy the rule - the OVAL check requires that no umask in the file is looser
# than 077, and that indented `umask 022` still fails it. This is a good example
# of why you run the scan instead of assuming: the naive "append the setting"
# fix looks right and does not pass.
#
# The regex mirrors SSG's own remediation: match anything up to `umask` on a
# non-comment line, then the digits, and replace only the digits.
set_umask_in() {
  local file="$1"
  [[ -f "$file" ]] || return 0
  if grep -qE '^[^#]*\bumask' "$file"; then
    sed -ri -e 's/^([^#]*\bumask)[[:space:]]+[[:digit:]]+/\1 077/g' "$file"
  else
    printf '\n# STIG: default umask 077\numask 077\n' >> "$file"
  fi
  echo "  umask 077 -> $file"
}

echo "==> shell umask"
set_umask_in /etc/profile
set_umask_in /etc/bashrc
set_umask_in /etc/csh.cshrc

# /etc/profile.d/*.sh are sourced after /etc/profile and can override it, so
# drop a file that sorts last and re-asserts the value.
cat > /etc/profile.d/zz-stig-umask.sh <<'EOF'
# STIG: enforce umask 077 after all other profile scripts have run.
umask 077
EOF
chmod 0644 /etc/profile.d/zz-stig-umask.sh
echo "  umask 077 -> /etc/profile.d/zz-stig-umask.sh"
