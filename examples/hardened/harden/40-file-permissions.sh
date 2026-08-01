#!/bin/bash
# =============================================================================
# 40-file-permissions.sh - permissions and ownership on account databases
# =============================================================================
# DISA Container Guide requirement: 2.16, and it directly supports 2.3
#
# SSG rules satisfied:
#   file_permissions_etc_shadow / file_owner_etc_shadow / file_groupowner_etc_shadow
#   file_permissions_etc_gshadow / file_owner_etc_gshadow / file_groupowner_etc_gshadow
#   file_permissions_etc_passwd  / file_owner_etc_passwd  / file_groupowner_etc_passwd
#   file_permissions_etc_group   / file_owner_etc_group   / file_groupowner_etc_group
#   no_empty_passwords
#   dir_perms_world_writable_sticky_bits
#
# The shadow files hold password hashes. Mode 0000 looks wrong the first time
# you see it - it is correct. Only root reads them, and root ignores DAC
# permissions entirely, so 0000 costs nothing and denies every other UID.
# =============================================================================
set -euo pipefail

echo "==> account database permissions"

harden_file() {
  local path="$1" mode="$2" owner="$3"
  [[ -e "$path" ]] || return 0
  chown "$owner" "$path"
  chmod "$mode" "$path"
  printf '  %-24s %s %s\n' "$path" "$mode" "$owner"
}

harden_file /etc/shadow   0000 root:root
harden_file /etc/shadow-  0000 root:root
harden_file /etc/gshadow  0000 root:root
harden_file /etc/gshadow- 0000 root:root
harden_file /etc/passwd   0644 root:root
harden_file /etc/passwd-  0644 root:root
harden_file /etc/group    0644 root:root
harden_file /etc/group-   0644 root:root

# No account may have an empty password. `nullok` in a PAM stack allows an
# empty password to authenticate; strip it wherever it appears.
echo "==> empty passwords"
if compgen -G "/etc/pam.d/*" > /dev/null; then
  sed -ri 's/\<nullok\>//g' /etc/pam.d/* 2>/dev/null || true
fi
if [[ -d /etc/security/pwquality.conf.d ]] || [[ -f /etc/security/pwquality.conf ]]; then
  sed -ri 's/\<nullok\>//g' /etc/security/pwquality.conf 2>/dev/null || true
fi
# Any account with an empty hash field gets locked (`!` prefix).
awk -F: '($2 == "") {print $1}' /etc/shadow | while read -r u; do
  echo "  locking passwordless account: $u"
  passwd -l "$u" >/dev/null 2>&1 || true
done

# Every world-writable directory must have the sticky bit, or any user can
# delete another user's files in it. /tmp normally already has it.
echo "==> world-writable directories"
find / -xdev -type d -perm -0002 ! -perm -1000 -print -exec chmod a+t {} + 2>/dev/null || true

# Home directories must not be world-readable.
echo "==> home directory permissions"
[[ -d /root ]] && chmod 0700 /root && echo "  /root 0700"

exit 0
