#!/bin/bash
# =============================================================================
# 70-misc-stig.sh - the last handful of findings from the baseline scan
# =============================================================================
# DISA Container Guide requirement: 2.16
#
# SSG rules satisfied:
#   ensure_gpgcheck_local_packages
#   file_permission_user_init_files_root
#   rootfiles_configured
#   use_pam_wheel_for_su
#
# These four are here because the BASELINE scan found them, not because anyone
# guessed. That is the intended workflow and it is worth stating plainly:
#
#     make stig  ->  read results/baseline/failed-rules.txt  ->  fix or justify
#
# Each fix below is the deliberate, readable version of what
# `oscap xccdf generate fix` produces. Read SSG's output, understand it, then
# write the version you are willing to defend - do not paste the generated
# script into your build. See docs/02, layer step 4.
# =============================================================================
set -euo pipefail

# -----------------------------------------------------------------------------
# ensure_gpgcheck_local_packages
# -----------------------------------------------------------------------------
# dnf.conf already sets gpgcheck=1, which covers packages from a repository.
# localpkg_gpgcheck covers `dnf install ./something.rpm` - a local file, which is
# exactly the path an attacker with a foothold would use. Directly supports
# requirement 2.11 (verified packages).
echo "==> localpkg_gpgcheck"
if [[ -f /etc/dnf/dnf.conf ]]; then
  if grep -qiE '^[[:space:]]*localpkg_gpgcheck\b' /etc/dnf/dnf.conf; then
    sed -ri 's/^[[:space:]]*localpkg_gpgcheck\b.*/localpkg_gpgcheck = 1/i' /etc/dnf/dnf.conf
  else
    printf 'localpkg_gpgcheck = 1\n' >> /etc/dnf/dnf.conf
  fi
  echo "  localpkg_gpgcheck = 1"
fi

# -----------------------------------------------------------------------------
# file_permission_user_init_files_root
# -----------------------------------------------------------------------------
# Shell init files (.bashrc, .bash_profile, .cshrc ...) run automatically on
# login. If one is group- or world-writable, anyone who can write it gets code
# execution as that user on their next shell. UBI ships them mode 0644.
#
# `chmod u-s,g-wxs,o=` is SSG's expression: strip setuid, strip group
# write/execute/setgid, remove all "other" permissions. Symbolic rather than a
# fixed octal so an intentionally stricter mode is not loosened.
echo "==> root init file permissions"
for f in /root/.[!.]*; do
  [[ -f "$f" ]] || continue
  chmod u-s,g-wxs,o= "$f"
  printf '  %-24s %s\n' "$f" "$(stat -c '%a' "$f")"
done

# -----------------------------------------------------------------------------
# rootfiles_configured
# -----------------------------------------------------------------------------
# systemd-tmpfiles restores root's init files from /usr/share/rootfiles if they
# are missing or replaced, with mode 0600 and root ownership. It is a small
# self-healing measure against an attacker who modifies root's .bashrc for
# persistence.
#
# In a container nothing runs systemd-tmpfiles, so this is inert at runtime -
# but the rule is scored against the image's configuration, and writing a
# four-line config is cheaper than defending an exception. This is the "cheap
# to comply, expensive to waive" case discussed in docs/12.
echo "==> /etc/tmpfiles.d/rootfiles.conf"
if rpm -q rootfiles >/dev/null 2>&1; then
  mkdir -p /etc/tmpfiles.d
  cat > /etc/tmpfiles.d/rootfiles.conf <<'EOF'
C /root/.bash_logout 600 root root - /usr/share/rootfiles/.bash_logout
C /root/.bash_profile 600 root root - /usr/share/rootfiles/.bash_profile
C /root/.bashrc 600 root root - /usr/share/rootfiles/.bashrc
C /root/.cshrc 600 root root - /usr/share/rootfiles/.cshrc
C /root/.tcshrc 600 root root - /usr/share/rootfiles/.tcshrc
EOF
  chmod 0644 /etc/tmpfiles.d/rootfiles.conf
  echo "  written"
else
  echo "  rootfiles package not installed, skipping"
fi

# -----------------------------------------------------------------------------
# use_pam_wheel_for_su
# -----------------------------------------------------------------------------
# Restrict `su` to members of the wheel group. In this image the wheel group has
# no members and the setuid bit has already been stripped from /usr/bin/su
# (requirement 2.3), so su is doubly unusable - which is the intent. Defence in
# depth: the DAC bit and the PAM stack fail independently.
echo "==> pam_wheel for su"
if [[ -f /etc/pam.d/su ]]; then
  if grep -qE '^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\.so.*use_uid' /etc/pam.d/su; then
    echo "  already configured"
  elif grep -qE '^[[:space:]]*#[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\.so.*use_uid' /etc/pam.d/su; then
    # Uncomment the line the distribution already ships, rather than appending a
    # duplicate. PAM stacks are order-sensitive; keep the vendor's placement.
    sed -ri 's/^[[:space:]]*#[[:space:]]*(auth[[:space:]]+required[[:space:]]+pam_wheel\.so.*use_uid.*)/\1/' /etc/pam.d/su
    echo "  uncommented the vendor's pam_wheel line"
  else
    sed -ri '0,/^auth/s//auth\t\trequired\tpam_wheel.so use_uid\nauth/' /etc/pam.d/su
    echo "  inserted pam_wheel before the first auth line"
  fi
  grep -E 'pam_wheel' /etc/pam.d/su | sed 's/^/    /'
fi
