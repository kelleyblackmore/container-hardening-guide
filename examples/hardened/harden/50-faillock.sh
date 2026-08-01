#!/bin/bash
# =============================================================================
# 50-faillock.sh - account lockout policy
# =============================================================================
# DISA Container Guide requirement: 2.16
#
# SSG rules satisfied:
#   accounts_passwords_pam_faillock_deny
#   accounts_passwords_pam_faillock_interval
#   accounts_passwords_pam_faillock_unlock_time
#   accounts_passwords_pam_faillock_dir
#   accounts_passwords_pam_faillock_audit
#   accounts_passwords_pam_faillock_silent
#
# RHEL 9 reads all of these from /etc/security/faillock.conf, so the whole
# rule family collapses into writing one file. On RHEL 7/8 you would be editing
# the pam_faillock lines in /etc/pam.d/system-auth and password-auth instead.
# =============================================================================
set -euo pipefail

echo "==> /etc/security/faillock.conf"

mkdir -p /etc/security
cat > /etc/security/faillock.conf <<'EOF'
# STIG-mandated account lockout policy.

# Lock the account after 3 consecutive failed attempts.
deny = 3

# Count failures inside a 15 minute window.
fail_interval = 900

# unlock_time = 0 means the lock never expires on its own: an administrator
# must clear it with `faillock --reset`. The STIG requires 0 (or >= 900 with a
# documented justification).
unlock_time = 0

# Track failures for root too.
even_deny_root

# Record failures under /var/log rather than /var/run, so the counters survive
# a restart of the running system.
dir = /var/log/faillock

# Send each failure to the audit subsystem...
audit

# ...but do not tell the user at the prompt that the account is locked, which
# would confirm to an attacker that the username is valid.
silent
EOF

chmod 0644 /etc/security/faillock.conf
chown root:root /etc/security/faillock.conf
mkdir -p /var/log/faillock
chmod 0755 /var/log/faillock

echo "  deny=3 fail_interval=900 unlock_time=0 even_deny_root audit silent"
