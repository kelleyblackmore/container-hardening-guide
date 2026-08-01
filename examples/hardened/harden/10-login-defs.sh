#!/bin/bash
# =============================================================================
# 10-login-defs.sh - password and umask policy in /etc/login.defs
# =============================================================================
# DISA Container Guide requirement: 2.16 (implement relevant STIG/SRG guidance)
#
# SSG rules satisfied (run the OpenSCAP scan to see the matching STIG IDs):
#   xccdf_org.ssgproject.content_rule_accounts_maximum_age_login_defs
#   xccdf_org.ssgproject.content_rule_accounts_minimum_age_login_defs
#   xccdf_org.ssgproject.content_rule_accounts_password_warn_age_login_defs
#   xccdf_org.ssgproject.content_rule_accounts_password_minlen_login_defs
#   xccdf_org.ssgproject.content_rule_accounts_umask_etc_login_defs
#   xccdf_org.ssgproject.content_rule_set_password_hashing_algorithm_logindefs
#
# "Why bother? Nobody logs into a container."
#   Mostly true, and that is exactly the argument you make in a WAIVER if you
#   want these deselected. But these settings are (a) free, (b) inherited by
#   any account the image creates, and (c) the scanner will fail them, which
#   means a human has to adjudicate every one. Fixing the cheap ones keeps your
#   Not-Applicable list short and defensible. See docs/12-waivers-and-poam.md.
# =============================================================================
set -euo pipefail

FILE=/etc/login.defs
[[ -f "$FILE" ]] || { echo "  $FILE absent, skipping"; exit 0; }

# set_login_def KEY VALUE - replace the directive if present, append if not.
# Idempotent: safe to run twice, and safe on a base image that already ships
# the setting. Anchored to start-of-line so commented-out examples are ignored.
set_login_def() {
  local key="$1" value="$2"
  if grep -qE "^[[:space:]]*${key}[[:space:]]" "$FILE"; then
    sed -ri "s|^[[:space:]]*${key}[[:space:]].*|${key}\t${value}|" "$FILE"
  else
    printf '%s\t%s\n' "$key" "$value" >> "$FILE"
  fi
  echo "  ${key} = ${value}"
}

echo "==> ${FILE}"

# Maximum password age: 60 days.
set_login_def PASS_MAX_DAYS 60

# Minimum password age: 1 day. Stops a user cycling through the password
# history in one sitting to get back to their old password.
set_login_def PASS_MIN_DAYS 1

# Warn 7 days before expiry.
set_login_def PASS_WARN_AGE 7

# Minimum length 15 characters.
set_login_def PASS_MIN_LEN 15

# Default umask 077: new files are rw------- and new dirs rwx------.
# The RHEL 9 STIG requires 077, which is stricter than the RHEL default of 022.
set_login_def UMASK 077

# SHA512 password hashing. yescrypt is also acceptable on RHEL 9; SHA512 is
# what the STIG explicitly names, so use it unless you have a reason not to.
set_login_def ENCRYPT_METHOD SHA512

# SHA512 rounds. More rounds = more expensive offline cracking.
set_login_def SHA_CRYPT_MIN_ROUNDS 5000

# Create a home directory for new users so a login never lands in /.
set_login_def CREATE_HOME yes
