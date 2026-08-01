#!/bin/bash
# =============================================================================
# 60-remove-attack-surface.sh - delete what the service does not need
# =============================================================================
# DISA Container Guide requirements:
#   2.1  SSH server daemon disabled
#   2.12 Only essential capabilities
#   2.13 Only ports used by the service
#
# SSG rules in the neighbourhood:
#   package_telnet-server_removed, package_telnetd_removed
#   package_rsh-server_removed, package_ypserv_removed, package_tftp-server_removed
#   service_sshd_disabled
#
# This is the "microservice" argument from section 2.12 of the guide, made
# concrete. Anything left in the image is (a) a CVE you will triage every week
# and (b) a tool an attacker gets to use for free after a code-execution bug.
#
# WHAT WE DELIBERATELY DO NOT REMOVE, and why:
#   * dnf/rpm    - removing the package manager is a real hardening technique
#                  (it stops an attacker installing tools), but it also blinds
#                  every SBOM and CVE scanner, and it makes OpenSCAP unable to
#                  evaluate a large chunk of the RHEL 9 STIG. For a base image
#                  that has to be SCANNED, keep it. For a final application
#                  image that ships to production, removing it is defensible -
#                  scan the parent, then strip in the child. docs/02 covers the
#                  trade-off.
#   * /bin/sh    - same argument. Also, `kubectl exec` for incident response
#                  becomes impossible without it. Distroless images make the
#                  opposite call; both are valid.
# =============================================================================
set -euo pipefail

echo "==> removing unnecessary network daemons and clients"

# Packages that must never be in a container image. Most are absent from UBI
# already; this asserts it and covers a base image that grew one.
UNWANTED=(
  openssh-server openssh-clients
  telnet telnet-server
  ftp vsftpd tftp tftp-server
  rsh rsh-server
  ypserv ypbind
  talk talk-server
  xinetd
  sendmail postfix
  avahi avahi-autoipd
  cups
  bind bind-utils
  nfs-utils rpcbind
  net-snmp
)

for pkg in "${UNWANTED[@]}"; do
  if rpm -q "$pkg" >/dev/null 2>&1; then
    echo "  removing $pkg"
    dnf -y remove "$pkg" >/dev/null 2>&1 || echo "  WARNING: could not remove $pkg"
  fi
done

# Assertion, not a hope. If sshd exists at this point the build stops.
# Requirement 2.1 is not negotiable and there is no "probably fine" version.
echo "==> asserting no SSH daemon [2.1]"
for p in /usr/sbin/sshd /usr/bin/sshd /sbin/sshd; do
  if [[ -e "$p" ]]; then
    echo "ERROR: SSH daemon present at $p - violates requirement 2.1" >&2
    exit 1
  fi
done
if rpm -q openssh-server >/dev/null 2>&1; then
  echo "ERROR: openssh-server package installed - violates requirement 2.1" >&2
  exit 1
fi
echo "  no sshd binary, no openssh-server package"

# Compilers and fetchers left in a runtime image let an attacker build and pull
# their own tooling. The multi-stage build already keeps the Go toolchain out;
# this catches anything the base image brought along.
echo "==> removing build and fetch tooling"
for pkg in gcc gcc-c++ make cmake git subversion; do
  if rpm -q "$pkg" >/dev/null 2>&1; then
    dnf -y remove "$pkg" >/dev/null 2>&1 || true
  fi
done

# Clean up whatever the removals left behind, in this same layer.
#
# Note what is NOT cleaned here: /tmp. These scripts run from /tmp/harden, and
# an `rm -rf /tmp/*` in this one deletes the scripts that have not run yet -
# the loop then fails with "No such file or directory" on the next script, an
# error that reads like a permissions or line-ending problem and is neither.
# /tmp is cleaned by the Dockerfile: once in the package layer, and again when
# the whole /tmp/harden directory is removed after the loop finishes.
dnf -y clean all >/dev/null 2>&1 || true
rm -rf /var/cache/dnf /var/cache/yum /var/tmp/*

echo "==> package count: $(rpm -qa | wc -l)"
