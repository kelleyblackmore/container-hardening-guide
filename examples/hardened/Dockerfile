# syntax=docker/dockerfile:1
# =============================================================================
#  THE ANNOTATED HARDENED CONTAINER
# =============================================================================
#  Every instruction below is numbered as a LAYER STEP and tagged with the
#  requirement it satisfies from:
#
#     DISA Container Image Creation and Deployment Guide, V2 R0.6 (02 Nov 2020)
#
#  Tags look like [2.5] and map to a section of that guide. The full text of
#  each requirement, the CCI, and the NIST 800-53 control are in
#  docs/03-image-creation-requirements.md. A line-by-line walkthrough of THIS
#  file is in examples/hardened/README.md.
#
#  Read the layer model first: docs/01-anatomy-of-a-container-image.md
#  Read what belongs in each layer: docs/02-layer-by-layer-hardening.md
# =============================================================================


# -----------------------------------------------------------------------------
# BUILD ARGUMENTS
# -----------------------------------------------------------------------------
# Declared before the first FROM so they are global and usable in every stage.
#
# [2.10] [2.14] [2.17] Base images come from an approved source and SHOULD be
#        pinned by digest, not by tag. A tag is a mutable pointer; a digest is
#        the sha256 of the image manifest and cannot be repointed at you.
#        In a DoD build you replace these with the Iron Bank equivalents:
#           registry1.dso.mil/ironbank/redhat/ubi/ubi9
#           registry1.dso.mil/ironbank/google/golang/golang-1.23
#        See docs/11-approved-sources.md.
#
#        This repo pins by TAG so the example keeps building for readers. To
#        pin by digest (what you actually ship):
#           make digests           # prints the current digests
#           RUNTIME_IMAGE=registry.access.redhat.com/ubi9/ubi@sha256:<digest>
ARG BUILDER_IMAGE=docker.io/library/golang:1.23-bookworm
ARG RUNTIME_IMAGE=registry.access.redhat.com/ubi9/ubi:9.6

# Non-root identity the service runs as. 1001 is conventional for OpenShift-
# style images; group 0 keeps it usable when the platform assigns a random UID.
ARG APP_UID=1001
ARG APP_GID=1001
ARG APP_USER=appuser
ARG APP_PORT=8080


# #############################################################################
#  STAGE 1 - BUILD
# #############################################################################
#  [2.8] [2.12] A multi-stage build is the single most effective hardening
#  move available to you. The compiler, module cache, headers, git, and every
#  build-time dependency live ONLY in this stage. None of it is in the shipped
#  image, so none of it is attack surface and none of it shows up in a CVE
#  scan. What crosses the stage boundary is exactly one file: the binary.
# #############################################################################
FROM ${BUILDER_IMAGE} AS build

WORKDIR /src

# [2.4] COPY, never ADD. ADD can fetch remote URLs and auto-extract archives -
#       two behaviours with unknown outcomes that bypass scanning. COPY only
#       copies local files from the build context. Nothing else.
#
# [2.4] Copy the module manifest first so the dependency layer is cached
#       independently of the source. This is a cache strategy, not a security
#       control - but note the tension with [2.8]: caching is what lets a stale
#       layer survive a rebuild. See docs/02 for how to break the cache
#       deliberately (--no-cache / --pull) on scheduled rebuilds.
COPY app/go.mod ./
COPY app/main.go ./

# CGO_ENABLED=0  -> a statically linked binary with no libc dependency, so the
#                   runtime image needs no shared libraries for it to run.
# -trimpath      -> strips local filesystem paths out of the binary; those paths
#                   leak build-host directory structure and usernames.
# -s -w          -> drop the symbol table and DWARF debug info. Smaller binary,
#                   less information handed to anyone who pulls the image.
# [2.4] The app has zero third-party dependencies, so this build needs no
#       network at all. That is the goal the guide describes: "ensure containers
#       can be built without connection to the internet". When you do have
#       dependencies, vendor them or pull them from an internal proxy that has
#       already scanned them.
ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOFLAGS="-trimpath"
RUN set -eux; \
    go vet ./...; \
    go build -ldflags="-s -w" -o /out/helloctr .; \
    test -x /out/helloctr


# #############################################################################
#  STAGE 2 - RUNTIME  (this is the image you ship)
# #############################################################################

# -----------------------------------------------------------------------------
# LAYER STEP 1 - THE BASE LAYER
# -----------------------------------------------------------------------------
# [2.10] [2.14] [2.17] Signed, approved, verifiable base image.
#        Red Hat signs UBI content and publishes digests. Verify before you
#        trust: see docs/10-stig-a-container-walkthrough.md step 1 for
#        `skopeo inspect` and cosign verification.
#
# Why full UBI9 and not ubi9-minimal or a distroless image? Because this repo
# has to SHOW you an OpenSCAP STIG scan, and the RHEL 9 STIG content evaluates
# an RPM-managed operating system. A distroless image is smaller and has less
# attack surface, but there is no OS to scan and the RHEL 9 STIG does not apply
# to it. Both answers are defensible - docs/02 covers when to pick which.
FROM ${RUNTIME_IMAGE}

ARG APP_UID
ARG APP_GID
ARG APP_USER
ARG APP_PORT

# The default RUN shell is `/bin/sh -c`, which reports the exit status of the
# LAST command in a pipeline. `false | true` succeeds. That means a failing
# check on the left of a pipe silently passes the build - which is how a broken
# verification step ends up shipping for six months without anyone noticing.
# pipefail makes the pipeline fail if ANY stage fails. (hadolint DL4006)
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# -----------------------------------------------------------------------------
# LAYER STEP 2 - METADATA
# -----------------------------------------------------------------------------
# Metadata is not a security control by itself, but it is what makes an image
# auditable: where it came from, what it is, and which commit built it.
# OCI standard annotation keys - use these, not the deprecated MAINTAINER.
# [2.9] Nothing sensitive goes in a label. Labels are readable by anyone who
#       can pull the image, with `docker inspect`, without ever running it.
LABEL org.opencontainers.image.title="helloctr" \
      org.opencontainers.image.description="Reference hardened container for the DISA Container Image Creation and Deployment Guide V2R0.6" \
      org.opencontainers.image.vendor="container-hardening-guide" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/kelleyblackmore/container-hardening-guide" \
      io.stigs.guide="DISA Container Image Creation and Deployment Guide V2R0.6"

# -----------------------------------------------------------------------------
# LAYER STEP 3 - PATCH AND MINIMISE THE OS
# -----------------------------------------------------------------------------
# One RUN, chained with && , cleanup in the SAME layer.
#
# [2.8] Why one RUN: a layer is a filesystem diff. If you install in one RUN and
#       `dnf clean all` in the next, the cache files are still present in the
#       earlier layer and still ship with the image - deleting a file in a later
#       layer only adds a whiteout entry, it does not reclaim the bytes. The
#       delete must happen in the layer that created the files.
#
# [2.8] Why --refresh: it forces metadata expiry so a cached layer cannot serve
#       you last month's package list on a rebuild. Combine with
#       `docker build --no-cache --pull` in your scheduled rebuild job.
#
# [2.11] Why nodocs / gpgcheck: install only verified packages. UBI repos have
#        gpgcheck=1 by default - the `rpm -q --qf %{SIGPMD5}` check below is a
#        belt-and-braces assertion that packages really are signed.
#
# [2.12] install_weak_deps=0: do not drag in "recommended" packages you never
#        asked for. Every unnecessary package is attack surface plus a CVE you
#        will have to triage.
#
# [2.1] Note what is NOT installed: no openssh-server. The SSH daemon must be
#       absent. To inspect a running container use `kubectl exec` / `docker
#       exec`; to change it, rebuild the image.
RUN set -eux; \
    dnf -y --refresh upgrade --security --setopt=install_weak_deps=0 --nodocs; \
    \
    # [2.1] Assert the SSH daemon is not present, and remove the client and
    #       other remote-access tooling if the base ever grows them.
    #
    #       Note the assertion form. `! rpm -q openssh-server` looks like it
    #       asserts absence, but under `set -e` a negated command does NOT
    #       abort - bash exempts it from errexit. The check would silently
    #       pass with sshd installed. shellcheck flags this as SC2251, which
    #       is exactly why hadolint runs shellcheck over every RUN.
    dnf -y remove openssh-server openssh-clients telnet ftp rsh 2>/dev/null || true; \
    if rpm -q openssh-server >/dev/null 2>&1 || [ -x /usr/sbin/sshd ]; then \
        echo "ERROR: SSH daemon present - violates requirement 2.1" >&2; exit 1; \
    fi; \
    \
    # [2.11] Every installed package must carry a valid signature from the
    #        repository's GPG key. An unsigned package here FAILS THE BUILD.
    #
    #        The query looks worse than it is. rpm stores the signature in one
    #        of four tags depending on how the package was signed, so you have
    #        to fall through all four: DSAHEADER, RSAHEADER, SIGGPG, SIGPGP.
    #        Checking only SIGPGP/SIGGPG - the obvious first attempt - reports
    #        most of a modern RHEL 9 base as "unsigned", because those packages
    #        carry an RSA *header* signature and nothing in SIGPGP.
    #
    #        A signed package renders "... Key ID <keyid>"; an unsigned one
    #        renders "(none)". gpg-pubkey entries are the imported keys
    #        themselves, not packages, so they are excluded.
    #        The `|| true` is required, not sloppiness: with `set -e` and
    #        `pipefail`, grep exiting 1 because it matched NOTHING - the good
    #        case, every package is signed - would abort the build.
    unsigned="$( { rpm -qa --qf \
        '%{NAME} %|DSAHEADER?{%{DSAHEADER:pgpsig}}:{%|RSAHEADER?{%{RSAHEADER:pgpsig}}:{%|SIGGPG?{%{SIGGPG:pgpsig}}:{%|SIGPGP?{%{SIGPGP:pgpsig}}:{(none)}|}|}|}|\n' \
        | grep -v '^gpg-pubkey ' | grep -v 'Key ID' | awk '{print $1}'; } || true)"; \
    if [ -n "$unsigned" ]; then \
        echo "ERROR: unsigned package(s) present: $unsigned" >&2; exit 1; \
    fi; \
    \
    # [2.8] Clean in the same layer that created the cache.
    dnf -y clean all; \
    rm -rf /var/cache/dnf /var/cache/yum /var/log/dnf.* /var/log/hawkey.log /tmp/* /var/tmp/*

# -----------------------------------------------------------------------------
# LAYER STEP 4 - OS HARDENING (the STIG remediation layer)
# -----------------------------------------------------------------------------
# [2.16] "The container image must implement any STIG or SRG guidance relevant
#        to the container service." For a RHEL-family image that means the RHEL
#        9 STIG, minus the rules that are Not Applicable to a container (kernel,
#        bootloader, auditd, physical console...). Those exclusions are not
#        hand-waving - they are recorded in oscap/not-applicable.rules and
#        rendered into a machine-readable tailoring file. See docs/05.
#
# Each script is small, single-purpose, and names the STIG rule it implements.
# Run them in one layer so the intermediate state never ships.
COPY --chmod=0755 harden/ /tmp/harden/
RUN set -eux; \
    for s in /tmp/harden/*.sh; do echo "==> $s"; "$s"; done; \
    rm -rf /tmp/harden

# -----------------------------------------------------------------------------
# LAYER STEP 5 - REMOVE SETUID / SETGID
# -----------------------------------------------------------------------------
# [2.3] "Permissions removed from executables that allow a user to execute
#       software at higher privileges."
#
# A setuid-root binary inside a container is a privilege-escalation primitive:
# if an attacker gets code execution as the unprivileged app user, `su`,
# `mount`, `chsh`, `pkexec` and friends are the ladder back up to root inside
# the namespace. The container should never need them - it is not a login host.
#
# This is belt-and-braces with the deployment-side control
# `allowPrivilegeEscalation: false` + `securityContext.capabilities.drop: [ALL]`
# (see k8s/deployment.yaml). Do BOTH: image-side so the binaries are inert even
# on a misconfigured platform, deployment-side so the kernel refuses the
# transition even if a setuid binary sneaks back in.
#
# -xdev keeps us out of mounted pseudo-filesystems. The find runs before USER,
# so it still has permission to chmod.
RUN set -eux; \
    find / -xdev -perm /6000 -type f -print -exec chmod -c ug-s {} + ; \
    # Assert: nothing setuid/setgid survives. Build fails if one does.
    remaining="$(find / -xdev -perm /6000 -type f -print)"; \
    if [ -n "$remaining" ]; then echo "ERROR: setuid/setgid remain: $remaining" >&2; exit 1; fi

# -----------------------------------------------------------------------------
# LAYER STEP 6 - THE NON-ROOT IDENTITY
# -----------------------------------------------------------------------------
# [2.2] The image must be built to execute as a non-privileged user.
#
# Create the account with a FIXED numeric UID. This matters: Kubernetes'
# `runAsNonRoot: true` check inspects the numeric UID in the image config. If
# USER names a user that the platform cannot resolve to a number, admission can
# reject the pod. A numeric USER is unambiguous.
#
# --system     -> no aging info, UID from the system range, no mail spool
# -s /sbin/nologin -> the account cannot be logged into even if something did
#                     manage to start a login service
RUN set -eux; \
    groupadd --system --gid "${APP_GID}" "${APP_USER}"; \
    useradd  --system --uid "${APP_UID}" --gid "${APP_GID}" \
             --home-dir /app --no-create-home --shell /sbin/nologin \
             --comment "helloctr service account" "${APP_USER}"; \
    install -d -o "${APP_UID}" -g "${APP_GID}" -m 0755 /app

# -----------------------------------------------------------------------------
# LAYER STEP 7 - THE APPLICATION LAYER
# -----------------------------------------------------------------------------
# [2.4] COPY from a prior build stage. No download, no extraction, no network.
#       The outcome is exactly one known file.
# --chown/--chmod set ownership in the same layer, avoiding a second full copy
# of the binary in a follow-up `RUN chown` layer.
#
# Mode 0555 = read + execute, no write, for everyone including the owner. The
# app cannot overwrite its own binary. This is the LAST layer with content,
# which is deliberate: it is the most volatile thing in the image, so a rebuild
# after a code change reuses every layer above it. See docs/01.
COPY --from=build --chown=${APP_UID}:${APP_GID} --chmod=0555 /out/helloctr /app/helloctr

# -----------------------------------------------------------------------------
# LAYER STEP 8 - RUNTIME CONFIGURATION
# -----------------------------------------------------------------------------
# [2.9] [2.18] ENV is for non-sensitive configuration ONLY. Anything set here
#       is visible in `docker inspect`, in the image history, and to every
#       process in the container. APP_SECRET_FILE is a PATH, not a secret -
#       the file it points at is mounted at runtime from a Kubernetes Secret.
#       Build-time secrets, when unavoidable, use BuildKit:
#           RUN --mount=type=secret,id=token ...
#       which never writes the value into a layer. See docs/07-trufflehog.md.
#
# hadolint DL3064 fires on the NAME APP_SECRET_FILE, which matches its
# "sensitive-looking variable" list. It is a false positive, and the distinction
# is the entire point of this block: the value is a filesystem PATH, and the file
# it names is mounted at runtime from a Kubernetes Secret. Suppressed narrowly,
# here, with the reason attached - never by adding DL3064 to the global ignore
# list in .hadolint.yaml, which would also suppress the real thing.
# hadolint ignore=DL3064
ENV PORT=${APP_PORT} \
    APP_SECRET_FILE=/run/secrets/app/token \
    HOME=/app

WORKDIR /app

# [2.5] [2.13] Expose ONLY the non-privileged port the service actually uses.
#       Ports below 1024 require CAP_NET_BIND_SERVICE or root. Map 80 -> 8080
#       at the platform layer instead (see k8s/deployment.yaml, Service.port
#       80 -> targetPort 8080). EXPOSE is documentation the scanners and the
#       platform read; it does not itself open anything.
EXPOSE ${APP_PORT}/tcp

# [2.2] Drop privileges. Everything after this line runs as ${APP_UID}. This is
#       the LAST thing before the entrypoint - every step that needed root
#       (patching, chmod, useradd) is already done and baked into a lower layer.
USER ${APP_UID}:${APP_GID}

# [2.6] Process health check. The container platform polls this to decide
#       whether the instance is still doing its job.
#
#       Two things to know:
#       1. It calls the app's own `-healthcheck` flag, so the image needs no
#          curl and no shell. Exec form -> no /bin/sh process is spawned.
#       2. Kubernetes IGNORES Dockerfile HEALTHCHECK. You still need it (DISA
#          requires it, and Docker/Compose/Swarm/Nomad all honour it), but the
#          Kubernetes equivalents are the liveness and readiness probes in
#          k8s/deployment.yaml - requirements [3.8] and [3.9].
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/app/helloctr", "-healthcheck"]

# Exec form (JSON array): the binary becomes PID 1 directly and receives
# SIGTERM. Shell form would wrap it in /bin/sh -c, which does NOT forward
# signals - your container would be SIGKILLed after the grace period instead of
# shutting down cleanly.
ENTRYPOINT ["/app/helloctr"]
