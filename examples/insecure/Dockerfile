# =============================================================================
#  THE ANTI-PATTERN CONTAINER  --  DO NOT COPY THIS. DO NOT DEPLOY THIS.
# =============================================================================
#  This file exists to be scanned and to fail. It is the "before" picture for
#  examples/hardened/Dockerfile.
#
#  Every line is tagged with the DISA Container Image Creation and Deployment
#  Guide V2R0.6 requirement it VIOLATES. Run the linters against it to see what
#  each tool catches and, more interestingly, what each tool misses:
#
#      make lint-insecure      # hadolint  -> catches maybe half of these
#      make scan-insecure      # trivy + grype + trufflehog
#
#  The gap between "hadolint is happy" and "this image is safe to run" is the
#  entire point of this repository.
# =============================================================================

# [2.10] [2.14] [2.17] Unpinned :latest from Docker Hub. Not a DoD-approved
#        source, no digest, no signature verification. What you build today and
#        what you build tomorrow are different images with the same name, and
#        you have no way to prove which one you shipped.
FROM ubuntu:latest

# Deprecated instruction; use LABEL org.opencontainers.image.authors instead.
MAINTAINER devteam@example.mil

# [2.4] [2.8] [2.11] [2.12] Four violations in one instruction:
#   - No `apt-get update` in the same layer as install, so a cached update
#     layer serves stale package indexes on rebuild.
#   - No version pinning: the outcome of this build is not knowable in advance.
#   - No cleanup, so /var/lib/apt/lists ships inside the image.
#   - Installs a pile of software the service does not need. Every one of these
#     is attack surface and a CVE queue: netcat and nmap are post-exploitation
#     tools you are helpfully pre-installing for the attacker.
RUN apt-get update
RUN apt-get install -y curl wget netcat-openbsd nmap vim git sudo openssh-server python3 build-essential

# [2.1] The SSH daemon. This is the single most-cited container finding. A
#       container is not a server you log into - it is a process. When you need
#       to change it, you rebuild it. When you need to look at it, you use
#       `kubectl exec` or ship the logs out.
RUN systemctl enable ssh || true
EXPOSE 22

# [2.5] [2.13] Privileged port. Binding 80 requires root or
#       CAP_NET_BIND_SERVICE, which is why the image below runs as root.
#       Map 80 -> 8080 at the Service layer instead.
EXPOSE 80
EXPOSE 443
# ...and a few more "just in case", each one advertising a service and its
# version to anyone who port-scans the pod. [2.13]
EXPOSE 3306
EXPOSE 8000-8100

# [2.9] [2.18] Embedded credentials. These are in the image history forever.
#       `docker history --no-trunc` prints them. Deleting the file in a later
#       layer does NOT remove them - the layer that added them still exists and
#       is still distributed. See docs/07-trufflehog.md.
#
#       A note on the placeholder values below, because the story is instructive.
#       The first version of this file used realistic-looking dummy credentials
#       in each provider's real format. GitHub's push protection scanned the
#       push, matched the Stripe key pattern, and REJECTED it outright - the
#       repository could not be created until the string was changed. The
#       credentials were fake and the intent was educational, and none of that
#       mattered: the pattern matched, so the push was blocked.
#
#       That is the control working exactly as designed, on the exact class of
#       mistake it exists to stop, before a single byte reached a public
#       repository. Turn it on: Settings -> Code security -> Push protection.
#       Then read docs/07 for the tools that cover what it does not.
ENV DB_PASSWORD=SuperSecret123!
ENV AWS_SECRET_ACCESS_KEY=EXAMPLE-40-CHAR-AWS-SECRET-NOT-A-REAL-KEY
ARG GITHUB_TOKEN=ghp_EXAMPLE_PLACEHOLDER_NOT_A_REAL_TOKEN
RUN echo "api_key=sk_live_EXAMPLE_PLACEHOLDER_NOT_A_REAL_KEY" > /etc/app.conf

# [2.4] ADD with a remote URL. It fetches over the network at build time,
#       nothing scans what comes back, and if the URL is compromised your image
#       is compromised. ADD also auto-extracts archives, so a malicious tarball
#       can write outside the destination directory. Use COPY, and fetch
#       dependencies through a proxy that scans them.
ADD https://example.com/installer.sh /tmp/installer.sh
RUN chmod +x /tmp/installer.sh && /tmp/installer.sh

# [2.4] curl | bash. The remote content is executed before anyone can look at
#       it, and it is different on every build.
RUN curl -fsSL https://example.com/setup | bash

# [2.3] Deliberately granting setuid root. Now any code execution as any user
#       inside the container is code execution as root inside the container -
#       and with a host path mount or a shared namespace, potentially outside.
COPY --chown=root:root entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 4755 /usr/local/bin/entrypoint.sh

# [2.3] Passwordless sudo for everyone.
RUN echo "ALL ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# [2.9] Copying the whole build context in. This is how .git, .env, ~/.aws,
#       id_rsa, and terraform.tfstate end up inside production images. Use a
#       .dockerignore and copy only what you need.
COPY . /app

# [2.2] No USER instruction, so the container runs as root (UID 0). Combined
#       with a hostPath mount or a shared namespace, root in the container is
#       effectively root on the node.
WORKDIR /app

# [2.6] No HEALTHCHECK, so the platform cannot tell a wedged process from a
#       working one.

# Shell form: the real process is a child of /bin/sh, which does not forward
# SIGTERM. Graceful shutdown never happens; the container gets SIGKILLed after
# the termination grace period.
CMD /usr/local/bin/entrypoint.sh && python3 -m http.server 80
