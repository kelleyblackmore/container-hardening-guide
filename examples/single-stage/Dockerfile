# syntax=docker/dockerfile:1
# =============================================================================
#  THE SINGLE-STAGE BUILD  --  the control group, not a recommendation
# =============================================================================
#  This builds the EXACT SAME application as examples/hardened, from the exact
#  same source, in one stage instead of two. It is here to be measured against
#  the two-stage version, not to be deployed.
#
#  Nothing here is stupid. This is what a reasonable person writes on the first
#  day: start from the language's official image, copy the source, build it, run
#  it. It works. Every test passes. It ships.
#
#  What it also does is ship the entire Go toolchain to production: the
#  compiler, the linker, the assembler, the module cache, git, curl, the full
#  Debian userland, and the source code of your application. All of it in the
#  image, all of it attack surface, all of it in your CVE report every week.
#
#  Build it and compare:
#      make compare-stages
#
#  The write-up: docs/13-multi-stage-builds.md
# =============================================================================

# The build context is examples/hardened/, so this reads the same app/ source
# the hardened image uses:
#     docker build -f examples/single-stage/Dockerfile examples/hardened

FROM docker.io/library/golang:1.26-bookworm

WORKDIR /src

# Same source, same compiler, same flags. The binary produced here is
# byte-comparable to the one in the hardened image.
COPY app/go.mod ./
COPY app/main.go ./

ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOFLAGS="-trimpath"
RUN go build -ldflags="-s -w" -o /usr/local/bin/helloctr .

# Everything below is a token effort at hardening this image, and the point is
# that it does not help much. You can add a USER, you can EXPOSE a high port,
# you can add a HEALTHCHECK - and the compiler is still in the image.
RUN groupadd --system --gid 1001 appuser \
 && useradd --system --uid 1001 --gid 1001 --no-create-home --shell /usr/sbin/nologin appuser

EXPOSE 8080/tcp
USER 1001:1001

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/usr/local/bin/helloctr", "-healthcheck"]

ENTRYPOINT ["/usr/local/bin/helloctr"]

# What is still wrong, none of which a USER line fixes:
#
#   [2.12] The Go toolchain, git, and a full Debian userland are present. An
#          attacker with code execution has a compiler and a fetch tool.
#   [2.12] The package COUNT barely moves (205 vs 188) and that is the trap:
#          the Go toolchain is unpacked into /usr/local/go, outside dpkg
#          entirely, so ~700 MB of compiler arrives without incrementing any
#          package-manager metric. See docs/13 section 13.2.
#   [2.9]  /src still contains your source code. On a private codebase that is
#          the leak nobody notices, because the image "works".
#   [2.8]  Roughly 2.3x the size of the two-stage image. Every pull, every
#          node, every rollback.
#   [2.16] Debian, so the RHEL 9 STIG does not apply - you would need the
#          Ubuntu/Debian equivalent, and the base image does not ship hardened.
#
# The two-stage version in examples/hardened fixes all of that with one extra
# FROM line and one COPY --from.
