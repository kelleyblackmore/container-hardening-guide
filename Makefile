SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

RUNTIME     ?= docker
IMAGE_NAME  ?= localhost/helloctr
IMAGE_TAG   ?= latest
IMAGE       ?= $(IMAGE_NAME):$(IMAGE_TAG)
IMAGE_SCAN  ?= localhost/helloctr-scan:latest
IMAGE_BAD   ?= localhost/helloctr-insecure:latest
IMAGE_SINGLE ?= localhost/helloctr-singlestage:latest

RESULTS     ?= results
TOOLS_BIN   ?= $(CURDIR)/.tools/bin
export PATH := $(TOOLS_BIN):$(PATH)

HARDENED_DIR := examples/hardened
INSECURE_DIR := examples/insecure
SINGLE_DIR   := examples/single-stage

.PHONY: help
help:
	@echo "container-hardening-guide"
	@echo ""
	@echo "  BUILD"
	@echo "    make build            Build the hardened image ($(IMAGE))"
	@echo "    make rebuild          Build with --no-cache --pull  [req 2.8, 2.15]"
	@echo "    make digests          Print the digests of the base images  [req 2.14]"
	@echo "    make compare-stages   Build the app single-stage vs multi-stage and"
	@echo "                          measure the difference               (docs/13)"
	@echo ""
	@echo "  LINT                                              (docs/06-hadolint.md)"
	@echo "    make lint             hadolint the hardened Dockerfile"
	@echo "    make lint-insecure    hadolint the anti-pattern - expected to fail"
	@echo "    make lint-k8s         kube-linter the deployment manifests"
	@echo ""
	@echo "  SCAN"
	@echo "    make scan-secrets     TruffleHog: history, tree, image layers  (docs/07)"
	@echo "    make scan-vulns       Trivy + Grype + Syft SBOM, and diff them (docs/08)"
	@echo "    make stig             OpenSCAP DISA STIG, baseline vs tailored (docs/05)"
	@echo "    make scan-all         Everything above"
	@echo ""
	@echo "  VERIFY"
	@echo "    make inspect          Prove the image config meets section 2"
	@echo "    make verify           Run it and exercise the endpoints"
	@echo ""
	@echo "  SETUP"
	@echo "    make install-tools    Install hadolint, trivy, grype, syft, trufflehog"
	@echo "    make clean            Remove results/ and built images"
	@echo ""
	@echo "  Variables: RUNTIME=$(RUNTIME) IMAGE=$(IMAGE)"

# =============================================================================
# BUILD
# =============================================================================
.PHONY: build
build:
	$(RUNTIME) build -f $(HARDENED_DIR)/Dockerfile -t "$(IMAGE)" $(HARDENED_DIR)
	@echo "==> built $(IMAGE)"

# [2.8] Cached layers are the mechanism by which a "rebuild" ships last month's
# packages. [2.15] --pull re-resolves the base tag so an updated base is picked
# up. Run this on a schedule (nightly/weekly), not just on code change: the
# image goes stale on its own, without anyone touching the repo.
.PHONY: rebuild
rebuild:
	$(RUNTIME) build --no-cache --pull -f $(HARDENED_DIR)/Dockerfile -t "$(IMAGE)" $(HARDENED_DIR)

# The anti-pattern image is NOT built by default. It installs an SSH server and
# a port scanner; there is no reason to have it on your machine. Lint and scan
# the Dockerfile instead.
.PHONY: build-insecure
build-insecure:
	@echo "!!! This builds a deliberately vulnerable image. Ctrl-C now unless you"
	@echo "!!! meant it. It is not needed for any other target."
	@sleep 5
	$(RUNTIME) build -f $(INSECURE_DIR)/Dockerfile -t "$(IMAGE_BAD)" $(INSECURE_DIR)

# Build the SAME application both ways and measure the difference.
# docs/13-multi-stage-builds.md explains what the numbers mean.
#
# Note the build context: the single-stage Dockerfile lives in its own directory
# but builds from examples/hardened, so both images compile identical source.
.PHONY: build-single-stage
build-single-stage:
	$(RUNTIME) build -f $(SINGLE_DIR)/Dockerfile -t "$(IMAGE_SINGLE)" $(HARDENED_DIR)

.PHONY: compare-stages
compare-stages: build build-single-stage
	@echo ""
	@echo "==================================================================="
	@echo " SINGLE-STAGE vs MULTI-STAGE - same source, same binary"
	@echo "==================================================================="
	@printf '%-34s %-18s %s\n' "" "single-stage" "two-stage"
	@printf '%-34s %-18s %s\n' "image size" \
	  "$$($(RUNTIME) images --format '{{.Size}}' $(IMAGE_SINGLE) | head -1)" \
	  "$$($(RUNTIME) images --format '{{.Size}}' $(IMAGE) | head -1)"
	@printf '%-34s %-18s %s\n' "layers" \
	  "$$($(RUNTIME) inspect --format '{{len .RootFS.Layers}}' $(IMAGE_SINGLE))" \
	  "$$($(RUNTIME) inspect --format '{{len .RootFS.Layers}}' $(IMAGE))"
	@printf '%-34s %-18s %s\n' "OS packages" \
	  "$$($(RUNTIME) run --rm --entrypoint /bin/sh $(IMAGE_SINGLE) -c "dpkg -l | grep -c '^ii'")" \
	  "$$($(RUNTIME) run --rm --entrypoint /bin/bash $(IMAGE) -c 'rpm -qa | wc -l')"
	@printf '%-34s %-18s %s\n' "build toolchain present" \
	  "$$($(RUNTIME) run --rm --entrypoint /bin/bash $(IMAGE_SINGLE) -c 'command -v go gcc git 2>/dev/null | wc -l') binaries" \
	  "$$($(RUNTIME) run --rm --entrypoint /bin/bash $(IMAGE) -c 'command -v go gcc git 2>/dev/null | wc -l') binaries"
	@printf '%-34s %-18s %s\n' "source code left in image" \
	  "$$($(RUNTIME) run --rm --entrypoint /bin/bash $(IMAGE_SINGLE) -c 'ls /src 2>/dev/null | wc -l') files" \
	  "$$($(RUNTIME) run --rm --entrypoint /bin/bash $(IMAGE) -c 'ls /src 2>/dev/null | wc -l') files"
	@echo ""
	@echo "--- the runtime binary is the SAME in both (sha256) ---"
	@$(RUNTIME) run --rm --entrypoint /bin/bash $(IMAGE_SINGLE) -c 'sha256sum /usr/local/bin/helloctr'
	@$(RUNTIME) run --rm --entrypoint /bin/bash $(IMAGE) -c 'sha256sum /app/helloctr'
	@echo ""
	@echo "--- everything above except the binary is packaging you chose to ship ---"
	@echo "--- now compare CVE counts:  make scan-vulns  vs the command below ---"
	@echo "      trivy image --severity HIGH,CRITICAL --ignore-unfixed $(IMAGE_SINGLE)"
	@echo ""
	@echo "Write-up: docs/13-multi-stage-builds.md"

# [2.14] Resolve tags to digests. Paste these into the Dockerfile ARGs to pin
# the build to bytes rather than to a mutable name.
.PHONY: digests
digests:
	@echo "Base image digests - pin these in $(HARDENED_DIR)/Dockerfile:"
	@for img in registry.access.redhat.com/ubi9/ubi:9.6 docker.io/library/golang:1.26-bookworm; do \
	  echo "  $$img"; \
	  $(RUNTIME) buildx imagetools inspect "$$img" 2>/dev/null | grep -m1 -i '^Digest:' || \
	    { $(RUNTIME) pull -q "$$img" >/dev/null && \
	      $(RUNTIME) inspect --format '  Digest: {{index .RepoDigests 0}}' "$$img"; }; \
	done

# =============================================================================
# LINT
# =============================================================================
.PHONY: lint
lint:
	hadolint --config .hadolint.yaml $(HARDENED_DIR)/Dockerfile
	hadolint --config .hadolint.yaml oscap/Containerfile.scan
	@echo "==> hadolint clean"

# Expected to produce a wall of findings. `-' lets make continue so you can read
# them; the point is to compare this output against the annotations in the file
# and notice what hadolint DOES NOT catch.
.PHONY: lint-insecure
lint-insecure:
	@echo "=== hadolint on the anti-pattern (findings are the expected output) ==="
	-hadolint --no-fail --config .hadolint.yaml $(INSECURE_DIR)/Dockerfile
	@echo ""
	@echo "Now open $(INSECURE_DIR)/Dockerfile and count the violations it"
	@echo "documents. hadolint found a fraction of them. Static Dockerfile"
	@echo "linting is one control, not the control."

.PHONY: lint-k8s
lint-k8s:
	kube-linter lint k8s/ || true

.PHONY: lint-shell
lint-shell:
	shellcheck scripts/*.sh oscap/*.sh $(HARDENED_DIR)/harden/*.sh

# =============================================================================
# SCAN
# =============================================================================
.PHONY: scan-secrets
scan-secrets:
	IMAGE="$(IMAGE)" OUT="$(RESULTS)/secrets" ./scripts/scan-secrets.sh "$(IMAGE)"

.PHONY: scan-vulns
scan-vulns: build
	IMAGE="$(IMAGE)" OUT="$(RESULTS)/vulns" ./scripts/scan-vulns.sh "$(IMAGE)"

.PHONY: stig
stig:
	RUNTIME=$(RUNTIME) IMAGE_APP="$(IMAGE)" IMAGE_SCAN="$(IMAGE_SCAN)" ./oscap/run-oscap.sh

.PHONY: scan-all
scan-all: lint scan-secrets scan-vulns stig

# =============================================================================
# VERIFY - prove the requirements, do not just claim them
# =============================================================================
# Everything here reads the image CONFIG, which is what an auditor can check
# without running anything. This is the evidence for section 2.
.PHONY: inspect
inspect: build
	@echo "=== [2.2] runs as a non-root user ==============================="
	@$(RUNTIME) inspect --format 'User        : {{.Config.User}}' "$(IMAGE)"
	@test -n "$$($(RUNTIME) inspect --format '{{.Config.User}}' $(IMAGE))" \
	  || { echo "FAIL: no USER set - container would run as root"; exit 1; }
	@echo ""
	@echo "=== [2.5][2.13] exposes only non-privileged ports ==============="
	@$(RUNTIME) inspect --format 'Ports       : {{range $$p, $$_ := .Config.ExposedPorts}}{{$$p}} {{end}}' "$(IMAGE)"
	@echo ""
	@echo "=== [2.6] has a process health check ============================"
	@$(RUNTIME) inspect --format 'Healthcheck : {{if .Config.Healthcheck}}{{.Config.Healthcheck.Test}}{{else}}MISSING{{end}}' "$(IMAGE)"
	@$(RUNTIME) inspect --format '{{if .Config.Healthcheck}}ok{{end}}' "$(IMAGE)" | grep -q ok \
	  || { echo "FAIL: no HEALTHCHECK"; exit 1; }
	@echo ""
	@echo "=== [2.1] no SSH daemon ========================================="
	@$(RUNTIME) run --rm --entrypoint /bin/bash "$(IMAGE)" -c \
	  'test ! -e /usr/sbin/sshd && ! rpm -q openssh-server >/dev/null 2>&1 && echo "ok: no sshd, no openssh-server"'
	@echo ""
	@echo "=== [2.3] no setuid/setgid executables =========================="
	@# --user 0: as the app user, find cannot traverse /root or /var/lib/rhsm,
	@# so a setuid binary in an unreadable directory would be missed.
	@$(RUNTIME) run --rm --user 0 --entrypoint /bin/bash "$(IMAGE)" -c \
	  'n=$$(find / -xdev -perm /6000 -type f | wc -l); echo "setuid/setgid files: $$n"; test "$$n" -eq 0'
	@echo ""
	@echo "=== [2.9][2.18] no obvious secrets in the build history ========="
	@$(RUNTIME) history --no-trunc "$(IMAGE)" \
	  | grep -Ei '(password|secret|token|api[_-]?key|BEGIN .* PRIVATE KEY)' \
	  && { echo "FAIL: credential-shaped string in image history"; exit 1; } \
	  || echo "ok: nothing credential-shaped in the layer history"
	@echo ""
	@echo "=== [2.8] layer count and size =================================="
	@$(RUNTIME) history "$(IMAGE)" | head -25
	@$(RUNTIME) inspect --format 'Total size  : {{.Size}} bytes' "$(IMAGE)"

# Runtime proof, with the same restrictions the Kubernetes manifest applies:
# read-only root filesystem, no capabilities, no privilege escalation, non-root.
# If the image only works without these flags, it is not ready to deploy.
.PHONY: verify
verify: build
	@echo "==> starting with --read-only, --cap-drop=ALL, --security-opt=no-new-privileges"
	@$(RUNTIME) rm -f helloctr-verify >/dev/null 2>&1 || true
	$(RUNTIME) run -d --name helloctr-verify \
	  --read-only \
	  --tmpfs /tmp:rw,noexec,nosuid,size=32m \
	  --cap-drop=ALL \
	  --security-opt=no-new-privileges \
	  --user 1001:1001 \
	  -p 8080:8080 "$(IMAGE)"
	@sleep 3
	@echo ""; echo "==> GET /"        ; $(RUNTIME) exec helloctr-verify /app/helloctr -healthcheck && echo "healthcheck: exit 0"
	@echo "==> effective user in the container:"
	@$(RUNTIME) exec helloctr-verify id 2>/dev/null || echo "(no id binary - fine)"
	@echo "==> container health status:"
	@$(RUNTIME) inspect --format '{{.State.Health.Status}}' helloctr-verify || true
	@echo "==> logs:"; $(RUNTIME) logs helloctr-verify
	@$(RUNTIME) rm -f helloctr-verify >/dev/null

# =============================================================================
# SETUP
# =============================================================================
.PHONY: install-tools
install-tools: $(TOOLS_BIN)
	@echo "==> trivy";      curl -sfL  https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b "$(TOOLS_BIN)"
	@echo "==> grype";      curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh              | sh -s -- -b "$(TOOLS_BIN)"
	@echo "==> syft";       curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh               | sh -s -- -b "$(TOOLS_BIN)"
	@echo "==> trufflehog"; curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b "$(TOOLS_BIN)"
	@echo "==> hadolint";   curl -sSfL -o "$(TOOLS_BIN)/hadolint" "https://github.com/hadolint/hadolint/releases/latest/download/hadolint-$$(uname -s)-$$(uname -m)" && chmod +x "$(TOOLS_BIN)/hadolint"
	@echo ""; echo "==> add to PATH:  export PATH=\"$(TOOLS_BIN):\$$PATH\""

$(TOOLS_BIN):
	mkdir -p "$(TOOLS_BIN)"

.PHONY: clean
clean:
	rm -rf "$(RESULTS)" .tools
	-$(RUNTIME) rmi -f "$(IMAGE)" "$(IMAGE_SCAN)" "$(IMAGE_BAD)" "$(IMAGE_SINGLE)" 2>/dev/null
