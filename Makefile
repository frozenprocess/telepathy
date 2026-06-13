# telepathy — build orchestration.
#
# The engine is its own Go module that builds against the *untouched* Calico
# source tree. We clone Calico at a pinned tag into third_party/calico and tie
# the two together with a repo-root go.work (Go workspace mode), so no files are
# ever injected into the Calico checkout.
#
#   make build      # clone Calico (if needed), create go.work, build the binary
#   make test       # build, then feed a sample Request in and print the raw output
#   make calico     # just fetch the pinned Calico source tree
#   make clean      # remove build artifacts
#   make distclean  # also remove the Calico checkout and go.work

CALICO_REPO    ?= https://github.com/projectcalico/calico.git
CALICO_VERSION ?= v3.32.0
CALICO_DIR     ?= third_party/calico

# Antrea source tree — the second CNI provider. It builds as its OWN binary
# (engines/antrea) over this tree, in a separate Go module/workspace, so its
# native dependency versions never have to reconcile with Calico's. Building the
# two CNIs as separate binaries is what removes the cross-CNI dependency
# conflicts (network-policy-api, controller-runtime) — there is no shared graph,
# hence no version pin.
ANTREA_REPO    ?= https://github.com/antrea-io/antrea.git
ANTREA_VERSION ?= v2.6.1
ANTREA_DIR     ?= third_party/antrea

# The shell binary (Calico in-process + the api contract).
BIN            ?= bin/telepathy
# The out-of-process Antrea engine binary, placed next to BIN so the shell finds
# it automatically (see proxy.go locate()).
ANTREA_BIN     ?= bin/telepathy-engine-antrea
ANTREA_MOD     ?= engines/antrea

# Docker build environment. GO_VERSION tracks .go-version so the container
# toolchain matches what the repo pins; override either var to retarget.
GO_VERSION     ?= $(shell cat .go-version 2>/dev/null || echo 1.25.6)
DOCKER_IMAGE   ?= golang:$(GO_VERSION)

# Build target for `build-docker`. The engine pulls in Linux-only Calico/Felix
# packages (syscall.Mount, unix.BPF_FS_MAGIC, ...), so GOOS is pinned to linux —
# this binary does NOT run on a macOS/Windows host, only in a Linux environment.
# GOARCH defaults to the host CPU so it runs natively under Docker on the same
# machine; override TARGET_OS / TARGET_ARCH to retarget.
TARGET_OS      ?= linux
TARGET_ARCH    ?= $(shell uname -m | sed -e 's/x86_64/amd64/' -e 's/aarch64/arm64/')

# Docker image built by `make image`. IMAGE_TAG defaults to the engine version.
# PLATFORM defaults to the host CPU so the image loads locally and runs natively
# under Docker (incl. on Apple Silicon Macs); set e.g.
# PLATFORM=linux/amd64,linux/arm64 for a multi-arch build (requires buildx +
# --push, since multi-arch images can't be loaded into the local daemon).
IMAGE_NAME     ?= telepathy
IMAGE_TAG      ?= $(ENGINE_VERSION)
IMAGE          ?= $(IMAGE_NAME):$(IMAGE_TAG)
PLATFORM       ?= linux/$(TARGET_ARCH)
# How the built image is delivered. --load drops a single-arch image into the
# local Docker daemon (needed with the buildx container driver). For a
# multi-arch PLATFORM, override with OUTPUT=--push (multi-arch can't be loaded
# locally and must go to a registry).
OUTPUT         ?= --load

# Version stamped into the binary (surfaced by `telepathy --version`).
# ENGINE_VERSION falls back to `git describe` when this repo has tags.
ENGINE_VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GIT_COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE     ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS        := -X main.engineVersion=$(ENGINE_VERSION) \
                  -X main.calicoVersion=$(CALICO_VERSION) \
                  -X main.gitCommit=$(GIT_COMMIT) \
                  -X main.buildDate=$(BUILD_DATE)

# The engine renders dataplane programs rather than loading them, so it builds
# without cgo. CGO_ENABLED=0 selects Felix's libbpf_stub.go (//go:build !cgo)
# and avoids needing libbpf C headers on the build host.
export CGO_ENABLED=0

.PHONY: help all build build-shell build-antrea build-docker image test calico antrea clean distclean

# Running `make` with no target prints the help below.
.DEFAULT_GOAL := help

# Sample evaluation input for `make test`: a topology piped on stdin plus a
# NetworkPolicy layered in via -policy. Override to point the smoke test at
# your own Request/manifest.
TEST_INPUT  ?= testdata/sample-topology.yaml
TEST_POLICY ?= testdata/sample-policy.yaml
TEST_ASSERT ?= testdata/sample-assertions.yaml

all: build  ## Build everything (default of `make all`)

# --- Help ------------------------------------------------------------------
# Self-documenting: scans this Makefile for targets annotated with a `##`
# comment and prints them. To list a new target here, just add `## description`
# after its prerequisites.
help:  ## Show this help
	@echo "telepathy — available targets:"
	@echo ""
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "} {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Common overridable vars: CALICO_VERSION, BIN, TEST_INPUT, TEST_POLICY, GO_VERSION, DOCKER_IMAGE"

# --- Calico source ---------------------------------------------------------
# Shallow clone of just the pinned tag. The directory existing is the marker
# that the checkout is present, so re-running is a no-op.
$(CALICO_DIR):
	@echo ">> cloning $(CALICO_REPO) @ $(CALICO_VERSION) into $(CALICO_DIR)"
	git clone --depth 1 --branch $(CALICO_VERSION) $(CALICO_REPO) $(CALICO_DIR)

calico: $(CALICO_DIR)  ## Fetch the pinned Calico source tree

# --- Antrea source ---------------------------------------------------------
# Shallow clone of the pinned Antrea tag, vendored the same way as Calico.
$(ANTREA_DIR):
	@echo ">> cloning $(ANTREA_REPO) @ $(ANTREA_VERSION) into $(ANTREA_DIR)"
	git clone --depth 1 --branch $(ANTREA_VERSION) $(ANTREA_REPO) $(ANTREA_DIR)

antrea: $(ANTREA_DIR)  ## Fetch the pinned Antrea source tree

# --- Workspaces ------------------------------------------------------------
# Each binary builds in its OWN workspace so the two CNI module graphs stay
# isolated (no shared-dependency reconciliation, no version pins). Both are
# generated build artifacts (gitignored), not edited.
#
# Root: the shell + the api contract + Calico's tree.
go.work: $(CALICO_DIR)
	@echo ">> initialising shell workspace (. + ./api + $(CALICO_DIR))"
	go work init . ./api $(CALICO_DIR)

# Antrea engine: its module + the api contract + Antrea's tree, with Antrea's
# native dependency versions.
$(ANTREA_MOD)/go.work: $(ANTREA_DIR)
	@echo ">> initialising antrea engine workspace ($(ANTREA_MOD) + ./api + $(ANTREA_DIR))"
	@# GOWORK pins the output to this module's own go.work; without it `go work
	@# init` walks up, finds the root workspace, and refuses.
	cd $(ANTREA_MOD) && GOWORK="$(CURDIR)/$(ANTREA_MOD)/go.work" go work init . ../../api ../../$(ANTREA_DIR)

# --- Build -----------------------------------------------------------------
build: build-shell build-antrea  ## Clone sources, create workspaces, build both binaries

build-shell: $(CALICO_DIR) go.work  ## Build the shell binary (Calico in-process)
	@mkdir -p $(dir $(BIN))
	@echo ">> building $(BIN)"
	go build -ldflags "$(LDFLAGS)" -o $(BIN) .
	@echo ">> built $(BIN)"

build-antrea: $(ANTREA_DIR) $(ANTREA_MOD)/go.work  ## Build the out-of-process Antrea engine binary
	@mkdir -p $(dir $(ANTREA_BIN))
	@echo ">> building $(ANTREA_BIN)"
	cd $(ANTREA_MOD) && go build -o $(CURDIR)/$(ANTREA_BIN) .
	@echo ">> built $(ANTREA_BIN)"

# --- Docker build ----------------------------------------------------------
# Build inside a pinned golang container instead of with the host toolchain,
# so the only host requirement is Docker. The repo is bind-mounted at /src and
# the regular `make build` runs inside it (the default golang image is Debian-
# based, so make and git are already present); artifacts land in ./bin on the
# host exactly like a native build. We run as the invoking user and point the
# Go caches at /tmp so nothing in the mount ends up root-owned.
#
# GOTOOLCHAIN=auto lets the container fetch whatever Go version the workspace
# requires (go.work / go.mod may pin a newer toolchain than the base image), so
# the build is insulated from host/image version drift.
#
# GOOS/GOARCH are pinned via TARGET_OS/TARGET_ARCH (linux + host CPU by default;
# see above). The engine is Linux-only, so the artifact is meant to run inside a
# Linux container/VM, not directly on a macOS or Windows host.
build-docker:  ## Build the binary inside a Docker container (no host Go needed)
	@echo ">> building in $(DOCKER_IMAGE) for $(TARGET_OS)/$(TARGET_ARCH)"
	docker run --rm \
		-u $$(id -u):$$(id -g) \
		-v "$(CURDIR)":/src \
		-w /src \
		-e CGO_ENABLED=0 \
		-e GOTOOLCHAIN=auto \
		-e GOOS=$(TARGET_OS) \
		-e GOARCH=$(TARGET_ARCH) \
		-e HOME=/tmp \
		-e GOCACHE=/tmp/.gocache \
		-e GOMODCACHE=/tmp/.gomodcache \
		$(DOCKER_IMAGE) \
		make build

# --- Docker image ----------------------------------------------------------
# Package the engine into a runnable Docker image (see Dockerfile). The image
# is always linux/<arch>, but that runs anywhere Docker does — including macOS
# and Windows hosts via Docker Desktop — so it's the portable way to ship a
# Linux-only binary. Version metadata is computed here (host has .git) and
# passed in as build args.
#
#   make image                         # tag telepathy:<version>, host arch
#   make image IMAGE=myrepo/engine:dev # custom name/tag
#   docker run --rm -i telepathy:<version> -policy /p.yaml < topo.yaml
image:  ## Build a Docker image with the engine (runs in Docker, incl. on Mac)
	@echo ">> building image $(IMAGE) for $(PLATFORM)"
	docker build \
		--platform $(PLATFORM) \
		--build-arg GO_VERSION=$(GO_VERSION) \
		--build-arg ENGINE_VERSION=$(ENGINE_VERSION) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		$(OUTPUT) \
		-t $(IMAGE) .
	@echo ">> built image $(IMAGE)"

# --- Smoke test ------------------------------------------------------------
# Build the engine, feed it the sample Request on stdin (with the sample
# policy layered in), and print the engine's raw JSON Response verbatim — no
# parsing or massaging, so you see exactly what a caller would get back.
test: build  ## Build, then feed a sample Request in and print the raw output
	@echo ">> sending $(TEST_INPUT) (+ $(TEST_POLICY)) to $(BIN)"
	@echo ">> ----- raw engine output -----"
	@$(BIN) -policy $(TEST_POLICY) < $(TEST_INPUT)
	@echo ">> ------------------------------"

verify: build  ## Build, then gate the topology against TEST_ASSERT (exits non-zero on a failed assertion — the CI contract)
	@echo ">> asserting $(TEST_ASSERT) against $(TEST_INPUT) (+ $(TEST_POLICY))"
	@$(BIN) test -assert $(TEST_ASSERT) -policy $(TEST_POLICY) < $(TEST_INPUT)

# DIFF_BASE / DIFF_HEAD are the two policy revisions diff-demo compares against
# the same topology — base (frontend-only) vs a PR that opens it to every pod.
DIFF_BASE ?= testdata/sample-policy.yaml
DIFF_HEAD ?= testdata/sample-policy-open.yaml

diff-demo: build  ## Evaluate base vs PR policy on the same topology and print the connectivity diff (text + PR-comment markdown)
	@$(BIN) -policy $(DIFF_BASE) < $(TEST_INPUT) > /tmp/telepathy-base.json
	@$(BIN) -policy $(DIFF_HEAD) < $(TEST_INPUT) > /tmp/telepathy-head.json
	@echo ">> ----- diff (text) -----"
	@$(BIN) diff /tmp/telepathy-base.json /tmp/telepathy-head.json
	@echo ">> ----- diff (markdown / PR comment) -----"
	@$(BIN) diff -format markdown /tmp/telepathy-base.json /tmp/telepathy-head.json

# --- Cleanup ---------------------------------------------------------------
clean:  ## Remove build artifacts
	rm -rf bin

distclean: clean  ## Also remove the Calico + Antrea checkouts and generated workspaces
	rm -rf $(CALICO_DIR) $(ANTREA_DIR) go.work go.work.sum $(ANTREA_MOD)/go.work $(ANTREA_MOD)/go.work.sum
