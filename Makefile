# calico-engine — build orchestration.
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
BIN            ?= bin/calico-engine

# Version stamped into the binary (surfaced by `calico-engine --version`).
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

.PHONY: help all build test calico clean distclean

# Running `make` with no target prints the help below.
.DEFAULT_GOAL := help

# Sample evaluation input for `make test`: a topology piped on stdin plus a
# NetworkPolicy layered in via -policy. Override to point the smoke test at
# your own Request/manifest.
TEST_INPUT  ?= testdata/sample-topology.yaml
TEST_POLICY ?= testdata/sample-policy.yaml

all: build  ## Build everything (default of `make all`)

# --- Help ------------------------------------------------------------------
# Self-documenting: scans this Makefile for targets annotated with a `##`
# comment and prints them. To list a new target here, just add `## description`
# after its prerequisites.
help:  ## Show this help
	@echo "calico-engine — available targets:"
	@echo ""
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "} {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Common overridable vars: CALICO_VERSION, BIN, TEST_INPUT, TEST_POLICY"

# --- Calico source ---------------------------------------------------------
# Shallow clone of just the pinned tag. The directory existing is the marker
# that the checkout is present, so re-running is a no-op.
$(CALICO_DIR):
	@echo ">> cloning $(CALICO_REPO) @ $(CALICO_VERSION) into $(CALICO_DIR)"
	git clone --depth 1 --branch $(CALICO_VERSION) $(CALICO_REPO) $(CALICO_DIR)

calico: $(CALICO_DIR)  ## Fetch the pinned Calico source tree

# --- Workspace -------------------------------------------------------------
# go.work makes the engine module (.) build against the local Calico checkout
# instead of a versioned dependency. Created once; left alone if it exists.
go.work: $(CALICO_DIR)
	@echo ">> initialising go workspace (. + $(CALICO_DIR))"
	go work init . $(CALICO_DIR)

# --- Build -----------------------------------------------------------------
build: $(CALICO_DIR) go.work  ## Clone Calico (if needed), create go.work, build the binary
	@mkdir -p $(dir $(BIN))
	@echo ">> building $(BIN)"
	go build -ldflags "$(LDFLAGS)" -o $(BIN) .
	@echo ">> built $(BIN)"

# --- Smoke test ------------------------------------------------------------
# Build the engine, feed it the sample Request on stdin (with the sample
# policy layered in), and print the engine's raw JSON Response verbatim — no
# parsing or massaging, so you see exactly what a caller would get back.
test: build  ## Build, then feed a sample Request in and print the raw output
	@echo ">> sending $(TEST_INPUT) (+ $(TEST_POLICY)) to $(BIN)"
	@echo ">> ----- raw engine output -----"
	@$(BIN) -policy $(TEST_POLICY) < $(TEST_INPUT)
	@echo ">> ------------------------------"

# --- Cleanup ---------------------------------------------------------------
clean:  ## Remove build artifacts
	rm -rf bin

distclean: clean  ## Also remove the Calico checkout and go.work
	rm -rf $(CALICO_DIR) go.work go.work.sum
