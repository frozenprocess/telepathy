// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 The Telepathy Authors
//
// This file is part of Telepathy.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build e2e

package e2e

import (
	"os"
	"strconv"
	"time"
)

// Config holds every tunable the harness reads from the environment, plus the
// timing constants the phases depend on, resolved once in loadConfig. Centralizing
// them here replaces the constellation of getenv accessor functions and scattered
// package consts that used to live across e2e_test.go, realize.go and probe.go, so
// a reader can see the suite's whole knob set — and its defaults — in one place.
//
// The exported behavior is unchanged: every field still maps to the same env var
// (and the same default) the old accessors used.
type Config struct {
	// TestdataDir is the directory of case sub-dirs. Default assumes the layout
	// `make e2e` produces (test CWD is the e2e package dir, so testdata sits
	// alongside it under e2e/testdata, reachable as ../e2e/testdata).
	TestdataDir string // TESTDATA_DIR
	// TelepathyBin is the engine binary the suite shells out to for predictions.
	TelepathyBin string // TELEPATHY_BIN
	// ClusterName is the kind cluster (and, as kind-<name>, its kubeconfig context).
	ClusterName string // CLUSTER_NAME

	// Provider is the CNI engine the suite compares the cluster against. It selects
	// both which `-provider` the engine runs as and which testdata cases apply: a
	// case runs when its flavor is "k8s" (provider-neutral) or equals this provider.
	// The provisioned cluster must match — `make e2e` brings up Calico, `make
	// e2e-antrea` brings up Antrea.
	Provider string // E2E_PROVIDER

	// AgnhostImage is the sig-network reference server/client (TCP/UDP/SCTP).
	// NetshootImage supplies ping (and other net tooling) for ICMP probes that
	// agnhost connect can't do. Overridable so a CI cache or air-gapped registry
	// can be pointed at.
	AgnhostImage  string // AGNHOST_IMAGE
	NetshootImage string // NETSHOOT_IMAGE

	// IncludeHEP gates the HostEndpoint cases. They narrow Calico's failsafe host
	// ports to a control-plane-only set cluster-wide for the duration of the case
	// (so the policy under test, not a failsafe, governs the probe ports) — a small
	// but real change to shared cluster state, so they are opt-in.
	IncludeHEP bool // E2E_INCLUDE_HEP=1

	// KeepOnFailure leaves a *failed* case's resources (namespaces, pods, policy,
	// HEPs, netsets — and, for HEP cases, the narrowed failsafes) in place instead
	// of tearing them down, so the scene can be poked at live with kubectl.
	// Successful cases always tear down.
	KeepOnFailure bool // E2E_KEEP=1

	// NoNodePool disables the disabled-IPPool-over-node-subnet workaround for HEP
	// cases (used to isolate the pool's effect when diagnosing a case).
	NoNodePool bool // E2E_NO_NODE_POOL=1

	// ArtifactRoot is the base directory for per-failure diagnostics, or "" when
	// capture is disabled. Each failing case gets a subdirectory under it.
	ArtifactRoot string // E2E_ARTIFACTS

	// SettleDelay gives Felix time to program a freshly applied policy before the
	// first probe. probe() also retries, but a short upfront settle cuts the number
	// of wasted first-attempt probes on deny flows (which can't be retried away).
	// HEPSettleDelay is the longer budget for HostEndpoint cases, whose
	// forward/preDNAT chains converge slower (see the settle site in runCase).
	SettleDelay    time.Duration
	HEPSettleDelay time.Duration

	// HealthGrace is how long ensureClusterHealthy waits for Calico to report
	// healthy BEFORE resorting to a dataplane restart. It is a max timeout, not a
	// fixed sleep: a recovered cluster (the common case) returns within a second
	// regardless. HealthRestartTimeout bounds both the calico-node rollout and the
	// post-restart recheck.
	HealthGrace          time.Duration
	HealthRestartTimeout time.Duration

	// ProbeExecTimeout bounds a single `kubectl exec` probe. The in-container client
	// already self-limits (agnhost connect --timeout=2s, ping -W2), so this only
	// fires when the exec channel itself stalls — e.g. a host policy under test
	// blackholed the API→kubelet stream. Without it a single wedged probe hangs the
	// whole suite indefinitely (observed: a preDNAT case stuck for ~19 minutes).
	ProbeExecTimeout time.Duration

	// ProbeConcurrency caps how many of a case's per-assertion probes run at once.
	// Probes are independent and dominated by waiting (a deny flow exhausts 4 ×
	// agnhost --timeout=2s before it concludes), so an all-deny case like
	// gnp-selector-has (30 flows) spends ~5min probing serially — enough to trip the
	// suite-wide `go test -timeout`. Fanning them out collapses that to ~1/N. Only
	// the plain workload-pod path parallelizes; HEP and external-observer cases stay
	// serial (their conntrack-flush / NodePort routing assumes one flow at a time).
	ProbeConcurrency int // E2E_PROBE_CONCURRENCY
}

// cfg is the suite-wide configuration, resolved once at package init. The harness
// is a single-process test binary, so a package-level value read at startup is the
// simplest faithful replacement for the per-call getenv accessors it supersedes.
var cfg = loadConfig()

// loadConfig resolves Config from the environment, applying the documented
// defaults. Timing constants have no env override (they encode dataplane
// convergence behavior, not user preference) and are set to their historical
// values here.
func loadConfig() Config {
	return Config{
		TestdataDir:   envOr("TESTDATA_DIR", "../e2e/testdata"),
		TelepathyBin:  envOr("TELEPATHY_BIN", "../bin/telepathy"),
		ClusterName:   envOr("CLUSTER_NAME", "telepathy-e2e"),
		Provider:      envOr("E2E_PROVIDER", "calico"),
		AgnhostImage:  envOr("AGNHOST_IMAGE", "registry.k8s.io/e2e-test-images/agnhost:2.52"),
		NetshootImage: envOr("NETSHOOT_IMAGE", "nicolaka/netshoot:latest"),
		IncludeHEP:    envBool("E2E_INCLUDE_HEP"),
		KeepOnFailure: envBool("E2E_KEEP"),
		NoNodePool:    envBool("E2E_NO_NODE_POOL"),
		ArtifactRoot:  os.Getenv("E2E_ARTIFACTS"),

		SettleDelay:    3 * time.Second,
		HEPSettleDelay: 45 * time.Second,

		HealthGrace:          120 * time.Second,
		HealthRestartTimeout: 180 * time.Second,

		ProbeExecTimeout: 15 * time.Second,

		ProbeConcurrency: envInt("E2E_PROBE_CONCURRENCY", 8),
	}
}

// envInt returns env var key parsed as a positive int, or def when unset, empty,
// unparseable or non-positive.
func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// envOr returns the value of env var key, or def when it is unset or empty.
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// envBool reports whether env var key is set to a truthy value (1/true/yes).
func envBool(key string) bool {
	switch os.Getenv(key) {
	case "1", "true", "yes":
		return true
	}
	return false
}
