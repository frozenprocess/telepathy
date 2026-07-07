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
	"context"
	"fmt"
	"strings"
	"time"
)

const (
	verdictAllow = "allow"
	verdictDeny  = "deny"
)

// probeTarget is where a flow lands: a real pod (probed at podIP) for workloads
// and HEP hosts (hostNetwork pods), or a Service ClusterIP.
type probeTarget struct {
	ip   string
	port int
}

// probeSource is where a flow originates. Normally it's a pod (HEP host actors
// are realized as hostNetwork pods, so the same kubectl-exec path generates
// host-originated traffic). When external is set, the source is an off-cluster
// observer Docker container (container holds its name) probed via `docker exec`
// instead of `kubectl exec` — used for north-south cases (preDNAT/NodePort).
type probeSource struct {
	ns        string
	pod       string
	external  bool
	container string
}

// probe runs the real connectivity test for one assertion's flow and returns
// "allow" or "deny". Connectivity is retried briefly: Calico programs policy
// asynchronously, so a flow that should be allowed can fail for the first
// fraction of a second after `kubectl apply`. A flow is "allow" if any attempt
// succeeds; only when every attempt fails (connection refused, dropped, or
// timed out) is it "deny".
func probe(ctx context.Context, c *cluster, src probeSource, dst probeTarget, proto string) (string, string, error) {
	proto = strings.ToLower(proto)
	const attempts = 4
	var lastOut string
	for i := 0; i < attempts; i++ {
		ok, out, err := probeOnce(ctx, c, src, dst, proto)
		lastOut = out
		if err != nil {
			return "", out, err // harness/exec failure, not a connectivity verdict
		}
		if ok {
			return verdictAllow, out, nil
		}
		if i < attempts-1 {
			select {
			case <-ctx.Done():
				return "", out, ctx.Err()
			case <-time.After(750 * time.Millisecond):
			}
		}
	}
	return verdictDeny, lastOut, nil
}

// probeOnce performs a single connectivity attempt. ok reports whether the
// connection succeeded; a non-nil error is reserved for harness problems
// (the exec channel timed out or the source pod vanished), distinct from a
// normal refused/dropped probe which returns ok=false, err=nil.
//
// The single attempt is bounded by cfg.ProbeExecTimeout: the in-container client
// already self-limits (agnhost connect --timeout=2s, ping -W2), so that ceiling
// only fires when the exec channel itself stalls — e.g. a host policy under test
// blackholed the API→kubelet stream. Without it a single wedged probe hangs the
// whole suite indefinitely (observed: a preDNAT case stuck for ~19 minutes).
func probeOnce(ctx context.Context, c *cluster, src probeSource, dst probeTarget, proto string) (ok bool, out string, err error) {
	ectx, cancel := context.WithTimeout(ctx, cfg.ProbeExecTimeout)
	defer cancel()

	switch proto {
	case "tcp", "udp", "sctp":
		// agnhost connect gives an unambiguous L4 verdict (its UDP/SCTP client
		// waits for the netexec server's echo, so "no reply" — drop or no
		// listener — is a clean failure, unlike a bare `nc -u`).
		target := fmt.Sprintf("%s:%d", dst.ip, dst.port)
		var out string
		var exitErr error
		if src.external {
			// Off-cluster observer: the agnhost binary runs in the Docker
			// container, so we docker-exec rather than kubectl-exec.
			out, exitErr = c.dockerExec(ectx, src.container,
				"/agnhost", "connect", target, "--protocol="+proto, "--timeout=2s")
		} else {
			out, exitErr = c.exec(ectx, src.ns, src.pod, "agnhost",
				"/agnhost", "connect", target, "--protocol="+proto, "--timeout=2s")
		}
		if ectx.Err() == context.DeadlineExceeded {
			return false, out, fmt.Errorf("probe exec exceeded %s (exec channel stalled)", cfg.ProbeExecTimeout)
		}
		return exitErr == nil, out, nil
	case "icmp":
		if src.external {
			// agnhost has no ICMP client; north-south cases probe L4 (NodePort).
			return false, "", fmt.Errorf("icmp probe not supported from an external observer")
		}
		// The sender needs a ping client, which only the Linux agnhost image has, so
		// the harness always pins ICMP-source pods to a Linux node (see e2e_test.go).
		// ICMP has no port; ping from the agnhost container (bundles busybox ping).
		out, exitErr := c.exec(ectx, src.ns, src.pod, "agnhost",
			"/bin/ping", "-c", "1", "-W", "2", dst.ip)
		if ectx.Err() == context.DeadlineExceeded {
			return false, out, fmt.Errorf("probe exec exceeded %s (exec channel stalled)", cfg.ProbeExecTimeout)
		}
		return exitErr == nil, out, nil
	default:
		return false, "", fmt.Errorf("unsupported probe protocol %q", proto)
	}
}
