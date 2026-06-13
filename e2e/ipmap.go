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
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"

	"github.com/frozenprocess/telepathy/api"
)

// ipToken matches an IPv4 address with an optional CIDR suffix. The e2e/testdata is
// IPv4-only; an IPv6 case would need this widened (and is called out as a known
// limitation in the e2e README).
var ipToken = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?\b`)

// ipRewriter maps the topology's fictional IPs onto the real IPs the cluster
// assigned, so the engine and the dataplane evaluate identical inputs. It
// rewrites two things:
//
//   - exact tokens: a fictional endpoint IP (e.g. 10.0.0.1) or a HostEndpoint's
//     fictional node IP (e.g. 172.18.0.2) is replaced by the real pod/node IP.
//   - CIDR tokens: a fictional CIDR in a policy/netset (e.g. 1.1.1.0/24) is
//     replaced by the /32(s) of whichever fictional endpoint IPs fall inside it,
//     mapped to their real IPs — so a rule that "allows egress to the internet
//     CIDR" really matches the pod standing in for the internet.
//
// A CIDR that contains no topology endpoint is left untouched: it matches no
// real pod on the cluster, and (because endpoint IPs are also remapped) matches
// nothing in the engine either — consistent on both sides.
type ipRewriter struct {
	exact      map[string]string // fictional IP -> real IP
	endpointIP map[string]string // fictional endpoint IP -> real IP (for CIDR containment)
	warns      []string
}

// buildIPRewriter assembles the rewriter from the real pod IPs (keyed by
// endpoint ID) and real node InternalIPs (keyed by node name).
func buildIPRewriter(req api.Request, podIP map[string]string, nodeIP map[string]string) *ipRewriter {
	r := &ipRewriter{exact: map[string]string{}, endpointIP: map[string]string{}}
	for _, e := range req.Endpoints {
		real := podIP[e.ID]
		if e.IP == "" || real == "" {
			continue
		}
		r.exact[e.IP] = real
		r.endpointIP[e.IP] = real
	}
	for _, h := range req.HostEndpoints {
		real := nodeIP[h.Node]
		if real == "" {
			continue
		}
		for _, ip := range h.ExpectedIPs {
			r.exact[ip] = real
		}
	}
	return r
}

// rewriteToken returns the replacement for a single IP/CIDR token, or the token
// unchanged when nothing maps. Multiple contained endpoints collapse to the
// first (with a warning); no current e2e/testdata case puts two endpoints in one
// referenced CIDR.
func (r *ipRewriter) rewriteToken(tok string) string {
	if v, ok := r.exact[tok]; ok {
		return v
	}
	if !strings.Contains(tok, "/") {
		return tok // bare external IP with no endpoint — leave as-is
	}
	_, ipnet, err := net.ParseCIDR(tok)
	if err != nil {
		return tok
	}
	// A catch-all or broad CIDR (e.g. 0.0.0.0/0, or a subnet the real pods land
	// in) already contains the real cluster IPs, so it matches every intended
	// destination on the dataplane exactly as written. Rewriting it would wrongly
	// collapse the whole range to a single /32. Only a *fictional* CIDR — one
	// that contains a placed fictional endpoint but no real cluster IP, so it
	// would match nothing as-is — needs remapping to its stand-in pod.
	for _, real := range r.endpointIP {
		if ip := net.ParseIP(real); ip != nil && ipnet.Contains(ip) {
			return tok
		}
	}
	var matched []string
	for fict, real := range r.endpointIP {
		if ip := net.ParseIP(fict); ip != nil && ipnet.Contains(ip) {
			matched = append(matched, real)
		}
	}
	if len(matched) == 0 {
		return tok
	}
	sort.Strings(matched)
	if len(matched) > 1 {
		r.warns = append(r.warns, fmt.Sprintf("CIDR %s contains %d endpoints %v; remapping to first only", tok, len(matched), matched))
	}
	return hostCIDR(matched[0])
}

// hostCIDR turns a bare IP into its single-host CIDR (/32), the form Calico
// nets entries expect. A token already carrying a prefix is returned as-is.
func hostCIDR(ip string) string {
	if strings.Contains(ip, "/") {
		return ip
	}
	return ip + "/32"
}

// rewriteText replaces every IP/CIDR token in a YAML document via rewriteToken.
// It works uniformly on topology.yaml (endpoint `ip:`, netset nets, HEP
// expectedIPs) and on policy.yaml (rule `nets`, ipBlock `cidr`) because all of
// them are just IP/CIDR literals in value position.
func (r *ipRewriter) rewriteText(text string) string {
	return ipToken.ReplaceAllStringFunc(text, r.rewriteToken)
}

// rewriteNets remaps a Calico nets list (used when re-rendering NetworkSets from
// the parsed Request rather than from raw text).
func (r *ipRewriter) rewriteNets(nets []string) []string {
	out := make([]string, 0, len(nets))
	for _, n := range nets {
		out = append(out, r.rewriteToken(n))
	}
	return out
}
