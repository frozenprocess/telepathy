// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 The Telepathy Authors
//
// This file is part of Telepathy.
//
// Telepathy is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License version 3 as published
// by the Free Software Foundation.
//
// Telepathy is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.

package engine

import (
	"net"
	"strconv"
	"strings"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/rules"
)

// flow implements checker.Flow for an L3/L4(/L7) pod-to-pod probe.
//
// Pre-extension this struct held only L3/L4. We now also carry HTTP method/
// path and the source/dest peer's SPIFFE principal so the checker's L7 and
// service-account-match paths exercise. Fields stay un-set (nil/empty) when
// the caller hasn't asked for them; the checker treats nil HTTP/principal as
// "don't constrain", matching what a real Dikastes evaluator does for an
// L3/L4-only flow.
type flow struct {
	srcIP, dstIP        net.IP
	srcPort, dstPort    int
	protocol            int
	httpMethod          *string
	httpPath            *string
	srcPrincipal        *string
	dstPrincipal        *string
	srcLabels           map[string]string
	dstLabels           map[string]string
}

func (f *flow) GetSourceIP() net.IP                { return f.srcIP }
func (f *flow) GetDestIP() net.IP                  { return f.dstIP }
func (f *flow) GetSourcePort() int                 { return f.srcPort }
func (f *flow) GetDestPort() int                   { return f.dstPort }
func (f *flow) GetProtocol() int                   { return f.protocol }
func (f *flow) GetHttpMethod() *string             { return f.httpMethod }
func (f *flow) GetHttpPath() *string               { return f.httpPath }
func (f *flow) GetSourcePrincipal() *string        { return f.srcPrincipal }
func (f *flow) GetDestPrincipal() *string          { return f.dstPrincipal }
func (f *flow) GetSourceLabels() map[string]string { return f.srcLabels }
func (f *flow) GetDestLabels() map[string]string   { return f.dstLabels }

func floatPtr(f float64) *float64 { return &f }

// IANA protocol numbers we accept by name. Anything else falls through to the
// numeric-pass-through below so policies / probes can target arbitrary
// protocol numbers (1-255) the way Calico's wire format does.
var protoByName = map[string]int{
	"tcp":     6,
	"udp":     17,
	"icmp":    1,
	"icmpv6":  58,
	"sctp":    132,
	"udplite": 136,
}

// protocolNumber turns a name ("tcp"), a wire-style int string ("17"), or a
// raw integer (passed in as its decimal form) into an IANA protocol number.
// Unknown names default to TCP — same behaviour the engine had pre-extension
// — but a warning is surfaced via Capabilities so the caller can detect drift.
func protocolNumber(s string) int {
	s = strings.ToLower(strings.TrimSpace(s))
	if n, ok := protoByName[s]; ok {
		return n
	}
	if n, err := strconv.Atoi(s); err == nil && n >= 0 && n <= 255 {
		return n
	}
	return 6
}

// protocolHasL4Ports reports whether the (req.Port) field is meaningful for
// the given protocol number. Only TCP / UDP / SCTP / UDPLite carry L4 ports;
// for ICMP, ICMPv6, and arbitrary numeric protocols we set dstPort to 0 so
// rules that filter on ports don't spuriously fail (or match a stale 8080).
func protocolHasL4Ports(p int) bool {
	switch p {
	case 6, 17, 132, 136: // tcp, udp, sctp, udplite
		return true
	}
	return false
}

// spiffePrincipal builds the SPIFFE-style URI Calico's app-policy/checker
// uses to identify a workload by service account, of the form
//   spiffe://cluster.local/ns/<namespace>/sa/<serviceAccount>
// Returns nil when either component is empty so the checker treats the
// peer as "unidentified" rather than matching a bogus SA.
func spiffePrincipal(namespace, serviceAccount string) *string {
	if namespace == "" || serviceAccount == "" {
		return nil
	}
	s := "spiffe://cluster.local/ns/" + namespace + "/sa/" + serviceAccount
	return &s
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// verdict interprets a checker trace: the last RuleID is always terminal
// (Allow or Deny; Pass only appears mid-trace).
func verdict(trace []*calc.RuleID) bool {
	if len(trace) == 0 {
		return false
	}
	return trace[len(trace)-1].Action == rules.RuleActionAllow
}
