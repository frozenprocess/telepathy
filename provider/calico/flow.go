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

package calico

import (
	"net"
	"strconv"
	"strings"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/rules"
)

// flow implements checker.Flow for an L3/L4(/L7) pod-to-pod probe. It carries
// L3/L4 plus HTTP method/path; the checker treats nil HTTP as "don't
// constrain", matching what a real Dikastes evaluator does for an L3/L4-only
// flow. The principal/labels accessors the interface requires return nil — we
// don't drive the checker's SPIFFE/service-account-match paths through this
// struct.
type flow struct {
	srcIP, dstIP     net.IP
	srcPort, dstPort int
	protocol         int
	httpMethod       *string
	httpPath         *string
}

func (f *flow) GetSourceIP() net.IP                { return f.srcIP }
func (f *flow) GetDestIP() net.IP                  { return f.dstIP }
func (f *flow) GetSourcePort() int                 { return f.srcPort }
func (f *flow) GetDestPort() int                   { return f.dstPort }
func (f *flow) GetProtocol() int                   { return f.protocol }
func (f *flow) GetHttpMethod() *string             { return f.httpMethod }
func (f *flow) GetHttpPath() *string               { return f.httpPath }
func (f *flow) GetSourcePrincipal() *string        { return nil }
func (f *flow) GetDestPrincipal() *string          { return nil }
func (f *flow) GetSourceLabels() map[string]string { return nil }
func (f *flow) GetDestLabels() map[string]string   { return nil }

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
