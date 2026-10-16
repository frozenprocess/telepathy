// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 The Telepathy Authors
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
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/projectcalico/calico/app-policy/checker"
	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/felix/types"
)

// Equivalence-class collapse of the connectivity matrix.
//
// The brute-force matrix loop calls checker.Evaluate O(N²) times (twice per
// ordered pair). For a large topology that is the whole runtime. But the
// checker's verdict for a flow is a pure function of a small amount of state:
//
//   - the OWNER endpoint's applied policy (checkTiers reads only ep.Tiers and
//     ep.ProfileIds — nothing else about the endpoint), and
//   - a set of IP-keyed membership answers: is srcIP / dstIP in each rule's
//     referenced IP-set, ip-port-set, or CIDR (matchSrc/DstIPSets,
//     matchDstIPPortSetIds, matchSrc/DstNet).
//
// Everything else the checker consults for a flow is either constant across the
// whole matrix (protocol / port / HTTP — the single probe) or IP-independent:
// the namespace- and service-account-selector paths are no-ops here because the
// probe carries no principal, so getSrc/DstPeer returns nil and matchNamespace
// / matchServiceAccounts short-circuit to true (see checker/match.go).
//
// So two endpoints are interchangeable — as source AND as destination — when
// they share (a) their applied-policy fingerprint and (b) their answers to the
// fixed probe set. Group endpoints into such classes, run the real checker once
// per (class, peer-class) combination, then fill the N² matrix by table lookup.
// Correctness is exact (same checker, same store); only redundant calls are
// removed.
//
// This path handles the HEP-free case (no HostEndpoint overlays). When HEPs are
// present the caller keeps the exact per-pair loop — those topologies are small
// and the overlay logic is node-dependent.

// peerProbes is the fixed set of IP-keyed membership tests the checker's
// per-pair matching consults. An endpoint's answers to these fully determine
// how every rule matches it as a peer.
type peerProbes struct {
	ipSetIDs      []string // membership tested with the bare IP string
	srcPortSetIDs []string
	srcPortSuffix string
	ipPortSetIDs  []string     // membership tested with "ip,proto:port"
	nets          []*net.IPNet // CIDRs matched with IPNet.Contains
	ipPortSuffix  string       // ",proto:port" appended to the IP for ip-port sets
}

// collapseProtoName mirrors checker.protocolMapL4 so the ip-port-set membership
// value is byte-identical to what matchDstIPPortSetIds builds (unknown protocol
// → empty, matching the checker's map miss).
var collapseProtoName = map[int]string{1: "icmp", 6: "tcp", 17: "udp", 132: "sctp"}

func collectPeerProbes(store *policystore.PolicyStore, protoNum, srcPort, dstPort int) peerProbes {
	ipset := map[string]bool{}
	ipport := map[string]bool{}
	srcport := map[string]bool{}
	netstr := map[string]bool{}
	add := func(m map[string]bool, ids []string) {
		for _, id := range ids {
			m[id] = true
		}
	}
	visit := func(r *proto.Rule) {
		add(ipset, r.GetSrcIpSetIds())
		add(ipset, r.GetNotSrcIpSetIds())
		add(ipset, r.GetDstIpSetIds())
		add(ipset, r.GetNotDstIpSetIds())
		add(ipport, r.GetDstIpPortSetIds())
		add(ipport, r.GetDstNamedPortIpSetIds())
		add(ipport, r.GetNotDstNamedPortIpSetIds())
		add(srcport, r.GetSrcNamedPortIpSetIds())
		add(srcport, r.GetNotSrcNamedPortIpSetIds())
		add(netstr, r.GetSrcNet())
		add(netstr, r.GetNotSrcNet())
		add(netstr, r.GetDstNet())
		add(netstr, r.GetNotDstNet())
	}
	for _, p := range store.PolicyByID {
		for _, r := range p.GetInboundRules() {
			visit(r)
		}
		for _, r := range p.GetOutboundRules() {
			visit(r)
		}
	}
	for _, pr := range store.ProfileByID {
		for _, r := range pr.GetInboundRules() {
			visit(r)
		}
		for _, r := range pr.GetOutboundRules() {
			visit(r)
		}
	}
	pp := peerProbes{ipPortSuffix: "," + collapseProtoName[protoNum] + ":" + strconv.Itoa(dstPort)}
	pp.srcPortSetIDs = sortedStrKeys(srcport)
	pp.srcPortSuffix = "," + collapseProtoName[protoNum] + ":" + strconv.Itoa(srcPort)
	pp.ipSetIDs = sortedStrKeys(ipset)
	pp.ipPortSetIDs = sortedStrKeys(ipport)
	for _, n := range sortedStrKeys(netstr) {
		if _, cidr, err := net.ParseCIDR(n); err == nil {
			pp.nets = append(pp.nets, cidr)
		}
	}
	return pp
}

// sig returns the endpoint's peer signature: its yes/no answer to every probe,
// in probe order, as a compact string usable as a map key. Two IPs with equal
// sigs match identically in every rule's peer position.
func (pp peerProbes) sig(store *policystore.PolicyStore, ip net.IP) string {
	if len(pp.ipSetIDs)+len(pp.ipPortSetIDs)+len(pp.srcPortSetIDs)+len(pp.nets) == 0 {
		return ""
	}
	var b strings.Builder
	b.Grow(len(pp.ipSetIDs) + len(pp.ipPortSetIDs) + len(pp.nets))
	ipStr := ip.String()
	for _, id := range pp.ipSetIDs {
		b.WriteByte(contains(store, id, ipStr))
	}
	if len(pp.ipPortSetIDs) > 0 {
		v := ipStr + pp.ipPortSuffix
		for _, id := range pp.ipPortSetIDs {
			b.WriteByte(contains(store, id, v))
		}
	}
	for _, id := range pp.srcPortSetIDs {
		b.WriteByte(contains(store, id, ipStr+pp.srcPortSuffix))
	}
	for _, cidr := range pp.nets {
		if cidr.Contains(ip) {
			b.WriteByte('1')
		} else {
			b.WriteByte('0')
		}
	}
	return b.String()
}

func contains(store *policystore.PolicyStore, id, value string) byte {
	if s := store.IPSetByID[id]; s != nil && s.Contains(value) {
		return '1'
	}
	return '0'
}

// ownerFingerprint identifies an endpoint as a policy OWNER: the exact tier /
// policy / profile structure checkTiers walks. Unpoliced endpoints collapse to
// one class ("U") — their own egress/ingress is unconditionally allowed.
func ownerFingerprint(a *actor) string {
	if a.unpoliced {
		return "U"
	}
	var b strings.Builder
	for _, t := range a.normalWEP().GetTiers() {
		b.WriteString(t.GetName())
		b.WriteByte('|')
		b.WriteString(t.GetDefaultAction())
		b.WriteByte('|')
		writePolicyIDs(&b, t.GetIngressPolicies())
		b.WriteByte('|')
		writePolicyIDs(&b, t.GetEgressPolicies())
		b.WriteByte(';')
	}
	b.WriteByte('#')
	b.WriteString(strings.Join(a.normalWEP().GetProfileIds(), ","))
	return b.String()
}

func writePolicyIDs(b *strings.Builder, ids []*proto.PolicyID) {
	for _, id := range ids {
		b.WriteString(id.GetKind())
		b.WriteByte('/')
		b.WriteString(id.GetNamespace())
		b.WriteByte('/')
		b.WriteString(id.GetName())
		b.WriteByte(',')
	}
}

func sortedStrKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// stdlib sort keeps the probe order deterministic so a sig is comparable
	// across endpoints (order-dependent bit string).
	sort.Strings(out)
	return out
}

// fillMatrixCollapsed computes the full connectivity matrix via equivalence
// classes and writes every ordered pair to sink. Result is identical to the
// per-pair loop in Evaluate for the HEP-free case.
func fillMatrixCollapsed(sink *matrixSink, store *policystore.PolicyStore, actors actorBundle, mkFlow func(src, dst *actor) *flow, scope checker.PolicyScope, protoNum, srcPort, dstPort int) {
	list := actors.list
	n := len(list)
	pp := collectPeerProbes(store, protoNum, srcPort, dstPort)

	repPeer, repClass, peerOf, classOf := groupActors(store, list, pp)

	nClass, nPeer := len(repClass), len(repPeer)
	if os.Getenv("POLICY_ENGINE_DEBUG") != "" {
		fmt.Fprintf(os.Stderr, "DEBUG collapse: %d endpoints -> %d owner-classes x %d peer-classes; %d checker calls vs %d brute (%.0fx)\n",
			n, nClass, nPeer, 2*nClass*nPeer, 2*n*(n-1), float64(n)*float64(n-1)/float64(nClass*nPeer))
	}

	egMemo, inMemo := evaluateClasses(store, scope, repClass, repPeer, mkFlow)

	// Expand: every ordered pair is now two array lookups.
	for i := 0; i < n; i++ {
		srcID := list[i].id
		egRow := classOf[i] * nPeer
		myPeer := peerOf[i]
		for j := 0; j < n; j++ {
			if srcID == list[j].id {
				continue
			}
			res := "deny"
			if egMemo[egRow+peerOf[j]] && inMemo[classOf[j]*nPeer+myPeer] {
				res = "allow"
			}
			sink.put(srcID, list[j].id, res)
		}
	}
}

func groupActors(store *policystore.PolicyStore, list []*actor, pp peerProbes) (repPeer, repClass []*actor, peerOf, classOf []int) {
	n := len(list)
	// Assign each actor a peer-signature id and an owner-class id
	// (owner-class = fingerprint + own peer-signature, because a rule can also
	// match the owner's own IP in its src/dst position).
	peerID := map[string]int{}
	classID := map[string]int{}
	peerOf = make([]int, n)
	classOf = make([]int, n)
	for i, a := range list {
		s := pp.sig(store, a.ip)
		pid, ok := peerID[s]
		if !ok {
			pid = len(repPeer)
			peerID[s] = pid
			repPeer = append(repPeer, a)
		}
		peerOf[i] = pid
		key := ownerFingerprint(a) + "\x00" + s
		cid, ok := classID[key]
		if !ok {
			cid = len(repClass)
			classID[key] = cid
			repClass = append(repClass, a)
		}
		classOf[i] = cid
	}

	return
}

func evaluateClasses(store *policystore.PolicyStore, scope checker.PolicyScope, repClass, repPeer []*actor, mkFlow func(src, dst *actor) *flow) ([]bool, []bool) {
	nClass, nPeer := len(repClass), len(repPeer)
	// egMemo[c*nPeer+p] = egress verdict when owner-class c is the SOURCE and
	// peer-class p is the DEST. inMemo is the mirror for ingress (owner = dest,
	// peer = source). Both reuse the real checker on class representatives.
	egMemo := make([]bool, nClass*nPeer)
	inMemo := make([]bool, nClass*nPeer)
	for c := 0; c < nClass; c++ {
		oc := repClass[c]
		row := c * nPeer
		probe := mkFlow(oc, oc)
		egress := ownerDirectionEvaluator(store, scope, oc, rules.RuleDirEgress, probe)
		ingress := ownerDirectionEvaluator(store, scope, oc, rules.RuleDirIngress, probe)
		for p := 0; p < nPeer; p++ {
			if oc.unpoliced {
				egMemo[row+p] = true
				inMemo[row+p] = true
				continue
			}
			peer := repPeer[p]
			egMemo[row+p] = egress(peer)
			inMemo[row+p] = ingress(peer)
		}
	}

	return egMemo, inMemo
}

// ownerDirectionEvaluator ignores probe distinctions introduced by policies
// that do not apply to this owner/direction. A default or profile-only verdict
// is then checked once, even if unrelated policies split peers into many classes.
// The native checker still decides all tier, pass, staged, and profile behavior.
func ownerDirectionEvaluator(store *policystore.PolicyStore, scope checker.PolicyScope, owner *actor, direction rules.RuleDir, probe *flow) func(*actor) bool {
	probes := collectOwnerProbes(store, owner, direction, probe)
	memo := map[string]bool{}
	return func(peer *actor) bool {
		signature := probes.sig(store, peer.ip)
		if allow, ok := memo[signature]; ok {
			return allow
		}
		f := *probe
		if direction == rules.RuleDirIngress {
			f.srcIP = peer.ip
		} else {
			f.dstIP = peer.ip
		}
		trace, _ := checker.Evaluate(scope, direction, store, owner.normalWEP(), &f)
		allow := verdict(trace)
		memo[signature] = allow
		return allow
	}
}

func collectOwnerProbes(store *policystore.PolicyStore, owner *actor, direction rules.RuleDir, probe *flow) peerProbes {
	var relevant []*proto.Rule
	inbound := direction == rules.RuleDirIngress
	for _, tier := range owner.normalWEP().GetTiers() {
		ids := tier.GetEgressPolicies()
		if inbound {
			ids = tier.GetIngressPolicies()
		}
		for _, id := range ids {
			p := store.PolicyByID[types.ProtoToPolicyID(id)]
			if inbound {
				relevant = append(relevant, p.GetInboundRules()...)
			} else {
				relevant = append(relevant, p.GetOutboundRules()...)
			}
		}
	}
	for _, name := range owner.normalWEP().GetProfileIds() {
		p := store.ProfileByID[types.ProfileID{Name: name}]
		if inbound {
			relevant = append(relevant, p.GetInboundRules()...)
		} else {
			relevant = append(relevant, p.GetOutboundRules()...)
		}
	}
	// Reuse the membership-probe collector; no policy semantics are evaluated here.
	subset := &policystore.PolicyStore{ProfileByID: map[types.ProfileID]*proto.Profile{{Name: "probes"}: {InboundRules: relevant}}}
	return collectPeerProbes(subset, probe.protocol, probe.srcPort, probe.dstPort)
}
