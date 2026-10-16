// SPDX-License-Identifier: Apache-2.0
package calico

import (
	"fmt"
	"github.com/projectcalico/calico/app-policy/checker"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/sirupsen/logrus"
	"net"
	"testing"

	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
)

func TestCollapseNamedPortSignatures(t *testing.T) {
	for _, tc := range []struct {
		name string
		rule *proto.Rule
		port int
	}{
		{"source", &proto.Rule{SrcNamedPortIpSetIds: []string{"ports"}}, 12345},
		{"not-source", &proto.Rule{NotSrcNamedPortIpSetIds: []string{"ports"}}, 12345},
		{"destination", &proto.Rule{DstNamedPortIpSetIds: []string{"ports"}}, 8080},
		{"not-destination", &proto.Rule{NotDstNamedPortIpSetIds: []string{"ports"}}, 8080},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := policystore.NewPolicyStore()
			store.ProfileByID[types.ProfileID{Name: "profile"}] = &proto.Profile{InboundRules: []*proto.Rule{tc.rule}}
			set := policystore.NewIPSet(proto.IPSetUpdate_IP_AND_PORT)
			suffix := "12345"
			if tc.port == 8080 {
				suffix = "8080"
			}
			set.AddString("10.0.0.1,sctp:" + suffix)
			store.IPSetByID["ports"] = set
			probes := collectPeerProbes(store, 132, 12345, 8080)
			actors := []*actor{
				{ip: net.ParseIP("10.0.0.1"), unpoliced: true},
				{ip: net.ParseIP("10.0.0.2"), unpoliced: true},
				{ip: net.ParseIP("10.0.0.3"), unpoliced: true},
			}
			peers, owners, peerOf, classOf := groupActors(store, actors, probes)
			if len(peers) != 2 || len(owners) != 2 || peerOf[0] == peerOf[1] || classOf[1] != classOf[2] {
				t.Fatalf("incorrect equivalence classes: peers=%v owners=%v", peerOf, classOf)
			}
		})
	}
}

func TestOwnerProbesIgnoreUnrelatedPolicies(t *testing.T) {
	store := policystore.NewPolicyStore()
	store.ProfileByID[types.ProfileID{Name: "allow"}] = &proto.Profile{InboundRules: []*proto.Rule{{Action: "allow"}}, OutboundRules: []*proto.Rule{{Action: "allow"}}}
	store.ProfileByID[types.ProfileID{Name: "other"}] = &proto.Profile{InboundRules: []*proto.Rule{{Action: "deny", SrcNet: []string{"10.0.0.1/32"}}}}
	owner := &actor{wep: &proto.WorkloadEndpoint{ProfileIds: []string{"allow"}}}
	probe := &flow{protocol: 6, srcPort: 12345, dstPort: 8080}
	for _, direction := range []rules.RuleDir{rules.RuleDirIngress, rules.RuleDirEgress} {
		local := collectOwnerProbes(store, owner, direction, probe)
		if len(local.nets) != 0 {
			t.Fatal("unrelated rules split the owner's peers")
		}
		eval := ownerDirectionEvaluator(store, checker.EnforcedOnly, owner, direction, probe)
		for _, ip := range []string{"10.0.0.1", "10.0.0.2"} {
			peer := &actor{ip: net.ParseIP(ip)}
			if !eval(peer) {
				t.Fatal("allow profile should allow every peer")
			}
		}
	}
}

// Many globally distinct peers, but this owner's profile allows all of them.
func BenchmarkOwnerDefaultCache(b *testing.B) {
	previous := logrus.GetLevel()
	logrus.SetLevel(logrus.ErrorLevel)
	b.Cleanup(func() { logrus.SetLevel(previous) })
	store := policystore.NewPolicyStore()
	store.ProfileByID[types.ProfileID{Name: "allow"}] = &proto.Profile{InboundRules: []*proto.Rule{{Action: "allow"}}, OutboundRules: []*proto.Rule{{Action: "allow"}}}
	owner := &actor{ip: net.ParseIP("10.1.0.1"), wep: &proto.WorkloadEndpoint{ProfileIds: []string{"allow"}}}
	peers := make([]*actor, 1000)
	for i := range peers {
		peers[i] = &actor{ip: net.ParseIP(fmt.Sprintf("10.0.%d.%d", i/250, i%250+1))}
	}
	mkFlow := flowFactory(Request{Protocol: "tcp", Port: 8080, SrcPort: 12345})
	for _, cached := range []bool{false, true} {
		b.Run(fmt.Sprintf("cached=%t", cached), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if cached {
					evaluateClasses(store, checker.EnforcedOnly, []*actor{owner}, peers, mkFlow)
					continue
				}
				for _, peer := range peers {
					checker.Evaluate(checker.EnforcedOnly, rules.RuleDirEgress, store, owner.normalWEP(), mkFlow(owner, peer))
					checker.Evaluate(checker.EnforcedOnly, rules.RuleDirIngress, store, owner.normalWEP(), mkFlow(peer, owner))
				}
			}
		})
	}
}
