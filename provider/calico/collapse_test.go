// SPDX-License-Identifier: Apache-2.0
package calico

import (
	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
	"net"
	"testing"
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
