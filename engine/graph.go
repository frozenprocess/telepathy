package engine

import (
	"strings"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/config"
	extdataplane "github.com/projectcalico/calico/felix/dataplane/external"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
)

// graphResult is the output of buildGraph: the populated policystore plus the
// per-endpoint proto representations the callers consume. Evaluate walks these
// with the app-policy checker; RenderIptables hands the policies/profiles/WEPs
// to the felix/rules renderer. Warnings/Errors accumulate feed-time issues so
// the caller can surface them without losing the rest of the result.
type graphResult struct {
	store     *policystore.PolicyStore
	wepByID   map[string]*proto.WorkloadEndpoint
	hepByName map[string]*proto.HostEndpoint
	// ipSetMembers holds the raw member strings the calc graph emitted per IP
	// set (the IPSetUpdate/IPSetDeltaUpdate payloads). The policystore folds
	// NET-type sets into a trie whose Members() is a stub, so callers that need
	// to enumerate members (RenderHNS, which inlines addresses into ACLs) read
	// them here instead. Membership tests (the checker) still use the store.
	ipSetMembers map[string][]string
	warnings     []string
	errors       []string
}

// buildGraph constructs Felix's calc graph from a Request, feeds in the tiers,
// profiles, namespaces, endpoints, extra resources and policies, then flushes
// it so every endpoint's computed proto.WorkloadEndpoint (with its resolved
// tier/policy ordering) lands in wepByID and every active policy/profile lands
// in store.PolicyByID / store.ProfileByID.
//
// icmp is the optional ICMP probe filter applied at feed time (Evaluate passes
// newICMPProbe(req) so contradictory ICMP rules are dropped before the
// checker, which matches only by protocol number, sees them). Pass nil to feed
// policies verbatim — RenderIptables does this, since iptables/nftables encode
// icmp type/code natively and shouldn't be pre-filtered by a probe.
func buildGraph(req Request, icmp *icmpProbe) graphResult {
	res := graphResult{
		wepByID:      map[string]*proto.WorkloadEndpoint{},
		hepByName:    map[string]*proto.HostEndpoint{},
		ipSetMembers: map[string][]string{},
	}

	// Build the calc graph and route its emitted proto into a policystore,
	// while stashing each endpoint's computed proto.WorkloadEndpoint (the
	// thing checker.Evaluate needs as its `ep` argument).
	conf := config.New()
	conf.FelixHostname = hostname

	eb := calc.NewEventSequencer(conf) // conf doubles as the EventSequencer's config source
	store := policystore.NewPolicyStore()
	res.store = store
	eb.Callback = func(msg any) {
		if tod, err := extdataplane.WrapPayloadWithEnvelope(msg, 0); err == nil && tod != nil {
			// policystore.ProcessUpdate has no HostEndpointUpdate case, so HEPs
			// are dropped here; we capture them separately below and synthesise
			// a WEP-shaped struct for checker.Evaluate at matrix time.
			store.ProcessUpdate("", tod, false)
		}
		if weu, ok := msg.(*proto.WorkloadEndpointUpdate); ok && weu.GetId() != nil {
			res.wepByID[weu.GetId().GetWorkloadId()] = weu.GetEndpoint()
		}
		if heu, ok := msg.(*proto.HostEndpointUpdate); ok && heu.GetId() != nil {
			res.hepByName[heu.GetId().GetEndpointId()] = heu.GetEndpoint()
		}
		// Capture raw IP-set members for enumeration (see ipSetMembers doc).
		if u, ok := msg.(*proto.IPSetUpdate); ok {
			res.ipSetMembers[u.GetId()] = append([]string(nil), u.GetMembers()...)
		}
		if d, ok := msg.(*proto.IPSetDeltaUpdate); ok {
			cur := res.ipSetMembers[d.GetId()]
			removed := map[string]bool{}
			for _, m := range d.GetRemovedMembers() {
				removed[m] = true
			}
			next := make([]string, 0, len(cur)+len(d.GetAddedMembers()))
			for _, m := range cur {
				if !removed[m] {
					next = append(next, m)
				}
			}
			next = append(next, d.GetAddedMembers()...)
			res.ipSetMembers[d.GetId()] = next
		}
	}

	calcGraph := calc.NewCalculationGraph(eb, calc.NewLookupsCache(), conf, func() {})
	disp := calcGraph.AllUpdDispatcher

	send := func(key model.Key, value any) {
		disp.OnUpdate(api.Update{
			UpdateType: api.UpdateTypeKVNew,
			KVPair:     model.KVPair{Key: key, Value: value},
		})
	}

	// Tiers must exist before any policy that lives in them. The "default" tier
	// holds K8s NPs and Calico v3 (Global)NetworkPolicies; "kube-admin" and
	// "kube-baseline" hold v1alpha2 ClusterNetworkPolicies (Admin/Baseline
	// respectively). Orders mirror what real Calico ships in the cluster:
	// Admin (1K) < default (1M) < Baseline (10M). Admin/Baseline default to
	// Pass so an unmatched-but-selected pod falls through to the next tier
	// (matching the upstream NPA semantics); default keeps Deny so existing
	// k8s NP / GNP testcases behave unchanged. The checker panics on empty
	// DefaultAction.
	send(model.TierKey{Name: names.KubeAdminTierName},
		&model.Tier{Order: floatPtr(apiv3.KubeAdminTierOrder), DefaultAction: apiv3.Pass})
	send(model.TierKey{Name: "default"},
		&model.Tier{Order: floatPtr(apiv3.DefaultTierOrder), DefaultAction: apiv3.Deny})
	send(model.TierKey{Name: names.KubeBaselineTierName},
		&model.Tier{Order: floatPtr(apiv3.KubeBaselineTierOrder), DefaultAction: apiv3.Pass})

	// Per-namespace default-allow profiles, so endpoints NOT selected by any
	// policy stay reachable (Calico's "allow until selected" behaviour).
	for _, ns := range req.Namespaces {
		send(model.ProfileRulesKey{ProfileKey: model.ProfileKey{Name: "kns." + ns.Name}},
			&model.ProfileRules{
				InboundRules:  []model.Rule{{Action: "allow"}},
				OutboundRules: []model.Rule{{Action: "allow"}},
			})
	}

	// Namespace labels, used to project Calico's pcns.* labels onto endpoints.
	nsLabels := map[string]map[string]string{}
	for _, ns := range req.Namespaces {
		nsLabels[ns.Name] = ns.Labels
	}

	// ServiceAccount labels, indexed by "<namespace>/<sa>" so endpoints can
	// look up their SA's labels and stamp them as pcsa.* — see
	// projectServiceAccountLabels for the projection rules.
	saIndex := map[string]map[string]string{}
	for _, sa := range req.ServiceAccounts {
		saIndex[sa.Namespace+"/"+sa.Name] = sa.Labels
	}

	// Workload endpoints. We add the projectcalico.org/namespace label that
	// Calico injects (k8s NetworkPolicy conversion scopes policies by it),
	// plus the namespace's labels projected as pcns.<k>=<v> (and a pcns name
	// label), plus the SA's labels projected as pcsa.<k>=<v> when the
	// endpoint declares a ServiceAccountName.
	for _, ep := range req.Endpoints {
		labels := map[string]string{}
		for k, v := range ep.Labels {
			labels[k] = v
		}
		labels[apiv3.LabelNamespace] = ep.Namespace
		labels["projectcalico.org/orchestrator"] = "k8s"
		for k, v := range nsLabels[ep.Namespace] {
			labels["pcns."+k] = v
		}
		labels["pcns.projectcalico.org/name"] = ep.Namespace
		projectServiceAccountLabels(labels, ep.Namespace, ep.ServiceAccountName, saIndex)

		wep := &model.WorkloadEndpoint{
			State:      "active",
			Name:       "cali-" + strings.ReplaceAll(ep.ID, "/", "-"),
			ProfileIDs: []string{"kns." + ep.Namespace},
			Labels:     uniquelabels.Make(labels),
		}
		applyEndpointIP(wep, ep.IP)
		applyEndpointPorts(wep, ep.Ports)

		send(model.WorkloadEndpointKey{
			Hostname:       hostname,
			OrchestratorID: "k8s",
			WorkloadID:     ep.ID,
			EndpointID:     "eth0",
		}, wep)
	}

	// Non-policy resources (host endpoints, network sets, services, slices).
	// Errors here go into the result but don't block the rest of the run.
	if w, e := feedExtraResources(send, req); len(w)+len(e) > 0 {
		res.warnings = append(res.warnings, w...)
		res.errors = append(res.errors, e...)
	}

	for _, p := range req.Policies {
		if err := feedPolicy(send, p, req.EvaluateStaged, icmp); err != nil {
			res.errors = append(res.errors, err.Error())
		}
	}

	// The policy resolver defers per-endpoint tier computation until in-sync,
	// so signal it; then CalcGraph.Flush() pushes endpoint updates into the
	// EventSequencer, and eb.Flush() emits them via our callback.
	disp.OnStatusUpdated(api.InSync)
	calcGraph.Flush()
	eb.Flush()

	return res
}
