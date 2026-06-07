package engine

import (
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
)

// icmpProbe is the probe-side ICMP fingerprint extracted from a Request. It's
// what filterRulesByICMP compares each apiv3.Rule's ICMP / NotICMP matcher
// against. nil means "no ICMP filtering"; that's the default for backward
// compatibility with callers that never set Request.ICMPType/.ICMPCode.
type icmpProbe struct {
	// protocol is the probe's IP protocol number. We only filter when this
	// is 1 (ICMP) or 58 (ICMPv6); rules with icmp/notICMP matchers under any
	// other probe protocol are dropped by matchL4Protocol upstream (the rule
	// would also have to declare protocol: ICMP for the matcher to be valid)
	// so we can leave them alone here.
	protocol int
	typ      *int
	code     *int
}

// newICMPProbe returns nil when the Request does not enable ICMP filtering:
// callers that leave ICMPType and ICMPCode nil keep the engine's
// pre-extension semantics (icmp.type/code silently ignored). When at least
// one is set, the probe becomes active.
func newICMPProbe(req Request) *icmpProbe {
	if req.ICMPType == nil && req.ICMPCode == nil {
		return nil
	}
	return &icmpProbe{
		protocol: protocolNumber(req.Protocol),
		typ:      req.ICMPType,
		code:     req.ICMPCode,
	}
}

// active reports whether the probe should filter at all. Centralises the
// "nil probe OR no fields set" check so callers don't repeat it.
func (p *icmpProbe) active() bool {
	return p != nil && (p.typ != nil || p.code != nil)
}

// applyICMPFilter rewrites a v3 (Staged){Global}NetworkPolicy's rule lists in
// place, dropping any rule whose icmp/notICMP matcher contradicts the probe.
// Other apiv3 kinds (NetworkSet, HostEndpoint, Tier, …) pass through
// untouched; the empty default branch keeps the call site uniform.
//
// We mutate before the libcalico-go updateprocessor runs so the calc graph
// — and therefore checker.Evaluate's view of the policy — never sees the
// dropped rules. This sidesteps the upstream app-policy/checker's blind spot
// (matchL4Protocol checks only the protocol number; icmp.type/code go through
// the proto.Rule oneof but no matcher reads them).
func applyICMPFilter(value any, p *icmpProbe) {
	if !p.active() {
		return
	}
	switch v := value.(type) {
	case *apiv3.NetworkPolicy:
		v.Spec.Ingress = filterRulesByICMP(v.Spec.Ingress, p)
		v.Spec.Egress = filterRulesByICMP(v.Spec.Egress, p)
	case *apiv3.GlobalNetworkPolicy:
		v.Spec.Ingress = filterRulesByICMP(v.Spec.Ingress, p)
		v.Spec.Egress = filterRulesByICMP(v.Spec.Egress, p)
	case *apiv3.StagedNetworkPolicy:
		v.Spec.Ingress = filterRulesByICMP(v.Spec.Ingress, p)
		v.Spec.Egress = filterRulesByICMP(v.Spec.Egress, p)
	case *apiv3.StagedGlobalNetworkPolicy:
		v.Spec.Ingress = filterRulesByICMP(v.Spec.Ingress, p)
		v.Spec.Egress = filterRulesByICMP(v.Spec.Egress, p)
	}
}

// filterRulesByICMP returns rules whose ICMP / NotICMP fields don't
// contradict the probe. Rule order is preserved so Calico's first-match
// semantics are unchanged for the rules that remain.
func filterRulesByICMP(rules []apiv3.Rule, p *icmpProbe) []apiv3.Rule {
	if !p.active() {
		return rules
	}
	out := make([]apiv3.Rule, 0, len(rules))
	for _, r := range rules {
		if ruleICMPMatchesProbe(r, p) {
			out = append(out, r)
		}
	}
	return out
}

// ruleICMPMatchesProbe reports whether the rule's ICMP / NotICMP fields
// admit a packet with the probe's type and code. Rules without either field
// pass through (icmp constraints absent ⇒ unconstrained at the ICMP layer).
//
// Semantics mirror the iptables / eBPF dataplane that Felix programs:
//
//   - rule.ICMP.Type==N matches iff probe.typ != nil && *probe.typ == N.
//     When probe.typ is nil, the rule is more specific than the caller is
//     willing to commit to; we drop the rule rather than guess. Same shape
//     for rule.ICMP.Code.
//   - rule.NotICMP.Type==N matches iff probe.typ == nil || *probe.typ != N.
//     A NotICMP block with both Type and Code only excludes the (Type,Code)
//     pair; either field differing means the negation is satisfied. That's
//     the same rule Felix's negative-rule rendering applies.
func ruleICMPMatchesProbe(r apiv3.Rule, p *icmpProbe) bool {
	if r.ICMP != nil {
		if r.ICMP.Type != nil {
			if p.typ == nil || *r.ICMP.Type != *p.typ {
				return false
			}
		}
		if r.ICMP.Code != nil {
			if p.code == nil || *r.ICMP.Code != *p.code {
				return false
			}
		}
	}
	if r.NotICMP != nil {
		// Negation is satisfied unless every field set on NotICMP matches
		// the probe exactly. (Type alone set ⇒ probe type must equal it for
		// exclusion; Type+Code set ⇒ both must equal.)
		excludes := true
		if r.NotICMP.Type != nil {
			if p.typ == nil || *r.NotICMP.Type != *p.typ {
				excludes = false
			}
		}
		if excludes && r.NotICMP.Code != nil {
			if p.code == nil || *r.NotICMP.Code != *p.code {
				excludes = false
			}
		}
		// If NotICMP had no fields set, treat it as a no-op (Calico's
		// admission rejects an empty NotICMP, but be defensive).
		if r.NotICMP.Type == nil && r.NotICMP.Code == nil {
			excludes = false
		}
		if excludes {
			return false
		}
	}
	return true
}
