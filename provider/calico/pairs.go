// SPDX-License-Identifier: Apache-2.0
package calico

import (
	"github.com/frozenprocess/telepathy/api"
	"github.com/projectcalico/calico/app-policy/policystore"
)

// fillMatrixPairs uses the same per-flow evaluator as the full matrix, including
// HEP overlays and staged scope. Only requested service columns resolve their
// backends; dependent verdicts are cached but never emitted as extra pairs.
func fillMatrixPairs(sink *matrixSink, req Request, actors actorBundle, store *policystore.PolicyStore, mkFlow func(*actor, *actor) *flow) {
	byID := make(map[string]*actor, len(actors.list))
	for _, a := range actors.list {
		byID[a.id] = a
	}
	services := make(map[string]ServiceInput, len(req.Services))
	for _, svc := range req.Services {
		services["svc/"+svc.Namespace+"/"+svc.Name] = svc
	}
	ipToID := make(map[string]string, len(req.Endpoints))
	for _, ep := range req.Endpoints {
		if ep.IP != "" {
			ipToID[ep.IP] = ep.ID
		}
	}
	backends := map[string][]string{}
	cache := map[api.MatrixPair]bool{}
	allows := func(src, dst *actor) bool {
		key := api.MatrixPair{From: src.id, To: dst.id}
		if allow, ok := cache[key]; ok {
			return allow
		}
		allow, _ := evalFlow(store, stagedScope(req), src, dst, mkFlow(src, dst), mkFlow(dst, src), actors.hepsByNode)
		cache[key] = allow
		return allow
	}
	seen := make(map[api.MatrixPair]bool, len(req.MatrixPairs))
	for _, pair := range req.MatrixPairs {
		src := byID[pair.From]
		if src == nil || seen[pair] {
			continue
		}
		seen[pair] = true
		allow := false
		if svc, ok := services[pair.To]; ok {
			ids, resolved := backends[pair.To]
			if !resolved {
				ids = serviceBackendIDs(svc, req, ipToID)
				backends[pair.To] = ids
			}
			for _, id := range ids {
				if id == src.id || (byID[id] != nil && allows(src, byID[id])) {
					allow = true
					break
				}
			}
		} else {
			dst := byID[pair.To]
			if dst == nil || src.id == dst.id {
				continue
			}
			allow = allows(src, dst)
		}
		verdict := "deny"
		if allow {
			verdict = "allow"
		}
		sink.put(pair.From, pair.To, verdict)
	}
}
