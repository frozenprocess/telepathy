// SPDX-License-Identifier: Apache-2.0
package api

import "iter"

// MatrixPair identifies an ordered flow to include in a partial matrix.
type MatrixPair struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// EndpointPairs visits requested pairs without scanning the full Cartesian
// product. An empty selection visits every distinct-ID pair. Unknown IDs and
// self-pairs are omitted, just as they are absent from a full matrix.
func EndpointPairs(endpoints []Endpoint, pairs []MatrixPair) iter.Seq2[int, int] {
	return func(yield func(int, int) bool) {
		if len(pairs) == 0 {
			for i := range endpoints {
				for j := range endpoints {
					if endpoints[i].ID != endpoints[j].ID && !yield(i, j) {
						return
					}
				}
			}
			return
		}
		indices := make(map[string][]int, len(endpoints))
		for i, ep := range endpoints {
			indices[ep.ID] = append(indices[ep.ID], i)
		}
		seen := make(map[MatrixPair]bool, len(pairs))
		for _, pair := range pairs {
			if pair.From == pair.To || seen[pair] {
				continue
			}
			seen[pair] = true
			for _, i := range indices[pair.From] {
				for _, j := range indices[pair.To] {
					if !yield(i, j) {
						return
					}
				}
			}
		}
	}
}
