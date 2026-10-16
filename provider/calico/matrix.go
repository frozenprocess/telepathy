// SPDX-License-Identifier: Apache-2.0
package calico

import (
	"bufio"
	"io"
)

// matrixSink collects the connectivity matrix. Default (in-memory) mode fills a
// map the Response carries. When streaming (req.MatrixSink != nil) it writes
// every pair to that writer as "src->dst\tverdict\n" and keeps resident only the
// columns a post-processor reads back — the external actors (buildActorReport)
// and Service backends (addServiceColumns) — reducing matrix memory to O(endpoints × kept columns). bufio latches the first write error; check it at flush.
type matrixSink struct {
	w    *bufio.Writer   // streaming target; nil = in-memory only
	keep map[string]bool // dst ids to retain in m while streaming; nil = keep all
	m    map[string]string
}

func newMatrixSink(w io.Writer, keep map[string]bool) *matrixSink {
	s := &matrixSink{m: map[string]string{}, keep: keep}
	if w != nil {
		s.w = bufio.NewWriterSize(w, 1<<20)
	}
	return s
}

func (s *matrixSink) put(src, dst, verdict string) {
	if s.w != nil {
		s.w.WriteString(src)
		s.w.WriteString("->")
		s.w.WriteString(dst)
		s.w.WriteByte('\t')
		s.w.WriteString(verdict)
		s.w.WriteByte('\n')
		if s.keep != nil && !s.keep[dst] {
			return // not needed by a post-processor — don't hold it in RAM
		}
	}
	s.m[src+"->"+dst] = verdict
}

func (s *matrixSink) get(src, dst string) string { return s.m[src+"->"+dst] }

func (s *matrixSink) flush() error {
	if s.w == nil {
		return nil
	}
	return s.w.Flush()
}

// matrixKeepSet is the set of dst ids whose matrix column a post-processor reads
// back: external actors (buildActorReport's internet posture) and Service
// backends (addServiceColumns' reachability OR). Under streaming, only these
// columns stay in RAM; every other pair is written straight to disk.
func matrixKeepSet(req Request, actors actorBundle) map[string]bool {
	keep := map[string]bool{}
	for _, a := range actors.list {
		if actorKindString(a) == "external" {
			keep[a.id] = true
		}
	}
	if len(req.Services) > 0 {
		ipToID := map[string]string{}
		for _, ep := range req.Endpoints {
			if ep.IP != "" {
				ipToID[ep.IP] = ep.ID
			}
		}
		for _, svc := range req.Services {
			for _, b := range serviceBackendIDs(svc, req, ipToID) {
				keep[b] = true
			}
		}
	}
	return keep
}
