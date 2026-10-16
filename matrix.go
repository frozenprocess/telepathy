// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/frozenprocess/telepathy/api"
)

// writeMatrixTSV dumps an in-memory matrix in the same "src->dst\tverdict" line
// format the engine streams, so -matrix-out yields an identical file whether the
// provider streamed or not.
func writeMatrixTSV(w io.Writer, m map[string]string) error {
	bw := bufio.NewWriterSize(w, 1<<20)
	for k, v := range m {
		bw.WriteString(k)
		bw.WriteByte('\t')
		bw.WriteString(v)
		bw.WriteByte('\n')
	}
	return bw.Flush()
}

// runAssertionsFromMatrixFile gates assertions against a matrix file streamed by
// -matrix-out. It keeps only the asserted pairs resident (from a single line
// scan), so a multi-GB matrix costs O(assertions) memory, not O(pairs).
func runAssertionsFromMatrixFile(path string, assertions []api.Assertion) (api.AssertionReport, error) {
	need := make(map[string]bool, len(assertions))
	for _, a := range assertions {
		need[a.From+"->"+a.To] = true
	}
	f, err := os.Open(path)
	if err != nil {
		return api.AssertionReport{}, err
	}
	defer f.Close()

	matrix := make(map[string]string, len(need))
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024) // headroom for long endpoint ids
	for sc.Scan() {
		line := sc.Text()
		tab := strings.IndexByte(line, '\t')
		if tab < 0 {
			continue
		}
		if key := line[:tab]; need[key] {
			matrix[key] = line[tab+1:]
		}
	}
	if err := sc.Err(); err != nil {
		return api.AssertionReport{}, fmt.Errorf("read matrix %s: %w", path, err)
	}
	return api.RunAssertionsOnMatrix(matrix, assertions), nil
}
