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

//go:build e2e

package e2e

import (
	"sort"
	"strings"

	"github.com/frozenprocess/telepathy/api"
)

// serverPlan is the full set of L4 ports a case's agnhost pods must listen on.
// agnhost netexec binds exactly one TCP, one UDP and (optionally) one SCTP port
// per process, so a case probing several ports of one protocol needs several
// netexec processes — see netexecProcs in manifest.go. tcp/udp always carry at
// least one port (agnhost's 8080/8081 defaults); sctp is empty unless probed.
type serverPlan struct {
	tcp  []int
	udp  []int
	sctp []int
}

// serverPorts decides which ports agnhost netexec must listen on for a case.
// agnhost's defaults already serve TCP on 8080 and UDP on 8081; we serve every
// distinct (protocol, port) the assertions probe, so a case that probes a
// protocol on more than one port (e.g. notPorts cases that check both the
// excluded app port and an allowed alt port) gets a listener on each.
func serverPorts(req api.Request, assertions []api.Assertion) serverPlan {
	byProto := map[string]map[int]bool{}
	add := func(proto string, port int) {
		proto = strings.ToLower(proto)
		if byProto[proto] == nil {
			byProto[proto] = map[int]bool{}
		}
		byProto[proto][port] = true
	}
	for _, a := range assertions {
		port := a.Port
		if port == 0 {
			port = req.Port
		}
		if port == 0 {
			port = 8080
		}
		proto := a.Protocol
		if proto == "" {
			proto = req.Protocol
		}
		if proto == "" {
			proto = "tcp"
		}
		add(proto, port)
	}
	sorted := func(proto string) []int {
		ports := byProto[proto]
		keys := make([]int, 0, len(ports))
		for p := range ports {
			keys = append(keys, p)
		}
		sort.Ints(keys)
		return keys
	}
	plan := serverPlan{tcp: sorted("tcp"), udp: sorted("udp"), sctp: sorted("sctp")}
	if len(plan.tcp) == 0 {
		plan.tcp = []int{8080}
	}
	if len(plan.udp) == 0 {
		plan.udp = []int{8081}
	}
	return plan
}

// joinManifests concatenates rendered docs with `---` separators, dropping empties.
func joinManifests(docs ...string) string {
	var nonEmpty []string
	for _, d := range docs {
		if strings.TrimSpace(d) != "" {
			nonEmpty = append(nonEmpty, strings.TrimRight(d, "\n"))
		}
	}
	return strings.Join(nonEmpty, "\n---\n") + "\n"
}
