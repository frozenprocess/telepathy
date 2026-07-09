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

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/frozenprocess/telepathy/api"
	"github.com/frozenprocess/telepathy/provider"
)

// Out-of-process providers run as their own binary, built from their own Go
// module so their CNI's dependency versions never have to reconcile with the
// shell's (Calico's). They speak the vendor-neutral JSON contract: an
// api.Request on stdin, an api.Response on stdout; `-capabilities` prints the
// capability list. The Antrea and Cilium providers are registered this way.
func init() {
	provider.Register(externalProvider{name: "antrea", binary: "telepathy-engine-antrea"})
	provider.Register(externalProvider{name: "cilium", binary: "telepathy-engine-cilium"})
}

// externalProvider is a provider.Provider backed by an external engine binary.
type externalProvider struct {
	name   string
	binary string
}

func (p externalProvider) Name() string { return p.name }

func (p externalProvider) Evaluate(req api.Request) api.Response {
	data, err := json.Marshal(req)
	if err != nil {
		return api.Response{Errors: []string{fmt.Sprintf("%s: marshal request: %v", p.name, err)}}
	}
	out, err := p.run(data)
	if err != nil {
		return api.Response{Errors: []string{err.Error()}}
	}
	var resp api.Response
	if err := json.Unmarshal(out, &resp); err != nil {
		return api.Response{Errors: []string{fmt.Sprintf("%s: decode response: %v", p.name, err)}}
	}
	return resp
}

func (p externalProvider) Capabilities() []api.Capability {
	out, err := p.run(nil, "-capabilities")
	if err != nil {
		return []api.Capability{{Name: p.name + " engine", Supported: false, Notes: err.Error()}}
	}
	var caps []api.Capability
	if err := json.Unmarshal(out, &caps); err != nil {
		return []api.Capability{{Name: p.name + " engine", Supported: false,
			Notes: fmt.Sprintf("decode capabilities: %v", err)}}
	}
	return caps
}

// run execs the engine binary with the given args, feeds stdin (when non-nil),
// and returns its stdout. stderr is folded into the error on failure.
func (p externalProvider) run(stdin []byte, args ...string) ([]byte, error) {
	bin, err := p.locate()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(bin, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := stderr.String()
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("%s engine: %s", p.name, msg)
	}
	return stdout.Bytes(), nil
}

// locate finds the engine binary: an explicit TELEPATHY_<NAME>_ENGINE override,
// then next to this executable (how `make build` lays them out), then $PATH.
func (p externalProvider) locate() (string, error) {
	if env := os.Getenv("TELEPATHY_" + upper(p.name) + "_ENGINE"); env != "" {
		return env, nil
	}
	if self, err := os.Executable(); err == nil {
		cand := filepath.Join(filepath.Dir(self), p.binary)
		if _, err := os.Stat(cand); err == nil {
			return cand, nil
		}
	}
	if path, err := exec.LookPath(p.binary); err == nil {
		return path, nil
	}
	return "", fmt.Errorf("%s engine binary %q not found "+
		"(build it with `make build`, or set TELEPATHY_%s_ENGINE)", p.name, p.binary, upper(p.name))
}

func upper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
	}
	return string(b)
}
