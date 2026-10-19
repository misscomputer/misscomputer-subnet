// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package main

import (
	"github.com/misscomputer/misscomputer-subnet/pkg/sandbox"
	"github.com/misscomputer/misscomputer-subnet/pkg/sandboxops"
)

const selfExecutable = ""

// The helper runs only inside a Linux sandbox; elsewhere every exec op is
// ops_unsupported, as file ops are through fsroot.
type unsupportedExecs struct{}

func newExecRunner(string, string) execRunner { return unsupportedExecs{} }

func (unsupportedExecs) start(string, sandboxops.ExecSpec) sandboxops.Response { return unsupported() }
func (unsupportedExecs) read(string, string, uint64, uint64) sandboxops.Response {
	return unsupported()
}
func (unsupportedExecs) cancel(string, bool) sandboxops.Response { return unsupported() }
func (unsupportedExecs) status(string) sandboxops.Response       { return unsupported() }

func unsupported() sandboxops.Response { return sandboxops.Failure(sandbox.OpCodeOpsUnsupport) }

func supervise(string, string) int { return 2 }
