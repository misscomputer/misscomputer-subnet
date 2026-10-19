// SPDX-License-Identifier: AGPL-3.0-only

// Command sandbox-ops-helper is the in-sandbox helper of sandbox-ops-v1
// (docs/sandbox-ops-v1.md, docs/sandbox-ops-v1-helper.md). A miner backend
// runs it with docker exec at the fixed path /.misscomputer/sandbox-ops-helper,
// as the image's default user, with an empty environment and no TTY. It reads
// one bounded request (pkg/sandboxops) on stdin, performs one file or exec
// operation inside the sandbox, writes one bounded response on stdout, and
// exits.
//
// It has no flags, configuration files, network or environment-driven
// behavior. File operations resolve through fsroot (openat2 in-root from "/").
// An exec runs under a supervisor process the helper starts in its own
// session; the supervisor captures each stream's first max_output_bytes under
// /tmp/.misscomputer-ops/<exec_id>, enforces the exec deadline, and kills the
// exec's process group on cancel. The helper is never PID 1 and never
// replaces the image entrypoint.
package main

import (
	"os"
)

// superviseArg is the internal first argument that turns a helper process
// started by the helper itself into an exec supervisor:
// supervise <capture root> <exec id>. The miner never passes arguments.
const superviseArg = "supervise"

func main() {
	if len(os.Args) == 4 && os.Args[1] == superviseArg {
		os.Exit(supervise(os.Args[2], os.Args[3]))
	}
	if len(os.Args) != 1 {
		os.Exit(2)
	}
	os.Exit(serveProcess(os.Stdin, os.Stdout))
}
