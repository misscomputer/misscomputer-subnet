// SPDX-License-Identifier: AGPL-3.0-only

// Command sandbox-host-observe prints, as a JSON array of
// sandbox-host-preflight.v1 checks, the read-only observations of
// pkg/sandboxhost for a host profile. The disposable conformance job runs it
// on the provisioned host so the live Go implementation, not only the lab
// script, is exercised against a real kernel. It never changes the host.
//
//	sandbox-host-observe -profile FILE preflight [-exclusive /a,/b]
//	sandbox-host-observe -profile FILE instance -pid PID
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/misscomputer/misscomputer-subnet/pkg/sandboxhost"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "sandbox-host-observe:", err)
		os.Exit(2)
	}
}

func run(args []string) error {
	global := flag.NewFlagSet("sandbox-host-observe", flag.ContinueOnError)
	profilePath := global.String("profile", "", "sandbox-host-profile.v1 file")
	if err := global.Parse(args); err != nil {
		return err
	}
	if *profilePath == "" || global.NArg() < 1 {
		return fmt.Errorf("usage: -profile FILE preflight|instance [flags]")
	}
	profile, err := sandboxhost.LoadProfile(*profilePath)
	if err != nil {
		return err
	}
	var checks []sandboxhost.Check
	mode := flag.NewFlagSet(global.Arg(0), flag.ContinueOnError)
	switch global.Arg(0) {
	case sandboxhost.ModePreflight:
		exclusive := mode.String("exclusive", "", "comma-separated cgroups sandboxes must not share")
		if err := mode.Parse(global.Args()[1:]); err != nil {
			return err
		}
		var list []string
		if *exclusive != "" {
			list = strings.Split(*exclusive, ",")
		}
		checks = sandboxhost.Host{}.Preflight(profile, list)
	case sandboxhost.ModeInstance:
		pid := mode.Int("pid", 0, "sentry PID of the instance")
		if err := mode.Parse(global.Args()[1:]); err != nil {
			return err
		}
		checks = sandboxhost.Host{}.ObserveInstance(profile, *pid)
	default:
		return fmt.Errorf("unknown mode %q", global.Arg(0))
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(checks)
}
