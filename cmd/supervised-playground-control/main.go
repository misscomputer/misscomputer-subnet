// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/misscomputer/misscomputer-subnet/pkg/playground"
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("supervised-playground-control", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	runID := flags.String("run-id", playground.DefaultRunID, "lowercase local run identity")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	bundle, err := playground.RunControl(ctx, *runID)
	if err != nil {
		return err
	}
	rendered, err := playground.MarshalControlBundle(bundle)
	if err != nil {
		return err
	}
	_, err = output.Write(rendered)
	return err
}
