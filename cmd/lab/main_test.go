// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"testing"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
)

func TestRunErrorAfterAcquisitionExecutesCleanup(t *testing.T) {
	cleaned := false
	openStore := func() (artifact.Store, func(), error) {
		return artifact.FileStore{Root: t.TempDir()}, func() { cleaned = true }, nil
	}
	err := runWithArtifactStore(context.Background(), []string{"-runtime=unsupported", "-size-mib=0"}, &bytes.Buffer{}, openStore)
	if err == nil {
		t.Fatal("unsupported runtime succeeded")
	}
	if !cleaned {
		t.Fatal("run error bypassed acquired artifact-store cleanup")
	}
}
