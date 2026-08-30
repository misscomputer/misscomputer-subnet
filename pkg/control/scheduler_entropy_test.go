// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"bytes"
	"errors"
	"testing"
)

type failingEntropy struct{}

func (failingEntropy) Read([]byte) (int, error) { return 0, errors.New("entropy failed") }

func TestSchedulerRandomIDUsesExplicitEntropySeam(t *testing.T) {
	scheduler := Scheduler{Entropy: bytes.NewReader(make([]byte, 16))}
	value, err := scheduler.randomID(16)
	if err != nil {
		t.Fatal(err)
	}
	if value != "00000000000000000000000000000000" {
		t.Fatalf("random ID = %q", value)
	}
	scheduler.Entropy = failingEntropy{}
	if _, err := scheduler.randomID(16); err == nil {
		t.Fatal("entropy failure was ignored")
	}
}
