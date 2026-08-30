// SPDX-License-Identifier: AGPL-3.0-only

package workload

import (
	"bytes"
	"errors"
	"testing"
)

func TestGenerateWithReaderIsDeterministicAndDecodable(t *testing.T) {
	entropy := bytes.NewReader(bytes.Repeat([]byte{0x5a}, 2048))
	spec, layer, err := GenerateWithReader("static", 1024, entropy)
	if err != nil {
		t.Fatal(err)
	}
	if spec.BuildID != "5a5a5a5a5a5a5a5a5a5a5a5a" || len(spec.ChallengeValue) != 64 {
		t.Fatalf("unexpected deterministic identity: %#v", spec)
	}
	if len(layer) != 1024 {
		t.Fatalf("layer length=%d want=1024", len(layer))
	}
	decoded, err := Decode(layer)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != spec {
		t.Fatalf("decoded spec=%#v want=%#v", decoded, spec)
	}
}

func TestGenerateSpecDoesNotMaterializeLargePayload(t *testing.T) {
	spec, err := GenerateSpecWithReader("heavy", 1<<30, bytes.NewReader(make([]byte, 44)))
	if err != nil {
		t.Fatal(err)
	}
	if spec.PayloadBytes != 1<<30 || len(spec.BuildID) != 24 || len(spec.ChallengeValue) != 64 {
		t.Fatalf("unexpected spec: %#v", spec)
	}
}

func TestInjectedEntropyFailureIsReturned(t *testing.T) {
	reader := errorReader{err: errors.New("entropy failed")}
	if _, err := GenerateSpecWithReader("static", 1024, reader); err == nil {
		t.Fatal("entropy failure was accepted")
	}
}

type errorReader struct{ err error }

func (reader errorReader) Read([]byte) (int, error) { return 0, reader.err }
