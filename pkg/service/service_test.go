// SPDX-License-Identifier: AGPL-3.0-only

package service

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestBridgeBindDefaultsToLoopbackOnly(t *testing.T) {
	for _, address := range []string{"127.0.0.1:9101", "[::1]:9101", "localhost:9101"} {
		if err := ValidateBind(address, false); err != nil {
			t.Fatalf("loopback address %q rejected: %v", address, err)
		}
	}
	if err := ValidateBind("0.0.0.0:9101", false); err == nil {
		t.Fatal("wildcard bridge bind was accepted without override")
	}
}

func TestSigningKeyIsPersistentAndPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "service.key")
	first, err := LoadOrCreateSigningKey(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreateSigningKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("service key changed across reload")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("service key mode = %o", info.Mode().Perm())
	}
}

func TestSigningKeyRejectsUnsafeExistingPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "service.key")
	if err := os.WriteFile(path, []byte("00"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateSigningKey(path); err == nil {
		t.Fatal("group/world-readable service key was accepted")
	}
}
