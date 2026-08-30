// SPDX-License-Identifier: AGPL-3.0-only

package tunnel

import "testing"

func TestRegistryRejectsUnsafeAndConflictingTargets(t *testing.T) {
	registry := NewLocalRegistry()
	for _, target := range []string{
		"ftp://127.0.0.1:80/path", "http://user@127.0.0.1:80/path",
		"http://127.0.0.1:80/path?target=other", "http://127.0.0.1:80/path#fragment",
		"http://127.0.0.1:80/path?", "http://127.0.0.1:80/path#",
	} {
		if err := registry.Register("endpoint", target); err == nil {
			t.Fatalf("unsafe target %q was accepted", target)
		}
	}
	if err := registry.Register("endpoint", "http://127.0.0.1:8080/runtime/endpoint"); err != nil {
		t.Fatal(err)
	}
	if err := registry.Register("endpoint", "http://127.0.0.1:8080/runtime/endpoint"); err != nil {
		t.Fatalf("exact idempotent registration failed: %v", err)
	}
	if err := registry.Register("endpoint", "http://127.0.0.1:8081/runtime/endpoint"); err == nil {
		t.Fatal("endpoint target rebinding was accepted")
	}
}
