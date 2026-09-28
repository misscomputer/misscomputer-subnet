// SPDX-License-Identifier: AGPL-3.0-only

package runtime

import (
	"regexp"
	"strings"
	"testing"
)

// Every endpoint incarnation owns a distinct deterministic container name
// and state directory, so stopping an old generation can never touch a new
// one.
func TestCleanupIdentityIsEndpointIncarnationSafe(t *testing.T) {
	runtime := NewDockerOCIRuntime("docker", t.TempDir(), DefaultOrganicNetwork, DefaultOrganicBridge)
	first := "same-5Fminer-g1-" + strings.Repeat("a", 32)
	second := "same-5Fminer-g2-" + strings.Repeat("b", 32)
	firstPlan, err := PrepareCleanup(runtime, first)
	if err != nil {
		t.Fatal(err)
	}
	secondPlan, err := PrepareCleanup(runtime, second)
	if err != nil {
		t.Fatal(err)
	}
	if firstPlan.InstanceID != InstanceName(first) || secondPlan.InstanceID != InstanceName(second) {
		t.Fatalf("runtime IDs are not derived from endpoint IDs: %q %q", firstPlan.InstanceID, secondPlan.InstanceID)
	}
	if firstPlan.InstanceID == secondPlan.InstanceID || firstPlan.LayerPath == secondPlan.LayerPath {
		t.Fatalf("incarnations collided: %+v %+v", firstPlan, secondPlan)
	}
	if again, err := PrepareCleanup(runtime, first); err != nil || again != firstPlan {
		t.Fatalf("cleanup identity is not deterministic: %+v %v", again, err)
	}
}

func TestInstanceNameNormalizationRetainsCollisionResistance(t *testing.T) {
	first := InstanceName("deployment/miner")
	second := InstanceName("deployment?miner")
	if first == second {
		t.Fatalf("normalized endpoint IDs collided at %q", first)
	}
	valid := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]+$`)
	for _, name := range []string{first, second, InstanceName(strings.Repeat("long/", 100))} {
		if !valid.MatchString(name) || len(name) > 70 {
			t.Fatalf("invalid runtime name %q", name)
		}
	}
}
