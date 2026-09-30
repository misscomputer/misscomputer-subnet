// SPDX-License-Identifier: AGPL-3.0-only

package neuron

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func registrationFixture(t *testing.T, name string) MinerRegistration {
	t.Helper()
	_, source, _, _ := runtime.Caller(0)
	payload, err := os.ReadFile(filepath.Join(filepath.Dir(source), "..", "..", "contracts", "fixtures", name))
	if err != nil {
		t.Fatal(err)
	}
	var registration MinerRegistration
	if err := json.Unmarshal(payload, &registration); err != nil {
		t.Fatal(err)
	}
	return registration
}

// A runtime learns capabilities only from a valid v3 registration; a v2
// registration or any malformed feature list grants none.
func TestRegistrationCapabilityFeaturesFailClosed(t *testing.T) {
	v2 := registrationFixture(t, "miner-registration.v2.json")
	v3 := registrationFixture(t, "miner-registration.v3.json")
	if features, err := v2.CapabilityFeatures(); err != nil || features != nil || v2.HasFeature("deploy") {
		t.Fatalf("v2: %v %v", features, err)
	}
	if !v3.HasFeature("organic-static-v1") || v3.HasFeature("organic-static-v2") {
		t.Fatal("v3 fixture feature lookup")
	}
	many := make([]string, MaxRegistrationFeatures+1)
	for index := range many {
		many[index] = fmt.Sprintf("feature-%02d", index)
	}
	with := func(protocol string, features *[]string) MinerRegistration {
		changed := v3
		changed.Protocol, changed.Features = protocol, features
		return changed
	}
	list := func(values ...string) *[]string { return &values }
	for name, registration := range map[string]MinerRegistration{
		"v2 with features": with(SynapseVersion, list("deploy")),
		"v3 without":       with(MinerRegistrationV3Version, nil),
		"unsorted":         with(MinerRegistrationV3Version, list("status", "deploy")),
		"duplicate":        with(MinerRegistrationV3Version, list("deploy", "deploy")),
		"not a token":      with(MinerRegistrationV3Version, list("Organic-OCI-v1")),
		"too many":         with(MinerRegistrationV3Version, &many),
		"unknown protocol": with("subnet-synapse.v4", list("deploy")),
	} {
		if _, err := registration.CapabilityFeatures(); err == nil || registration.HasFeature("deploy") {
			t.Errorf("%s: accepted", name)
		}
	}
}
