// SPDX-License-Identifier: AGPL-3.0-only

package neuron

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func TestSharedContractFixtures(t *testing.T) {
	_, source, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "..", "..", "contracts", "fixtures"))
	tests := []struct {
		file string
		out  any
	}{
		{"capabilities.v2.json", &CapabilitiesSynapse{}},
		{"deploy.v2.json", &DeploySynapse{}},
		{"status.v2.json", &StatusSynapse{}},
		{"deactivate.v2.json", &DeactivateSynapse{}},
		{"capabilities-response.v2.json", &CapabilitiesResponse{}},
		{"deploy-response.v2.json", &DeployResponse{}},
		{"miner-registration.v2.json", &MinerRegistration{}},
		{"miner-set.v2.json", &MinerSet{}},
		{"chain-state.v2.json", &ChainState{}},
		{"health-observation.v2.json", &HealthObservation{}},
		{"recovery-response.v2.json", &RecoveryResponse{}},
		{"bridge-deactivate.v2.json", &BridgeDeactivateRequest{}},
	}
	for _, test := range tests {
		t.Run(test.file, func(t *testing.T) {
			payload, err := os.ReadFile(filepath.Join(root, test.file))
			if err != nil {
				t.Fatal(err)
			}
			decoder := json.NewDecoder(bytes.NewReader(payload))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(test.out); err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(test.out)
			if err != nil {
				t.Fatalf("round trip failed: %v", err)
			}
			var originalValue, encodedValue any
			if err := json.Unmarshal(payload, &originalValue); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(encoded, &encodedValue); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(originalValue, encodedValue) {
				t.Fatalf("Go contract drifted from fixture\nfixture: %s\nencoded: %s", payload, encoded)
			}
		})
	}
}
