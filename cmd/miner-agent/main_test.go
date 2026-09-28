// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/misscomputer/misscomputer-subnet/pkg/durable"
	"github.com/misscomputer/misscomputer-subnet/pkg/miner"
	"github.com/misscomputer/misscomputer-subnet/pkg/neuron"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	deployruntime "github.com/misscomputer/misscomputer-subnet/pkg/runtime"
)

func TestAssignmentErrorMappingIsStable(t *testing.T) {
	tests := []struct {
		message   string
		status    int
		code      string
		retryable bool
	}{
		{"replayed assignment nonce", http.StatusConflict, "replayed_assignment", false},
		{"ticket is expired", http.StatusGone, "expired_assignment", false},
		{"invalid ticket signature", http.StatusForbidden, "identity_mismatch", false},
		{"ticket miner service key does not match this agent", http.StatusForbidden, "identity_mismatch", false},
		{"ticket miner transport or certificate pin does not match this agent", http.StatusForbidden, "identity_mismatch", false},
		{"artifact digest mismatch", http.StatusUnprocessableEntity, "assignment_failed", false},
	}
	for _, test := range tests {
		status, code, retryable := assignmentError(errors.New(test.message))
		if status != test.status || code != test.code || retryable != test.retryable {
			t.Fatalf("mapping %q = (%d,%q,%v)", test.message, status, code, retryable)
		}
	}
}

func TestCapabilitiesExposeExactConfiguredTransportIdentity(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name      string
		transport string
		pin       string
		organic   bool
	}{
		{name: "https", transport: neuron.TransportHTTPS, pin: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{name: "https organic runtime", transport: neuron.TransportHTTPS, pin: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", organic: true},
		{name: "mock http", transport: neuron.TransportHTTP},
	} {
		t.Run(test.name, func(t *testing.T) {
			agent := miner.NewAgent("miner", nil, privateKey, nil, nil, nil)
			agent.MinerTransport = test.transport
			agent.MinerTLSCertificateSHA256 = test.pin
			if test.organic {
				agent.OCI = unusedOCIRuntime{}
			}
			service := &api{agent: agent, network: "local", netuid: 24, hotkey: "miner", public: publicKey}
			response := httptest.NewRecorder()
			service.capabilities(response, httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil))
			if response.Code != http.StatusOK {
				t.Fatalf("capabilities returned %d", response.Code)
			}
			var capabilities neuron.LocalCapabilities
			if err := json.Unmarshal(response.Body.Bytes(), &capabilities); err != nil {
				t.Fatal(err)
			}
			if capabilities.Transport != test.transport || optionalString(capabilities.TransportCertificateSHA256) != test.pin ||
				(test.pin == "") != (capabilities.TransportCertificateSHA256 == nil) {
				t.Fatalf("capabilities transport identity = %#v", capabilities)
			}
			organic := false
			for _, feature := range capabilities.Features {
				organic = organic || feature == neuron.FeatureOrganicOCIV1
			}
			// Validators treat a missing organic-oci-v1 as ineligible, so it is
			// advertised exactly when an OCI runtime passed startup checks.
			if organic != test.organic {
				t.Fatalf("organic-oci-v1 advertised=%t with organic runtime=%t", organic, test.organic)
			}
		})
	}
}

func TestStatusAndDeactivateRejectTicketWithoutTransportPin(t *testing.T) {
	store, err := durable.Open(t.TempDir() + "/state.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	legacy := protocol.Ticket{
		Version: protocol.OrganicVersion, DeploymentID: "legacy", MinerID: "miner", Generation: 1, AssignmentNonce: "legacy-nonce",
		Subnet: &protocol.SubnetBinding{ValidatorHotkey: "validator"},
	}
	if err := store.SaveAssignment(context.Background(), legacy, "ready"); err != nil {
		t.Fatal(err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	agent := miner.NewAgent("miner", nil, privateKey, nil, nil, nil)
	agent.MinerTransport = neuron.TransportHTTPS
	agent.MinerTLSCertificateSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	service := &api{agent: agent, store: store}
	endpointID := protocol.EndpointID(legacy)
	tests := []struct {
		name    string
		payload any
		handle  func(http.ResponseWriter, *http.Request)
	}{
		{
			name: "status", payload: neuron.StatusSynapse{Protocol: neuron.SynapseVersion, RequestID: "status", CallerHotkey: "validator", EndpointID: endpointID},
			handle: service.status,
		},
		{
			name: "deactivate", payload: neuron.DeactivateSynapse{Protocol: neuron.SynapseVersion, RequestID: "deactivate", CallerHotkey: "validator", EndpointID: endpointID, DeploymentID: legacy.DeploymentID},
			handle: service.deactivate,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload, err := json.Marshal(test.payload)
			if err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			test.handle(response, httptest.NewRequest(http.MethodPost, "/v1/"+test.name, bytes.NewReader(payload)))
			if response.Code != http.StatusForbidden {
				t.Fatalf("unpinned %s ticket returned %d body=%s", test.name, response.Code, response.Body.String())
			}
		})
	}
}

func TestDecodeJSONRejectsUnknownAndTrailingValues(t *testing.T) {
	type request struct {
		Value string `json:"value"`
	}
	for _, payload := range []string{
		`{"value":"ok","unknown":true}`,
		`{"value":"ok"} {"value":"second"}`,
	} {
		var value request
		if err := decodeJSON(strings.NewReader(payload), &value); err == nil {
			t.Fatalf("invalid JSON contract accepted: %s", payload)
		}
	}
}

type unusedOCIRuntime struct{}

func (unusedOCIRuntime) Launch(context.Context, deployruntime.Launch) (deployruntime.Started, error) {
	return deployruntime.Started{}, errors.New("unused")
}
func (unusedOCIRuntime) Running(context.Context, string) (bool, error) { return false, nil }
func (unusedOCIRuntime) Stop(context.Context, string) error            { return nil }

// The production bridge accepts only subnet-synapse.v3 with deployment.v4.
// Retired synthetic envelopes cannot reach identity or runtime work.
func TestAssignEnvelopesRefuseTheOtherTicketVersion(t *testing.T) {
	raw, err := os.ReadFile("../../contracts/fixtures/deploy.v3.json")
	if err != nil {
		t.Fatal(err)
	}
	request := func(protocolVersion string, mutate func(ticket map[string]any)) []byte {
		var document map[string]any
		if err := json.Unmarshal(raw, &document); err != nil {
			t.Fatal(err)
		}
		document["protocol"] = protocolVersion
		document["binding_verified"] = true
		mutate(document["ticket"].(map[string]any))
		encoded, _ := json.Marshal(document)
		return encoded
	}
	organicRequest := func(mutate func(ticket map[string]any)) []byte { return request(neuron.OrganicSynapseVersion, mutate) }
	var golden neuron.DeploySynapseV3
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatal(err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	service := &api{agent: miner.NewAgent(golden.Ticket.MinerID, nil, privateKey, nil, nil, nil)}
	for name, test := range map[string]struct {
		body []byte
		code string
	}{
		"v3 envelope with deployment.v3 ticket": {organicRequest(func(ticket map[string]any) { ticket["version"] = "deployment.v3" }), "invalid_request"},
		"v3 envelope with deployment.v1 ticket": {organicRequest(func(ticket map[string]any) { ticket["version"] = "deployment.v1" }), "invalid_request"},
		"v3 envelope with challenge fields":     {organicRequest(func(ticket map[string]any) { ticket["challenge_path"] = "/__challenge/x" }), "invalid_request"},
		"v2 envelope with deployment.v4 ticket": {request(neuron.SynapseVersion, func(map[string]any) {}), "version_mismatch"},
		"v2 envelope with deployment.v3 ticket": {request(neuron.SynapseVersion, func(ticket map[string]any) { ticket["version"] = "deployment.v3" }), "version_mismatch"},
	} {
		t.Run(name, func(t *testing.T) {
			response := httptest.NewRecorder()
			service.assign(response, httptest.NewRequest(http.MethodPost, "/v1/assignments", bytes.NewReader(test.body)))
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"`+test.code+`"`) {
				t.Fatalf("assign returned %d body=%s, want %s", response.Code, response.Body.String(), test.code)
			}
		})
	}
}

// TestBridgeHandlerForwardsRuntimePathsWithoutServeMuxCleaning guards the
// production wiring: ServeMux would 301-redirect "//" or "/./" application
// paths, so runtime requests must bypass it and arrive byte-exact.
func TestBridgeHandlerForwardsRuntimePathsWithoutServeMuxCleaning(t *testing.T) {
	var runtimeURI, muxURI string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		muxURI = req.RequestURI
		w.WriteHeader(http.StatusNoContent)
	})
	handler := bridgeHandler(mux, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		runtimeURI = req.RequestURI
		w.WriteHeader(http.StatusNoContent)
	}))
	server := httptest.NewServer(handler)
	defer server.Close()
	for _, target := range []string{"/v1/runtime/ep-1/a//b/./c/../d?x=1;y=%zz", "/v1/capabilities"} {
		response, err := server.Client().Get(server.URL + target)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("%s returned %d", target, response.StatusCode)
		}
	}
	if runtimeURI != "/v1/runtime/ep-1/a//b/./c/../d?x=1;y=%zz" || muxURI != "/v1/capabilities" {
		t.Fatalf("runtime=%q mux=%q", runtimeURI, muxURI)
	}
}
