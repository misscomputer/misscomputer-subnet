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
	"strings"
	"testing"

	"github.com/misscomputer/misscomputer-subnet/pkg/durable"
	"github.com/misscomputer/misscomputer-subnet/pkg/miner"
	"github.com/misscomputer/misscomputer-subnet/pkg/neuron"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
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
	}{
		{name: "https", transport: neuron.TransportHTTPS, pin: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{name: "mock http", transport: neuron.TransportHTTP},
	} {
		t.Run(test.name, func(t *testing.T) {
			agent := miner.NewAgent("miner", nil, privateKey, nil, nil, nil)
			agent.MinerTransport = test.transport
			agent.MinerTLSCertificateSHA256 = test.pin
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
			attested := false
			for _, feature := range capabilities.Features {
				attested = attested || feature == neuron.FeatureProbeAttestationV1
			}
			if !attested {
				t.Fatalf("capabilities do not advertise mandatory %s: %v", neuron.FeatureProbeAttestationV1, capabilities.Features)
			}
		})
	}
}

func TestStatusAndDeactivateRejectLegacyTicketWithoutTransportPin(t *testing.T) {
	store, err := durable.Open(t.TempDir() + "/state.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	legacy := protocol.Ticket{
		Version: "deployment.v2", DeploymentID: "legacy", MinerID: "miner", Generation: 1, AssignmentNonce: "legacy-nonce",
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
				t.Fatalf("legacy %s ticket returned %d body=%s", test.name, response.Code, response.Body.String())
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

func TestDeployResponsePromotesCachedReplayMetadata(t *testing.T) {
	response := deployResponse("replayed-request", miner.Result{Idempotent: true})
	if !response.Idempotent {
		t.Fatal("cached result was not reported as idempotent")
	}
	payload, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["idempotent"] != true {
		t.Fatalf("top-level idempotent field = %#v", decoded["idempotent"])
	}
	result, ok := decoded["result"].(map[string]any)
	if !ok {
		t.Fatalf("result shape = %#v", decoded["result"])
	}
	if _, leaked := result["idempotent"]; leaked {
		t.Fatal("internal idempotency metadata leaked into MinerResult")
	}
}
