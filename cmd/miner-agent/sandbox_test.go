// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/durable"
	"github.com/misscomputer/misscomputer-subnet/pkg/miner"
	"github.com/misscomputer/misscomputer-subnet/pkg/neuron"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	"github.com/misscomputer/misscomputer-subnet/pkg/sandbox"
)

var sandboxPaths = []string{"/v1/sandbox/reservations", "/v1/sandbox/leases", "/v1/sandbox/renewals", "/v1/sandbox/releases"}

func serve(handler http.Handler, method, path string, body []byte) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(method, path, bytes.NewReader(body)))
	return response
}

func advertised(t *testing.T, service *api) []string {
	t.Helper()
	var capabilities neuron.LocalCapabilities
	response := serve(service.routes(), http.MethodGet, "/v1/capabilities", nil)
	if err := json.Unmarshal(response.Body.Bytes(), &capabilities); err != nil {
		t.Fatal(err)
	}
	return capabilities.Features
}

// With the lane off (the default) the miner serves exactly the routes and
// advertises exactly the features it did before the lane existed, and "on"
// refuses to start because no isolation backend is available.
func TestSandboxLeasesOffKeepsRoutesAndFeaturesUnchanged(t *testing.T) {
	if lane, err := openSandboxLeases("off"); lane != nil || err != nil {
		t.Fatalf("default sandbox mode: %v %v", lane, err)
	}
	for _, mode := range []string{"on", "true", ""} {
		if lane, err := openSandboxLeases(mode); lane != nil || err == nil {
			t.Fatalf("--sandbox-leases %q started: %v %v", mode, lane, err)
		}
	}
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)
	for _, test := range []struct {
		name     string
		organic  bool
		features []string
	}{
		{name: "web only", features: []string{"deploy", "status", "deactivate", "runtime-proxy"}},
		{name: "organic", organic: true, features: []string{"deploy", "status", "deactivate", "runtime-proxy", neuron.FeatureOrganicOCIV1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			agent := miner.NewAgent("miner", nil, privateKey, nil, nil, nil)
			agent.MinerTransport = neuron.TransportHTTP
			if test.organic {
				agent.OCI = unusedOCIRuntime{}
			}
			service := &api{agent: agent, network: "mock", netuid: 24, hotkey: "miner", public: publicKey}
			if got := advertised(t, service); !slices.Equal(got, test.features) {
				t.Fatalf("features = %v, want %v", got, test.features)
			}
			for _, path := range sandboxPaths {
				if response := serve(service.routes(), http.MethodPost, path, []byte(`{}`)); response.Code != http.StatusNotFound {
					t.Fatalf("POST %s answered %d with the lane off", path, response.Code)
				}
			}
		})
	}
}

// sandboxBackend is an in-memory isolation backend for bridge tests.
type sandboxBackend struct{ live map[string]bool }

func (b *sandboxBackend) Budget(context.Context) (miner.SandboxBudget, error) {
	return miner.SandboxBudget{Cgroup: "/mc-sandboxes", DiskMiB: 40960, Sandboxes: 4}, nil
}
func (b *sandboxBackend) Unsupported(protocol.SandboxLeaseV1) string { return "" }
func (b *sandboxBackend) Create(_ context.Context, instance string, _ protocol.SandboxLeaseV1) error {
	b.live[instance] = true
	return nil
}
func (b *sandboxBackend) Destroy(_ context.Context, instance string) error {
	delete(b.live, instance)
	return nil
}

// With an enabled lane the bridge accepts validator-signed sandbox
// documents in the subnet-sandbox-synapse.v1 envelope and answers signed
// receipts; unverified bindings, wrong envelopes and equivocation are
// bridge errors without a receipt.
func TestSandboxRoutesAnswerSignedReceiptsThroughTheBridge(t *testing.T) {
	const (
		validatorHotkey = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
		minerHotkey     = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
	)
	ctx := context.Background()
	validatorPublic, validatorPrivate, _ := ed25519.GenerateKey(nil)
	minerPublic, minerPrivate, _ := ed25519.GenerateKey(nil)
	root := t.TempDir()
	dir := filepath.Join(root, "mc-sandboxes")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cpu.max"), []byte("400000 100000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "memory.max"), []byte(fmt.Sprint(8<<30)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	state, err := durable.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	leases, err := state.EnableSandboxLeases(ctx)
	if err != nil {
		t.Fatal(err)
	}
	agent := miner.NewAgent(minerHotkey, nil, minerPrivate, nil, nil, nil)
	agent.MinerTransport = neuron.TransportHTTP
	backend := &sandboxBackend{live: map[string]bool{}}
	lane, err := miner.NewSandboxLane(ctx, agent, leases, backend, miner.SandboxLaneConfig{
		Budget: sandbox.Capacity{CPUMillis: 4000, MemoryMiB: 8192, DiskMiB: 40960, Sandboxes: 4}, CgroupRoot: root,
	})
	if err != nil {
		t.Fatal(err)
	}
	service := &api{agent: agent, store: state, network: "mock", netuid: 24, hotkey: minerHotkey, public: minerPublic, sandbox: lane}
	if !slices.Contains(advertised(t, service), sandbox.CapabilityFeature) {
		t.Fatal("enabled lane does not advertise sandbox-lease-v1")
	}

	now := time.Now().UTC()
	binding := &protocol.StaticSubnetBindingV1{
		Network: "mock", NetUID: 24, ValidatorHotkey: validatorHotkey, MinerHotkey: minerHotkey,
		MinerAxonURL: "http://127.0.0.1:8091", MinerTransport: neuron.TransportHTTP, ChainBlock: 100, Epoch: 1, ExpiresAtBlock: 112,
		ValidatorServicePublicKey: hex.EncodeToString(validatorPublic), MinerServicePublicKey: hex.EncodeToString(minerPublic),
	}
	reservation := func(nonce string) protocol.SandboxReservationV1 {
		r := protocol.SandboxReservationV1{
			Generation: 1, HoldExpiresAt: *protocol.StaticTime(now.Add(time.Minute)), IssuedAt: *protocol.StaticTime(now), MinerID: minerHotkey,
			ReservationNonce: nonce, Resources: sandbox.Resources{CPUMillis: 1000, MemoryMiB: 2048, DiskMiB: 10240, PIDs: 512},
			SandboxID: "sbx-" + strings.Repeat("0", 31) + "1", Schema: protocol.SandboxReservationSchema, SchemaVersion: 1,
			Subnet: binding, WorkloadKind: sandbox.WorkloadKind,
		}
		if err := protocol.SignSandboxReservationV1(&r, validatorPrivate); err != nil {
			t.Fatal(err)
		}
		return r
	}
	envelope := func(document any, mutate func(*sandboxRequest[any])) []byte {
		request := sandboxRequest[any]{
			Protocol: sandboxSynapseVersion, RequestID: "req-1", CurrentBlock: 101, CallerHotkey: validatorHotkey, BindingVerified: true,
			ValidatorBinding: neuron.ServiceKeyBinding{
				Protocol: neuron.ServiceBindingVersion, Role: "validator", Network: "mock", NetUID: 24, Hotkey: validatorHotkey,
				ServicePublicKey: hex.EncodeToString(validatorPublic), Transport: neuron.TransportLocal, Generation: 1,
				ValidFromBlock: 100, ExpiresAtBlock: 200,
			},
			Document: document,
		}
		if mutate != nil {
			mutate(&request)
		}
		body, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	held := reservation(strings.Repeat("a1", 16))
	response := serve(service.routes(), http.MethodPost, "/v1/sandbox/reservations", envelope(held, nil))
	var answer sandboxResponse
	if err := decodeJSON(bytes.NewReader(response.Body.Bytes()), &answer); err != nil {
		t.Fatalf("reservation response %d: %v %s", response.Code, err, response.Body.String())
	}
	digest, _ := protocol.SandboxDigestV1(held)
	if err := protocol.VerifySandboxReceiptV1(answer.Receipt, minerPublic); err != nil {
		t.Fatal(err)
	}
	if answer.Receipt.Stage != sandbox.StageHeld || answer.RequestID != "req-1" ||
		protocol.SandboxReceiptAnswersV1(answer.Receipt, protocol.SandboxReservationSchema, digest, held.SandboxID, minerHotkey, 1, binding) != nil {
		t.Fatalf("reservation receipt %+v", answer.Receipt)
	}

	for _, test := range []struct {
		name   string
		body   []byte
		status int
		code   string
	}{
		{name: "equivocating reservation", body: envelope(reservation(strings.Repeat("b2", 16)), nil), status: http.StatusConflict, code: "sandbox_conflict"},
		{name: "binding not verified", body: envelope(held, func(r *sandboxRequest[any]) { r.BindingVerified = false }), status: http.StatusForbidden, code: "binding_unverified"},
		{name: "another envelope", body: envelope(held, func(r *sandboxRequest[any]) { r.Protocol = neuron.StaticSynapseVersion }), status: http.StatusBadRequest, code: "version_mismatch"},
		{name: "binding of another caller", body: envelope(held, func(r *sandboxRequest[any]) { r.CallerHotkey = minerHotkey }), status: http.StatusForbidden, code: "identity_mismatch"},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := serve(service.routes(), http.MethodPost, "/v1/sandbox/reservations", test.body)
			if response.Code != test.status || !strings.Contains(response.Body.String(), `"`+test.code+`"`) {
				t.Fatalf("status %d body %s, want %d %s", response.Code, response.Body.String(), test.status, test.code)
			}
		})
	}
	if len(backend.live) != 0 {
		t.Fatalf("reservations started %d sandboxes", len(backend.live))
	}
}
