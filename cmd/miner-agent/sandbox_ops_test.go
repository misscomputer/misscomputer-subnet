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
	"github.com/misscomputer/misscomputer-subnet/pkg/sandboxops"
)

// opsSandboxBackend answers every helper call with a directory stat.
type opsSandboxBackend struct{ sandboxBackend }

func (b *opsSandboxBackend) RunHelper(context.Context, string, []byte) ([]byte, error) {
	return sandboxops.Encode(sandboxops.Response{Protocol: sandboxops.Protocol, File: &sandbox.FileInfo{Mode: 0o755, Size: 4096, Type: sandbox.FileTypeDirectory}})
}

// --sandbox-ops is off by default and on only together with the lease lane
// and an explicit configuration naming every unadopted parameter.
func TestSandboxOpsFlagsRefuseIncompleteConfiguration(t *testing.T) {
	if settings, err := loadSandboxOps("off", "", "off"); settings != nil || err != nil {
		t.Fatalf("default ops mode: %v %v", settings, err)
	}
	config := filepath.Join(t.TempDir(), "ops.json")
	if err := os.WriteFile(config, []byte(`{"helper_dir":"/opt/mc/ops-helper","helper_sha256":"`+strings.Repeat("a", 64)+`","start_resolution_ms":10000,"state_timeout_ms":5000,"kill_grace_ms":1000,"max_in_flight":64,"max_in_flight_bytes":33554432,"max_outcomes":1024}`), 0o600); err != nil {
		t.Fatal(err)
	}
	unknown := filepath.Join(t.TempDir(), "unknown.json")
	if err := os.WriteFile(unknown, []byte(`{"helper_dir":"/x","n_ops":64}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ mode, path, leases string }{
		{"off", config, "on"}, {"on", config, "off"}, {"on", "", "on"}, {"maybe", config, "on"}, {"on", unknown, "on"},
	} {
		if _, err := loadSandboxOps(tc.mode, tc.path, tc.leases); err == nil {
			t.Errorf("accepted --sandbox-ops %s config=%q leases=%s", tc.mode, tc.path, tc.leases)
		}
	}
	settings, err := loadSandboxOps("on", config, "on")
	if err != nil || settings.helper.Dir != "/opt/mc/ops-helper" || settings.config.StartResolution != 10*time.Second || settings.config.MaxOutcomes != 1024 {
		t.Fatalf("loaded %+v %v", settings, err)
	}
}

// The ops route and the sandbox-ops-v1 feature exist only once ops are
// enabled; then a validator-signed op travels the bridge envelope and is
// answered with a receipt the validator can verify.
func TestSandboxOpsRouteAnswersVerifiableReceipts(t *testing.T) {
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
	for name, value := range map[string]string{"cpu.max": "400000 100000\n", "memory.max": fmt.Sprint(8<<30) + "\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0o644); err != nil {
			t.Fatal(err)
		}
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
	lane, err := miner.NewSandboxLane(ctx, agent, leases, &opsSandboxBackend{sandboxBackend{live: map[string]bool{}}}, miner.SandboxLaneConfig{
		Budget: sandbox.Capacity{CPUMillis: 4000, MemoryMiB: 8192, DiskMiB: 40960, Sandboxes: 4}, CgroupRoot: root,
		AgentCgroup: "/system.slice/miner-agent.service", DeploymentCgroup: "/system.slice/deployment-v4.slice",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer lane.Close(ctx)
	service := &api{agent: agent, store: state, network: "mock", netuid: 24, hotkey: minerHotkey, public: minerPublic, sandbox: lane}
	if slices.Contains(advertised(t, service), sandbox.OpsCapabilityFeature) {
		t.Fatal("sandbox-ops-v1 advertised without ops")
	}
	if response := serve(service.routes(), http.MethodPost, "/v1/sandbox/ops", []byte(`{}`)); response.Code != http.StatusNotFound {
		t.Fatalf("ops route answered %d without ops", response.Code)
	}

	now := time.Now().UTC()
	binding := &protocol.StaticSubnetBindingV1{
		Network: "mock", NetUID: 24, ValidatorHotkey: validatorHotkey, MinerHotkey: minerHotkey,
		MinerAxonURL: "http://127.0.0.1:8091", MinerTransport: neuron.TransportHTTP, ChainBlock: 100, Epoch: 1, ExpiresAtBlock: 112,
		ValidatorServicePublicKey: hex.EncodeToString(validatorPublic), MinerServicePublicKey: hex.EncodeToString(minerPublic),
	}
	request := miner.SandboxRequest{ValidatorKey: validatorPublic, CurrentBlock: 101, Network: "mock", NetUID: 24, CallerHotkey: validatorHotkey, MinerHotkey: minerHotkey}
	reservation := protocol.SandboxReservationV1{
		Generation: 1, HoldExpiresAt: *protocol.StaticTime(now.Add(time.Minute)), IssuedAt: *protocol.StaticTime(now), MinerID: minerHotkey,
		ReservationNonce: strings.Repeat("a1", 16), Resources: sandbox.Resources{CPUMillis: 1000, MemoryMiB: 2048, DiskMiB: 10240, PIDs: 512},
		SandboxID: "sbx-" + strings.Repeat("0", 31) + "1", Schema: protocol.SandboxReservationSchema, SchemaVersion: 1, Subnet: binding, WorkloadKind: sandbox.WorkloadKind,
	}
	if err := protocol.SignSandboxReservationV1(&reservation, validatorPrivate); err != nil {
		t.Fatal(err)
	}
	if _, err := lane.Reserve(ctx, reservation, request); err != nil {
		t.Fatal(err)
	}
	digest, _ := protocol.SandboxDigestV1(reservation)
	image := "sha256:" + strings.Repeat("c4", 32)
	lease := protocol.SandboxLeaseV1{
		AssignmentNonce: strings.Repeat("c3", 16), Env: map[string]string{}, Generation: 1, ImageDigest: image,
		ImageReference: "docker.io/library/python@" + image, Isolation: sandbox.IsolationGVisor, IssuedAt: *protocol.StaticTime(now),
		LeaseExpiresAt: *protocol.StaticTime(now.Add(10 * time.Minute)), MinerID: minerHotkey,
		Network:           sandbox.NetworkPolicy{Mode: sandbox.NetworkNone, Allow: []string{}},
		ReservationDigest: digest, Resources: reservation.Resources, SandboxID: reservation.SandboxID, Schema: protocol.SandboxLeaseSchema, SchemaVersion: 1,
		SecretEnv: sandbox.SecretEnv{Delivery: sandbox.SecretDeliveryNone, Names: []string{}}, Subnet: binding, WorkloadKind: sandbox.WorkloadKind,
	}
	if err := protocol.SignSandboxLeaseV1(&lease, validatorPrivate); err != nil {
		t.Fatal(err)
	}
	if receipt, err := lane.Commit(ctx, lease, request); err != nil || receipt.Stage != sandbox.StageReady {
		t.Fatalf("commit: %+v %v", receipt.Stage, err)
	}
	if err := enableSandboxOps(ctx, lane, state, &sandboxOpsSettings{config: miner.SandboxOpsConfig{
		StartResolution: time.Second, StateTimeout: time.Second, KillGrace: time.Second, MaxInFlight: 4, MaxInFlightBytes: 4 << 20, MaxOutcomes: 4,
	}}); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(advertised(t, service), sandbox.OpsCapabilityFeature) {
		t.Fatal("enabled ops do not advertise sandbox-ops-v1")
	}

	leaseDigest, _ := protocol.SandboxDigestV1(lease)
	path := "/work"
	op := protocol.SandboxOpRequestV1{
		ExpiresAt: *protocol.StaticTime(now.Add(time.Minute)), Generation: 1, IssuedAt: *protocol.StaticTime(now), LeaseDigest: leaseDigest,
		LeaseID: protocol.SandboxLeaseIDV1(lease), MinerID: minerHotkey, Op: sandbox.OpFileStat, OpNonce: strings.Repeat("e5", 16), Path: &path,
		SandboxID: lease.SandboxID, Schema: protocol.SandboxOpRequestSchema, SchemaVersion: 1, Subnet: binding, WorkloadKind: sandbox.WorkloadKind,
	}
	if err := protocol.SignSandboxOpRequestV1(&op, validatorPrivate); err != nil {
		t.Fatal(err)
	}
	envelope := func(mutate func(*sandboxOpsRequest)) []byte {
		input := sandboxOpsRequest{
			Protocol: sandboxOpsSynapseVersion, RequestID: "op-1", CurrentBlock: 101, CallerHotkey: validatorHotkey, BindingVerified: true,
			ValidatorBinding: neuron.ServiceKeyBinding{
				Protocol: neuron.ServiceBindingVersion, Role: "validator", Network: "mock", NetUID: 24, Hotkey: validatorHotkey,
				ServicePublicKey: hex.EncodeToString(validatorPublic), Transport: neuron.TransportLocal, Generation: 1,
				ValidFromBlock: 100, ExpiresAtBlock: 200,
			},
			Document: op,
		}
		if mutate != nil {
			mutate(&input)
		}
		body, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	response := serve(service.routes(), http.MethodPost, "/v1/sandbox/ops", envelope(nil))
	var answer sandboxOpsResponse
	if err := decodeJSON(bytes.NewReader(response.Body.Bytes()), &answer); err != nil {
		t.Fatalf("op response %d: %v %s", response.Code, err, response.Body.String())
	}
	if err := protocol.VerifySandboxOpReceiptV1(answer.Receipt, minerPublic); err != nil {
		t.Fatal(err)
	}
	if err := protocol.SandboxOpReceiptAnswersV1(answer.Receipt, op, nil); err != nil || answer.Receipt.Stage != sandbox.OpStageCompleted ||
		answer.Result != nil || answer.RequestID != "op-1" {
		t.Fatalf("op receipt %+v (%v)", answer, err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*sandboxOpsRequest)
		status int
		code   string
	}{
		{"lease envelope", func(r *sandboxOpsRequest) { r.Protocol = sandboxSynapseVersion }, http.StatusBadRequest, "version_mismatch"},
		{"unverified binding", func(r *sandboxOpsRequest) { r.BindingVerified = false }, http.StatusForbidden, "binding_unverified"},
		{"unexpected payload", func(r *sandboxOpsRequest) { r.Payload = sandboxops.EncodeData([]byte("x")) }, http.StatusBadRequest, "sandbox_op_payload_mismatch"},
		{"non-canonical payload", func(r *sandboxOpsRequest) { bad := "eA"; r.Payload = &bad }, http.StatusBadRequest, "invalid_request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := serve(service.routes(), http.MethodPost, "/v1/sandbox/ops", envelope(tc.mutate))
			if response.Code != tc.status || !strings.Contains(response.Body.String(), `"`+tc.code+`"`) {
				t.Fatalf("status %d body %s, want %d %s", response.Code, response.Body.String(), tc.status, tc.code)
			}
		})
	}
	if err := lane.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if response := serve(service.routes(), http.MethodPost, "/v1/sandbox/ops", envelope(nil)); response.Code != http.StatusServiceUnavailable ||
		!strings.Contains(response.Body.String(), `"sandbox_lane_closed"`) {
		t.Fatalf("op after Close: %d %s", response.Code, response.Body.String())
	}
}
