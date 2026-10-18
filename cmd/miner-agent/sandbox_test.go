// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/bridge"
	"github.com/misscomputer/misscomputer-subnet/pkg/durable"
	"github.com/misscomputer/misscomputer-subnet/pkg/miner"
	"github.com/misscomputer/misscomputer-subnet/pkg/neuron"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	"github.com/misscomputer/misscomputer-subnet/pkg/sandbox"
)

var sandboxPaths = []string{"/v1/sandbox/reservations/replay", "/v1/sandbox/reservations", "/v1/sandbox/leases", "/v1/sandbox/renewals", "/v1/sandbox/releases"}

func serve(handler http.Handler, method, path string, body []byte) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(method, path, bytes.NewReader(body)))
	return response
}

// TestSandboxReplayProcessFixture is the Go side of the Python subprocess
// contract test. Only the isolation backend/cgroup are fixtures: HTTP routes,
// HMAC/nonces, binding high-water, signed admission, SQLite and receipts are
// the real owners. No fixture endpoint exists in the production binary.
func TestSandboxReplayProcessFixture(t *testing.T) {
	root := os.Getenv("MC_REPLAY_FIXTURE_DIR")
	if root == "" {
		t.Skip("launched only by the authenticated Python boundary test")
	}
	ctx := context.Background()
	validatorKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, 32))
	minerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, 32))
	const minerHotkey = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
	store, err := durable.Open(filepath.Join(root, "agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	leaselane, err := store.EnableSandboxLeases(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cgroup := filepath.Join(root, "cgroup", "mc-sandboxes")
	if err := os.MkdirAll(cgroup, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"cpu.max": "400000 100000\n", "memory.max": "8589934592\n"} {
		if err := os.WriteFile(filepath.Join(cgroup, name), []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	agent := miner.NewAgent(minerHotkey, nil, minerKey, nil, nil, nil)
	agent.MinerTransport = neuron.TransportHTTP
	backend := &sandboxBackend{live: map[string]bool{}}
	lane, err := miner.NewSandboxLane(ctx, agent, leaselane, backend, miner.SandboxLaneConfig{
		Budget:     sandbox.Capacity{CPUMillis: 4000, MemoryMiB: 8192, DiskMiB: 40960, Sandboxes: 4},
		CgroupRoot: filepath.Join(root, "cgroup"), AgentCgroup: "/agent", DeploymentCgroup: "/deployments",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer lane.Close(ctx)
	uid := uint16(1)
	service := &api{agent: agent, store: store, network: "local", netuid: 24, hotkey: minerHotkey, uid: &uid,
		public: minerKey.Public().(ed25519.PublicKey), sandbox: lane, sandboxReservationReplay: true}
	auth := bridge.Authenticator{Secret: []byte("sandbox-replay-local-test-secret-32"), Store: store}
	server := httptest.NewServer(auth.Middleware(service.routes()))
	defer server.Close()
	encoder := json.NewEncoder(os.Stdout)
	if err := encoder.Encode(map[string]string{"url": server.URL, "miner_key": hex.EncodeToString(service.public), "validator_key": hex.EncodeToString(validatorKey.Public().(ed25519.PublicKey))}); err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		var command struct {
			Operation   string                        `json:"operation"`
			Reservation protocol.SandboxReservationV1 `json:"reservation"`
			Receipt     protocol.SandboxReceiptV1     `json:"receipt"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &command); err != nil {
			t.Fatal(err)
		}
		switch command.Operation {
		case "sign":
			if err := protocol.SignSandboxReservationV1(&command.Reservation, validatorKey); err != nil {
				t.Fatal(err)
			}
			if err := encoder.Encode(command.Reservation); err != nil {
				t.Fatal(err)
			}
		case "verify":
			if err := protocol.VerifySandboxReceiptV1(command.Receipt, service.public); err != nil {
				t.Fatal(err)
			}
			if err := protocol.SandboxReceiptAnswersV1(command.Receipt, command.Reservation); err != nil {
				t.Fatal(err)
			}
			if err := encoder.Encode(map[string]bool{"verified": true}); err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatal("unknown fixture operation")
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(backend.live) != 0 {
		t.Fatal("read-only test created a backend instance")
	}
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
	if lane, err := openSandboxLeases(context.Background(), sandboxOptions{Mode: "off"}, nil, nil); lane != nil || err != nil {
		t.Fatalf("default sandbox mode: %v %v", lane, err)
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
type sandboxBackend struct {
	live       map[string]bool
	destroyErr error
}

func (b *sandboxBackend) Budget(context.Context) (miner.SandboxBudget, error) {
	return miner.SandboxBudget{Cgroup: "/mc-sandboxes", DiskMiB: 40960, Sandboxes: 4}, nil
}
func (b *sandboxBackend) Unsupported(protocol.SandboxLeaseV1) string { return "" }
func (b *sandboxBackend) Create(_ context.Context, instance string, _ protocol.SandboxLeaseV1) error {
	b.live[instance] = true
	return nil
}
func (b *sandboxBackend) Destroy(_ context.Context, instance string) error {
	if b.destroyErr != nil {
		return b.destroyErr
	}
	delete(b.live, instance)
	return nil
}
func (b *sandboxBackend) Instances(context.Context) ([]miner.SandboxInstance, error) { return nil, nil }
func (b *sandboxBackend) Reclaim(context.Context) error                              { return nil }

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
		AgentCgroup: "/system.slice/miner-agent.service", DeploymentCgroup: "/system.slice/deployment-v4.slice",
	})
	if err != nil {
		t.Fatal(err)
	}
	service := &api{agent: agent, store: state, network: "mock", netuid: 24, hotkey: minerHotkey, public: minerPublic, sandbox: lane, sandboxReservationReplay: true}
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
	replayPath := "/v1/sandbox/reservations/replay"
	assertReplayError := func(r protocol.SandboxReservationV1, status int, code string) {
		t.Helper()
		response := serve(service.routes(), http.MethodPost, replayPath, envelope(r, nil))
		if response.Code != status || !strings.Contains(response.Body.String(), `"`+code+`"`) {
			t.Fatalf("replay: %d %s, want %d %s", response.Code, response.Body.String(), status, code)
		}
	}
	// A missing hold cannot be fabricated by the replay route.
	assertReplayError(held, http.StatusNotFound, "sandbox_replay_hold_absent")
	used, active, err := leases.Occupancy(ctx, now)
	if err != nil || used.Sandboxes != 0 || active.Sandboxes != 0 || len(backend.live) != 0 {
		t.Fatalf("absent replay acquired capacity/backend: %+v %+v %v", used, active, err)
	}
	// Having the lease lane alone is insufficient: replay remains default off.
	service.sandboxReservationReplay = false
	if slices.Contains(advertised(t, service), sandbox.ReservationReplayFeature) {
		t.Fatal("disabled replay advertised")
	}
	if got := serve(service.routes(), http.MethodPost, replayPath, envelope(held, nil)); got.Code != http.StatusNotFound {
		t.Fatalf("disabled replay returned %d", got.Code)
	}
	service.sandboxReservationReplay = true
	if !slices.Contains(advertised(t, service), sandbox.ReservationReplayFeature) {
		t.Fatal("enabled replay not advertised")
	}
	response := serve(service.routes(), http.MethodPost, "/v1/sandbox/reservations", envelope(held, nil))
	var answer sandboxResponse
	if err := decodeJSON(bytes.NewReader(response.Body.Bytes()), &answer); err != nil {
		t.Fatalf("reservation response %d: %v %s", response.Code, err, response.Body.String())
	}
	if err := protocol.VerifySandboxReceiptV1(answer.Receipt, minerPublic); err != nil {
		t.Fatal(err)
	}
	if answer.Receipt.Stage != sandbox.StageHeld || answer.RequestID != "req-1" ||
		protocol.SandboxReceiptAnswersV1(answer.Receipt, held) != nil {
		t.Fatalf("reservation receipt %+v", answer.Receipt)
	}

	// Existing-only replay is an independent contract: the exact signed hold
	// must be observable without ordinary Reserve or backend work.
	replayed := serve(service.routes(), http.MethodPost, "/v1/sandbox/reservations/replay", envelope(held, nil))
	if replayed.Code != http.StatusOK {
		t.Fatalf("existing-hold replay contract: status %d body %s", replayed.Code, replayed.Body.String())
	}
	var replayAnswer sandboxResponse
	if err := decodeJSON(bytes.NewReader(replayed.Body.Bytes()), &replayAnswer); err != nil {
		t.Fatal(err)
	}
	if err := protocol.VerifySandboxReceiptV1(replayAnswer.Receipt, minerPublic); err != nil {
		t.Fatal(err)
	}
	if replayAnswer.Receipt.Stage != sandbox.StageHeld || protocol.SandboxReceiptAnswersV1(replayAnswer.Receipt, held) != nil {
		t.Fatalf("replay did not answer the exact held document: %+v", replayAnswer)
	}

	assertReplayError(reservation(strings.Repeat("b2", 16)), http.StatusConflict, "sandbox_conflict")
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

	// A release whose sandbox cannot be destroyed yet is a retryable bridge
	// error, not a released receipt; its replay is acknowledged once the
	// sandbox is gone.
	digest, _ := protocol.SandboxDigestV1(held)
	image := "sha256:" + strings.Repeat("c4", 32)
	lease := protocol.SandboxLeaseV1{
		AssignmentNonce: strings.Repeat("c3", 16), Env: map[string]string{}, Generation: 1, ImageDigest: image,
		ImageReference: "docker.io/library/python@" + image, Isolation: sandbox.IsolationGVisor, IssuedAt: *protocol.StaticTime(now),
		LeaseExpiresAt: *protocol.StaticTime(now.Add(10 * time.Minute)), MinerID: minerHotkey,
		Network:           sandbox.NetworkPolicy{Mode: sandbox.NetworkNone, Allow: []string{}},
		ReservationDigest: digest, Resources: held.Resources, SandboxID: held.SandboxID, Schema: protocol.SandboxLeaseSchema, SchemaVersion: 1,
		SecretEnv: sandbox.SecretEnv{Delivery: sandbox.SecretDeliveryNone, Names: []string{}}, Subnet: binding, WorkloadKind: sandbox.WorkloadKind,
	}
	if err := protocol.SignSandboxLeaseV1(&lease, validatorPrivate); err != nil {
		t.Fatal(err)
	}
	if response := serve(service.routes(), http.MethodPost, "/v1/sandbox/leases", envelope(lease, nil)); response.Code != http.StatusOK || len(backend.live) != 1 {
		t.Fatalf("lease: %d %s live=%d", response.Code, response.Body.String(), len(backend.live))
	}
	assertReplayError(held, http.StatusConflict, "sandbox_replay_not_held")
	release := protocol.SandboxReleaseV1{
		Generation: 1, IssuedAt: *protocol.StaticTime(now), MinerID: minerHotkey, Reason: sandbox.ReleaseCustomerDelete,
		SandboxID: held.SandboxID, Schema: protocol.SandboxReleaseSchema, SchemaVersion: 1, Subnet: binding,
	}
	if err := protocol.SignSandboxReleaseV1(&release, validatorPrivate); err != nil {
		t.Fatal(err)
	}
	backend.destroyErr = errors.New("daemon down")
	response = serve(service.routes(), http.MethodPost, "/v1/sandbox/releases", envelope(release, nil))
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), `"cleanup_pending"`) ||
		!strings.Contains(response.Body.String(), `"retryable":true`) {
		t.Fatalf("release with a failing destroy: %d %s", response.Code, response.Body.String())
	}
	backend.destroyErr = nil
	response = serve(service.routes(), http.MethodPost, "/v1/sandbox/releases", envelope(release, nil))
	answer = sandboxResponse{}
	if err := decodeJSON(bytes.NewReader(response.Body.Bytes()), &answer); err != nil || answer.Receipt.Stage != sandbox.StageReleased || len(backend.live) != 0 {
		t.Fatalf("replayed release: %d %s live=%d", response.Code, response.Body.String(), len(backend.live))
	}
	assertReplayError(held, http.StatusConflict, "sandbox_replay_fenced")
	// All chain/binding windows remain current: this 410 is the original
	// hold timestamp, not an expired ticket or forged admission envelope.
	expired := reservation(strings.Repeat("d4", 16))
	expired.SandboxID = "sbx-" + strings.Repeat("0", 31) + "2"
	expired.IssuedAt = *protocol.StaticTime(now.Add(-2 * time.Minute))
	expired.HoldExpiresAt = *protocol.StaticTime(now.Add(-time.Minute))
	if err := protocol.SignSandboxReservationV1(&expired, validatorPrivate); err != nil {
		t.Fatal(err)
	}
	if _, err := leases.Hold(ctx, expired, sandbox.Capacity{CPUMillis: 4000, MemoryMiB: 8192, DiskMiB: 40960, Sandboxes: 4}, now.Add(-90*time.Second)); err != nil {
		t.Fatal(err)
	}
	assertReplayError(expired, http.StatusGone, "expired_assignment")
	// Once shutdown closed the lane, documents are refused as retryable.
	if err := service.sandbox.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertReplayError(held, http.StatusServiceUnavailable, "sandbox_lane_closed")
	response = serve(service.routes(), http.MethodPost, "/v1/sandbox/releases", envelope(release, nil))
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), `"sandbox_lane_closed"`) ||
		!strings.Contains(response.Body.String(), `"retryable":true`) {
		t.Fatalf("release after the lane closed: %d %s", response.Code, response.Body.String())
	}
}

// sandboxProfile writes a valid sandbox-host-profile.v1 document whose
// cgroup root holds deployment, and whose dedicated daemon socket does not
// exist, so no daemon or host is ever reached.
func sandboxProfile(t *testing.T) (profile, cgroupRoot string) {
	t.Helper()
	dir := t.TempDir()
	cgroupRoot = filepath.Join(dir, "cgroup")
	if err := os.MkdirAll(filepath.Join(cgroupRoot, "deployment.slice"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cgroupRoot, "deployment.slice", "cgroup.procs"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	profile = filepath.Join(dir, "profile.json")
	document := `{"schema": "miss.computer/misscomputer-subnet/sandbox-host-profile", "schema_version": 1,
		"docker_host": "unix://` + dir + `/run/docker.sock",
		"containerd": {"address": "` + dir + `/run/containerd.sock", "namespace": "mc-sandbox", "plugins_namespace": "mc-sandbox-plugins"},
		"data_root": "` + dir + `/data", "docker_data_root": "` + dir + `/data/docker", "run_root": "` + dir + `/run",
		"runtime": {"name": "runsc", "path": "` + dir + `/bin/runsc", "sha256": "` + strings.Repeat("a", 64) + `",
			"sentry_path": "` + dir + `/bin/gvisor_sentry", "sentry_sha256": "` + strings.Repeat("b", 64) + `",
			"args": ["--systemd-cgroup", "--overlay2=none"], "release": "release-20261005.0"},
		"engine": {"docker_version": "28.0.4", "egress_table": "mcsbx_engine_egress"},
		"cgroup_root": "` + cgroupRoot + `", "lease_slice": "mcsbxlease.slice", "engine_slice": "mcsbxengine.slice",
		"aggregate": {"cpu_millis": 2000, "memory_mib": 1024, "pids": 1024, "data_fs_mib": 4096, "run_tmpfs_mib": 64,
			"image_reserve_mib": 512, "engine_overhead_mib": 512, "image_max_mib": 256, "log_mib": 16, "disk_mib": 1984, "sandboxes": 4},
		"per_lease": {"default_writable_mib": 64, "log_max_size_mib": 8, "log_max_file": 2, "pids_max": 64,
			"mounts": "none", "image_volumes": "refuse", "network_modes": ["none"], "isolation": ["gvisor"]}}`
	if err := os.WriteFile(profile, []byte(document), 0o644); err != nil {
		t.Fatal(err)
	}
	return profile, cgroupRoot
}

// --sandbox-leases stays off unless asked for, refuses a configured but
// unused sandbox setting, and with "on" starts nothing unless every input
// is given and valid and the host preflight passes. None of these cases
// reaches a daemon: the profile's socket does not exist.
func TestSandboxLeasesStartOnlyAfterTheHostPreflight(t *testing.T) {
	profile, _ := sandboxProfile(t)
	daemonConfig := filepath.Join(t.TempDir(), "daemon.json")
	if err := os.WriteFile(daemonConfig, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	store, err := durable.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	on := sandboxOptions{Mode: "on", HostProfile: profile, DeploymentCgroup: "/deployment.slice", DaemonConfig: daemonConfig}
	for _, test := range []struct {
		name    string
		options sandboxOptions
		want    string
	}{
		{name: "off with a profile", options: sandboxOptions{Mode: "off", HostProfile: profile}, want: "require --sandbox-leases on"},
		{name: "off with a deployment cgroup", options: sandboxOptions{Mode: "off", DeploymentCgroup: "/deployment.slice"}, want: "require --sandbox-leases on"},
		{name: "off with a daemon configuration", options: sandboxOptions{Mode: "off", DaemonConfig: daemonConfig}, want: "require --sandbox-leases on"},
		{name: "unknown mode", options: sandboxOptions{Mode: "true"}, want: "unsupported"},
		{name: "empty mode", options: sandboxOptions{}, want: "unsupported"},
		{name: "on without a profile", options: sandboxOptions{Mode: "on", DeploymentCgroup: "/deployment.slice", DaemonConfig: daemonConfig}, want: "requires --sandbox-host-profile"},
		{name: "on without a deployment cgroup", options: sandboxOptions{Mode: "on", HostProfile: profile, DaemonConfig: daemonConfig}, want: "requires --sandbox-host-profile"},
		{name: "on without a daemon configuration", options: sandboxOptions{Mode: "on", HostProfile: profile, DeploymentCgroup: "/deployment.slice"}, want: "requires --sandbox-host-profile"},
		{name: "on with a missing profile", options: sandboxOptions{Mode: "on", HostProfile: profile + ".missing", DeploymentCgroup: "/deployment.slice", DaemonConfig: daemonConfig}, want: "sandbox host profile"},
		{name: "on with a relative deployment cgroup", options: sandboxOptions{Mode: "on", HostProfile: profile, DeploymentCgroup: "deployment.slice", DaemonConfig: daemonConfig}, want: "clean absolute cgroup path"},
		{name: "on with a deployment cgroup that does not exist", options: sandboxOptions{Mode: "on", HostProfile: profile, DeploymentCgroup: "/typo.slice", DaemonConfig: daemonConfig}, want: "is not a cgroup"},
		{name: "on with a host whose daemon does not answer", options: on, want: "sandbox host preflight"},
	} {
		t.Run(test.name, func(t *testing.T) {
			lane, err := openSandboxLeases(context.Background(), test.options, miner.NewAgent("miner", nil, nil, nil, nil, nil), store)
			if lane != nil || err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("openSandboxLeases = %v, %v, want an error containing %q", lane, err, test.want)
			}
		})
	}
}
