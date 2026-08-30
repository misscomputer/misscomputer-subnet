// SPDX-License-Identifier: AGPL-3.0-only

package miner

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
	"github.com/misscomputer/misscomputer-subnet/pkg/durable"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	deployruntime "github.com/misscomputer/misscomputer-subnet/pkg/runtime"
	"github.com/misscomputer/misscomputer-subnet/pkg/tunnel"
	"github.com/misscomputer/misscomputer-subnet/pkg/workload"
)

type cleanupRuntime struct {
	instance deployruntime.Instance
	mu       sync.Mutex
	active   bool
	deploys  int
	stops    int
	failStop int
	stopCtx  error
	stopIDs  []string
}

func (r *cleanupRuntime) Deploy(_ context.Context, ticket protocol.Ticket, _ artifact.Manifest, _ [][]byte) (deployruntime.Instance, error) {
	r.mu.Lock()
	r.deploys++
	r.active = true
	r.instance.ID = deployruntime.InstanceName(protocol.EndpointID(ticket))
	instance := r.instance
	r.mu.Unlock()
	return instance, nil
}

func (r *cleanupRuntime) Stop(ctx context.Context, instanceID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stops++
	r.stopCtx = ctx.Err()
	r.stopIDs = append(r.stopIDs, instanceID)
	if r.failStop > 0 {
		r.failStop--
		return errors.New("stop failed")
	}
	r.active = false
	return nil
}

type persistenceInspectingRuntime struct {
	state       *durable.Store
	endpointID  string
	cleanupPath string
	found       durable.Endpoint
}

func (r *persistenceInspectingRuntime) PlanCleanup(ticket protocol.Ticket) (deployruntime.CleanupPlan, error) {
	return deployruntime.CleanupPlan{
		InstanceID: deployruntime.InstanceName(protocol.EndpointID(ticket)),
		LayerPath:  r.cleanupPath,
		LayerRoot:  filepath.Dir(r.cleanupPath),
	}, nil
}

func (r *persistenceInspectingRuntime) Deploy(context.Context, protocol.Ticket, artifact.Manifest, [][]byte) (deployruntime.Instance, error) {
	endpoints, err := r.state.ActiveEndpoints(context.Background())
	if err != nil {
		return deployruntime.Instance{}, err
	}
	for _, endpoint := range endpoints {
		if endpoint.EndpointID == r.endpointID {
			r.found = endpoint
			break
		}
	}
	return deployruntime.Instance{}, errors.New("injected deploy interruption")
}

func (r *persistenceInspectingRuntime) Stop(context.Context, string) error { return nil }

type legacyCleanupRuntime struct {
	legacyPath  string
	plannedPath string
	failStop    int
	mu          sync.Mutex
	active      bool
	inspections int
	stopPlans   []deployruntime.CleanupPlan
}

func (r *legacyCleanupRuntime) PlanCleanup(ticket protocol.Ticket) (deployruntime.CleanupPlan, error) {
	return deployruntime.CleanupPlan{
		InstanceID: deployruntime.InstanceName(protocol.EndpointID(ticket)),
		LayerPath:  r.plannedPath,
		LayerRoot:  filepath.Dir(r.plannedPath),
	}, nil
}

func (r *legacyCleanupRuntime) RecoverCleanup(_ context.Context, ticket protocol.Ticket) (deployruntime.CleanupPlan, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.inspections++
	return deployruntime.CleanupPlan{
		InstanceID: deployruntime.InstanceName(protocol.EndpointID(ticket)),
		LayerPath:  r.legacyPath,
		LayerRoot:  filepath.Dir(r.legacyPath),
	}, nil
}

func (r *legacyCleanupRuntime) Deploy(context.Context, protocol.Ticket, artifact.Manifest, [][]byte) (deployruntime.Instance, error) {
	return deployruntime.Instance{}, errors.New("unexpected deploy")
}

func (r *legacyCleanupRuntime) Stop(_ context.Context, instanceID string) error {
	return r.StopCleanup(context.Background(), deployruntime.CleanupPlan{InstanceID: instanceID})
}

func (r *legacyCleanupRuntime) StopCleanup(_ context.Context, plan deployruntime.CleanupPlan) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopPlans = append(r.stopPlans, plan)
	if r.failStop > 0 {
		r.failStop--
		return errors.New("stop failed")
	}
	r.active = false
	return nil
}

type cancelTransport struct {
	started chan struct{}
	once    sync.Once
}

type slowIgnoringRuntime struct {
	instance deployruntime.Instance
	started  chan struct{}
	release  chan struct{}
	mu       sync.Mutex
	active   bool
	stops    int
}

func (r *slowIgnoringRuntime) Deploy(_ context.Context, ticket protocol.Ticket, _ artifact.Manifest, _ [][]byte) (deployruntime.Instance, error) {
	close(r.started)
	<-r.release
	r.mu.Lock()
	r.active = true
	r.instance.ID = deployruntime.InstanceName(protocol.EndpointID(ticket))
	instance := r.instance
	r.mu.Unlock()
	return instance, nil
}

func (r *slowIgnoringRuntime) Stop(context.Context, string) error {
	r.mu.Lock()
	r.active = false
	r.stops++
	r.mu.Unlock()
	return nil
}

func (t *cancelTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.once.Do(func() { close(t.started) })
	<-req.Context().Done()
	return nil, req.Context().Err()
}

func agentFixture(t *testing.T, runtime deployruntime.Runtime, client *http.Client) (*Agent, protocol.Ticket, *tunnel.LocalRegistry, ed25519.PrivateKey) {
	t.Helper()
	ctx := context.Background()
	ownerPublic, ownerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, minerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store := artifact.FileStore{Root: t.TempDir()}
	spec, layer, err := workload.Generate("static", 1024)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := artifact.Publish(ctx, store, spec.Kind, [][]byte{layer}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ticket := protocol.Ticket{
		Version: protocol.Version, DeploymentID: "cleanup", Generation: 4, AssignmentNonce: "nonce", MinerID: "m1",
		ImageDigest: manifest.ImageDigest, ManifestKey: artifact.ManifestKey(manifest.ImageDigest), RouteHost: "cleanup.test",
		ChallengePath: spec.ChallengePath, ChallengeSHA256: protocol.ChallengeDigest(spec.ChallengeValue),
		Health:   protocol.HealthSpec{Path: "/healthz", ExpectedStatus: http.StatusOK, IntervalMillis: 1, TimeoutMillis: 30_000},
		IssuedAt: time.Now().Add(-time.Second), ExpiresAt: time.Now().Add(time.Minute),
	}
	if err := protocol.SignTicket(&ticket, ownerPrivate); err != nil {
		t.Fatal(err)
	}
	tunnels := tunnel.NewLocalRegistry()
	agent := NewAgent("m1", ownerPublic, minerPrivate, store, runtime, tunnels)
	agent.HTTPClient = client
	return agent, ticket, tunnels, ownerPrivate
}

func TestDurableReadyAssignmentReplayReportsIdempotency(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer server.Close()
	runtime := &cleanupRuntime{instance: deployruntime.Instance{ID: "runtime-instance", URL: server.URL}}
	agent, ticket, _, ownerPrivate := agentFixture(t, runtime, server.Client())
	state, err := durable.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	agent.State = state

	first, err := agent.Assign(context.Background(), ticket)
	if err != nil {
		t.Fatal(err)
	}
	if first.Idempotent {
		t.Fatal("fresh assignment was reported as idempotent")
	}
	replayed, err := agent.Assign(context.Background(), ticket)
	if err != nil {
		t.Fatal(err)
	}
	if !replayed.Idempotent || replayed.EndpointID != first.EndpointID || replayed.Receipt.Signature != first.Receipt.Signature {
		t.Fatalf("cached replay metadata/result mismatch: first=%+v replay=%+v", first, replayed)
	}
	conflicting := ticket
	conflicting.RouteHost = "other.test"
	if err := protocol.SignTicket(&conflicting, ownerPrivate); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.Assign(context.Background(), conflicting); err == nil {
		t.Fatal("cached endpoint accepted a different exact ticket as idempotent")
	}
	runtime.mu.Lock()
	deploys := runtime.deploys
	runtime.mu.Unlock()
	if deploys != 1 {
		t.Fatalf("cached replay deployed the runtime %d times", deploys)
	}
	if err := agent.Deactivate(context.Background(), first.EndpointID); err != nil {
		t.Fatal(err)
	}
}

func TestCancelledHealthWaitCleansRuntimeWithFreshContext(t *testing.T) {
	runtime := &cleanupRuntime{instance: deployruntime.Instance{ID: "runtime-instance", URL: "http://workload.test"}}
	transport := &cancelTransport{started: make(chan struct{})}
	agent, ticket, tunnels, _ := agentFixture(t, runtime, &http.Client{Transport: transport})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := agent.Assign(ctx, ticket)
		done <- err
	}()
	<-transport.started
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("assignment error = %v", err)
	}
	endpointID := protocol.EndpointID(ticket)
	if _, err := tunnels.Resolve(endpointID); err == nil {
		t.Fatal("cancelled assignment left its tunnel registered")
	}
	agent.mu.Lock()
	_, retained := agent.instances[endpointID]
	agent.mu.Unlock()
	runtime.mu.Lock()
	active, stops, stopCtx := runtime.active, runtime.stops, runtime.stopCtx
	runtime.mu.Unlock()
	if retained || active || stops != 1 {
		t.Fatalf("cleanup retained=%v active=%v stops=%d", retained, active, stops)
	}
	if stopCtx != nil {
		t.Fatalf("runtime cleanup reused cancelled assignment context: %v", stopCtx)
	}
}

func TestEarlyDeactivationFenceForceStopsLateRuntimeAndSurvivesRestart(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer server.Close()
	runtime := &slowIgnoringRuntime{
		instance: deployruntime.Instance{ID: "late-runtime", URL: server.URL},
		started:  make(chan struct{}), release: make(chan struct{}),
	}
	agent, ticket, tunnels, _ := agentFixture(t, runtime, server.Client())
	path := filepath.Join(t.TempDir(), "fenced-agent.db")
	state, err := durable.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	agent.State = state
	done := make(chan error, 1)
	go func() {
		_, assignErr := agent.Assign(context.Background(), ticket)
		done <- assignErr
	}()
	<-runtime.started
	if err := agent.Deactivate(context.Background(), protocol.EndpointID(ticket)); err != nil {
		t.Fatal(err)
	}
	close(runtime.release)
	if assignErr := <-done; !errors.Is(assignErr, durable.ErrEndpointDeactivated) {
		t.Fatalf("late assignment error=%v", assignErr)
	}
	runtime.mu.Lock()
	active, stops := runtime.active, runtime.stops
	runtime.mu.Unlock()
	if active || stops != 2 {
		t.Fatalf("late runtime cleanup active=%t stops=%d", active, stops)
	}
	if _, err := tunnels.Resolve(protocol.EndpointID(ticket)); err == nil {
		t.Fatal("fenced late runtime retained a tunnel")
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := durable.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if endpoints, err := reopened.ActiveEndpoints(context.Background()); err != nil || len(endpoints) != 0 {
		t.Fatalf("fenced runtime stranded after restart: %+v err=%v", endpoints, err)
	}
}

func TestDeactivateRetainsBookkeepingUntilStopSucceeds(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer server.Close()
	runtime := &cleanupRuntime{instance: deployruntime.Instance{ID: "runtime-instance", URL: server.URL}, failStop: 1}
	agent, ticket, tunnels, _ := agentFixture(t, runtime, server.Client())
	result, err := agent.Assign(context.Background(), ticket)
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.Deactivate(context.Background(), result.EndpointID); err == nil {
		t.Fatal("first stop failure was hidden")
	}
	agent.mu.Lock()
	instanceID := agent.instances[result.EndpointID]
	agent.mu.Unlock()
	if instanceID != runtime.instance.ID {
		t.Fatalf("failed stop discarded endpoint bookkeeping: %q", instanceID)
	}
	if _, err := tunnels.Resolve(result.EndpointID); err == nil {
		t.Fatal("failed stop left tunnel in routing")
	}
	if err := agent.Deactivate(context.Background(), result.EndpointID); err != nil {
		t.Fatalf("retry deactivation: %v", err)
	}
	agent.mu.Lock()
	_, retained := agent.instances[result.EndpointID]
	agent.mu.Unlock()
	if retained {
		t.Fatal("successful retry retained endpoint bookkeeping")
	}
}

func TestAssignBoundRejectsAnotherMinerServiceKey(t *testing.T) {
	validatorPublic, validatorPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, minerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uid := uint16(7)
	pin := hex.EncodeToString(make([]byte, 32))
	now := time.Now().UTC()
	ticket := protocol.Ticket{
		Version: protocol.BoundVersion, DeploymentID: "bound", Generation: 1, MinerID: "miner-hotkey",
		ImageDigest: "sha256:" + string(make([]byte, 64)), ManifestKey: "manifest", RouteHost: "bound.test",
		AssignmentNonce: "0123456789abcdef0123456789abcdef", ChallengePath: "/challenge",
		ChallengeSHA256: protocol.ChallengeDigest("value"), IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute),
		Subnet: &protocol.SubnetBinding{
			Network: "test", NetUID: 42, ValidatorHotkey: "validator-hotkey", MinerHotkey: "miner-hotkey", MinerUID: &uid,
			MinerAxonURL: "https://8.8.8.8:8091", MinerTransport: "https", MinerTLSCertificateSHA256: &pin,
			ChainBlock: 100, Epoch: 10, ExpiresAtBlock: 112,
			ValidatorServicePublicKey: hex.EncodeToString(validatorPublic), MinerServicePublicKey: hex.EncodeToString(otherPublic),
		},
	}
	if err := protocol.SignTicket(&ticket, validatorPrivate); err != nil {
		t.Fatal(err)
	}
	agent := NewAgent("miner-hotkey", nil, minerPrivate, nil, nil, nil)
	agent.MinerTransport = "https"
	agent.MinerTLSCertificateSHA256 = pin
	if _, err := agent.AssignBound(context.Background(), ticket, validatorPublic, 101, "test", 42, "validator-hotkey", "miner-hotkey", &uid); err == nil {
		t.Fatal("ticket bound to another miner service key was accepted")
	}
}

func TestAssignBoundRejectsConfiguredTransportPinMismatch(t *testing.T) {
	validatorPublic, validatorPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	minerPublic, minerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uid := uint16(7)
	signedPin := hex.EncodeToString(make([]byte, 32))
	configuredPin := "1111111111111111111111111111111111111111111111111111111111111111"
	now := time.Now().UTC()
	ticket := protocol.Ticket{
		Version: protocol.BoundVersion, DeploymentID: "bound", Generation: 1, MinerID: "miner-hotkey",
		AssignmentNonce: "transport-pin-nonce", IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute),
		Subnet: &protocol.SubnetBinding{
			Network: "test", NetUID: 42, ValidatorHotkey: "validator-hotkey", MinerHotkey: "miner-hotkey", MinerUID: &uid,
			MinerAxonURL: "https://8.8.8.8:8091", MinerTransport: "https", MinerTLSCertificateSHA256: &signedPin,
			ChainBlock: 100, ExpiresAtBlock: 112, ValidatorServicePublicKey: hex.EncodeToString(validatorPublic),
			MinerServicePublicKey: hex.EncodeToString(minerPublic),
		},
	}
	if err := protocol.SignTicket(&ticket, validatorPrivate); err != nil {
		t.Fatal(err)
	}
	agent := NewAgent("miner-hotkey", nil, minerPrivate, nil, nil, nil)
	agent.MinerTransport = "https"
	agent.MinerTLSCertificateSHA256 = configuredPin
	if _, err := agent.AssignBound(context.Background(), ticket, validatorPublic, 101, "test", 42, "validator-hotkey", "miner-hotkey", &uid); err == nil {
		t.Fatal("ticket pin differing from the miner's configured certificate was accepted")
	}
}

func TestRecoverCleanupUsesPrivateRuntimeIdentityAndPersistsDeactivation(t *testing.T) {
	state, err := durable.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	runtime := &cleanupRuntime{instance: deployruntime.Instance{ID: "runtime-private", URL: "http://127.0.0.1:1"}, active: true}
	runtimeTicket := protocol.Ticket{
		DeploymentID: "restart", MinerID: "m1", Generation: 1, AssignmentNonce: "runtime",
	}
	endpoint := durable.Endpoint{
		EndpointID: protocol.EndpointID(runtimeTicket), DeploymentID: "restart", MinerHotkey: "m1",
		RuntimeID: runtime.instance.ID, RuntimeURL: runtime.instance.URL, Active: true,
	}
	if err := state.SaveAssignment(context.Background(), runtimeTicket, "ready"); err != nil {
		t.Fatal(err)
	}
	if err := state.PutEndpoint(context.Background(), endpoint); err != nil {
		t.Fatal(err)
	}
	pendingTicket := protocol.Ticket{
		DeploymentID: "pre-runtime-crash", MinerID: "m1", Generation: 1, AssignmentNonce: "pending",
	}
	if err := state.SaveAssignment(context.Background(), pendingTicket, "processing"); err != nil {
		t.Fatal(err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	agent := NewAgent("m1", nil, privateKey, nil, runtime, tunnel.NewLocalRegistry())
	agent.State = state
	if err := agent.RecoverCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	active, err := state.ActiveEndpoints(context.Background())
	if err != nil || len(active) != 0 {
		t.Fatalf("restart cleanup left active endpoints: %#v err=%v", active, err)
	}
	pending, err := state.CleanupAssignments(context.Background(), "m1")
	if err != nil || len(pending) != 0 {
		t.Fatalf("restart cleanup left pre-runtime assignments: %#v err=%v", pending, err)
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.stops != 2 || runtime.active {
		t.Fatalf("restart cleanup stops=%d active=%v", runtime.stops, runtime.active)
	}
}

func TestAssignPersistsDeterministicCleanupIdentityBeforeRuntimeLaunch(t *testing.T) {
	state, err := durable.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	runtime := &persistenceInspectingRuntime{state: state}
	agent, ticket, _, _ := agentFixture(t, runtime, nil)
	agent.State = state
	runtime.endpointID = protocol.EndpointID(ticket)
	runtime.cleanupPath = filepath.Join(t.TempDir(), "durable-runtime.layer")

	if _, err := agent.Assign(context.Background(), ticket); err == nil || !strings.Contains(err.Error(), "injected deploy interruption") {
		t.Fatalf("assignment error = %v", err)
	}
	expectedRuntimeID := deployruntime.InstanceName(runtime.endpointID)
	if runtime.found.EndpointID != runtime.endpointID || runtime.found.RuntimeID != expectedRuntimeID || runtime.found.RuntimeURL != "" || runtime.found.RuntimeCleanupPath != runtime.cleanupPath || !runtime.found.Active {
		t.Fatalf("pre-launch durable cleanup incarnation = %#v, want endpoint=%q runtime=%q creating", runtime.found, runtime.endpointID, expectedRuntimeID)
	}
}

func TestRestartCleanupRecoversAssignmentOnlyDaemonAndRetriesFailedStop(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	state, err := durable.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ticket := protocol.Ticket{
		DeploymentID: "crash-window", MinerID: "m1", Generation: 7, AssignmentNonce: "daemon-created-before-endpoint",
	}
	if err := state.SaveAssignment(context.Background(), ticket, "processing"); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}

	expectedRuntimeID := deployruntime.InstanceName(protocol.EndpointID(ticket))
	runtime := &cleanupRuntime{
		instance: deployruntime.Instance{ID: expectedRuntimeID},
		active:   true,
		failStop: 1,
	}
	firstState, err := durable.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	firstAgent := NewAgent("m1", nil, privateKey, nil, runtime, tunnel.NewLocalRegistry())
	firstAgent.State = firstState
	if err := firstAgent.RecoverCleanup(context.Background()); err == nil || !strings.Contains(err.Error(), "stop failed") {
		t.Fatalf("first restart cleanup error = %v", err)
	}
	active, err := firstState.ActiveEndpoints(context.Background())
	if err != nil || len(active) != 1 || active[0].RuntimeID != expectedRuntimeID {
		t.Fatalf("failed stop did not retain exact cleanup incarnation: %#v err=%v", active, err)
	}
	if err := firstState.Close(); err != nil {
		t.Fatal(err)
	}

	secondState, err := durable.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer secondState.Close()
	secondAgent := NewAgent("m1", nil, privateKey, nil, runtime, tunnel.NewLocalRegistry())
	secondAgent.State = secondState
	if err := secondAgent.RecoverCleanup(context.Background()); err != nil {
		t.Fatalf("second restart cleanup: %v", err)
	}
	active, err = secondState.ActiveEndpoints(context.Background())
	if err != nil || len(active) != 0 {
		t.Fatalf("successful retry retained active endpoints: %#v err=%v", active, err)
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.active || runtime.stops != 2 || len(runtime.stopIDs) != 2 || runtime.stopIDs[0] != expectedRuntimeID || runtime.stopIDs[1] != expectedRuntimeID {
		t.Fatalf("daemon cleanup active=%v stops=%d identities=%v", runtime.active, runtime.stops, runtime.stopIDs)
	}
}

func TestRestartCleanupRecoversAlreadyFencedAssignmentOnlyDaemon(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	state, err := durable.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ticket := protocol.Ticket{
		DeploymentID: "fenced-crash-window", MinerID: "m1", Generation: 3, AssignmentNonce: "fenced-daemon",
		Subnet: &protocol.SubnetBinding{ValidatorHotkey: "validator"},
	}
	endpointID := protocol.EndpointID(ticket)
	if err := state.SaveAssignment(context.Background(), ticket, "processing"); err != nil {
		t.Fatal(err)
	}
	if err := state.FenceEndpointDeactivation(context.Background(), endpointID, ticket.DeploymentID, ticket.MinerID, "validator"); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}

	runtime := &cleanupRuntime{
		instance: deployruntime.Instance{ID: deployruntime.InstanceName(endpointID)},
		active:   true,
		failStop: 1,
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	firstState, err := durable.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	firstAgent := NewAgent("m1", nil, privateKey, nil, runtime, tunnel.NewLocalRegistry())
	firstAgent.State = firstState
	if err := firstAgent.RecoverCleanup(context.Background()); err == nil || !strings.Contains(err.Error(), "stop failed") {
		t.Fatalf("first fenced restart cleanup error = %v", err)
	}
	active, err := firstState.ActiveEndpoints(context.Background())
	if err != nil || len(active) != 1 || active[0].RuntimeID != deployruntime.InstanceName(endpointID) {
		t.Fatalf("failed fenced stop did not retain cleanup-only incarnation: %#v err=%v", active, err)
	}
	if err := firstState.PutEndpoint(context.Background(), durable.Endpoint{
		EndpointID: endpointID, DeploymentID: ticket.DeploymentID, MinerHotkey: ticket.MinerID,
		RuntimeID: deployruntime.InstanceName(endpointID), RuntimeURL: "http://127.0.0.1:1", Active: true,
	}); !errors.Is(err, durable.ErrEndpointDeactivated) {
		t.Fatalf("fenced cleanup row allowed a new activation: %v", err)
	}
	if err := firstState.Close(); err != nil {
		t.Fatal(err)
	}

	secondState, err := durable.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer secondState.Close()
	secondAgent := NewAgent("m1", nil, privateKey, nil, runtime, tunnel.NewLocalRegistry())
	secondAgent.State = secondState
	if err := secondAgent.RecoverCleanup(context.Background()); err != nil {
		t.Fatalf("second fenced restart cleanup: %v", err)
	}
	if active, err := secondState.ActiveEndpoints(context.Background()); err != nil || len(active) != 0 {
		t.Fatalf("successful fenced retry retained cleanup state: %#v err=%v", active, err)
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.active || runtime.stops != 2 {
		t.Fatalf("fenced daemon cleanup active=%v stops=%d", runtime.active, runtime.stops)
	}
}

func TestRestartCleanupInspectsAndPersistsExactLegacyLayerBeforeStop(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	state, err := durable.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ticket := protocol.Ticket{
		DeploymentID: "legacy-layer", MinerID: "m1", Generation: 9, AssignmentNonce: "legacy-random-layer",
	}
	if err := state.SaveAssignment(context.Background(), ticket, "processing"); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	stateDir := t.TempDir()
	legacyPath := filepath.Join(stateDir, "verified-381902.layer")
	plannedPath := filepath.Join(stateDir, deployruntime.InstanceName(protocol.EndpointID(ticket))+".layer")
	runtime := &legacyCleanupRuntime{legacyPath: legacyPath, plannedPath: plannedPath, failStop: 1, active: true}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	firstState, err := durable.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	firstAgent := NewAgent("m1", nil, privateKey, nil, runtime, tunnel.NewLocalRegistry())
	firstAgent.State = firstState
	if err := firstAgent.RecoverCleanup(context.Background()); err == nil || !strings.Contains(err.Error(), "stop failed") {
		t.Fatalf("first legacy cleanup error = %v", err)
	}
	active, err := firstState.ActiveEndpoints(context.Background())
	if err != nil || len(active) != 1 || active[0].RuntimeCleanupPath != legacyPath {
		t.Fatalf("exact inspected legacy path was not durable before stop: %#v err=%v", active, err)
	}
	if err := firstState.Close(); err != nil {
		t.Fatal(err)
	}

	// The second process must use the persisted legacy source without another
	// inspection or invention from its (possibly changed) runtime state root.
	runtime.plannedPath = filepath.Join(t.TempDir(), deployruntime.InstanceName(protocol.EndpointID(ticket))+".layer")
	secondState, err := durable.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer secondState.Close()
	secondAgent := NewAgent("m1", nil, privateKey, nil, runtime, tunnel.NewLocalRegistry())
	secondAgent.State = secondState
	if err := secondAgent.RecoverCleanup(context.Background()); err != nil {
		t.Fatalf("legacy cleanup retry: %v", err)
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.active || runtime.inspections != 1 || len(runtime.stopPlans) != 2 || runtime.stopPlans[0].LayerPath != legacyPath || runtime.stopPlans[1].LayerPath != legacyPath {
		t.Fatalf("legacy cleanup active=%v inspections=%d plans=%+v", runtime.active, runtime.inspections, runtime.stopPlans)
	}
}
