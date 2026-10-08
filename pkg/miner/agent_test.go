// SPDX-License-Identifier: AGPL-3.0-only

package miner

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/durable"
	"github.com/misscomputer/misscomputer-subnet/pkg/organic"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	deployruntime "github.com/misscomputer/misscomputer-subnet/pkg/runtime"
	"github.com/misscomputer/misscomputer-subnet/pkg/tunnel"
)

// lifecycleRuntime is an OCI runtime whose launch can be held open and whose
// stops can fail, so the agent's cleanup ownership can be observed.
type lifecycleRuntime struct {
	url      string
	started  chan struct{}
	release  chan struct{}
	mu       sync.Mutex
	active   bool
	launches int
	stops    int
	failStop int
	stopCtx  error
	stopIDs  []string
}

func (r *lifecycleRuntime) Launch(_ context.Context, l deployruntime.Launch) (deployruntime.Started, error) {
	if r.started != nil {
		close(r.started)
		<-r.release
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.launches++
	r.active = true
	return deployruntime.Started{
		Instance:                deployruntime.Instance{ID: l.InstanceID, URL: r.url},
		LoadedImageConfigDigest: l.Manifest.Config.Digest, ImageReadyAt: time.Now().UTC(),
	}, nil
}

func (r *lifecycleRuntime) Running(context.Context, string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.active, nil
}

func (r *lifecycleRuntime) Stop(ctx context.Context, instanceID string) error {
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

// persistenceInspectingRuntime plans a Docker-style cleanup path and, at
// launch, records the durable endpoint row the agent wrote before it.
type persistenceInspectingRuntime struct {
	lifecycleRuntime
	state       *durable.Store
	endpointID  string
	cleanupPath string
	found       durable.Endpoint
}

func (r *persistenceInspectingRuntime) PlanCleanup(endpointID string) (deployruntime.CleanupPlan, error) {
	return deployruntime.CleanupPlan{
		InstanceID: deployruntime.InstanceName(endpointID), LayerPath: r.cleanupPath, LayerRoot: filepath.Dir(r.cleanupPath),
	}, nil
}

func (r *persistenceInspectingRuntime) Launch(context.Context, deployruntime.Launch) (deployruntime.Started, error) {
	endpoints, err := r.state.ActiveEndpoints(context.Background())
	if err != nil {
		return deployruntime.Started{}, err
	}
	for _, endpoint := range endpoints {
		if endpoint.EndpointID == r.endpointID {
			r.found = endpoint
		}
	}
	return deployruntime.Started{}, errors.New("injected launch interruption")
}

type cancelTransport struct {
	started chan struct{}
	once    sync.Once
}

func (t *cancelTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.once.Do(func() { close(t.started) })
	<-req.Context().Done()
	return nil, req.Context().Err()
}

// lifecycleHarness is an organic harness whose OCI runtime is runtime.
func lifecycleHarness(t *testing.T, runtime deployruntime.OCIRuntime) *organicHarness {
	t.Helper()
	h := newOrganicHarness(t, "http://127.0.0.1:1")
	h.agent.OCI = runtime
	return h
}

func healthyApp(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	t.Cleanup(server.Close)
	return server
}

// storedTicket is a durable deployment.v4 assignment row for recovery tests.
func storedTicket(deploymentID string, generation uint64, label string) protocol.Ticket {
	return protocol.Ticket{
		Version: protocol.OrganicVersion, DeploymentID: deploymentID, MinerID: testMinerHotkey,
		Generation: generation, AssignmentNonce: fixtureNonce(label),
	}
}

// fixtureNonce derives the canonical 32-hex assignment nonce of label.
func fixtureNonce(label string) string {
	sum := sha256.Sum256([]byte(label))
	return hex.EncodeToString(sum[:16])
}

func TestReadyAssignmentReplayRefusesAnotherExactTicket(t *testing.T) {
	app := healthyApp(t)
	runtime := &lifecycleRuntime{url: app.URL}
	h := lifecycleHarness(t, runtime)
	h.agent.HTTPClient = app.Client()
	ticket := h.ticket(t, strings.Repeat("1", 32), nil)
	first, err := h.assign(ticket)
	if err != nil || first.Idempotent {
		t.Fatalf("fresh assignment = %+v err=%v", first, err)
	}
	conflicting := h.ticket(t, ticket.AssignmentNonce, func(value *protocol.TicketV4) { value.IssuedAt = ticket.IssuedAt.Add(time.Millisecond) })
	if _, err := h.assign(conflicting); err == nil {
		t.Fatal("cached endpoint accepted a different exact ticket as idempotent")
	}
	runtime.mu.Lock()
	launches := runtime.launches
	runtime.mu.Unlock()
	if launches != 1 {
		t.Fatalf("replay launched the runtime %d times", launches)
	}
	if err := h.agent.Deactivate(context.Background(), first.EndpointID); err != nil {
		t.Fatal(err)
	}
	if err := h.agent.Deactivate(context.Background(), first.EndpointID); err != nil {
		t.Fatalf("repeat deactivation: %v", err)
	}
}

func TestCancelledHealthWaitCleansRuntimeWithFreshContext(t *testing.T) {
	runtime := &lifecycleRuntime{url: "http://app.test"}
	h := lifecycleHarness(t, runtime)
	transport := &cancelTransport{started: make(chan struct{})}
	h.agent.HTTPClient = &http.Client{Transport: transport}
	ticket := h.ticket(t, strings.Repeat("2", 32), nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		uid := h.uid
		_, err := h.agent.AssignBoundV4(ctx, ticket, h.validatorKey.Public().(ed25519.PublicKey), 101,
			testNetwork, testNetUID, testValidatorHotkey, testMinerHotkey, &uid)
		done <- err
	}()
	<-transport.started
	cancel()
	if err := <-done; err == nil {
		t.Fatal("cancelled assignment succeeded")
	}
	endpointID := protocol.EndpointIDV4(ticket)
	if _, err := h.tunnels.Resolve(endpointID); err == nil {
		t.Fatal("cancelled assignment left its tunnel registered")
	}
	h.agent.mu.Lock()
	_, retained := h.agent.instances[endpointID]
	h.agent.mu.Unlock()
	runtime.mu.Lock()
	active, stops, stopCtx := runtime.active, runtime.stops, runtime.stopCtx
	runtime.mu.Unlock()
	if retained || active || stops == 0 {
		t.Fatalf("cleanup retained=%v active=%v stops=%d", retained, active, stops)
	}
	if stopCtx != nil {
		t.Fatalf("runtime cleanup reused the cancelled assignment context: %v", stopCtx)
	}
}

func TestEarlyDeactivationFenceForceStopsLateRuntimeAndSurvivesRestart(t *testing.T) {
	app := healthyApp(t)
	runtime := &lifecycleRuntime{url: app.URL, started: make(chan struct{}), release: make(chan struct{})}
	h := lifecycleHarness(t, runtime)
	h.agent.HTTPClient = app.Client()
	ticket := h.ticket(t, strings.Repeat("3", 32), nil)
	endpointID := protocol.EndpointIDV4(ticket)
	done := make(chan ResultV4, 1)
	go func() {
		result, _ := h.assign(ticket)
		done <- result
	}()
	<-runtime.started
	if err := h.agent.Deactivate(context.Background(), endpointID); err != nil {
		t.Fatal(err)
	}
	close(runtime.release)
	result := <-done
	if result.Receipt.Stage != protocol.StageFailed || result.Receipt.ErrorCode == nil || *result.Receipt.ErrorCode != "deactivated" {
		t.Fatalf("late assignment receipt = %+v", result.Receipt)
	}
	runtime.mu.Lock()
	active, stops := runtime.active, runtime.stops
	runtime.mu.Unlock()
	if active || stops < 2 {
		t.Fatalf("late runtime cleanup active=%t stops=%d", active, stops)
	}
	if _, err := h.tunnels.Resolve(endpointID); err == nil {
		t.Fatal("fenced late runtime retained a tunnel")
	}
	if endpoints, err := h.state.ActiveEndpoints(context.Background()); err != nil || len(endpoints) != 0 {
		t.Fatalf("fenced runtime stranded for restart: %+v err=%v", endpoints, err)
	}
}

func TestDeactivateRetainsBookkeepingUntilStopSucceeds(t *testing.T) {
	app := healthyApp(t)
	runtime := &lifecycleRuntime{url: app.URL, failStop: 1}
	h := lifecycleHarness(t, runtime)
	h.agent.HTTPClient = app.Client()
	result, err := h.assign(h.ticket(t, strings.Repeat("4", 32), nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := h.agent.Deactivate(context.Background(), result.EndpointID); err == nil {
		t.Fatal("first stop failure was hidden")
	}
	h.agent.mu.Lock()
	instanceID := h.agent.instances[result.EndpointID]
	h.agent.mu.Unlock()
	if instanceID != deployruntime.InstanceName(result.EndpointID) {
		t.Fatalf("failed stop discarded endpoint bookkeeping: %q", instanceID)
	}
	if _, err := h.tunnels.Resolve(result.EndpointID); err == nil {
		t.Fatal("failed stop left the tunnel in routing")
	}
	if err := h.agent.Deactivate(context.Background(), result.EndpointID); err != nil {
		t.Fatalf("retry deactivation: %v", err)
	}
	h.agent.mu.Lock()
	_, retained := h.agent.instances[result.EndpointID]
	h.agent.mu.Unlock()
	if retained {
		t.Fatal("successful retry retained endpoint bookkeeping")
	}
}

// A restarted agent never serves an incarnation its predecessor started:
// recovery retires it before any edge request can reach the container.
func TestRestartNeverServesAnOldIncarnation(t *testing.T) {
	var hits atomic.Int64
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer app.Close()
	h := newOrganicHarness(t, app.URL)
	h.agent.HTTPClient = app.Client()
	ticket := h.ticket(t, strings.Repeat("5", 32), nil)
	result, err := h.assign(ticket)
	if err != nil {
		t.Fatal(err)
	}
	restarted := NewAgent(testMinerHotkey, nil, h.minerKey, h.agent.Artifacts, h.runtime, tunnel.NewLocalRegistry())
	restarted.State = h.state
	restarted.MinerTransport, restarted.MinerTLSCertificateSHA256 = h.agent.MinerTransport, h.agent.MinerTLSCertificateSHA256
	if err := restarted.RecoverCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := hits.Load()
	request := edgeRequest{method: http.MethodGet, path: "/"}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(EdgeAuthorizationHeader, signEdge(t, h.validatorKey, result.EndpointID, request, time.Now()))
	recorder := httptest.NewRecorder()
	restarted.ProxyRuntime(recorder, req, result.EndpointID)
	if recorder.Code != http.StatusNotFound || hits.Load() != before {
		t.Fatalf("restarted agent served an old incarnation: status=%d contacts=%d", recorder.Code, hits.Load()-before)
	}
	if got := recorder.Header().Values(organic.AgentEndpointUnavailableHeader); len(got) != 1 || got[0] != organic.AgentEndpointUnavailableValue {
		t.Fatalf("restarted agent availability signal = %v", got)
	}
}

func TestRecoverCleanupUsesPrivateRuntimeIdentityAndPersistsDeactivation(t *testing.T) {
	state, err := durable.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	runtime := &lifecycleRuntime{active: true}
	runtimeTicket := storedTicket("restart", 1, "runtime")
	endpoint := durable.Endpoint{
		EndpointID: protocol.EndpointID(runtimeTicket), DeploymentID: "restart", MinerHotkey: testMinerHotkey,
		RuntimeID: "runtime-private", RuntimeURL: "http://127.0.0.1:1", Active: true,
	}
	if err := state.SaveAssignment(context.Background(), runtimeTicket, "ready"); err != nil {
		t.Fatal(err)
	}
	if err := state.PutEndpoint(context.Background(), endpoint); err != nil {
		t.Fatal(err)
	}
	if err := state.SaveAssignment(context.Background(), storedTicket("pre-runtime-crash", 1, "pending"), "processing"); err != nil {
		t.Fatal(err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	agent := NewAgent(testMinerHotkey, nil, privateKey, nil, runtime, tunnel.NewLocalRegistry())
	agent.State = state
	if err := agent.RecoverCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if active, err := state.ActiveEndpoints(context.Background()); err != nil || len(active) != 0 {
		t.Fatalf("restart cleanup left active endpoints: %#v err=%v", active, err)
	}
	if pending, err := state.CleanupAssignments(context.Background(), testMinerHotkey); err != nil || len(pending) != 0 {
		t.Fatalf("restart cleanup left pre-runtime assignments: %#v err=%v", pending, err)
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.stops != 2 || runtime.active || runtime.stopIDs[0] != "runtime-private" {
		t.Fatalf("restart cleanup stops=%d active=%v identities=%v", runtime.stops, runtime.active, runtime.stopIDs)
	}
}

func TestAssignPersistsDeterministicCleanupIdentityBeforeRuntimeLaunch(t *testing.T) {
	h := newOrganicHarness(t, "http://127.0.0.1:1")
	ticket := h.ticket(t, strings.Repeat("6", 32), nil)
	runtime := &persistenceInspectingRuntime{
		state: h.state, endpointID: protocol.EndpointIDV4(ticket), cleanupPath: filepath.Join(t.TempDir(), "durable-runtime.oci"),
	}
	h.agent.OCI = runtime
	if _, err := h.assign(ticket); err == nil || !strings.Contains(err.Error(), "injected launch interruption") {
		t.Fatalf("assignment error = %v", err)
	}
	expectedRuntimeID := deployruntime.InstanceName(runtime.endpointID)
	if runtime.found.EndpointID != runtime.endpointID || runtime.found.RuntimeID != expectedRuntimeID || runtime.found.RuntimeURL != "" ||
		runtime.found.RuntimeCleanupPath != runtime.cleanupPath || !runtime.found.Active {
		t.Fatalf("pre-launch durable cleanup incarnation = %#v, want endpoint=%q runtime=%q creating", runtime.found, runtime.endpointID, expectedRuntimeID)
	}
}

func TestRestartCleanupRecoversAssignmentOnlyDaemonAndRetriesFailedStop(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	state, err := durable.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ticket := storedTicket("crash-window", 7, "daemon-created-before-endpoint")
	if err := state.SaveAssignment(context.Background(), ticket, "processing"); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	expectedRuntimeID := deployruntime.InstanceName(protocol.EndpointID(ticket))
	runtime := &lifecycleRuntime{active: true, failStop: 1}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recover := func() (*durable.Store, error) {
		reopened, err := durable.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		agent := NewAgent(testMinerHotkey, nil, privateKey, nil, runtime, tunnel.NewLocalRegistry())
		agent.State = reopened
		return reopened, agent.RecoverCleanup(context.Background())
	}
	firstState, err := recover()
	if err == nil || !strings.Contains(err.Error(), "stop failed") {
		t.Fatalf("first restart cleanup error = %v", err)
	}
	active, err := firstState.ActiveEndpoints(context.Background())
	if err != nil || len(active) != 1 || active[0].RuntimeID != expectedRuntimeID {
		t.Fatalf("failed stop did not retain the exact cleanup incarnation: %#v err=%v", active, err)
	}
	if err := firstState.Close(); err != nil {
		t.Fatal(err)
	}
	secondState, err := recover()
	defer secondState.Close()
	if err != nil {
		t.Fatalf("second restart cleanup: %v", err)
	}
	if active, err := secondState.ActiveEndpoints(context.Background()); err != nil || len(active) != 0 {
		t.Fatalf("successful retry retained active endpoints: %#v err=%v", active, err)
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.active || runtime.stops != 2 || runtime.stopIDs[0] != expectedRuntimeID || runtime.stopIDs[1] != expectedRuntimeID {
		t.Fatalf("daemon cleanup active=%v stops=%d identities=%v", runtime.active, runtime.stops, runtime.stopIDs)
	}
}

func TestRestartCleanupRecoversAlreadyFencedAssignmentOnlyDaemon(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	state, err := durable.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ticket := storedTicket("fenced-crash-window", 3, "fenced-daemon")
	ticket.Subnet = &protocol.SubnetBinding{ValidatorHotkey: testValidatorHotkey}
	endpointID := protocol.EndpointID(ticket)
	if err := state.SaveAssignment(context.Background(), ticket, "processing"); err != nil {
		t.Fatal(err)
	}
	if err := state.FenceEndpointDeactivation(context.Background(), endpointID, ticket.DeploymentID, ticket.MinerID, testValidatorHotkey); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	runtime := &lifecycleRuntime{active: true, failStop: 1}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	firstState, err := durable.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	firstAgent := NewAgent(testMinerHotkey, nil, privateKey, nil, runtime, tunnel.NewLocalRegistry())
	firstAgent.State = firstState
	if err := firstAgent.RecoverCleanup(context.Background()); err == nil || !strings.Contains(err.Error(), "stop failed") {
		t.Fatalf("first fenced restart cleanup error = %v", err)
	}
	active, err := firstState.ActiveEndpoints(context.Background())
	if err != nil || len(active) != 1 || active[0].RuntimeID != deployruntime.InstanceName(endpointID) {
		t.Fatalf("failed fenced stop did not retain the cleanup-only incarnation: %#v err=%v", active, err)
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
	secondAgent := NewAgent(testMinerHotkey, nil, privateKey, nil, runtime, tunnel.NewLocalRegistry())
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
