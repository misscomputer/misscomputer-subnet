// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
	"github.com/misscomputer/misscomputer-subnet/pkg/edge"
	"github.com/misscomputer/misscomputer-subnet/pkg/ledger"
	"github.com/misscomputer/misscomputer-subnet/pkg/miner"
	"github.com/misscomputer/misscomputer-subnet/pkg/policy"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	deployruntime "github.com/misscomputer/misscomputer-subnet/pkg/runtime"
	"github.com/misscomputer/misscomputer-subnet/pkg/tunnel"
	"github.com/misscomputer/misscomputer-subnet/pkg/validator"
	"github.com/misscomputer/misscomputer-subnet/pkg/workload"
)

func newAuthorizedTestRouter(t *testing.T, tunnels tunnel.Registry, probeToken string, authority ed25519.PublicKey, domain string) *edge.Router {
	t.Helper()
	if domain == "" {
		domain = "on.miss.computer"
	}
	router, err := edge.NewAuthorizedRouter(tunnels, probeToken, edge.RouterConfig{
		AuthorityKey: authority, Domain: domain, AllowPrivateUpstreams: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return router
}

func TestThreeMinerDeployment(t *testing.T) {
	ctx := context.Background()
	ownerPub, ownerPriv, _ := ed25519.GenerateKey(rand.Reader)
	store := artifact.FileStore{Root: t.TempDir()}
	spec, unique, err := workload.Generate("static", 1024)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := artifact.Publish(ctx, store, spec.Kind, [][]byte{[]byte("common-layer"), unique}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tunnels := tunnel.NewLocalRegistry()
	probeToken := "test-probe-token"
	router := newAuthorizedTestRouter(t, tunnels, probeToken, ownerPub, "on.miss.computer")
	edgeServer := httptest.NewServer(router)
	defer edgeServer.Close()
	miners := make([]miner.Assigner, 0, 4)
	var removedRuntime *trackingRuntime
	for _, id := range []string{"m1", "m2", "m3", "m4"} {
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		var runtime deployruntime.Runtime = deployruntime.NewLocalRuntime()
		if id == "m1" {
			removedRuntime = &trackingRuntime{inner: runtime}
			runtime = removedRuntime
		}
		agent := miner.NewAgent(id, ownerPub, key, store, runtime, tunnels)
		if id == "m1" {
			miners = append(miners, &timestampSpoofMiner{inner: agent})
		} else {
			miners = append(miners, agent)
		}
	}
	s := Scheduler{SigningKey: ownerPriv, Miners: miners, Router: router, Ledger: ledger.New(), Validator: validator.Validator{Vantage: "test", EdgeURL: edgeServer.URL, InternalProbeToken: probeToken}, Health: policy.NewMonitor(), Replicas: 3, Domain: "on.miss.computer"}
	result, err := s.Deploy(ctx, DeployRequest{DeploymentID: "abc", Manifest: manifest, ManifestKey: artifact.ManifestKey(manifest.ImageDigest), Workload: spec, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.ReadyMiners) != 3 || result.FirstReplicaAt.IsZero() || result.FullRedundancyAt.IsZero() || !result.PublicProbe.Correct {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(result.Observations) != 3 {
		t.Fatalf("expected three validator-side observations: %+v", result.Observations)
	}
	for _, observation := range result.Observations {
		if observation.MinerHotkey == "m1" && observation.LatencyMS > 5_000 {
			t.Fatalf("miner-provided timestamps influenced scoring latency: %+v", observation)
		}
	}
	if got := len(router.Replicas("abc.on.miss.computer")); got != 3 {
		t.Fatalf("got %d routes", got)
	}
	var removedEndpoint string
	for _, replica := range router.Replicas("abc.on.miss.computer") {
		if replica.MinerID == "m1" {
			removedEndpoint = replica.EndpointID
		}
	}
	if removedEndpoint == "" {
		t.Fatal("m1 endpoint was not routed")
	}
	now := time.Now()
	if action, err := s.HandleHealth(ctx, "abc", "abc-m1", "m1", "vantage-a", false, false, false, now); err != nil || action.RemoveFromRouting {
		t.Fatalf("first failure action=%+v err=%v", action, err)
	}
	if action, err := s.HandleHealth(ctx, "abc", "abc-m1", "m1", "vantage-a", false, false, false, now.Add(time.Second)); err != nil || !action.AssignReplacement {
		t.Fatalf("replacement action=%+v err=%v", action, err)
	}
	replicas := router.Replicas("abc.on.miss.computer")
	if len(replicas) != 3 {
		t.Fatalf("replacement left %d routes", len(replicas))
	}
	found := false
	for _, replica := range replicas {
		found = found || replica.MinerID == "m4"
	}
	if !found {
		t.Fatal("replacement miner m4 was not routed")
	}
	if _, err := tunnels.Resolve(removedEndpoint); err == nil {
		t.Fatal("removed miner tunnel is still registered")
	}
	if !removedRuntime.WasStopped(deployruntime.InstanceName(removedEndpoint)) {
		t.Fatal("removed miner runtime was not stopped")
	}
}

type timestampSpoofMiner struct{ inner *miner.Agent }

func (m *timestampSpoofMiner) ID() string                   { return m.inner.ID() }
func (m *timestampSpoofMiner) PublicKey() ed25519.PublicKey { return m.inner.PublicKey() }
func (m *timestampSpoofMiner) Assign(ctx context.Context, ticket protocol.Ticket) (miner.Result, error) {
	result, err := m.inner.Assign(ctx, ticket)
	if err == nil {
		result.Receipt.AssignmentSeen = time.Unix(0, 0).UTC()
		result.Receipt.HealthPassed = time.Now().UTC().Add(100 * 365 * 24 * time.Hour)
		err = protocol.SignReceipt(&result.Receipt, m.inner.SigningKey)
	}
	return result, err
}
func (m *timestampSpoofMiner) Deactivate(ctx context.Context, endpointID string) error {
	return m.inner.Deactivate(ctx, endpointID)
}

type trackingRuntime struct {
	inner   deployruntime.Runtime
	mu      sync.Mutex
	stopped []string
}

func (r *trackingRuntime) Deploy(ctx context.Context, ticket protocol.Ticket, manifest artifact.Manifest, layers [][]byte) (deployruntime.Instance, error) {
	return r.inner.Deploy(ctx, ticket, manifest, layers)
}

func (r *trackingRuntime) Stop(ctx context.Context, instanceID string) error {
	r.mu.Lock()
	r.stopped = append(r.stopped, instanceID)
	r.mu.Unlock()
	return r.inner.Stop(ctx, instanceID)
}

func (r *trackingRuntime) WasStopped(instanceID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, stopped := range r.stopped {
		if stopped == instanceID {
			return true
		}
	}
	return false
}

type receiptOnlyMiner struct {
	id  string
	pub ed25519.PublicKey
}

func (m receiptOnlyMiner) ID() string                   { return m.id }
func (m receiptOnlyMiner) PublicKey() ed25519.PublicKey { return m.pub }
func (m receiptOnlyMiner) Assign(context.Context, protocol.Ticket) (miner.Result, error) {
	return miner.Result{}, nil
}
func (m receiptOnlyMiner) Deactivate(context.Context, string) error { return nil }

func TestReceiptBoundToExactTicket(t *testing.T) {
	pub, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	candidate := receiptOnlyMiner{id: "m1", pub: pub}
	ticket := protocol.Ticket{
		Version: protocol.Version, DeploymentID: "d1", Generation: 7, AssignmentNonce: "nonce-a",
		MinerID: "m1", ImageDigest: "sha256:image", ManifestKey: "v1/manifests/image.json", RouteHost: "d1.on.miss.computer",
	}
	receipt := protocol.Receipt{
		Version: protocol.Version, DeploymentID: ticket.DeploymentID, Generation: ticket.Generation,
		AssignmentNonce: ticket.AssignmentNonce, MinerID: ticket.MinerID, ReplicaID: "d1-m1",
		EndpointID: protocol.EndpointID(ticket), ImageDigest: ticket.ImageDigest, ManifestKey: ticket.ManifestKey,
		RouteHost: ticket.RouteHost, Stage: protocol.StageReady,
	}
	if err := protocol.SignReceipt(&receipt, privateKey); err != nil {
		t.Fatal(err)
	}
	s := Scheduler{Ledger: ledger.New()}
	result := miner.Result{Receipt: receipt, EndpointID: receipt.EndpointID}
	if err := s.verifyResult(candidate, ticket, result); err != nil {
		t.Fatalf("matching receipt rejected: %v", err)
	}
	replayedForNewTicket := ticket
	replayedForNewTicket.AssignmentNonce = "nonce-b"
	if err := s.verifyResult(candidate, replayedForNewTicket, result); err == nil {
		t.Fatal("receipt replayed under a new ticket nonce was accepted")
	}
	replayedForNewGeneration := ticket
	replayedForNewGeneration.Generation++
	if err := s.verifyResult(candidate, replayedForNewGeneration, result); err == nil {
		t.Fatal("receipt replayed under a new generation was accepted")
	}
	wrongEndpoint := result
	wrongEndpoint.EndpointID = "d1-m1-g999"
	if err := s.verifyResult(candidate, ticket, wrongEndpoint); err == nil {
		t.Fatal("receipt with mismatched returned endpoint was accepted")
	}
}

type tamperingMiner struct {
	inner      *miner.Agent
	endpointID string
}

func (m *tamperingMiner) ID() string                   { return m.inner.ID() }
func (m *tamperingMiner) PublicKey() ed25519.PublicKey { return m.inner.PublicKey() }
func (m *tamperingMiner) Assign(ctx context.Context, ticket protocol.Ticket) (miner.Result, error) {
	m.endpointID = protocol.EndpointID(ticket)
	result, err := m.inner.Assign(ctx, ticket)
	if err == nil {
		result.Receipt.AssignmentNonce = "tampered-after-signing"
	}
	return result, err
}
func (m *tamperingMiner) Deactivate(ctx context.Context, endpointID string) error {
	return m.inner.Deactivate(ctx, endpointID)
}

func TestInvalidReceiptDeactivatesDerivedEndpoint(t *testing.T) {
	ctx := context.Background()
	ownerPub, ownerPriv, _ := ed25519.GenerateKey(rand.Reader)
	store := artifact.FileStore{Root: t.TempDir()}
	spec, unique, err := workload.Generate("static", 1024)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := artifact.Publish(ctx, store, spec.Kind, [][]byte{[]byte("base"), unique}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tunnels := tunnel.NewLocalRegistry()
	probeToken := "receipt-cleanup-token"
	router := newAuthorizedTestRouter(t, tunnels, probeToken, ownerPub, "on.miss.computer")
	edgeServer := httptest.NewServer(router)
	defer edgeServer.Close()
	miners := make([]miner.Assigner, 0, 4)
	var tamperedRuntime *trackingRuntime
	var tamperedMiner *tamperingMiner
	for _, id := range []string{"m1", "m2", "m3", "m4"} {
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		var runtime deployruntime.Runtime = deployruntime.NewLocalRuntime()
		if id == "m2" {
			tamperedRuntime = &trackingRuntime{inner: runtime}
			runtime = tamperedRuntime
		}
		agent := miner.NewAgent(id, ownerPub, key, store, runtime, tunnels)
		if id == "m2" {
			tamperedMiner = &tamperingMiner{inner: agent}
			miners = append(miners, tamperedMiner)
		} else {
			miners = append(miners, agent)
		}
	}
	s := Scheduler{
		SigningKey: ownerPriv, Miners: miners, Router: router, Ledger: ledger.New(), Health: policy.NewMonitor(), Replicas: 3, Domain: "on.miss.computer",
		Validator: validator.Validator{Vantage: "test", EdgeURL: edgeServer.URL, InternalProbeToken: probeToken},
	}
	result, err := s.Deploy(ctx, DeployRequest{DeploymentID: "verify", Manifest: manifest, ManifestKey: artifact.ManifestKey(manifest.ImageDigest), Workload: spec, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if !contains(result.FailedMiners, "m2") || contains(result.ReadyMiners, "m2") {
		t.Fatalf("tampered receipt was not rejected: %+v", result)
	}
	if _, err := tunnels.Resolve(tamperedMiner.endpointID); err == nil {
		t.Fatal("tampered receipt tunnel is still registered")
	}
	if !tamperedRuntime.WasStopped(deployruntime.InstanceName(tamperedMiner.endpointID)) {
		t.Fatal("tampered receipt runtime was not stopped")
	}
}

type wrongChallengeRuntime struct {
	delay      time.Duration
	servers    map[string]*httptest.Server
	endpointID string
}

func (r *wrongChallengeRuntime) Deploy(ctx context.Context, ticket protocol.Ticket, _ artifact.Manifest, _ [][]byte) (deployruntime.Instance, error) {
	r.endpointID = protocol.EndpointID(ticket)
	select {
	case <-ctx.Done():
		return deployruntime.Instance{}, ctx.Err()
	case <-time.After(r.delay):
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc(ticket.ChallengePath, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("wrong-challenge")) })
	server := httptest.NewServer(mux)
	id := deployruntime.InstanceName(protocol.EndpointID(ticket))
	r.servers[id] = server
	return deployruntime.Instance{ID: id, URL: server.URL}, nil
}

func (r *wrongChallengeRuntime) Stop(_ context.Context, instanceID string) error {
	if server := r.servers[instanceID]; server != nil {
		server.Close()
		delete(r.servers, instanceID)
	}
	return nil
}

func TestTargetedProbePreventsGoodReplicaMaskingBadCandidate(t *testing.T) {
	ctx := context.Background()
	ownerPub, ownerPriv, _ := ed25519.GenerateKey(rand.Reader)
	store := artifact.FileStore{Root: t.TempDir()}
	spec, unique, err := workload.Generate("static", 1024)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := artifact.Publish(ctx, store, spec.Kind, [][]byte{[]byte("base"), unique}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tunnels := tunnel.NewLocalRegistry()
	probeToken := "targeted-test-token"
	router := newAuthorizedTestRouter(t, tunnels, probeToken, ownerPub, "on.miss.computer")
	edgeServer := httptest.NewServer(router)
	defer edgeServer.Close()
	miners := make([]miner.Assigner, 0, 4)
	var rejectedRuntime *wrongChallengeRuntime
	for _, id := range []string{"m1", "m2", "m3", "m4"} {
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		var runtime deployruntime.Runtime = deployruntime.NewLocalRuntime()
		if id == "m2" {
			rejectedRuntime = &wrongChallengeRuntime{delay: 30 * time.Millisecond, servers: make(map[string]*httptest.Server)}
			runtime = rejectedRuntime
		}
		miners = append(miners, miner.NewAgent(id, ownerPub, key, store, runtime, tunnels))
	}
	s := Scheduler{
		SigningKey: ownerPriv, Miners: miners, Router: router, Ledger: ledger.New(), Health: policy.NewMonitor(), Replicas: 3, Domain: "on.miss.computer",
		Validator: validator.Validator{Vantage: "test", EdgeURL: edgeServer.URL, InternalProbeToken: probeToken},
	}
	result, err := s.Deploy(ctx, DeployRequest{DeploymentID: "masked", Manifest: manifest, ManifestKey: artifact.ManifestKey(manifest.ImageDigest), Workload: spec, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range result.ReadyMiners {
		if id == "m2" {
			t.Fatal("bad candidate was accepted because another replica masked it")
		}
	}
	if !contains(result.FailedMiners, "m2") || !contains(result.ReadyMiners, "m4") {
		t.Fatalf("bad candidate was not replaced: %+v", result)
	}
	for _, replica := range router.Replicas("masked.on.miss.computer") {
		if replica.MinerID == "m2" {
			t.Fatal("bad candidate remained in routing")
		}
	}
	if _, err := tunnels.Resolve(rejectedRuntime.endpointID); err == nil {
		t.Fatal("rejected candidate tunnel is still registered")
	}
	if len(rejectedRuntime.servers) != 0 {
		t.Fatal("rejected candidate runtime is still running")
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestDeploymentIDMustBeOneSafeDNSLabel(t *testing.T) {
	scheduler := Scheduler{}
	for _, value := range []string{"../escape", "mixed.Case", "-leading", "trailing-", "two.labels"} {
		if _, err := scheduler.Deploy(context.Background(), DeployRequest{DeploymentID: value}); err == nil {
			t.Fatalf("unsafe deployment ID %q accepted", value)
		}
	}
}
