// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
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
	"github.com/misscomputer/misscomputer-subnet/pkg/ledger"
	"github.com/misscomputer/misscomputer-subnet/pkg/miner"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	deployruntime "github.com/misscomputer/misscomputer-subnet/pkg/runtime"
	"github.com/misscomputer/misscomputer-subnet/pkg/tunnel"
	"github.com/misscomputer/misscomputer-subnet/pkg/validator"
	"github.com/misscomputer/misscomputer-subnet/pkg/workload"
)

type countingAssigner struct {
	inner miner.Assigner
	mu    sync.Mutex
	seen  []protocol.Ticket
}

type receiptTamperAssigner struct {
	inner miner.Assigner
}

type flakyDeactivateAssigner struct {
	inner    miner.Assigner
	mu       sync.Mutex
	failures int
	calls    int
}

func (m *receiptTamperAssigner) ID() string                   { return m.inner.ID() }
func (m *receiptTamperAssigner) PublicKey() ed25519.PublicKey { return m.inner.PublicKey() }
func (m *receiptTamperAssigner) Assign(ctx context.Context, ticket protocol.Ticket) (miner.Result, error) {
	result, err := m.inner.Assign(ctx, ticket)
	if err == nil {
		result.Receipt.AssignmentNonce = "tampered-after-signing"
	}
	return result, err
}
func (m *receiptTamperAssigner) Deactivate(ctx context.Context, endpointID string) error {
	return m.inner.Deactivate(ctx, endpointID)
}

func (m *flakyDeactivateAssigner) ID() string                   { return m.inner.ID() }
func (m *flakyDeactivateAssigner) PublicKey() ed25519.PublicKey { return m.inner.PublicKey() }
func (m *flakyDeactivateAssigner) Assign(ctx context.Context, ticket protocol.Ticket) (miner.Result, error) {
	return m.inner.Assign(ctx, ticket)
}
func (m *flakyDeactivateAssigner) Deactivate(ctx context.Context, endpointID string) error {
	m.mu.Lock()
	m.calls++
	if m.failures > 0 {
		m.failures--
		m.mu.Unlock()
		return errors.New("injected deactivation failure")
	}
	m.mu.Unlock()
	return m.inner.Deactivate(ctx, endpointID)
}
func (m *flakyDeactivateAssigner) Calls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

func (m *countingAssigner) ID() string                   { return m.inner.ID() }
func (m *countingAssigner) PublicKey() ed25519.PublicKey { return m.inner.PublicKey() }
func (m *countingAssigner) Assign(ctx context.Context, ticket protocol.Ticket) (miner.Result, error) {
	m.mu.Lock()
	m.seen = append(m.seen, ticket)
	m.mu.Unlock()
	return m.inner.Assign(ctx, ticket)
}
func (m *countingAssigner) Deactivate(ctx context.Context, endpointID string) error {
	return m.inner.Deactivate(ctx, endpointID)
}
func (m *countingAssigner) Assignments() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.seen)
}

type schedulerHarness struct {
	scheduler *Scheduler
	request   DeployRequest
	miners    map[string]*countingAssigner
}

func newSchedulerHarness(t *testing.T, ids []string, replicas int) *schedulerHarness {
	t.Helper()
	ctx := context.Background()
	ownerPublic, ownerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store := artifact.FileStore{Root: t.TempDir()}
	spec, layer, err := workload.Generate("static", 1024)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := artifact.Publish(ctx, store, spec.Kind, [][]byte{[]byte("base"), layer}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tunnels := tunnel.NewLocalRegistry()
	probeToken := "scheduler-regression-probe"
	router := newAuthorizedTestRouter(t, tunnels, probeToken, ownerPublic, "on.miss.computer")
	edgeServer := httptest.NewServer(router)
	t.Cleanup(edgeServer.Close)
	assigners := make([]miner.Assigner, 0, len(ids))
	byID := make(map[string]*countingAssigner, len(ids))
	for _, id := range ids {
		_, signingKey, keyErr := ed25519.GenerateKey(rand.Reader)
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		agent := miner.NewAgent(id, ownerPublic, signingKey, store, deployruntime.NewLocalRuntime(), tunnels)
		tracked := &countingAssigner{inner: agent}
		byID[id] = tracked
		assigners = append(assigners, tracked)
	}
	assignmentLedger := ledger.New()
	scheduler := &Scheduler{
		SigningKey: ownerPrivate, Miners: assigners, Router: router, Ledger: assignmentLedger, Replicas: replicas, Domain: "on.miss.computer",
		Validator: validator.Validator{Vantage: "test", EdgeURL: edgeServer.URL, InternalProbeToken: probeToken},
	}
	return &schedulerHarness{
		scheduler: scheduler,
		request: DeployRequest{
			DeploymentID: "regression", Manifest: manifest, ManifestKey: artifact.ManifestKey(manifest.ImageDigest), Workload: spec, Timeout: 5 * time.Second,
		},
		miners: byID,
	}
}

func (h *schedulerHarness) cleanup(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := h.scheduler.DeactivateDeployment(ctx, h.request.DeploymentID); err != nil {
		t.Fatal(err)
	}
}

func useDurableLedger(t *testing.T, h *schedulerHarness) (*durable.Store, *sql.DB) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scheduler-state.db")
	store, err := durable.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	assignmentLedger, err := ledger.NewDurable(store)
	if err != nil {
		t.Fatal(err)
	}
	h.scheduler.Ledger = assignmentLedger
	triggerDB, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = triggerDB.Close() })
	return store, triggerDB
}

func failTrustZero(t *testing.T, values *ledger.Ledger, triggerDB *sql.DB, minerID string) {
	t.Helper()
	if err := values.SetTrust(minerID, 1); err != nil {
		t.Fatal(err)
	}
	statement := `CREATE TRIGGER fail_trust_zero
BEFORE UPDATE OF value ON trust
WHEN OLD.miner_hotkey = '` + minerID + `' AND NEW.value = 0
BEGIN
  SELECT RAISE(FAIL, 'transient trust failure');
END`
	if _, err := triggerDB.ExecContext(context.Background(), statement); err != nil {
		t.Fatal(err)
	}
}

func restoreTrustWrites(t *testing.T, triggerDB *sql.DB) {
	t.Helper()
	if _, err := triggerDB.ExecContext(context.Background(), `DROP TRIGGER fail_trust_zero`); err != nil {
		t.Fatal(err)
	}
}

func TestDeployExcludesTrustZeroMiner(t *testing.T) {
	h := newSchedulerHarness(t, []string{"m1", "m2", "m3", "m4"}, 3)
	h.scheduler.Ledger.SetTrust("m1", 0)
	result, err := h.scheduler.Deploy(context.Background(), h.request)
	if err != nil {
		t.Fatal(err)
	}
	defer h.cleanup(t)
	if h.miners["m1"].Assignments() != 0 || contains(result.ReadyMiners, "m1") {
		t.Fatalf("trust-zero miner was assigned: result=%+v assignments=%d", result, h.miners["m1"].Assignments())
	}
}

func TestRequiredMinerAndEvidenceOnlyScoringBoundary(t *testing.T) {
	h := newSchedulerHarness(t, []string{"m1", "m2", "m3", "m4"}, 3)
	store, _ := useDurableLedger(t, h)
	h.request.RequiredMiner = "m4"
	h.request.ScoringDisposition = ScoringEvidenceOnly
	result, err := h.scheduler.Deploy(context.Background(), h.request)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.cleanup(t) })
	if result.RequiredMiner != "m4" || result.ScoringDisposition != ScoringEvidenceOnly || len(result.AcceptedTickets) != 3 {
		t.Fatalf("result did not retain target/evidence handoff: %+v", result)
	}
	found := false
	for _, minerID := range result.ReadyMiners {
		found = found || minerID == "m4"
	}
	if !found || h.miners["m4"].Assignments() != 1 {
		t.Fatalf("required miner was not atomically assigned: ready=%v assignments=%d", result.ReadyMiners, h.miners["m4"].Assignments())
	}
	observations, err := store.Observations(context.Background(), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(observations) != 0 || len(result.Observations) != 3 {
		t.Fatalf("evidence-only observations persisted=%d returned=%d", len(observations), len(result.Observations))
	}
	disposition, exists := h.scheduler.DeploymentScoringDisposition(h.request.DeploymentID)
	if !exists || disposition != ScoringEvidenceOnly {
		t.Fatalf("deployment scoring disposition=%q exists=%t", disposition, exists)
	}
	var targetReplica string
	for _, replica := range h.scheduler.ActiveReplicas(h.request.DeploymentID) {
		if replica.MinerID == "m4" {
			targetReplica = replica.ReplicaID
		}
	}
	if targetReplica == "" {
		t.Fatal("required miner replica is unavailable")
	}
	action, err := h.scheduler.HandleHealth(
		context.Background(), h.request.DeploymentID, targetReplica, "m4", "campaign-probe", true, false, true, time.Now().UTC(),
	)
	if err != nil || action.TrustZero || h.scheduler.Ledger.Trust("m4") != ledger.DefaultTrust {
		t.Fatalf("evidence-only health action=%+v trust=%v err=%v", action, h.scheduler.Ledger.Trust("m4"), err)
	}
	observations, err = store.Observations(context.Background(), time.Time{})
	if err != nil || len(observations) != 0 {
		t.Fatalf("evidence-only replacement observations=%v err=%v", observations, err)
	}
}

func TestRequiredMinerFailureCannotFallThroughToUntargetedSuccess(t *testing.T) {
	h := newSchedulerHarness(t, []string{"m1", "m2", "m3", "m4"}, 3)
	if err := h.scheduler.Ledger.SetTrust("m4", 0); err != nil {
		t.Fatal(err)
	}
	h.request.RequiredMiner = "m4"
	result, err := h.scheduler.Deploy(context.Background(), h.request)
	var capacity *CapacityError
	if !errors.As(err, &capacity) {
		t.Fatalf("result=%+v error=%v, want capacity failure", result, err)
	}
	if len(result.ReadyMiners) != 0 || h.miners["m1"].Assignments() != 0 || h.miners["m2"].Assignments() != 0 || h.miners["m3"].Assignments() != 0 {
		t.Fatalf("untargeted miners were attempted after target rejection: result=%+v", result)
	}
}

func TestEvidenceOnlyInvalidReceiptDoesNotChangeEconomicTrust(t *testing.T) {
	h := newSchedulerHarness(t, []string{"m1", "m2", "m3", "m4"}, 3)
	store, _ := useDurableLedger(t, h)
	for index, candidate := range h.scheduler.Miners {
		if candidate.ID() == "m4" {
			h.scheduler.Miners[index] = &receiptTamperAssigner{inner: candidate}
		}
	}
	h.request.RequiredMiner = "m4"
	h.request.ScoringDisposition = ScoringEvidenceOnly
	_, err := h.scheduler.Deploy(context.Background(), h.request)
	if err == nil {
		t.Fatal("tampered required receipt was accepted")
	}
	if trust := h.scheduler.Ledger.Trust("m4"); trust != ledger.DefaultTrust {
		t.Fatalf("evidence-only receipt changed economic trust to %v", trust)
	}
	observations, observationErr := store.Observations(context.Background(), time.Time{})
	if observationErr != nil || len(observations) != 0 {
		t.Fatalf("evidence-only receipt persisted observations=%v err=%v", observations, observationErr)
	}
}

func TestDeploymentDeactivationRetainsExactFailedAssignmentForRetry(t *testing.T) {
	h := newSchedulerHarness(t, []string{"m1", "m2", "m3"}, 3)
	flaky := &flakyDeactivateAssigner{inner: h.scheduler.Miners[0], failures: 1}
	h.scheduler.Miners[0] = flaky
	if _, err := h.scheduler.Deploy(context.Background(), h.request); err != nil {
		t.Fatal(err)
	}
	if err := h.scheduler.DeactivateDeployment(context.Background(), h.request.DeploymentID); err == nil {
		t.Fatal("injected cleanup failure was hidden")
	}
	active := h.scheduler.ActiveReplicas(h.request.DeploymentID)
	pending, err := h.scheduler.PendingCleanupAssignments(context.Background(), h.request.DeploymentID)
	if err != nil || len(active) != 1 || active[0].MinerID != "m1" || pending != 1 {
		t.Fatalf("failed cleanup active=%+v pending=%d err=%v", active, pending, err)
	}
	if _, exists := h.scheduler.DeploymentScoringDisposition(h.request.DeploymentID); !exists {
		t.Fatal("failed cleanup discarded deployment ownership")
	}
	if err := h.scheduler.DeactivateDeployment(context.Background(), h.request.DeploymentID); err != nil {
		t.Fatalf("retry cleanup: %v", err)
	}
	pending, err = h.scheduler.PendingCleanupAssignments(context.Background(), h.request.DeploymentID)
	if err != nil || pending != 0 || flaky.Calls() != 2 {
		t.Fatalf("cleanup retry pending=%d calls=%d err=%v", pending, flaky.Calls(), err)
	}
	if _, exists := h.scheduler.DeploymentScoringDisposition(h.request.DeploymentID); exists {
		t.Fatal("successful cleanup retained deployment ownership")
	}
}

func TestInvalidReceiptTrustPersistenceFailurePropagatesAfterCleanup(t *testing.T) {
	h := newSchedulerHarness(t, []string{"m1", "m2"}, 1)
	store, triggerDB := useDurableLedger(t, h)
	failTrustZero(t, h.scheduler.Ledger, triggerDB, "m1")
	h.scheduler.Miners[0] = &receiptTamperAssigner{inner: h.scheduler.Miners[0]}

	result, err := h.scheduler.Deploy(context.Background(), h.request)
	if err == nil || !strings.Contains(err.Error(), "persist trust-zero") {
		t.Fatalf("trust persistence failure was not propagated: result=%+v err=%v", result, err)
	}
	if h.scheduler.Ledger.Eligible("m1") {
		t.Fatal("failed durable trust write reopened the in-process eligibility gate")
	}
	if durableTrust, exists, trustErr := store.Trust(context.Background(), "m1"); trustErr != nil || !exists || durableTrust != 1 {
		t.Fatalf("failed trust write unexpectedly mutated durable trust: value=%v exists=%v err=%v", durableTrust, exists, trustErr)
	}
	pending, cleanupErr := store.CleanupAssignments(context.Background(), "m1")
	if cleanupErr != nil || len(pending) != 0 {
		t.Fatalf("invalid receipt was not cleaned before propagation: pending=%+v err=%v", pending, cleanupErr)
	}
	if h.miners["m2"].Assignments() != 0 {
		t.Fatal("deployment continued after its trust-zero persistence operation failed")
	}

	restoreTrustWrites(t, triggerDB)
	if err := h.scheduler.Ledger.SetTrust("m1", 0); err != nil {
		t.Fatalf("trust write did not recover after the transient failure: %v", err)
	}
}

func TestHealthTrustPersistenceFailureStillRestoresReplica(t *testing.T) {
	h := newSchedulerHarness(t, []string{"m1", "m2"}, 1)
	store, triggerDB := useDurableLedger(t, h)
	if _, err := h.scheduler.Deploy(context.Background(), h.request); err != nil {
		t.Fatal(err)
	}
	deactivated := false
	defer func() {
		if !deactivated {
			h.cleanup(t)
		}
	}()
	failTrustZero(t, h.scheduler.Ledger, triggerDB, "m1")

	action, err := h.scheduler.HandleHealth(
		context.Background(), h.request.DeploymentID, "regression-m1", "m1", "v1",
		true, false, true, time.Now(),
	)
	if err == nil || !strings.Contains(err.Error(), "persist trust-zero") {
		t.Fatalf("health trust persistence failure was not propagated: action=%+v err=%v", action, err)
	}
	if !action.RemoveFromRouting || !action.AssignReplacement || !action.TrustZero {
		t.Fatalf("unexpected fraud policy action: %+v", action)
	}
	if h.miners["m2"].Assignments() != 1 {
		t.Fatalf("trust persistence failure prevented replacement: assignments=%d", h.miners["m2"].Assignments())
	}
	replicas := h.scheduler.Router.Replicas("regression.on.miss.computer")
	if len(replicas) != 1 || replicas[0].MinerID != "m2" {
		t.Fatalf("replacement did not restore the route: %+v", replicas)
	}
	if h.scheduler.Ledger.Eligible("m1") {
		t.Fatal("failed durable trust write reopened the in-process eligibility gate")
	}
	if durableTrust, exists, trustErr := store.Trust(context.Background(), "m1"); trustErr != nil || !exists || durableTrust != 1 {
		t.Fatalf("failed trust write unexpectedly mutated durable trust: value=%v exists=%v err=%v", durableTrust, exists, trustErr)
	}

	restoreTrustWrites(t, triggerDB)
	if err := h.scheduler.Ledger.SetTrust("m1", 0); err != nil {
		t.Fatalf("trust write did not recover after the transient failure: %v", err)
	}
	h.cleanup(t)
	deactivated = true
}

func TestRemovedAndFraudZeroedMinersAreNotReselected(t *testing.T) {
	h := newSchedulerHarness(t, []string{"m1", "m2", "m3", "m4", "m5"}, 3)
	if _, err := h.scheduler.Deploy(context.Background(), h.request); err != nil {
		t.Fatal(err)
	}
	defer h.cleanup(t)
	now := time.Now()
	action, err := h.scheduler.HandleHealth(context.Background(), h.request.DeploymentID, "regression-m1", "m1", "v1", true, false, false, now)
	if err != nil || !action.TrustZero || !action.AssignReplacement {
		t.Fatalf("fraud removal action=%+v err=%v", action, err)
	}
	if h.miners["m4"].Assignments() != 1 {
		t.Fatalf("first clean replacement assignments=%d", h.miners["m4"].Assignments())
	}
	if _, err := h.scheduler.HandleHealth(context.Background(), h.request.DeploymentID, "regression-m4", "m4", "v1", false, false, false, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	action, err = h.scheduler.HandleHealth(context.Background(), h.request.DeploymentID, "regression-m4", "m4", "v1", false, false, false, now.Add(2*time.Second))
	if err != nil || !action.AssignReplacement {
		t.Fatalf("network removal action=%+v err=%v", action, err)
	}
	if h.miners["m1"].Assignments() != 1 || h.miners["m4"].Assignments() != 1 || h.miners["m5"].Assignments() != 1 {
		t.Fatalf("quarantined miners cycled: m1=%d m4=%d m5=%d", h.miners["m1"].Assignments(), h.miners["m4"].Assignments(), h.miners["m5"].Assignments())
	}
}

func TestRemovedMinerCapacityErrorDoesNotCycle(t *testing.T) {
	h := newSchedulerHarness(t, []string{"m1", "m2", "m3", "m4"}, 3)
	if _, err := h.scheduler.Deploy(context.Background(), h.request); err != nil {
		t.Fatal(err)
	}
	defer h.cleanup(t)
	now := time.Now()
	if _, err := h.scheduler.HandleHealth(context.Background(), h.request.DeploymentID, "regression-m1", "m1", "v1", true, false, false, now); err != nil {
		t.Fatal(err)
	}
	if _, err := h.scheduler.HandleHealth(context.Background(), h.request.DeploymentID, "regression-m4", "m4", "v1", false, false, false, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	_, err := h.scheduler.HandleHealth(context.Background(), h.request.DeploymentID, "regression-m4", "m4", "v1", false, false, false, now.Add(2*time.Second))
	var capacity *CapacityError
	if !errors.As(err, &capacity) {
		t.Fatalf("capacity error = %v", err)
	}
	if h.miners["m1"].Assignments() != 1 || h.miners["m4"].Assignments() != 1 {
		t.Fatalf("removed candidate was retried: m1=%d m4=%d", h.miners["m1"].Assignments(), h.miners["m4"].Assignments())
	}
}

func TestAcceptanceNetworkFailureImmediatelyZerosTrust(t *testing.T) {
	h := newSchedulerHarness(t, []string{"m1"}, 1)
	h.scheduler.Validator.EdgeURL = "http://127.0.0.1:1"
	h.scheduler.Validator.Client = &http.Client{Timeout: 100 * time.Millisecond}
	_, err := h.scheduler.Deploy(context.Background(), h.request)
	var capacity *CapacityError
	if !errors.As(err, &capacity) {
		t.Fatalf("network acceptance failure error = %v", err)
	}
	if got := h.scheduler.Ledger.Trust("m1"); got != 0 {
		t.Fatalf("trust after one unreachable acceptance probe = %v", got)
	}
}

type lateSuccessMiner struct {
	id          string
	publicKey   ed25519.PublicKey
	release     chan struct{}
	started     chan struct{}
	deactivated chan struct{}
	onceStart   sync.Once
	onceStop    sync.Once
	mu          sync.Mutex
	active      map[string]bool
}

func newLateSuccessMiner(t *testing.T, id string) *lateSuccessMiner {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &lateSuccessMiner{
		id: id, publicKey: publicKey, release: make(chan struct{}), started: make(chan struct{}),
		deactivated: make(chan struct{}), active: make(map[string]bool),
	}
}

func (m *lateSuccessMiner) ID() string                   { return m.id }
func (m *lateSuccessMiner) PublicKey() ed25519.PublicKey { return m.publicKey }
func (m *lateSuccessMiner) Assign(_ context.Context, ticket protocol.Ticket) (miner.Result, error) {
	m.onceStart.Do(func() { close(m.started) })
	<-m.release
	endpointID := protocol.EndpointID(ticket)
	m.mu.Lock()
	m.active[endpointID] = true
	m.mu.Unlock()
	return miner.Result{EndpointID: endpointID}, nil
}
func (m *lateSuccessMiner) Deactivate(_ context.Context, endpointID string) error {
	m.mu.Lock()
	wasActive := m.active[endpointID]
	delete(m.active, endpointID)
	m.mu.Unlock()
	if wasActive {
		m.onceStop.Do(func() { close(m.deactivated) })
	}
	return nil
}
func (m *lateSuccessMiner) activeCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.active)
}

func TestDeployCleansLateSuccessAfterTimeout(t *testing.T) {
	_, ownerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	late := newLateSuccessMiner(t, "late")
	router := newAuthorizedTestRouter(t, tunnel.NewLocalRegistry(), "probe", ownerPrivate.Public().(ed25519.PublicKey), "on.miss.computer")
	scheduler := &Scheduler{SigningKey: ownerPrivate, Miners: []miner.Assigner{late}, Router: router, Ledger: ledger.New(), Replicas: 1}
	request := DeployRequest{DeploymentID: "late", Timeout: 30 * time.Millisecond}
	startedAt := time.Now()
	_, err = scheduler.Deploy(context.Background(), request)
	if err == nil {
		t.Fatal("timed out deployment succeeded")
	}
	if elapsed := time.Since(startedAt); elapsed > time.Second {
		t.Fatalf("Deploy blocked on cancellation-ignoring assigner for %s", elapsed)
	}
	<-late.started
	close(late.release)
	select {
	case <-late.deactivated:
	case <-time.After(time.Second):
		t.Fatal("late-successful assignment was not deactivated")
	}
	if got := late.activeCount(); got != 0 {
		t.Fatalf("late assignment left %d active endpoints", got)
	}
	scheduler.mu.Lock()
	_, registered := scheduler.states[request.DeploymentID]
	scheduler.mu.Unlock()
	if registered {
		t.Fatal("failed deployment registration was not rolled back")
	}
}

type blockingErrorMiner struct {
	id        string
	publicKey ed25519.PublicKey
	started   chan struct{}
	release   chan struct{}
	once      sync.Once
}

func (m *blockingErrorMiner) ID() string                   { return m.id }
func (m *blockingErrorMiner) PublicKey() ed25519.PublicKey { return m.publicKey }
func (m *blockingErrorMiner) Assign(context.Context, protocol.Ticket) (miner.Result, error) {
	m.once.Do(func() { close(m.started) })
	<-m.release
	return miner.Result{}, errors.New("assignment failed")
}
func (m *blockingErrorMiner) Deactivate(context.Context, string) error { return nil }

func TestConcurrentDuplicateDeploymentIDRejectedAndRollbackAllowsRetry(t *testing.T) {
	_, ownerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blocked := &blockingErrorMiner{id: "m1", publicKey: publicKey, started: make(chan struct{}), release: make(chan struct{})}
	scheduler := &Scheduler{
		SigningKey: ownerPrivate, Miners: []miner.Assigner{blocked}, Router: newAuthorizedTestRouter(t, tunnel.NewLocalRegistry(), "probe", ownerPrivate.Public().(ed25519.PublicKey), "on.miss.computer"), Ledger: ledger.New(), Replicas: 1,
	}
	request := DeployRequest{DeploymentID: "duplicate", Timeout: time.Second}
	firstDone := make(chan error, 1)
	go func() {
		_, deployErr := scheduler.Deploy(context.Background(), request)
		firstDone <- deployErr
	}()
	<-blocked.started
	if _, duplicateErr := scheduler.Deploy(context.Background(), request); !errors.Is(duplicateErr, ErrDeploymentActive) {
		t.Fatalf("duplicate error = %v", duplicateErr)
	}
	close(blocked.release)
	if firstErr := <-firstDone; firstErr == nil {
		t.Fatal("first failed assignment unexpectedly deployed")
	}
	if _, retryErr := scheduler.Deploy(context.Background(), request); errors.Is(retryErr, ErrDeploymentActive) {
		t.Fatalf("failed deployment stranded active registration: %v", retryErr)
	}
}

func TestConcurrentHealthReplacementsReserveDistinctCandidates(t *testing.T) {
	h := newSchedulerHarness(t, []string{"m1", "m2", "m3", "m4", "m5"}, 3)
	if _, err := h.scheduler.Deploy(context.Background(), h.request); err != nil {
		t.Fatal(err)
	}
	defer h.cleanup(t)
	start := make(chan struct{})
	errs := make(chan error, 2)
	for _, id := range []string{"m1", "m2"} {
		id := id
		go func() {
			<-start
			_, healthErr := h.scheduler.HandleHealth(context.Background(), h.request.DeploymentID, "regression-"+id, id, "v1", true, false, false, time.Now())
			errs <- healthErr
		}()
	}
	close(start)
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if h.miners["m4"].Assignments() != 1 || h.miners["m5"].Assignments() != 1 {
		t.Fatalf("replacement reservations were shared: m4=%d m5=%d", h.miners["m4"].Assignments(), h.miners["m5"].Assignments())
	}
	replicas := h.scheduler.Router.Replicas("regression.on.miss.computer")
	if len(replicas) != 3 {
		t.Fatalf("concurrent replacement left %d replicas: %+v", len(replicas), replicas)
	}
}

func TestConcurrentDeployDefaultInitializationDoesNotMutateReplicaSetting(t *testing.T) {
	_, ownerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	miners := make([]miner.Assigner, 0, 3)
	for i := 0; i < 3; i++ {
		publicKey, _, keyErr := ed25519.GenerateKey(rand.Reader)
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		miners = append(miners, &immediateErrorMiner{id: string(rune('a' + i)), publicKey: publicKey})
	}
	scheduler := &Scheduler{SigningKey: ownerPrivate, Miners: miners, Router: newAuthorizedTestRouter(t, tunnel.NewLocalRegistry(), "probe", ownerPrivate.Public().(ed25519.PublicKey), "on.miss.computer"), Ledger: ledger.New()}
	var wait sync.WaitGroup
	for _, id := range []string{"defaults-a", "defaults-b"} {
		id := id
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, _ = scheduler.Deploy(context.Background(), DeployRequest{DeploymentID: id, Timeout: time.Second})
		}()
	}
	wait.Wait()
	if scheduler.Replicas != 0 {
		t.Fatalf("Deploy mutated configured replica default to %d", scheduler.Replicas)
	}
}

type immediateErrorMiner struct {
	id        string
	publicKey ed25519.PublicKey
}

func (m *immediateErrorMiner) ID() string                   { return m.id }
func (m *immediateErrorMiner) PublicKey() ed25519.PublicKey { return m.publicKey }
func (m *immediateErrorMiner) Assign(context.Context, protocol.Ticket) (miner.Result, error) {
	return miner.Result{}, errors.New("assignment failed")
}
func (m *immediateErrorMiner) Deactivate(context.Context, string) error { return nil }

type knownCleanupMiner struct {
	immediateErrorMiner
	endpointID   string
	deploymentID string
	calls        int
	failures     int
}

func (m *knownCleanupMiner) DeactivateKnown(_ context.Context, endpointID, deploymentID string) error {
	m.calls++
	m.endpointID = endpointID
	m.deploymentID = deploymentID
	if m.failures > 0 {
		m.failures--
		return errors.New("remote cleanup failed")
	}
	return nil
}

func TestFailedTicketCleanupCarriesDeploymentIdentity(t *testing.T) {
	candidate := &knownCleanupMiner{immediateErrorMiner: immediateErrorMiner{id: "miner"}}
	ticket := protocol.Ticket{
		DeploymentID: "owned-deployment", MinerID: "miner", Generation: 3, AssignmentNonce: "nonce",
	}
	scheduler := &Scheduler{Ledger: ledger.New()}
	if err := scheduler.deactivateTicket(candidate, ticket); err != nil {
		t.Fatal(err)
	}
	if candidate.endpointID != protocol.EndpointID(ticket) || candidate.deploymentID != ticket.DeploymentID {
		t.Fatalf("cleanup lost exact ticket ownership: endpoint=%q deployment=%q", candidate.endpointID, candidate.deploymentID)
	}
}

func TestFailedKnownTicketCleanupRemainsDurableAndRetryable(t *testing.T) {
	ctx := context.Background()
	store, err := durable.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ticket := protocol.Ticket{
		DeploymentID: "retry-cleanup", MinerID: "miner", Generation: 2, AssignmentNonce: "retry-nonce",
	}
	endpointID := protocol.EndpointID(ticket)
	if err := store.SaveAssignment(ctx, ticket, "ready"); err != nil {
		t.Fatal(err)
	}
	if err := store.PutEndpoint(ctx, durable.Endpoint{
		EndpointID: endpointID, DeploymentID: ticket.DeploymentID, MinerHotkey: ticket.MinerID, Active: true,
	}); err != nil {
		t.Fatal(err)
	}
	assignmentLedger, err := ledger.NewDurable(store)
	if err != nil {
		t.Fatal(err)
	}
	scheduler := &Scheduler{Ledger: assignmentLedger}
	candidate := &knownCleanupMiner{
		immediateErrorMiner: immediateErrorMiner{id: ticket.MinerID}, failures: 1,
	}

	if err := scheduler.deactivateTicket(candidate, ticket); err == nil {
		t.Fatal("remote cleanup failure was hidden")
	}
	pending, err := store.CleanupAssignments(ctx, ticket.MinerID)
	if err != nil || len(pending) != 1 || pending[0].EndpointID != endpointID {
		t.Fatalf("failed cleanup lost retryable assignment: pending=%+v err=%v", pending, err)
	}
	active, err := store.ActiveEndpoints(ctx)
	if err != nil || len(active) != 1 || active[0].EndpointID != endpointID {
		t.Fatalf("failed cleanup marked endpoint inactive: active=%+v err=%v", active, err)
	}

	if err := scheduler.deactivateTicket(candidate, ticket); err != nil {
		t.Fatalf("retry cleanup: %v", err)
	}
	pending, err = store.CleanupAssignments(ctx, ticket.MinerID)
	if err != nil || len(pending) != 0 {
		t.Fatalf("successful retry left assignment pending: pending=%+v err=%v", pending, err)
	}
	active, err = store.ActiveEndpoints(ctx)
	if err != nil || len(active) != 0 {
		t.Fatalf("successful retry left endpoint active: active=%+v err=%v", active, err)
	}
	if candidate.calls != 2 || candidate.endpointID != endpointID || candidate.deploymentID != ticket.DeploymentID {
		t.Fatalf("cleanup retry identity/calls mismatch: %+v", candidate)
	}
}

func routedEndpointID(t *testing.T, h *schedulerHarness, minerID string) string {
	t.Helper()
	for _, replica := range h.scheduler.Router.Replicas("regression.on.miss.computer") {
		if replica.MinerID == minerID {
			return replica.EndpointID
		}
	}
	t.Fatalf("miner %q is not routed", minerID)
	return ""
}

func TestHealthRemovalReleasesMonitorState(t *testing.T) {
	h := newSchedulerHarness(t, []string{"m1", "m2", "m3", "m4"}, 3)
	if _, err := h.scheduler.Deploy(context.Background(), h.request); err != nil {
		t.Fatal(err)
	}
	defer h.cleanup(t)
	removedEndpoint := routedEndpointID(t, h, "m1")
	now := time.Now()
	if action, err := h.scheduler.HandleHealth(context.Background(), h.request.DeploymentID, "regression-m1", "m1", "v1", false, false, false, now); err != nil || action.RemoveFromRouting {
		t.Fatalf("first failure action=%+v err=%v", action, err)
	}
	action, err := h.scheduler.HandleHealth(context.Background(), h.request.DeploymentID, "regression-m1", "m1", "v1", false, false, false, now.Add(time.Second))
	if err != nil || !action.RemoveFromRouting {
		t.Fatalf("second failure action=%+v err=%v", action, err)
	}
	// The removed incarnation's counters must be released: a later observation
	// of the same endpoint key within the rapid window starts from zero
	// instead of inheriting two failures and demanding removal again.
	if got := h.scheduler.monitor().Observe(removedEndpoint, "v1", false, false, false, now.Add(2*time.Second)); got.RemoveFromRouting {
		t.Fatalf("removed endpoint retained rapid-failure state: %+v", got)
	}
}

func TestLegacyObserveHealthRepeatedExactRemovalIsIdempotent(t *testing.T) {
	h := newSchedulerHarness(t, []string{"m1"}, 1)
	if _, err := h.scheduler.Deploy(context.Background(), h.request); err != nil {
		t.Fatal(err)
	}
	deactivated := false
	defer func() {
		if !deactivated {
			h.cleanup(t)
		}
	}()
	replicas := h.scheduler.Router.Replicas("regression.on.miss.computer")
	if len(replicas) != 1 {
		t.Fatalf("active replicas = %+v", replicas)
	}
	replica := replicas[0]
	now := time.Now()
	for attempt := range 2 {
		action, err := h.scheduler.ObserveHealth(
			"regression.on.miss.computer", replica.ID, replica.EndpointID, replica.MinerID, "v1",
			true, false, false, now.Add(time.Duration(attempt)*time.Second),
		)
		if err != nil || !action.RemoveFromRouting || !action.TrustZero {
			t.Fatalf("exact removal attempt %d action=%+v err=%v", attempt+1, action, err)
		}
	}
	if got := h.scheduler.Router.Replicas("regression.on.miss.computer"); len(got) != 0 {
		t.Fatalf("repeated removal republished route: %+v", got)
	}
	if _, err := h.scheduler.ObserveHealth(
		"regression.on.miss.computer", replica.ID, replica.EndpointID, "another-miner", "v1",
		true, false, false, now.Add(2*time.Second),
	); err == nil {
		t.Fatal("cross-incarnation health removal was treated as idempotent")
	}
	if err := h.scheduler.DeactivateDeployment(context.Background(), h.request.DeploymentID); err != nil {
		t.Fatal(err)
	}
	deactivated = true
}

func TestDeactivateDeploymentReleasesMonitorState(t *testing.T) {
	h := newSchedulerHarness(t, []string{"m1", "m2", "m3"}, 3)
	if _, err := h.scheduler.Deploy(context.Background(), h.request); err != nil {
		t.Fatal(err)
	}
	endpoint := routedEndpointID(t, h, "m1")
	now := time.Now()
	if action, err := h.scheduler.HandleHealth(context.Background(), h.request.DeploymentID, "regression-m1", "m1", "v1", false, false, false, now); err != nil || action.RemoveFromRouting {
		t.Fatalf("first failure action=%+v err=%v", action, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := h.scheduler.DeactivateDeployment(ctx, h.request.DeploymentID); err != nil {
		t.Fatal(err)
	}
	if got := h.scheduler.monitor().Observe(endpoint, "v1", false, false, false, now.Add(time.Second)); got.RemoveFromRouting {
		t.Fatalf("deactivated deployment retained endpoint health state: %+v", got)
	}
}
