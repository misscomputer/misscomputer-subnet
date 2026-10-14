// SPDX-License-Identifier: AGPL-3.0-only

package miner

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/durable"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	"github.com/misscomputer/misscomputer-subnet/pkg/sandbox"
)

const (
	sbValidatorHotkey = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
	sbMinerHotkey     = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
	sbCgroup          = "/mc-sandboxes"
)

var (
	sbT0        = time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	sbResources = sandbox.Resources{CPUMillis: 1000, MemoryMiB: 2048, DiskMiB: 10240, PIDs: 512}
	sbBudget    = sandbox.Capacity{CPUMillis: 4000, MemoryMiB: 8192, DiskMiB: 40960, Sandboxes: 4}
)

// sbBackend is an in-memory isolation backend: it records which sandboxes
// exist and fails or refuses on request.
type sbBackend struct {
	mu          sync.Mutex
	live        map[string]bool
	leaseIDs    map[string]string
	reclaimed   int
	created     []string
	destroyed   []string
	unsupported string
	createErr   error
	destroyErr  error
	createGate  chan struct{}
}

func newSBBackend() *sbBackend {
	return &sbBackend{live: map[string]bool{}, leaseIDs: map[string]string{}}
}

func (b *sbBackend) Budget(context.Context) (SandboxBudget, error) {
	return SandboxBudget{Cgroup: sbCgroup, DiskMiB: sbBudget.DiskMiB, Sandboxes: sbBudget.Sandboxes}, nil
}

func (b *sbBackend) Unsupported(protocol.SandboxLeaseV1) string { return b.unsupported }

func (b *sbBackend) Create(ctx context.Context, instance string, lease protocol.SandboxLeaseV1) error {
	if b.createGate != nil {
		<-b.createGate
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.created = append(b.created, instance)
	if b.createErr != nil {
		return b.createErr
	}
	b.live[instance] = true
	b.leaseIDs[instance] = protocol.SandboxLeaseIDV1(lease)
	return nil
}

func (b *sbBackend) Destroy(ctx context.Context, instance string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.destroyed = append(b.destroyed, instance)
	if b.destroyErr != nil {
		return b.destroyErr
	}
	delete(b.live, instance)
	return nil
}

func (b *sbBackend) Instances(ctx context.Context) ([]SandboxInstance, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	var instances []SandboxInstance
	for name := range b.live {
		instances = append(instances, SandboxInstance{Name: name, LeaseID: b.leaseIDs[name]})
	}
	return instances, nil
}

// adopt makes the backend hold a sandbox the lane did not create.
func (b *sbBackend) adopt(instance SandboxInstance) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.live[instance.Name] = true
	b.leaseIDs[instance.Name] = instance.LeaseID
}

func (b *sbBackend) Reclaim(context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.reclaimed++
	return nil
}

func (b *sbBackend) state() (live int, created, destroyed []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.live), append([]string(nil), b.created...), append([]string(nil), b.destroyed...)
}

// sbFixture is one miner with a durable sandbox lane and a validator that
// signs documents for it.
type sbFixture struct {
	t         *testing.T
	validator ed25519.PrivateKey
	miner     ed25519.PrivateKey
	store     *durable.SandboxLeases
	backend   *sbBackend
	lane      *SandboxLane
	root      string
	now       time.Time
}

func writeCgroup(t *testing.T, root, cpu, memory string) {
	t.Helper()
	dir := filepath.Join(root, sbCgroup)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"cpu.max": cpu, "memory.max": memory} {
		if value == "" {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func newSBFixture(t *testing.T) *sbFixture {
	t.Helper()
	f := &sbFixture{
		t:         t,
		validator: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, 32)),
		miner:     ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, 32)),
		backend:   newSBBackend(),
		root:      t.TempDir(),
		now:       sbT0,
	}
	writeCgroup(t, f.root, "400000 100000", fmt.Sprint(8192<<20))
	store, err := durable.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	if f.store, err = store.EnableSandboxLeases(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.lane = f.newLane(f.agent())
	return f
}

func (f *sbFixture) agent() *Agent {
	agent := NewAgent(sbMinerHotkey, nil, f.miner, nil, nil, nil)
	agent.MinerTransport = "http"
	return agent
}

func (f *sbFixture) newLane(agent *Agent) *SandboxLane {
	f.t.Helper()
	lane, err := NewSandboxLane(context.Background(), agent, f.store, f.backend, SandboxLaneConfig{Budget: sbBudget, CgroupRoot: f.root, AgentCgroup: "/system.slice/miner-agent.service", DeploymentCgroup: "/system.slice/deployment-v4.slice"})
	if err != nil {
		f.t.Fatal(err)
	}
	lane.now = func() time.Time { return f.now }
	return lane
}

func (f *sbFixture) request() SandboxRequest {
	return SandboxRequest{
		ValidatorKey: f.validator.Public().(ed25519.PublicKey), CurrentBlock: 101, Network: "mock", NetUID: 24,
		CallerHotkey: sbValidatorHotkey, MinerHotkey: sbMinerHotkey,
	}
}

func (f *sbFixture) binding() *protocol.StaticSubnetBindingV1 {
	return &protocol.StaticSubnetBindingV1{
		Network: "mock", NetUID: 24, ValidatorHotkey: sbValidatorHotkey, MinerHotkey: sbMinerHotkey,
		MinerAxonURL: "http://127.0.0.1:8091", MinerTransport: "http", ChainBlock: 100, Epoch: 1, ExpiresAtBlock: 112,
		ValidatorServicePublicKey: hex.EncodeToString(f.validator.Public().(ed25519.PublicKey)),
		MinerServicePublicKey:     hex.EncodeToString(f.miner.Public().(ed25519.PublicKey)),
	}
}

func stamp(value time.Time) string { return *protocol.StaticTime(value) }

func (f *sbFixture) reservation(n int) protocol.SandboxReservationV1 {
	f.t.Helper()
	r := protocol.SandboxReservationV1{
		Generation: 1, HoldExpiresAt: stamp(f.now.Add(time.Minute)), IssuedAt: stamp(f.now), MinerID: sbMinerHotkey,
		ReservationNonce: fmt.Sprintf("%032x", n), Resources: sbResources, SandboxID: fmt.Sprintf("sbx-%032x", n),
		Schema: protocol.SandboxReservationSchema, SchemaVersion: 1, Subnet: f.binding(), WorkloadKind: sandbox.WorkloadKind,
	}
	if err := protocol.SignSandboxReservationV1(&r, f.validator); err != nil {
		f.t.Fatal(err)
	}
	return r
}

func (f *sbFixture) lease(r protocol.SandboxReservationV1, mutate func(*protocol.SandboxLeaseV1)) protocol.SandboxLeaseV1 {
	f.t.Helper()
	digest, err := protocol.SandboxDigestV1(r)
	if err != nil {
		f.t.Fatal(err)
	}
	image := "sha256:" + strings.Repeat("c4", 32)
	l := protocol.SandboxLeaseV1{
		AssignmentNonce: strings.Repeat("ab", 16), Env: map[string]string{}, Generation: r.Generation, ImageDigest: image,
		ImageReference: "docker.io/library/python@" + image, Isolation: sandbox.IsolationGVisor, IssuedAt: stamp(f.now),
		LeaseExpiresAt: stamp(f.now.Add(10 * time.Minute)), MinerID: r.MinerID,
		Network:           sandbox.NetworkPolicy{Mode: sandbox.NetworkNone, Allow: []string{}},
		ReservationDigest: digest, Resources: r.Resources, SandboxID: r.SandboxID, Schema: protocol.SandboxLeaseSchema, SchemaVersion: 1,
		SecretEnv: sandbox.SecretEnv{Delivery: sandbox.SecretDeliveryNone, Names: []string{}}, Subnet: f.binding(), WorkloadKind: sandbox.WorkloadKind,
	}
	if mutate != nil {
		mutate(&l)
	}
	if err := protocol.SignSandboxLeaseV1(&l, f.validator); err != nil {
		f.t.Fatal(err)
	}
	return l
}

func (f *sbFixture) renewal(l protocol.SandboxLeaseV1, seq uint64) protocol.SandboxRenewalV1 {
	f.t.Helper()
	digest, _ := protocol.SandboxDigestV1(l)
	r := protocol.SandboxRenewalV1{
		Generation: l.Generation, IssuedAt: stamp(f.now), LeaseDigest: digest, LeaseExpiresAt: stamp(f.now.Add(14 * time.Minute)),
		LeaseID: protocol.SandboxLeaseIDV1(l), MinerID: l.MinerID, RenewalSeq: seq, SandboxID: l.SandboxID,
		Schema: protocol.SandboxRenewalSchema, SchemaVersion: 1, Subnet: f.binding(),
	}
	if err := protocol.SignSandboxRenewalV1(&r, f.validator); err != nil {
		f.t.Fatal(err)
	}
	return r
}

func (f *sbFixture) release(r protocol.SandboxReservationV1) protocol.SandboxReleaseV1 {
	f.t.Helper()
	rel := protocol.SandboxReleaseV1{
		Generation: r.Generation, IssuedAt: stamp(f.now), MinerID: r.MinerID, Reason: sandbox.ReleaseCustomerDelete, SandboxID: r.SandboxID,
		Schema: protocol.SandboxReleaseSchema, SchemaVersion: 1, Subnet: f.binding(),
	}
	if err := protocol.SignSandboxReleaseV1(&rel, f.validator); err != nil {
		f.t.Fatal(err)
	}
	return rel
}

// check verifies a receipt the way the validator will: the miner's bound
// service key signed it and it answers exactly the document sent.
func (f *sbFixture) check(receipt protocol.SandboxReceiptV1, err error, schema string, document any, stage, code string) protocol.SandboxReceiptV1 {
	f.t.Helper()
	if err != nil {
		f.t.Fatal(err)
	}
	if err := protocol.VerifySandboxReceiptV1(receipt, f.miner.Public().(ed25519.PublicKey)); err != nil {
		f.t.Fatalf("receipt does not verify: %v", err)
	}
	if err := protocol.SandboxReceiptAnswersV1(receipt, document); err != nil {
		f.t.Fatal(err)
	}
	got := ""
	if receipt.ErrorCode != nil {
		got = *receipt.ErrorCode
	}
	if receipt.Stage != stage || got != code {
		f.t.Fatalf("receipt %s/%q, want %s/%q", receipt.Stage, got, stage, code)
	}
	return receipt
}

func (f *sbFixture) commitHeld(n int, mutate func(*protocol.SandboxLeaseV1)) (protocol.SandboxReservationV1, protocol.SandboxLeaseV1, protocol.SandboxReceiptV1, error) {
	f.t.Helper()
	r := f.reservation(n)
	receipt, err := f.lane.Reserve(context.Background(), r, f.request())
	f.check(receipt, err, protocol.SandboxReservationSchema, r, sandbox.StageHeld, "")
	l := f.lease(r, mutate)
	receipt, err = f.lane.Commit(context.Background(), l, f.request())
	return r, l, receipt, err
}

// Every document through the lane: a hold, a lease whose sandbox starts
// under its deterministic name, a renewal, an exact replay that starts
// nothing, and a release that destroys the sandbox and frees capacity.
func TestSandboxLaneLifecycleSignsReceiptsAndDrivesTheBackend(t *testing.T) {
	f := newSBFixture(t)
	ctx := context.Background()
	r, l, receipt, err := f.commitHeld(1, nil)
	f.check(receipt, err, protocol.SandboxLeaseSchema, l, sandbox.StageReady, "")
	instance := SandboxInstanceName(protocol.SandboxLeaseIDV1(l))
	if live, created, _ := f.backend.state(); live != 1 || len(created) != 1 || created[0] != instance {
		t.Fatalf("after commit: live=%d created=%v, want one %s", live, created, instance)
	}
	if receipt.CapacityActive.Sandboxes != 1 || receipt.CapacityTotal != sbBudget {
		t.Fatalf("lease receipt capacity = %+v of %+v", receipt.CapacityActive, receipt.CapacityTotal)
	}

	receipt, err = f.lane.Commit(ctx, l, f.request())
	f.check(receipt, err, protocol.SandboxLeaseSchema, l, sandbox.StageReady, "")
	if _, created, _ := f.backend.state(); len(created) != 1 {
		t.Fatalf("a replayed lease created %d sandboxes", len(created))
	}

	f.now = f.now.Add(time.Minute)
	renewal := f.renewal(l, 1)
	receipt, err = f.lane.Renew(ctx, renewal, f.request())
	if f.check(receipt, err, protocol.SandboxRenewalSchema, renewal, sandbox.StageReady, "").RenewalSeq != 1 {
		t.Fatalf("renewal receipt seq = %d", receipt.RenewalSeq)
	}

	release := f.release(r)
	receipt, err = f.lane.Release(ctx, release, f.request())
	f.check(receipt, err, protocol.SandboxReleaseSchema, release, sandbox.StageReleased, "")
	if live, _, destroyed := f.backend.state(); live != 0 || len(destroyed) != 1 || destroyed[0] != instance {
		t.Fatalf("after release: live=%d destroyed=%v", live, destroyed)
	}
	if receipt.CapacityActive.Sandboxes != 0 || receipt.CapacityHeld.Sandboxes != 0 {
		t.Fatalf("release receipt still holds capacity: %+v %+v", receipt.CapacityHeld, receipt.CapacityActive)
	}
}

// A lease the lane or backend cannot run exactly, or whose create fails,
// answers failed with the right attribution, leaves no sandbox, and frees
// its capacity. A backend cannot relabel its own fault as a non-fault.
func TestSandboxLeaseThatCannotStartIsRefusedAndFreed(t *testing.T) {
	sealed := func(l *protocol.SandboxLeaseV1) {
		bundle := "sha256:" + strings.Repeat("d5", 32)
		l.SecretEnv = sandbox.SecretEnv{Delivery: sandbox.SecretDeliverySealedBundle, Names: []string{"API_KEY"}, BundleDigest: &bundle}
	}
	for _, test := range []struct {
		name        string
		mutate      func(*protocol.SandboxLeaseV1)
		unsupported string
		createErr   error
		code        string
		creates     int
	}{
		{name: "sealed secret delivery", mutate: sealed, code: "secret_delivery_unsupported"},
		{name: "backend cannot isolate", unsupported: "isolation_unsupported", code: "isolation_unsupported"},
		{name: "backend relabels a fault", unsupported: "miner_restart", code: "runtime_start_failed"},
		{name: "image unavailable", createErr: &SandboxRefusal{Code: "image_unavailable"}, code: "image_unavailable", creates: 1},
		{name: "refusal with a fault code", createErr: &SandboxRefusal{Code: "miner_restart"}, code: "runtime_start_failed", creates: 1},
		{name: "create fails", createErr: errors.New("runtime exploded"), code: "runtime_start_failed", creates: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newSBFixture(t)
			f.backend.unsupported, f.backend.createErr = test.unsupported, test.createErr
			_, l, receipt, err := f.commitHeld(1, test.mutate)
			f.check(receipt, err, protocol.SandboxLeaseSchema, l, sandbox.StageFailed, test.code)
			live, created, _ := f.backend.state()
			if live != 0 || len(created) != test.creates {
				t.Fatalf("live=%d creates=%d, want 0 and %d", live, len(created), test.creates)
			}
			if receipt.CapacityActive.Sandboxes != 0 {
				t.Fatalf("failed lease still consumes capacity: %+v", receipt.CapacityActive)
			}
			again, err := f.lane.Commit(context.Background(), l, f.request())
			f.check(again, err, protocol.SandboxLeaseSchema, l, sandbox.StageFailed, test.code)
		})
	}
}

// A sandbox whose destroy fails keeps consuming capacity until a later
// sweep destroys it.
func TestSandboxDestroyFailureKeepsCapacityUntilSweep(t *testing.T) {
	f := newSBFixture(t)
	f.backend.createErr = errors.New("runtime exploded")
	f.backend.destroyErr = errors.New("daemon down")
	_, l, receipt, err := f.commitHeld(1, nil)
	f.check(receipt, err, protocol.SandboxLeaseSchema, l, sandbox.StageFailed, "runtime_start_failed")
	if receipt.CapacityActive.Sandboxes != 1 {
		t.Fatalf("an undestroyed sandbox freed its capacity: %+v", receipt.CapacityActive)
	}
	if err := f.lane.Sweep(context.Background()); err == nil {
		t.Fatal("sweep reported success while destroy fails")
	}
	f.backend.destroyErr = nil
	if err := f.lane.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, active, err := f.store.Occupancy(context.Background(), f.now); err != nil || active.Sandboxes != 0 {
		t.Fatalf("after a successful sweep active=%+v err=%v", active, err)
	}
}

// A client disconnect after the lease was saved must not abort a successful
// create or prevent cleanup of a failed one.
func TestSandboxCommitFinishesAfterRequestCancellation(t *testing.T) {
	for _, test := range []struct {
		name      string
		createErr error
		stage     string
		code      string
		status    string
		active    int
	}{
		{name: "create succeeds", stage: sandbox.StageReady, status: "running", active: 1},
		{name: "create fails", createErr: errors.New("runtime failed to start"), stage: sandbox.StageFailed, code: "runtime_start_failed", status: "failed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newSBFixture(t)
			ctx := context.Background()
			r := f.reservation(1)
			receipt, err := f.lane.Reserve(ctx, r, f.request())
			f.check(receipt, err, protocol.SandboxReservationSchema, r, sandbox.StageHeld, "")
			l := f.lease(r, nil)
			leaseID := protocol.SandboxLeaseIDV1(l)
			f.backend.createGate = make(chan struct{})
			f.backend.createErr = test.createErr
			requestCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			type result struct {
				receipt protocol.SandboxReceiptV1
				err     error
			}
			done := make(chan result, 1)
			go func() {
				receipt, err := f.lane.Commit(requestCtx, l, f.request())
				done <- result{receipt, err}
			}()
			waitLease(t, f, leaseID, "pending")
			cancel()
			close(f.backend.createGate)
			got := <-done
			f.check(got.receipt, got.err, protocol.SandboxLeaseSchema, l, test.stage, test.code)
			if record, found, err := f.store.Lease(ctx, leaseID); err != nil || !found || record.Status != test.status {
				t.Fatalf("cancelled request left lease at %q (found=%v, err=%v), want %s", record.Status, found, err, test.status)
			}
			if _, active, err := f.store.Occupancy(ctx, f.now); err != nil || active.Sandboxes != test.active {
				t.Fatalf("cancelled request left active capacity %+v, err=%v; want %d sandboxes", active, err, test.active)
			}
		})
	}
}

// A crash after the durable pending write can be resumed by the same signed
// lease rather than returning accepted forever without a sandbox.
func TestSandboxCommitReplayStartsOrphanedPendingLease(t *testing.T) {
	f := newSBFixture(t)
	ctx := context.Background()
	r := f.reservation(1)
	receipt, err := f.lane.Reserve(ctx, r, f.request())
	f.check(receipt, err, protocol.SandboxReservationSchema, r, sandbox.StageHeld, "")
	l := f.lease(r, nil)
	if outcome, err := f.store.CommitLease(ctx, l, f.now); err != nil || !outcome.Start {
		t.Fatalf("stage pending lease: outcome=%+v err=%v", outcome, err)
	}
	receipt, err = f.lane.Commit(ctx, l, f.request())
	f.check(receipt, err, protocol.SandboxLeaseSchema, l, sandbox.StageReady, "")
	if live, created, _ := f.backend.state(); live != 1 || len(created) != 1 {
		t.Fatalf("replayed pending lease: live=%d creates=%v, want one live sandbox", live, created)
	}
}

// A create that completes after the hard expiry cannot turn a durable
// pending lease into a ready sandbox, even if admission preceded expiry.
func TestSandboxCreateFinishingAfterExpiryDestroysSandbox(t *testing.T) {
	f := newSBFixture(t)
	ctx := context.Background()
	r := f.reservation(1)
	if receipt, err := f.lane.Reserve(ctx, r, f.request()); err != nil || receipt.Stage != sandbox.StageHeld {
		t.Fatalf("reserve: stage=%s err=%v", receipt.Stage, err)
	}
	l := f.lease(r, func(l *protocol.SandboxLeaseV1) {
		l.LeaseExpiresAt = stamp(f.now.Add(2 * time.Second))
	})
	leaseID := protocol.SandboxLeaseIDV1(l)
	var clock atomic.Int64
	clock.Store(f.now.UnixNano())
	f.lane.now = func() time.Time { return time.Unix(0, clock.Load()).UTC() }
	f.backend.createGate = make(chan struct{})
	type result struct {
		receipt protocol.SandboxReceiptV1
		err     error
	}
	done := make(chan result, 1)
	go func() {
		receipt, err := f.lane.Commit(ctx, l, f.request())
		done <- result{receipt, err}
	}()
	waitLease(t, f, leaseID, "pending")
	clock.Store(f.now.Add(2 * time.Second).UnixNano())
	close(f.backend.createGate)
	got := <-done
	f.check(got.receipt, got.err, protocol.SandboxLeaseSchema, l, sandbox.StageExpired, "")
	if live, _, destroyed := f.backend.state(); live != 0 || len(destroyed) != 1 {
		t.Fatalf("expired create left sandbox running: live=%d destroyed=%v", live, destroyed)
	}
	if record, found, err := f.store.Lease(ctx, leaseID); err != nil || !found || record.Status != "expired" {
		t.Fatalf("expired create durable state: %+v found=%v err=%v", record, found, err)
	}
}

// A release that lands while the sandbox is still being created fences the
// identity at once; the sandbox is destroyed after create returns and the
// lease ends released, not running.
func TestSandboxReleaseDuringCreateDestroysTheSandbox(t *testing.T) {
	f := newSBFixture(t)
	ctx := context.Background()
	r := f.reservation(1)
	receipt, err := f.lane.Reserve(ctx, r, f.request())
	f.check(receipt, err, protocol.SandboxReservationSchema, r, sandbox.StageHeld, "")
	l := f.lease(r, nil)
	leaseID := protocol.SandboxLeaseIDV1(l)
	f.backend.createGate = make(chan struct{})

	type result struct {
		receipt protocol.SandboxReceiptV1
		err     error
	}
	committed, released := make(chan result, 1), make(chan result, 1)
	go func() {
		receipt, err := f.lane.Commit(ctx, l, f.request())
		committed <- result{receipt, err}
	}()
	waitLease(t, f, leaseID, "pending")
	release := f.release(r)
	go func() {
		receipt, err := f.lane.Release(ctx, release, f.request())
		released <- result{receipt, err}
	}()
	waitLease(t, f, leaseID, "cleanup")
	close(f.backend.createGate)

	commit := <-committed
	f.check(commit.receipt, commit.err, protocol.SandboxLeaseSchema, l, sandbox.StageReleased, "")
	rel := <-released
	f.check(rel.receipt, rel.err, protocol.SandboxReleaseSchema, release, sandbox.StageReleased, "")
	if live, created, destroyed := f.backend.state(); live != 0 || len(created) != 1 || len(destroyed) == 0 {
		t.Fatalf("live=%d created=%v destroyed=%v", live, created, destroyed)
	}
	if record, _, _ := f.store.Lease(ctx, leaseID); record.Status != "released" {
		t.Fatalf("lease status %q, want released", record.Status)
	}
}

func waitLease(t *testing.T, f *sbFixture, leaseID, status string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if record, found, err := f.store.Lease(context.Background(), leaseID); err == nil && found && record.Status == status {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("lease never reached %s", status)
}

// On restart every sandbox that may exist is destroyed before the lane
// serves, and its lease answers failed/miner_restart (attributable).
func TestSandboxRecoverDestroysEverySandbox(t *testing.T) {
	f := newSBFixture(t)
	_, l, receipt, err := f.commitHeld(1, nil)
	f.check(receipt, err, protocol.SandboxLeaseSchema, l, sandbox.StageReady, "")
	// A sandbox the durable state never recorded, such as one left by a
	// lost state database, is destroyed as well.
	f.backend.adopt(SandboxInstance{Name: "miss-unrecorded-000000000000", LeaseID: ""})
	restarted := f.newLane(f.agent())
	if err := restarted.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if live, _, _ := f.backend.state(); live != 0 {
		t.Fatalf("%d sandboxes survive restart recovery", live)
	}
	if f.backend.reclaimed != 1 {
		t.Fatalf("restart recovery reclaimed backend storage %d times, want once", f.backend.reclaimed)
	}
	again, err := restarted.Commit(context.Background(), l, f.request())
	f.check(again, err, protocol.SandboxLeaseSchema, l, sandbox.StageFailed, "miner_restart")
}

// Documents not addressed to this agent's exact service identity are
// rejected before any durable change.
func TestSandboxLaneRejectsDocumentsForAnotherAgent(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*sbFixture) (*SandboxLane, SandboxRequest)
	}{
		{name: "another miner service key", mutate: func(f *sbFixture) (*SandboxLane, SandboxRequest) {
			agent := f.agent()
			agent.SigningKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x33}, 32))
			return f.newLane(agent), f.request()
		}},
		{name: "another transport", mutate: func(f *sbFixture) (*SandboxLane, SandboxRequest) {
			agent := f.agent()
			agent.MinerTransport, agent.MinerTLSCertificateSHA256 = "https", strings.Repeat("3a", 32)
			return f.newLane(agent), f.request()
		}},
		{name: "another validator key", mutate: func(f *sbFixture) (*SandboxLane, SandboxRequest) {
			request := f.request()
			request.ValidatorKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x44}, 32)).Public().(ed25519.PublicKey)
			return f.lane, request
		}},
		{name: "another caller", mutate: func(f *sbFixture) (*SandboxLane, SandboxRequest) {
			request := f.request()
			request.CallerHotkey = sbMinerHotkey
			return f.lane, request
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newSBFixture(t)
			lane, request := test.mutate(f)
			if _, err := lane.Reserve(context.Background(), f.reservation(1), request); err == nil {
				t.Fatal("reservation for another identity was accepted")
			}
			if held, _, err := f.store.Occupancy(context.Background(), f.now); err != nil || held.Sandboxes != 0 {
				t.Fatalf("rejected reservation left held=%+v err=%v", held, err)
			}
		})
	}
}

// The lane, and so the capability, exists only with a backend that runs
// sandboxes in a dedicated cgroup v2 subtree with finite CPU and memory
// limits covering the configured budget, disjoint from the agent's and the
// web replicas' cgroups.
func TestNewSandboxLaneRequiresAnEnforcedDedicatedBudget(t *testing.T) {
	for _, test := range []struct {
		name      string
		cpu, mem  string
		agentPath string
		webPath   string
		omitAgent bool
		omitWeb   bool
		budget    func(*sandbox.Capacity)
		noBackend bool
		ok        bool
	}{
		{name: "enforced budget covers the configured one", cpu: "400000 100000", mem: fmt.Sprint(8192 << 20), ok: true},
		{name: "missing agent path", cpu: "400000 100000", mem: fmt.Sprint(8192 << 20), omitAgent: true},
		{name: "missing web path", cpu: "400000 100000", mem: fmt.Sprint(8192 << 20), omitWeb: true},
		{name: "root as agent path", cpu: "400000 100000", mem: fmt.Sprint(8192 << 20), agentPath: "/"},
		{name: "no backend", cpu: "400000 100000", mem: fmt.Sprint(8192 << 20), noBackend: true},
		{name: "unlimited cpu", cpu: "max 100000", mem: fmt.Sprint(8192 << 20)},
		{name: "unlimited memory", cpu: "400000 100000", mem: "max"},
		{name: "no cgroup files", cpu: "", mem: ""},
		{name: "cpu below budget", cpu: "200000 100000", mem: fmt.Sprint(8192 << 20)},
		{name: "memory below budget", cpu: "400000 100000", mem: fmt.Sprint(4096 << 20)},
		{name: "disk above backend limit", cpu: "400000 100000", mem: fmt.Sprint(8192 << 20), budget: func(c *sandbox.Capacity) { c.DiskMiB++ }},
		{name: "is the web replica cgroup", cpu: "400000 100000", mem: fmt.Sprint(8192 << 20), webPath: sbCgroup},
		{name: "contains the agent cgroup", cpu: "400000 100000", mem: fmt.Sprint(8192 << 20), agentPath: sbCgroup + "/agent"},
		{name: "zero budget component", cpu: "400000 100000", mem: fmt.Sprint(8192 << 20), budget: func(c *sandbox.Capacity) { c.Sandboxes = 0 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newSBFixture(t)
			root := t.TempDir()
			writeCgroup(t, root, test.cpu, test.mem)
			budget := sbBudget
			if test.budget != nil {
				test.budget(&budget)
			}
			var backend SandboxBackend = f.backend
			if test.noBackend {
				backend = nil
			}
			agentPath, webPath := "/system.slice/miner-agent.service", "/system.slice/deployment-v4.slice"
			if test.agentPath != "" {
				agentPath = test.agentPath
			}
			if test.webPath != "" {
				webPath = test.webPath
			}
			if test.omitAgent {
				agentPath = ""
			}
			if test.omitWeb {
				webPath = ""
			}
			_, err := NewSandboxLane(context.Background(), f.agent(), f.store, backend, SandboxLaneConfig{
				Budget: budget, CgroupRoot: root, AgentCgroup: agentPath, DeploymentCgroup: webPath,
			})
			if (err == nil) != test.ok {
				t.Fatalf("NewSandboxLane error = %v, want ok=%t", err, test.ok)
			}
		})
	}
}

// A cgroup limit read through a symlink can describe a different subtree
// (or an ordinary file), while the sandbox subtree remains unlimited.
func TestNewSandboxLaneRejectsSymlinkedCgroupLimits(t *testing.T) {
	for _, name := range []string{"directory", "cpu.max", "memory.max"} {
		t.Run(name, func(t *testing.T) {
			f := newSBFixture(t)
			root := t.TempDir()
			writeCgroup(t, root, "400000 100000", fmt.Sprint(8192<<20))
			dir := filepath.Join(root, sbCgroup)
			if name == "directory" {
				outside := filepath.Join(t.TempDir(), "finite-cgroup")
				if err := os.Rename(dir, outside); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, dir); err != nil {
					t.Fatal(err)
				}
			} else {
				limit := filepath.Join(dir, name)
				outside := filepath.Join(t.TempDir(), name)
				if err := os.Rename(limit, outside); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, limit); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := NewSandboxLane(context.Background(), f.agent(), f.store, f.backend, SandboxLaneConfig{
				Budget: sbBudget, CgroupRoot: root, AgentCgroup: "/system.slice/miner-agent.service", DeploymentCgroup: "/system.slice/deployment-v4.slice",
			}); err == nil {
				t.Fatal("accepted finite limits outside the selected sandbox cgroup")
			}
		})
	}
}

// A release receipt tells the validator the slot is free, so it is signed
// only once every sandbox of the identity is destroyed. While a destroy
// fails, the release answers ErrSandboxCleanupPending (no receipt), the
// fence stays durable and the capacity stays consumed; a replay of the
// same release after the backend recovers destroys the sandbox and is
// acknowledged.
func TestSandboxReleaseIsAcknowledgedOnlyAfterDestroy(t *testing.T) {
	f := newSBFixture(t)
	ctx := context.Background()
	r, l, receipt, err := f.commitHeld(1, nil)
	f.check(receipt, err, protocol.SandboxLeaseSchema, l, sandbox.StageReady, "")
	f.backend.destroyErr = errors.New("daemon down")
	release := f.release(r)
	if receipt, err := f.lane.Release(ctx, release, f.request()); !errors.Is(err, ErrSandboxCleanupPending) {
		t.Fatalf("release with a failing destroy answered %s/%v, want ErrSandboxCleanupPending", receipt.Stage, err)
	}
	if live, _, _ := f.backend.state(); live != 1 {
		t.Fatalf("live sandboxes = %d, want the undestroyed one", live)
	}
	if _, active, err := f.store.Occupancy(ctx, f.now); err != nil || active.Sandboxes != 1 {
		t.Fatalf("capacity after a failed destroy: active=%+v err=%v", active, err)
	}
	// The fence is durable even without a receipt.
	again, err := f.lane.Reserve(ctx, f.reservation(1), f.request())
	f.check(again, err, protocol.SandboxReservationSchema, f.reservation(1), sandbox.StageRefused, "released_before_use")

	f.backend.destroyErr = nil
	receipt, err = f.lane.Release(ctx, release, f.request())
	f.check(receipt, err, protocol.SandboxReleaseSchema, release, sandbox.StageReleased, "")
	if live, _, _ := f.backend.state(); live != 0 || receipt.CapacityActive.Sandboxes != 0 {
		t.Fatalf("after the acknowledged release: live=%d active=%+v", live, receipt.CapacityActive)
	}
}

// Sweep destroys every backend sandbox without a live lease: one whose
// lease is unknown, one whose lease is terminal, and one whose labels do not
// tie it to its name. A sandbox whose lease is live is kept.
func TestSandboxSweepDestroysOrphansAndKeepsLiveSandboxes(t *testing.T) {
	f := newSBFixture(t)
	ctx := context.Background()
	_, live, receipt, err := f.commitHeld(1, nil)
	f.check(receipt, err, protocol.SandboxLeaseSchema, live, sandbox.StageReady, "")
	released, gone, receipt, err := f.commitHeld(2, func(l *protocol.SandboxLeaseV1) { l.AssignmentNonce = strings.Repeat("cd", 16) })
	f.check(receipt, err, protocol.SandboxLeaseSchema, gone, sandbox.StageReady, "")
	release := f.release(released)
	receipt, err = f.lane.Release(ctx, release, f.request())
	f.check(receipt, err, protocol.SandboxReleaseSchema, release, sandbox.StageReleased, "")

	liveName := SandboxInstanceName(protocol.SandboxLeaseIDV1(live))
	unknownLease := strings.Replace(protocol.SandboxLeaseIDV1(live), "-g1-", "-g7-", 1)
	orphans := []SandboxInstance{
		{Name: SandboxInstanceName(unknownLease), LeaseID: unknownLease},
		{Name: SandboxInstanceName(protocol.SandboxLeaseIDV1(gone)), LeaseID: protocol.SandboxLeaseIDV1(gone)},
		{Name: "miss-mislabelled-000000000000", LeaseID: protocol.SandboxLeaseIDV1(live)},
	}
	for _, orphan := range orphans {
		f.backend.adopt(orphan)
	}
	if err := f.lane.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	f.backend.mu.Lock()
	defer f.backend.mu.Unlock()
	if len(f.backend.live) != 1 || !f.backend.live[liveName] {
		t.Fatalf("after sweep live sandboxes = %v, want only %s", f.backend.live, liveName)
	}
}
