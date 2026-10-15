// SPDX-License-Identifier: AGPL-3.0-only

package sandboxbackend_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/durable"
	"github.com/misscomputer/misscomputer-subnet/pkg/miner"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	"github.com/misscomputer/misscomputer-subnet/pkg/sandbox"
	"github.com/misscomputer/misscomputer-subnet/pkg/sandboxbackend"
)

// integrationImage runs /pause forever, so a sandbox stays up with the
// image's own command. It is a multi-platform index digest, which also
// proves digest verification of an index pull.
const integrationImage = "registry.k8s.io/pause@sha256:ee6521f290b2168b6e0935a181d4cff9be1ac3f505666ef0e3c98fae8199917a"

// exitingImage's default command is "sh", which exits at once without
// stdin: a workload that exits by itself (contract D11).
const exitingImage = "registry.k8s.io/e2e-test-images/busybox@sha256:a9155b13325b2abef48e71de77bb8ac015412a566829f621d06bfae5c699b1b9"

// TestGVisorLaneOnDisposableHost drives the real sandbox lane through the
// real backend on a provisioned disposable host: a dedicated Docker daemon
// with runsc registered, a finite sandbox slice and an XFS project-quota
// data root. It runs only when MC_SANDBOX_BACKEND_IT=1 and must never run
// on a miner, validator or shared host. The host is described by
// MC_SANDBOX_DOCKER_HOST, MC_SANDBOX_RUNTIME, MC_SANDBOX_RUNSC_PATH,
// MC_SANDBOX_RUNSC_SHA256, MC_SANDBOX_SENTRY_PATH, MC_SANDBOX_SENTRY_SHA256,
// MC_SANDBOX_DATA_ROOT, MC_SANDBOX_SLICE and MC_SANDBOX_DEPLOYMENT_CGROUP.
func TestGVisorLaneOnDisposableHost(t *testing.T) {
	if os.Getenv("MC_SANDBOX_BACKEND_IT") != "1" {
		t.Skip("set MC_SANDBOX_BACKEND_IT=1 on a disposable provisioned host")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	config := sandboxbackend.Config{
		DockerHost: os.Getenv("MC_SANDBOX_DOCKER_HOST"), Runtime: os.Getenv("MC_SANDBOX_RUNTIME"),
		RunscPath: os.Getenv("MC_SANDBOX_RUNSC_PATH"), RunscSHA256: os.Getenv("MC_SANDBOX_RUNSC_SHA256"),
		SentryPath: os.Getenv("MC_SANDBOX_SENTRY_PATH"), SentrySHA256: os.Getenv("MC_SANDBOX_SENTRY_SHA256"),
		DataRoot: os.Getenv("MC_SANDBOX_DATA_ROOT"), Slice: os.Getenv("MC_SANDBOX_SLICE"),
		DiskMiB: sandbox.MinDiskMiB, Sandboxes: 1, ImageMaxMiB: 64, LogMiB: 4, PIDsMax: sandbox.MinPIDs,
	}
	backend, err := sandboxbackend.Open(ctx, config)
	if err != nil {
		t.Fatalf("backend preflight on the provisioned host: %v", err)
	}
	t.Cleanup(func() {
		instances, _ := backend.Instances(context.Background())
		for _, instance := range instances {
			if err := backend.Destroy(context.Background(), instance.Name); err != nil {
				t.Errorf("cleanup %s: %v", instance.Name, err)
			}
		}
	})
	sliceCgroup, err := sandboxbackend.SliceCgroup(config.Slice)
	if err != nil {
		t.Fatal(err)
	}
	cpuMillis, memoryMiB := sliceLimits(t, sliceCgroup)
	budget := sandbox.Capacity{CPUMillis: cpuMillis, MemoryMiB: memoryMiB, DiskMiB: config.DiskMiB, Sandboxes: 1}
	resources := sandbox.Resources{CPUMillis: sandbox.MinCPUMillis, MemoryMiB: sandbox.MinMemoryMiB, DiskMiB: sandbox.MinDiskMiB, PIDs: sandbox.MinPIDs}

	h := newLaneHost(t, ctx, backend, budget)
	r := h.reservation(resources)
	receipt, err := h.lane.Reserve(ctx, r, h.request())
	h.expect(receipt, err, sandbox.StageHeld)
	lease := h.lease(r, integrationImage)
	receipt, err = h.lane.Commit(ctx, lease, h.request())
	h.expect(receipt, err, sandbox.StageReady)
	instance := miner.SandboxInstanceName(protocol.SandboxLeaseIDV1(lease))
	instances, err := backend.Instances(ctx)
	if err != nil || len(instances) != 1 || instances[0].Name != instance {
		t.Fatalf("sandboxes after commit = %+v, %v", instances, err)
	}
	// An exact replay answers from durable state; Create is idempotent.
	if err := backend.Create(ctx, instance, lease); err != nil {
		t.Fatalf("replayed create on the live sandbox: %v", err)
	}

	// A release is acknowledged only once the sandbox is gone.
	release := h.release(r)
	receipt, err = h.lane.Release(ctx, release, h.request())
	h.expect(receipt, err, sandbox.StageReleased)
	if instances, err := backend.Instances(ctx); err != nil || len(instances) != 0 {
		t.Fatalf("sandboxes after release = %+v, %v", instances, err)
	}

	// A workload that exits by itself is served, not a miner fault (D11),
	// and keeps its sandbox until release.
	r = h.reservation(resources)
	receipt, err = h.lane.Reserve(ctx, r, h.request())
	h.expect(receipt, err, sandbox.StageHeld)
	receipt, err = h.lane.Commit(ctx, h.lease(r, exitingImage), h.request())
	h.expect(receipt, err, sandbox.StageReady)
	if instances, err := backend.Instances(ctx); err != nil || len(instances) != 1 {
		t.Fatalf("sandboxes after an exited workload = %+v, %v", instances, err)
	}
	receipt, err = h.lane.Release(ctx, h.release(r), h.request())
	h.expect(receipt, err, sandbox.StageReleased)

	// A restart destroys every sandbox before the lane serves again.
	r = h.reservation(resources)
	receipt, err = h.lane.Reserve(ctx, r, h.request())
	h.expect(receipt, err, sandbox.StageHeld)
	lease = h.lease(r, integrationImage)
	receipt, err = h.lane.Commit(ctx, lease, h.request())
	h.expect(receipt, err, sandbox.StageReady)
	restarted := h.newLane(backend, budget)
	if err := restarted.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	if instances, err := backend.Instances(ctx); err != nil || len(instances) != 0 {
		t.Fatalf("sandboxes after restart recovery = %+v, %v", instances, err)
	}
	receipt, err = restarted.Commit(ctx, lease, h.request())
	h.expect(receipt, err, sandbox.StageFailed)
}

func sliceLimits(t *testing.T, cgroup string) (cpuMillis, memoryMiB int) {
	t.Helper()
	dir := filepath.Join(miner.DefaultCgroupRoot, cgroup)
	cpu, err := os.ReadFile(filepath.Join(dir, "cpu.max"))
	if err != nil {
		t.Fatal(err)
	}
	memory, err := os.ReadFile(filepath.Join(dir, "memory.max"))
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(cpu))
	quota, _ := strconv.Atoi(fields[0])
	period, _ := strconv.Atoi(fields[1])
	bytes, _ := strconv.Atoi(strings.TrimSpace(string(memory)))
	return quota * 1000 / period, bytes >> 20
}

// laneHost is one miner with the real lane over the real backend, and a
// validator that signs documents for it.
type laneHost struct {
	t         *testing.T
	validator ed25519.PrivateKey
	minerKey  ed25519.PrivateKey
	store     *durable.SandboxLeases
	lane      *miner.SandboxLane
	now       time.Time
	sandboxes int
}

const (
	itValidatorHotkey = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
	itMinerHotkey     = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
)

func newLaneHost(t *testing.T, ctx context.Context, backend miner.SandboxBackend, budget sandbox.Capacity) *laneHost {
	t.Helper()
	store, err := durable.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	leases, err := store.EnableSandboxLeases(ctx)
	if err != nil {
		t.Fatal(err)
	}
	h := &laneHost{
		t: t, store: leases, now: time.Now().UTC().Truncate(time.Second),
		validator: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, 32)),
		minerKey:  ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, 32)),
	}
	h.lane = h.newLane(backend, budget)
	return h
}

func (h *laneHost) newLane(backend miner.SandboxBackend, budget sandbox.Capacity) *miner.SandboxLane {
	h.t.Helper()
	raw, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		h.t.Fatal(err)
	}
	self := strings.TrimPrefix(strings.TrimSpace(string(raw)), "0::")
	agent := miner.NewAgent(itMinerHotkey, nil, h.minerKey, nil, nil, nil)
	agent.MinerTransport = "http"
	lane, err := miner.NewSandboxLane(context.Background(), agent, h.store, backend, miner.SandboxLaneConfig{
		Budget: budget, CgroupRoot: miner.DefaultCgroupRoot, AgentCgroup: self, DeploymentCgroup: os.Getenv("MC_SANDBOX_DEPLOYMENT_CGROUP"),
	})
	if err != nil {
		h.t.Fatalf("sandbox lane on the provisioned host: %v", err)
	}
	return lane
}

func (h *laneHost) request() miner.SandboxRequest {
	return miner.SandboxRequest{
		ValidatorKey: h.validator.Public().(ed25519.PublicKey), CurrentBlock: 101, Network: "mock", NetUID: 24,
		CallerHotkey: itValidatorHotkey, MinerHotkey: itMinerHotkey,
	}
}

func (h *laneHost) binding() *protocol.StaticSubnetBindingV1 {
	return &protocol.StaticSubnetBindingV1{
		Network: "mock", NetUID: 24, ValidatorHotkey: itValidatorHotkey, MinerHotkey: itMinerHotkey,
		MinerAxonURL: "http://127.0.0.1:8091", MinerTransport: "http", ChainBlock: 100, Epoch: 1, ExpiresAtBlock: 112,
		ValidatorServicePublicKey: hex.EncodeToString(h.validator.Public().(ed25519.PublicKey)),
		MinerServicePublicKey:     hex.EncodeToString(h.minerKey.Public().(ed25519.PublicKey)),
	}
}

func (h *laneHost) reservation(resources sandbox.Resources) protocol.SandboxReservationV1 {
	h.t.Helper()
	h.sandboxes++
	nonce := fmt.Sprintf("%016x%016x", h.now.UnixNano(), h.sandboxes)
	r := protocol.SandboxReservationV1{
		Generation: 1, HoldExpiresAt: *protocol.StaticTime(h.now.Add(time.Minute)), IssuedAt: *protocol.StaticTime(h.now),
		MinerID: itMinerHotkey, ReservationNonce: nonce, Resources: resources, SandboxID: "sbx-" + nonce,
		Schema: protocol.SandboxReservationSchema, SchemaVersion: 1, Subnet: h.binding(), WorkloadKind: sandbox.WorkloadKind,
	}
	if err := protocol.SignSandboxReservationV1(&r, h.validator); err != nil {
		h.t.Fatal(err)
	}
	return r
}

func (h *laneHost) lease(r protocol.SandboxReservationV1, reference string) protocol.SandboxLeaseV1 {
	h.t.Helper()
	digest, err := protocol.SandboxDigestV1(r)
	if err != nil {
		h.t.Fatal(err)
	}
	image, _ := sandbox.ImageDigest(reference)
	l := protocol.SandboxLeaseV1{
		AssignmentNonce: r.ReservationNonce, Env: map[string]string{}, Generation: 1, ImageDigest: image,
		ImageReference: reference, Isolation: sandbox.IsolationGVisor, IssuedAt: *protocol.StaticTime(h.now),
		LeaseExpiresAt: *protocol.StaticTime(h.now.Add(10 * time.Minute)), MinerID: itMinerHotkey,
		Network:           sandbox.NetworkPolicy{Mode: sandbox.NetworkNone, Allow: []string{}},
		ReservationDigest: digest, Resources: r.Resources, SandboxID: r.SandboxID, Schema: protocol.SandboxLeaseSchema, SchemaVersion: 1,
		SecretEnv: sandbox.SecretEnv{Delivery: sandbox.SecretDeliveryNone, Names: []string{}}, Subnet: h.binding(), WorkloadKind: sandbox.WorkloadKind,
	}
	if err := protocol.SignSandboxLeaseV1(&l, h.validator); err != nil {
		h.t.Fatal(err)
	}
	return l
}

func (h *laneHost) release(r protocol.SandboxReservationV1) protocol.SandboxReleaseV1 {
	h.t.Helper()
	release := protocol.SandboxReleaseV1{
		Generation: r.Generation, IssuedAt: *protocol.StaticTime(h.now), MinerID: r.MinerID, Reason: sandbox.ReleaseCustomerDelete,
		SandboxID: r.SandboxID, Schema: protocol.SandboxReleaseSchema, SchemaVersion: 1, Subnet: h.binding(),
	}
	if err := protocol.SignSandboxReleaseV1(&release, h.validator); err != nil {
		h.t.Fatal(err)
	}
	return release
}

func (h *laneHost) expect(receipt protocol.SandboxReceiptV1, err error, stage string) {
	h.t.Helper()
	if err != nil {
		h.t.Fatal(err)
	}
	if err := protocol.VerifySandboxReceiptV1(receipt, h.minerKey.Public().(ed25519.PublicKey)); err != nil {
		h.t.Fatalf("receipt does not verify: %v", err)
	}
	if receipt.Stage != stage {
		code := ""
		if receipt.ErrorCode != nil {
			code = *receipt.ErrorCode
		}
		h.t.Fatalf("receipt %s/%s, want %s", receipt.Stage, code, stage)
	}
}
