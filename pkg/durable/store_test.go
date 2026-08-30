// SPDX-License-Identifier: AGPL-3.0-only

package durable

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
)

func TestSQLitePersistsReplayTrustAssignmentEndpointAndObservation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	accepted, err := store.ReserveReplay(ctx, "assignment", "nonce", time.Now().Add(time.Minute))
	if err != nil || !accepted {
		t.Fatalf("first replay reservation: accepted=%v err=%v", accepted, err)
	}
	if accepted, err := store.ReserveReplay(ctx, "assignment", "expired", time.Now().Add(-time.Second)); err == nil || accepted {
		t.Fatalf("past replay expiry accepted: accepted=%v err=%v", accepted, err)
	}
	ticket := protocol.Ticket{DeploymentID: "app", Generation: 1, MinerID: "miner", AssignmentNonce: "nonce"}
	if err := store.SaveAssignment(ctx, ticket, "processing"); err != nil {
		t.Fatal(err)
	}
	pendingCleanup, err := store.CleanupAssignments(ctx, "miner")
	if err != nil || len(pendingCleanup) != 1 || pendingCleanup[0].EndpointID != protocol.EndpointID(ticket) {
		t.Fatalf("assignment crash window not recoverable: %#v err=%v", pendingCleanup, err)
	}
	mutated := ticket
	mutated.RouteHost = "another.example"
	if err := store.SaveAssignment(ctx, mutated, "processing"); err == nil {
		t.Fatal("endpoint collision with a different exact ticket was accepted")
	}
	uid := uint16(7)
	binding := ServiceBinding{
		Role: "miner", Network: "test", NetUID: 42, Hotkey: "miner", ServicePublicKey: "aa", Generation: 2,
		UID: &uid, Transport: "https", TransportCertificateSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ExpiresAtBlock: 120, BindingJSON: json.RawMessage(`{"signed":"first"}`),
	}
	if err := store.UpsertServiceBinding(ctx, binding); err != nil {
		t.Fatal(err)
	}
	binding.ServicePublicKey = "bb"
	binding.BindingJSON = json.RawMessage(`{"signed":"equivocation"}`)
	if err := store.UpsertServiceBinding(ctx, binding); err == nil {
		t.Fatal("same-generation service key equivocation was accepted")
	}
	binding.ServicePublicKey = "aa"
	otherUID := uint16(8)
	binding.UID = &otherUID
	binding.BindingJSON = json.RawMessage(`{"signed":"uid-equivocation"}`)
	if err := store.UpsertServiceBinding(ctx, binding); err == nil {
		t.Fatal("same-generation service UID equivocation was accepted")
	}
	binding.UID = &uid
	binding.TransportCertificateSHA256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	binding.BindingJSON = json.RawMessage(`{"signed":"pin-equivocation"}`)
	if err := store.UpsertServiceBinding(ctx, binding); err == nil {
		t.Fatal("same-generation transport pin equivocation was accepted")
	}
	binding.TransportCertificateSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	binding.ExpiresAtBlock = 121
	binding.BindingJSON = json.RawMessage(`{"signed":"expiry-equivocation"}`)
	if err := store.UpsertServiceBinding(ctx, binding); err == nil {
		t.Fatal("same-generation service expiry extension was accepted")
	}
	binding.ExpiresAtBlock = 120
	binding.BindingJSON = json.RawMessage(`{"signed":"different-envelope"}`)
	if err := store.UpsertServiceBinding(ctx, binding); err != nil {
		t.Fatalf("same-generation fresh challenge with exact identity failed: %v", err)
	}
	cleanupPath := filepath.Join(filepath.Dir(path), "private-runtime.layer")
	if err := store.PutEndpoint(ctx, Endpoint{
		EndpointID: protocol.EndpointID(ticket), DeploymentID: "app", MinerHotkey: "miner",
		RuntimeID: "private-runtime", RuntimeURL: "http://127.0.0.1:1", RuntimeCleanupPath: cleanupPath, Active: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutEndpoint(ctx, Endpoint{EndpointID: protocol.EndpointID(ticket), DeploymentID: "another-app", MinerHotkey: "other-miner", Active: true}); err == nil {
		t.Fatal("endpoint incarnation was reassigned to another owner")
	}
	if err := store.SetTrust(ctx, "miner", 0); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordObservation(ctx, Observation{MinerHotkey: "miner", Success: false, Availability: 0, ObservedAt: time.Now(), Kind: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	persistedBinding, exists, err := reopened.ServiceBinding(ctx, "miner", "test", 42, "miner")
	if err != nil || !exists || persistedBinding.Transport != "https" || persistedBinding.TransportCertificateSHA256 != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("transport pin did not survive restart: %#v exists=%v err=%v", persistedBinding, exists, err)
	}
	accepted, err = reopened.ReserveReplay(ctx, "assignment", "nonce", time.Now().Add(time.Minute))
	if err != nil || accepted {
		t.Fatalf("replay survived restart: accepted=%v err=%v", accepted, err)
	}
	trust, exists, err := reopened.Trust(ctx, "miner")
	if err != nil || !exists || trust != 0 {
		t.Fatalf("trust did not survive: trust=%v exists=%v err=%v", trust, exists, err)
	}
	endpoints, err := reopened.ActiveEndpoints(ctx)
	if err != nil || len(endpoints) != 1 || endpoints[0].RuntimeID != "private-runtime" || endpoints[0].RuntimeCleanupPath != cleanupPath {
		t.Fatalf("endpoint recovery mismatch: %#v err=%v", endpoints, err)
	}
	observations, err := reopened.Observations(ctx, time.Now().Add(-time.Hour))
	if err != nil || len(observations) != 1 {
		t.Fatalf("observation recovery mismatch: %#v err=%v", observations, err)
	}
	receipt := protocol.Receipt{EndpointID: protocol.EndpointID(ticket), Stage: protocol.StageReady}
	if err := reopened.SaveReceipt(ctx, receipt); err != nil {
		t.Fatal(err)
	}
	if _, active, err := reopened.CachedResult(ctx, receipt.EndpointID); err != nil || !active {
		t.Fatalf("active idempotent result unavailable: active=%v err=%v", active, err)
	}
	if err := reopened.DeactivateEndpoint(ctx, receipt.EndpointID); err != nil {
		t.Fatal(err)
	}
	receipt.Error = "late failure completion"
	receipt.Stage = protocol.StageFailed
	if err := reopened.SaveReceipt(ctx, receipt); err != nil {
		t.Fatal(err)
	}
	if _, active, err := reopened.CachedResult(ctx, receipt.EndpointID); err != nil || active {
		t.Fatalf("inactive stale ready result returned: active=%v err=%v", active, err)
	}
	if _, status, exists, err := reopened.AssignmentTicket(ctx, receipt.EndpointID); err != nil || !exists || status != "deactivated" {
		t.Fatalf("deactivation status mismatch: status=%q exists=%v err=%v", status, exists, err)
	}
	if pendingCleanup, err := reopened.CleanupAssignments(ctx, "miner"); err != nil || len(pendingCleanup) != 0 {
		t.Fatalf("deactivated assignment remained recoverable: %#v err=%v", pendingCleanup, err)
	}
}

func TestExactDeactivationFenceWinsBeforeAssignmentAndRuntimeActivation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fence.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ticket := protocol.Ticket{
		DeploymentID: "cancelled", MinerID: "miner", Generation: 1, AssignmentNonce: "cancelled-nonce",
		Subnet: &protocol.SubnetBinding{ValidatorHotkey: "validator"},
	}
	endpointID := protocol.EndpointID(ticket)
	if err := store.DeactivateEndpointOwned(ctx, endpointID, ticket.DeploymentID, ticket.MinerID, "validator"); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAssignment(ctx, ticket, "processing"); !errors.Is(err, ErrEndpointDeactivated) {
		t.Fatalf("late assignment crossed deactivation fence: %v", err)
	}
	if err := store.PutEndpoint(ctx, Endpoint{
		EndpointID: endpointID, DeploymentID: ticket.DeploymentID, MinerHotkey: ticket.MinerID,
		RuntimeID: "late-runtime", RuntimeURL: "http://127.0.0.1:1", Active: true,
	}); !errors.Is(err, ErrEndpointDeactivated) {
		t.Fatalf("late runtime activation crossed deactivation fence: %v", err)
	}
	if err := store.DeactivateEndpointOwned(ctx, endpointID, ticket.DeploymentID, ticket.MinerID, "another-validator"); err == nil {
		t.Fatal("another validator replaced the exact deactivation owner")
	}
	if err := store.CompleteEndpointDeactivation(ctx, endpointID, "other-deployment", ticket.MinerID); err != nil {
		// No runtime row exists yet, so exact completion remains an idempotent
		// no-op; the fence itself still rejects the conflicting owner above.
		t.Fatalf("pre-runtime completion should be idempotent: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if endpoints, err := reopened.ActiveEndpoints(ctx); err != nil || len(endpoints) != 0 {
		t.Fatalf("fenced endpoint became active after restart: %+v err=%v", endpoints, err)
	}
	if _, status, exists, err := reopened.AssignmentTicket(ctx, endpointID); err != nil || !exists || status != "deactivated" {
		t.Fatalf("fenced ticket audit state mismatch: status=%q exists=%t err=%v", status, exists, err)
	}
}

func TestDeactivationFenceRetainsRuntimeForRecoveryUntilStopCompletes(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "cleanup-aware.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	ticket := protocol.Ticket{DeploymentID: "cleanup", MinerID: "miner", Generation: 1, AssignmentNonce: "nonce"}
	endpointID := protocol.EndpointID(ticket)
	if err := store.SaveAssignment(ctx, ticket, "processing"); err != nil {
		t.Fatal(err)
	}
	if err := store.PutEndpoint(ctx, Endpoint{
		EndpointID: endpointID, DeploymentID: ticket.DeploymentID, MinerHotkey: ticket.MinerID,
		RuntimeID: "runtime", RuntimeURL: "http://127.0.0.1:1", Active: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.FenceEndpointDeactivation(ctx, endpointID, ticket.DeploymentID, ticket.MinerID, ""); err != nil {
		t.Fatal(err)
	}
	if endpoints, err := store.ActiveEndpoints(ctx); err != nil || len(endpoints) != 1 {
		t.Fatalf("fence hid runtime before Stop could recover it: %+v err=%v", endpoints, err)
	}
	if err := store.CompleteEndpointDeactivation(ctx, endpointID, "other-deployment", ticket.MinerID); err == nil {
		t.Fatal("conflicting owner completed another runtime's deactivation")
	}
	if endpoints, err := store.ActiveEndpoints(ctx); err != nil || len(endpoints) != 1 {
		t.Fatalf("conflicting completion changed runtime state: %+v err=%v", endpoints, err)
	}
	if err := store.CompleteEndpointDeactivation(ctx, endpointID, ticket.DeploymentID, ticket.MinerID); err != nil {
		t.Fatal(err)
	}
	if endpoints, err := store.ActiveEndpoints(ctx); err != nil || len(endpoints) != 0 {
		t.Fatalf("completed cleanup retained runtime: %+v err=%v", endpoints, err)
	}
}

func TestServiceBindingV1DatabaseMigratesTransportColumns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE service_bindings (
role TEXT NOT NULL, network TEXT NOT NULL, netuid INTEGER NOT NULL, hotkey TEXT NOT NULL, uid INTEGER,
service_public_key TEXT NOT NULL, generation INTEGER NOT NULL, expires_at_block INTEGER NOT NULL,
binding_json BLOB NOT NULL, updated_at_ns INTEGER NOT NULL, PRIMARY KEY(role,network,netuid,hotkey));`)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := Open(path)
	if err != nil {
		t.Fatalf("open and migrate v1 database: %v", err)
	}
	defer store.Close()
	binding := ServiceBinding{
		Role: "miner", Network: "test", NetUID: 42, Hotkey: "miner", ServicePublicKey: "aa", Transport: "https",
		TransportCertificateSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Generation:                 1, ExpiresAtBlock: 10, BindingJSON: []byte(`{"version":2}`),
	}
	if err := store.UpsertServiceBinding(context.Background(), binding); err != nil {
		t.Fatalf("write migrated transport binding: %v", err)
	}
	loaded, found, err := store.ServiceBinding(context.Background(), "miner", "test", 42, "miner")
	if err != nil || !found || loaded.TransportCertificateSHA256 != binding.TransportCertificateSHA256 {
		t.Fatalf("load migrated transport binding: %#v found=%v err=%v", loaded, found, err)
	}
}

func TestEndpointIncarnationDatabaseMigratesCleanupMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-endpoint.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE endpoint_incarnations (
endpoint_id TEXT PRIMARY KEY, deployment_id TEXT NOT NULL, miner_hotkey TEXT NOT NULL,
runtime_id TEXT NOT NULL DEFAULT '', runtime_url TEXT NOT NULL DEFAULT '',
active INTEGER NOT NULL, updated_at_ns INTEGER NOT NULL);`)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := Open(path)
	if err != nil {
		t.Fatalf("open and migrate endpoint database: %v", err)
	}
	defer store.Close()
	ticket := protocol.Ticket{
		DeploymentID: "migrated", MinerID: "miner", Generation: 1, AssignmentNonce: "cleanup-column",
	}
	if err := store.SaveAssignment(context.Background(), ticket, "processing"); err != nil {
		t.Fatal(err)
	}
	cleanupPath := filepath.Join(filepath.Dir(path), "migrated.layer")
	if err := store.PutEndpoint(context.Background(), Endpoint{
		EndpointID: protocol.EndpointID(ticket), DeploymentID: ticket.DeploymentID,
		MinerHotkey: ticket.MinerID, RuntimeID: "runtime", RuntimeCleanupPath: cleanupPath, Active: true,
	}); err != nil {
		t.Fatalf("persist migrated cleanup metadata: %v", err)
	}
	endpoint, exists, err := store.EndpointIncarnation(
		context.Background(), protocol.EndpointID(ticket),
	)
	if err != nil || !exists || endpoint.RuntimeCleanupPath != cleanupPath {
		t.Fatalf("migrated cleanup metadata = %#v exists=%t err=%v", endpoint, exists, err)
	}
}

func TestMinerRegistrationRotationIsAtomicWithServiceBindingPin(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	uid := uint16(1)
	pinA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	pinB := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	binding := ServiceBinding{
		Role: "miner", Network: "test", NetUID: 42, Hotkey: "miner", UID: &uid, ServicePublicKey: "key",
		Transport: "https", TransportCertificateSHA256: pinA, Generation: 1, ExpiresAtBlock: 100, BindingJSON: []byte(`{"pin":"a"}`),
	}
	registration := MinerRegistration{
		Network: "test", NetUID: 42, Hotkey: "miner", UID: &uid, AxonURL: "https://8.8.8.8:8091", BridgeURL: "http://127.0.0.1:9200",
		ServicePublicKey: "key", Transport: "https", TransportCertificateSHA256: pinA, TransportCertificateDER: []byte{1},
		BindingGeneration: 1, BindingExpiresAtBlock: 100, BindingJSON: binding.BindingJSON,
	}
	if err := store.UpsertMinerRegistration(ctx, binding, registration); err != nil {
		t.Fatal(err)
	}
	binding.ExpiresAtBlock = 101
	binding.BindingJSON = []byte(`{"pin":"a","expiry":101}`)
	registration.BindingExpiresAtBlock = 101
	registration.BindingJSON = binding.BindingJSON
	if err := store.UpsertMinerRegistration(ctx, binding, registration); err == nil {
		t.Fatal("same-generation registration expiry extension succeeded")
	}
	binding.ExpiresAtBlock = 100
	binding.BindingJSON = []byte(`{"pin":"a"}`)
	registration.BindingExpiresAtBlock = 100
	registration.BindingJSON = binding.BindingJSON
	binding.TransportCertificateSHA256 = pinB
	binding.BindingJSON = []byte(`{"pin":"b"}`)
	registration.TransportCertificateSHA256 = pinB
	registration.TransportCertificateDER = []byte{2}
	registration.BindingJSON = binding.BindingJSON
	if err := store.UpsertMinerRegistration(ctx, binding, registration); err == nil {
		t.Fatal("same-generation registration pin rotation succeeded")
	}
	loaded, found, err := store.MinerRegistration(ctx, "test", 42, "miner")
	if err != nil || !found || loaded.TransportCertificateSHA256 != pinA || string(loaded.TransportCertificateDER) != string([]byte{1}) {
		t.Fatalf("failed rotation replaced accepted registration: %#v found=%v err=%v", loaded, found, err)
	}
	binding.Generation = 2
	registration.BindingGeneration = 2
	if err := store.UpsertMinerRegistration(ctx, binding, registration); err != nil {
		t.Fatalf("higher-generation pin rotation failed: %v", err)
	}
	loaded, found, err = store.MinerRegistration(ctx, "test", 42, "miner")
	if err != nil || !found || loaded.TransportCertificateSHA256 != pinB || string(loaded.TransportCertificateDER) != string([]byte{2}) {
		t.Fatalf("successful rotation was not published atomically: %#v found=%v err=%v", loaded, found, err)
	}
}
