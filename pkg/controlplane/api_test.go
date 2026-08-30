// SPDX-License-Identifier: AGPL-3.0-only

package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
	"github.com/misscomputer/misscomputer-subnet/pkg/campaign"
	campaignintegration "github.com/misscomputer/misscomputer-subnet/pkg/campaign/integration"
	"github.com/misscomputer/misscomputer-subnet/pkg/control"
	"github.com/misscomputer/misscomputer-subnet/pkg/durable"
	"github.com/misscomputer/misscomputer-subnet/pkg/ledger"
	"github.com/misscomputer/misscomputer-subnet/pkg/neuron"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	"github.com/misscomputer/misscomputer-subnet/pkg/remote"
	"github.com/misscomputer/misscomputer-subnet/pkg/tunnel"
)

func TestLocalSyntheticEndpointRemainsDisabledByDefault(t *testing.T) {
	service := &api{}
	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/local/deployments",
		strings.NewReader(`{"credential":"must-not-be-decoded"}`),
	)
	response := httptest.NewRecorder()
	service.deploySynthetic(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("disabled local synthetic endpoint status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "must-not-be-decoded") {
		t.Fatal("disabled local synthetic endpoint decoded or reflected its request")
	}
}

func TestCampaignSurfacesAndCapabilityRemainDisabledByDefault(t *testing.T) {
	service := &api{publicKey: make(ed25519.PublicKey, ed25519.PublicKeySize)}
	statusResponse := httptest.NewRecorder()
	service.campaignStatus(statusResponse, httptest.NewRequest(http.MethodGet, "/v1/campaign/status", nil))
	if statusResponse.Code != http.StatusNotFound {
		t.Fatalf("disabled campaign status=%d body=%s", statusResponse.Code, statusResponse.Body.String())
	}
	evidenceResponse := httptest.NewRecorder()
	evidenceRequest := httptest.NewRequest(http.MethodGet, "/v1/campaign/evidence/1", nil)
	evidenceRequest.SetPathValue("sequence", "1")
	service.campaignEvidence(evidenceResponse, evidenceRequest)
	if evidenceResponse.Code != http.StatusNotFound {
		t.Fatalf("disabled campaign evidence=%d body=%s", evidenceResponse.Code, evidenceResponse.Body.String())
	}
	capabilitiesResponse := httptest.NewRecorder()
	service.capabilities(capabilitiesResponse, httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil))
	if capabilitiesResponse.Code != http.StatusOK || strings.Contains(capabilitiesResponse.Body.String(), "synthetic-campaign") {
		t.Fatalf("inert capabilities=%d body=%s", capabilitiesResponse.Code, capabilitiesResponse.Body.String())
	}
}

func TestCampaignResumeReloadsProtectedReadinessFile(t *testing.T) {
	now := time.Now().UTC().Round(0)
	config := campaignintegration.DefaultRuntimeConfig()
	config.Campaign.Enabled = true
	digest, err := campaignintegration.RuntimeConfigDigest(config)
	if err != nil {
		t.Fatal(err)
	}
	stateDirectory := t.TempDir()
	if err := os.Chmod(stateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	initial := controlReadinessProof(t, now.Add(-time.Minute), now.Add(time.Hour))
	runner, err := campaignintegration.NewRunner(config, digest, campaignintegration.Dependencies{
		StateDirectory: stateDirectory,
		Environment: campaignintegration.ActivationEnvironment{
			Network: campaign.MainnetNetwork, NetUID: campaign.MainnetNetUID, Domain: campaign.MainnetDomain,
			EdgeRequiresManagedWildcard: true, EdgeProbeURL: "https://{host}",
		},
		Readiness: initial, Scheduler: campaignResumeScheduler{}, Artifacts: artifact.FileStore{Root: t.TempDir()},
		Miners: func() []string { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer runner.Close()
	if err := runner.Pause(); err != nil {
		t.Fatal(err)
	}

	readinessPath := filepath.Join(t.TempDir(), "readiness.json")
	expired := controlReadinessProof(t, now.Add(-2*time.Hour), now.Add(-time.Hour))
	writeControlReadiness(t, readinessPath, expired)
	service := &api{campaign: runner, campaignReadinessFile: readinessPath}
	response := httptest.NewRecorder()
	service.campaignResume(response, httptest.NewRequest(http.MethodPost, "/v1/campaign/resume", nil))
	if response.Code != http.StatusConflict {
		t.Fatalf("expired readiness resume status=%d body=%s", response.Code, response.Body.String())
	}
	status, err := runner.Status()
	if err != nil || status.Mode != campaign.ModePaused || status.ReadinessProofSHA256 != initial.ProofDigestSHA256 {
		t.Fatalf("expired reload status=%+v err=%v", status, err)
	}

	fresh := controlReadinessProof(t, now.Add(-time.Minute), now.Add(2*time.Hour))
	writeControlReadiness(t, readinessPath, fresh)
	response = httptest.NewRecorder()
	service.campaignResume(response, httptest.NewRequest(http.MethodPost, "/v1/campaign/resume", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("fresh readiness resume status=%d body=%s", response.Code, response.Body.String())
	}
	status, err = runner.Status()
	if err != nil || status.Mode != campaign.ModeRunning || !status.ReadinessReady ||
		status.ReadinessProofSHA256 != fresh.ProofDigestSHA256 {
		t.Fatalf("fresh reload status=%+v err=%v", status, err)
	}
}

type campaignResumeScheduler struct{}

func (campaignResumeScheduler) Deploy(context.Context, control.DeployRequest) (control.DeployResult, error) {
	return control.DeployResult{}, context.Canceled
}

func (campaignResumeScheduler) DeactivateDeployment(context.Context, string) error { return nil }

func (campaignResumeScheduler) PendingCleanupAssignments(context.Context, string) (int, error) {
	return 0, nil
}

func controlReadinessProof(t *testing.T, verifiedAt, expiresAt time.Time) campaignintegration.WildcardReadinessProof {
	t.Helper()
	proof, err := campaignintegration.SealReadinessProof(campaignintegration.WildcardReadinessProof{
		Version: campaignintegration.ReadinessProofVersion, Network: campaign.MainnetNetwork, NetUID: campaign.MainnetNetUID,
		Domain: campaign.MainnetDomain, WildcardHost: "*." + campaign.MainnetDomain,
		DNSPreprovisioned: true, TunnelPreprovisioned: true, CertificatePreprovisioned: true, PublicProbeVerified: true,
		VerifiedAt: verifiedAt.UTC().Round(0), ExpiresAt: expiresAt.UTC().Round(0),
	})
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func writeControlReadiness(t *testing.T, path string, proof campaignintegration.WildcardReadinessProof) {
	t.Helper()
	payload, err := campaignintegration.MarshalReadinessProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestEvidenceOnlyCampaignHealthCannotEnterScoringObservations(t *testing.T) {
	store, err := durable.Open(t.TempDir() + "/state.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	assignmentLedger, err := ledger.NewDurable(store)
	if err != nil {
		t.Fatal(err)
	}
	service := &api{ledger: assignmentLedger}
	observation := neuron.HealthObservation{
		MinerHotkey: "MinerA", Reachable: true, Correct: true, LatencyMS: 7,
		Availability: 1, ObservedAt: time.Now().UTC(),
	}
	if err := service.recordHealthObservation(control.ScoringEvidenceOnly, observation); err != nil {
		t.Fatal(err)
	}
	values, err := store.Observations(context.Background(), time.Time{})
	if err != nil || len(values) != 0 {
		t.Fatalf("evidence-only health observations=%v err=%v", values, err)
	}
	if err := service.recordHealthObservation(control.ScoringProductionEligible, observation); err != nil {
		t.Fatal(err)
	}
	values, err = store.Observations(context.Background(), time.Time{})
	if err != nil || len(values) != 1 {
		t.Fatalf("production health observations=%v err=%v", values, err)
	}
}

func TestRecoveryReportsEveryNonDeactivatedAssignment(t *testing.T) {
	ctx := context.Background()
	store, err := durable.Open(t.TempDir() + "/state.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	tickets := []protocol.Ticket{
		{DeploymentID: "healthy", MinerID: "recovered-miner", Generation: 1, AssignmentNonce: "healthy-nonce"},
		{DeploymentID: "orphan", MinerID: "pending-miner", Generation: 1, AssignmentNonce: "orphan-nonce"},
	}
	for _, ticket := range tickets {
		if err := store.SaveAssignment(ctx, ticket, "ready"); err != nil {
			t.Fatal(err)
		}
	}
	startupRecovery, err := loadStartupRecovery(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	service := &api{store: store, startupRecovery: startupRecovery}
	readRecovery := func() neuron.RecoveryResponse {
		t.Helper()
		response := httptest.NewRecorder()
		service.recovery(response, httptest.NewRequest(http.MethodGet, "/v1/recovery", nil))
		if response.Code != http.StatusOK {
			t.Fatalf("recovery: %d %s", response.Code, response.Body.String())
		}
		var decoded neuron.RecoveryResponse
		if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
			t.Fatal(err)
		}
		return decoded
	}
	if got := readRecovery(); got.NonDeactivatedAssignments != 2 || got.PendingStartupAssignments != 2 {
		t.Fatalf("recovery=%+v, want healthy and cleanup-pending rows in both counts", got)
	}
	if err := store.DeactivateEndpoint(ctx, protocol.EndpointID(tickets[1])); err != nil {
		t.Fatal(err)
	}
	service.resolveStartupAssignment("pending-miner", protocol.EndpointID(tickets[1]))
	if got := readRecovery(); got.NonDeactivatedAssignments != 1 || got.PendingStartupAssignments != 1 {
		t.Fatalf("recovery=%+v after pending cleanup, want one healthy row", got)
	}
	if err := store.DeactivateEndpoint(ctx, protocol.EndpointID(tickets[0])); err != nil {
		t.Fatal(err)
	}
	service.resolveStartupAssignment("recovered-miner", protocol.EndpointID(tickets[0]))
	if got := readRecovery(); got.NonDeactivatedAssignments != 0 || got.PendingStartupAssignments != 0 {
		t.Fatalf("recovery=%+v after all cleanup", got)
	}
}

func TestMinerRegistrationReadbackReturnsOneExactIdentity(t *testing.T) {
	pin := strings.Repeat("a", 64)
	expected := neuron.MinerRegistration{
		Protocol: neuron.SynapseVersion, Network: "test", NetUID: 24, Hotkey: "miner-hotkey",
		AxonURL: "https://8.8.8.8:8091", BridgeURL: "http://127.0.0.1:9200",
		TransportCertificateDERBase64: "cHVibGljLWRlcg==",
		ServiceBinding: neuron.ServiceKeyBinding{
			Protocol: neuron.ServiceBindingVersion, Role: "miner", Transport: neuron.TransportHTTPS,
			TransportCertificateSHA256: &pin,
		},
	}
	service := &api{registrations: map[string]neuron.MinerRegistration{expected.Hotkey: expected}}
	request := httptest.NewRequest(http.MethodGet, "/v1/miners/miner-hotkey", nil)
	request.SetPathValue("hotkey", expected.Hotkey)
	response := httptest.NewRecorder()
	service.minerRegistration(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("registration readback status=%d body=%s", response.Code, response.Body.String())
	}
	var actual neuron.MinerRegistration
	if err := json.Unmarshal(response.Body.Bytes(), &actual); err != nil {
		t.Fatal(err)
	}
	if actual.Hotkey != expected.Hotkey || actual.AxonURL != expected.AxonURL ||
		actual.TransportCertificateDERBase64 != expected.TransportCertificateDERBase64 {
		t.Fatalf("registration readback drifted: %+v", actual)
	}

	missing := httptest.NewRequest(http.MethodGet, "/v1/miners/missing", nil)
	missing.SetPathValue("hotkey", "missing")
	missingResponse := httptest.NewRecorder()
	service.minerRegistration(missingResponse, missing)
	if missingResponse.Code != http.StatusNotFound {
		t.Fatalf("missing registration status=%d", missingResponse.Code)
	}
}

func TestAuthoritativeMinerSetPrunesStaleCandidates(t *testing.T) {
	uidOne, uidTwo := uint16(1), uint16(2)
	service := &api{
		network: "test", netuid: 42, chainState: &neuron.ChainState{Block: 100},
		miners: map[string]*remote.Assigner{
			"current": {MinerHotkey: "current", MinerUID: &uidOne, AxonURL: "http://8.8.8.1:8091"},
			"stale":   {MinerHotkey: "stale", MinerUID: &uidTwo, AxonURL: "http://8.8.8.2:8091"},
		},
		registrations: map[string]neuron.MinerRegistration{
			"current": {Hotkey: "current", UID: &uidOne, AxonURL: "http://8.8.8.1:8091"},
			"stale":   {Hotkey: "stale", UID: &uidTwo, AxonURL: "http://8.8.8.2:8091"},
		},
		startupRecovery: map[string][]startupAssignment{
			"stale": {{endpoint: durable.Endpoint{EndpointID: "stale-old-1", MinerHotkey: "stale"}}},
		},
		scheduler: &control.Scheduler{},
	}
	payload, err := json.Marshal(neuron.MinerSet{
		Protocol: neuron.SynapseVersion, Network: "test", NetUID: 42, Block: 100, Hotkeys: []string{"current"},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/miners/snapshot", bytes.NewReader(payload))
	response := httptest.NewRecorder()
	service.replaceMinerSet(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("replace miner set: %d %s", response.Code, response.Body.String())
	}
	if service.miners["current"] == nil || service.miners["stale"] != nil || len(service.scheduler.Miners) != 1 {
		t.Fatalf("stale candidate survived: miners=%v scheduler=%d", service.miners, len(service.scheduler.Miners))
	}
	if !service.minerSetReady || service.minerSetBlock != 100 {
		t.Fatalf("authoritative miner set was not marked ready: ready=%t block=%d", service.minerSetReady, service.minerSetBlock)
	}
	if len(service.startupRecovery["stale"]) != 1 {
		t.Fatal("metagraph pruning mutated the immutable startup recovery snapshot")
	}
}

func TestMinerInventoryHidesRegistrationsUntilMinerSetCommit(t *testing.T) {
	committedUID, pendingUID := uint16(1), uint16(2)
	service := &api{
		network: "test", netuid: 42, chainState: &neuron.ChainState{Block: 100},
		miners: map[string]*remote.Assigner{
			"committed": {MinerHotkey: "committed", MinerUID: &committedUID, AxonURL: "http://8.8.8.1:8091"},
		},
		registrations: map[string]neuron.MinerRegistration{
			"committed": {Hotkey: "committed", UID: &committedUID, AxonURL: "http://8.8.8.1:8091"},
		},
		scheduler: &control.Scheduler{}, ledger: ledger.New(),
	}
	payload, err := json.Marshal(neuron.MinerSet{
		Protocol: neuron.SynapseVersion, Network: "test", NetUID: 42, Block: 100,
		Hotkeys: []string{"committed"},
	})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	service.replaceMinerSet(response, httptest.NewRequest(http.MethodPost, "/v1/miners/snapshot", bytes.NewReader(payload)))
	if response.Code != http.StatusOK {
		t.Fatalf("commit miner set: %d %s", response.Code, response.Body.String())
	}

	// A successful handshake publishes its registration before the matching
	// authoritative miner-set transaction. Inventory readiness must continue
	// to describe the committed scheduler view during that window.
	service.mu.Lock()
	service.miners["pending"] = &remote.Assigner{MinerHotkey: "pending", MinerUID: &pendingUID, AxonURL: "http://8.8.8.2:8091"}
	service.registrations["pending"] = neuron.MinerRegistration{Hotkey: "pending", UID: &pendingUID, AxonURL: "http://8.8.8.2:8091"}
	service.mu.Unlock()

	response = httptest.NewRecorder()
	service.listMiners(response, httptest.NewRequest(http.MethodGet, "/v1/miners", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("list miners: %d %s", response.Code, response.Body.String())
	}
	var inventory struct {
		Block  uint64                     `json:"block"`
		Miners []neuron.MinerRegistration `json:"miners"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &inventory); err != nil {
		t.Fatal(err)
	}
	if inventory.Block != 100 || len(inventory.Miners) != 1 || inventory.Miners[0].Hotkey != "committed" {
		t.Fatalf("inventory exposed an uncommitted registration: %+v", inventory)
	}
}

func TestMinerSetPublicationIDBindsExactIdentityAndOrdering(t *testing.T) {
	uidOne, uidTwo := uint16(1), uint16(2)
	pin := strings.Repeat("a", 64)
	registrations := map[string]neuron.MinerRegistration{
		"two": {
			Hotkey: "two", UID: &uidTwo, AxonURL: "https://8.8.8.2:8091",
			ServiceBinding: neuron.ServiceKeyBinding{ServicePublicKey: strings.Repeat("2", 64), Transport: neuron.TransportHTTPS, TransportCertificateSHA256: &pin},
		},
		"one": {
			Hotkey: "one", UID: &uidOne, AxonURL: "https://8.8.8.1:8091",
			ServiceBinding: neuron.ServiceKeyBinding{ServicePublicKey: strings.Repeat("1", 64), Transport: neuron.TransportHTTPS, TransportCertificateSHA256: &pin},
		},
	}
	baseline := minerSetPublicationID(100, registrations)
	if baseline != "4bcfe37e60c812d7e5248fb68bc31bba5f43fa00bcd26c31d56e4de070f33f81" {
		t.Fatalf("publication wire identity changed: %s", baseline)
	}
	reordered := map[string]neuron.MinerRegistration{"one": registrations["one"], "two": registrations["two"]}
	if got := minerSetPublicationID(100, reordered); got != baseline {
		t.Fatalf("map order changed publication identity: %s != %s", got, baseline)
	}
	rotated := map[string]neuron.MinerRegistration{"one": registrations["one"], "two": registrations["two"]}
	changed := rotated["one"]
	changed.ServiceBinding.ServicePublicKey = strings.Repeat("3", 64)
	rotated["one"] = changed
	if got := minerSetPublicationID(100, rotated); got == baseline {
		t.Fatal("service-key rotation did not change publication identity")
	}
	if got := minerSetPublicationID(101, registrations); got == baseline {
		t.Fatal("block change did not change publication identity")
	}
}

func TestAuthoritativeMinerSetRejectsUnboundWithoutPartialPrune(t *testing.T) {
	service := &api{
		network: "test", netuid: 42, chainState: &neuron.ChainState{Block: 100},
		miners: map[string]*remote.Assigner{"existing": {}},
		registrations: map[string]neuron.MinerRegistration{
			"existing": {Hotkey: "existing"},
		},
		scheduler: &control.Scheduler{},
	}
	payload, _ := json.Marshal(neuron.MinerSet{
		Protocol: neuron.SynapseVersion, Network: "test", NetUID: 42, Block: 100, Hotkeys: []string{"unbound"},
	})
	response := httptest.NewRecorder()
	service.replaceMinerSet(response, httptest.NewRequest(http.MethodPost, "/v1/miners/snapshot", bytes.NewReader(payload)))
	if response.Code != http.StatusConflict || service.miners["existing"] == nil {
		t.Fatalf("unbound snapshot partially mutated state: %d %s", response.Code, response.Body.String())
	}
}

func TestAuthoritativeMinerSetRejectsDuplicateAndConflictingIdentities(t *testing.T) {
	run := func(t *testing.T, hotkeys []string, secondUID uint16, secondAxon string) {
		t.Helper()
		firstUID := uint16(1)
		miners := map[string]*remote.Assigner{
			"one": {MinerHotkey: "one", MinerUID: &firstUID, AxonURL: "http://8.8.8.1:8091"},
			"two": {MinerHotkey: "two", MinerUID: &secondUID, AxonURL: secondAxon},
		}
		registrations := map[string]neuron.MinerRegistration{
			"one": {Hotkey: "one", UID: &firstUID, AxonURL: "http://8.8.8.1:8091"},
			"two": {Hotkey: "two", UID: &secondUID, AxonURL: secondAxon},
		}
		service := &api{
			network: "test", netuid: 42, chainState: &neuron.ChainState{Block: 100},
			miners: miners, registrations: registrations, scheduler: &control.Scheduler{},
		}
		payload, err := json.Marshal(neuron.MinerSet{
			Protocol: neuron.SynapseVersion, Network: "test", NetUID: 42, Block: 100, Hotkeys: hotkeys,
		})
		if err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		service.replaceMinerSet(response, httptest.NewRequest(http.MethodPost, "/v1/miners/snapshot", bytes.NewReader(payload)))
		if response.Code != http.StatusConflict {
			t.Fatalf("conflicting snapshot status=%d body=%s", response.Code, response.Body.String())
		}
		if service.chainState.Block != 100 || len(service.miners) != 2 || len(service.scheduler.Miners) != 0 {
			t.Fatalf("conflicting snapshot partially committed: chain=%+v miners=%d scheduler=%d", service.chainState, len(service.miners), len(service.scheduler.Miners))
		}
	}

	t.Run("duplicate hotkey", func(t *testing.T) {
		run(t, []string{"one", "one"}, 2, "http://8.8.8.2:8091")
	})
	t.Run("duplicate UID", func(t *testing.T) {
		run(t, []string{"one", "two"}, 1, "http://8.8.8.2:8091")
	})
	t.Run("duplicate axon", func(t *testing.T) {
		run(t, []string{"one", "two"}, 2, "http://8.8.8.1:8091")
	})
}

func testChainState(publicKey ed25519.PublicKey, block, tempo uint64) neuron.ChainState {
	uid := uint16(0)
	return neuron.ChainState{
		Protocol: neuron.SynapseVersion, Network: "test", NetUID: 42, Block: block, Epoch: block / tempo, Tempo: tempo,
		ValidatorHotkey: "validator",
		ValidatorBinding: neuron.ServiceKeyBinding{
			Protocol: neuron.ServiceBindingVersion, Role: "validator", Network: "test", NetUID: 42,
			Hotkey: "validator", UID: &uid, ServicePublicKey: hex.EncodeToString(publicKey), Transport: neuron.TransportLocal, Generation: block/tempo + 1,
			ValidFromBlock: block, ExpiresAtBlock: block + 100,
		},
	}
}

func TestChainAdmissionRejectsRollbackAndSameHeightConflict(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name      string
		committed neuron.ChainState
		pending   *neuron.ChainState
		input     neuron.ChainState
	}{
		{
			name: "committed rollback", committed: testChainState(publicKey, 105, 12),
			input: testChainState(publicKey, 104, 12),
		},
		{
			name: "pending rollback", committed: testChainState(publicKey, 100, 12),
			pending: func() *neuron.ChainState {
				value := testChainState(publicKey, 105, 12)
				return &value
			}(),
			input: testChainState(publicKey, 104, 12),
		},
		{
			name: "same height conflict", committed: testChainState(publicKey, 104, 13),
			input: testChainState(publicKey, 104, 12),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, err := durable.Open(t.TempDir() + "/state.db")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			committed := test.committed
			service := &api{
				network: "test", netuid: 42, validatorHotkey: "validator", publicKey: publicKey, store: store,
				chainState: &committed, pendingChainState: test.pending,
			}
			payload, err := json.Marshal(test.input)
			if err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			service.updateChain(response, httptest.NewRequest(http.MethodPost, "/v1/chain-state", bytes.NewReader(payload)))
			if response.Code != http.StatusConflict {
				t.Fatalf("chain admission status=%d body=%s", response.Code, response.Body.String())
			}
			pendingChanged := test.pending != nil && (service.pendingChainState == nil || service.pendingChainState.Block != test.pending.Block)
			if service.chainState.Block != committed.Block || pendingChanged {
				t.Fatalf("rejected chain state mutated admission floor: committed=%+v pending=%+v", service.chainState, service.pendingChainState)
			}
		})
	}
}

func TestChainAdmissionRejectsPendingSameHeightConflictWithoutCommittedState(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := durable.Open(t.TempDir() + "/state.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	pending := testChainState(publicKey, 104, 13)
	service := &api{
		network: "test", netuid: 42, validatorHotkey: "validator", publicKey: publicKey, store: store,
		pendingChainState: &pending,
	}
	payload, err := json.Marshal(testChainState(publicKey, 104, 12))
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	service.updateChain(response, httptest.NewRequest(http.MethodPost, "/v1/chain-state", bytes.NewReader(payload)))
	if response.Code != http.StatusConflict {
		t.Fatalf("chain admission status=%d body=%s", response.Code, response.Body.String())
	}
	if service.chainState != nil || service.pendingChainState == nil || service.pendingChainState.Tempo != pending.Tempo {
		t.Fatalf("rejected state mutated pending-only admission floor: committed=%+v pending=%+v", service.chainState, service.pendingChainState)
	}
}

func TestChainRefreshCommitsWithMatchingMinerSetWithoutReadinessGap(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := durable.Open(t.TempDir() + "/state.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	minerUID := uint16(1)
	service := &api{
		network: "test", netuid: 42, validatorHotkey: "validator", publicKey: publicKey, store: store,
		chainState: &neuron.ChainState{Block: 100}, minerSetBlock: 100, minerSetReady: true,
		miners: map[string]*remote.Assigner{
			"miner": {MinerHotkey: "miner", MinerUID: &minerUID, AxonURL: "http://8.8.8.1:8091", Transport: neuron.TransportHTTP},
		},
		registrations: map[string]neuron.MinerRegistration{
			"miner": {Hotkey: "miner", UID: &minerUID, AxonURL: "http://8.8.8.1:8091", ServiceBinding: neuron.ServiceKeyBinding{Transport: neuron.TransportHTTP}},
		},
		scheduler: &control.Scheduler{},
	}
	service.scheduler.SetSubnet(protocol.SubnetBinding{ChainBlock: 100})
	binding := neuron.ServiceKeyBinding{
		Protocol: neuron.ServiceBindingVersion, Role: "validator", Network: "test", NetUID: 42,
		Hotkey: "validator", ServicePublicKey: hex.EncodeToString(publicKey), Transport: neuron.TransportLocal, Generation: 2,
		ValidFromBlock: 101, ExpiresAtBlock: 200,
	}
	chain := neuron.ChainState{
		Protocol: neuron.SynapseVersion, Network: "test", NetUID: 42, Block: 101, Epoch: 8, Tempo: 12,
		ValidatorHotkey: "validator", ValidatorBinding: binding,
	}
	payload, err := json.Marshal(chain)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	service.updateChain(response, httptest.NewRequest(http.MethodPost, "/v1/chain-state", bytes.NewReader(payload)))
	if response.Code != http.StatusOK {
		t.Fatalf("stage chain: %d %s", response.Code, response.Body.String())
	}
	if service.chainState.Block != 100 || service.pendingChainState == nil || service.pendingChainState.Block != 101 || !service.minerSetReady {
		t.Fatalf("active snapshot changed before miner-set commit: active=%+v pending=%+v ready=%t", service.chainState, service.pendingChainState, service.minerSetReady)
	}
	if service.scheduler.Subnet == nil || service.scheduler.Subnet.ChainBlock != 100 {
		t.Fatalf("scheduler binding changed before commit: %+v", service.scheduler.Subnet)
	}

	minerSet, err := json.Marshal(neuron.MinerSet{
		Protocol: neuron.SynapseVersion, Network: "test", NetUID: 42, Block: 101, Hotkeys: []string{"miner"},
	})
	if err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	service.replaceMinerSet(response, httptest.NewRequest(http.MethodPost, "/v1/miners/snapshot", bytes.NewReader(minerSet)))
	if response.Code != http.StatusOK {
		t.Fatalf("commit miner set: %d %s", response.Code, response.Body.String())
	}
	if service.chainState.Block != 101 || service.pendingChainState != nil || !service.minerSetReady || service.minerSetBlock != 101 {
		t.Fatalf("new snapshot was not atomically committed: active=%+v pending=%+v ready=%t", service.chainState, service.pendingChainState, service.minerSetReady)
	}
	if service.scheduler.Subnet == nil || service.scheduler.Subnet.ChainBlock != 101 {
		t.Fatalf("scheduler binding was not committed: %+v", service.scheduler.Subnet)
	}
}

type recordedDeactivation struct {
	hotkey  string
	request neuron.BridgeDeactivateRequest
}

// recoveryHarness drives registerMiner against a real durable store and a
// recording deactivation bridge, with the immutable startup recovery snapshot
// captured exactly as New captures it before the control plane serves.
type recoveryHarness struct {
	t             *testing.T
	store         *durable.Store
	service       *api
	bridgeServer  *httptest.Server
	mu            sync.Mutex
	deactivations []recordedDeactivation
}

func newRecoveryHarness(t *testing.T, store *durable.Store) *recoveryHarness {
	t.Helper()
	harness := &recoveryHarness{t: t, store: store}
	harness.bridgeServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/deactivate") {
			t.Errorf("unexpected bridge request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var request neuron.BridgeDeactivateRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode deactivate request: %v", err)
		}
		parts := strings.Split(r.URL.Path, "/")
		harness.mu.Lock()
		harness.deactivations = append(harness.deactivations, recordedDeactivation{hotkey: parts[len(parts)-2], request: request})
		harness.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(neuron.DeactivateResponse{
			Protocol: neuron.SynapseVersion, RequestID: request.RequestID, Status: "deactivated",
		})
	}))
	t.Cleanup(harness.bridgeServer.Close)
	startupRecovery, err := loadStartupRecovery(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	harness.service = &api{
		scheduler: &control.Scheduler{}, store: store, secret: bytes.Repeat([]byte{7}, 32),
		network: "local", netuid: 42, validatorHotkey: "validator", allowPrivateAxons: true, allowInsecureMockHTTP: true,
		chainState:      &neuron.ChainState{Block: 100},
		miners:          make(map[string]*remote.Assigner),
		registrations:   make(map[string]neuron.MinerRegistration),
		startupRecovery: startupRecovery,
		tunnels:         tunnel.NewLocalRegistry(),
	}
	return harness
}

func (h *recoveryHarness) register(uid uint16, serviceKey ed25519.PublicKey, axon string, generation uint64) *httptest.ResponseRecorder {
	h.t.Helper()
	payload, err := json.Marshal(neuron.MinerRegistration{
		Protocol: neuron.SynapseVersion, Network: "local", NetUID: 42, Hotkey: "miner", UID: &uid,
		AxonURL: axon, BridgeURL: h.bridgeServer.URL,
		ServiceBinding: neuron.ServiceKeyBinding{
			Protocol: neuron.ServiceBindingVersion, Role: "miner", Network: "local", NetUID: 42,
			Hotkey: "miner", UID: &uid, ServicePublicKey: hex.EncodeToString(serviceKey),
			Transport:  neuron.TransportHTTP,
			Generation: generation, ValidFromBlock: 90, ExpiresAtBlock: 200, Challenge: "c", Signature: "s",
		},
	})
	if err != nil {
		h.t.Fatal(err)
	}
	response := httptest.NewRecorder()
	h.service.registerMiner(response, httptest.NewRequest(http.MethodPost, "/v1/miners", bytes.NewReader(payload)))
	return response
}

func (h *recoveryHarness) delivered() []recordedDeactivation {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]recordedDeactivation(nil), h.deactivations...)
}

func (h *recoveryHarness) pendingStartup(hotkey string) int {
	h.service.mu.Lock()
	defer h.service.mu.Unlock()
	return len(h.service.startupRecovery[hotkey])
}

func TestConcurrentRegistrationsCannotPublishOlderGenerationLast(t *testing.T) {
	store, err := durable.Open(t.TempDir() + "/state.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	harness := newRecoveryHarness(t, store)
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uid := uint16(7)
	start := make(chan struct{})
	responses := make(chan *httptest.ResponseRecorder, 2)
	var workers sync.WaitGroup
	for _, generation := range []uint64{1, 2} {
		generation := generation
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			responses <- harness.register(uid, publicKey, "http://10.0.0.7:8091", generation)
		}()
	}
	close(start)
	workers.Wait()
	close(responses)
	accepted := 0
	for response := range responses {
		if response.Code == http.StatusOK {
			accepted++
		} else if response.Code != http.StatusConflict {
			t.Fatalf("unexpected concurrent registration status=%d body=%s", response.Code, response.Body.String())
		}
	}
	if accepted < 1 {
		t.Fatal("neither valid registration generation was accepted")
	}
	harness.service.mu.Lock()
	liveGeneration := harness.service.registrations["miner"].ServiceBinding.Generation
	harness.service.mu.Unlock()
	stored, found, err := store.ServiceBinding(context.Background(), "miner", "local", 42, "miner")
	if err != nil || !found || stored.Generation != 2 || liveGeneration != 2 {
		t.Fatalf("registration rotation diverged: durable=%d live=%d found=%t err=%v", stored.Generation, liveGeneration, found, err)
	}
}

func boundTestTicket(deploymentID, nonce string, uid uint16, serviceKey ed25519.PublicKey, axon string) protocol.Ticket {
	return protocol.Ticket{
		Version: protocol.BoundVersion, DeploymentID: deploymentID, MinerID: "miner",
		Generation: 3, AssignmentNonce: nonce,
		Subnet: &protocol.SubnetBinding{
			Network: "test", NetUID: 42, ValidatorHotkey: "validator", MinerHotkey: "miner",
			MinerUID: &uid, MinerAxonURL: axon, MinerTransport: neuron.TransportHTTP, MinerServicePublicKey: hex.EncodeToString(serviceKey),
		},
	}
}

// TestRegistrationRecoveryRequiresExactAssignmentIdentity is the PR5-SOL-F1
// restart-recovery regression: a same-hotkey registration under a different
// UID/service identity must never deliver, or durably retire, cleanup for an
// assignment issued to the previous identity. Only the exact old identity may
// clean it up, and the assignment stays pending until it does.
func TestRegistrationRecoveryRequiresExactAssignmentIdentity(t *testing.T) {
	ctx := context.Background()
	store, err := durable.Open(t.TempDir() + "/state.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	oldPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	oldUID, newUID := uint16(7), uint16(9)
	ticket := boundTestTicket("held", "0123456789abcdef0123456789abcdef", oldUID, oldPublic, "http://10.0.0.7:8091")
	if err := store.SaveAssignment(ctx, ticket, "ready"); err != nil {
		t.Fatal(err)
	}
	endpointID := protocol.EndpointID(ticket)
	harness := newRecoveryHarness(t, store)

	// A rebound same-hotkey identity registers successfully but must not
	// authorize cleanup of the previous identity's assignment.
	if response := harness.register(newUID, newPublic, "http://10.0.0.9:8091", 1); response.Code != http.StatusOK {
		t.Fatalf("register rebound identity: %d %s", response.Code, response.Body.String())
	}
	if delivered := harness.delivered(); len(delivered) != 0 {
		t.Fatalf("rebound identity received %d cleanup deliveries for the old assignment", len(delivered))
	}
	remaining, err := store.CleanupAssignments(ctx, "miner")
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 1 || remaining[0].EndpointID != endpointID {
		t.Fatalf("old assignment was retired through the new identity: %+v", remaining)
	}
	if harness.pendingStartup("miner") != 1 {
		t.Fatal("recovery no longer holds the identity-mismatched assignment pending")
	}

	// The exact old identity still cleans up its own assignment.
	if response := harness.register(oldUID, oldPublic, "http://10.0.0.7:8091", 2); response.Code != http.StatusOK {
		t.Fatalf("register exact old identity: %d %s", response.Code, response.Body.String())
	}
	delivered := harness.delivered()
	if len(delivered) != 1 {
		t.Fatalf("exact-identity recovery delivered %d cleanups, want 1", len(delivered))
	}
	got := delivered[0]
	if got.hotkey != "miner" || got.request.EndpointID != endpointID || got.request.DeploymentID != "held" {
		t.Fatalf("cleanup targeted the wrong assignment: %+v", got)
	}
	if got.request.MinerHotkey != "miner" || got.request.MinerUID == nil || *got.request.MinerUID != oldUID ||
		got.request.AxonURL != "http://10.0.0.7:8091" || got.request.MinerServicePublicKey != hex.EncodeToString(oldPublic) ||
		got.request.MinerTransport != neuron.TransportHTTP || got.request.MinerTLSCertificateSHA256 != nil {
		t.Fatalf("cleanup request does not carry the exact assignment identity: %+v", got.request)
	}
	remaining, err = store.CleanupAssignments(ctx, "miner")
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 0 {
		t.Fatalf("exact-identity cleanup did not retire durable state: %+v", remaining)
	}
	if harness.pendingStartup("miner") != 0 {
		t.Fatal("recovery did not close after exact-identity cleanup")
	}
}

// TestRegistrationRecoveryRequiresExactAssignmentAxon is the PR5-SOL-F4
// regression: the same hotkey, UID, and service key reappearing at a
// different axon after a restart must not receive cleanup for the old
// assignment or retire its durable state. Only the exact assignment-time
// axon, signed into the ticket, may clean it up.
func TestRegistrationRecoveryRequiresExactAssignmentAxon(t *testing.T) {
	ctx := context.Background()
	store, err := durable.Open(t.TempDir() + "/state.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uid := uint16(7)
	ticket := boundTestTicket("held", "aaaa456789abcdef0123456789abcdef", uid, publicKey, "http://10.0.0.7:8091")
	if err := store.SaveAssignment(ctx, ticket, "ready"); err != nil {
		t.Fatal(err)
	}
	endpointID := protocol.EndpointID(ticket)
	harness := newRecoveryHarness(t, store)

	// The same hotkey, UID, and service key rebinds to a different axon. The
	// old runtime may still be serving at the assignment-time axon, so the
	// rebound axon must never see or retire this assignment's cleanup.
	if response := harness.register(uid, publicKey, "http://10.0.0.8:8091", 1); response.Code != http.StatusOK {
		t.Fatalf("register rebound axon: %d %s", response.Code, response.Body.String())
	}
	if delivered := harness.delivered(); len(delivered) != 0 {
		t.Fatalf("rebound axon received %d cleanup deliveries for the old assignment", len(delivered))
	}
	remaining, err := store.CleanupAssignments(ctx, "miner")
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 1 || remaining[0].EndpointID != endpointID {
		t.Fatalf("old assignment was retired through the rebound axon: %+v", remaining)
	}
	if harness.pendingStartup("miner") != 1 {
		t.Fatal("axon-mismatched assignment did not stay pending")
	}

	// The exact original axon identity, if still valid, cleans it up.
	if response := harness.register(uid, publicKey, "http://10.0.0.7:8091", 2); response.Code != http.StatusOK {
		t.Fatalf("register exact assignment-time axon: %d %s", response.Code, response.Body.String())
	}
	delivered := harness.delivered()
	if len(delivered) != 1 || delivered[0].request.EndpointID != endpointID ||
		delivered[0].request.AxonURL != "http://10.0.0.7:8091" {
		t.Fatalf("exact-axon recovery delivered wrong cleanup: %+v", delivered)
	}
	remaining, err = store.CleanupAssignments(ctx, "miner")
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 0 || harness.pendingStartup("miner") != 0 {
		t.Fatalf("exact-axon cleanup did not retire durable state: %+v", remaining)
	}
}

// TestRegistrationRecoveryFailsClosedForLegacyTicketsWithoutAxon covers
// durable rows created before the signed assignment-time axon existed. Such
// rows carry no axon and can never prove which axon received the work, so
// they must stay pending for every registration instead of being delivered
// to a potentially rebound axon or retired.
func TestRegistrationRecoveryFailsClosedForLegacyTicketsWithoutAxon(t *testing.T) {
	ctx := context.Background()
	store, err := durable.Open(t.TempDir() + "/state.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uid := uint16(7)
	legacy := boundTestTicket("legacy", "bbbb456789abcdef0123456789abcdef", uid, publicKey, "")
	if err := store.SaveAssignment(ctx, legacy, "ready"); err != nil {
		t.Fatal(err)
	}
	harness := newRecoveryHarness(t, store)

	for attempt, axon := range []string{"http://10.0.0.7:8091", "http://10.0.0.8:8091"} {
		if response := harness.register(uid, publicKey, axon, uint64(attempt+1)); response.Code != http.StatusOK {
			t.Fatalf("register attempt %d: %d %s", attempt, response.Code, response.Body.String())
		}
	}
	if delivered := harness.delivered(); len(delivered) != 0 {
		t.Fatalf("legacy no-axon assignment was delivered %d cleanups", len(delivered))
	}
	remaining, err := store.CleanupAssignments(ctx, "miner")
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 1 || harness.pendingStartup("miner") != 1 {
		t.Fatalf("legacy assignment did not fail closed: remaining=%+v pending=%d", remaining, harness.pendingStartup("miner"))
	}
}

// TestStartupRecoveryNeverSweepsCurrentProcessAssignments is the PR5-SOL-F5
// regression: while an unresolved startup mismatch keeps recovery pending,
// assignments created by the running process after startup must never enter
// the recovery sweep, even when their identity matches the registering miner
// exactly. Only the immutable startup snapshot may be reconciled.
func TestStartupRecoveryNeverSweepsCurrentProcessAssignments(t *testing.T) {
	ctx := context.Background()
	store, err := durable.Open(t.TempDir() + "/state.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	oldPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	currentPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uid := uint16(7)
	// An unresolved pre-restart assignment issued to a different service key
	// keeps recovery open across every later registration.
	oldTicket := boundTestTicket("held", "cccc456789abcdef0123456789abcdef", uid, oldPublic, "http://10.0.0.7:8091")
	if err := store.SaveAssignment(ctx, oldTicket, "ready"); err != nil {
		t.Fatal(err)
	}
	harness := newRecoveryHarness(t, store)

	if response := harness.register(uid, currentPublic, "http://10.0.0.7:8091", 1); response.Code != http.StatusOK {
		t.Fatalf("initial registration: %d %s", response.Code, response.Body.String())
	}

	// The running process now creates and persists a new assignment whose
	// identity exactly matches the registered miner, exactly as the
	// scheduler does during Deploy.
	currentTicket := boundTestTicket("current", "dddd456789abcdef0123456789abcdef", uid, currentPublic, "http://10.0.0.7:8091")
	if err := store.SaveAssignment(ctx, currentTicket, "ready"); err != nil {
		t.Fatal(err)
	}
	currentEndpoint := protocol.EndpointID(currentTicket)

	// Repeated capability registrations reconcile only the startup snapshot:
	// the current-process assignment receives zero recovery cleanup and
	// remains active, while the old startup item stays pending.
	for attempt := 0; attempt < 3; attempt++ {
		if response := harness.register(uid, currentPublic, "http://10.0.0.7:8091", uint64(attempt+2)); response.Code != http.StatusOK {
			t.Fatalf("repeat registration %d: %d %s", attempt, response.Code, response.Body.String())
		}
	}
	if delivered := harness.delivered(); len(delivered) != 0 {
		t.Fatalf("recovery swept %d cleanups into current post-startup work: %+v", len(delivered), delivered)
	}
	_, status, exists, err := store.AssignmentTicket(ctx, currentEndpoint)
	if err != nil || !exists {
		t.Fatalf("current assignment disappeared: exists=%t err=%v", exists, err)
	}
	if status != "ready" {
		t.Fatalf("current-process assignment was durably retired by recovery: status=%q", status)
	}
	remaining, err := store.CleanupAssignments(ctx, "miner")
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 2 {
		t.Fatalf("expected pending old and active current assignments, got %+v", remaining)
	}
	if harness.pendingStartup("miner") != 1 {
		t.Fatalf("startup snapshot drifted: pending=%d, want only the immutable old item", harness.pendingStartup("miner"))
	}
}
