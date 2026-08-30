// SPDX-License-Identifier: AGPL-3.0-only

package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
	"github.com/misscomputer/misscomputer-subnet/pkg/bridge"
	campaignintegration "github.com/misscomputer/misscomputer-subnet/pkg/campaign/integration"
	"github.com/misscomputer/misscomputer-subnet/pkg/control"
	"github.com/misscomputer/misscomputer-subnet/pkg/durable"
	"github.com/misscomputer/misscomputer-subnet/pkg/edge"
	"github.com/misscomputer/misscomputer-subnet/pkg/ledger"
	"github.com/misscomputer/misscomputer-subnet/pkg/miner"
	"github.com/misscomputer/misscomputer-subnet/pkg/neuron"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	"github.com/misscomputer/misscomputer-subnet/pkg/remote"
	"github.com/misscomputer/misscomputer-subnet/pkg/tunnel"
	validatorcore "github.com/misscomputer/misscomputer-subnet/pkg/validator"
	"github.com/misscomputer/misscomputer-subnet/pkg/workload"
)

type api struct {
	mu                    sync.Mutex
	registrationLocksMu   sync.Mutex
	registrationLocks     map[string]*sync.Mutex
	scheduler             *control.Scheduler
	ledger                *ledger.Ledger
	store                 *durable.Store
	artifacts             artifact.Store
	secret                []byte
	publicKey             ed25519.PublicKey
	network               string
	netuid                uint16
	validatorHotkey       string
	allowSynthetic        bool
	allowPrivateAxons     bool
	allowInsecureMockHTTP bool
	campaign              *campaignintegration.Runner
	campaignReadinessFile string
	chainState            *neuron.ChainState
	pendingChainState     *neuron.ChainState
	minerSetBlock         uint64
	minerSetReady         bool
	minerSetPublication   string
	miners                map[string]*remote.Assigner
	registrations         map[string]neuron.MinerRegistration
	// publishedRegistrations is the last miner-set transaction committed to
	// the scheduler. registrations also contains per-miner handshakes staged
	// for a pending refresh and remains available for exact acknowledgement
	// reconciliation through /v1/miners/{hotkey}.
	publishedRegistrations map[string]neuron.MinerRegistration
	// startupRecovery is the immutable restart-recovery snapshot, captured
	// once before the control API serves any request. Membership is fixed at
	// startup: capability registrations may only reconcile this set, so
	// assignments created by the running process can never be swept by
	// registration-time recovery cleanup. Resolved items are removed;
	// unresolved items stay pending for their exact assignment identity.
	startupRecovery map[string][]startupAssignment
	tunnels         tunnel.Registry
}

// startupAssignment is one member of the immutable startup recovery snapshot:
// an assignment that was not durably deactivated when this process started,
// together with the exact signed ticket identity it was issued to.
type startupAssignment struct {
	endpoint  durable.Endpoint
	ticket    protocol.Ticket
	hasTicket bool
}

// loadStartupRecovery captures the restart-recovery snapshot before normal
// service operation begins. New calls it before the route table is served. Only assignments that already existed at process
// startup are ever eligible for registration-time recovery cleanup.
func loadStartupRecovery(ctx context.Context, store *durable.Store) (map[string][]startupAssignment, error) {
	endpoints, err := store.CleanupAssignments(ctx, "")
	if err != nil {
		return nil, err
	}
	snapshot := make(map[string][]startupAssignment, len(endpoints))
	for _, endpoint := range endpoints {
		ticket, _, exists, err := store.AssignmentTicket(ctx, endpoint.EndpointID)
		if err != nil {
			return nil, err
		}
		snapshot[endpoint.MinerHotkey] = append(snapshot[endpoint.MinerHotkey], startupAssignment{
			endpoint: endpoint, ticket: ticket, hasTicket: exists,
		})
	}
	return snapshot, nil
}

type deploymentView struct {
	Deployment ledger.Deployment       `json:"deployment"`
	Active     []control.ActiveReplica `json:"active_replicas"`
	Routes     []edge.Replica          `json:"routes"`
}

func localMockNetwork(network string) bool {
	normalized := strings.ToLower(strings.TrimSpace(network))
	return normalized == "local" || normalized == "mock" || strings.HasPrefix(normalized, "mock-")
}

func splitNonempty(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func (a *api) campaignMinerIDs() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.chainState == nil || !a.minerSetReady || a.minerSetBlock != a.chainState.Block {
		return nil
	}
	miners := make([]string, 0, len(a.publishedRegistrations))
	for hotkey := range a.publishedRegistrations {
		miners = append(miners, hotkey)
	}
	sort.Strings(miners)
	return miners
}

func (a *api) capabilities(w http.ResponseWriter, _ *http.Request) {
	features := []string{"scheduler", "replacement", "scoring", "dry-run-weights"}
	if a.campaign != nil {
		features = append(features, "synthetic-campaign-v1")
	}
	writeJSON(w, http.StatusOK, neuron.ControlCapabilities{
		Protocol: neuron.SynapseVersion, ServicePublicKey: hex.EncodeToString(a.publicKey),
		Features: features, WeightsEnabled: false,
	})
}

func (a *api) campaignStatus(w http.ResponseWriter, _ *http.Request) {
	if a.campaign == nil {
		bridge.WriteError(w, http.StatusNotFound, "disabled", "synthetic campaign is disabled", false)
		return
	}
	status, err := a.campaign.Status()
	if err != nil {
		bridge.WriteError(w, http.StatusServiceUnavailable, "campaign_state_unavailable", "synthetic campaign state is unavailable", true)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (a *api) campaignEvidence(w http.ResponseWriter, req *http.Request) {
	if a.campaign == nil {
		bridge.WriteError(w, http.StatusNotFound, "disabled", "synthetic campaign is disabled", false)
		return
	}
	sequence, err := strconv.ParseUint(req.PathValue("sequence"), 10, 64)
	if err != nil || sequence == 0 {
		bridge.WriteError(w, http.StatusBadRequest, "invalid_sequence", "campaign sequence must be a positive integer", false)
		return
	}
	evidence, err := a.campaign.Evidence(sequence)
	if err != nil {
		status := http.StatusServiceUnavailable
		code := "campaign_evidence_unavailable"
		retryable := true
		if errors.Is(err, os.ErrNotExist) {
			status, code, retryable = http.StatusNotFound, "not_found", false
		}
		bridge.WriteError(w, status, code, "campaign evidence is unavailable", retryable)
		return
	}
	writeJSON(w, http.StatusOK, evidence)
}

func (a *api) campaignPause(w http.ResponseWriter, _ *http.Request) {
	a.campaignAction(w, func() error { return a.campaign.Pause() })
}

func (a *api) campaignResume(w http.ResponseWriter, _ *http.Request) {
	if a.campaign == nil {
		bridge.WriteError(w, http.StatusNotFound, "disabled", "synthetic campaign is disabled", false)
		return
	}
	readiness, err := campaignintegration.LoadReadinessProof(a.campaignReadinessFile, time.Now().UTC())
	if err != nil {
		bridge.WriteError(w, http.StatusConflict, "campaign_transition_failed", "synthetic campaign transition failed", false)
		return
	}
	a.campaignAction(w, func() error { return a.campaign.ReloadReadinessAndResume(readiness) })
}

func (a *api) campaignDrain(w http.ResponseWriter, _ *http.Request) {
	a.campaignAction(w, func() error { return a.campaign.Drain() })
}

func (a *api) campaignShutdown(w http.ResponseWriter, req *http.Request) {
	if a.campaign == nil {
		bridge.WriteError(w, http.StatusNotFound, "disabled", "synthetic campaign is disabled", false)
		return
	}
	ctx, cancel := context.WithTimeout(req.Context(), 20*time.Second)
	defer cancel()
	a.campaignAction(w, func() error { return a.campaign.Shutdown(ctx) })
}

func (a *api) campaignAction(w http.ResponseWriter, action func() error) {
	if a.campaign == nil {
		bridge.WriteError(w, http.StatusNotFound, "disabled", "synthetic campaign is disabled", false)
		return
	}
	if err := action(); err != nil {
		bridge.WriteError(w, http.StatusConflict, "campaign_transition_failed", "synthetic campaign transition failed", false)
		return
	}
	status, err := a.campaign.Status()
	if err != nil {
		bridge.WriteError(w, http.StatusServiceUnavailable, "campaign_state_unavailable", "synthetic campaign state is unavailable", true)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"protocol": campaignintegration.StatusVersion, "status": string(status.Mode),
	})
}

func (a *api) updateChain(w http.ResponseWriter, req *http.Request) {
	var input neuron.ChainState
	if err := decodeJSON(req.Body, &input); err != nil {
		bridge.WriteError(w, http.StatusBadRequest, "invalid_request", err.Error(), false)
		return
	}
	binding := input.ValidatorBinding
	if input.Protocol != neuron.SynapseVersion || input.Network != a.network || input.NetUID != a.netuid || input.ValidatorHotkey != a.validatorHotkey ||
		input.Tempo == 0 || input.Epoch != input.Block/input.Tempo || binding.Protocol != neuron.ServiceBindingVersion ||
		binding.Role != "validator" || binding.Hotkey != a.validatorHotkey || binding.Network != a.network || binding.NetUID != a.netuid ||
		binding.ServicePublicKey != hex.EncodeToString(a.publicKey) || input.Block < binding.ValidFromBlock || input.Block >= binding.ExpiresAtBlock {
		bridge.WriteError(w, http.StatusForbidden, "identity_mismatch", "chain state or validator service binding does not match configured identity", false)
		return
	}
	if err := neuron.ValidateServiceBindingTransport(binding, false); err != nil {
		bridge.WriteError(w, http.StatusForbidden, "identity_mismatch", err.Error(), false)
		return
	}
	a.mu.Lock()
	latestBlock := uint64(0)
	var latestState *neuron.ChainState
	if a.chainState != nil {
		latestBlock = a.chainState.Block
		latestState = a.chainState
	}
	if a.pendingChainState != nil && a.pendingChainState.Block >= latestBlock {
		latestBlock = a.pendingChainState.Block
		latestState = a.pendingChainState
	}
	if input.Block < latestBlock {
		a.mu.Unlock()
		bridge.WriteError(w, http.StatusConflict, "chain_rollback", "chain block moved backwards", false)
		return
	}
	if input.Block == latestBlock && latestState != nil && !sameChainIdentity(input, *latestState) {
		a.mu.Unlock()
		bridge.WriteError(w, http.StatusConflict, "chain_reorg", "chain state conflicts at the latest admitted block", false)
		return
	}
	if err := a.store.UpsertServiceBinding(req.Context(), durable.ServiceBinding{
		Role: binding.Role, Network: binding.Network, NetUID: binding.NetUID, Hotkey: binding.Hotkey, UID: binding.UID,
		ServicePublicKey: binding.ServicePublicKey, Transport: binding.Transport, TransportCertificateSHA256: optionalString(binding.TransportCertificateSHA256),
		Generation: binding.Generation, ExpiresAtBlock: binding.ExpiresAtBlock, BindingJSON: neuron.BindingJSON(binding),
	}); err != nil {
		a.mu.Unlock()
		bridge.WriteError(w, http.StatusConflict, "binding_rollback", err.Error(), false)
		return
	}
	copy := input
	// Stage the chain snapshot until Python has completed capability discovery
	// and posts the matching authoritative miner set. The previously committed
	// chain/miner pair remains schedulable during this short transaction, which
	// avoids a recurring not-ready window on every metagraph refresh.
	a.pendingChainState = &copy
	a.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"protocol": neuron.SynapseVersion, "status": "synced", "block": input.Block})
}

func sameChainIdentity(left, right neuron.ChainState) bool {
	leftBinding, rightBinding := left.ValidatorBinding, right.ValidatorBinding
	return left.Network == right.Network && left.NetUID == right.NetUID && left.Block == right.Block &&
		left.Epoch == right.Epoch && left.Tempo == right.Tempo && left.ValidatorHotkey == right.ValidatorHotkey &&
		leftBinding.Role == rightBinding.Role && leftBinding.Network == rightBinding.Network && leftBinding.NetUID == rightBinding.NetUID &&
		leftBinding.Hotkey == rightBinding.Hotkey && equalUID(leftBinding.UID, rightBinding.UID) &&
		leftBinding.ServicePublicKey == rightBinding.ServicePublicKey && leftBinding.Generation == rightBinding.Generation &&
		leftBinding.Transport == rightBinding.Transport && equalOptionalString(leftBinding.TransportCertificateSHA256, rightBinding.TransportCertificateSHA256) &&
		leftBinding.ValidFromBlock == rightBinding.ValidFromBlock && leftBinding.ExpiresAtBlock == rightBinding.ExpiresAtBlock
}

func (a *api) registerMiner(w http.ResponseWriter, req *http.Request) {
	var input neuron.MinerRegistration
	if err := decodeJSON(req.Body, &input); err != nil {
		bridge.WriteError(w, http.StatusBadRequest, "invalid_request", err.Error(), false)
		return
	}
	registrationLock := a.registrationLock(input.Hotkey)
	registrationLock.Lock()
	defer registrationLock.Unlock()
	a.mu.Lock()
	chain := a.pendingChainState
	if chain == nil {
		chain = a.chainState
	}
	a.mu.Unlock()
	binding := input.ServiceBinding
	if chain == nil {
		bridge.WriteError(w, http.StatusServiceUnavailable, "metagraph_not_ready", "validator chain state has not been synchronized", true)
		return
	}
	if input.Protocol != neuron.SynapseVersion || input.Network != a.network || input.NetUID != a.netuid || input.Hotkey != binding.Hotkey ||
		!equalUID(input.UID, binding.UID) || binding.Protocol != neuron.ServiceBindingVersion || binding.Role != "miner" ||
		binding.Network != a.network || binding.NetUID != a.netuid || chain.Block < binding.ValidFromBlock || binding.ExpiresAtBlock <= chain.Block {
		bridge.WriteError(w, http.StatusForbidden, "identity_mismatch", "miner registration binding does not match the configured subnet", false)
		return
	}
	if err := neuron.ValidateServiceBindingTransport(binding, a.allowInsecureMockHTTP); err != nil {
		bridge.WriteError(w, http.StatusForbidden, "identity_mismatch", err.Error(), false)
		return
	}
	assigner, err := remote.NewWithTransportPolicy(input, a.secret, a.tunnels, a.allowPrivateAxons, a.allowInsecureMockHTTP)
	if err != nil {
		bridge.WriteError(w, http.StatusBadRequest, "invalid_miner", err.Error(), false)
		return
	}
	// Publish and compare only the canonical numeric-IP identities produced by
	// the strict parser (not alternate textual IPv6 spellings or trailing `/`).
	input.AxonURL = assigner.AxonURL
	input.BridgeURL = assigner.BridgeURL
	storedBinding, stored, err := a.store.ServiceBinding(req.Context(), "miner", binding.Network, binding.NetUID, binding.Hotkey)
	if err != nil {
		bridge.WriteError(w, http.StatusInternalServerError, "state_error", err.Error(), true)
		return
	}
	if stored && (binding.Generation < storedBinding.Generation ||
		(binding.Generation == storedBinding.Generation &&
			(storedBinding.ServicePublicKey != binding.ServicePublicKey || !equalUID(storedBinding.UID, binding.UID) ||
				storedBinding.Transport != binding.Transport || storedBinding.TransportCertificateSHA256 != optionalString(binding.TransportCertificateSHA256) ||
				binding.ExpiresAtBlock < storedBinding.ExpiresAtBlock))) {
		bridge.WriteError(w, http.StatusConflict, "binding_rollback", "miner service binding generation rollback or same-generation identity conflict", false)
		return
	}
	// Registration-time recovery reconciles only the immutable startup
	// snapshot. Assignments created by this running process are tracked by
	// the scheduler and must never be swept here, even when an unresolved
	// legacy mismatch keeps recovery pending for the same hotkey.
	a.mu.Lock()
	pending := append([]startupAssignment(nil), a.startupRecovery[input.Hotkey]...)
	a.mu.Unlock()
	for _, item := range pending {
		// Cleanup authority is bound to the exact signed-ticket identity,
		// including the normalized assignment-time axon. A same-hotkey
		// registration under a different UID, service key, or axon must
		// never deactivate, or durably retire state for, an assignment
		// issued to the previous identity; such assignments remain visible
		// through /v1/recovery instead of being falsely retired while the
		// old runtime may still exist. Durable rows persisted before the
		// signed axon field carry no assignment-time axon and therefore
		// also fail closed here, staying pending rather than being
		// delivered to a potentially rebound axon.
		subnet := item.ticket.Subnet
		if !item.hasTicket || subnet == nil || item.ticket.MinerID != input.Hotkey ||
			!equalUID(subnet.MinerUID, binding.UID) ||
			subnet.MinerServicePublicKey != binding.ServicePublicKey ||
			subnet.MinerAxonURL == "" || subnet.MinerAxonURL != assigner.AxonURL ||
			subnet.MinerTransport != assigner.Transport || !optionalStringEqualsValue(subnet.MinerTLSCertificateSHA256, assigner.TLSCertificateSHA256) {
			continue
		}
		cleanupCtx, cancel := context.WithTimeout(req.Context(), 15*time.Second)
		err := assigner.DeactivateKnown(cleanupCtx, item.endpoint.EndpointID, item.endpoint.DeploymentID)
		cancel()
		if err != nil {
			bridge.WriteError(w, http.StatusBadGateway, "restart_cleanup_failed", err.Error(), true)
			return
		}
		if err := a.store.DeactivateEndpoint(context.Background(), item.endpoint.EndpointID); err != nil {
			bridge.WriteError(w, http.StatusInternalServerError, "state_error", err.Error(), true)
			return
		}
		a.resolveStartupAssignment(input.Hotkey, item.endpoint.EndpointID)
	}
	// Persist only after every fallible identity and restart-cleanup check has
	// succeeded. Publication under the mutex immediately follows, so a failed
	// rotation never replaces the accepted pin in the durable or live handle.
	durableBinding := durable.ServiceBinding{
		Role: binding.Role, Network: binding.Network, NetUID: binding.NetUID, Hotkey: binding.Hotkey, UID: binding.UID,
		ServicePublicKey: binding.ServicePublicKey, Transport: binding.Transport, TransportCertificateSHA256: optionalString(binding.TransportCertificateSHA256),
		Generation: binding.Generation, ExpiresAtBlock: binding.ExpiresAtBlock, BindingJSON: neuron.BindingJSON(binding),
	}
	a.mu.Lock()
	currentChain := a.pendingChainState
	if currentChain == nil {
		currentChain = a.chainState
	}
	if currentChain == nil || currentChain.Block < binding.ValidFromBlock || currentChain.Block >= binding.ExpiresAtBlock {
		a.mu.Unlock()
		bridge.WriteError(w, http.StatusConflict, "stale_binding", "miner binding expired before atomic publication", false)
		return
	}
	if err := a.store.UpsertMinerRegistration(req.Context(), durableBinding, durable.MinerRegistration{
		Network: input.Network, NetUID: input.NetUID, Hotkey: input.Hotkey, UID: input.UID,
		AxonURL: assigner.AxonURL, BridgeURL: assigner.BridgeURL, ServicePublicKey: binding.ServicePublicKey,
		Transport: assigner.Transport, TransportCertificateSHA256: assigner.TLSCertificateSHA256,
		TransportCertificateDER: append([]byte(nil), assigner.TLSCertificateDER...), BindingGeneration: binding.Generation,
		BindingExpiresAtBlock: binding.ExpiresAtBlock, BindingJSON: neuron.BindingJSON(binding),
	}); err != nil {
		a.mu.Unlock()
		bridge.WriteError(w, http.StatusConflict, "binding_rollback", err.Error(), false)
		return
	}
	a.miners[input.Hotkey] = assigner
	a.registrations[input.Hotkey] = input
	a.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"protocol": neuron.SynapseVersion, "status": "registered", "hotkey": input.Hotkey})
}

func (a *api) registrationLock(hotkey string) *sync.Mutex {
	a.registrationLocksMu.Lock()
	defer a.registrationLocksMu.Unlock()
	if a.registrationLocks == nil {
		a.registrationLocks = make(map[string]*sync.Mutex)
	}
	lock := a.registrationLocks[hotkey]
	if lock == nil {
		lock = &sync.Mutex{}
		a.registrationLocks[hotkey] = lock
	}
	return lock
}

func (a *api) replaceMinerSet(w http.ResponseWriter, req *http.Request) {
	var input neuron.MinerSet
	if err := decodeJSON(req.Body, &input); err != nil {
		bridge.WriteError(w, http.StatusBadRequest, "invalid_request", err.Error(), false)
		return
	}
	a.mu.Lock()
	targetChain := a.pendingChainState
	if targetChain == nil {
		targetChain = a.chainState
	}
	if targetChain == nil || input.Protocol != neuron.SynapseVersion || input.Network != a.network ||
		input.NetUID != a.netuid || input.Block != targetChain.Block {
		a.mu.Unlock()
		bridge.WriteError(w, http.StatusConflict, "stale_miner_set", "miner set does not match current chain state", false)
		return
	}
	wanted := make(map[string]struct{}, len(input.Hotkeys))
	for _, hotkey := range input.Hotkeys {
		if hotkey == "" {
			a.mu.Unlock()
			bridge.WriteError(w, http.StatusBadRequest, "invalid_request", "miner hotkey is empty", false)
			return
		}
		if _, duplicate := wanted[hotkey]; duplicate {
			a.mu.Unlock()
			bridge.WriteError(w, http.StatusConflict, "conflicting_miner_identity", "miner set contains a duplicate hotkey", false)
			return
		}
		wanted[hotkey] = struct{}{}
	}
	uidOwners := make(map[uint16]string, len(wanted))
	axonOwners := make(map[string]string, len(wanted))
	for hotkey := range wanted {
		assigner := a.miners[hotkey]
		registration, registered := a.registrations[hotkey]
		if assigner == nil || !registered {
			a.mu.Unlock()
			bridge.WriteError(w, http.StatusConflict, "unbound_miner", "miner set contains a miner without a current handshake", false)
			return
		}
		if registration.Hotkey != hotkey || registration.UID == nil || assigner.MinerHotkey != hotkey ||
			!equalUID(registration.UID, assigner.MinerUID) || strings.TrimRight(registration.AxonURL, "/") != assigner.AxonURL ||
			registration.ServiceBinding.ServicePublicKey != hex.EncodeToString(assigner.ServiceKey) ||
			registration.ServiceBinding.Transport != assigner.Transport ||
			!optionalStringEqualsValue(registration.ServiceBinding.TransportCertificateSHA256, assigner.TLSCertificateSHA256) {
			a.mu.Unlock()
			bridge.WriteError(w, http.StatusConflict, "conflicting_miner_identity", "miner set contains a conflicting handshake identity", false)
			return
		}
		uid := *registration.UID
		if owner, duplicate := uidOwners[uid]; duplicate && owner != hotkey {
			a.mu.Unlock()
			bridge.WriteError(w, http.StatusConflict, "conflicting_miner_identity", "miner set contains a duplicate UID", false)
			return
		}
		uidOwners[uid] = hotkey
		if owner, duplicate := axonOwners[assigner.AxonURL]; duplicate && owner != hotkey {
			a.mu.Unlock()
			bridge.WriteError(w, http.StatusConflict, "conflicting_miner_identity", "miner set contains a duplicate axon identity", false)
			return
		}
		axonOwners[assigner.AxonURL] = hotkey
	}
	published := make(map[string]neuron.MinerRegistration, len(wanted))
	for hotkey := range wanted {
		published[hotkey] = a.registrations[hotkey]
	}
	committedChain := *targetChain
	publicationID := minerSetPublicationID(input.Block, published)
	candidates := a.sortedMinersLocked(published)
	binding := committedChain.ValidatorBinding
	subnet := protocol.SubnetBinding{
		Network: committedChain.Network, NetUID: committedChain.NetUID, ValidatorHotkey: committedChain.ValidatorHotkey,
		ChainBlock: committedChain.Block, Epoch: committedChain.Epoch,
		ExpiresAtBlock:            min(committedChain.Block+max(committedChain.Tempo, 12), binding.ExpiresAtBlock),
		ValidatorServicePublicKey: binding.ServicePublicKey,
	}
	if err := a.scheduler.InstallPublication(publicationID, subnet, candidates); err != nil {
		a.mu.Unlock()
		bridge.WriteError(w, http.StatusConflict, "invalid_publication", err.Error(), false)
		return
	}
	for hotkey := range a.miners {
		if _, exists := wanted[hotkey]; !exists {
			delete(a.miners, hotkey)
			delete(a.registrations, hotkey)
		}
	}
	a.chainState = &committedChain
	a.pendingChainState = nil
	a.minerSetBlock = input.Block
	a.minerSetPublication = publicationID
	a.publishedRegistrations = published
	a.minerSetReady = true
	a.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"protocol": neuron.SynapseVersion, "status": "replaced", "block": input.Block,
		"miners": len(candidates), "publication_id": publicationID,
	})
}

type publicationMinerIdentity struct {
	Hotkey     string  `json:"hotkey"`
	UID        *uint16 `json:"uid"`
	AxonURL    string  `json:"axon_url"`
	ServiceKey string  `json:"service_key"`
	Transport  string  `json:"transport"`
	TLSPin     *string `json:"tls_pin"`
}

func minerSetPublicationID(block uint64, registrations map[string]neuron.MinerRegistration) string {
	identities := make([]publicationMinerIdentity, 0, len(registrations))
	for _, registration := range registrations {
		identities = append(identities, publicationMinerIdentity{
			Hotkey: registration.Hotkey, UID: registration.UID, AxonURL: registration.AxonURL,
			ServiceKey: registration.ServiceBinding.ServicePublicKey,
			Transport:  registration.ServiceBinding.Transport,
			TLSPin:     registration.ServiceBinding.TransportCertificateSHA256,
		})
	}
	sort.Slice(identities, func(i, j int) bool { return identities[i].Hotkey < identities[j].Hotkey })
	payload, err := json.Marshal(struct {
		Version int                        `json:"version"`
		Block   uint64                     `json:"block"`
		Miners  []publicationMinerIdentity `json:"miners"`
	}{Version: 1, Block: block, Miners: identities})
	if err != nil {
		panic("marshal miner-set publication identity: " + err.Error())
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

func equalUID(left, right *uint16) bool {
	return (left == nil && right == nil) || (left != nil && right != nil && *left == *right)
}

func optionalString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func equalOptionalString(left, right *string) bool {
	return (left == nil && right == nil) || (left != nil && right != nil && *left == *right)
}

func optionalStringEqualsValue(value *string, expected string) bool {
	if expected == "" {
		return value == nil
	}
	return value != nil && *value == expected
}

func (a *api) sortedMinersLocked(published map[string]neuron.MinerRegistration) []miner.Assigner {
	registrations := make([]neuron.MinerRegistration, 0, len(published))
	for _, registration := range published {
		registrations = append(registrations, registration)
	}
	sort.Slice(registrations, func(i, j int) bool {
		left, right := registrations[i].UID, registrations[j].UID
		if left != nil && right != nil && *left != *right {
			return *left < *right
		}
		if left != nil && right == nil {
			return true
		}
		if left == nil && right != nil {
			return false
		}
		return registrations[i].Hotkey < registrations[j].Hotkey
	})
	values := make([]miner.Assigner, 0, len(registrations))
	for _, registration := range registrations {
		values = append(values, a.miners[registration.Hotkey])
	}
	return values
}

func (a *api) listMiners(w http.ResponseWriter, _ *http.Request) {
	a.mu.Lock()
	values := make([]neuron.MinerRegistration, 0, len(a.publishedRegistrations))
	for _, registration := range a.publishedRegistrations {
		values = append(values, registration)
	}
	block := a.minerSetBlock
	ready := a.minerSetReady
	publicationID := a.minerSetPublication
	a.mu.Unlock()
	sort.Slice(values, func(i, j int) bool { return values[i].Hotkey < values[j].Hotkey })
	// eligible_hotkeys lets the deterministic mock E2E prove the clean-spare
	// invariant (an eligible, unassigned miner) before omission/replacement
	// without exposing raw trust values.
	eligible := make([]string, 0, len(values))
	for _, registration := range values {
		if a.ledger.Eligible(registration.Hotkey) {
			eligible = append(eligible, registration.Hotkey)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"protocol": neuron.SynapseVersion, "block": block, "ready": ready,
		"publication_id": publicationID, "miners": values, "eligible_hotkeys": eligible,
	})
}

func (a *api) minerRegistration(w http.ResponseWriter, req *http.Request) {
	hotkey := req.PathValue("hotkey")
	a.mu.Lock()
	registration, exists := a.registrations[hotkey]
	a.mu.Unlock()
	if !exists || hotkey == "" {
		bridge.WriteError(w, http.StatusNotFound, "not_found", "miner registration is unavailable", false)
		return
	}
	writeJSON(w, http.StatusOK, registration)
}

func (a *api) deploy(w http.ResponseWriter, req *http.Request) {
	var input neuron.DeployRequest
	if err := decodeJSON(req.Body, &input); err != nil {
		bridge.WriteError(w, http.StatusBadRequest, "invalid_request", err.Error(), false)
		return
	}
	if input.Protocol != neuron.SynapseVersion {
		bridge.WriteError(w, http.StatusBadRequest, "version_mismatch", "unsupported deployment contract", false)
		return
	}
	if !control.ValidDeploymentID(input.DeploymentID) {
		bridge.WriteError(w, http.StatusBadRequest, "invalid_deployment_id", "deployment ID must be a lowercase DNS label", false)
		return
	}
	if input.TimeoutMS < 1_000 || input.TimeoutMS > 180_000 {
		bridge.WriteError(w, http.StatusBadRequest, "invalid_timeout", "deployment timeout must be in [1000,180000] ms", false)
		return
	}
	a.deployRequest(w, req, control.DeployRequest{
		DeploymentID: input.DeploymentID,
		Manifest:     input.Manifest,
		ManifestKey:  input.ManifestKey,
		Workload:     input.Workload,
		Timeout:      time.Duration(input.TimeoutMS) * time.Millisecond,
	})
}

func (a *api) deploySynthetic(w http.ResponseWriter, req *http.Request) {
	if !a.allowSynthetic {
		bridge.WriteError(w, http.StatusNotFound, "disabled", "local synthetic workloads are disabled", false)
		return
	}
	var input neuron.LocalSyntheticDeployRequest
	if err := decodeJSON(req.Body, &input); err != nil {
		bridge.WriteError(w, http.StatusBadRequest, "invalid_request", err.Error(), false)
		return
	}
	if input.Protocol != neuron.SynapseVersion || !control.ValidDeploymentID(input.DeploymentID) || input.SizeBytes < 1024 || input.SizeBytes > 512<<20 ||
		input.TimeoutMS < 1_000 || input.TimeoutMS > 180_000 {
		bridge.WriteError(w, http.StatusBadRequest, "invalid_request", "invalid local deployment parameters", false)
		return
	}
	spec, layer, err := workload.Generate(input.Kind, input.SizeBytes)
	if err != nil {
		bridge.WriteError(w, http.StatusInternalServerError, "workload_failed", err.Error(), true)
		return
	}
	manifest, err := artifact.Publish(req.Context(), a.artifacts, spec.Kind, [][]byte{[]byte("misscomputer-runtime-base-v1"), layer}, map[string]string{"build_id": spec.BuildID})
	if err != nil {
		bridge.WriteError(w, http.StatusInternalServerError, "artifact_failed", err.Error(), true)
		return
	}
	a.deployRequest(w, req, control.DeployRequest{
		DeploymentID: input.DeploymentID, Manifest: manifest, ManifestKey: artifact.ManifestKey(manifest.ImageDigest), Workload: spec,
		Timeout: time.Duration(input.TimeoutMS) * time.Millisecond,
	})
}

func (a *api) deployRequest(w http.ResponseWriter, req *http.Request, input control.DeployRequest) {
	a.mu.Lock()
	ready := a.chainState != nil && a.minerSetReady && a.minerSetBlock == a.chainState.Block
	minerCount := len(a.miners)
	a.mu.Unlock()
	if !ready {
		bridge.WriteError(w, http.StatusServiceUnavailable, "metagraph_not_ready", "validator chain state has not been synchronized", true)
		return
	}
	if minerCount < 3 {
		bridge.WriteError(w, http.StatusServiceUnavailable, "insufficient_miners", "fewer than three authenticated miners are registered", true)
		return
	}
	result, err := a.scheduler.Deploy(req.Context(), input)
	if err != nil {
		bridge.WriteError(w, http.StatusUnprocessableEntity, "deployment_failed", err.Error(), false)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (a *api) deployment(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("deployment")
	snapshot, exists := a.ledger.Snapshot(id)
	if !exists {
		bridge.WriteError(w, http.StatusNotFound, "not_found", "deployment is unknown", false)
		return
	}
	writeJSON(w, http.StatusOK, deploymentView{Deployment: snapshot, Active: a.scheduler.ActiveReplicas(id), Routes: a.scheduler.Router.Replicas(snapshot.RouteHost)})
}

func (a *api) deactivateDeployment(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("deployment")
	if err := a.scheduler.DeactivateDeployment(req.Context(), id); err != nil {
		bridge.WriteError(w, http.StatusBadGateway, "cleanup_failed", err.Error(), true)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"protocol": neuron.SynapseVersion, "status": "deactivated", "deployment_id": id})
}

func (a *api) health(w http.ResponseWriter, req *http.Request) {
	var input neuron.HealthObservation
	if err := decodeJSON(req.Body, &input); err != nil {
		bridge.WriteError(w, http.StatusBadRequest, "invalid_request", err.Error(), false)
		return
	}
	now := time.Now().UTC()
	if input.Protocol != neuron.SynapseVersion || input.ObservedAt.IsZero() || input.Vantage == "" ||
		input.LatencyMS < 0 || input.Availability < 0 || input.Availability > 1 ||
		input.ObservedAt.Before(now.Add(-5*time.Minute)) || input.ObservedAt.After(now.Add(30*time.Second)) {
		bridge.WriteError(w, http.StatusBadRequest, "invalid_request", "invalid health observation", false)
		return
	}
	scoringDisposition, _ := a.scheduler.DeploymentScoringDisposition(input.DeploymentID)
	action, err := a.scheduler.HandleHealth(req.Context(), input.DeploymentID, input.ReplicaID, input.MinerHotkey, input.Vantage, input.Reachable, input.Correct, input.Fraudulent, input.ObservedAt)
	if err != nil {
		bridge.WriteError(w, http.StatusUnprocessableEntity, "health_action_failed", err.Error(), false)
		return
	}
	if err := a.recordHealthObservation(scoringDisposition, input); err != nil {
		bridge.WriteError(w, http.StatusInternalServerError, "state_error", err.Error(), true)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"protocol": neuron.SynapseVersion, "action": action})
}

func (a *api) recordHealthObservation(disposition control.ScoringDisposition, input neuron.HealthObservation) error {
	if disposition == control.ScoringEvidenceOnly {
		return nil
	}
	return a.ledger.RecordObservation(durable.Observation{
		MinerHotkey: input.MinerHotkey, Success: input.Reachable && input.Correct && !input.Fraudulent,
		LatencyMS: input.LatencyMS, Availability: input.Availability, ObservedAt: input.ObservedAt, Kind: "health",
	})
}

func (a *api) weights(w http.ResponseWriter, req *http.Request) {
	hours := 24
	if raw := req.URL.Query().Get("hours"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 24*30 {
			bridge.WriteError(w, http.StatusBadRequest, "invalid_window", "hours must be in [1,720]", false)
			return
		}
		hours = parsed
	}
	observations, err := a.store.Observations(req.Context(), time.Now().UTC().Add(-time.Duration(hours)*time.Hour))
	if err != nil {
		bridge.WriteError(w, http.StatusInternalServerError, "state_error", err.Error(), true)
		return
	}
	trust, err := a.store.TrustSnapshot(req.Context())
	if err != nil {
		bridge.WriteError(w, http.StatusInternalServerError, "state_error", err.Error(), true)
		return
	}
	weights := validatorcore.PrepareWeights(observations, trust, time.Second)
	writeJSON(w, http.StatusOK, map[string]any{"protocol": neuron.SynapseVersion, "dry_run": true, "weights": weights})
}

// resolveStartupAssignment removes one durably deactivated member from the
// immutable startup recovery snapshot. Membership only ever shrinks; nothing
// is added after loadStartupRecovery.
func (a *api) resolveStartupAssignment(hotkey, endpointID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	items := a.startupRecovery[hotkey]
	remaining := items[:0]
	for _, item := range items {
		if item.endpoint.EndpointID != endpointID {
			remaining = append(remaining, item)
		}
	}
	if len(remaining) == 0 {
		delete(a.startupRecovery, hotkey)
		return
	}
	a.startupRecovery[hotkey] = remaining
}

func (a *api) recovery(w http.ResponseWriter, req *http.Request) {
	active, err := a.store.CleanupAssignments(req.Context(), "")
	if err != nil {
		bridge.WriteError(w, http.StatusInternalServerError, "state_error", err.Error(), true)
		return
	}
	a.mu.Lock()
	pendingStartup := 0
	for _, items := range a.startupRecovery {
		pendingStartup += len(items)
	}
	a.mu.Unlock()
	writeJSON(w, http.StatusOK, neuron.RecoveryResponse{
		Protocol: neuron.SynapseVersion, NonDeactivatedAssignments: len(active),
		PendingStartupAssignments: pendingStartup,
	})
}

func decodeJSON(reader io.Reader, output any) error {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request must contain one JSON value")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
