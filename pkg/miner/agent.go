// SPDX-License-Identifier: AGPL-3.0-only

package miner

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
	"github.com/misscomputer/misscomputer-subnet/pkg/durable"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	deployruntime "github.com/misscomputer/misscomputer-subnet/pkg/runtime"
	"github.com/misscomputer/misscomputer-subnet/pkg/tunnel"
)

type Result struct {
	Receipt    protocol.Receipt `json:"receipt"`
	EndpointID string           `json:"endpoint_id"`
	Idempotent bool             `json:"-"`
}

type Assigner interface {
	ID() string
	PublicKey() ed25519.PublicKey
	Assign(ctx context.Context, ticket protocol.Ticket) (Result, error)
	Deactivate(ctx context.Context, endpointID string) error
}

type SubnetIdentity struct {
	Hotkey string
	UID    *uint16
	// AxonURL is the normalized assignment-time transport address of the
	// miner. The scheduler signs it into each bound ticket so cleanup and
	// restart recovery stay bound to the exact axon that received the work.
	AxonURL                    string
	Transport                  string
	TransportCertificateSHA256 string
}

// BoundAssigner is implemented by remote neuron adapters. The scheduler uses
// this metadata only to bind its signed ticket; it never delegates placement
// or replacement decisions to Python.
type BoundAssigner interface {
	Assigner
	SubnetIdentity() SubnetIdentity
}

type Agent struct {
	MinerID              string
	OwnerKey             ed25519.PublicKey
	SigningKey           ed25519.PrivateKey
	Artifacts            artifact.Store
	Runtime              deployruntime.Runtime
	Tunnels              tunnel.Registry
	HTTPClient           *http.Client
	mu                   sync.Mutex
	seenNonces           map[string]struct{}
	instances            map[string]string
	instanceURLs         map[string]string
	instanceCleanupPaths map[string]string
	instanceCleanupRoots map[string]string
	// creating remains true from the durable pre-launch incarnation through
	// receipt persistence. A concurrent deactivation may stop the deterministic
	// identity immediately, but must leave that row recoverable until the
	// creator observes the fence and performs its final idempotent cleanup.
	creating              map[string]bool
	deactivationRequested map[string]bool
	State                 *durable.Store
	// MinerTransport and MinerTLSCertificateSHA256 are the local operator
	// configuration. Network-facing tickets must match them exactly so a
	// signed registration or ticket cannot downgrade the running miner.
	MinerTransport            string
	MinerTLSCertificateSHA256 string
}

func NewAgent(id string, ownerKey ed25519.PublicKey, signingKey ed25519.PrivateKey, artifacts artifact.Store, runtime deployruntime.Runtime, tunnels tunnel.Registry) *Agent {
	return &Agent{
		MinerID: id, OwnerKey: ownerKey, SigningKey: signingKey, Artifacts: artifacts, Runtime: runtime, Tunnels: tunnels,
		seenNonces: make(map[string]struct{}), instances: make(map[string]string), instanceURLs: make(map[string]string),
		instanceCleanupPaths: make(map[string]string), instanceCleanupRoots: make(map[string]string),
		creating: make(map[string]bool), deactivationRequested: make(map[string]bool),
	}
}

func (a *Agent) ID() string { return a.MinerID }

func (a *Agent) PublicKey() ed25519.PublicKey { return a.SigningKey.Public().(ed25519.PublicKey) }

func (a *Agent) Assign(ctx context.Context, ticket protocol.Ticket) (Result, error) {
	seen := time.Now().UTC()
	if err := protocol.VerifyTicket(ticket, a.OwnerKey, seen); err != nil {
		return Result{}, err
	}
	return a.assignVerified(ctx, ticket, seen)
}

// AssignBound is the neuron-facing entry point. callerHotkey is asserted by
// the local Python btauth verifier and carried over an authenticated loopback
// bridge; Go independently checks every signed ticket binding before work.
func (a *Agent) AssignBound(ctx context.Context, ticket protocol.Ticket, validatorServiceKey ed25519.PublicKey, currentBlock uint64, network string, netuid uint16, callerHotkey, minerHotkey string, minerUID *uint16) (Result, error) {
	seen := time.Now().UTC()
	if err := protocol.VerifyBoundTicket(ticket, validatorServiceKey, seen, currentBlock, network, netuid, callerHotkey, minerHotkey, minerUID); err != nil {
		return Result{}, err
	}
	if ticket.Subnet.MinerServicePublicKey != hex.EncodeToString(a.PublicKey()) {
		return Result{}, fmt.Errorf("ticket miner service key does not match this agent")
	}
	if err := a.ValidateSubnetTransport(ticket); err != nil {
		return Result{}, err
	}
	return a.assignVerified(ctx, ticket, seen)
}

// ValidateSubnetTransport rejects legacy and downgraded durable tickets before
// assignment, status, or cleanup can act on their identity.
func (a *Agent) ValidateSubnetTransport(ticket protocol.Ticket) error {
	if ticket.Version != protocol.BoundVersion || ticket.Subnet == nil {
		return fmt.Errorf("network ticket lacks the current bound transport identity")
	}
	if ticket.Subnet.MinerTransport != a.MinerTransport ||
		!optionalStringEquals(ticket.Subnet.MinerTLSCertificateSHA256, a.MinerTLSCertificateSHA256) {
		return fmt.Errorf("ticket miner transport or certificate pin does not match this agent")
	}
	if a.MinerTransport == "https" {
		if !canonicalSHA256(a.MinerTLSCertificateSHA256) {
			return fmt.Errorf("agent HTTPS certificate pin is invalid")
		}
		return nil
	}
	if a.MinerTransport != "http" || a.MinerTLSCertificateSHA256 != "" {
		return fmt.Errorf("agent transport configuration is invalid")
	}
	return nil
}

func optionalStringEquals(value *string, expected string) bool {
	if expected == "" {
		return value == nil
	}
	return value != nil && *value == expected
}

func canonicalSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(value) == 64 && len(decoded) == 32 && value == hex.EncodeToString(decoded)
}

func (a *Agent) assignVerified(ctx context.Context, ticket protocol.Ticket, seen time.Time) (Result, error) {
	if ticket.MinerID != a.MinerID {
		return Result{}, fmt.Errorf("ticket assigned to %q, agent is %q", ticket.MinerID, a.MinerID)
	}
	endpointID := protocol.EndpointID(ticket)
	if a.State != nil {
		if cached, exists, err := a.State.CachedResult(ctx, endpointID); err != nil {
			return Result{}, err
		} else if exists && cached.Stage == protocol.StageReady && cached.AssignmentNonce == ticket.AssignmentNonce {
			stored, _, found, err := a.State.AssignmentTicket(ctx, endpointID)
			if err != nil {
				return Result{}, err
			}
			if !found || !protocol.EqualTicket(stored, ticket) {
				return Result{}, fmt.Errorf("assignment endpoint %q conflicts with another exact ticket", endpointID)
			}
			return Result{Receipt: cached, EndpointID: endpointID, Idempotent: true}, nil
		}
		reserved, err := a.State.ReserveReplay(ctx, "assignment", ticket.AssignmentNonce, ticket.ExpiresAt.Add(time.Minute))
		if err != nil {
			return Result{}, err
		}
		if !reserved {
			return Result{}, fmt.Errorf("replayed assignment nonce")
		}
		if err := a.State.SaveAssignment(ctx, ticket, "processing"); err != nil {
			return Result{}, err
		}
	} else {
		a.mu.Lock()
		if _, exists := a.seenNonces[ticket.AssignmentNonce]; exists {
			a.mu.Unlock()
			return Result{}, fmt.Errorf("replayed assignment nonce")
		}
		a.seenNonces[ticket.AssignmentNonce] = struct{}{}
		a.mu.Unlock()
	}
	replicaID := protocol.ReplicaID(ticket)
	receipt := protocol.Receipt{
		Version: ticket.Version, DeploymentID: ticket.DeploymentID, Generation: ticket.Generation,
		AssignmentNonce: ticket.AssignmentNonce, MinerID: a.MinerID, ReplicaID: replicaID,
		EndpointID: endpointID, ImageDigest: ticket.ImageDigest, ManifestKey: ticket.ManifestKey,
		RouteHost: ticket.RouteHost, Stage: protocol.StageFailed, AssignmentSeen: seen, PullStarted: time.Now().UTC(), Subnet: ticket.Subnet,
	}
	manifest, layers, err := artifact.Fetch(ctx, a.Artifacts, ticket.ManifestKey, ticket.ImageDigest)
	if err != nil {
		return a.failed(receipt, err)
	}
	receipt.PullCompleted = time.Now().UTC()
	if a.Runtime == nil {
		return a.failed(receipt, fmt.Errorf("runtime backend is unavailable for assignment"))
	}
	cleanupPlan, err := deployruntime.PrepareCleanup(a.Runtime, ticket)
	if err != nil {
		return a.failed(receipt, err)
	}
	expectedInstanceID := cleanupPlan.InstanceID
	// Publish the scheduler-derived cleanup identity before Runtime.Deploy can
	// ask a daemon to create anything. RuntimeURL intentionally stays empty:
	// active + empty URL is the durable creating/cleanup incarnation. Docker's
	// exact prepared layer path is persisted with it for restart cleanup even
	// if the configured state directory later changes.
	a.mu.Lock()
	a.instances[endpointID] = expectedInstanceID
	a.instanceURLs[endpointID] = ""
	a.instanceCleanupPaths[endpointID] = cleanupPlan.LayerPath
	a.instanceCleanupRoots[endpointID] = cleanupPlan.LayerRoot
	a.creating[endpointID] = true
	a.mu.Unlock()
	if a.State != nil {
		if err := a.State.PutEndpoint(ctx, durable.Endpoint{
			EndpointID: endpointID, DeploymentID: ticket.DeploymentID, MinerHotkey: a.MinerID,
			RuntimeID: expectedInstanceID, RuntimeURL: "", RuntimeCleanupPath: cleanupPlan.LayerPath, RuntimeCleanupRoot: cleanupPlan.LayerRoot, Active: true,
		}); err != nil {
			a.cleanupEndpoint(endpointID)
			return a.failed(receipt, err)
		}
	}
	instance, err := a.Runtime.Deploy(ctx, ticket, manifest, layers)
	if err != nil {
		a.cleanupEndpoint(endpointID)
		return a.failed(receipt, err)
	}
	if instance.ID != expectedInstanceID {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		unexpectedErr := a.Runtime.Stop(cleanupCtx, instance.ID)
		cancel()
		a.cleanupEndpoint(endpointID)
		identityErr := fmt.Errorf("runtime returned non-deterministic instance identity %q, expected %q", instance.ID, expectedInstanceID)
		if unexpectedErr != nil {
			identityErr = fmt.Errorf("%w; unexpected runtime cleanup: %v", identityErr, unexpectedErr)
		}
		return a.failed(receipt, identityErr)
	}
	// Record the scheduler-derived endpoint mapping before any subsequent step
	// can fail or observe cancellation. Deactivate can now always resolve a
	// successfully-created runtime, even while Assign is still in flight.
	a.mu.Lock()
	a.instances[endpointID] = instance.ID
	a.instanceURLs[endpointID] = instance.URL
	a.mu.Unlock()
	if a.State != nil {
		if err := a.State.PutEndpoint(ctx, durable.Endpoint{
			EndpointID: endpointID, DeploymentID: ticket.DeploymentID, MinerHotkey: a.MinerID,
			RuntimeID: instance.ID, RuntimeURL: instance.URL, RuntimeCleanupPath: cleanupPlan.LayerPath, RuntimeCleanupRoot: cleanupPlan.LayerRoot, Active: true,
		}); err != nil {
			a.cleanupEndpoint(endpointID)
			return a.failed(receipt, err)
		}
	}
	receipt.RuntimeStarted = time.Now().UTC()
	if err := ctx.Err(); err != nil {
		a.cleanupEndpoint(endpointID)
		return a.failed(receipt, err)
	}
	if err := a.Tunnels.Register(endpointID, instance.URL); err != nil {
		a.cleanupEndpoint(endpointID)
		return a.failed(receipt, err)
	}
	client := a.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: time.Second}
	}
	if err := waitForHealth(ctx, client, instance.URL+ticket.Health.Path, ticket.Health); err != nil {
		a.cleanupEndpoint(endpointID)
		return a.failed(receipt, err)
	}
	receipt.HealthPassed = time.Now().UTC()
	receipt.Stage = protocol.StageReady
	if err := protocol.SignReceipt(&receipt, a.SigningKey); err != nil {
		a.cleanupEndpoint(endpointID)
		return Result{}, err
	}
	if a.State != nil {
		if err := a.State.SaveReceipt(ctx, receipt); err != nil {
			a.cleanupEndpoint(endpointID)
			return Result{}, err
		}
	}
	a.mu.Lock()
	deactivationRequested := a.deactivationRequested[endpointID]
	a.creating[endpointID] = false
	a.mu.Unlock()
	if deactivationRequested {
		a.cleanupEndpoint(endpointID)
		return a.failed(receipt, durable.ErrEndpointDeactivated)
	}
	return Result{Receipt: receipt, EndpointID: endpointID}, nil
}

// Deactivate resolves a scheduler-derived endpoint identity through private
// agent state. The scheduler never supplies or trusts a miner runtime ID.
func (a *Agent) Deactivate(ctx context.Context, endpointID string) error {
	a.mu.Lock()
	a.deactivationRequested[endpointID] = true
	a.mu.Unlock()
	if a.Tunnels != nil {
		a.Tunnels.Unregister(endpointID)
	}
	deploymentID := ""
	validatorHotkey := ""
	cleanupPath := ""
	cleanupRoot := ""
	if a.State != nil {
		ticket, _, exists, err := a.State.AssignmentTicket(ctx, endpointID)
		if err != nil {
			return err
		}
		if exists {
			deploymentID = ticket.DeploymentID
			if ticket.Subnet != nil {
				validatorHotkey = ticket.Subnet.ValidatorHotkey
			}
			// Upgrade assignment-only rows left by the reviewed version into an
			// exact recoverable cleanup incarnation before fencing. This makes a
			// failed Stop survive into the next restart instead of disappearing
			// when the assignment status becomes deactivated.
			endpoint, hasEndpoint, endpointErr := a.State.EndpointIncarnation(ctx, endpointID)
			if endpointErr != nil {
				return endpointErr
			}
			if !hasEndpoint {
				cleanupPlan, planErr := deployruntime.RecoverCleanup(ctx, a.Runtime, ticket)
				if planErr != nil {
					return planErr
				}
				endpoint = durable.Endpoint{
					EndpointID: endpointID, DeploymentID: deploymentID, MinerHotkey: a.MinerID,
					RuntimeID: cleanupPlan.InstanceID, RuntimeCleanupPath: cleanupPlan.LayerPath, RuntimeCleanupRoot: cleanupPlan.LayerRoot, Active: true,
				}
				if err := a.State.PutCleanupEndpoint(ctx, endpoint); err != nil {
					return err
				}
			} else if endpoint.RuntimeCleanupPath == "" || endpoint.RuntimeCleanupRoot == "" {
				cleanupPlan := deployruntime.CleanupPlan{
					InstanceID: endpoint.RuntimeID, LayerPath: endpoint.RuntimeCleanupPath,
				}
				if endpoint.RuntimeCleanupPath != "" {
					// da6dc42 already persisted the exact deterministic path but
					// predates the ownership-root column. Preserve that path across
					// configuration changes and add its original parent boundary.
					cleanupPlan.LayerRoot = filepath.Dir(endpoint.RuntimeCleanupPath)
				} else {
					var planErr error
					cleanupPlan, planErr = deployruntime.RecoverCleanup(ctx, a.Runtime, ticket)
					if planErr != nil {
						return planErr
					}
				}
				if cleanupPlan.InstanceID == endpoint.RuntimeID {
					endpoint.RuntimeCleanupPath = cleanupPlan.LayerPath
					endpoint.RuntimeCleanupRoot = cleanupPlan.LayerRoot
					if err := a.State.PutCleanupEndpoint(ctx, endpoint); err != nil {
						return err
					}
				}
			}
			cleanupPath = endpoint.RuntimeCleanupPath
			cleanupRoot = endpoint.RuntimeCleanupRoot
			a.mu.Lock()
			if a.instances[endpointID] == "" {
				a.instances[endpointID] = endpoint.RuntimeID
				a.instanceURLs[endpointID] = endpoint.RuntimeURL
			}
			if a.instanceCleanupPaths[endpointID] == "" {
				a.instanceCleanupPaths[endpointID] = cleanupPath
			}
			if a.instanceCleanupRoots[endpointID] == "" {
				a.instanceCleanupRoots[endpointID] = cleanupRoot
			}
			a.mu.Unlock()
			if err := a.State.FenceEndpointDeactivation(ctx, endpointID, deploymentID, a.MinerID, validatorHotkey); err != nil {
				return err
			}
		}
	}
	a.mu.Lock()
	instanceID := a.instances[endpointID]
	if cleanupPath == "" {
		cleanupPath = a.instanceCleanupPaths[endpointID]
	}
	if cleanupRoot == "" {
		cleanupRoot = a.instanceCleanupRoots[endpointID]
	}
	creating := a.creating[endpointID]
	a.mu.Unlock()
	if instanceID == "" {
		if a.State != nil && deploymentID != "" {
			return a.State.CompleteEndpointDeactivation(ctx, endpointID, deploymentID, a.MinerID)
		}
		return nil
	}
	if a.Runtime == nil {
		return fmt.Errorf("runtime backend is unavailable for endpoint cleanup")
	}
	if err := deployruntime.StopCleanup(ctx, a.Runtime, deployruntime.CleanupPlan{InstanceID: instanceID, LayerPath: cleanupPath, LayerRoot: cleanupRoot}); err != nil {
		return err
	}
	// A creator that has not yet returned from Deploy can launch after this
	// idempotent Stop. Its durable row therefore stays active until the creator
	// observes deactivationRequested, stops again, and completes cleanup. After
	// a process restart creating is false, so recovery can complete normally.
	if creating {
		return nil
	}
	// Persist the lifecycle transition before discarding the private runtime
	// mapping. If SQLite fails, a retry still has the exact runtime identity;
	// runtimes are required to make Stop idempotent.
	if a.State != nil {
		if err := a.State.CompleteEndpointDeactivation(ctx, endpointID, deploymentID, a.MinerID); err != nil {
			return err
		}
	}
	a.mu.Lock()
	if a.instances[endpointID] == instanceID {
		delete(a.instances, endpointID)
		delete(a.instanceURLs, endpointID)
		delete(a.instanceCleanupPaths, endpointID)
		delete(a.instanceCleanupRoots, endpointID)
	}
	a.mu.Unlock()
	return nil
}

// FenceDeactivation records a validator-owned cancellation that reaches the
// miner before its matching assignment request. The later signed exact ticket
// may be audited, but Assign can never create or activate its runtime.
func (a *Agent) FenceDeactivation(ctx context.Context, endpointID, deploymentID, validatorHotkey string) error {
	if a.State == nil {
		return fmt.Errorf("durable miner state is required for pre-assignment deactivation")
	}
	a.mu.Lock()
	a.deactivationRequested[endpointID] = true
	a.mu.Unlock()
	if err := a.State.FenceEndpointDeactivation(ctx, endpointID, deploymentID, a.MinerID, validatorHotkey); err != nil {
		return err
	}
	endpoint, exists, err := a.State.EndpointIncarnation(ctx, endpointID)
	if err != nil || !exists {
		return err
	}
	a.mu.Lock()
	creating := a.creating[endpointID]
	if a.instances[endpointID] == "" {
		a.instances[endpointID] = endpoint.RuntimeID
		a.instanceURLs[endpointID] = endpoint.RuntimeURL
	}
	if a.instanceCleanupPaths[endpointID] == "" {
		a.instanceCleanupPaths[endpointID] = endpoint.RuntimeCleanupPath
	}
	if a.instanceCleanupRoots[endpointID] == "" {
		a.instanceCleanupRoots[endpointID] = endpoint.RuntimeCleanupRoot
	}
	a.mu.Unlock()
	if a.Runtime == nil {
		return fmt.Errorf("runtime backend is unavailable for endpoint cleanup")
	}
	if err := deployruntime.StopCleanup(ctx, a.Runtime, deployruntime.CleanupPlan{
		InstanceID: endpoint.RuntimeID, LayerPath: endpoint.RuntimeCleanupPath, LayerRoot: endpoint.RuntimeCleanupRoot,
	}); err != nil {
		return err
	}
	if creating {
		return nil
	}
	if err := a.State.CompleteEndpointDeactivation(ctx, endpointID, deploymentID, a.MinerID); err != nil {
		return err
	}
	a.mu.Lock()
	if a.instances[endpointID] == endpoint.RuntimeID {
		delete(a.instances, endpointID)
		delete(a.instanceURLs, endpointID)
		delete(a.instanceCleanupPaths, endpointID)
		delete(a.instanceCleanupRoots, endpointID)
	}
	a.mu.Unlock()
	return nil
}

// RecoverCleanup removes runtime incarnations left active across a service
// restart before accepting new assignments. It is safe for already-absent
// runtime objects and leaves failed cleanup rows active for the next retry.
func (a *Agent) RecoverCleanup(ctx context.Context) error {
	if a.State == nil {
		return nil
	}
	endpoints, err := a.State.ActiveEndpoints(ctx)
	if err != nil {
		return err
	}
	for _, endpoint := range endpoints {
		a.mu.Lock()
		a.instances[endpoint.EndpointID] = endpoint.RuntimeID
		a.instanceURLs[endpoint.EndpointID] = endpoint.RuntimeURL
		a.instanceCleanupPaths[endpoint.EndpointID] = endpoint.RuntimeCleanupPath
		a.instanceCleanupRoots[endpoint.EndpointID] = endpoint.RuntimeCleanupRoot
		a.mu.Unlock()
		if err := a.Deactivate(ctx, endpoint.EndpointID); err != nil {
			return fmt.Errorf("recover endpoint %s: %w", endpoint.EndpointID, err)
		}
	}
	// Also close the crash window after a ticket was durably published but
	// before any runtime-incarnation row existed.
	pending, err := a.State.AssignmentsWithoutIncarnation(ctx, a.MinerID)
	if err != nil {
		return err
	}
	for _, assignment := range pending {
		if err := a.Deactivate(ctx, assignment.EndpointID); err != nil {
			return fmt.Errorf("recover assignment %s: %w", assignment.EndpointID, err)
		}
	}
	return nil
}

// maxProbeChallengeResponseBytes strictly bounds the only response the agent
// ever buffers: the hidden challenge body, whose correct form is a 64-byte
// digest string. Anything larger fails the probe closed before more is read.
const maxProbeChallengeResponseBytes = 64 << 10

var errProbeResponseRejected = errors.New("probe challenge response rejected")

// probeInterception carries the already-admitted scheduler-derived assignment
// binding for exactly one challenge probe between request admission and
// response attestation.
type probeInterception struct {
	nonce  string
	ticket protocol.Ticket
}

// ProxyRuntime resolves only the scheduler-derived endpoint ID retained in
// private agent state. No miner-provided container/runtime identifier crosses
// this boundary. A request carrying the public probe nonce header is admitted
// only as the exact active assignment challenge request and, when the served
// bytes match the signed challenge digest, leaves with exactly one
// miner-signed attestation header; the workload can never supply one.
func (a *Agent) ProxyRuntime(w http.ResponseWriter, req *http.Request, endpointID string) {
	a.mu.Lock()
	rawURL := a.instanceURLs[endpointID]
	a.mu.Unlock()
	if rawURL == "" {
		http.Error(w, "endpoint is inactive", http.StatusNotFound)
		return
	}
	var probe *probeInterception
	if nonces := req.Header.Values(protocol.ProbeNonceHeader); len(nonces) > 0 {
		interception, status, err := a.admitProbe(req, endpointID, nonces)
		if err != nil {
			http.Error(w, err.Error(), status)
			return
		}
		probe = interception
	}
	target, err := url.Parse(rawURL)
	if err != nil {
		http.Error(w, "endpoint target invalid", http.StatusBadGateway)
		return
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	upstreamDirector := proxy.Director
	proxy.Director = func(request *http.Request) {
		upstreamDirector(request)
		// The nonce is edge/agent probe protocol and only this agent may ever
		// produce the attestation header; neither crosses into the workload.
		request.Header.Del(protocol.ProbeNonceHeader)
		request.Header.Del(protocol.ProbeAttestationHeader)
	}
	proxy.ModifyResponse = func(response *http.Response) error {
		// A workload-supplied attestation header is always a spoof.
		response.Header.Del(protocol.ProbeAttestationHeader)
		if probe == nil {
			return nil
		}
		return a.attestProbeResponse(response, probe)
	}
	proxy.ErrorHandler = func(writer http.ResponseWriter, _ *http.Request, proxyErr error) {
		if errors.Is(proxyErr, errProbeResponseRejected) {
			http.Error(writer, "probe challenge response rejected", http.StatusBadGateway)
			return
		}
		http.Error(writer, "runtime unavailable", http.StatusBadGateway)
	}
	proxy.ServeHTTP(w, req)
}

// admitProbe admits exactly one canonical challenge probe against the retained
// scheduler-derived assignment identity. Every malformed or duplicate nonce,
// inactive, stale, or substituted ticket, restart or key-rotation
// inconsistency, and non-exact challenge request fails closed before the
// workload is contacted.
func (a *Agent) admitProbe(req *http.Request, endpointID string, nonces []string) (*probeInterception, int, error) {
	if len(nonces) != 1 || !protocol.CanonicalProbeNonce(nonces[0]) {
		return nil, http.StatusBadRequest, errors.New("probe nonce header must appear exactly once with 64 lowercase hex characters")
	}
	if a.State == nil {
		return nil, http.StatusConflict, errors.New("probe attestation requires durable miner state")
	}
	ticket, status, exists, err := a.State.AssignmentTicket(req.Context(), endpointID)
	if err != nil {
		return nil, http.StatusInternalServerError, errors.New("probe assignment state is unavailable")
	}
	if !exists || status != string(protocol.StageReady) {
		return nil, http.StatusConflict, errors.New("probe endpoint has no ready assignment")
	}
	if protocol.EndpointID(ticket) != endpointID {
		return nil, http.StatusConflict, errors.New("probe assignment identity mismatch")
	}
	if err := a.ValidateSubnetTransport(ticket); err != nil {
		return nil, http.StatusConflict, errors.New("probe assignment transport identity mismatch")
	}
	binding := ticket.Subnet
	if binding.MinerHotkey != a.MinerID || ticket.MinerID != a.MinerID ||
		binding.MinerServicePublicKey != hex.EncodeToString(a.PublicKey()) {
		return nil, http.StatusConflict, errors.New("probe assignment service identity mismatch")
	}
	validatorKey, err := hex.DecodeString(binding.ValidatorServicePublicKey)
	if err != nil || len(validatorKey) != ed25519.PublicKeySize {
		return nil, http.StatusConflict, errors.New("probe assignment validator key is invalid")
	}
	if err := protocol.VerifyTicketSignature(ticket, ed25519.PublicKey(validatorKey)); err != nil {
		return nil, http.StatusConflict, errors.New("probe assignment ticket signature is invalid")
	}
	if req.Method != http.MethodGet || req.URL.Path != ticket.ChallengePath ||
		req.URL.RawQuery != "" || req.URL.Fragment != "" {
		return nil, http.StatusConflict, errors.New("probe request is not the exact assignment challenge request")
	}
	return &probeInterception{nonce: nonces[0], ticket: ticket}, 0, nil
}

// attestProbeResponse buffers the admitted challenge response within a strict
// small bound, requires status 200 and the ticket's exact signed challenge
// digest, and sets exactly one canonical miner-signed attestation header. Any
// status, size, digest, build, or signing mismatch fails the exchange closed.
func (a *Agent) attestProbeResponse(response *http.Response, probe *probeInterception) error {
	if response.StatusCode != http.StatusOK {
		return errProbeResponseRejected
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxProbeChallengeResponseBytes+1))
	closeErr := response.Body.Close()
	if err != nil || closeErr != nil || len(body) > maxProbeChallengeResponseBytes {
		return errProbeResponseRejected
	}
	digest := sha256.Sum256(body)
	attestation, err := protocol.BuildProbeAttestation(probe.ticket, probe.nonce, hex.EncodeToString(digest[:]))
	if err != nil {
		return errProbeResponseRejected
	}
	if err := protocol.SignProbeAttestation(&attestation, a.SigningKey); err != nil {
		return errProbeResponseRejected
	}
	header, err := protocol.EncodeProbeAttestationHeader(attestation)
	if err != nil {
		return errProbeResponseRejected
	}
	response.Header.Set(protocol.ProbeAttestationHeader, header)
	response.Header.Set("Content-Length", strconv.Itoa(len(body)))
	response.ContentLength = int64(len(body))
	response.TransferEncoding = nil
	response.Body = io.NopCloser(bytes.NewReader(body))
	return nil
}

// cleanupEndpoint is deliberately independent of the assignment context: a
// cancelled deployment request must not prevent runtime or tunnel cleanup.
func (a *Agent) cleanupEndpoint(endpointID string) {
	a.mu.Lock()
	a.creating[endpointID] = false
	a.deactivationRequested[endpointID] = true
	a.mu.Unlock()
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = a.Deactivate(cleanupCtx, endpointID)
}

func waitForHealth(ctx context.Context, client *http.Client, target string, spec protocol.HealthSpec) error {
	timeout := time.Duration(spec.TimeoutMillis) * time.Millisecond
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	interval := time.Duration(spec.IntervalMillis) * time.Millisecond
	if interval <= 0 {
		interval = 100 * time.Millisecond
	}
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == spec.ExpectedStatus {
				return nil
			}
			lastErr = fmt.Errorf("health returned %d", resp.StatusCode)
		} else {
			lastErr = err
		}
		if time.Now().Add(interval).After(deadline) {
			return fmt.Errorf("health did not pass before timeout: %w", lastErr)
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (a *Agent) failed(receipt protocol.Receipt, cause error) (Result, error) {
	receipt.Error = cause.Error()
	_ = protocol.SignReceipt(&receipt, a.SigningKey)
	if a.State != nil {
		_ = a.State.SaveReceipt(context.Background(), receipt)
	}
	return Result{Receipt: receipt}, cause
}
