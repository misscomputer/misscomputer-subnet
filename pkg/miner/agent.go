// SPDX-License-Identifier: AGPL-3.0-only

package miner

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"net/http"
	"path/filepath"
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
	MinerID    string
	OwnerKey   ed25519.PublicKey
	SigningKey ed25519.PrivateKey
	Artifacts  artifact.Store
	// OCI runs organic deployment.v4 assignments (AssignBoundV4).
	OCI deployruntime.OCIRuntime
	// Static serves static-site-v1 assignments (AssignBoundStaticV1); nil
	// disables the workload and its capability.
	Static     *StaticSites
	Tunnels    tunnel.Registry
	HTTPClient *http.Client
	mu         sync.Mutex
	seenNonces map[string]struct{}
	// edgeNonces is the in-memory edge/probe nonce replay cache used only
	// when no durable State is configured.
	edgeNonces           map[string]time.Time
	instances            map[string]string
	instanceURLs         map[string]string
	instanceCleanupPaths map[string]string
	instanceCleanupRoots map[string]string
	// organicTickets holds the exact deployment.v4 ticket of every started
	// organic endpoint; the runtime ingress verifies edge requests against
	// its validator service key.
	organicTickets map[string]protocol.TicketV4
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
	// edgeReplay rejects reuse of an edge-runtime-request nonce (§6.9).
	edgeReplay edgeReplayCache
}

func NewAgent(id string, ownerKey ed25519.PublicKey, signingKey ed25519.PrivateKey, artifacts artifact.Store, runtime deployruntime.OCIRuntime, tunnels tunnel.Registry) *Agent {
	return &Agent{
		MinerID: id, OwnerKey: ownerKey, SigningKey: signingKey, Artifacts: artifacts, OCI: runtime, Tunnels: tunnels,
		seenNonces: make(map[string]struct{}), instances: make(map[string]string), instanceURLs: make(map[string]string),
		instanceCleanupPaths: make(map[string]string), instanceCleanupRoots: make(map[string]string),
		organicTickets: make(map[string]protocol.TicketV4), edgeNonces: make(map[string]time.Time),
		creating: make(map[string]bool), deactivationRequested: make(map[string]bool),
	}
}

func (a *Agent) ID() string { return a.MinerID }

func (a *Agent) PublicKey() ed25519.PublicKey { return a.SigningKey.Public().(ed25519.PublicKey) }

// ValidateSubnetTransport rejects unbound and downgraded durable tickets
// before status, cleanup, or runtime ingress can act on their identity.
func (a *Agent) ValidateSubnetTransport(ticket protocol.Ticket) error {
	if ticket.Version != protocol.OrganicVersion || ticket.Subnet == nil {
		return fmt.Errorf("network ticket lacks the current bound transport identity")
	}
	return a.validateTransportBinding(ticket.Subnet)
}

func (a *Agent) validateTransportBinding(binding *protocol.SubnetBinding) error {
	if binding == nil {
		return fmt.Errorf("network ticket lacks the current bound transport identity")
	}
	if binding.MinerTransport != a.MinerTransport ||
		!optionalStringEquals(binding.MinerTLSCertificateSHA256, a.MinerTLSCertificateSHA256) {
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

// Deactivate resolves a scheduler-derived endpoint identity through private
// agent state. The scheduler never supplies or trusts a miner runtime ID.
func (a *Agent) Deactivate(ctx context.Context, endpointID string) error {
	if handled, err := a.deactivateStatic(ctx, endpointID); handled || err != nil {
		return err
	}
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
				cleanupPlan, planErr := deployruntime.PrepareCleanup(a.cleanupBackend(), endpointID)
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
			} else if !endpoint.Active {
				// A completed exact deactivation is idempotent. Reassert its durable
				// owner fence, but never reopen the inactive incarnation merely to
				// upgrade optional backend cleanup metadata.
				return a.State.FenceEndpointDeactivation(ctx, endpointID, deploymentID, a.MinerID, validatorHotkey)
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
					cleanupPlan, planErr = deployruntime.PrepareCleanup(a.cleanupBackend(), endpointID)
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
	backend := a.cleanupBackend()
	if backend == nil {
		return fmt.Errorf("runtime backend is unavailable for endpoint cleanup")
	}
	if err := deployruntime.StopCleanup(ctx, backend, deployruntime.CleanupPlan{InstanceID: instanceID, LayerPath: cleanupPath, LayerRoot: cleanupRoot}); err != nil {
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
		delete(a.organicTickets, endpointID)
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
	backend := a.cleanupBackend()
	if backend == nil {
		return fmt.Errorf("runtime backend is unavailable for endpoint cleanup")
	}
	if err := deployruntime.StopCleanup(ctx, backend, deployruntime.CleanupPlan{
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
		delete(a.organicTickets, endpointID)
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
	if err := a.recoverStatic(ctx); err != nil {
		return err
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

// ProxyRuntime resolves only the scheduler-derived endpoint ID retained in
// private agent state. No miner-provided container/runtime identifier crosses
// this boundary. Every request must first carry a valid edge-runtime-request
// signature (§6.9) from the endpoint's ticket-bound validator service key;
// otherwise it is answered 401 without contacting the application. A request
// that also carries an organic probe authorization for this exact endpoint
// incarnation leaves with exactly one miner-signed miner-probe-attestation
// v2; the application can never supply one.
func (a *Agent) ProxyRuntime(w http.ResponseWriter, req *http.Request, endpointID string) {
	if a.Static != nil {
		if endpoint := a.Static.lookup(endpointID); endpoint != nil {
			a.serveStatic(w, req, endpointID, endpoint)
			return
		}
	}
	if _, status, err := a.authorizeEdgeRuntimeRequest(req, endpointID); err != nil {
		http.Error(w, err.Error(), status)
		return
	}
	a.mu.Lock()
	rawURL := a.instanceURLs[endpointID]
	ticket, started := a.organicTickets[endpointID]
	a.mu.Unlock()
	if rawURL == "" || !started {
		http.Error(w, "endpoint is inactive", http.StatusNotFound)
		return
	}
	a.proxyOrganic(w, req, endpointID, rawURL, ticket)
}

// cleanupBackend is the configured runtime that owns endpoint cleanup.
func (a *Agent) cleanupBackend() deployruntime.Stopper {
	if a.OCI == nil {
		return nil
	}
	return a.OCI
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
