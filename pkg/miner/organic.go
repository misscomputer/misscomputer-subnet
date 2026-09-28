// SPDX-License-Identifier: AGPL-3.0-only

package miner

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
	"github.com/misscomputer/misscomputer-subnet/pkg/durable"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	deployruntime "github.com/misscomputer/misscomputer-subnet/pkg/runtime"
)

// ResultV4 is the miner's answer to one deployment.v4 assignment. The
// neuron bridge renders it as neuron.MinerResultV4.
type ResultV4 struct {
	Receipt    protocol.ReceiptV4
	EndpointID string
	Idempotent bool
}

// AssignBoundV4 is the neuron-facing entry point for organic assignments
// carried by subnet-synapse.v3. callerHotkey was authenticated by the Python
// btauth verifier; Go independently verifies the signed ticket, its subnet
// binding and this agent's transport identity before any work.
func (a *Agent) AssignBoundV4(ctx context.Context, ticket protocol.TicketV4, validatorServiceKey ed25519.PublicKey, currentBlock uint64, network string, netuid uint16, callerHotkey, minerHotkey string, minerUID *uint16) (ResultV4, error) {
	seen := time.Now().UTC()
	if err := protocol.VerifyBoundTicket(ticket, validatorServiceKey, seen, currentBlock, network, netuid, callerHotkey, minerHotkey, minerUID); err != nil {
		return ResultV4{}, err
	}
	if ticket.Subnet.MinerServicePublicKey != hex.EncodeToString(a.PublicKey()) {
		return ResultV4{}, fmt.Errorf("ticket miner service key does not match this agent")
	}
	if err := a.validateTransportBinding(ticket.Subnet); err != nil {
		return ResultV4{}, err
	}
	return a.assignVerifiedV4(ctx, ticket, seen)
}

func (a *Agent) assignVerifiedV4(ctx context.Context, ticket protocol.TicketV4, seen time.Time) (ResultV4, error) {
	if ticket.MinerID != a.MinerID {
		return ResultV4{}, fmt.Errorf("ticket assigned to %q, agent is %q", ticket.MinerID, a.MinerID)
	}
	// TicketV4.Validate already pinned resources to organic.SmallV1; the
	// profile carries the engine settings this miner implements for it.
	profile, ok := deployruntime.LookupProfile(ticket.Workload.RuntimeProfile)
	if !ok || profile.Resources != ticket.Resources {
		return ResultV4{}, fmt.Errorf("runtime profile %q is not implemented", ticket.Workload.RuntimeProfile)
	}
	if cached, err := a.admitV4(ctx, ticket); err != nil || cached != nil {
		if cached != nil {
			return *cached, nil
		}
		return ResultV4{}, err
	}
	return a.assignOrganic(ctx, ticket, profile, seen)
}

// admitV4 enforces exact-ticket replay and one-time nonce use for v4.
func (a *Agent) admitV4(ctx context.Context, ticket protocol.TicketV4) (*ResultV4, error) {
	endpointID := protocol.EndpointIDV4(ticket)
	if a.State == nil {
		a.mu.Lock()
		defer a.mu.Unlock()
		if _, exists := a.seenNonces[ticket.AssignmentNonce]; exists {
			return nil, fmt.Errorf("replayed assignment nonce")
		}
		a.seenNonces[ticket.AssignmentNonce] = struct{}{}
		return nil, nil
	}
	if cached, exists, err := a.State.CachedResultV4(ctx, endpointID); err != nil {
		return nil, err
	} else if exists && cached.Stage == protocol.StageReady && cached.AssignmentNonce == ticket.AssignmentNonce {
		stored, _, found, err := a.State.AssignmentTicketV4(ctx, endpointID)
		if err != nil {
			return nil, err
		}
		if !found || !equalTicketV4(stored, ticket) {
			return nil, fmt.Errorf("assignment endpoint %q conflicts with another exact ticket", endpointID)
		}
		return &ResultV4{Receipt: cached, EndpointID: endpointID, Idempotent: true}, nil
	}
	reserved, err := a.State.ReserveReplay(ctx, "assignment", ticket.AssignmentNonce, ticket.ExpiresAt.Add(time.Minute))
	if err != nil {
		return nil, err
	}
	if !reserved {
		return nil, fmt.Errorf("replayed assignment nonce")
	}
	if err := a.State.SaveAssignmentV4(ctx, ticket, "processing"); err != nil {
		return nil, err
	}
	return nil, nil
}

func equalTicketV4(left, right protocol.TicketV4) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

// assignOrganic runs one admitted assignment and signs its receipt v4:
// ready with loaded_image_config_digest, or failed with an error_code.
func (a *Agent) assignOrganic(ctx context.Context, ticket protocol.TicketV4, profile deployruntime.Profile, seen time.Time) (ResultV4, error) {
	endpointID := protocol.EndpointIDV4(ticket)
	receipt := protocol.ReceiptV4{
		Version: protocol.OrganicVersion, DeploymentID: ticket.DeploymentID, Generation: ticket.Generation,
		AssignmentNonce: ticket.AssignmentNonce, MinerID: a.MinerID, ReplicaID: protocol.ReplicaIDV4(ticket),
		EndpointID: endpointID, ImageDigest: ticket.ImageDigest, ManifestKey: ticket.ManifestKey,
		RouteHost: ticket.RouteHost, Stage: protocol.StageFailed, AssignmentSeen: seen, PullStarted: time.Now().UTC(), Subnet: ticket.Subnet,
	}
	loaded, err := a.runOrganic(ctx, ticket, profile, &receipt)
	if err != nil {
		return a.failedOrganic(receipt, err)
	}
	receipt.HealthPassed = time.Now().UTC()
	receipt.Stage = protocol.StageReady
	receipt.LoadedImageConfigDigest = &loaded
	if err := protocol.SignReceiptV4(&receipt, a.SigningKey); err != nil {
		a.cleanupEndpoint(endpointID)
		return ResultV4{}, err
	}
	if a.State != nil {
		if err := a.State.SaveReceiptV4(ctx, receipt); err != nil {
			a.cleanupEndpoint(endpointID)
			return ResultV4{}, err
		}
	}
	a.mu.Lock()
	deactivationRequested := a.deactivationRequested[endpointID]
	a.creating[endpointID] = false
	a.mu.Unlock()
	if deactivationRequested {
		a.cleanupEndpoint(endpointID)
		receipt.LoadedImageConfigDigest = nil
		return a.failedOrganic(receipt, deployruntime.Fail(deployruntime.CodeDeactivated, durable.ErrEndpointDeactivated))
	}
	return ResultV4{Receipt: receipt, EndpointID: endpointID}, nil
}

// runOrganic fetches the artifact manifest by its signed digest, launches
// the verified OCI image under the ticket's profile, registers the endpoint,
// and runs startup health directly against the container. It returns the
// proven loaded image config digest. Every failure carries a receipt error
// code and has already cleaned up whatever was created.
func (a *Agent) runOrganic(ctx context.Context, ticket protocol.TicketV4, profile deployruntime.Profile, receipt *protocol.ReceiptV4) (string, error) {
	endpointID := protocol.EndpointIDV4(ticket)
	if a.OCI == nil {
		return "", deployruntime.Fail(deployruntime.CodeInternal, errors.New("organic OCI runtime is unavailable"))
	}
	blobs, ok := a.Artifacts.(artifact.BlobOpener)
	if !ok {
		return "", deployruntime.Fail(deployruntime.CodeInternal, errors.New("artifact store cannot stream blobs"))
	}
	manifest, err := artifact.FetchManifestV2(ctx, a.Artifacts, ticket.ManifestKey, ticket.ImageDigest)
	if err != nil {
		code := deployruntime.CodeArtifactFetchFailed
		if artifact.IsVerifyError(err) {
			code = deployruntime.CodeArtifactVerifyFailed
		}
		return "", deployruntime.Fail(code, err)
	}
	cleanupPlan, err := deployruntime.PrepareCleanup(a.OCI, endpointID)
	if err != nil {
		return "", deployruntime.Fail(deployruntime.CodeInternal, err)
	}
	// Cleanup ownership starts before the engine can create anything: the
	// deterministic identity is recorded (durably when state is configured)
	// with an empty URL, marking a creating incarnation.
	a.mu.Lock()
	a.instances[endpointID] = cleanupPlan.InstanceID
	a.instanceURLs[endpointID] = ""
	a.instanceCleanupPaths[endpointID] = cleanupPlan.LayerPath
	a.instanceCleanupRoots[endpointID] = cleanupPlan.LayerRoot
	a.creating[endpointID] = true
	a.mu.Unlock()
	endpoint := durable.Endpoint{
		EndpointID: endpointID, DeploymentID: ticket.DeploymentID, MinerHotkey: a.MinerID,
		RuntimeID: cleanupPlan.InstanceID, RuntimeCleanupPath: cleanupPlan.LayerPath, RuntimeCleanupRoot: cleanupPlan.LayerRoot, Active: true,
	}
	if a.State != nil {
		if err := a.State.PutEndpoint(ctx, endpoint); err != nil {
			a.cleanupEndpoint(endpointID)
			return "", organicContextFailure(err)
		}
	}
	started, err := a.OCI.Launch(ctx, deployruntime.Launch{
		InstanceID: cleanupPlan.InstanceID, ArtifactDigest: ticket.ImageDigest, Manifest: manifest,
		Blobs: blobs, Workload: ticket.Workload, Profile: profile,
	})
	if err != nil {
		a.cleanupEndpoint(endpointID)
		return "", organicContextFailure(err)
	}
	receipt.PullCompleted = started.ImageReadyAt
	if started.Instance.ID != cleanupPlan.InstanceID || started.LoadedImageConfigDigest != manifest.Config.Digest {
		a.cleanupEndpoint(endpointID)
		return "", deployruntime.Fail(deployruntime.CodeInternal, fmt.Errorf("runtime returned instance %q image %q, expected %q image %q", started.Instance.ID, started.LoadedImageConfigDigest, cleanupPlan.InstanceID, manifest.Config.Digest))
	}
	a.mu.Lock()
	a.instanceURLs[endpointID] = started.Instance.URL
	a.organicTickets[endpointID] = ticket
	a.mu.Unlock()
	endpoint.RuntimeURL = started.Instance.URL
	if a.State != nil {
		if err := a.State.PutEndpoint(ctx, endpoint); err != nil {
			a.cleanupEndpoint(endpointID)
			return "", organicContextFailure(err)
		}
	}
	receipt.RuntimeStarted = time.Now().UTC()
	if err := a.Tunnels.Register(endpointID, started.Instance.URL); err != nil {
		a.cleanupEndpoint(endpointID)
		return "", deployruntime.Fail(deployruntime.CodeInternal, err)
	}
	running := func(checkCtx context.Context) (bool, error) { return a.OCI.Running(checkCtx, started.Instance.ID) }
	if err := deployruntime.StartupHealth(ctx, a.HTTPClient, started.Instance.URL, ticket.RouteHost, ticket.Health.HealthPredicate, running); err != nil {
		a.cleanupEndpoint(endpointID)
		return "", organicContextFailure(err)
	}
	return started.LoadedImageConfigDigest, nil
}

// organicContextFailure maps a deactivation fence to the deactivated code,
// keeping any runtime-supplied code otherwise.
func organicContextFailure(err error) error {
	if errors.Is(err, durable.ErrEndpointDeactivated) {
		return deployruntime.Fail(deployruntime.CodeDeactivated, err)
	}
	return deployruntime.Fail(deployruntime.CodeInternal, err)
}

func (a *Agent) failedOrganic(receipt protocol.ReceiptV4, cause error) (ResultV4, error) {
	code := string(deployruntime.FailureCodeOf(cause))
	receipt.Stage = protocol.StageFailed
	receipt.ErrorCode = &code
	receipt.Error = deployruntime.ReceiptError(cause)
	if err := protocol.SignReceiptV4(&receipt, a.SigningKey); err != nil {
		return ResultV4{EndpointID: receipt.EndpointID}, errors.Join(cause, err)
	}
	if a.State != nil {
		_ = a.State.SaveReceiptV4(context.Background(), receipt)
	}
	return ResultV4{Receipt: receipt, EndpointID: receipt.EndpointID}, cause
}
