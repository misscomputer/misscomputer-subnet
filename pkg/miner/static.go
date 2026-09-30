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
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
	"github.com/misscomputer/misscomputer-subnet/pkg/durable"
	"github.com/misscomputer/misscomputer-subnet/pkg/organic"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	deployruntime "github.com/misscomputer/misscomputer-subnet/pkg/runtime"
	"github.com/misscomputer/misscomputer-subnet/pkg/static"
)

const (
	// DefaultStaticFetchTimeout bounds manifest plus every blob of one site.
	DefaultStaticFetchTimeout = 2 * time.Minute
	// DefaultStaticRequestConcurrency bounds in-flight requests per static
	// endpoint so one busy site cannot starve other endpoints.
	DefaultStaticRequestConcurrency = 64
)

// StaticSites is the miner's static-site-v1 runtime: verified pins served by
// the shared static-handler.v1. It never starts a container, never touches
// the OCI runtime or its network, and a nil Agent.Static disables the
// workload and its capability entirely.
type StaticSites struct {
	Cache              *static.Cache
	FetchTimeout       time.Duration
	RequestConcurrency int
	mu                 sync.Mutex
	endpoints          map[string]*staticEndpoint
}

type staticEndpoint struct {
	ticket protocol.StaticTicketV1
	site   *static.Site
	slots  chan struct{}
}

// NewStaticSites configures the static runtime over an opened cache.
func NewStaticSites(cache *static.Cache, fetchTimeout time.Duration, requestConcurrency int) *StaticSites {
	if fetchTimeout <= 0 {
		fetchTimeout = DefaultStaticFetchTimeout
	}
	if requestConcurrency <= 0 {
		requestConcurrency = DefaultStaticRequestConcurrency
	}
	return &StaticSites{Cache: cache, FetchTimeout: fetchTimeout, RequestConcurrency: requestConcurrency, endpoints: make(map[string]*staticEndpoint)}
}

func (s *StaticSites) lookup(endpointID string) *staticEndpoint {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.endpoints[endpointID]
}

func (s *StaticSites) remove(endpointID string) {
	s.mu.Lock()
	endpoint := s.endpoints[endpointID]
	delete(s.endpoints, endpointID)
	s.mu.Unlock()
	if endpoint != nil {
		endpoint.site.Release()
	}
}

// StaticResultV1 is the miner's answer to one static assignment.
type StaticResultV1 struct {
	Receipt    protocol.StaticReceiptV1
	EndpointID string
	Idempotent bool
}

// AssignBoundStaticV1 is the entry point for static tickets carried by
// subnet-static-synapse.v1. callerHotkey was authenticated by the Python
// btauth verifier; Go verifies the signed ticket, its subnet binding and this
// agent's transport identity before any work. A ticket that fails these
// checks gets no receipt and consumes no nonce.
func (a *Agent) AssignBoundStaticV1(ctx context.Context, ticket protocol.StaticTicketV1, validatorServiceKey ed25519.PublicKey, currentBlock uint64, network string, netuid uint16, callerHotkey, minerHotkey string, minerUID *uint16) (StaticResultV1, error) {
	seen := time.Now().UTC()
	if a.Static == nil {
		return StaticResultV1{}, errors.New("static sites are not enabled on this miner")
	}
	if a.State == nil {
		return StaticResultV1{}, errors.New("static sites require durable miner state")
	}
	if err := protocol.VerifyBoundStaticTicketV1(ticket, validatorServiceKey, seen, currentBlock, network, netuid, callerHotkey, minerHotkey, minerUID); err != nil {
		return StaticResultV1{}, err
	}
	if ticket.Subnet.MinerServicePublicKey != hex.EncodeToString(a.PublicKey()) {
		return StaticResultV1{}, fmt.Errorf("ticket miner service key does not match this agent")
	}
	if err := a.validateTransportBinding(ticket.Subnet.Binding()); err != nil {
		return StaticResultV1{}, err
	}
	if ticket.MinerID != a.MinerID {
		return StaticResultV1{}, fmt.Errorf("ticket assigned to %q, agent is %q", ticket.MinerID, a.MinerID)
	}
	if cached, err := a.admitStatic(ctx, ticket); err != nil || cached != nil {
		if cached != nil {
			return *cached, nil
		}
		return StaticResultV1{}, err
	}
	return a.assignStatic(ctx, ticket, seen)
}

// admitStatic returns the cached ready result for the exact same ticket, or
// consumes the one-time assignment nonce (shared with deployment.v4) and
// records the exact ticket.
func (a *Agent) admitStatic(ctx context.Context, ticket protocol.StaticTicketV1) (*StaticResultV1, error) {
	endpointID := protocol.StaticEndpointIDV1(ticket)
	record, found, err := a.State.StaticAssignment(ctx, endpointID)
	if err != nil {
		return nil, err
	}
	if found {
		if !equalStaticTicket(record.Ticket, ticket) {
			return nil, fmt.Errorf("static endpoint %q conflicts with another exact ticket", endpointID)
		}
		if record.Active && record.Receipt != nil && record.Receipt.Stage == protocol.StageReady && a.Static.lookup(endpointID) != nil {
			return &StaticResultV1{Receipt: *record.Receipt, EndpointID: endpointID, Idempotent: true}, nil
		}
	}
	reserved, err := a.State.ReserveReplay(ctx, "assignment", ticket.AssignmentNonce, time.Now().Add(10*time.Minute))
	if err != nil {
		return nil, err
	}
	if !reserved {
		return nil, fmt.Errorf("replayed assignment nonce")
	}
	if err := a.State.SaveStaticAssignment(ctx, ticket, "processing"); err != nil {
		return nil, err
	}
	return nil, nil
}

func equalStaticTicket(left, right protocol.StaticTicketV1) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

// assignStatic verifies the whole site, then signs and persists ready before
// the endpoint becomes servable. Every failure signs a failed receipt with a
// static error code and leaves nothing pinned.
func (a *Agent) assignStatic(ctx context.Context, ticket protocol.StaticTicketV1, seen time.Time) (StaticResultV1, error) {
	endpointID := protocol.StaticEndpointIDV1(ticket)
	ticketDigest, err := protocol.StaticTicketDigestV1(ticket)
	if err != nil {
		return StaticResultV1{}, err
	}
	receipt := protocol.StaticReceiptV1{
		AssignmentNonce: ticket.AssignmentNonce, AssignmentSeen: protocol.StaticTime(seen), DeploymentID: ticket.DeploymentID,
		EndpointID: endpointID, FetchStarted: protocol.StaticTime(time.Now()), Generation: ticket.Generation,
		MinerID: a.MinerID, ReleaseDigest: ticket.ReleaseDigest, ReplicaID: protocol.StaticReplicaIDV1(ticket),
		RouteHost: ticket.RouteHost, Schema: protocol.StaticReceiptSchema, SchemaVersion: protocol.StaticSchemaVersion,
		ServerImplementationDigest: ticket.ServerImplementationDigest, SiteDigest: ticket.SiteDigest,
		Stage: protocol.StageFailed, Subnet: ticket.Subnet, TicketDigest: ticketDigest,
	}
	site, err := a.pinStatic(ctx, ticket)
	if err != nil {
		return a.failedStatic(receipt, err)
	}
	receipt.FetchCompleted = protocol.StaticTime(time.Now())
	count, total := len(site.Manifest.Files), site.Manifest.TotalBytes()
	receipt.Stage, receipt.VerifiedFileCount, receipt.VerifiedTotalBytes = protocol.StageReady, &count, &total
	receipt.ServingStarted = protocol.StaticTime(time.Now())
	if err := protocol.SignStaticReceiptV1(&receipt, a.SigningKey); err != nil {
		site.Release()
		return StaticResultV1{}, err
	}
	if err := a.State.SaveStaticReceipt(ctx, receipt, true); err != nil {
		site.Release()
		return a.failedStatic(withoutReady(receipt), organicStaticFailure(err))
	}
	a.mu.Lock()
	deactivationRequested := a.deactivationRequested[endpointID]
	if !deactivationRequested {
		a.Static.mu.Lock()
		a.Static.endpoints[endpointID] = &staticEndpoint{ticket: ticket, site: site, slots: make(chan struct{}, a.Static.RequestConcurrency)}
		a.Static.mu.Unlock()
	}
	a.mu.Unlock()
	if deactivationRequested {
		site.Release()
		_ = a.State.CompleteStaticDeactivation(context.WithoutCancel(ctx), endpointID)
		return a.failedStatic(withoutReady(receipt), static.Fail(static.CodeDeactivated, durable.ErrEndpointDeactivated))
	}
	return StaticResultV1{Receipt: receipt, EndpointID: endpointID}, nil
}

// pinStatic fetches the manifest by its bound key, verifies it against the
// bound site digest, requires this miner's handler, and verifies every body.
func (a *Agent) pinStatic(ctx context.Context, ticket protocol.StaticTicketV1) (*static.Site, error) {
	if ticket.ServerImplementationDigest != static.ServerImplementationDigest {
		return nil, static.Fail(static.CodeServerImplementationMismatch,
			fmt.Errorf("ticket names handler %s, this miner implements %s", ticket.ServerImplementationDigest, static.ServerImplementationDigest))
	}
	blobs, ok := a.Artifacts.(artifact.BlobOpener)
	if !ok {
		return nil, static.Fail(static.CodeInternal, errors.New("artifact store cannot stream blobs"))
	}
	fetchCtx, cancel := context.WithTimeout(ctx, a.Static.FetchTimeout)
	defer cancel()
	reader, err := blobs.OpenBounded(fetchCtx, ticket.SiteManifestKey, static.MaxManifestBytes)
	if err != nil {
		if artifact.IsOversize(err) {
			return nil, static.Fail(static.CodeVerifyFailed, err)
		}
		return nil, static.Fail(static.CodeFetchFailed, err)
	}
	stored, err := io.ReadAll(reader)
	reader.Close()
	if err != nil {
		if artifact.IsOversize(err) {
			return nil, static.Fail(static.CodeVerifyFailed, err)
		}
		return nil, static.Fail(static.CodeFetchFailed, err)
	}
	manifest, err := static.Parse(stored, ticket.SiteDigest)
	if err != nil {
		return nil, err
	}
	return a.Static.Cache.Pin(fetchCtx, blobs, ticket.SiteDigest, manifest, static.PinOptions{})
}

func withoutReady(receipt protocol.StaticReceiptV1) protocol.StaticReceiptV1 {
	receipt.Stage, receipt.VerifiedFileCount, receipt.VerifiedTotalBytes, receipt.ServingStarted = protocol.StageFailed, nil, nil, nil
	return receipt
}

func organicStaticFailure(err error) error {
	if errors.Is(err, durable.ErrEndpointDeactivated) {
		return static.Fail(static.CodeDeactivated, err)
	}
	return static.Fail(static.CodeInternal, err)
}

func (a *Agent) failedStatic(receipt protocol.StaticReceiptV1, cause error) (StaticResultV1, error) {
	code := string(static.CodeOf(cause))
	receipt.Stage, receipt.ErrorCode, receipt.Error = protocol.StageFailed, &code, deployruntime.ReceiptError(cause)
	receipt.VerifiedFileCount, receipt.VerifiedTotalBytes, receipt.ServingStarted = nil, nil, nil
	if err := protocol.SignStaticReceiptV1(&receipt, a.SigningKey); err != nil {
		return StaticResultV1{EndpointID: receipt.EndpointID}, errors.Join(cause, err)
	}
	_ = a.State.SaveStaticReceipt(context.Background(), receipt, false)
	return StaticResultV1{Receipt: receipt, EndpointID: receipt.EndpointID}, cause
}

// deactivateStatic retires a static endpoint if endpointID names one. It
// fences first, so a concurrent creator can never make the site servable
// afterwards, then drops the pin.
func (a *Agent) deactivateStatic(ctx context.Context, endpointID string) (bool, error) {
	if a.State == nil {
		return false, nil
	}
	record, found, err := a.State.StaticAssignment(ctx, endpointID)
	if err != nil || !found {
		return false, err
	}
	a.mu.Lock()
	a.deactivationRequested[endpointID] = true
	a.mu.Unlock()
	if a.Tunnels != nil {
		a.Tunnels.Unregister(endpointID)
	}
	ticket := record.Ticket
	validator := ""
	if ticket.Subnet != nil {
		validator = ticket.Subnet.ValidatorHotkey
	}
	if err := a.State.FenceEndpointDeactivation(ctx, endpointID, ticket.DeploymentID, ticket.MinerID, validator); err != nil {
		return true, err
	}
	if a.Static != nil {
		a.Static.remove(endpointID)
	}
	return true, a.State.CompleteStaticDeactivation(ctx, endpointID)
}

// recoverStatic retires every static endpoint left by a previous process:
// pins do not survive a restart (the cache sweeps its blobs), so a restarted
// miner never serves an endpoint whose bytes it has not re-verified.
func (a *Agent) recoverStatic(ctx context.Context) error {
	records, err := a.State.StaticAssignmentsToRecover(ctx)
	if err != nil {
		return err
	}
	for _, record := range records {
		endpointID := protocol.StaticEndpointIDV1(record.Ticket)
		if _, err := a.deactivateStatic(ctx, endpointID); err != nil {
			return fmt.Errorf("recover static endpoint %s: %w", endpointID, err)
		}
	}
	return nil
}

// StaticRecord exposes the durable static assignment of endpointID to the
// bridge (status and deactivation ownership checks).
func (a *Agent) StaticRecord(ctx context.Context, endpointID string) (durable.StaticRecord, bool, error) {
	if a.State == nil {
		return durable.StaticRecord{}, false, nil
	}
	return a.State.StaticAssignment(ctx, endpointID)
}

// serveStatic answers one runtime-ingress request for a pinned static
// endpoint: the same edge-runtime-request v1 authorization as dynamic
// endpoints, then the shared static-handler.v1 over the verified pin, and a
// miner-probe-attestation v2 for an authorized validator probe.
func (a *Agent) serveStatic(w http.ResponseWriter, req *http.Request, endpointID string, endpoint *staticEndpoint) {
	if !forwardedRuntimeMethods[req.Method] {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	headers := req.Header.Values(EdgeAuthorizationHeader)
	validatorKey, keyErr := hex.DecodeString(endpoint.ticket.Subnet.ValidatorServicePublicKey)
	if len(headers) != 1 || keyErr != nil || len(validatorKey) != ed25519.PublicKeySize {
		http.Error(w, "exactly one edge runtime authorization is required", http.StatusUnauthorized)
		return
	}
	if err := a.verifyEdgeRequest(req, endpointID, headers[0], ed25519.PublicKey(validatorKey)); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	var probe *organic.ProbeAuthorization
	if values := req.Header.Values(organic.OrganicProbeAuthorizationHeader); len(values) > 0 {
		authorization, err := a.admitOrganicProbe(req.Context(), values, req.Method, req.URL.EscapedPath(), req.URL.RawQuery, endpointID, endpoint.ticket.Generation)
		if err != nil {
			http.Error(w, "probe authorization rejected", http.StatusUnauthorized)
			return
		}
		probe = &authorization
	}
	select {
	case endpoint.slots <- struct{}{}:
		defer func() { <-endpoint.slots }()
	default:
		_, _ = static.WriteResponse(w, static.Unavailable(req.Method), endpoint.site, nil)
		return
	}
	response := static.ResolveRequest(endpoint.site.Index(), req, staticRawPath(req, endpointID), "")
	var extra http.Header
	if probe != nil {
		header, err := a.attestStatic(response, *probe, endpoint.ticket)
		if err != nil {
			http.Error(w, "probe attestation unavailable", http.StatusBadGateway)
			return
		}
		extra = http.Header{organic.ProbeAttestationHeader: {header}}
	}
	if headerSent, err := static.WriteResponse(w, response, endpoint.site, extra); err != nil {
		// The pinned copy no longer matches its manifest: stop serving it.
		a.Static.remove(endpointID)
		if headerSent {
			panic(http.ErrAbortHandler)
		}
		http.Error(w, "static endpoint unavailable", http.StatusBadGateway)
	}
}

// staticRawPath is the raw application path after /runtime/<endpoint_id>,
// taken from the unparsed request-target so no decoding or re-escaping can
// change it (§4.3).
func staticRawPath(req *http.Request, endpointID string) string {
	target := req.RequestURI
	marker := "/" + endpointID + "/"
	if cut := strings.Index(target, marker); cut >= 0 {
		target = target[cut+len(marker)-1:]
		if query := strings.IndexByte(target, '?'); query >= 0 {
			target = target[:query]
		}
		return target
	}
	return req.URL.EscapedPath()
}

// attestStatic signs miner-probe-attestation v2 over the response the
// handler is about to send: artifact_digest is the site digest and
// ticket_digest the static ticket digest (static-site contract §11.4).
func (a *Agent) attestStatic(response static.Response, probe organic.ProbeAuthorization, ticket protocol.StaticTicketV1) (string, error) {
	ticketDigest, err := protocol.StaticTicketDigestV1(ticket)
	if err != nil {
		return "", err
	}
	headerDigest, err := response.HeaderSHA256()
	if err != nil {
		return "", err
	}
	attestation := organic.ProbeAttestationV2{
		Schema: organic.SchemaPrefix + "miner-probe-attestation", SchemaVersion: 2,
		EndpointID: probe.EndpointID, Generation: probe.Generation, TicketDigest: ticketDigest, ArtifactDigest: ticket.SiteDigest,
		ValidatorHotkey: probe.ValidatorHotkey, ProbeNonce: probe.Nonce, RequestMethod: probe.Method, RequestPath: probe.Path,
		ResponseStatus: response.Status, ResponseBodySHA256: response.BodySHA256(), ResponseHeaderSHA256: headerDigest,
		ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := organic.SignProbeAttestationV2(&attestation, a.SigningKey); err != nil {
		return "", err
	}
	return EncodeProbeAttestationV2Header(attestation)
}
