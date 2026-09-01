// SPDX-License-Identifier: AGPL-3.0-only

package miner

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
	"github.com/misscomputer/misscomputer-subnet/pkg/durable"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	deployruntime "github.com/misscomputer/misscomputer-subnet/pkg/runtime"
	"github.com/misscomputer/misscomputer-subnet/pkg/tunnel"
	"github.com/misscomputer/misscomputer-subnet/pkg/workload"
)

const probeTestNonce = "6f9c1b9d3f0a4c8e2d5b7a9c1e3f5a7b9d0c2e4f6a8b0c1d2e3f4a5b6c7d8e9f"

type boundProbeFixture struct {
	agent      *Agent
	ticket     protocol.Ticket
	endpointID string
	spec       workload.Spec
	validator  ed25519.PrivateKey
}

// newBoundProbeFixture drives the production assignment path end to end: a
// bound mock-HTTP ticket is verified, deployed onto the local runtime, health
// checked, and durably recorded ready before any probe is attempted.
func newBoundProbeFixture(t *testing.T, hotkey string, uid uint16, axonURL string) *boundProbeFixture {
	t.Helper()
	ctx := context.Background()
	validatorPublic, validatorPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	minerPublic, minerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store := artifact.FileStore{Root: t.TempDir()}
	spec, layer, err := workload.Generate("static", 1024)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := artifact.Publish(ctx, store, spec.Kind, [][]byte{layer}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if axonURL == "" {
		axonURL = "http://127.0.0.1:9101"
	}
	minerUID := uid
	ticket := protocol.Ticket{
		Version: protocol.BoundVersion, DeploymentID: "probe-deploy", Generation: 1,
		ImageDigest: manifest.ImageDigest, ManifestKey: artifact.ManifestKey(manifest.ImageDigest),
		MinerID: hotkey, RouteHost: "probe-deploy.mock.local",
		AssignmentNonce: strings.Repeat(hex.EncodeToString([]byte{byte(uid)}), 16),
		ChallengePath:   spec.ChallengePath, ChallengeSHA256: protocol.ChallengeDigest(spec.ChallengeValue),
		Health:   protocol.HealthSpec{Path: "/healthz", ExpectedStatus: http.StatusOK, IntervalMillis: 1, TimeoutMillis: 30_000},
		IssuedAt: time.Now().Add(-time.Second).UTC(), ExpiresAt: time.Now().Add(time.Minute).UTC(),
		Subnet: &protocol.SubnetBinding{
			Network: "mock", NetUID: 24, ValidatorHotkey: "ValidatorHot", MinerHotkey: hotkey, MinerUID: &minerUID,
			MinerAxonURL: axonURL, MinerTransport: "http", MinerTLSCertificateSHA256: nil,
			ChainBlock: 100, Epoch: 1, ExpiresAtBlock: 200,
			ValidatorServicePublicKey: hex.EncodeToString(validatorPublic),
			MinerServicePublicKey:     hex.EncodeToString(minerPublic),
		},
	}
	if err := protocol.SignTicket(&ticket, validatorPrivate); err != nil {
		t.Fatal(err)
	}
	state, err := durable.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	agent := NewAgent(hotkey, validatorPublic, minerPrivate, store, deployruntime.NewLocalRuntime(), tunnel.NewLocalRegistry())
	agent.State = state
	agent.MinerTransport = "http"
	result, err := agent.AssignBound(ctx, ticket, validatorPublic, 100, "mock", 24, "ValidatorHot", hotkey, &minerUID)
	if err != nil {
		t.Fatal(err)
	}
	if result.Receipt.Stage != protocol.StageReady {
		t.Fatalf("assignment did not become ready: %+v", result.Receipt)
	}
	return &boundProbeFixture{
		agent: agent, ticket: ticket, endpointID: result.EndpointID, spec: spec, validator: validatorPrivate,
	}
}

func (f *boundProbeFixture) probe(t *testing.T, method, path string, nonces ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "http://bridge.local"+path, nil)
	for _, nonce := range nonces {
		req.Header.Add(protocol.ProbeNonceHeader, nonce)
	}
	recorder := httptest.NewRecorder()
	f.agent.ProxyRuntime(recorder, req, f.endpointID)
	return recorder
}

// overrideUpstream repoints the retained active incarnation at a test server
// so workload spoofing, wrong bodies, and transport faults can be simulated
// without touching the durable assignment identity.
func (f *boundProbeFixture) overrideUpstream(url string) {
	f.agent.mu.Lock()
	f.agent.instanceURLs[f.endpointID] = url
	f.agent.mu.Unlock()
}

func decodeRecordedAttestation(t *testing.T, recorder *httptest.ResponseRecorder) protocol.ProbeAttestation {
	t.Helper()
	values := recorder.Result().Header.Values(protocol.ProbeAttestationHeader)
	if len(values) != 1 {
		t.Fatalf("expected exactly one attestation header, got %d", len(values))
	}
	attestation, err := protocol.DecodeProbeAttestationHeader(values[0])
	if err != nil {
		t.Fatal(err)
	}
	return attestation
}

func TestProxyRuntimeAttestsExactChallengeProbe(t *testing.T) {
	fixture := newBoundProbeFixture(t, "MinerHotA", 7, "")
	recorder := fixture.probe(t, http.MethodGet, fixture.spec.ChallengePath, probeTestNonce)
	if recorder.Code != http.StatusOK {
		t.Fatalf("probe returned %d: %s", recorder.Code, recorder.Body.String())
	}
	if recorder.Body.String() != fixture.spec.ChallengeValue {
		t.Fatalf("probe body diverged from the challenge value: %q", recorder.Body.String())
	}
	if got := recorder.Result().Header.Get("X-Build-ID"); got != fixture.spec.BuildID {
		t.Fatalf("challenge build header was not preserved: %q", got)
	}
	attestation := decodeRecordedAttestation(t, recorder)
	if err := protocol.VerifyProbeAttestation(attestation, fixture.agent.PublicKey()); err != nil {
		t.Fatal(err)
	}
	ticket := fixture.ticket
	if attestation.ProbeNonce != probeTestNonce || attestation.RouteHost != ticket.RouteHost ||
		attestation.DeploymentID != ticket.DeploymentID || attestation.Generation != ticket.Generation ||
		attestation.AssignmentNonce != ticket.AssignmentNonce || attestation.EndpointID != fixture.endpointID ||
		attestation.MinerUID != *ticket.Subnet.MinerUID || attestation.MinerHotkey != ticket.MinerID ||
		attestation.MinerServicePublicKey != ticket.Subnet.MinerServicePublicKey ||
		attestation.ResponseStatus != http.StatusOK || attestation.ResponseBodySHA256 != ticket.ChallengeSHA256 {
		t.Fatalf("attestation does not bind the exact assignment identity: %+v", attestation)
	}
	replayed := fixture.probe(t, http.MethodGet, fixture.spec.ChallengePath, probeTestNonce)
	if replayed.Code != http.StatusOK || decodeRecordedAttestation(t, replayed) != attestation {
		t.Fatal("a replayed nonce must reproduce the identical deterministic statement, never a new one")
	}
}

func TestProxyRuntimeFailsClosedOnNonCanonicalNonceHeaders(t *testing.T) {
	fixture := newBoundProbeFixture(t, "MinerHotB", 8, "")
	upstreamHits := 0
	counter := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { upstreamHits++ }))
	defer counter.Close()
	fixture.overrideUpstream(counter.URL)
	for name, nonces := range map[string][]string{
		"duplicate":        {probeTestNonce, probeTestNonce},
		"two distinct":     {probeTestNonce, strings.Repeat("a", 64)},
		"empty value":      {""},
		"wrong length":     {probeTestNonce[:63]},
		"overlong":         {probeTestNonce + "0"},
		"mixed case":       {strings.ToUpper(probeTestNonce[:32]) + probeTestNonce[32:]},
		"non hex":          {strings.Repeat("g", 64)},
		"comma smuggling":  {probeTestNonce + ", " + probeTestNonce},
		"whitespace value": {" " + probeTestNonce[1:]},
	} {
		recorder := fixture.probe(t, http.MethodGet, fixture.spec.ChallengePath, nonces...)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("%s nonce returned %d, want 400", name, recorder.Code)
		}
		if recorder.Result().Header.Get(protocol.ProbeAttestationHeader) != "" {
			t.Fatalf("%s nonce produced an attestation header", name)
		}
	}
	if upstreamHits != 0 {
		t.Fatalf("malformed probes reached the workload %d times", upstreamHits)
	}
}

func TestProxyRuntimeFailsClosedOnNonExactChallengeRequests(t *testing.T) {
	fixture := newBoundProbeFixture(t, "MinerHotC", 9, "")
	for name, request := range map[string]struct {
		method string
		path   string
	}{
		"wrong path":       {http.MethodGet, "/healthz"},
		"prefix path":      {http.MethodGet, fixture.spec.ChallengePath + "/extra"},
		"query string":     {http.MethodGet, fixture.spec.ChallengePath + "?probe=1"},
		"post method":      {http.MethodPost, fixture.spec.ChallengePath},
		"head method":      {http.MethodHead, fixture.spec.ChallengePath},
		"other deployment": {http.MethodGet, "/__challenge/" + strings.Repeat("0", 24)},
	} {
		recorder := fixture.probe(t, request.method, request.path, probeTestNonce)
		if recorder.Code != http.StatusConflict {
			t.Fatalf("%s returned %d, want 409", name, recorder.Code)
		}
		if recorder.Result().Header.Get(protocol.ProbeAttestationHeader) != "" {
			t.Fatalf("%s produced an attestation header", name)
		}
	}
	// The same requests without a nonce header remain ordinary workload
	// traffic: the hidden challenge still serves and never carries a
	// spoofable attestation slot.
	plain := fixture.probe(t, http.MethodGet, fixture.spec.ChallengePath)
	if plain.Code != http.StatusOK || plain.Body.String() != fixture.spec.ChallengeValue {
		t.Fatalf("ordinary challenge request broke: %d", plain.Code)
	}
	if plain.Result().Header.Get(protocol.ProbeAttestationHeader) != "" {
		t.Fatal("ordinary request carried an attestation header")
	}
	health := fixture.probe(t, http.MethodGet, "/healthz")
	if health.Code != http.StatusOK {
		t.Fatalf("ordinary non-probe workload request broke: %d", health.Code)
	}
}

func TestProxyRuntimeStripsWorkloadSpoofedAttestationHeaders(t *testing.T) {
	fixture := newBoundProbeFixture(t, "MinerHotD", 10, "")
	spoof := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get(protocol.ProbeNonceHeader) != "" || req.Header.Get(protocol.ProbeAttestationHeader) != "" {
			t.Error("probe protocol headers crossed into the workload")
		}
		w.Header().Add(protocol.ProbeAttestationHeader, "c3Bvb2Y=")
		w.Header().Add(protocol.ProbeAttestationHeader, "c3Bvb2YtdHdv")
		w.Header().Set("X-Build-ID", fixture.spec.BuildID)
		_, _ = w.Write([]byte(fixture.spec.ChallengeValue))
	}))
	defer spoof.Close()
	fixture.overrideUpstream(spoof.URL)

	attested := fixture.probe(t, http.MethodGet, fixture.spec.ChallengePath, probeTestNonce)
	if attested.Code != http.StatusOK {
		t.Fatalf("attested probe returned %d", attested.Code)
	}
	attestation := decodeRecordedAttestation(t, attested)
	if err := protocol.VerifyProbeAttestation(attestation, fixture.agent.PublicKey()); err != nil {
		t.Fatalf("spoofed headers displaced the miner-signed statement: %v", err)
	}

	ordinary := fixture.probe(t, http.MethodGet, fixture.spec.ChallengePath)
	if ordinary.Code != http.StatusOK {
		t.Fatalf("ordinary request returned %d", ordinary.Code)
	}
	if values := ordinary.Result().Header.Values(protocol.ProbeAttestationHeader); len(values) != 0 {
		t.Fatalf("workload spoof headers survived an ordinary response: %v", values)
	}
}

func TestProxyRuntimeFailsClosedOnWrongStatusBodyOversizeAndTransport(t *testing.T) {
	fixture := newBoundProbeFixture(t, "MinerHotE", 11, "")
	cases := map[string]http.HandlerFunc{
		"wrong body": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("not-the-challenge"))
		},
		"wrong status": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(fixture.spec.ChallengeValue))
		},
		"redirect": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", "https://elsewhere.invalid/")
			w.WriteHeader(http.StatusFound)
		},
		"oversized": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(make([]byte, maxProbeChallengeResponseBytes+1))
		},
	}
	for name, handler := range cases {
		server := httptest.NewServer(handler)
		fixture.overrideUpstream(server.URL)
		recorder := fixture.probe(t, http.MethodGet, fixture.spec.ChallengePath, probeTestNonce)
		server.Close()
		if recorder.Code != http.StatusBadGateway {
			t.Fatalf("%s returned %d, want 502", name, recorder.Code)
		}
		if recorder.Result().Header.Get(protocol.ProbeAttestationHeader) != "" {
			t.Fatalf("%s produced an attestation header", name)
		}
	}
	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closed.Close()
	fixture.overrideUpstream(closed.URL)
	transport := fixture.probe(t, http.MethodGet, fixture.spec.ChallengePath, probeTestNonce)
	if transport.Code != http.StatusBadGateway || transport.Result().Header.Get(protocol.ProbeAttestationHeader) != "" {
		t.Fatalf("transport failure returned %d", transport.Code)
	}
}

func TestProxyRuntimeFailsClosedOnCancelledProbe(t *testing.T) {
	fixture := newBoundProbeFixture(t, "MinerHotF", 12, "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodGet, "http://bridge.local"+fixture.spec.ChallengePath, nil).WithContext(ctx)
	req.Header.Set(protocol.ProbeNonceHeader, probeTestNonce)
	recorder := httptest.NewRecorder()
	fixture.agent.ProxyRuntime(recorder, req, fixture.endpointID)
	if recorder.Code == http.StatusOK || recorder.Result().Header.Get(protocol.ProbeAttestationHeader) != "" {
		t.Fatalf("cancelled probe produced %d with attestation", recorder.Code)
	}
}

func TestProxyRuntimeFailsClosedOnDeactivatedStaleAndRotatedAssignments(t *testing.T) {
	fixture := newBoundProbeFixture(t, "MinerHotG", 13, "")
	workloadURL := func() string {
		fixture.agent.mu.Lock()
		defer fixture.agent.mu.Unlock()
		return fixture.agent.instanceURLs[fixture.endpointID]
	}()

	// Service-key rotation: the durable ticket binds the previous key.
	_, rotated, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	original := fixture.agent.SigningKey
	fixture.agent.SigningKey = rotated
	if recorder := fixture.probe(t, http.MethodGet, fixture.spec.ChallengePath, probeTestNonce); recorder.Code != http.StatusConflict {
		t.Fatalf("rotated service key returned %d, want 409", recorder.Code)
	}
	fixture.agent.SigningKey = original

	// Deactivation removes the active incarnation entirely.
	if err := fixture.agent.Deactivate(context.Background(), fixture.endpointID); err != nil {
		t.Fatal(err)
	}
	if recorder := fixture.probe(t, http.MethodGet, fixture.spec.ChallengePath, probeTestNonce); recorder.Code != http.StatusNotFound {
		t.Fatalf("deactivated endpoint returned %d, want 404", recorder.Code)
	}
	// Even a stale incarnation mapping cannot resurrect a deactivated
	// durable assignment.
	fixture.overrideUpstream(workloadURL)
	if recorder := fixture.probe(t, http.MethodGet, fixture.spec.ChallengePath, probeTestNonce); recorder.Code != http.StatusConflict {
		t.Fatalf("stale incarnation over deactivated assignment returned %d, want 409", recorder.Code)
	}
}

func TestProxyRuntimeFailsClosedOnSubstitutedTicketAndMissingState(t *testing.T) {
	validatorPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, minerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uid := uint16(21)
	forged := protocol.Ticket{
		Version: protocol.BoundVersion, DeploymentID: "probe-deploy", Generation: 1,
		ImageDigest: "sha256:" + strings.Repeat("ab", 32), ManifestKey: "v1/manifests/x.json",
		MinerID: "MinerHotH", RouteHost: "probe-deploy.mock.local",
		AssignmentNonce: strings.Repeat("15", 16),
		ChallengePath:   "/__challenge/" + strings.Repeat("0", 24),
		ChallengeSHA256: protocol.ChallengeDigest("forged"),
		IssuedAt:        time.Now().Add(-time.Second).UTC(), ExpiresAt: time.Now().Add(time.Minute).UTC(),
		Subnet: &protocol.SubnetBinding{
			Network: "mock", NetUID: 24, ValidatorHotkey: "ValidatorHot", MinerHotkey: "MinerHotH", MinerUID: &uid,
			MinerAxonURL: "http://127.0.0.1:9101", MinerTransport: "http",
			ChainBlock: 100, Epoch: 1, ExpiresAtBlock: 200,
			ValidatorServicePublicKey: hex.EncodeToString(validatorPublic),
			MinerServicePublicKey:     hex.EncodeToString(minerPrivate.Public().(ed25519.PublicKey)),
		},
		Signature: strings.Repeat("00", 64),
	}
	state, err := durable.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	if err := state.SaveAssignment(context.Background(), forged, string(protocol.StageReady)); err != nil {
		t.Fatal(err)
	}
	agent := NewAgent("MinerHotH", validatorPublic, minerPrivate, nil, nil, tunnel.NewLocalRegistry())
	agent.State = state
	agent.MinerTransport = "http"
	endpointID := protocol.EndpointID(forged)
	agent.mu.Lock()
	agent.instanceURLs[endpointID] = "http://127.0.0.1:1"
	agent.mu.Unlock()
	req := httptest.NewRequest(http.MethodGet, "http://bridge.local"+forged.ChallengePath, nil)
	req.Header.Set(protocol.ProbeNonceHeader, probeTestNonce)
	recorder := httptest.NewRecorder()
	agent.ProxyRuntime(recorder, req, endpointID)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("substituted unsigned ticket returned %d, want 409", recorder.Code)
	}

	// Without durable state no probe can ever bind a scheduler identity.
	stateless := NewAgent("MinerHotH", validatorPublic, minerPrivate, nil, nil, tunnel.NewLocalRegistry())
	stateless.mu.Lock()
	stateless.instanceURLs["endpoint"] = "http://127.0.0.1:1"
	stateless.mu.Unlock()
	statelessRecorder := httptest.NewRecorder()
	statelessReq := httptest.NewRequest(http.MethodGet, "http://bridge.local/__challenge/"+strings.Repeat("0", 24), nil)
	statelessReq.Header.Set(protocol.ProbeNonceHeader, probeTestNonce)
	stateless.ProxyRuntime(statelessRecorder, statelessReq, "endpoint")
	if statelessRecorder.Code != http.StatusConflict {
		t.Fatalf("stateless probe returned %d, want 409", statelessRecorder.Code)
	}
}

func TestProxyRuntimeFailsClosedOnLegacyUnboundAssignment(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer server.Close()
	runtime := &cleanupRuntime{instance: deployruntime.Instance{ID: "runtime-instance", URL: server.URL}}
	agent, ticket, _, _ := agentFixture(t, runtime, server.Client())
	state, err := durable.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	agent.State = state
	result, err := agent.Assign(context.Background(), ticket)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://bridge.local"+ticket.ChallengePath, nil)
	req.Header.Set(protocol.ProbeNonceHeader, probeTestNonce)
	recorder := httptest.NewRecorder()
	agent.ProxyRuntime(recorder, req, result.EndpointID)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("legacy unbound assignment returned %d, want 409", recorder.Code)
	}
	if err := agent.Deactivate(context.Background(), result.EndpointID); err != nil {
		t.Fatal(err)
	}
}

func TestProxyRuntimeRestartCannotAttestForOldIncarnation(t *testing.T) {
	fixture := newBoundProbeFixture(t, "MinerHotI", 14, "")
	restarted := NewAgent("MinerHotI", fixture.agent.OwnerKey, fixture.agent.SigningKey, fixture.agent.Artifacts, fixture.agent.Runtime, tunnel.NewLocalRegistry())
	restarted.State = fixture.agent.State
	restarted.MinerTransport = "http"
	if err := restarted.RecoverCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://bridge.local"+fixture.spec.ChallengePath, nil)
	req.Header.Set(protocol.ProbeNonceHeader, probeTestNonce)
	recorder := httptest.NewRecorder()
	restarted.ProxyRuntime(recorder, req, fixture.endpointID)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("restarted agent served an old incarnation probe with %d, want 404", recorder.Code)
	}
}

func TestProxyRuntimeStreamsLargeNonProbeResponsesUnbuffered(t *testing.T) {
	fixture := newBoundProbeFixture(t, "MinerHotJ", 15, "")
	large := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(protocol.ProbeAttestationHeader, "c3Bvb2Y=")
		_, _ = w.Write(make([]byte, 3*maxProbeChallengeResponseBytes))
	}))
	defer large.Close()
	fixture.overrideUpstream(large.URL)
	recorder := fixture.probe(t, http.MethodGet, "/large")
	if recorder.Code != http.StatusOK || recorder.Body.Len() != 3*maxProbeChallengeResponseBytes {
		t.Fatalf("large ordinary response was truncated: %d bytes, status %d", recorder.Body.Len(), recorder.Code)
	}
	if recorder.Result().Header.Get(protocol.ProbeAttestationHeader) != "" {
		t.Fatal("spoofed attestation header survived the ordinary response")
	}
}
