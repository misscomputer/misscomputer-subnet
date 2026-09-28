// SPDX-License-Identifier: AGPL-3.0-only

package miner

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
	"github.com/misscomputer/misscomputer-subnet/pkg/artifact/ocitest"
	"github.com/misscomputer/misscomputer-subnet/pkg/durable"
	"github.com/misscomputer/misscomputer-subnet/pkg/organic"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	deployruntime "github.com/misscomputer/misscomputer-subnet/pkg/runtime"
	"github.com/misscomputer/misscomputer-subnet/pkg/tunnel"
)

type fakeOCIRuntime struct {
	mu        sync.Mutex
	url       string
	launchErr error
	exits     bool
	alive     bool
	launches  []deployruntime.Launch
	stops     []string
}

func (f *fakeOCIRuntime) Launch(_ context.Context, l deployruntime.Launch) (deployruntime.Started, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.launches = append(f.launches, l)
	if f.launchErr != nil {
		return deployruntime.Started{}, f.launchErr
	}
	f.alive = !f.exits
	return deployruntime.Started{
		Instance:                deployruntime.Instance{ID: l.InstanceID, URL: f.url},
		LoadedImageConfigDigest: l.Manifest.Config.Digest, ImageReadyAt: time.Now().UTC(),
	}, nil
}

func (f *fakeOCIRuntime) Running(context.Context, string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.alive, nil
}

func (f *fakeOCIRuntime) Stop(_ context.Context, instanceID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stops = append(f.stops, instanceID)
	f.alive = false
	return nil
}

const (
	testMinerHotkey     = "5FminerHotkey"
	testValidatorHotkey = "5Hvalidator"
	testNetwork         = "test"
	testNetUID          = uint16(24)
)

var testCertificatePin = strings.Repeat("3a", 32)

type organicHarness struct {
	agent        *Agent
	runtime      *fakeOCIRuntime
	state        *durable.Store
	tunnels      *tunnel.LocalRegistry
	image        ocitest.Image
	validatorKey ed25519.PrivateKey
	minerKey     ed25519.PrivateKey
	uid          uint16
}

func newOrganicHarness(t *testing.T, appURL string) *organicHarness {
	t.Helper()
	image, err := ocitest.Build(ocitest.Spec{
		Layers: []map[string]ocitest.File{{"app": {Mode: 0o755, Body: []byte("binary")}}}, Entrypoint: []string{"/app"}, Gzip: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	store := artifact.FileStore{Root: t.TempDir()}
	if err := image.Publish(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	state, err := durable.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { state.Close() })
	_, validatorKey, _ := ed25519.GenerateKey(rand.Reader)
	_, minerKey, _ := ed25519.GenerateKey(rand.Reader)
	h := &organicHarness{
		runtime: &fakeOCIRuntime{url: appURL}, state: state, tunnels: tunnel.NewLocalRegistry(),
		image: image, validatorKey: validatorKey, minerKey: minerKey, uid: 17,
	}
	h.agent = NewAgent(testMinerHotkey, nil, minerKey, store, nil, h.tunnels)
	h.agent.OCI, h.agent.State = h.runtime, state
	h.agent.MinerTransport, h.agent.MinerTLSCertificateSHA256 = "https", testCertificatePin
	return h
}

// ticket returns a signed deployment.v4 ticket for this harness.
func (h *organicHarness) ticket(t *testing.T, nonce string, change func(*protocol.TicketV4)) protocol.TicketV4 {
	t.Helper()
	now := time.Now().UTC()
	pin := testCertificatePin
	uid := h.uid
	ticket := protocol.TicketV4{
		Version: protocol.OrganicVersion, DeploymentID: "hello-k3j9x0q2ab", Generation: 1,
		ImageDigest: h.image.ArtifactDigest, ManifestKey: artifact.ManifestKey(h.image.ArtifactDigest),
		MinerID: testMinerHotkey, RouteHost: "hello-k3j9x0q2ab.on.miss.computer", AssignmentNonce: nonce,
		Workload: protocol.WorkloadV4{
			Kind: organic.WorkloadKind, ContainerPort: 8080, RuntimeProfile: organic.RuntimeProfile,
			Env: protocol.WorkloadEnvV4{Host: "0.0.0.0", Port: "8080"},
		},
		Resources: organic.SmallV1,
		Health: organic.TicketHealth{HealthPredicate: organic.HealthPredicate{
			Method: "GET", Path: "/", ExpectedStatuses: []int{200}, SuccessesRequired: 2,
			IntervalMillis: 500, ProbeTimeoutMillis: 1000, StartupTimeoutMillis: 5000,
		}, FailureThreshold: 2},
		IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(5 * time.Minute),
		Subnet: &protocol.SubnetBinding{
			Network: testNetwork, NetUID: testNetUID, ValidatorHotkey: testValidatorHotkey, MinerHotkey: testMinerHotkey,
			MinerUID: &uid, MinerAxonURL: "https://8.8.8.8:8091", MinerTransport: "https", MinerTLSCertificateSHA256: &pin,
			ChainBlock: 100, Epoch: 10, ExpiresAtBlock: 125,
			ValidatorServicePublicKey: hex.EncodeToString(h.validatorKey.Public().(ed25519.PublicKey)),
			MinerServicePublicKey:     hex.EncodeToString(h.minerKey.Public().(ed25519.PublicKey)),
		},
	}
	if change != nil {
		change(&ticket)
	}
	if err := protocol.SignTicketV4(&ticket, h.validatorKey); err != nil {
		t.Fatal(err)
	}
	return ticket
}

func (h *organicHarness) assign(ticket protocol.TicketV4) (ResultV4, error) {
	uid := h.uid
	return h.agent.AssignBoundV4(context.Background(), ticket, h.validatorKey.Public().(ed25519.PublicKey), 101,
		testNetwork, testNetUID, testValidatorHotkey, testMinerHotkey, &uid)
}

// The miner's receipts are the scheduler's only acceptance evidence, so
// they are checked with the scheduler's own verification functions.
func TestAssignBoundV4SignsVerifiableReceiptForEveryOutcome(t *testing.T) {
	ok := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }
	for index, test := range []struct {
		name         string
		app          http.HandlerFunc
		launchErr    error
		exits        bool
		unpublish    bool
		want         string
		wantLaunches int
	}{
		{name: "ready", app: ok, wantLaunches: 1},
		{name: "artifact unavailable", app: ok, unpublish: true, want: "artifact_fetch_failed"},
		{name: "runtime identity mismatch", app: ok, wantLaunches: 1, want: "image_identity_mismatch",
			launchErr: deployruntime.Fail(deployruntime.CodeImageIdentityMismatch, errors.New("loaded image differs"))},
		{name: "app returns wrong status", wantLaunches: 1, want: "health_unexpected_status",
			app: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) }},
		{name: "app process exits", exits: true, wantLaunches: 1, want: "container_exited",
			app: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(test.app)
			defer server.Close()
			h := newOrganicHarness(t, server.URL)
			h.runtime.launchErr, h.runtime.exits = test.launchErr, test.exits
			h.agent.HTTPClient = server.Client()
			if test.unpublish {
				h.agent.Artifacts = artifact.FileStore{Root: t.TempDir()}
			}
			ticket := h.ticket(t, fmt.Sprintf("%032x", index+1), nil)
			result, err := h.assign(ticket)
			receipt := result.Receipt
			minerPublic := h.minerKey.Public().(ed25519.PublicKey)
			if verifyErr := protocol.VerifyReceiptV4(receipt, minerPublic); verifyErr != nil {
				t.Fatalf("receipt does not verify: %v (assign err=%v)", verifyErr, err)
			}
			if matchErr := protocol.ReceiptMatchesTicketV4(ticket, receipt, h.image.Manifest.Config.Digest); matchErr != nil {
				t.Fatalf("receipt does not answer the ticket: %v", matchErr)
			}
			h.runtime.mu.Lock()
			launches, stops := len(h.runtime.launches), h.runtime.stops
			h.runtime.mu.Unlock()
			if launches != test.wantLaunches {
				t.Fatalf("launches = %d, want %d", launches, test.wantLaunches)
			}
			active, stateErr := h.state.ActiveEndpoints(context.Background())
			if stateErr != nil {
				t.Fatal(stateErr)
			}
			endpointID := protocol.EndpointIDV4(ticket)
			if test.want == "" {
				if err != nil || receipt.Stage != protocol.StageReady || receipt.ErrorCode != nil ||
					*receipt.LoadedImageConfigDigest != h.image.Manifest.Config.Digest {
					t.Fatalf("ready receipt=%+v err=%v", receipt, err)
				}
				if len(active) != 1 || active[0].RuntimeURL != server.URL {
					t.Fatalf("durable endpoint = %+v", active)
				}
				replay, err := h.assign(ticket)
				if err != nil || !replay.Idempotent || replay.Receipt.Signature != receipt.Signature {
					t.Fatalf("exact replay = %+v err=%v", replay, err)
				}
				return
			}
			if err == nil || receipt.Stage != protocol.StageFailed || receipt.ErrorCode == nil || *receipt.ErrorCode != test.want {
				t.Fatalf("failed receipt stage=%s code=%v err=%v, want %s", receipt.Stage, receipt.ErrorCode, err, test.want)
			}
			if _, resolveErr := h.tunnels.Resolve(endpointID); resolveErr == nil || len(active) != 0 {
				t.Fatalf("failed assignment left routing or endpoints: %+v", active)
			}
			if test.wantLaunches != 0 && (len(stops) == 0 || stops[0] != deployruntime.InstanceName(endpointID)) {
				t.Fatalf("launched runtime was not stopped by its deterministic identity: %v", stops)
			}
			stored, found, err := h.state.StoredReceiptV4(context.Background(), endpointID)
			if err != nil || !found || stored.Signature != receipt.Signature {
				t.Fatalf("failed receipt not retained for status: found=%t err=%v", found, err)
			}
		})
	}
}

func TestAssignBoundV4RejectsTicketsBeforeAdmission(t *testing.T) {
	h := newOrganicHarness(t, "http://127.0.0.1:1")
	otherValidator, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	for _, test := range []struct {
		name   string
		ticket func() protocol.TicketV4
	}{
		{"signed by another key", func() protocol.TicketV4 {
			ticket := h.ticket(t, strings.Repeat("a", 32), func(ticket *protocol.TicketV4) {
				ticket.Subnet.ValidatorServicePublicKey = hex.EncodeToString(otherValidator)
			})
			_ = protocol.SignTicketV4(&ticket, otherKey)
			return ticket
		}},
		{"another miner service key", func() protocol.TicketV4 {
			return h.ticket(t, strings.Repeat("b", 32), func(ticket *protocol.TicketV4) {
				ticket.Subnet.MinerServicePublicKey = hex.EncodeToString(otherValidator)
			})
		}},
		{"downgraded transport pin", func() protocol.TicketV4 {
			return h.ticket(t, strings.Repeat("c", 32), func(ticket *protocol.TicketV4) {
				other := strings.Repeat("11", 32)
				ticket.Subnet.MinerTLSCertificateSHA256 = &other
			})
		}},
		{"expired chain block", func() protocol.TicketV4 {
			return h.ticket(t, strings.Repeat("d", 32), func(ticket *protocol.TicketV4) { ticket.Subnet.ExpiresAtBlock = 101 })
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := h.assign(test.ticket())
			if err == nil || result.Receipt.Signature != "" {
				t.Fatalf("ticket admitted: err=%v receipt signed=%t", err, result.Receipt.Signature != "")
			}
		})
	}
	h.runtime.mu.Lock()
	defer h.runtime.mu.Unlock()
	if len(h.runtime.launches) != 0 {
		t.Fatalf("rejected tickets launched %d runtimes", len(h.runtime.launches))
	}
}

type edgeRequest struct {
	method, path, query string
	body                []byte
	header              func(signed string) string
	probe               string
}

func signEdge(t *testing.T, key ed25519.PrivateKey, endpointID string, r edgeRequest, at time.Time) string {
	t.Helper()
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	sum := sha256.Sum256(r.body)
	header, err := organic.SignEdgeRuntimeRequest(organic.EdgeRuntimeRequest{
		BodySHA256: hex.EncodeToString(sum[:]), EndpointID: endpointID, Method: r.method,
		Nonce: hex.EncodeToString(nonce), Path: r.path, Query: r.query, Timestamp: at.UnixNano(),
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return header
}

func probeHeader(t *testing.T, p organic.ProbeAuthorization) string {
	t.Helper()
	document, err := organic.Canonical(p)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(document)
}

func TestOrganicIngressRequiresEdgeSignatureAndAttestsProbes(t *testing.T) {
	var contacted atomic.Int32
	var seenHost, seenMiss atomic.Value
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contacted.Add(1)
		seenHost.Store(r.Host)
		seenMiss.Store(r.Header.Get(organic.EdgeAuthorizationHeader) + r.Header.Get(organic.OrganicProbeAuthorizationHeader))
		w.Header().Set("X-Miss-Probe-Attestation", "spoofed")
		w.Header().Set("Content-Type", "text/plain")
		if r.URL.Path == "/" {
			_, _ = w.Write([]byte("organic-ready"))
			return
		}
		body, _ := io.ReadAll(r.Body)
		_, _ = w.Write(append([]byte(r.Method+" "+r.URL.RequestURI()+" "), body...))
	}))
	defer app.Close()
	h := newOrganicHarness(t, app.URL)
	h.agent.HTTPClient = app.Client()
	ticket := h.ticket(t, strings.Repeat("e", 32), nil)
	if _, err := h.assign(ticket); err != nil {
		t.Fatal(err)
	}
	endpointID := protocol.EndpointIDV4(ticket)
	serve := func(r edgeRequest, header string) *httptest.ResponseRecorder {
		target := "/api/" + r.path
		if r.query != "" {
			target += "?" + r.query
		}
		req := httptest.NewRequest(r.method, target, strings.NewReader(string(r.body)))
		req.URL.Path, req.URL.RawPath = mustUnescape(t, r.path), r.path
		req.URL.RawQuery = r.query
		if header != "" {
			req.Header.Set(organic.EdgeAuthorizationHeader, header)
		}
		if r.probe != "" {
			req.Header.Set(organic.OrganicProbeAuthorizationHeader, r.probe)
		}
		recorder := httptest.NewRecorder()
		h.agent.ProxyRuntime(recorder, req, endpointID)
		return recorder
	}
	post := edgeRequest{method: http.MethodPost, path: "/items/a%2Fb", query: "x=1&y=%20", body: []byte(`{"n":1}`)}
	before := contacted.Load()
	valid := signEdge(t, h.validatorKey, endpointID, post, time.Now())
	response := serve(post, valid)
	if response.Code != http.StatusOK || response.Body.String() != `POST /items/a%2Fb?x=1&y=%20 {"n":1}` {
		t.Fatalf("signed request: %d %q", response.Code, response.Body.String())
	}
	if seenHost.Load() != ticket.RouteHost || seenMiss.Load() != "" || response.Header().Get("X-Miss-Probe-Attestation") != "" {
		t.Fatalf("host=%v forwarded miss headers=%q response attestation=%q", seenHost.Load(), seenMiss.Load(), response.Header().Get("X-Miss-Probe-Attestation"))
	}
	if serve(post, valid).Code != http.StatusUnauthorized {
		t.Fatal("replayed edge nonce was accepted")
	}
	tamperedQuery, tamperedBody := post, post
	tamperedQuery.query = "x=2&y=%20"
	tamperedBody.body = []byte(`{"n":2}`)
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	for name, attempt := range map[string]func() int{
		"missing signature": func() int { return serve(post, "").Code },
		"stale signature": func() int {
			return serve(post, signEdge(t, h.validatorKey, endpointID, post, time.Now().Add(-11*time.Second))).Code
		},
		"other key": func() int { return serve(post, signEdge(t, otherKey, endpointID, post, time.Now())).Code },
		"query changed": func() int {
			return serve(tamperedQuery, signEdge(t, h.validatorKey, endpointID, post, time.Now())).Code
		},
		"body changed": func() int { return serve(tamperedBody, signEdge(t, h.validatorKey, endpointID, post, time.Now())).Code },
	} {
		if code := attempt(); code != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", name, code)
		}
	}
	if contacted.Load() != before+1 {
		t.Fatalf("rejected requests reached the container: %d contacts", contacted.Load()-before)
	}

	nonce := make([]byte, 32)
	_, _ = rand.Read(nonce)
	authorization := organic.ProbeAuthorization{
		Schema: organic.SchemaPrefix + "organic-probe-authorization", SchemaVersion: 1,
		ValidatorHotkey: testValidatorHotkey, EndpointID: endpointID, Generation: 1, Method: "GET", Path: "/",
		Nonce: hex.EncodeToString(nonce), IssuedAt: time.Now().UTC().Truncate(time.Second).Format(time.RFC3339),
		Signature: strings.Repeat("0", 128),
	}
	probe := edgeRequest{method: http.MethodGet, path: "/", probe: probeHeader(t, authorization)}
	response = serve(probe, signEdge(t, h.validatorKey, endpointID, probe, time.Now()))
	encoded := response.Header().Get(organic.ProbeAttestationHeader)
	document, err := base64.StdEncoding.DecodeString(encoded)
	if response.Code != http.StatusOK || err != nil {
		t.Fatalf("probe: %d header=%q err=%v", response.Code, encoded, err)
	}
	var attestation organic.ProbeAttestationV2
	if err := organic.DecodeCanonical(append(document, '\n'), &attestation); err != nil {
		t.Fatalf("attestation document: %v", err)
	}
	if err := organic.VerifyProbeAttestationV2(attestation, h.minerKey.Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("attestation signature: %v", err)
	}
	ticketDigest, _ := protocol.TicketDigestV4(ticket)
	bodySum := sha256.Sum256([]byte("organic-ready"))
	if attestation.TicketDigest != ticketDigest || attestation.ArtifactDigest != ticket.ImageDigest ||
		attestation.ProbeNonce != authorization.Nonce || attestation.ValidatorHotkey != testValidatorHotkey ||
		attestation.ResponseStatus != http.StatusOK || attestation.ResponseBodySHA256 != hex.EncodeToString(bodySum[:]) {
		t.Fatalf("attestation does not bind the probe: %+v", attestation)
	}
	contactsBeforeReplay := contacted.Load()
	if serve(probe, signEdge(t, h.validatorKey, endpointID, probe, time.Now())).Code != http.StatusUnauthorized {
		t.Fatal("replayed probe nonce was accepted")
	}
	wrongPath := authorization
	wrongPath.Nonce = strings.Repeat("ab", 32)
	wrongPath.Path = "/other"
	mismatched := edgeRequest{method: http.MethodGet, path: "/", probe: probeHeader(t, wrongPath)}
	if serve(mismatched, signEdge(t, h.validatorKey, endpointID, mismatched, time.Now())).Code != http.StatusUnauthorized {
		t.Fatal("probe authorization for another path was accepted")
	}
	if contacted.Load() != contactsBeforeReplay {
		t.Fatal("rejected probes reached the container")
	}
}

func mustUnescape(t *testing.T, raw string) string {
	t.Helper()
	decoded, err := url.PathUnescape(raw)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
