// SPDX-License-Identifier: AGPL-3.0-only

package miner

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
	"github.com/misscomputer/misscomputer-subnet/pkg/organic"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	"github.com/misscomputer/misscomputer-subnet/pkg/static"
)

var staticBodies = map[string][]byte{
	"/app.js":          []byte("console.log(1);\n"),
	"/docs/index.html": []byte("<!doctype html><title>docs</title>\n"),
	"/index.html":      []byte("<!doctype html><title>hello</title>\n"),
}

type staticHarness struct {
	*organicHarness
	store     artifact.FileStore
	cacheRoot string
	manifest  static.Manifest
	digest    string
}

func bodySHA(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// newStaticHarness publishes the site exactly as the promoter would: every
// blob under its content key and the stored manifest under its site key.
func newStaticHarness(t *testing.T, publish func(store artifact.FileStore, path string, body []byte) []byte) *staticHarness {
	t.Helper()
	h := &staticHarness{organicHarness: newOrganicHarness(t, healthyApp(t).URL), cacheRoot: t.TempDir()}
	h.store = h.agent.Artifacts.(artifact.FileStore)
	h.manifest = static.Manifest{Handler: static.HandlerVersion, Schema: static.ManifestSchema, SchemaVersion: 1}
	for _, path := range []string{"/app.js", "/docs/index.html", "/index.html"} {
		body := staticBodies[path]
		stored := body
		if publish != nil {
			stored = publish(h.store, path, body)
		}
		if stored != nil {
			if err := h.store.Put(context.Background(), static.BlobKey(bodySHA(body)), stored, ""); err != nil {
				t.Fatal(err)
			}
		}
		h.manifest.Files = append(h.manifest.Files, static.File{
			BodySHA256: bodySHA(body), ContentLength: int64(len(body)), ContentType: static.ContentTypeFor(path), Path: path,
		})
	}
	stored, digest, err := static.Encode(h.manifest)
	if err != nil {
		t.Fatal(err)
	}
	h.digest = digest
	if err := h.store.Put(context.Background(), static.ManifestKey(digest), stored, ""); err != nil {
		t.Fatal(err)
	}
	h.enable(t)
	return h
}

func (h *staticHarness) enable(t *testing.T) {
	t.Helper()
	cache, err := static.OpenCache(h.cacheRoot, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	h.agent.Static = NewStaticSites(cache, 10*time.Second, 4)
}

func (h *staticHarness) staticTicket(t *testing.T, nonce string, change func(*protocol.StaticTicketV1)) protocol.StaticTicketV1 {
	t.Helper()
	now := time.Now().UTC()
	pin := testCertificatePin
	uid := h.uid
	ticket := protocol.StaticTicketV1{
		AssignmentNonce: nonce, DeploymentID: "hello-k3j9x0q2ab", Generation: 1,
		IssuedAt: *protocol.StaticTime(now.Add(-time.Second)), ExpiresAt: *protocol.StaticTime(now.Add(5 * time.Minute)),
		MinerID: testMinerHotkey, ReleaseDigest: "sha256:" + strings.Repeat("9b", 32), RouteHost: "hello-k3j9x0q2ab.on.miss.computer",
		Schema: protocol.StaticTicketSchema, SchemaVersion: 1, ServerImplementationDigest: static.ServerImplementationDigest,
		SiteDigest: h.digest, SiteManifestKey: static.ManifestKey(h.digest), WorkloadKind: static.WorkloadKind,
		Subnet: &protocol.StaticSubnetBindingV1{
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
	if err := protocol.SignStaticTicketV1(&ticket, h.validatorKey); err != nil {
		t.Fatal(err)
	}
	return ticket
}

func (h *staticHarness) assignStatic(ticket protocol.StaticTicketV1) (StaticResultV1, error) {
	uid := h.uid
	return h.agent.AssignBoundStaticV1(context.Background(), ticket, h.validatorKey.Public().(ed25519.PublicKey), 101,
		testNetwork, testNetUID, testValidatorHotkey, testMinerHotkey, &uid)
}

// request sends one edge-signed request through the real runtime ingress.
func (h *staticHarness) request(t *testing.T, endpointID string, r edgeRequest, sign bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(r.method, "/v1/runtime/"+endpointID+r.path, bytes.NewReader(r.body))
	if sign {
		req.Header.Set(organic.EdgeAuthorizationHeader, signEdge(t, h.validatorKey, endpointID, r, time.Now()))
	}
	if r.probe != "" {
		req.Header.Set(organic.OrganicProbeAuthorizationHeader, r.probe)
	}
	recorder := httptest.NewRecorder()
	h.agent.RuntimeIngressHandler("/v1/runtime/").ServeHTTP(recorder, req)
	return recorder
}

func nonceHex(t *testing.T) string {
	t.Helper()
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	return hex.EncodeToString(nonce)
}

// A ready receipt is the scheduler's evidence that every byte was verified:
// it is checked with the scheduler's own functions, and the endpoint then
// serves the shared handler's exact responses, attests probes, and stops
// serving on deactivation.
func TestStaticAssignmentVerifiesEverySiteByteBeforeReadyAndServing(t *testing.T) {
	h := newStaticHarness(t, nil)
	ticket := h.staticTicket(t, nonceHex(t), nil)
	result, err := h.assignStatic(ticket)
	if err != nil {
		t.Fatal(err)
	}
	receipt := result.Receipt
	if err := protocol.VerifyStaticReceiptV1(receipt, h.minerKey.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	if err := protocol.StaticReceiptMatchesTicketV1(ticket, receipt); err != nil {
		t.Fatal(err)
	}
	total := int64(len(staticBodies["/app.js"]) + len(staticBodies["/docs/index.html"]) + len(staticBodies["/index.html"]))
	if receipt.Stage != protocol.StageReady || *receipt.VerifiedFileCount != 3 || *receipt.VerifiedTotalBytes != total {
		t.Fatalf("receipt %+v", receipt)
	}
	endpointID := result.EndpointID
	get := h.request(t, endpointID, edgeRequest{method: http.MethodGet, path: "/docs/"}, true)
	want := static.NewIndex(h.manifest).Resolve(http.MethodGet, "/docs/", false)
	if get.Code != http.StatusOK || !bytes.Equal(get.Body.Bytes(), staticBodies["/docs/index.html"]) ||
		get.Header().Get("Content-Type") != want.File.ContentType || get.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatalf("GET /docs/: %d %q %v", get.Code, get.Body.String(), get.Header())
	}
	if code := h.request(t, endpointID, edgeRequest{method: http.MethodGet, path: "/"}, false).Code; code != http.StatusUnauthorized {
		t.Fatalf("unsigned request: %d", code)
	}
	if code := h.request(t, endpointID, edgeRequest{method: http.MethodGet, path: "/x", body: []byte("b")}, true).Code; code != http.StatusBadRequest {
		t.Fatalf("request with a body: %d", code)
	}

	authorization := organic.ProbeAuthorization{
		Schema: organic.SchemaPrefix + "organic-probe-authorization", SchemaVersion: 1,
		ValidatorHotkey: testValidatorHotkey, EndpointID: endpointID, Generation: 1, Method: "GET", Path: "/app.js",
		Nonce: nonceHex(t) + nonceHex(t), IssuedAt: time.Now().UTC().Truncate(time.Second).Format(time.RFC3339),
		Signature: strings.Repeat("0", 128),
	}
	probed := h.request(t, endpointID, edgeRequest{method: http.MethodGet, path: "/app.js", probe: probeHeader(t, authorization)}, true)
	document, err := base64.StdEncoding.DecodeString(probed.Header().Get(organic.ProbeAttestationHeader))
	if probed.Code != http.StatusOK || err != nil {
		t.Fatalf("probe: %d %v", probed.Code, err)
	}
	var attestation organic.ProbeAttestationV2
	if err := organic.DecodeCanonical(append(document, '\n'), &attestation); err != nil {
		t.Fatal(err)
	}
	if err := organic.VerifyProbeAttestationV2(attestation, h.minerKey.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	ticketDigest, _ := protocol.StaticTicketDigestV1(ticket)
	expected := static.NewIndex(h.manifest).Resolve(http.MethodGet, "/app.js", false)
	headerDigest, _ := expected.HeaderSHA256()
	if attestation.ArtifactDigest != h.digest || attestation.TicketDigest != ticketDigest ||
		attestation.ResponseBodySHA256 != bodySHA(staticBodies["/app.js"]) || attestation.ResponseHeaderSHA256 != headerDigest {
		t.Fatalf("attestation does not bind the site response: %+v", attestation)
	}

	again, err := h.assignStatic(ticket)
	if err != nil || !again.Idempotent || again.Receipt.Signature != receipt.Signature {
		t.Fatalf("exact replay: idempotent=%v err=%v", again.Idempotent, err)
	}
	if err := h.agent.Deactivate(context.Background(), endpointID); err != nil {
		t.Fatal(err)
	}
	if code := h.request(t, endpointID, edgeRequest{method: http.MethodGet, path: "/"}, true).Code; code == http.StatusOK {
		t.Fatal("deactivated static endpoint still serves")
	}
	if h.agent.Static.Cache.Occupancy() != 0 {
		t.Fatalf("deactivation kept %d pinned bytes", h.agent.Static.Cache.Occupancy())
	}
}

// Every admitted failure is a signed, attributed failed receipt, and the
// endpoint never serves a byte.
func TestStaticAssignmentFailuresSignAttributedReceiptsAndNeverServe(t *testing.T) {
	cases := []struct {
		name    string
		publish func(artifact.FileStore, string, []byte) []byte
		change  func(*protocol.StaticTicketV1)
		after   func(*testing.T, *staticHarness)
		code    static.Code
	}{
		{name: "one body forged", publish: func(_ artifact.FileStore, path string, body []byte) []byte {
			if path == "/app.js" {
				return bytes.ToUpper(body)
			}
			return body
		}, code: static.CodeVerifyFailed},
		{name: "one body missing", publish: func(_ artifact.FileStore, path string, body []byte) []byte {
			if path == "/docs/index.html" {
				return nil
			}
			return body
		}, code: static.CodeFetchFailed},
		{name: "manifest missing", change: func(ticket *protocol.StaticTicketV1) {
			ticket.SiteDigest = "sha256:" + strings.Repeat("0", 64)
			ticket.SiteManifestKey = static.ManifestKey(ticket.SiteDigest)
		}, code: static.CodeFetchFailed},
		{name: "manifest bytes forged", after: func(t *testing.T, h *staticHarness) {
			path := filepath.Join(h.store.Root, filepath.FromSlash(static.ManifestKey(h.digest)))
			stored, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, bytes.Replace(stored, []byte("app.js"), []byte("app.jz"), 1), 0o600); err != nil {
				t.Fatal(err)
			}
		}, code: static.CodeVerifyFailed},
		{name: "other handler", change: func(ticket *protocol.StaticTicketV1) {
			ticket.ServerImplementationDigest = "sha256:" + strings.Repeat("ab", 32)
		}, code: static.CodeServerImplementationMismatch},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			h := newStaticHarness(t, test.publish)
			if test.after != nil {
				test.after(t, h)
			}
			ticket := h.staticTicket(t, nonceHex(t), test.change)
			result, err := h.assignStatic(ticket)
			if err == nil || static.CodeOf(err) != test.code {
				t.Fatalf("error %v, want code %s", err, test.code)
			}
			receipt := result.Receipt
			if verifyErr := protocol.VerifyStaticReceiptV1(receipt, h.minerKey.Public().(ed25519.PublicKey)); verifyErr != nil {
				t.Fatal(verifyErr)
			}
			if receipt.Stage != protocol.StageFailed || receipt.ErrorCode == nil || *receipt.ErrorCode != string(test.code) ||
				protocol.StaticReceiptMatchesTicketV1(ticket, receipt) != nil {
				t.Fatalf("receipt %+v", receipt)
			}
			if code := h.request(t, result.EndpointID, edgeRequest{method: http.MethodGet, path: "/"}, true).Code; code == http.StatusOK {
				t.Fatal("failed static endpoint serves")
			}
			if h.agent.Static.Cache.Occupancy() != 0 {
				t.Fatalf("failed assignment kept %d pinned bytes", h.agent.Static.Cache.Occupancy())
			}
		})
	}
}

// Refusals before admission leave no receipt and no consumed nonce, so a
// correctly configured retry of the same signed ticket can still succeed;
// a deactivation fence that arrives first always wins.
func TestStaticAdmissionFailsClosedBeforeAnyWork(t *testing.T) {
	h := newStaticHarness(t, nil)
	enabled := h.agent.Static
	h.agent.Static = nil
	ticket := h.staticTicket(t, nonceHex(t), nil)
	if result, err := h.assignStatic(ticket); err == nil || result.Receipt.Signature != "" {
		t.Fatalf("disabled miner: receipt %+v err %v", result.Receipt, err)
	}
	h.agent.Static = enabled
	if _, err := h.assignStatic(ticket); err != nil {
		t.Fatalf("retry after enabling: %v", err)
	}

	fenced := h.staticTicket(t, nonceHex(t), func(ticket *protocol.StaticTicketV1) { ticket.Generation = 2 })
	endpointID := protocol.StaticEndpointIDV1(fenced)
	if err := h.agent.FenceDeactivation(context.Background(), endpointID, fenced.DeploymentID, testValidatorHotkey); err != nil {
		t.Fatal(err)
	}
	if _, err := h.assignStatic(fenced); err == nil {
		t.Fatal("assignment after its deactivation fence was accepted")
	}
	if code := h.request(t, endpointID, edgeRequest{method: http.MethodGet, path: "/"}, true).Code; code == http.StatusOK {
		t.Fatal("fenced static endpoint serves")
	}
}

// A restart never serves a static endpoint whose bytes this process has not
// verified, and static rows never disturb dynamic restart recovery.
func TestRestartRetiresStaticEndpointsAlongsideDynamicOnes(t *testing.T) {
	h := newStaticHarness(t, nil)
	dynamic := h.ticket(t, nonceHex(t), nil)
	if _, err := h.assign(dynamic); err != nil {
		t.Fatal(err)
	}
	ticket := h.staticTicket(t, nonceHex(t), nil)
	result, err := h.assignStatic(ticket)
	if err != nil {
		t.Fatal(err)
	}
	restarted := NewAgent(testMinerHotkey, nil, h.minerKey, h.store, h.runtime, h.tunnels)
	restarted.State, restarted.MinerTransport, restarted.MinerTLSCertificateSHA256 = h.state, "https", testCertificatePin
	h.agent = restarted
	h.enable(t)
	if err := restarted.RecoverCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	record, found, err := h.state.StaticAssignment(context.Background(), result.EndpointID)
	if err != nil || !found || record.Active || record.Status != "deactivated" {
		t.Fatalf("static record after restart: %+v found=%v err=%v", record, found, err)
	}
	if code := h.request(t, result.EndpointID, edgeRequest{method: http.MethodGet, path: "/"}, true).Code; code == http.StatusOK {
		t.Fatal("restarted miner served an unverified static endpoint")
	}
	if active, _ := h.state.ActiveEndpoints(context.Background()); len(active) != 0 {
		t.Fatalf("dynamic endpoints left active after recovery: %+v", active)
	}
}
