// SPDX-License-Identifier: AGPL-3.0-only

package miner

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/organic"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
)

// minerIngressFixture wires one bound organic miner agent behind the
// production runtime ingress handler, with the container replaced by a
// recording application server. No edge is involved: the handler's own
// signature verification is the boundary under test. The edge-to-workload
// forwarding semantics are owned by the edge conformance tests.
type minerIngressFixture struct {
	endpointID string
	validator  ed25519.PrivateKey
	axon       *httptest.Server
	hits       *atomic.Int64
}

func newMinerIngressFixture(t *testing.T) *minerIngressFixture {
	t.Helper()
	hits := new(atomic.Int64)
	serving := new(atomic.Bool)
	container := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !serving.Load() {
			// Startup health before the route exists.
			w.WriteHeader(http.StatusOK)
			return
		}
		hits.Add(1)
		_, _ = w.Write([]byte("app"))
	}))
	t.Cleanup(container.Close)
	h := newOrganicHarness(t, container.URL)
	h.agent.HTTPClient = container.Client()
	axon := httptest.NewServer(h.agent.RuntimeIngressHandler("/runtime/"))
	t.Cleanup(axon.Close)
	h.agent.MinerTransport, h.agent.MinerTLSCertificateSHA256 = "http", ""
	ticket := h.ticket(t, strings.Repeat("f", 32), func(ticket *protocol.TicketV4) {
		ticket.Subnet.MinerAxonURL, ticket.Subnet.MinerTransport, ticket.Subnet.MinerTLSCertificateSHA256 = axon.URL, "http", nil
	})
	result, err := h.assign(ticket)
	if err != nil {
		t.Fatalf("organic assignment: %v", err)
	}
	serving.Store(true)
	return &minerIngressFixture{
		endpointID: result.EndpointID, validator: h.validatorKey, axon: axon, hits: hits,
	}
}

// TestDirectRuntimeRequestsWithoutValidEdgeSignatureNeverReachWorkload is the
// §6.9 bypass guard: a caller that skips the edge, replays a captured
// authorization, re-targets it, signs with another key, or presents a stale
// one is answered 401 by the miner without any workload contact.
func TestDirectRuntimeRequestsWithoutValidEdgeSignatureNeverReachWorkload(t *testing.T) {
	fixture := newMinerIngressFixture(t)
	endpointID := fixture.endpointID
	direct := func(target, authorization string) int {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, fixture.axon.URL+"/runtime/"+endpointID+target, nil)
		if err != nil {
			t.Fatal(err)
		}
		if authorization != "" {
			req.Header.Set(EdgeAuthorizationHeader, authorization)
		}
		resp, err := fixture.axon.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	sign := func(key ed25519.PrivateKey, path string, at time.Time) string {
		t.Helper()
		return signEdge(t, key, endpointID, edgeRequest{method: http.MethodGet, path: path}, at)
	}
	_, stranger, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	valid := sign(fixture.validator, "/healthz", time.Now())
	if status := direct("/healthz", valid); status != http.StatusOK {
		t.Fatalf("correctly signed direct request returned %d", status)
	}
	for name, attempt := range map[string]struct{ target, authorization string }{
		"no authorization":     {"/healthz", ""},
		"replayed":             {"/healthz", valid},
		"re-targeted path":     {"/admin", sign(fixture.validator, "/healthz", time.Now())},
		"added query":          {"/healthz?debug=1", sign(fixture.validator, "/healthz", time.Now())},
		"non-validator signer": {"/healthz", sign(stranger, "/healthz", time.Now())},
		"stale":                {"/healthz", sign(fixture.validator, "/healthz", time.Now().Add(-organic.EdgeRequestFreshness-time.Second))},
		"malformed":            {"/healthz", "v1 ts=1,nonce=00,sig=00"},
	} {
		if status := direct(attempt.target, attempt.authorization); status != http.StatusUnauthorized {
			t.Fatalf("%s direct request returned %d, want 401", name, status)
		}
	}
	if hits := fixture.hits.Load(); hits != 1 {
		t.Fatalf("workload was contacted %d times, want only the one valid request", hits)
	}
}
