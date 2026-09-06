// SPDX-License-Identifier: AGPL-3.0-only

package edge

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/misscomputer/misscomputer-subnet/pkg/tunnel"
)

func addLocalTestReplica(t *testing.T, router *Router, tunnels tunnel.Registry, host string, replica Replica) {
	t.Helper()
	target, err := tunnels.Resolve(replica.EndpointID)
	if err != nil {
		t.Fatal(err)
	}
	router.addLocal(host, replica, target)
}

func TestGenerateProbeTokenUsesIndependentCryptographicRandomness(t *testing.T) {
	first, err := GenerateProbeToken()
	if err != nil {
		t.Fatal(err)
	}
	second, err := GenerateProbeToken()
	if err != nil {
		t.Fatal(err)
	}
	if first == second || first == "visible-build-id" || second == "visible-build-id" {
		t.Fatalf("probe tokens are derivable or repeated: %q %q", first, second)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(first)
	if err != nil || len(decoded) != 32 {
		t.Fatalf("probe token entropy bytes=%d err=%v", len(decoded), err)
	}
}

func TestAuthenticatedTargetedProbeSelectsPendingReplica(t *testing.T) {
	backend := func(body string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get(TargetReplicaHeader) != "" || r.Header.Get(ProbeAuthorizationHeader) != "" {
				http.Error(w, "internal headers leaked", http.StatusInternalServerError)
				return
			}
			_, _ = w.Write([]byte(body))
		}))
	}
	good, pending := backend("good"), backend("pending")
	defer good.Close()
	defer pending.Close()
	tunnels := tunnel.NewLocalRegistry()
	if err := tunnels.Register("good-endpoint", good.URL); err != nil {
		t.Fatal(err)
	}
	if err := tunnels.Register("pending-endpoint", pending.URL); err != nil {
		t.Fatal(err)
	}
	router := NewRouter(tunnels, "probe-secret")
	addLocalTestReplica(t, router, tunnels, "app.test", Replica{ID: "good", EndpointID: "good-endpoint", Healthy: true})
	addLocalTestReplica(t, router, tunnels, "app.test", Replica{ID: "pending", EndpointID: "pending-endpoint", Healthy: false})
	edgeServer := httptest.NewServer(router)
	defer edgeServer.Close()

	request := func(token string) (int, string) {
		req, _ := http.NewRequest(http.MethodGet, edgeServer.URL, nil)
		req.Host = "app.test"
		req.Header.Set(TargetReplicaHeader, "pending")
		if token != "" {
			req.Header.Set(ProbeAuthorizationHeader, token)
		}
		resp, err := edgeServer.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}
	if status, _ := request(""); status != http.StatusForbidden {
		t.Fatalf("unauthenticated target returned %d", status)
	}
	if status, body := request("probe-secret"); status != http.StatusOK || body != "pending" {
		t.Fatalf("authenticated target returned status=%d body=%q", status, body)
	}
	req, _ := http.NewRequest(http.MethodGet, edgeServer.URL, nil)
	req.Host = "app.test"
	req.Header.Set(ProbeAuthorizationHeader, "token-only-injection")
	resp, err := edgeServer.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "good" {
		t.Fatalf("normal route leaked token header: status=%d body=%q", resp.StatusCode, body)
	}
}

func TestRoundRobinCounterOverflowRoutesWithoutPanic(t *testing.T) {
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("first")) }))
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("second")) }))
	defer first.Close()
	defer second.Close()
	tunnels := tunnel.NewLocalRegistry()
	if err := tunnels.Register("first-endpoint", first.URL); err != nil {
		t.Fatal(err)
	}
	if err := tunnels.Register("second-endpoint", second.URL); err != nil {
		t.Fatal(err)
	}
	router := NewRouter(tunnels, "probe-secret")
	addLocalTestReplica(t, router, tunnels, "overflow.test", Replica{ID: "r1", EndpointID: "first-endpoint", Healthy: true})
	addLocalTestReplica(t, router, tunnels, "overflow.test", Replica{ID: "r2", EndpointID: "second-endpoint", Healthy: true})
	// Seed the shared counter past MaxInt64. The previous int conversion made
	// the index negative here and panicked the public serving path.
	router.next.Store(1<<63 + 1)
	seen := make(map[string]int)
	for i := 0; i < 4; i++ {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "http://overflow.test/", nil)
		router.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("request %d status = %d", i, recorder.Code)
		}
		seen[recorder.Body.String()]++
	}
	if len(seen) != 2 || seen["first"] != 2 || seen["second"] != 2 {
		t.Fatalf("overflowed counter broke rotation: %v", seen)
	}
}

// TestUpstreamMarkerSeparatesReplicaResponsesFromEdgeErrors pins the exact
// signal a health driver needs. Every status below is reachable through the
// same probe request, and status alone cannot tell them apart: the edge answers
// with a status of its own precisely when the replica is the thing that is down
// or unroutable. Only responses the edge actually proxied back from a replica
// may carry the upstream marker.
func TestUpstreamMarkerSeparatesReplicaResponsesFromEdgeErrors(t *testing.T) {
	live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// A replica that forges the marker changes nothing: the edge Sets it, and
		// this response genuinely did come from a replica anyway.
		w.Header().Set(UpstreamResponseHeader, "forged-by-the-miner")
		_, _ = w.Write([]byte("served"))
	}))
	defer live.Close()
	// A backend that is registered but refuses connections is exactly the dead
	// miner behind a live edge: the ReverseProxy error handler answers 502.
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	tunnels := tunnel.NewLocalRegistry()
	if err := tunnels.Register("live-endpoint", live.URL); err != nil {
		t.Fatal(err)
	}
	if err := tunnels.Register("dead-endpoint", deadURL); err != nil {
		t.Fatal(err)
	}
	router := NewRouter(tunnels, "probe-secret")
	addLocalTestReplica(t, router, tunnels, "marker.test", Replica{ID: "live", EndpointID: "live-endpoint", Healthy: true})
	addLocalTestReplica(t, router, tunnels, "marker.test", Replica{ID: "dead", EndpointID: "dead-endpoint", Healthy: false})
	// A replica whose tunnel target never resolved is routed but unproxyable.
	router.addLocal("marker.test", Replica{ID: "untunnelled", EndpointID: "untunnelled-endpoint", Healthy: false}, nil)

	probe := func(host, target, token string) *http.Response {
		t.Helper()
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "http://"+host+"/challenge", nil)
		request.Host = host
		if target != "" {
			request.Header.Set(TargetReplicaHeader, target)
			request.Header.Set(ProbeAuthorizationHeader, token)
		}
		router.ServeHTTP(recorder, request)
		return recorder.Result()
	}

	served := probe("marker.test", "live", "probe-secret")
	defer served.Body.Close()
	if served.StatusCode != http.StatusOK {
		t.Fatalf("targeted probe of a live replica returned %d", served.StatusCode)
	}
	if got := served.Header.Values(UpstreamResponseHeader); len(got) != 1 || got[0] != UpstreamResponseMarker {
		t.Fatalf("a proxied replica response did not carry exactly the upstream marker: %v", got)
	}

	for name, edgeCase := range map[string]struct {
		response *http.Response
		status   int
	}{
		"dial failure to a dead replica": {probe("marker.test", "dead", "probe-secret"), http.StatusBadGateway},
		"replica with no tunnel target":  {probe("marker.test", "untunnelled", "probe-secret"), http.StatusBadGateway},
		"replica not in the routes":      {probe("marker.test", "replaced-already", "probe-secret"), http.StatusNotFound},
		"probe token misconfigured":      {probe("marker.test", "live", "wrong-token"), http.StatusForbidden},
		"nothing healthy on the host":    {probe("empty.test", "", ""), http.StatusServiceUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			defer edgeCase.response.Body.Close()
			// Assert the exact status so the marker assertion below cannot pass
			// vacuously against some other rejection.
			if edgeCase.response.StatusCode != edgeCase.status {
				t.Fatalf("edge answered %d, want %d", edgeCase.response.StatusCode, edgeCase.status)
			}
			if got := edgeCase.response.Header.Get(UpstreamResponseHeader); got != "" {
				t.Fatalf("an edge-generated %d claimed to come from a replica: %q", edgeCase.response.StatusCode, got)
			}
		})
	}
}
