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
