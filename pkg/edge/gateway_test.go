// SPDX-License-Identifier: AGPL-3.0-only

package edge

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func activeGatewayFixture(t *testing.T, backend http.Handler, routerConfig RouterConfig, gatewayConfig GatewayConfig) (*Gateway, routeFixture) {
	t.Helper()
	fixture := newRouteFixture(t, "app", 1, "gateway-nonce")
	fixture.backend.Close()
	fixture.registry.Unregister(fixture.receipt.EndpointID)
	fixture.backend = httptest.NewServer(backend)
	if err := fixture.registry.Register(fixture.receipt.EndpointID, fixture.backend.URL); err != nil {
		t.Fatal(err)
	}
	routerConfig.AllowPrivateUpstreams = true
	router := fixture.router(t, routerConfig)
	if err := router.RegisterPending(context.Background(), fixture.ticket, fixture.receipt, fixture.minerPublic, fixture.validatorPrivate); err != nil {
		t.Fatal(err)
	}
	if err := router.Activate(context.Background(), fixture.ticket, fixture.receipt, fixture.minerPublic, fixture.validatorPrivate); err != nil {
		t.Fatal(err)
	}
	gatewayConfig.Domain = "miss.computer"
	gatewayConfig.HostLabelPrefix = "edge-dev-"
	gateway, err := NewGateway(router, gatewayConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gateway.Close)
	t.Cleanup(fixture.backend.Close)
	return gateway, fixture
}

func TestGatewayStrictHostAndPrivateIngressPolicy(t *testing.T) {
	gateway, _ := activeGatewayFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), RouterConfig{}, GatewayConfig{})
	server := httptest.NewServer(gateway)
	defer server.Close()

	for _, host := range []string{
		"miss.computer", "app.miss.computer", "edge-dev-app.other.example", "nested.edge-dev-app.miss.computer",
		"edge-dev-app.miss.computer.", "edge-dev-.miss.computer", "edge-dev-app.on.miss.computer",
	} {
		req, _ := http.NewRequest(http.MethodGet, server.URL+"/", nil)
		req.Host = host
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusMisdirectedRequest {
			t.Fatalf("invalid Host %q returned %d", host, resp.StatusCode)
		}
	}
	req, _ := http.NewRequest(http.MethodGet, server.URL+"/", nil)
	req.Host = "edge-dev-app.miss.computer:443"
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("canonical host with port returned %d", resp.StatusCode)
	}

	direct := httptest.NewRequest(http.MethodGet, "http://edge-dev-app.miss.computer/", nil)
	direct.RemoteAddr = "10.0.0.8:12345"
	recorder := httptest.NewRecorder()
	gateway.ServeHTTP(recorder, direct)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("untrusted private ingress returned %d", recorder.Code)
	}
}

func TestGatewayReverseProxyPreservesRequestAndRebuildsForwarding(t *testing.T) {
	seen := make(chan string, 1)
	gateway, _ := activeGatewayFixture(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		payload, _ := io.ReadAll(req.Body)
		seen <- fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s", req.Method, req.URL.RequestURI(), req.Host, string(payload),
			req.Header.Get("X-Forwarded-For"), req.Header.Get("X-Forwarded-Proto"), req.Header.Get("X-Trusted-Request-ID"), req.Header.Get(TargetReplicaHeader))
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("proxied"))
	}), RouterConfig{}, GatewayConfig{MaxRequestBytes: 64})
	server := httptest.NewServer(gateway)
	defer server.Close()
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/upload?q=1", strings.NewReader("payload"))
	req.Host = "edge-dev-app.miss.computer"
	req.Header.Set("X-Forwarded-For", "203.0.113.99")
	req.Header.Set("X-Forwarded-Proto", "gopher")
	req.Header.Set("X-Trusted-Request-ID", "spoofed-ray")
	req.Header.Set(TargetReplicaHeader, fixtureReplicaNoTarget())
	// A client cannot select a replica without the independent probe token.
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unauthenticated targeted request returned %d", resp.StatusCode)
	}

	req, _ = http.NewRequest(http.MethodPost, server.URL+"/upload?q=1", strings.NewReader("payload"))
	req.Host = "edge-dev-app.miss.computer"
	req.Header.Set("X-Forwarded-For", "203.0.113.99")
	req.Header.Set("X-Forwarded-Proto", "gopher")
	req.Header.Set("X-Trusted-Request-ID", "spoofed-ray")
	resp, err = server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "proxied" {
		t.Fatalf("proxy status=%d body=%q", resp.StatusCode, body)
	}
	observation := <-seen
	if !strings.HasPrefix(observation, "POST|/upload?q=1|edge-dev-app.miss.computer|payload|127.0.0.1|http|") || !strings.HasSuffix(observation, "||") {
		t.Fatalf("unexpected upstream request: %q", observation)
	}
}

func fixtureReplicaNoTarget() string { return "app-miner-a" }

func TestGatewayBoundsTimeoutsStreamingAndUpgradeDisposition(t *testing.T) {
	var calls atomic.Int64
	backend := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls.Add(1)
		switch req.URL.Path {
		case "/large":
			_, _ = w.Write([]byte("12345"))
		case "/slow":
			time.Sleep(80 * time.Millisecond)
			_, _ = w.Write([]byte("late"))
		case "/stream":
			_, _ = w.Write([]byte("a"))
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
			_, _ = w.Write([]byte("b"))
		default:
			_, _ = io.Copy(io.Discard, req.Body)
			w.WriteHeader(http.StatusNoContent)
		}
	})
	gateway, _ := activeGatewayFixture(t, backend, RouterConfig{MaxResponseBytes: 4, ResponseHeaderTimeout: 20 * time.Millisecond}, GatewayConfig{MaxRequestBytes: 4})
	server := httptest.NewServer(gateway)
	defer server.Close()

	request := func(method, path, body string) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(method, server.URL+path, strings.NewReader(body))
		req.Host = "edge-dev-app.miss.computer"
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	resp := request(http.MethodPost, "/", "12345")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge || calls.Load() != 0 {
		t.Fatalf("oversized request status=%d backend_calls=%d", resp.StatusCode, calls.Load())
	}
	resp = request(http.MethodGet, "/large", "")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("known oversized response status=%d", resp.StatusCode)
	}
	resp = request(http.MethodGet, "/slow", "")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("response header timeout status=%d", resp.StatusCode)
	}
	resp = request(http.MethodGet, "/stream", "")
	streamed, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(streamed) != "ab" {
		t.Fatalf("bounded response streaming status=%d body=%q", resp.StatusCode, streamed)
	}

	beforeUpgrade := calls.Load()
	req, _ := http.NewRequest(http.MethodGet, server.URL+"/", nil)
	req.Host = "edge-dev-app.miss.computer"
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUpgradeRequired || calls.Load() != beforeUpgrade {
		t.Fatalf("WebSocket disposition status=%d backend_calls=%d", resp.StatusCode, calls.Load())
	}
}

func TestGatewayRequiresGenericIngressIdentityOnlyFromTrustedPeer(t *testing.T) {
	gateway, _ := activeGatewayFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), RouterConfig{}, GatewayConfig{RequireTrustedIngressIdentity: true})
	server := httptest.NewServer(gateway)
	defer server.Close()
	req, _ := http.NewRequest(http.MethodGet, server.URL+"/", nil)
	req.Host = "edge-dev-app.miss.computer"
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("missing trusted ingress identity returned %d", resp.StatusCode)
	}
	req, _ = http.NewRequest(http.MethodGet, server.URL+"/", nil)
	req.Host = "edge-dev-app.miss.computer"
	req.Header.Set("X-Trusted-Client-IP", "198.51.100.10")
	req.Header.Set("X-Trusted-Request-ID", "abcdef0123456789-IAD")
	resp, err = server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("trusted generic ingress returned %d", resp.StatusCode)
	}
}
