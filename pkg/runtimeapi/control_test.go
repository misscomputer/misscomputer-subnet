// SPDX-License-Identifier: AGPL-3.0-only

package runtimeapi

import (
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type recordedControl struct {
	method, path, query, body string
}

// recordingPlane stands in for the production control plane: it records what
// the runtime replayed into it and answers with a JSON document.
type recordingPlane struct {
	mu    sync.Mutex
	calls []recordedControl
	mux   *http.ServeMux
}

func newRecordingPlane(t *testing.T) *recordingPlane {
	t.Helper()
	plane := &recordingPlane{mux: http.NewServeMux()}
	record := func(status int) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			payload, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("read replayed body: %v", err)
			}
			plane.mu.Lock()
			plane.calls = append(plane.calls, recordedControl{method: r.Method, path: r.URL.Path, query: r.URL.RawQuery, body: string(payload)})
			plane.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]any{"route": r.Pattern, "hotkey": r.PathValue("hotkey")})
		}
	}
	for _, route := range []string{
		"GET /v1/capabilities", "POST /v1/chain-state", "POST /v1/miners", "GET /v1/miners/{hotkey}",
		"POST /v1/miners/snapshot", "GET /v1/miners", "POST /v1/deployments", "POST /v1/local/deployments",
		"GET /v1/deployments/{deployment}", "DELETE /v1/deployments/{deployment}", "POST /v1/health", "GET /v1/weights",
		"GET /v1/recovery", "GET /v1/campaign/status", "GET /v1/campaign/evidence/{sequence}", "POST /v1/campaign/pause",
		"POST /v1/campaign/resume", "POST /v1/campaign/drain", "POST /v1/campaign/shutdown",
	} {
		plane.mux.HandleFunc(route, record(http.StatusOK))
	}
	return plane
}

func (p *recordingPlane) ServeHTTP(w http.ResponseWriter, r *http.Request) { p.mux.ServeHTTP(w, r) }

func (p *recordingPlane) recorded() []recordedControl {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]recordedControl(nil), p.calls...)
}

func openServer(t *testing.T) *Server {
	t.Helper()
	server, err := Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server
}

func controlCall(t *testing.T, server *Server, method, path, query, body string) ControlResponse {
	t.Helper()
	response := controlAttempt(t, server, method, path, query, body)
	if response.Error != nil {
		t.Fatalf("%s %s: %+v", method, path, response.Error)
	}
	var result ControlResponse
	if err := json.Unmarshal(response.Result, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func controlAttempt(t *testing.T, server *Server, method, path, query, body string) Response {
	t.Helper()
	params, err := json.Marshal(ControlRequest{Method: method, Path: path, Query: query, Body: json.RawMessage(body)})
	if err != nil {
		t.Fatal(err)
	}
	rpcMethod := controlRPCMethod(method, path)
	if rpcMethod == "" {
		t.Fatalf("no public runtime RPC method for %s %s", method, path)
	}
	return server.Handle(mustRequest(t, rpcMethod, params))
}

func mustRequest(t *testing.T, method string, params json.RawMessage) []byte {
	t.Helper()
	payload, err := json.Marshal(Request{JSONRPC: "2.0", ID: "test", Method: method, Params: params})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestAllNineteenControlOperationsReachTheControlPlane(t *testing.T) {
	server := openServer(t)
	plane := newRecordingPlane(t)
	server.Control = plane
	requests := []struct{ method, path, query, body string }{
		{http.MethodGet, "/v1/capabilities", "", `{}`},
		{http.MethodPost, "/v1/chain-state", "", `{"network":"finney"}`},
		{http.MethodPost, "/v1/miners", "", `{"hotkey":"miner-a"}`},
		{http.MethodGet, "/v1/miners/miner-a", "", `{}`},
		{http.MethodPost, "/v1/miners/snapshot", "", `{"hotkeys":[]}`},
		{http.MethodGet, "/v1/miners", "", `{}`},
		{http.MethodPost, "/v1/deployments", "", `{"deployment_id":"deployment-a"}`},
		{http.MethodPost, "/v1/local/deployments", "", `{"deployment_id":"local-a"}`},
		{http.MethodGet, "/v1/deployments/deployment-a", "", `{}`},
		{http.MethodDelete, "/v1/deployments/deployment-a", "", `{}`},
		{http.MethodPost, "/v1/health", "", `{"reachable":true}`},
		{http.MethodGet, "/v1/weights", "hours=24", `{}`},
		{http.MethodGet, "/v1/recovery", "", `{}`},
		{http.MethodGet, "/v1/campaign/status", "", `{}`},
		{http.MethodGet, "/v1/campaign/evidence/1", "", `{}`},
		{http.MethodPost, "/v1/campaign/pause", "", `{}`},
		{http.MethodPost, "/v1/campaign/resume", "", `{}`},
		{http.MethodPost, "/v1/campaign/drain", "", `{}`},
		{http.MethodPost, "/v1/campaign/shutdown", "", `{}`},
	}
	if len(requests) != 19 {
		t.Fatal("control operation inventory changed")
	}
	for _, request := range requests {
		result := controlCall(t, server, request.method, request.path, request.query, request.body)
		if result.Status != http.StatusOK || !json.Valid(result.Body) {
			t.Fatalf("%s %s returned %+v", request.method, request.path, result)
		}
	}
	calls := plane.recorded()
	if len(calls) != len(requests) {
		t.Fatalf("control plane received %d operations, want %d", len(calls), len(requests))
	}
	for index, request := range requests {
		got := calls[index]
		if got.method != request.method || got.path != request.path || got.query != request.query || got.body != request.body {
			t.Fatalf("operation %d replayed as %+v, want %+v", index, got, request)
		}
	}
	miner := controlCall(t, server, http.MethodGet, "/v1/miners/miner-a", "", `{}`)
	if !strings.Contains(string(miner.Body), `"hotkey":"miner-a"`) {
		t.Fatalf("path values were not routed: %s", miner.Body)
	}
}

func TestControlFailsClosedWithoutAnInstalledControlPlane(t *testing.T) {
	server := openServer(t)
	response := controlAttempt(t, server, http.MethodGet, "/v1/weights", "", `{}`)
	if response.Error == nil || response.Error.Code != -32000 {
		t.Fatalf("control without a plane answered %+v", response)
	}
}

func TestControlRejectsNonCanonicalBodiesUncleanTargetsAndUnknownOperations(t *testing.T) {
	server := openServer(t)
	server.Control = newRecordingPlane(t)
	nonCanonical := []byte(`{"jsonrpc":"2.0","id":"test","method":"runtime.v1.health.record","params":{"method":"POST","path":"/v1/health","body":{"healthy": true}}}`)
	if response := server.Handle(nonCanonical); response.Error == nil {
		t.Fatal("non-canonical control body accepted")
	}
	for _, target := range []ControlRequest{
		{Method: http.MethodGet, Path: "/v1/weights", Query: "hours=24#x", Body: json.RawMessage(`{}`)},
		{Method: http.MethodGet, Path: "/v1/weights", Query: "hours=%zz", Body: json.RawMessage(`{}`)},
		{Method: http.MethodGet, Path: "/v1//weights", Body: json.RawMessage(`{}`)},
		{Method: http.MethodGet, Path: "/v1/weights/../miners", Body: json.RawMessage(`{}`)},
		{Method: http.MethodGet, Path: "/v1/weights?hours=1", Body: json.RawMessage(`{}`)},
		{Method: http.MethodPut, Path: "/v1/weights", Body: json.RawMessage(`{}`)},
	} {
		if _, rpcError := server.handleControl(target); rpcError == nil {
			t.Fatalf("unclean control target accepted: %+v", target)
		}
	}
	got, rpcError := server.handleControl(ControlRequest{Method: http.MethodGet, Path: "/v1/not-real", Body: json.RawMessage(`{}`)})
	if rpcError != nil || got.Status != http.StatusNotFound || !json.Valid(got.Body) {
		t.Fatalf("unknown operation = %+v err=%v", got, rpcError)
	}
	if response := server.Handle(mustRequest(t, "runtime.v1.weights.get", json.RawMessage(`{"method":"GET","path":"/v1/miners","body":{}}`))); response.Error == nil {
		t.Fatal("mismatched typed method and target accepted")
	}
}

func TestControlNormalizesNonJSONAndOversizedResponses(t *testing.T) {
	server := openServer(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/weights", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "plain text failure", http.StatusServiceUnavailable)
	})
	mux.HandleFunc("GET /v1/recovery", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"payload":"` + strings.Repeat("x", maximumControlResponseBytes) + `"}`))
	})
	server.Control = mux
	text := controlCall(t, server, http.MethodGet, "/v1/weights", "", `{}`)
	if text.Status != http.StatusServiceUnavailable || !strings.Contains(string(text.Body), `"non_json_response"`) {
		t.Fatalf("plain-text response was not normalized: %+v", text)
	}
	large := controlCall(t, server, http.MethodGet, "/v1/recovery", "", `{}`)
	if large.Status != http.StatusBadGateway || !strings.Contains(string(large.Body), `"response_too_large"`) {
		t.Fatalf("oversized response was not rejected: status=%d len=%d", large.Status, len(large.Body))
	}
}
