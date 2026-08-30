// SPDX-License-Identifier: AGPL-3.0-only

package runtimeapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"path"
	"strings"
)

const (
	maximumControlBodyBytes = 1 << 20
	// maximumControlResponseBytes keeps every control response inside one
	// runtime message together with the JSON-RPC envelope.
	maximumControlResponseBytes = MaxMessageBytes - (64 << 10)
	maximumControlTargetBytes   = 512
)

// handleControl executes one typed control operation against the installed
// control plane. The operation is replayed as an in-process HTTP request so
// the public scheduler, edge authority, health, weight, recovery, and
// campaign handlers run exactly as they do behind the production route table.
func (s *Server) handleControl(input ControlRequest) (ControlResponse, *Error) {
	if len(input.Body) > maximumControlBodyBytes || !validControlTarget(input.Method, input.Path) || !validControlQuery(input.Query) {
		return ControlResponse{}, invalidParams()
	}
	body := input.Body
	if len(body) == 0 {
		body = json.RawMessage(`{}`)
	}
	canonical, err := canonicalJSON(body)
	if err != nil || !bytes.Equal(body, canonical) {
		return ControlResponse{}, invalidParams()
	}
	handler := s.Control
	if handler == nil {
		return ControlResponse{}, &Error{Code: -32000, Message: "control plane unavailable"}
	}
	target := input.Path
	if input.Query != "" {
		target += "?" + input.Query
	}
	request, err := http.NewRequest(input.Method, target, bytes.NewReader(body))
	if err != nil {
		return ControlResponse{}, invalidParams()
	}
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(body))
	request.RemoteAddr = "runtime.v1"
	recorder := &controlRecorder{header: make(http.Header), limit: maximumControlResponseBytes}
	handler.ServeHTTP(recorder, request)
	return recorder.response(), nil
}

// controlRecorder captures one in-process control response without ever
// touching a network socket. Responses larger than the runtime message limit
// are reported as an explicit failure instead of being truncated.
type controlRecorder struct {
	header   http.Header
	status   int
	body     bytes.Buffer
	limit    int
	overflow bool
}

func (r *controlRecorder) Header() http.Header { return r.header }

func (r *controlRecorder) WriteHeader(status int) {
	if r.status == 0 {
		r.status = status
	}
}

func (r *controlRecorder) Write(payload []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	if r.overflow || r.body.Len()+len(payload) > r.limit {
		r.overflow = true
		return 0, errors.New("control response exceeds the runtime message limit")
	}
	return r.body.Write(payload)
}

func (r *controlRecorder) response() ControlResponse {
	if r.overflow {
		return jsonControl(http.StatusBadGateway, controlError("response_too_large", "control response exceeds the runtime message limit", false))
	}
	status := r.status
	if status == 0 {
		status = http.StatusOK
	}
	body := bytes.TrimSpace(r.body.Bytes())
	if len(body) == 0 {
		body = []byte(`{}`)
	}
	if !json.Valid(body) {
		message := string(body)
		if len(message) > 256 {
			message = message[:256]
		}
		return jsonControl(status, controlError("non_json_response", message, false))
	}
	return ControlResponse{Status: status, Body: cloneRaw(body)}
}

func controlRPCMethod(method, path string) string {
	switch {
	case method == http.MethodGet && path == "/v1/capabilities":
		return "runtime.v1.capabilities.get"
	case method == http.MethodPost && path == "/v1/chain-state":
		return "runtime.v1.chain.stage"
	case method == http.MethodPost && path == "/v1/miners":
		return "runtime.v1.miner.register"
	case method == http.MethodPost && path == "/v1/miners/snapshot":
		return "runtime.v1.miner.snapshot"
	case method == http.MethodGet && path == "/v1/miners":
		return "runtime.v1.miner.list"
	case method == http.MethodGet && strings.HasPrefix(path, "/v1/miners/") && strings.Count(path, "/") == 3:
		return "runtime.v1.miner.get"
	case method == http.MethodPost && path == "/v1/deployments":
		return "runtime.v1.deployment.create"
	case method == http.MethodPost && path == "/v1/local/deployments":
		return "runtime.v1.deployment.local.create"
	case method == http.MethodGet && strings.HasPrefix(path, "/v1/deployments/") && strings.Count(path, "/") == 3:
		return "runtime.v1.deployment.get"
	case method == http.MethodDelete && strings.HasPrefix(path, "/v1/deployments/") && strings.Count(path, "/") == 3:
		return "runtime.v1.deployment.delete"
	case method == http.MethodPost && path == "/v1/health":
		return "runtime.v1.health.record"
	case method == http.MethodGet && path == "/v1/weights":
		return "runtime.v1.weights.get"
	case method == http.MethodGet && path == "/v1/recovery":
		return "runtime.v1.recovery.get"
	case method == http.MethodGet && path == "/v1/campaign/status":
		return "runtime.v1.campaign.status"
	case method == http.MethodGet && strings.HasPrefix(path, "/v1/campaign/evidence/") && strings.Count(path, "/") == 4:
		return "runtime.v1.campaign.evidence.get"
	case method == http.MethodPost && path == "/v1/campaign/pause":
		return "runtime.v1.campaign.pause"
	case method == http.MethodPost && path == "/v1/campaign/resume":
		return "runtime.v1.campaign.resume"
	case method == http.MethodPost && path == "/v1/campaign/drain":
		return "runtime.v1.campaign.drain"
	case method == http.MethodPost && path == "/v1/campaign/shutdown":
		return "runtime.v1.campaign.shutdown"
	default:
		return ""
	}
}

func validControlTarget(method, target string) bool {
	if method != http.MethodGet && method != http.MethodPost && method != http.MethodDelete {
		return false
	}
	if !strings.HasPrefix(target, "/v1/") || len(target) > maximumControlTargetBytes || !printableASCII(target) {
		return false
	}
	if strings.ContainsAny(target, "?#\\") || path.Clean(target) != target {
		return false
	}
	return true
}

func validControlQuery(query string) bool {
	if query == "" {
		return true
	}
	if len(query) > maximumControlTargetBytes || !printableASCII(query) || strings.ContainsAny(query, "#?") {
		return false
	}
	_, err := url.ParseQuery(query)
	return err == nil
}

func printableASCII(value string) bool {
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func jsonControl(status int, value any) ControlResponse {
	if raw, ok := value.(json.RawMessage); ok {
		return ControlResponse{Status: status, Body: cloneRaw(raw)}
	}
	payload, _ := json.Marshal(value)
	return ControlResponse{Status: status, Body: payload}
}

func controlError(code, message string, retryable bool) map[string]any {
	return map[string]any{"error": map[string]any{"code": code, "message": message, "retryable": retryable}}
}
