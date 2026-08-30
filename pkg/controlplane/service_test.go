// SPDX-License-Identifier: AGPL-3.0-only

package controlplane

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
	"github.com/misscomputer/misscomputer-subnet/pkg/durable"
	"github.com/misscomputer/misscomputer-subnet/pkg/neuron"
)

func testConfig(t *testing.T) Config {
	t.Helper()
	root := t.TempDir()
	return Config{
		Network: "local", NetUID: 42, ValidatorHotkey: "validator", Domain: "mock.local", Replicas: 3,
		BridgeSecret:   bytes.Repeat([]byte{7}, 32),
		ServiceKeyFile: filepath.Join(root, "service.key"), StateDB: filepath.Join(root, "control.db"),
		Artifacts:    artifact.FileStore{Root: filepath.Join(root, "artifacts")},
		EdgeProbeURL: "http://127.0.0.1:8081", EdgeTrustedProxyCIDRs: []string{"127.0.0.0/8", "::1/128"},
	}
}

func newTestPlane(t *testing.T, adjust func(*Config)) *Plane {
	t.Helper()
	config := testConfig(t)
	if adjust != nil {
		adjust(&config)
	}
	plane, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = plane.Close(ctx)
	})
	return plane
}

func call(t *testing.T, handler http.Handler, method, target string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	switch value := body.(type) {
	case nil:
		reader = bytes.NewReader([]byte(`{}`))
	case string:
		reader = bytes.NewReader([]byte(value))
	default:
		payload, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(payload)
	}
	request := httptest.NewRequest(method, target, reader)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestNewRejectsIncompleteOrUnsafeConfiguration(t *testing.T) {
	for name, adjust := range map[string]func(*Config){
		"missing identity":                 func(c *Config) { c.ValidatorHotkey = "" },
		"wrong replica count":              func(c *Config) { c.Replicas = 2 },
		"short bridge secret":              func(c *Config) { c.BridgeSecret = c.BridgeSecret[:31] },
		"missing artifact store":           func(c *Config) { c.Artifacts = nil },
		"missing probe":                    func(c *Config) { c.EdgeProbeURL = "" },
		"trusted ingress with local probe": func(c *Config) { c.EdgeRequireTrustedIngressIdentity = true },
		"private axons off mock network": func(c *Config) {
			c.Network = "finney"
			c.AllowPrivateAxons = true
		},
		"insecure http without private axons": func(c *Config) { c.AllowInsecureMockHTTP = true },
		"no trusted proxies":                  func(c *Config) { c.EdgeTrustedProxyCIDRs = nil },
		"invalid trusted proxy":               func(c *Config) { c.EdgeTrustedProxyCIDRs = []string{"not-a-cidr"} },
	} {
		t.Run(name, func(t *testing.T) {
			config := testConfig(t)
			adjust(&config)
			if plane, err := New(config); err == nil {
				_ = plane.Close(context.Background())
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
}

func TestControlPlaneServesTheProductionRouteTable(t *testing.T) {
	plane := newTestPlane(t, nil)
	handler := plane.Control()

	capabilities := call(t, handler, http.MethodGet, "/v1/capabilities", nil)
	if capabilities.Code != http.StatusOK {
		t.Fatalf("capabilities: %d %s", capabilities.Code, capabilities.Body.String())
	}
	var decoded neuron.ControlCapabilities
	if err := json.Unmarshal(capabilities.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Protocol != neuron.SynapseVersion || decoded.ServicePublicKey != hex.EncodeToString(plane.ServicePublicKey()) ||
		!strings.Contains(strings.Join(decoded.Features, ","), "scheduler") || decoded.WeightsEnabled {
		t.Fatalf("capabilities do not describe the running control plane: %+v", decoded)
	}

	if weights := call(t, handler, http.MethodGet, "/v1/weights?hours=0", nil); weights.Code != http.StatusBadRequest {
		t.Fatalf("invalid weight window accepted: %d %s", weights.Code, weights.Body.String())
	}
	deploy := call(t, handler, http.MethodPost, "/v1/deployments", neuron.DeployRequest{
		Protocol: neuron.SynapseVersion, DeploymentID: "demo", TimeoutMS: 5_000,
	})
	if deploy.Code != http.StatusServiceUnavailable || !strings.Contains(deploy.Body.String(), "metagraph_not_ready") {
		t.Fatalf("deployment before chain sync was not gated by the scheduler: %d %s", deploy.Code, deploy.Body.String())
	}
	if local := call(t, handler, http.MethodPost, "/v1/local/deployments", nil); local.Code != http.StatusNotFound {
		t.Fatalf("local workloads enabled by default: %d", local.Code)
	}
	recovery := call(t, handler, http.MethodGet, "/v1/recovery", nil)
	var recovered neuron.RecoveryResponse
	if recovery.Code != http.StatusOK || json.Unmarshal(recovery.Body.Bytes(), &recovered) != nil || recovered.Protocol != neuron.SynapseVersion {
		t.Fatalf("recovery: %d %s", recovery.Code, recovery.Body.String())
	}
	if status := call(t, handler, http.MethodGet, "/v1/campaign/status", nil); status.Code != http.StatusNotFound {
		t.Fatalf("campaign reported enabled without configuration: %d %s", status.Code, status.Body.String())
	}
	if health := call(t, handler, http.MethodPost, "/v1/health", `{"protocol":"wrong"}`); health.Code != http.StatusBadRequest {
		t.Fatalf("invalid health observation accepted: %d", health.Code)
	}
	if missing := call(t, handler, http.MethodGet, "/v1/miners/absent", nil); missing.Code != http.StatusNotFound {
		t.Fatalf("unknown miner readback: %d", missing.Code)
	}
	if unknown := call(t, handler, http.MethodGet, "/v1/not-a-route", nil); unknown.Code != http.StatusNotFound {
		t.Fatalf("unknown route: %d", unknown.Code)
	}
}

func TestDryRunWeightsAreComputedFromDurableObservations(t *testing.T) {
	plane := newTestPlane(t, nil)
	handler := plane.Control()
	empty := call(t, handler, http.MethodGet, "/v1/weights?hours=24", nil)
	if empty.Code != http.StatusOK || !strings.Contains(empty.Body.String(), `"weights":[]`) {
		t.Fatalf("empty weights: %d %s", empty.Code, empty.Body.String())
	}
	observation := durable.Observation{
		MinerHotkey: "miner-a", Success: true, LatencyMS: 25, Availability: 1, ObservedAt: time.Now().UTC(), Kind: "health",
	}
	if err := plane.api.ledger.RecordObservation(observation); err != nil {
		t.Fatal(err)
	}
	weights := call(t, handler, http.MethodGet, "/v1/weights?hours=24", nil)
	var decoded struct {
		Protocol string `json:"protocol"`
		DryRun   bool   `json:"dry_run"`
		Weights  []struct {
			MinerHotkey string  `json:"miner_hotkey"`
			Weight      float64 `json:"weight"`
			Samples     int     `json:"samples"`
		} `json:"weights"`
	}
	if weights.Code != http.StatusOK || json.Unmarshal(weights.Body.Bytes(), &decoded) != nil {
		t.Fatalf("weights: %d %s", weights.Code, weights.Body.String())
	}
	if decoded.Protocol != neuron.SynapseVersion || !decoded.DryRun || len(decoded.Weights) != 1 ||
		decoded.Weights[0].MinerHotkey != "miner-a" || decoded.Weights[0].Weight <= 0 || decoded.Weights[0].Samples != 1 {
		t.Fatalf("weights were not computed from the recorded observation: %s", weights.Body.String())
	}
}

func TestEdgeOriginTrustsOnlyConfiguredPeersAndDeploymentHosts(t *testing.T) {
	plane := newTestPlane(t, nil)
	handler := plane.Edge()
	for _, test := range []struct {
		name       string
		host, peer string
		forbidden  bool
		misdirect  bool
	}{
		{name: "untrusted peer", host: "demo.mock.local", peer: "8.8.8.8:4000", forbidden: true},
		{name: "foreign host", host: "demo.example.com", peer: "127.0.0.1:4000", misdirect: true},
		{name: "trusted peer without route", host: "demo.mock.local", peer: "127.0.0.1:4000"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "http://"+test.host+"/index.html", nil)
			request.Host = test.host
			request.RemoteAddr = test.peer
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			switch {
			case test.forbidden && response.Code != http.StatusForbidden:
				t.Fatalf("untrusted peer was served: %d", response.Code)
			case test.misdirect && response.Code != http.StatusMisdirectedRequest:
				t.Fatalf("foreign host was routed: %d", response.Code)
			case !test.forbidden && !test.misdirect && (response.Code == http.StatusForbidden || response.Code == http.StatusMisdirectedRequest || response.Code == http.StatusOK):
				t.Fatalf("trusted peer without a route answered %d", response.Code)
			}
		})
	}
}
