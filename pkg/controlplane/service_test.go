// SPDX-License-Identifier: AGPL-3.0-only

package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
	"github.com/misscomputer/misscomputer-subnet/pkg/control"
	"github.com/misscomputer/misscomputer-subnet/pkg/durable"
	"github.com/misscomputer/misscomputer-subnet/pkg/edge"
	"github.com/misscomputer/misscomputer-subnet/pkg/miner"
	"github.com/misscomputer/misscomputer-subnet/pkg/neuron"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	deployruntime "github.com/misscomputer/misscomputer-subnet/pkg/runtime"
	"github.com/misscomputer/misscomputer-subnet/pkg/workload"
)

type planeBlockingAssigner struct {
	id      string
	key     ed25519.PublicKey
	started chan struct{}
	release chan struct{}
}

func (m *planeBlockingAssigner) ID() string                   { return m.id }
func (m *planeBlockingAssigner) PublicKey() ed25519.PublicKey { return m.key }
func (m *planeBlockingAssigner) Assign(context.Context, protocol.Ticket) (miner.Result, error) {
	close(m.started)
	<-m.release
	return miner.Result{}, errors.New("released assignment")
}
func (*planeBlockingAssigner) Deactivate(context.Context, string) error { return nil }

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
		"negative probe interval":             func(c *Config) { c.PeriodicProbeInterval = -time.Second },
		"negative probe timeout":              func(c *Config) { c.PeriodicProbeTimeout = -time.Second },
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

func TestPlaneCloseRefusesToCloseResourcesUnderLiveSchedulerWorker(t *testing.T) {
	plane := newTestPlane(t, nil)
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blocked := &planeBlockingAssigner{id: "blocked", key: publicKey, started: make(chan struct{}), release: make(chan struct{})}
	plane.scheduler.Replicas = 1
	plane.scheduler.SetMiners([]miner.Assigner{blocked})
	spec, layer, err := workload.Generate("static", 1024)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := artifact.Publish(context.Background(), plane.api.artifacts, spec.Kind, [][]byte{layer}, nil)
	if err != nil {
		t.Fatal(err)
	}
	deployDone := make(chan error, 1)
	go func() {
		_, deployErr := plane.scheduler.Deploy(context.Background(), control.DeployRequest{
			DeploymentID: "close-owned", Manifest: manifest, ManifestKey: artifact.ManifestKey(manifest.ImageDigest), Workload: spec, Timeout: 20 * time.Millisecond,
		})
		deployDone <- deployErr
	}()
	<-blocked.started
	if err := <-deployDone; err == nil {
		t.Fatal("timed out assignment succeeded")
	}
	closeCtx, cancelClose := context.WithTimeout(context.Background(), 20*time.Millisecond)
	if err := plane.Close(closeCtx); !errors.Is(err, context.DeadlineExceeded) {
		cancelClose()
		t.Fatalf("Plane.Close did not surface live scheduler ownership: %v", err)
	}
	cancelClose()
	if _, err := plane.store.ActiveEndpoints(context.Background()); err != nil {
		t.Fatalf("Plane.Close closed durable state after failed drain: %v", err)
	}
	close(blocked.release)
	joined, cancelJoined := context.WithTimeout(context.Background(), time.Second)
	if err := plane.scheduler.Drain(joined); err != nil {
		cancelJoined()
		t.Fatal(err)
	}
	cancelJoined()
	finalCtx, cancelFinal := context.WithTimeout(context.Background(), time.Second)
	if err := plane.Close(finalCtx); err != nil {
		cancelFinal()
		t.Fatalf("Plane.Close after lifecycle join: %v", err)
	}
	cancelFinal()
}

func TestPlaneCloseJoinsWholeAdmittedRequestBeforeClosingStore(t *testing.T) {
	plane := newTestPlane(t, nil)
	started := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan struct{})
	handler := plane.admittedHandler(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		response.WriteHeader(http.StatusNoContent)
	}))
	go func() {
		defer close(finished)
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/health", nil))
	}()
	<-started

	short, cancelShort := context.WithTimeout(context.Background(), 10*time.Millisecond)
	if err := plane.Close(short); !errors.Is(err, context.DeadlineExceeded) {
		cancelShort()
		t.Fatalf("Plane.Close did not surface admitted request ownership: %v", err)
	}
	cancelShort()
	if _, err := plane.store.ActiveEndpoints(context.Background()); err != nil {
		t.Fatalf("Plane.Close closed durable state beneath request tail: %v", err)
	}
	rejected := httptest.NewRecorder()
	handler.ServeHTTP(rejected, httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil))
	if rejected.Code != http.StatusServiceUnavailable {
		t.Fatalf("new request entered sealed Plane: %d", rejected.Code)
	}
	close(release)
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("admitted request did not finish")
	}
	joined, cancelJoined := context.WithTimeout(context.Background(), time.Second)
	defer cancelJoined()
	if err := plane.Close(joined); err != nil {
		t.Fatalf("Plane.Close after request join: %v", err)
	}
	if err := plane.Close(context.Background()); err != nil {
		t.Fatalf("second completed Plane.Close is not idempotent: %v", err)
	}
}

func TestPlaneCloseRefusesResourcesUntilRunJoins(t *testing.T) {
	plane := newTestPlane(t, nil)
	runCtx, cancelRun := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- plane.Run(runCtx) }()
	deadline := time.Now().Add(time.Second)
	for {
		plane.runMu.Lock()
		active := plane.runActive
		plane.runMu.Unlock()
		if active {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Plane.Run did not enter its lifecycle")
		}
		time.Sleep(time.Millisecond)
	}
	short, cancelShort := context.WithTimeout(context.Background(), 10*time.Millisecond)
	if err := plane.Close(short); !errors.Is(err, context.DeadlineExceeded) {
		cancelShort()
		t.Fatalf("Plane.Close did not refuse a live runner: %v", err)
	}
	cancelShort()
	if _, err := plane.store.ActiveEndpoints(context.Background()); err != nil {
		t.Fatalf("store closed beneath Plane.Run: %v", err)
	}
	cancelRun()
	if err := <-runDone; err != nil {
		t.Fatal(err)
	}
	joined, cancelJoined := context.WithTimeout(context.Background(), time.Second)
	defer cancelJoined()
	if err := plane.Close(joined); err != nil {
		t.Fatalf("Plane.Close after runner join: %v", err)
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
	legacyHealth := neuron.HealthObservation{
		Protocol: neuron.SynapseVersion, DeploymentID: "demo", ReplicaID: "demo-miner", EndpointID: "demo-miner-g1-old",
		MinerHotkey: "miner", Vantage: "external", Reachable: true, Correct: true, LatencyMS: 1, Availability: 1, ObservedAt: time.Now().UTC(),
	}
	if health := call(t, handler, http.MethodPost, "/v1/health", legacyHealth); health.Code != http.StatusBadRequest {
		t.Fatalf("legacy unbound health observation accepted: %d %s", health.Code, health.Body.String())
	}
	legacyHealth.Protocol = neuron.HealthObservationVersion
	legacyHealth.EndpointID = ""
	if health := call(t, handler, http.MethodPost, "/v1/health", legacyHealth); health.Code != http.StatusBadRequest {
		t.Fatalf("v3 health observation without endpoint incarnation accepted: %d %s", health.Code, health.Body.String())
	}
	completeHealth := map[string]any{
		"protocol": neuron.HealthObservationVersion, "deployment_id": "unknown", "replica_id": "unknown-miner",
		"endpoint_id": "unknown-miner-g1-nonce", "miner_hotkey": "miner", "vantage": "external",
		"reachable": true, "correct": true, "fraudulent": false, "latency_ms": int64(0),
		"availability": float64(1), "observed_at": time.Now().UTC(),
	}
	if health := call(t, handler, http.MethodPost, "/v1/health", completeHealth); health.Code != http.StatusUnprocessableEntity {
		t.Fatalf("complete unknown health observation did not reach identity validation: %d %s", health.Code, health.Body.String())
	}
	for _, requiredScalar := range []string{"reachable", "correct", "fraudulent", "latency_ms", "availability"} {
		missing := make(map[string]any, len(completeHealth))
		for key, value := range completeHealth {
			missing[key] = value
		}
		delete(missing, requiredScalar)
		if health := call(t, handler, http.MethodPost, "/v1/health", missing); health.Code != http.StatusBadRequest {
			t.Fatalf("health observation missing %s accepted: %d %s", requiredScalar, health.Code, health.Body.String())
		}
		nullValue := make(map[string]any, len(completeHealth))
		for key, value := range completeHealth {
			nullValue[key] = value
		}
		nullValue[requiredScalar] = nil
		if health := call(t, handler, http.MethodPost, "/v1/health", nullValue); health.Code != http.StatusBadRequest {
			t.Fatalf("health observation with null %s accepted: %d %s", requiredScalar, health.Code, health.Body.String())
		}
	}
	unknownField := make(map[string]any, len(completeHealth)+1)
	for key, value := range completeHealth {
		unknownField[key] = value
	}
	unknownField["unreviewed_extension"] = true
	if health := call(t, handler, http.MethodPost, "/v1/health", unknownField); health.Code != http.StatusBadRequest {
		t.Fatalf("health observation with unknown field accepted: %d %s", health.Code, health.Body.String())
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

func TestHealthObservationInsertFailureLeavesAuthenticatedReportRetryable(t *testing.T) {
	var statePath string
	plane := newTestPlane(t, func(config *Config) {
		statePath = config.StateDB
	})
	testRouter, err := edge.NewAuthorizedRouter(plane.api.tunnels, plane.scheduler.Validator.InternalProbeToken, edge.RouterConfig{
		AuthorityKey: plane.ServicePublicKey(), Store: plane.store, Domain: "mock.local",
		AllowPrivateUpstreams: true, AllowInsecureMockHTTP: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	testGateway, err := edge.NewGateway(testRouter, edge.GatewayConfig{Domain: "mock.local"})
	if err != nil {
		t.Fatal(err)
	}
	plane.gateway.Close()
	plane.gateway = testGateway
	plane.scheduler.Router = testRouter
	edgeServer := httptest.NewServer(plane.Edge())
	defer edgeServer.Close()
	plane.scheduler.Validator.EdgeURL = edgeServer.URL
	ownerPublic := plane.ServicePublicKey()
	for _, minerID := range []string{"m1", "m2", "m3", "m4"} {
		_, minerPrivate, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		agent := miner.NewAgent(minerID, ownerPublic, minerPrivate, plane.api.artifacts, deployruntime.NewLocalRuntime(), plane.api.tunnels)
		plane.scheduler.Miners = append(plane.scheduler.Miners, agent)
	}
	spec, layer, err := workload.Generate("static", 1024)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := artifact.Publish(context.Background(), plane.api.artifacts, spec.Kind, [][]byte{[]byte("base"), layer}, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := control.DeployRequest{
		DeploymentID: "health-commit-retry", Manifest: manifest, ManifestKey: artifact.ManifestKey(manifest.ImageDigest), Workload: spec,
	}
	if _, err := plane.scheduler.Deploy(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := plane.scheduler.DeactivateDeployment(ctx, request.DeploymentID); err != nil {
			t.Errorf("cleanup deployment: %v", err)
		}
	}()
	target := plane.scheduler.ActiveReplicas(request.DeploymentID)[0]
	input := neuron.HealthObservation{
		Protocol: neuron.HealthObservationVersion, DeploymentID: request.DeploymentID,
		ReplicaID: target.ReplicaID, EndpointID: target.EndpointID, MinerHotkey: target.MinerID,
		Vantage: "authenticated-external", Reachable: true, Correct: true,
		LatencyMS: 7, Availability: 1, ObservedAt: time.Now().UTC(),
	}

	triggerDB, err := sql.Open("sqlite", statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer triggerDB.Close()
	if _, err := triggerDB.ExecContext(context.Background(), `CREATE TRIGGER fail_health_observation
BEFORE INSERT ON observations WHEN NEW.kind = 'health'
BEGIN SELECT RAISE(FAIL, 'injected health observation failure'); END`); err != nil {
		t.Fatal(err)
	}
	handler := plane.Control()
	failed := call(t, handler, http.MethodPost, "/v1/health", input)
	if failed.Code != http.StatusInternalServerError || !strings.Contains(failed.Body.String(), "state_error") {
		t.Fatalf("durable observation failure was not retriable: %d %s", failed.Code, failed.Body.String())
	}
	if _, err := triggerDB.ExecContext(context.Background(), `DROP TRIGGER fail_health_observation`); err != nil {
		t.Fatal(err)
	}
	retried := call(t, handler, http.MethodPost, "/v1/health", input)
	if retried.Code != http.StatusOK {
		t.Fatalf("identical authenticated retry was rejected: %d %s", retried.Code, retried.Body.String())
	}
	replayed := call(t, handler, http.MethodPost, "/v1/health", input)
	if replayed.Code != http.StatusUnprocessableEntity {
		t.Fatalf("committed replay was not rejected: %d %s", replayed.Code, replayed.Body.String())
	}
	observations, err := plane.store.Observations(context.Background(), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	healthSamples := 0
	for _, observation := range observations {
		if observation.Kind == "health" && observation.MinerHotkey == target.MinerID {
			healthSamples++
		}
	}
	if healthSamples != 1 {
		t.Fatalf("health report persisted %d scoring samples, want exactly one", healthSamples)
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

func TestPeriodicProberIsOptInAndRunsBesideTheCampaign(t *testing.T) {
	// Without the interval the plane must behave exactly as before: no prober,
	// and Run blocks purely on cancellation.
	inert := newTestPlane(t, nil)
	if inert.prober != nil {
		t.Fatal("periodic prober was constructed without an explicit interval")
	}

	plane := newTestPlane(t, func(c *Config) {
		c.PeriodicProbeInterval = 5 * time.Millisecond
		c.PeriodicProbeTimeout = time.Millisecond
	})
	if plane.prober == nil {
		t.Fatal("configured periodic prober was not constructed")
	}
	if plane.prober.Interval != 5*time.Millisecond || plane.prober.Timeout != time.Millisecond {
		t.Fatalf("prober did not carry its configuration: %+v", plane.prober)
	}

	// Run supervises the prober beside the campaign and joins it on
	// cancellation; a prober that was never started, or one whose goroutine
	// outlives its context, hangs here instead of returning. What the prober
	// then does to each endpoint is asserted where endpoints exist, in
	// control.TestProberRunObservesEveryReplicaUntilCancelled.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- plane.Run(ctx) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Plane.Run returned %v after cancellation", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Plane.Run did not stop the prober and return")
	}
}

func TestNewRefusesProbeCadenceThatCanNeverEvict(t *testing.T) {
	// The CLI already refuses these, but a library caller configuring the plane
	// directly used to get a prober that started, swept, and evicted nothing.
	for name, mutate := range map[string]func(*Config){
		"timeout is not shorter than interval": func(c *Config) {
			c.PeriodicProbeInterval, c.PeriodicProbeTimeout = time.Second, time.Second
		},
		"unset timeout defaults above the interval": func(c *Config) {
			c.PeriodicProbeInterval = time.Second
		},
		"cadence exceeds the health rapid window": func(c *Config) {
			c.PeriodicProbeInterval, c.PeriodicProbeTimeout = 30*time.Second, time.Second
		},
		"duration addition overflows": func(c *Config) {
			var err error
			c.PeriodicProbeInterval, err = time.ParseDuration("2000000h")
			if err != nil {
				t.Fatal(err)
			}
			c.PeriodicProbeTimeout, err = time.ParseDuration("1000000h")
			if err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := testConfig(t)
			mutate(&config)
			plane, err := New(config)
			if err == nil {
				closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = plane.Close(closeCtx)
				t.Fatal("New accepted a probe cadence that can never evict an unreachable replica")
			}
			if !errors.Is(err, control.ErrProbeCadence) {
				t.Fatalf("New returned %v, want a probe cadence refusal", err)
			}
		})
	}
}
