// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
	"github.com/misscomputer/misscomputer-subnet/pkg/artifact/ocitest"
	"github.com/misscomputer/misscomputer-subnet/pkg/durable"
	"github.com/misscomputer/misscomputer-subnet/pkg/miner"
	"github.com/misscomputer/misscomputer-subnet/pkg/neuron"
	"github.com/misscomputer/misscomputer-subnet/pkg/organic"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	deployruntime "github.com/misscomputer/misscomputer-subnet/pkg/runtime"
	"github.com/misscomputer/misscomputer-subnet/pkg/tunnel"
)

// servingOCIRuntime stands in for the Docker engine only: it "launches" the
// verified artifact by pointing the instance at an already-running app and
// reports the config digest the agent verified.
type servingOCIRuntime struct {
	url      string
	mu       sync.Mutex
	launches []deployruntime.Launch
	stops    []string
}

func (r *servingOCIRuntime) Launch(_ context.Context, launch deployruntime.Launch) (deployruntime.Started, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.launches = append(r.launches, launch)
	return deployruntime.Started{
		Instance:                deployruntime.Instance{ID: launch.InstanceID, URL: r.url},
		LoadedImageConfigDigest: launch.Manifest.Config.Digest, ImageReadyAt: time.Now().UTC(),
	}, nil
}

func (r *servingOCIRuntime) Running(context.Context, string) (bool, error) { return true, nil }

func (r *servingOCIRuntime) Stop(_ context.Context, instanceID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stops = append(r.stops, instanceID)
	return nil
}

// A scheduler-signed deployment.v4 ticket, sent as the typed
// subnet-synapse.v3 JSON payload, travels through the real bridge handler,
// the agent's bound verification and the organic OCI path to a miner-signed
// ready receipt v4 that the scheduler's acceptance checks admit. Status,
// replay and deactivation then operate on the same v4 incarnation.
func TestOrganicAssignReachesVerifiedReadyReceiptV4(t *testing.T) {
	ctx := context.Background()
	const (
		validatorHotkey = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
		minerHotkey     = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
		routeLabel      = "hello-world-k3j9x0q2ab"
		marker          = "organic-ready"
	)
	image, err := ocitest.Build(ocitest.Spec{
		Layers: []map[string]ocitest.File{{"app": {Mode: 0o755, Body: []byte("binary")}}}, Entrypoint: []string{"/app"}, Gzip: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	artifacts := artifact.FileStore{Root: t.TempDir()}
	if err := image.Publish(ctx, artifacts); err != nil {
		t.Fatal(err)
	}
	var probedHost string
	var probeMu sync.Mutex
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet || req.URL.Path != "/healthz" {
			http.NotFound(w, req)
			return
		}
		probeMu.Lock()
		probedHost = req.Host
		probeMu.Unlock()
		_, _ = w.Write([]byte(marker))
	}))
	defer app.Close()

	validatorPublic, validatorPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	minerPublic, minerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uid := uint16(17)
	now := time.Now().UTC()
	responseMarker := marker
	ticket := protocol.TicketV4{
		Version: protocol.OrganicVersion, DeploymentID: routeLabel, Generation: 1,
		ImageDigest: image.ArtifactDigest, ManifestKey: organic.ManifestKey(image.ArtifactDigest),
		MinerID: minerHotkey, RouteHost: organic.RouteHost(routeLabel), AssignmentNonce: "c0634d1e9b2f4a7788d1e0f5a6b7c8d9",
		Workload: protocol.WorkloadV4{
			Kind: organic.WorkloadKind, ContainerPort: 8080, RuntimeProfile: organic.RuntimeProfile,
			Env: protocol.WorkloadEnvV4{Host: "0.0.0.0", Port: "8080"},
		},
		Resources: organic.SmallV1,
		Health: organic.TicketHealth{
			HealthPredicate: organic.HealthPredicate{
				Method: http.MethodGet, Path: "/healthz", ExpectedStatuses: []int{http.StatusOK}, ResponseMarker: &responseMarker,
				SuccessesRequired: 1, IntervalMillis: 500, ProbeTimeoutMillis: 1000, StartupTimeoutMillis: 5000,
			},
			FailureThreshold: organic.HealthFailureThreshold,
		},
		IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(5 * time.Minute),
		Subnet: &protocol.SubnetBinding{
			Network: "mock", NetUID: 24, ValidatorHotkey: validatorHotkey, MinerHotkey: minerHotkey, MinerUID: &uid,
			MinerAxonURL: "http://127.0.0.1:8091", MinerTransport: neuron.TransportHTTP, ChainBlock: 100, Epoch: 1, ExpiresAtBlock: 112,
			ValidatorServicePublicKey: hex.EncodeToString(validatorPublic), MinerServicePublicKey: hex.EncodeToString(minerPublic),
		},
	}
	if err := protocol.SignTicketV4(&ticket, validatorPrivate); err != nil {
		t.Fatal(err)
	}
	assignBody, err := json.Marshal(neuron.LocalAssignRequestV3{
		Protocol: neuron.OrganicSynapseVersion, RequestID: "assign-1", CurrentBlock: 101, CallerHotkey: validatorHotkey,
		BindingVerified: true, Ticket: ticket,
		ValidatorBinding: neuron.ServiceKeyBinding{
			Protocol: neuron.ServiceBindingVersion, Role: "validator", Network: "mock", NetUID: 24, Hotkey: validatorHotkey,
			ServicePublicKey: hex.EncodeToString(validatorPublic), Transport: neuron.TransportLocal, Generation: 1,
			ValidFromBlock: 100, ExpiresAtBlock: 200,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	state, err := durable.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	runtime := &servingOCIRuntime{url: app.URL}
	agent := miner.NewAgent(minerHotkey, nil, minerPrivate, artifacts, nil, tunnel.NewLocalRegistry())
	agent.OCI, agent.State, agent.HTTPClient, agent.MinerTransport = runtime, state, app.Client(), neuron.TransportHTTP
	service := &api{agent: agent, store: state, network: "mock", netuid: 24, hotkey: minerHotkey, uid: &uid, public: minerPublic}

	post := func(handle http.HandlerFunc, path string, body []byte) []byte {
		t.Helper()
		response := httptest.NewRecorder()
		handle(response, httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body)))
		if response.Code != http.StatusOK {
			t.Fatalf("%s returned %d: %s", path, response.Code, response.Body.String())
		}
		return response.Body.Bytes()
	}
	acceptReady := func(raw []byte) neuron.DeployResponseV3 {
		t.Helper()
		var response neuron.DeployResponseV3
		if err := organic.DecodeStrict(raw, &response); err != nil {
			t.Fatalf("deploy response is not a strict subnet-synapse.v3 document: %v\n%s", err, raw)
		}
		receipt := response.Result.Receipt
		// The scheduler's acceptance: miner service-key signature, exact
		// answer to this ticket, and the artifact's config digest loaded.
		if err := protocol.VerifyReceiptV4(receipt, minerPublic); err != nil {
			t.Fatalf("ready receipt signature: %v", err)
		}
		if err := protocol.ReceiptMatchesTicketV4(ticket, receipt, image.Manifest.Config.Digest); err != nil {
			t.Fatalf("ready receipt does not answer the ticket: %v", err)
		}
		if receipt.Stage != protocol.StageReady || receipt.ErrorCode != nil || response.Result.EndpointID != protocol.EndpointIDV4(ticket) {
			t.Fatalf("receipt is not a ready v4 answer: %+v", response.Result)
		}
		return response
	}

	first := acceptReady(post(service.assign, "/v1/assignments", assignBody))
	if first.RequestID != "assign-1" || first.Idempotent {
		t.Fatalf("first assignment response = %+v", first)
	}
	runtime.mu.Lock()
	launches := append([]deployruntime.Launch(nil), runtime.launches...)
	runtime.mu.Unlock()
	if len(launches) != 1 || launches[0].ArtifactDigest != ticket.ImageDigest || launches[0].Workload.ContainerPort != 8080 ||
		launches[0].Profile.Name != deployruntime.SmallV1.Name {
		t.Fatalf("runtime launch = %+v", launches)
	}
	probeMu.Lock()
	if probedHost != ticket.RouteHost {
		t.Fatalf("startup health Host = %q, want the signed route host", probedHost)
	}
	probeMu.Unlock()

	stored, status, found, err := state.AssignmentTicket(ctx, first.Result.EndpointID)
	if err != nil || !found || status != string(protocol.StageReady) {
		t.Fatalf("durable assignment = %q %v %v", status, found, err)
	}
	if storedV4, err := stored.V4(); err != nil || protocol.VerifyTicketV4Signature(storedV4, validatorPublic) != nil {
		t.Fatalf("durable ticket is not the signed v4 ticket: %v", err)
	}

	replay := acceptReady(post(service.assign, "/v1/assignments", assignBody))
	if !replay.Idempotent || replay.Result.Receipt.Signature != first.Result.Receipt.Signature {
		t.Fatalf("exact replay was not the cached ready receipt: %+v", replay)
	}

	statusBody, _ := json.Marshal(neuron.StatusSynapse{
		Protocol: neuron.SynapseVersion, RequestID: "status-1", CurrentBlock: 101, CallerHotkey: validatorHotkey, EndpointID: first.Result.EndpointID,
	})
	var statusResponse neuron.StatusResponseV3
	if err := organic.DecodeStrict(post(service.status, "/v1/status", statusBody), &statusResponse); err != nil {
		t.Fatalf("status response is not a strict subnet-synapse.v3 document: %v", err)
	}
	if statusResponse.Status != "ready" || statusResponse.Receipt == nil || statusResponse.Receipt.Signature != first.Result.Receipt.Signature {
		t.Fatalf("status = %+v", statusResponse)
	}

	deactivateBody, _ := json.Marshal(neuron.DeactivateSynapse{
		Protocol: neuron.SynapseVersion, RequestID: "deactivate-1", CurrentBlock: 101, CallerHotkey: validatorHotkey,
		EndpointID: first.Result.EndpointID, DeploymentID: ticket.DeploymentID,
	})
	post(service.deactivate, "/v1/deactivate", deactivateBody)
	runtime.mu.Lock()
	stops := len(runtime.stops)
	runtime.mu.Unlock()
	if stops == 0 {
		t.Fatal("deactivating the v4 endpoint did not stop its runtime")
	}
}
