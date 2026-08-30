// SPDX-License-Identifier: AGPL-3.0-only

package control_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
	"github.com/misscomputer/misscomputer-subnet/pkg/control"
	"github.com/misscomputer/misscomputer-subnet/pkg/durable"
	"github.com/misscomputer/misscomputer-subnet/pkg/edge"
	"github.com/misscomputer/misscomputer-subnet/pkg/ledger"
	"github.com/misscomputer/misscomputer-subnet/pkg/miner"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	"github.com/misscomputer/misscomputer-subnet/pkg/remote"
	deployruntime "github.com/misscomputer/misscomputer-subnet/pkg/runtime"
	"github.com/misscomputer/misscomputer-subnet/pkg/tunnel"
	"github.com/misscomputer/misscomputer-subnet/pkg/workload"
)

type forwardingSlowRuntime struct {
	instance deployruntime.Instance
	started  chan struct{}
	release  chan struct{}
	mu       sync.Mutex
	active   bool
	stops    int
}

type forwardingAssignRequest struct {
	RequestID string          `json:"request_id"`
	Ticket    protocol.Ticket `json:"ticket"`
}

type forwardingDeployResponse struct {
	Protocol  string       `json:"protocol"`
	RequestID string       `json:"request_id"`
	Result    miner.Result `json:"result"`
}

type forwardingDeactivateRequest struct {
	RequestID  string `json:"request_id"`
	EndpointID string `json:"endpoint_id"`
}

type forwardingDeactivateResponse struct {
	Protocol  string `json:"protocol"`
	RequestID string `json:"request_id"`
	Status    string `json:"status"`
}

func (r *forwardingSlowRuntime) Deploy(_ context.Context, ticket protocol.Ticket, _ artifact.Manifest, _ [][]byte) (deployruntime.Instance, error) {
	close(r.started)
	<-r.release
	r.mu.Lock()
	r.active = true
	r.instance.ID = deployruntime.InstanceName(protocol.EndpointID(ticket))
	instance := r.instance
	r.mu.Unlock()
	return instance, nil
}

func (r *forwardingSlowRuntime) Stop(context.Context, string) error {
	r.mu.Lock()
	r.active = false
	r.stops++
	r.mu.Unlock()
	return nil
}

func TestSchedulerCancellationAcrossForwardingBoundaryCannotStrandMinerRuntime(t *testing.T) {
	validatorPublic, validatorPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	minerPublic, minerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(t.TempDir(), "forwarded-miner.db")
	state, err := durable.Open(statePath)
	if err != nil {
		t.Fatal(err)
	}
	store := artifact.FileStore{Root: t.TempDir()}
	spec, layer, err := workload.Generate("static", 1024)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := artifact.Publish(context.Background(), store, spec.Kind, [][]byte{layer}, nil)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &forwardingSlowRuntime{
		instance: deployruntime.Instance{ID: "slow-runtime", URL: "http://127.0.0.1:1"},
		started:  make(chan struct{}), release: make(chan struct{}),
	}
	agent := miner.NewAgent("forwarded-miner", validatorPublic, minerPrivate, store, runtime, tunnel.NewLocalRegistry())
	agent.State = state
	forwardingDone := make(chan struct{})
	forwarder := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case strings.HasSuffix(req.URL.Path, "/deploy"):
			defer close(forwardingDone)
			var input forwardingAssignRequest
			if err := json.NewDecoder(req.Body).Decode(&input); err != nil {
				t.Errorf("decode forwarded assignment: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			// Model Python forwarding that owns its bounded miner operation even
			// after the Go client disconnects. Independent deactivation must fence
			// the exact assignment before this late runtime can become active.
			result, assignErr := agent.Assign(context.Background(), input.Ticket)
			if assignErr != nil {
				w.WriteHeader(http.StatusUnprocessableEntity)
				return
			}
			_ = json.NewEncoder(w).Encode(forwardingDeployResponse{
				Protocol: "subnet-synapse.v2", RequestID: input.RequestID, Result: result,
			})
		case strings.HasSuffix(req.URL.Path, "/deactivate"):
			var input forwardingDeactivateRequest
			if err := json.NewDecoder(req.Body).Decode(&input); err != nil {
				t.Errorf("decode forwarded deactivation: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if err := agent.Deactivate(context.Background(), input.EndpointID); err != nil {
				t.Errorf("forward deactivation: %v", err)
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			_ = json.NewEncoder(w).Encode(forwardingDeactivateResponse{
				Protocol: "subnet-synapse.v2", RequestID: input.RequestID, Status: "deactivated",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer forwarder.Close()
	assigner := &remote.Assigner{
		MinerHotkey: "forwarded-miner", ServiceKey: minerPublic, BridgeURL: forwarder.URL,
		Secret: []byte("forwarding-boundary-secret-32-bytes"), Client: forwarder.Client(), Retries: 0,
	}
	router, err := edge.NewAuthorizedRouter(tunnel.NewLocalRegistry(), "probe", edge.RouterConfig{
		AuthorityKey: validatorPublic, Domain: "on.miss.computer", AllowPrivateUpstreams: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	scheduler := &control.Scheduler{
		SigningKey: validatorPrivate, Miners: []miner.Assigner{assigner}, Router: router,
		Ledger: ledger.New(), Replicas: 1,
	}
	request := control.DeployRequest{
		DeploymentID: "forward-cancel", Manifest: manifest,
		ManifestKey: artifact.ManifestKey(manifest.ImageDigest), Workload: spec,
		Timeout: 30 * time.Millisecond,
	}
	deployDone := make(chan error, 1)
	go func() {
		_, deployErr := scheduler.Deploy(context.Background(), request)
		deployDone <- deployErr
	}()
	<-runtime.started
	if deployErr := <-deployDone; deployErr == nil {
		t.Fatal("cancelled forwarded deployment succeeded")
	}
	close(runtime.release)
	select {
	case <-forwardingDone:
	case <-time.After(time.Second):
		t.Fatal("detached forwarding task did not finish")
	}
	runtime.mu.Lock()
	active, stops := runtime.active, runtime.stops
	runtime.mu.Unlock()
	if active || stops < 1 {
		t.Fatalf("forwarded late runtime active=%t stops=%d", active, stops)
	}
	if endpoints, err := state.ActiveEndpoints(context.Background()); err != nil || len(endpoints) != 0 {
		t.Fatalf("durable state retained forwarded runtime: %+v err=%v", endpoints, err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := durable.Open(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if endpoints, err := reopened.ActiveEndpoints(context.Background()); err != nil || len(endpoints) != 0 {
		t.Fatalf("restart recovered a stranded forwarded runtime: %+v err=%v", endpoints, err)
	}
}
