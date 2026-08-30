// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
	"github.com/misscomputer/misscomputer-subnet/pkg/durable"
	"github.com/misscomputer/misscomputer-subnet/pkg/edge"
	"github.com/misscomputer/misscomputer-subnet/pkg/ledger"
	"github.com/misscomputer/misscomputer-subnet/pkg/miner"
	deployruntime "github.com/misscomputer/misscomputer-subnet/pkg/runtime"
	"github.com/misscomputer/misscomputer-subnet/pkg/tunnel"
	"github.com/misscomputer/misscomputer-subnet/pkg/validator"
	"github.com/misscomputer/misscomputer-subnet/pkg/workload"
)

func assertGenerationSuffix(t *testing.T, replicas []edge.Replica, marker string) {
	t.Helper()
	if len(replicas) == 0 {
		t.Fatal("no routed replicas to inspect")
	}
	for _, replica := range replicas {
		if !strings.Contains(replica.EndpointID, marker) {
			t.Fatalf("endpoint %q does not carry expected generation marker %q", replica.EndpointID, marker)
		}
	}
}

// EDGE-AUDIT-F1 regression: a deployment ID that was cleanly deactivated must
// be redeployable with the same miners. The route authority keeps a monotonic
// per-(deployment,miner) generation high-water mark, so a new incarnation has
// to continue the generation sequence instead of restarting at one.
func TestRedeployAfterCleanDeactivationReusesMiners(t *testing.T) {
	h := newSchedulerHarness(t, []string{"m1", "m2", "m3"}, 3)
	first, err := h.scheduler.Deploy(context.Background(), h.request)
	if err != nil {
		t.Fatalf("first deploy: %v", err)
	}
	if len(first.ReadyMiners) != 3 {
		t.Fatalf("first deploy ready miners: %+v", first)
	}
	assertGenerationSuffix(t, h.scheduler.Router.Replicas("regression.on.miss.computer"), "-g1-")
	h.cleanup(t)

	second, err := h.scheduler.Deploy(context.Background(), h.request)
	if err != nil {
		t.Fatalf("redeploy after clean deactivation: %v", err)
	}
	defer h.cleanup(t)
	if len(second.ReadyMiners) != 3 {
		t.Fatalf("redeploy ready miners: %+v", second)
	}
	replicas := h.scheduler.Router.Replicas("regression.on.miss.computer")
	if len(replicas) != 3 {
		t.Fatalf("redeploy routed %d replicas: %+v", len(replicas), replicas)
	}
	// The new incarnation must not reuse a previously consumed generation, or
	// the stale-generation and duplicate-generation replay protections would
	// have to be weakened to admit it.
	assertGenerationSuffix(t, replicas, "-g2-")
}

type durableControlPlane struct {
	scheduler *Scheduler
	store     *durable.Store
	closeFns  []func()
}

func (p *durableControlPlane) close() {
	for index := len(p.closeFns) - 1; index >= 0; index-- {
		p.closeFns[index]()
	}
}

func bootDurableControlPlane(t *testing.T, dbPath string, ownerPrivate ed25519.PrivateKey, artifacts artifact.FileStore) *durableControlPlane {
	t.Helper()
	store, err := durable.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	assignmentLedger, err := ledger.NewDurable(store)
	if err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	tunnels := tunnel.NewLocalRegistry()
	probeToken := "durable-redeploy-probe"
	ownerPublic := ownerPrivate.Public().(ed25519.PublicKey)
	router, err := edge.NewAuthorizedRouter(tunnels, probeToken, edge.RouterConfig{
		AuthorityKey: ownerPublic, Store: store, Domain: "on.miss.computer", AllowPrivateUpstreams: true,
	})
	if err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	edgeServer := httptest.NewServer(router)
	assigners := make([]miner.Assigner, 0, 3)
	for _, id := range []string{"m1", "m2", "m3"} {
		_, signingKey, keyErr := ed25519.GenerateKey(rand.Reader)
		if keyErr != nil {
			edgeServer.Close()
			_ = store.Close()
			t.Fatal(keyErr)
		}
		assigners = append(assigners, miner.NewAgent(id, ownerPublic, signingKey, artifacts, deployruntime.NewLocalRuntime(), tunnels))
	}
	scheduler := &Scheduler{
		SigningKey: ownerPrivate, Miners: assigners, Router: router, Ledger: assignmentLedger, Replicas: 3, Domain: "on.miss.computer",
		Validator: validator.Validator{Vantage: "test", EdgeURL: edgeServer.URL, InternalProbeToken: probeToken},
	}
	return &durableControlPlane{
		scheduler: scheduler, store: store,
		closeFns: []func(){func() { _ = store.Close() }, edgeServer.Close},
	}
}

// EDGE-AUDIT-F1 regression, durable restart variant: the persisted per-miner
// generation high-water mark survives a control-plane restart, so a restarted
// authority must also continue the sequence when the same deployment ID is
// redeployed after clean deactivation.
func TestRedeployAfterRestartWithDurableStateContinuesGenerations(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "redeploy-state.db")
	_, ownerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	artifacts := artifact.FileStore{Root: t.TempDir()}
	spec, layer, err := workload.Generate("static", 1024)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := artifact.Publish(ctx, artifacts, spec.Kind, [][]byte{[]byte("base"), layer}, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := DeployRequest{
		DeploymentID: "redeploy", Manifest: manifest, ManifestKey: artifact.ManifestKey(manifest.ImageDigest),
		Workload: spec, Timeout: 5 * time.Second,
	}

	first := bootDurableControlPlane(t, dbPath, ownerPrivate, artifacts)
	result, err := first.scheduler.Deploy(ctx, request)
	if err != nil {
		first.close()
		t.Fatalf("first durable deploy: %v", err)
	}
	if len(result.ReadyMiners) != 3 {
		first.close()
		t.Fatalf("first durable deploy ready miners: %+v", result)
	}
	deactivateCtx, cancel := context.WithTimeout(ctx, time.Second)
	err = first.scheduler.DeactivateDeployment(deactivateCtx, request.DeploymentID)
	cancel()
	if err != nil {
		first.close()
		t.Fatalf("deactivate before restart: %v", err)
	}
	first.close()

	second := bootDurableControlPlane(t, dbPath, ownerPrivate, artifacts)
	defer second.close()
	result, err = second.scheduler.Deploy(ctx, request)
	if err != nil {
		t.Fatalf("redeploy after restart: %v", err)
	}
	if len(result.ReadyMiners) != 3 {
		t.Fatalf("redeploy after restart ready miners: %+v", result)
	}
	assertGenerationSuffix(t, second.scheduler.Router.Replicas("redeploy.on.miss.computer"), "-g2-")
	deactivateCtx, cancel = context.WithTimeout(ctx, time.Second)
	defer cancel()
	if err := second.scheduler.DeactivateDeployment(deactivateCtx, request.DeploymentID); err != nil {
		t.Fatal(err)
	}
}
