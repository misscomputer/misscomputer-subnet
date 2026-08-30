// SPDX-License-Identifier: AGPL-3.0-only

package durable

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/edge"
	"github.com/misscomputer/misscomputer-subnet/pkg/tunnel"
)

func TestEdgeRouteRestartQuarantinesInsteadOfRepublishing(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "edge.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	record := edge.RouteRecord{
		EndpointID: "app-miner-g1-nonce", DeploymentID: "app", Generation: 1, MinerID: "miner",
		ReplicaID: "app-miner", RouteHost: "edge-dev-app.miss.computer", State: "pending",
		TicketJSON: []byte(`{"exact":"ticket"}`), ReceiptJSON: []byte(`{"exact":"receipt"}`),
	}
	if err := store.PutEdgeRoute(ctx, record); err != nil {
		t.Fatal(err)
	}
	active := record
	active.State = "active"
	if err := store.ActivateEdgeRoute(ctx, active); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	router, err := edge.NewAuthorizedRouter(tunnel.NewLocalRegistry(), "probe", edge.RouterConfig{
		AuthorityKey: public, Store: reopened, Domain: "miss.computer", HostLabelPrefix: "edge-dev-", AllowPrivateUpstreams: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	persisted, found, err := reopened.EdgeRoute(ctx, record.EndpointID)
	if err != nil || !found {
		t.Fatalf("persisted route found=%v err=%v", found, err)
	}
	if persisted.State != "quarantined" {
		t.Fatalf("restart state = %q", persisted.State)
	}
	if replicas := router.Replicas(record.RouteHost); len(replicas) != 0 {
		t.Fatalf("restart republished stale routes: %+v", replicas)
	}
}

func TestEdgeRoutePersistenceRejectsTombstoneAndGenerationRollback(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "edge.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	newer := edge.RouteRecord{
		EndpointID: "app-miner-g2-new", DeploymentID: "app", Generation: 2, MinerID: "miner", ReplicaID: "app-miner",
		RouteHost: "edge-dev-app.miss.computer", State: "deactivated", TicketJSON: []byte(`{"generation":2}`),
	}
	if err := store.DeactivateEdgeRoute(ctx, newer); err != nil {
		t.Fatal(err)
	}
	resurrect := newer
	resurrect.State = "pending"
	resurrect.ReceiptJSON = []byte(`{"ready":true}`)
	if err := store.PutEdgeRoute(ctx, resurrect); err == nil {
		t.Fatal("deactivated exact incarnation was republished")
	}
	stale := edge.RouteRecord{
		EndpointID: "app-miner-g1-old", DeploymentID: "app", Generation: 1, MinerID: "miner", ReplicaID: "app-miner",
		RouteHost: "edge-dev-app.miss.computer", State: "pending", TicketJSON: []byte(`{"generation":1}`), ReceiptJSON: []byte(`{"ready":true}`),
	}
	if err := store.PutEdgeRoute(ctx, stale); !errors.Is(err, edge.ErrStaleRoute) {
		t.Fatalf("generation rollback error = %v", err)
	}
}

func TestHighestEdgeGenerationSpansMinersAndStates(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "edge.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if got, err := store.HighestEdgeGeneration(ctx, "app"); err != nil || got != 0 {
		t.Fatalf("unknown deployment generation=%d err=%v", got, err)
	}
	for _, record := range []edge.RouteRecord{
		{EndpointID: "app-a-g1-n1", DeploymentID: "app", Generation: 1, MinerID: "miner-a", ReplicaID: "app-a", RouteHost: "edge-dev-app.miss.computer", State: "deactivated", TicketJSON: []byte(`{"g":1}`)},
		{EndpointID: "app-b-g3-n2", DeploymentID: "app", Generation: 3, MinerID: "miner-b", ReplicaID: "app-b", RouteHost: "edge-dev-app.miss.computer", State: "deactivated", TicketJSON: []byte(`{"g":3}`)},
		{EndpointID: "other-a-g9-n3", DeploymentID: "other", Generation: 9, MinerID: "miner-a", ReplicaID: "other-a", RouteHost: "edge-dev-other.miss.computer", State: "deactivated", TicketJSON: []byte(`{"g":9}`)},
	} {
		if err := store.DeactivateEdgeRoute(ctx, record); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := store.HighestEdgeGeneration(ctx, "app"); err != nil || got != 3 {
		t.Fatalf("deployment-wide generation=%d err=%v", got, err)
	}
	if got, err := store.HighestEdgeGeneration(ctx, "other"); err != nil || got != 9 {
		t.Fatalf("isolated deployment generation=%d err=%v", got, err)
	}
}

func TestAtomicEdgeTransitionRollsBackReplayOnPersistenceFailure(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "edge.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	record := edge.RouteRecord{
		EndpointID: "retry-miner-g1-nonce", DeploymentID: "retry", Generation: 1, MinerID: "miner", ReplicaID: "retry-miner",
		RouteHost: "edge-dev-retry.miss.computer", State: "pending", TicketJSON: []byte(`{"generation":1}`), ReceiptJSON: []byte(`{"ready":true}`),
	}
	if _, err := store.db.ExecContext(ctx, `CREATE TRIGGER fail_edge_route BEFORE INSERT ON edge_routes BEGIN SELECT RAISE(ABORT, 'forced transition failure'); END`); err != nil {
		t.Fatal(err)
	}
	expiresAt := time.Now().UTC().Add(time.Minute)
	committed, err := store.ApplyEdgeRouteTransition(ctx, "edge-route-update", "retry-key", expiresAt, record)
	if err == nil || committed {
		t.Fatalf("forced transition failure committed=%v err=%v", committed, err)
	}
	var replayCount, routeCount int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM replay_keys WHERE scope='edge-route-update' AND replay_key='retry-key'`).Scan(&replayCount); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM edge_routes WHERE endpoint_id=?`, record.EndpointID).Scan(&routeCount); err != nil {
		t.Fatal(err)
	}
	if replayCount != 0 || routeCount != 0 {
		t.Fatalf("failed atomic transition leaked state: replay=%d route=%d", replayCount, routeCount)
	}
	if _, err := store.db.ExecContext(ctx, `DROP TRIGGER fail_edge_route`); err != nil {
		t.Fatal(err)
	}
	committed, err = store.ApplyEdgeRouteTransition(ctx, "edge-route-update", "retry-key", expiresAt, record)
	if err != nil || !committed {
		t.Fatalf("retry after transient transition failure committed=%v err=%v", committed, err)
	}
	if committed, err = store.ApplyEdgeRouteTransition(ctx, "edge-route-update", "retry-key", expiresAt, record); err != nil || committed {
		t.Fatalf("replay after successful transition committed=%v err=%v", committed, err)
	}
}

func TestAtomicEdgeTransitionValidationFailureIsRetryable(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "edge.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	pending := edge.RouteRecord{
		EndpointID: "activate-miner-g1-nonce", DeploymentID: "activate", Generation: 1, MinerID: "miner", ReplicaID: "activate-miner",
		RouteHost: "edge-dev-activate.miss.computer", State: "pending", TicketJSON: []byte(`{"generation":1}`), ReceiptJSON: []byte(`{"ready":true}`),
	}
	active := pending
	active.State = "active"
	expiresAt := time.Now().UTC().Add(time.Minute)
	committed, err := store.ApplyEdgeRouteTransition(ctx, "edge-route-update", "activate-key", expiresAt, active)
	if err == nil || committed {
		t.Fatalf("activation without pending route committed=%v err=%v", committed, err)
	}
	var replayCount int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM replay_keys WHERE scope='edge-route-update' AND replay_key='activate-key'`).Scan(&replayCount); err != nil {
		t.Fatal(err)
	}
	if replayCount != 0 {
		t.Fatalf("failed transition consumed replay key: %d", replayCount)
	}
	if err := store.PutEdgeRoute(ctx, pending); err != nil {
		t.Fatal(err)
	}
	committed, err = store.ApplyEdgeRouteTransition(ctx, "edge-route-update", "activate-key", expiresAt, active)
	if err != nil || !committed {
		t.Fatalf("valid retry after transition prerequisite committed=%v err=%v", committed, err)
	}
}

func TestAtomicEdgeTransitionConcurrentReplayHasOneWinner(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "edge.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	record := edge.RouteRecord{
		EndpointID: "concurrent-miner-g1-nonce", DeploymentID: "concurrent", Generation: 1, MinerID: "miner", ReplicaID: "concurrent-miner",
		RouteHost: "edge-dev-concurrent.miss.computer", State: "pending", TicketJSON: []byte(`{"generation":1}`), ReceiptJSON: []byte(`{"ready":true}`),
	}
	const contenders = 24
	start := make(chan struct{})
	results := make(chan struct {
		committed bool
		err       error
	}, contenders)
	var workers sync.WaitGroup
	for range contenders {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			committed, err := store.ApplyEdgeRouteTransition(context.Background(), "edge-route-update", "concurrent-key", time.Now().UTC().Add(time.Minute), record)
			results <- struct {
				committed bool
				err       error
			}{committed: committed, err: err}
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	winners := 0
	for result := range results {
		if result.err != nil {
			t.Fatalf("concurrent atomic transition error: %v", result.err)
		}
		if result.committed {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("concurrent atomic transition winners = %d", winners)
	}
}
