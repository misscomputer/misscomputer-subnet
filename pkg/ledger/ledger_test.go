// SPDX-License-Identifier: AGPL-3.0-only

package ledger

import (
	"context"
	"database/sql"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/durable"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
)

func TestTrustEligibilityDefaultsAndConcurrentReads(t *testing.T) {
	ledger := New()
	if got := ledger.Trust("new-miner"); got != DefaultTrust || !ledger.Eligible("new-miner") {
		t.Fatalf("new miner trust=%v eligible=%v", got, ledger.Eligible("new-miner"))
	}
	if err := ledger.SetTrust("zeroed", 0); err != nil {
		t.Fatal(err)
	}
	if ledger.Eligible("zeroed") {
		t.Fatal("trust-zero miner is eligible")
	}
	var wait sync.WaitGroup
	for i := 0; i < 20; i++ {
		wait.Add(2)
		go func(value float64) {
			defer wait.Done()
			_ = ledger.SetTrust("raced", value)
		}(float64(i % 2))
		go func() {
			defer wait.Done()
			_ = ledger.Trust("raced")
			_ = ledger.Eligible("raced")
		}()
	}
	wait.Wait()
}

func TestReceiptPersistenceErrorIsScopedAndRecovers(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	store, err := durable.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	values, err := NewDurable(store)
	if err != nil {
		t.Fatal(err)
	}
	tickets := []protocol.Ticket{
		{DeploymentID: "first", MinerID: "miner-a", Generation: 1, AssignmentNonce: "nonce-a"},
		{DeploymentID: "second", MinerID: "miner-b", Generation: 1, AssignmentNonce: "nonce-b"},
	}
	for _, ticket := range tickets {
		if err := store.SaveAssignment(ctx, ticket, "published"); err != nil {
			t.Fatal(err)
		}
		values.Start(Deployment{ID: ticket.DeploymentID, TicketPublished: time.Now().UTC()})
	}
	receipt := func(ticket protocol.Ticket) protocol.Receipt {
		return protocol.Receipt{
			DeploymentID: ticket.DeploymentID, MinerID: ticket.MinerID,
			EndpointID: protocol.EndpointID(ticket), Stage: protocol.StageReady,
		}
	}

	triggerDB, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer triggerDB.Close()
	if _, err := triggerDB.ExecContext(ctx, `CREATE TRIGGER fail_receipt_update
BEFORE UPDATE OF receipt_json ON assignments
BEGIN
  SELECT RAISE(FAIL, 'transient receipt failure');
END`); err != nil {
		t.Fatal(err)
	}
	if err := values.AddReceipt(receipt(tickets[0])); err == nil {
		t.Fatal("transient durable receipt failure was hidden")
	}
	if snapshot, ok := values.Snapshot(tickets[0].DeploymentID); !ok || len(snapshot.Receipts) != 0 {
		t.Fatalf("failed receipt entered the read model: snapshot=%+v exists=%v", snapshot, ok)
	}
	if _, status, exists, err := store.AssignmentTicket(ctx, protocol.EndpointID(tickets[0])); err != nil || !exists || status != "published" {
		t.Fatalf("failed receipt changed durable assignment: status=%q exists=%v err=%v", status, exists, err)
	}

	if _, err := triggerDB.ExecContext(ctx, `DROP TRIGGER fail_receipt_update`); err != nil {
		t.Fatal(err)
	}
	if err := values.AddReceipt(receipt(tickets[1])); err != nil {
		t.Fatalf("unrelated receipt was poisoned by prior failure: %v", err)
	}
	if snapshot, ok := values.Snapshot(tickets[1].DeploymentID); !ok || len(snapshot.Receipts) != 1 {
		t.Fatalf("unrelated receipt missing from read model: snapshot=%+v exists=%v", snapshot, ok)
	}
	if err := values.AddReceipt(receipt(tickets[0])); err != nil {
		t.Fatalf("retry after transient failure did not recover: %v", err)
	}
	if snapshot, ok := values.Snapshot(tickets[0].DeploymentID); !ok || len(snapshot.Receipts) != 1 {
		t.Fatalf("retried receipt missing from read model: snapshot=%+v exists=%v", snapshot, ok)
	}
}
