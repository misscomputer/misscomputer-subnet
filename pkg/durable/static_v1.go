// SPDX-License-Identifier: AGPL-3.0-only

package durable

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
)

// Static assignments live in their own table. The deployment.v4 assignments
// table, its decoders and its recovery queries never see a static ticket, so
// the dynamic lifecycle is unchanged. Both kinds share the one-time
// "assignment" nonce scope and the kind-neutral endpoint deactivation fences.
func init() {
	schemaExtensions = append(schemaExtensions, `
CREATE TABLE IF NOT EXISTS static_assignments (
  endpoint_id TEXT PRIMARY KEY,
  deployment_id TEXT NOT NULL,
  miner_hotkey TEXT NOT NULL,
  validator_hotkey TEXT NOT NULL,
  assignment_nonce TEXT NOT NULL UNIQUE,
  generation INTEGER NOT NULL,
  status TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 0,
  ticket_json BLOB NOT NULL,
  receipt_json BLOB,
  updated_at_ns INTEGER NOT NULL
);`)
}

// StaticRecord is one durable static assignment.
type StaticRecord struct {
	Ticket  protocol.StaticTicketV1
	Receipt *protocol.StaticReceiptV1
	Status  string
	// Active is true only between a persisted ready receipt and deactivation.
	Active bool
}

func staticValidator(ticket protocol.StaticTicketV1) string {
	if ticket.Subnet == nil {
		return ""
	}
	return ticket.Subnet.ValidatorHotkey
}

// SaveStaticAssignment records an exact static ticket for its endpoint. A
// deactivation fence recorded first wins: the row is kept as deactivated and
// ErrEndpointDeactivated is returned.
func (s *Store) SaveStaticAssignment(ctx context.Context, ticket protocol.StaticTicketV1, status string) error {
	payload, err := json.Marshal(ticket)
	if err != nil {
		return err
	}
	endpointID := protocol.StaticEndpointIDV1(ticket)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var dynamic int
	switch err := tx.QueryRowContext(ctx, `SELECT 1 FROM assignments WHERE endpoint_id=?`, endpointID).Scan(&dynamic); {
	case err == nil:
		return fmt.Errorf("endpoint %q is already a dynamic assignment", endpointID)
	case !errors.Is(err, sql.ErrNoRows):
		return err
	}
	fenced, err := endpointFencedTx(ctx, tx, endpointID, ticket.DeploymentID, ticket.MinerID, staticValidator(ticket))
	if err != nil {
		return err
	}
	now := time.Now().UTC().UnixNano()
	var existing []byte
	var existingStatus string
	err = tx.QueryRowContext(ctx, `SELECT ticket_json,status FROM static_assignments WHERE endpoint_id=?`, endpointID).Scan(&existing, &existingStatus)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if fenced {
			status = "deactivated"
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO static_assignments(endpoint_id,deployment_id,miner_hotkey,validator_hotkey,assignment_nonce,generation,status,active,ticket_json,updated_at_ns)
VALUES(?,?,?,?,?,?,?,0,?,?)`, endpointID, ticket.DeploymentID, ticket.MinerID, staticValidator(ticket), ticket.AssignmentNonce, ticket.Generation, status, payload, now)
	case err != nil:
		return err
	case !bytes.Equal(existing, payload):
		return fmt.Errorf("static endpoint %q conflicts with another exact ticket", endpointID)
	case existingStatus == "deactivated" || fenced:
		fenced = true
		_, err = tx.ExecContext(ctx, `UPDATE static_assignments SET status='deactivated',active=0,updated_at_ns=? WHERE endpoint_id=?`, now, endpointID)
	default:
		_, err = tx.ExecContext(ctx, `UPDATE static_assignments SET status=?,updated_at_ns=? WHERE endpoint_id=?`, status, now, endpointID)
	}
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if fenced {
		return ErrEndpointDeactivated
	}
	return nil
}

// SaveStaticReceipt stores a signed receipt. Activation (a ready receipt the
// miner will serve) fails with ErrEndpointDeactivated when a fence or a
// deactivation already won; the receipt is still retained for audit.
func (s *Store) SaveStaticReceipt(ctx context.Context, receipt protocol.StaticReceiptV1, activate bool) error {
	payload, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var deploymentID, minerHotkey, validatorHotkey, status string
	if err := tx.QueryRowContext(ctx, `SELECT deployment_id,miner_hotkey,validator_hotkey,status FROM static_assignments WHERE endpoint_id=?`, receipt.EndpointID).Scan(
		&deploymentID, &minerHotkey, &validatorHotkey, &status,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("static receipt endpoint %q has no durable assignment", receipt.EndpointID)
		}
		return err
	}
	fenced, err := endpointFencedTx(ctx, tx, receipt.EndpointID, deploymentID, minerHotkey, validatorHotkey)
	if err != nil {
		return err
	}
	deactivated := fenced || status == "deactivated"
	active := 0
	if activate && !deactivated {
		active = 1
	}
	if deactivated {
		status = "deactivated"
	} else {
		status = string(receipt.Stage)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE static_assignments SET status=?,active=?,receipt_json=?,updated_at_ns=? WHERE endpoint_id=?`,
		status, active, payload, time.Now().UTC().UnixNano(), receipt.EndpointID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if activate && deactivated {
		return ErrEndpointDeactivated
	}
	return nil
}

// StaticAssignment returns the durable static record of endpointID.
func (s *Store) StaticAssignment(ctx context.Context, endpointID string) (StaticRecord, bool, error) {
	record, err := scanStatic(s.db.QueryRowContext(ctx, `SELECT ticket_json,receipt_json,status,active FROM static_assignments WHERE endpoint_id=?`, endpointID))
	if errors.Is(err, sql.ErrNoRows) {
		return StaticRecord{}, false, nil
	}
	return record, err == nil, err
}

// StaticAssignmentsToRecover lists every static endpoint not yet completely
// deactivated. Pins do not survive a restart, so recovery retires them all.
func (s *Store) StaticAssignmentsToRecover(ctx context.Context) ([]StaticRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT ticket_json,receipt_json,status,active FROM static_assignments WHERE status!='deactivated' OR active=1 ORDER BY endpoint_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []StaticRecord
	for rows.Next() {
		record, err := scanStatic(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

// CompleteStaticDeactivation marks a static endpoint deactivated and not
// servable. The caller has already fenced it and dropped its pin.
func (s *Store) CompleteStaticDeactivation(ctx context.Context, endpointID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE static_assignments SET status='deactivated',active=0,updated_at_ns=? WHERE endpoint_id=?`,
		time.Now().UTC().UnixNano(), endpointID)
	return err
}

type rowScanner interface{ Scan(...any) error }

func scanStatic(row rowScanner) (StaticRecord, error) {
	var ticketJSON, receiptJSON []byte
	var record StaticRecord
	if err := row.Scan(&ticketJSON, &receiptJSON, &record.Status, &record.Active); err != nil {
		return StaticRecord{}, err
	}
	if err := json.Unmarshal(ticketJSON, &record.Ticket); err != nil {
		return StaticRecord{}, fmt.Errorf("decode static ticket: %w", err)
	}
	if receiptJSON != nil {
		var receipt protocol.StaticReceiptV1
		if err := json.Unmarshal(receiptJSON, &receipt); err != nil {
			return StaticRecord{}, fmt.Errorf("decode static receipt: %w", err)
		}
		record.Receipt = &receipt
	}
	return record, nil
}
