// SPDX-License-Identifier: AGPL-3.0-only

package durable

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
)

// deployment.v4 assignments share the assignments table and every endpoint
// lifecycle rule with v3: the row identity, owner fences and deactivation
// semantics are version independent. Only the stored ticket and receipt
// documents differ.

// SaveAssignmentV4 records an exact deployment.v4 ticket for its endpoint.
func (s *Store) SaveAssignmentV4(ctx context.Context, ticket protocol.TicketV4, status string) error {
	payload, err := json.Marshal(ticket)
	if err != nil {
		return err
	}
	validatorHotkey := ""
	if ticket.Subnet != nil {
		validatorHotkey = ticket.Subnet.ValidatorHotkey
	}
	return s.saveAssignment(ctx, payload, assignmentIdentity{
		endpointID: protocol.EndpointIDV4(ticket), deploymentID: ticket.DeploymentID, minerID: ticket.MinerID,
		nonce: ticket.AssignmentNonce, generation: ticket.Generation, validatorHotkey: validatorHotkey,
	}, status)
}

// SaveReceiptV4 stores a signed deployment.v4 receipt for its endpoint.
func (s *Store) SaveReceiptV4(ctx context.Context, receipt protocol.ReceiptV4) error {
	payload, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	return s.saveReceipt(ctx, payload, receipt.EndpointID, string(receipt.Stage))
}

// CachedResultV4 returns the receipt of an active deployment.v4 endpoint.
func (s *Store) CachedResultV4(ctx context.Context, endpointID string) (protocol.ReceiptV4, bool, error) {
	payload, found, err := s.cachedReceipt(ctx, endpointID)
	if err != nil || !found {
		return protocol.ReceiptV4{}, false, err
	}
	var receipt protocol.ReceiptV4
	if err := json.Unmarshal(payload, &receipt); err != nil {
		return protocol.ReceiptV4{}, false, err
	}
	return receipt, true, nil
}

// StoredReceiptV4 returns the latest receipt of a deployment.v4 assignment
// regardless of endpoint activity (status reporting of failed attempts).
func (s *Store) StoredReceiptV4(ctx context.Context, endpointID string) (protocol.ReceiptV4, bool, error) {
	var payload []byte
	err := s.db.QueryRowContext(ctx, `SELECT receipt_json FROM assignments WHERE endpoint_id=? AND receipt_json IS NOT NULL`, endpointID).Scan(&payload)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return protocol.ReceiptV4{}, false, nil
		}
		return protocol.ReceiptV4{}, false, err
	}
	var receipt protocol.ReceiptV4
	if err := json.Unmarshal(payload, &receipt); err != nil {
		return protocol.ReceiptV4{}, false, err
	}
	return receipt, true, nil
}

// AssignmentTicketV4 returns the exact stored deployment.v4 ticket; found is
// false for an absent row or a row holding another ticket version.
func (s *Store) AssignmentTicketV4(ctx context.Context, endpointID string) (protocol.TicketV4, string, bool, error) {
	payload, status, found, err := s.assignmentPayload(ctx, endpointID)
	if err != nil || !found {
		return protocol.TicketV4{}, "", false, err
	}
	var version struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(payload, &version); err != nil {
		return protocol.TicketV4{}, "", false, err
	}
	if version.Version != protocol.OrganicVersion {
		return protocol.TicketV4{}, "", false, nil
	}
	var ticket protocol.TicketV4
	if err := json.Unmarshal(payload, &ticket); err != nil {
		return protocol.TicketV4{}, "", false, err
	}
	return ticket, status, true, nil
}
