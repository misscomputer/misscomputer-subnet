// SPDX-License-Identifier: AGPL-3.0-only

package durable

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/edge"
)

// ApplyEdgeRouteTransition reserves a one-time signed update and changes its
// exact route incarnation in one database transaction. Transition validation
// or persistence failure therefore cannot burn an otherwise retryable update.
func (s *Store) ApplyEdgeRouteTransition(ctx context.Context, scope, replayKey string, expiresAt time.Time, route edge.RouteRecord) (bool, error) {
	if err := validateReplayReservation(scope, replayKey, expiresAt); err != nil {
		return false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	reserved, err := reserveReplayTx(ctx, tx, scope, replayKey, expiresAt)
	if err != nil || !reserved {
		return reserved, err
	}
	switch route.State {
	case "pending":
		err = putEdgeRouteTx(ctx, tx, route)
	case "active":
		err = activateEdgeRouteTx(ctx, tx, route)
	case "deactivated":
		err = deactivateEdgeRouteTx(ctx, tx, route)
	default:
		err = fmt.Errorf("unsupported edge route transition state %q", route.State)
	}
	if err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) PutEdgeRoute(ctx context.Context, route edge.RouteRecord) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := putEdgeRouteTx(ctx, tx, route); err != nil {
		return err
	}
	return tx.Commit()
}

func putEdgeRouteTx(ctx context.Context, tx *sql.Tx, route edge.RouteRecord) error {
	if err := validateEdgeRoute(route, "pending", true); err != nil {
		return err
	}
	if err := validateEdgeOwnership(ctx, tx, route); err != nil {
		return err
	}
	existing, found, err := queryEdgeRoute(ctx, tx, route.EndpointID)
	if err != nil {
		return err
	}
	var maximum sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT MAX(generation) FROM edge_routes WHERE deployment_id=? AND miner_hotkey=?`, route.DeploymentID, route.MinerID).Scan(&maximum); err != nil {
		return err
	}
	if !found && maximum.Valid && route.Generation <= uint64(maximum.Int64) {
		return edge.ErrStaleRoute
	}
	if found {
		if !samePersistedRoute(existing, route) {
			return fmt.Errorf("edge route endpoint %q conflicts with another exact signed ticket", route.EndpointID)
		}
		if existing.State == "deactivated" {
			return errors.New("deactivated edge incarnation cannot be republished")
		}
		if len(existing.ReceiptJSON) > 0 && !bytes.Equal(existing.ReceiptJSON, route.ReceiptJSON) {
			return errors.New("edge route receipt conflicts with the persisted exact receipt")
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO edge_routes(endpoint_id,deployment_id,generation,miner_hotkey,replica_id,route_host,state,ticket_json,receipt_json,updated_at_ns)
VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(endpoint_id) DO UPDATE SET state='pending',receipt_json=excluded.receipt_json,updated_at_ns=excluded.updated_at_ns`,
		route.EndpointID, route.DeploymentID, route.Generation, route.MinerID, route.ReplicaID, route.RouteHost,
		"pending", route.TicketJSON, route.ReceiptJSON, time.Now().UTC().UnixNano())
	if err != nil {
		return err
	}
	return nil
}

func (s *Store) ActivateEdgeRoute(ctx context.Context, route edge.RouteRecord) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := activateEdgeRouteTx(ctx, tx, route); err != nil {
		return err
	}
	return tx.Commit()
}

func activateEdgeRouteTx(ctx context.Context, tx *sql.Tx, route edge.RouteRecord) error {
	if err := validateEdgeRoute(route, "active", true); err != nil {
		return err
	}
	existing, found, err := queryEdgeRoute(ctx, tx, route.EndpointID)
	if err != nil {
		return err
	}
	if !found || !samePersistedRoute(existing, route) || !bytes.Equal(existing.ReceiptJSON, route.ReceiptJSON) || existing.State != "pending" {
		return errors.New("only the exact persisted pending edge incarnation can be activated")
	}
	result, err := tx.ExecContext(ctx, `UPDATE edge_routes SET state='active',updated_at_ns=? WHERE endpoint_id=? AND state='pending'`, time.Now().UTC().UnixNano(), route.EndpointID)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		return errors.New("edge route activation lost a concurrent lifecycle race")
	}
	return nil
}

func (s *Store) DeactivateEdgeRoute(ctx context.Context, route edge.RouteRecord) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := deactivateEdgeRouteTx(ctx, tx, route); err != nil {
		return err
	}
	return tx.Commit()
}

func deactivateEdgeRouteTx(ctx context.Context, tx *sql.Tx, route edge.RouteRecord) error {
	if err := validateEdgeRoute(route, "deactivated", false); err != nil {
		return err
	}
	existing, found, err := queryEdgeRoute(ctx, tx, route.EndpointID)
	if err != nil {
		return err
	}
	if found && !samePersistedRoute(existing, route) {
		return fmt.Errorf("edge route endpoint %q conflicts with another exact signed ticket", route.EndpointID)
	}
	if found {
		_, err = tx.ExecContext(ctx, `UPDATE edge_routes SET state='deactivated',updated_at_ns=? WHERE endpoint_id=?`, time.Now().UTC().UnixNano(), route.EndpointID)
	} else {
		if err := validateEdgeOwnership(ctx, tx, route); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO edge_routes(endpoint_id,deployment_id,generation,miner_hotkey,replica_id,route_host,state,ticket_json,receipt_json,updated_at_ns)
VALUES(?,?,?,?,?,?,?,?,NULL,?)`, route.EndpointID, route.DeploymentID, route.Generation, route.MinerID, route.ReplicaID,
			route.RouteHost, "deactivated", route.TicketJSON, time.Now().UTC().UnixNano())
	}
	if err != nil {
		return err
	}
	return nil
}

// HighestEdgeGeneration returns the highest persisted route generation for a
// deployment across all miners and lifecycle states, or zero when none exists.
// It lets a restarted route authority continue a deployment's generation
// sequence instead of reissuing generations the store would reject as stale.
func (s *Store) HighestEdgeGeneration(ctx context.Context, deploymentID string) (uint64, error) {
	var maximum sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT MAX(generation) FROM edge_routes WHERE deployment_id=?`, deploymentID).Scan(&maximum); err != nil {
		return 0, err
	}
	if !maximum.Valid || maximum.Int64 < 0 {
		return 0, nil
	}
	return uint64(maximum.Int64), nil
}

func (s *Store) QuarantineEdgeRoutes(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `UPDATE edge_routes SET state='quarantined',updated_at_ns=? WHERE state IN ('pending','active')`, time.Now().UTC().UnixNano())
	return err
}

func (s *Store) EdgeRoute(ctx context.Context, endpointID string) (edge.RouteRecord, bool, error) {
	return queryEdgeRoute(ctx, s.db, endpointID)
}

type edgeQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func queryEdgeRoute(ctx context.Context, queryer edgeQueryer, endpointID string) (edge.RouteRecord, bool, error) {
	var route edge.RouteRecord
	err := queryer.QueryRowContext(ctx, `SELECT endpoint_id,deployment_id,generation,miner_hotkey,replica_id,route_host,state,ticket_json,COALESCE(receipt_json,X'') FROM edge_routes WHERE endpoint_id=?`, endpointID).Scan(
		&route.EndpointID, &route.DeploymentID, &route.Generation, &route.MinerID, &route.ReplicaID, &route.RouteHost,
		&route.State, &route.TicketJSON, &route.ReceiptJSON,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return edge.RouteRecord{}, false, nil
	}
	return route, err == nil, err
}

func validateEdgeOwnership(ctx context.Context, tx *sql.Tx, route edge.RouteRecord) error {
	var conflict int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM edge_routes WHERE route_host=? AND deployment_id<>?`, route.RouteHost, route.DeploymentID).Scan(&conflict); err != nil {
		return err
	}
	if conflict > 0 {
		return errors.New("edge route host is owned by another deployment")
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM edge_routes WHERE deployment_id=? AND route_host<>?`, route.DeploymentID, route.RouteHost).Scan(&conflict); err != nil {
		return err
	}
	if conflict > 0 {
		return errors.New("edge deployment cannot claim another route host")
	}
	return nil
}

func validateEdgeRoute(route edge.RouteRecord, expectedState string, receiptRequired bool) error {
	if route.EndpointID == "" || route.DeploymentID == "" || route.Generation == 0 || route.Generation > uint64(1<<63-1) || route.MinerID == "" ||
		route.ReplicaID == "" || route.RouteHost == "" || len(route.TicketJSON) == 0 || route.State != expectedState ||
		(receiptRequired && len(route.ReceiptJSON) == 0) {
		return errors.New("persisted edge route is incomplete")
	}
	return nil
}

func samePersistedRoute(left, right edge.RouteRecord) bool {
	return left.EndpointID == right.EndpointID && left.DeploymentID == right.DeploymentID && left.Generation == right.Generation &&
		left.MinerID == right.MinerID && left.ReplicaID == right.ReplicaID && left.RouteHost == right.RouteHost &&
		bytes.Equal(left.TicketJSON, right.TicketJSON)
}
