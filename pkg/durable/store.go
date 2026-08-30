// SPDX-License-Identifier: AGPL-3.0-only

// Package durable provides the small transactional state boundary shared by
// the long-running Go services. It intentionally stores protocol JSON intact
// so restart recovery and audits do not depend on an ORM projection.
package durable

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

var ErrEndpointDeactivated = errors.New("endpoint has a durable deactivation fence")

type Endpoint struct {
	EndpointID   string
	DeploymentID string
	MinerHotkey  string
	RuntimeID    string
	RuntimeURL   string
	// RuntimeCleanupPath is private backend metadata prepared before launch.
	// It never crosses the scheduler or public protocol boundary.
	RuntimeCleanupPath string
	// RuntimeCleanupRoot is the canonical ownership boundary against which the
	// persisted cleanup path was validated. Keeping it with the exact path lets
	// a later restart validate old metadata even if runtime configuration moves.
	RuntimeCleanupRoot string
	Active             bool
}

type Observation struct {
	MinerHotkey  string    `json:"miner_hotkey"`
	Success      bool      `json:"success"`
	LatencyMS    int64     `json:"latency_ms"`
	Availability float64   `json:"availability"`
	ObservedAt   time.Time `json:"observed_at"`
	Kind         string    `json:"kind"`
}

type ServiceBinding struct {
	Role                       string
	Network                    string
	NetUID                     uint16
	Hotkey                     string
	UID                        *uint16
	ServicePublicKey           string
	Transport                  string
	TransportCertificateSHA256 string
	Generation                 uint64
	ExpiresAtBlock             uint64
	BindingJSON                []byte
}

type MinerRegistration struct {
	Network                    string
	NetUID                     uint16
	Hotkey                     string
	UID                        *uint16
	AxonURL                    string
	BridgeURL                  string
	ServicePublicKey           string
	Transport                  string
	TransportCertificateSHA256 string
	TransportCertificateDER    []byte
	BindingGeneration          uint64
	BindingExpiresAtBlock      uint64
	BindingJSON                []byte
}

func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("durable database path is required")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open durable database: %w", err)
	}
	db.SetMaxOpenConns(1)
	store := &Store{db: db}
	if err := store.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	const schema = `
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA busy_timeout=5000;
CREATE TABLE IF NOT EXISTS replay_keys (
  scope TEXT NOT NULL,
  replay_key TEXT NOT NULL,
  expires_at_ns INTEGER NOT NULL,
  PRIMARY KEY(scope, replay_key)
);
CREATE TABLE IF NOT EXISTS assignments (
  endpoint_id TEXT PRIMARY KEY,
  deployment_id TEXT NOT NULL,
  miner_hotkey TEXT NOT NULL,
  assignment_nonce TEXT NOT NULL UNIQUE,
  generation INTEGER NOT NULL,
  status TEXT NOT NULL,
  ticket_json BLOB NOT NULL,
  receipt_json BLOB,
  updated_at_ns INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS endpoint_incarnations (
  endpoint_id TEXT PRIMARY KEY,
  deployment_id TEXT NOT NULL,
  miner_hotkey TEXT NOT NULL,
  runtime_id TEXT NOT NULL DEFAULT '',
  runtime_url TEXT NOT NULL DEFAULT '',
  runtime_cleanup_path TEXT NOT NULL DEFAULT '',
  runtime_cleanup_root TEXT NOT NULL DEFAULT '',
  active INTEGER NOT NULL,
  updated_at_ns INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS endpoint_deactivation_fences (
  endpoint_id TEXT PRIMARY KEY,
  deployment_id TEXT NOT NULL,
  miner_hotkey TEXT NOT NULL,
  validator_hotkey TEXT NOT NULL,
  updated_at_ns INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS edge_routes (
  endpoint_id TEXT PRIMARY KEY,
  deployment_id TEXT NOT NULL,
  generation INTEGER NOT NULL,
  miner_hotkey TEXT NOT NULL,
  replica_id TEXT NOT NULL,
  route_host TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('pending','active','quarantined','deactivated')),
  ticket_json BLOB NOT NULL,
  receipt_json BLOB,
  updated_at_ns INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS edge_routes_owner_generation ON edge_routes(deployment_id, miner_hotkey, generation);
CREATE INDEX IF NOT EXISTS edge_routes_host_state ON edge_routes(route_host, state);
CREATE TABLE IF NOT EXISTS trust (
  miner_hotkey TEXT PRIMARY KEY,
  value REAL NOT NULL CHECK(value >= 0 AND value <= 1),
  updated_at_ns INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS observations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  miner_hotkey TEXT NOT NULL,
  success INTEGER NOT NULL,
  latency_ms INTEGER NOT NULL,
  availability REAL NOT NULL,
  kind TEXT NOT NULL,
  observed_at_ns INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS observations_miner_time ON observations(miner_hotkey, observed_at_ns);
CREATE TABLE IF NOT EXISTS service_bindings (
  role TEXT NOT NULL,
  network TEXT NOT NULL,
  netuid INTEGER NOT NULL,
  hotkey TEXT NOT NULL,
  uid INTEGER,
  service_public_key TEXT NOT NULL,
	transport TEXT NOT NULL DEFAULT '',
	transport_certificate_sha256 TEXT NOT NULL DEFAULT '',
  generation INTEGER NOT NULL,
  expires_at_block INTEGER NOT NULL,
  binding_json BLOB NOT NULL,
  updated_at_ns INTEGER NOT NULL,
  PRIMARY KEY(role, network, netuid, hotkey)
);
CREATE TABLE IF NOT EXISTS miner_registrations (
  network TEXT NOT NULL,
  netuid INTEGER NOT NULL,
  hotkey TEXT NOT NULL,
  uid INTEGER,
  axon_url TEXT NOT NULL,
  bridge_url TEXT NOT NULL,
  service_public_key TEXT NOT NULL,
  transport TEXT NOT NULL,
  transport_certificate_sha256 TEXT NOT NULL DEFAULT '',
  transport_certificate_der BLOB NOT NULL DEFAULT X'',
  binding_generation INTEGER NOT NULL,
  binding_expires_at_block INTEGER NOT NULL,
  binding_json BLOB NOT NULL,
  updated_at_ns INTEGER NOT NULL,
  PRIMARY KEY(network, netuid, hotkey)
);`
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("migrate durable database: %w", err)
	}
	// Databases created by service-binding.v1 need explicit additive columns;
	// CREATE TABLE IF NOT EXISTS does not evolve an existing table.
	if err := s.ensureColumn(ctx, "service_bindings", "transport", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn(ctx, "service_bindings", "transport_certificate_sha256", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn(ctx, "endpoint_incarnations", "runtime_cleanup_path", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn(ctx, "endpoint_incarnations", "runtime_cleanup_root", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	return nil
}

func (s *Store) ensureColumn(ctx context.Context, table, column, declaration string) error {
	rows, err := s.db.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
	if err != nil {
		return fmt.Errorf("inspect durable table %s: %w", table, err)
	}
	found := false
	for rows.Next() {
		var cid int
		var name, columnType string
		var notNull, primaryKey int
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			rows.Close()
			return err
		}
		if name == column {
			found = true
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if found {
		return nil
	}
	if _, err := s.db.ExecContext(ctx, `ALTER TABLE `+table+` ADD COLUMN `+column+` `+declaration); err != nil {
		return fmt.Errorf("add durable column %s.%s: %w", table, column, err)
	}
	return nil
}

// ReserveReplay atomically records a replay key. Expired rows are removed in
// the same transaction. It returns false for an already-live key.
func (s *Store) ReserveReplay(ctx context.Context, scope, key string, expiresAt time.Time) (bool, error) {
	if err := validateReplayReservation(scope, key, expiresAt); err != nil {
		return false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	reserved, err := reserveReplayTx(ctx, tx, scope, key, expiresAt)
	if err != nil || !reserved {
		return reserved, err
	}
	return true, tx.Commit()
}

func validateReplayReservation(scope, key string, expiresAt time.Time) error {
	if scope == "" || key == "" || !expiresAt.After(time.Now().UTC()) {
		return errors.New("replay scope, key, and future expiry are required")
	}
	return nil
}

func reserveReplayTx(ctx context.Context, tx *sql.Tx, scope, key string, expiresAt time.Time) (bool, error) {
	now := time.Now().UTC().UnixNano()
	if _, err := tx.ExecContext(ctx, `DELETE FROM replay_keys WHERE expires_at_ns <= ?`, now); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO replay_keys(scope,replay_key,expires_at_ns) VALUES(?,?,?)`, scope, key, expiresAt.UTC().UnixNano()); err != nil {
		if isConstraint(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (s *Store) SaveAssignment(ctx context.Context, ticket protocol.Ticket, status string) error {
	payload, err := json.Marshal(ticket)
	if err != nil {
		return err
	}
	endpointID := protocol.EndpointID(ticket)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	validatorHotkey := ticketValidatorHotkey(ticket)
	fenced, err := endpointFencedTx(ctx, tx, endpointID, ticket.DeploymentID, ticket.MinerID, validatorHotkey)
	if err != nil {
		return err
	}
	var existing []byte
	var existingStatus string
	err = tx.QueryRowContext(ctx, `SELECT ticket_json,status FROM assignments WHERE endpoint_id=?`, endpointID).Scan(&existing, &existingStatus)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if fenced {
			status = "deactivated"
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO assignments(endpoint_id,deployment_id,miner_hotkey,assignment_nonce,generation,status,ticket_json,updated_at_ns)
VALUES(?,?,?,?,?,?,?,?)`, endpointID, ticket.DeploymentID, ticket.MinerID, ticket.AssignmentNonce, ticket.Generation, status, payload, time.Now().UTC().UnixNano())
	case err != nil:
		return err
	case !bytes.Equal(existing, payload):
		return fmt.Errorf("assignment endpoint %q conflicts with another exact ticket", endpointID)
	case existingStatus == "deactivated" || fenced:
		fenced = true
		_, err = tx.ExecContext(ctx, `UPDATE assignments SET status='deactivated',updated_at_ns=? WHERE endpoint_id=?`, time.Now().UTC().UnixNano(), endpointID)
	default:
		_, err = tx.ExecContext(ctx, `UPDATE assignments SET status=?,updated_at_ns=? WHERE endpoint_id=?`, status, time.Now().UTC().UnixNano(), endpointID)
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

func ticketValidatorHotkey(ticket protocol.Ticket) string {
	if ticket.Subnet == nil {
		return ""
	}
	return ticket.Subnet.ValidatorHotkey
}

func validateExactTicketOwner(payload []byte, endpointID, deploymentID, minerHotkey, validatorHotkey string) error {
	var ticket protocol.Ticket
	if err := json.Unmarshal(payload, &ticket); err != nil {
		return fmt.Errorf("decode exact-owner ticket: %w", err)
	}
	if protocol.EndpointID(ticket) != endpointID || ticket.DeploymentID != deploymentID || ticket.MinerID != minerHotkey || ticketValidatorHotkey(ticket) != validatorHotkey {
		return fmt.Errorf("endpoint %q conflicts with another exact ticket owner", endpointID)
	}
	return nil
}

func endpointFencedTx(ctx context.Context, tx *sql.Tx, endpointID, deploymentID, minerHotkey, validatorHotkey string) (bool, error) {
	var fencedDeployment, fencedMiner, fencedValidator string
	err := tx.QueryRowContext(ctx, `SELECT deployment_id,miner_hotkey,validator_hotkey FROM endpoint_deactivation_fences WHERE endpoint_id=?`, endpointID).Scan(
		&fencedDeployment, &fencedMiner, &fencedValidator,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if fencedDeployment != deploymentID || fencedMiner != minerHotkey || fencedValidator != validatorHotkey {
		return false, fmt.Errorf("endpoint deactivation fence %q conflicts with another exact owner", endpointID)
	}
	return true, nil
}

func (s *Store) SaveReceipt(ctx context.Context, receipt protocol.Receipt) error {
	payload, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `UPDATE assignments SET status=CASE WHEN status='deactivated' THEN status ELSE ? END,receipt_json=?,updated_at_ns=? WHERE endpoint_id=?`,
		string(receipt.Stage), payload, time.Now().UTC().UnixNano(), receipt.EndpointID)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		return fmt.Errorf("receipt endpoint %q has no durable assignment", receipt.EndpointID)
	}
	return nil
}

func (s *Store) CachedResult(ctx context.Context, endpointID string) (protocol.Receipt, bool, error) {
	var payload []byte
	err := s.db.QueryRowContext(ctx, `SELECT a.receipt_json FROM assignments a
JOIN endpoint_incarnations e ON e.endpoint_id=a.endpoint_id
WHERE a.endpoint_id=? AND a.status != 'deactivated' AND a.receipt_json IS NOT NULL AND e.active=1`, endpointID).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return protocol.Receipt{}, false, nil
	}
	if err != nil {
		return protocol.Receipt{}, false, err
	}
	var receipt protocol.Receipt
	if err := json.Unmarshal(payload, &receipt); err != nil {
		return protocol.Receipt{}, false, err
	}
	return receipt, true, nil
}

func (s *Store) AssignmentTicket(ctx context.Context, endpointID string) (protocol.Ticket, string, bool, error) {
	var payload []byte
	var status string
	err := s.db.QueryRowContext(ctx, `SELECT ticket_json,status FROM assignments WHERE endpoint_id=?`, endpointID).Scan(&payload, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return protocol.Ticket{}, "", false, nil
	}
	if err != nil {
		return protocol.Ticket{}, "", false, err
	}
	var ticket protocol.Ticket
	if err := json.Unmarshal(payload, &ticket); err != nil {
		return protocol.Ticket{}, "", false, err
	}
	return ticket, status, true, nil
}

func (s *Store) ServiceBinding(ctx context.Context, role, network string, netuid uint16, hotkey string) (ServiceBinding, bool, error) {
	var binding ServiceBinding
	var uid sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT role,network,netuid,hotkey,uid,service_public_key,transport,transport_certificate_sha256,generation,expires_at_block,binding_json
FROM service_bindings WHERE role=? AND network=? AND netuid=? AND hotkey=?`, role, network, netuid, hotkey).Scan(
		&binding.Role, &binding.Network, &binding.NetUID, &binding.Hotkey, &uid, &binding.ServicePublicKey, &binding.Transport, &binding.TransportCertificateSHA256,
		&binding.Generation, &binding.ExpiresAtBlock, &binding.BindingJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return ServiceBinding{}, false, nil
	}
	if err != nil {
		return ServiceBinding{}, false, err
	}
	if uid.Valid {
		value := uint16(uid.Int64)
		binding.UID = &value
	}
	return binding, true, nil
}

func (s *Store) MinerRegistration(ctx context.Context, network string, netuid uint16, hotkey string) (MinerRegistration, bool, error) {
	var registration MinerRegistration
	var uid sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT network,netuid,hotkey,uid,axon_url,bridge_url,service_public_key,transport,
transport_certificate_sha256,transport_certificate_der,binding_generation,binding_expires_at_block,binding_json
FROM miner_registrations WHERE network=? AND netuid=? AND hotkey=?`, network, netuid, hotkey).Scan(
		&registration.Network, &registration.NetUID, &registration.Hotkey, &uid, &registration.AxonURL, &registration.BridgeURL,
		&registration.ServicePublicKey, &registration.Transport, &registration.TransportCertificateSHA256, &registration.TransportCertificateDER,
		&registration.BindingGeneration, &registration.BindingExpiresAtBlock, &registration.BindingJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return MinerRegistration{}, false, nil
	}
	if err != nil {
		return MinerRegistration{}, false, err
	}
	if uid.Valid {
		value := uint16(uid.Int64)
		registration.UID = &value
	}
	return registration, true, nil
}

func (s *Store) PutEndpoint(ctx context.Context, endpoint Endpoint) error {
	if endpoint.EndpointID == "" || endpoint.DeploymentID == "" || endpoint.MinerHotkey == "" {
		return errors.New("endpoint ID, deployment ID, and miner hotkey are required")
	}
	active := 0
	if endpoint.Active {
		active = 1
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var assignmentDeployment, assignmentMiner, assignmentStatus string
	var ticketJSON []byte
	err = tx.QueryRowContext(ctx, `SELECT deployment_id,miner_hotkey,status,ticket_json FROM assignments WHERE endpoint_id=?`, endpoint.EndpointID).Scan(
		&assignmentDeployment, &assignmentMiner, &assignmentStatus, &ticketJSON,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("endpoint incarnation %q has no exact durable assignment", endpoint.EndpointID)
		}
		return err
	}
	if assignmentDeployment != endpoint.DeploymentID || assignmentMiner != endpoint.MinerHotkey {
		return fmt.Errorf("endpoint incarnation %q conflicts with another owner", endpoint.EndpointID)
	}
	var ticket protocol.Ticket
	if err := json.Unmarshal(ticketJSON, &ticket); err != nil {
		return fmt.Errorf("decode endpoint assignment ticket: %w", err)
	}
	if endpoint.Active {
		fenced, fenceErr := endpointFencedTx(
			ctx, tx, endpoint.EndpointID, endpoint.DeploymentID, endpoint.MinerHotkey, ticketValidatorHotkey(ticket),
		)
		if fenceErr != nil {
			return fenceErr
		}
		if fenced || assignmentStatus == "deactivated" {
			return ErrEndpointDeactivated
		}
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO endpoint_incarnations(endpoint_id,deployment_id,miner_hotkey,runtime_id,runtime_url,runtime_cleanup_path,runtime_cleanup_root,active,updated_at_ns)
VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(endpoint_id) DO UPDATE SET runtime_id=excluded.runtime_id,runtime_url=excluded.runtime_url,runtime_cleanup_path=excluded.runtime_cleanup_path,runtime_cleanup_root=excluded.runtime_cleanup_root,active=excluded.active,updated_at_ns=excluded.updated_at_ns
WHERE endpoint_incarnations.deployment_id=excluded.deployment_id AND endpoint_incarnations.miner_hotkey=excluded.miner_hotkey`,
		endpoint.EndpointID, endpoint.DeploymentID, endpoint.MinerHotkey, endpoint.RuntimeID, endpoint.RuntimeURL, endpoint.RuntimeCleanupPath, endpoint.RuntimeCleanupRoot, active, time.Now().UTC().UnixNano())
	if err != nil {
		return err
	}
	// Endpoint incarnations are scheduler-derived identities. A caller may
	// refresh private runtime details for the same owner, but must never reuse
	// one incarnation for another deployment or miner.
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("endpoint incarnation %q conflicts with another owner", endpoint.EndpointID)
	}
	return tx.Commit()
}

// PutCleanupEndpoint persists private cleanup authority without crossing the
// activation fence. It can create the cleanup-only incarnation needed to
// retire a daemon object left by an assignment-only crash, including when the
// exact assignment is already deactivated. It never publishes a runtime URL,
// never changes assignment status, never reopens completed cleanup, and never
// permits PutEndpoint to activate through the fence.
func (s *Store) PutCleanupEndpoint(ctx context.Context, endpoint Endpoint) error {
	if endpoint.EndpointID == "" || endpoint.DeploymentID == "" || endpoint.MinerHotkey == "" || endpoint.RuntimeID == "" || !endpoint.Active {
		return errors.New("cleanup endpoint requires exact owner, runtime identity, and pending state")
	}
	if (endpoint.RuntimeCleanupPath == "") != (endpoint.RuntimeCleanupRoot == "") {
		return errors.New("cleanup endpoint path and ownership root must be paired")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var assignmentDeployment, assignmentMiner string
	var ticketJSON []byte
	if err := tx.QueryRowContext(ctx, `SELECT deployment_id,miner_hotkey,ticket_json FROM assignments WHERE endpoint_id=?`, endpoint.EndpointID).Scan(
		&assignmentDeployment, &assignmentMiner, &ticketJSON,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("cleanup endpoint %q has no exact durable assignment", endpoint.EndpointID)
		}
		return err
	}
	if assignmentDeployment != endpoint.DeploymentID || assignmentMiner != endpoint.MinerHotkey {
		return fmt.Errorf("cleanup endpoint %q conflicts with another owner", endpoint.EndpointID)
	}
	if err := validateExactTicketOwner(ticketJSON, endpoint.EndpointID, endpoint.DeploymentID, endpoint.MinerHotkey, ticketValidatorFromJSON(ticketJSON)); err != nil {
		return err
	}

	var existingDeployment, existingMiner, existingRuntime, existingPath, existingRoot string
	var existingActive bool
	err = tx.QueryRowContext(ctx, `SELECT deployment_id,miner_hotkey,runtime_id,runtime_cleanup_path,runtime_cleanup_root,active FROM endpoint_incarnations WHERE endpoint_id=?`, endpoint.EndpointID).Scan(
		&existingDeployment, &existingMiner, &existingRuntime, &existingPath, &existingRoot, &existingActive,
	)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		_, err = tx.ExecContext(ctx, `INSERT INTO endpoint_incarnations(endpoint_id,deployment_id,miner_hotkey,runtime_id,runtime_url,runtime_cleanup_path,runtime_cleanup_root,active,updated_at_ns)
VALUES(?,?,?,?,?,?,?,1,?)`, endpoint.EndpointID, endpoint.DeploymentID, endpoint.MinerHotkey, endpoint.RuntimeID, "", endpoint.RuntimeCleanupPath, endpoint.RuntimeCleanupRoot, time.Now().UTC().UnixNano())
	case err != nil:
		return err
	case existingDeployment != endpoint.DeploymentID || existingMiner != endpoint.MinerHotkey:
		return fmt.Errorf("cleanup endpoint %q conflicts with another owner", endpoint.EndpointID)
	case !existingActive:
		// Completed cleanup is terminal. Recovery selects only assignments with
		// no incarnation, so this is an idempotent defensive no-op.
		return nil
	case existingRuntime != "" && existingRuntime != endpoint.RuntimeID:
		return fmt.Errorf("cleanup endpoint %q conflicts with another runtime identity", endpoint.EndpointID)
	case existingPath != "" && endpoint.RuntimeCleanupPath != "" && existingPath != endpoint.RuntimeCleanupPath:
		return fmt.Errorf("cleanup endpoint %q conflicts with another cleanup path", endpoint.EndpointID)
	case existingRoot != "" && endpoint.RuntimeCleanupRoot != "" && existingRoot != endpoint.RuntimeCleanupRoot:
		return fmt.Errorf("cleanup endpoint %q conflicts with another cleanup root", endpoint.EndpointID)
	default:
		if endpoint.RuntimeCleanupPath == "" {
			endpoint.RuntimeCleanupPath = existingPath
		}
		if endpoint.RuntimeCleanupRoot == "" {
			endpoint.RuntimeCleanupRoot = existingRoot
		}
		_, err = tx.ExecContext(ctx, `UPDATE endpoint_incarnations SET runtime_id=?,runtime_cleanup_path=?,runtime_cleanup_root=?,updated_at_ns=? WHERE endpoint_id=? AND active=1`,
			endpoint.RuntimeID, endpoint.RuntimeCleanupPath, endpoint.RuntimeCleanupRoot, time.Now().UTC().UnixNano(), endpoint.EndpointID)
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

func ticketValidatorFromJSON(payload []byte) string {
	var ticket protocol.Ticket
	if json.Unmarshal(payload, &ticket) != nil {
		return ""
	}
	return ticketValidatorHotkey(ticket)
}

func (s *Store) DeactivateEndpoint(ctx context.Context, endpointID string) error {
	ticket, _, exists, err := s.AssignmentTicket(ctx, endpointID)
	if err != nil {
		return err
	}
	if exists {
		return s.DeactivateEndpointOwned(ctx, endpointID, ticket.DeploymentID, ticket.MinerID, ticketValidatorHotkey(ticket))
	}
	_, err = s.db.ExecContext(ctx, `UPDATE endpoint_incarnations SET active=0,updated_at_ns=? WHERE endpoint_id=?`, time.Now().UTC().UnixNano(), endpointID)
	return err
}

// DeactivateEndpointOwned records a durable exact-owner fence even before the
// matching assignment or runtime row exists. A later exact ticket can be
// retained as deactivated for audit, but can never activate a runtime.
func (s *Store) DeactivateEndpointOwned(ctx context.Context, endpointID, deploymentID, minerHotkey, validatorHotkey string) error {
	if err := s.FenceEndpointDeactivation(ctx, endpointID, deploymentID, minerHotkey, validatorHotkey); err != nil {
		return err
	}
	return s.CompleteEndpointDeactivation(ctx, endpointID, deploymentID, minerHotkey)
}

// FenceEndpointDeactivation makes deactivation win against every later
// assignment/runtime activation, while deliberately leaving an already-active
// incarnation recoverable until its runtime Stop succeeds.
func (s *Store) FenceEndpointDeactivation(ctx context.Context, endpointID, deploymentID, minerHotkey, validatorHotkey string) error {
	if endpointID == "" || deploymentID == "" || minerHotkey == "" {
		return errors.New("endpoint deactivation requires exact endpoint, deployment, and miner identities")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC().UnixNano()
	var assignmentTicket []byte
	err = tx.QueryRowContext(ctx, `SELECT ticket_json FROM assignments WHERE endpoint_id=?`, endpointID).Scan(&assignmentTicket)
	if err == nil {
		if err := validateExactTicketOwner(assignmentTicket, endpointID, deploymentID, minerHotkey, validatorHotkey); err != nil {
			return err
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var endpointDeployment, endpointMiner string
	err = tx.QueryRowContext(ctx, `SELECT deployment_id,miner_hotkey FROM endpoint_incarnations WHERE endpoint_id=?`, endpointID).Scan(
		&endpointDeployment, &endpointMiner,
	)
	if err == nil && (endpointDeployment != deploymentID || endpointMiner != minerHotkey) {
		return fmt.Errorf("endpoint incarnation %q conflicts with another exact owner", endpointID)
	} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var routeTicket []byte
	err = tx.QueryRowContext(ctx, `SELECT ticket_json FROM edge_routes WHERE endpoint_id=?`, endpointID).Scan(&routeTicket)
	if err == nil {
		if err := validateExactTicketOwner(routeTicket, endpointID, deploymentID, minerHotkey, validatorHotkey); err != nil {
			return err
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO endpoint_deactivation_fences(endpoint_id,deployment_id,miner_hotkey,validator_hotkey,updated_at_ns)
VALUES(?,?,?,?,?) ON CONFLICT(endpoint_id) DO UPDATE SET updated_at_ns=excluded.updated_at_ns
WHERE endpoint_deactivation_fences.deployment_id=excluded.deployment_id AND endpoint_deactivation_fences.miner_hotkey=excluded.miner_hotkey AND endpoint_deactivation_fences.validator_hotkey=excluded.validator_hotkey`,
		endpointID, deploymentID, minerHotkey, validatorHotkey, now)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("endpoint deactivation fence %q conflicts with another exact owner", endpointID)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE assignments SET status='deactivated',updated_at_ns=? WHERE endpoint_id=? AND deployment_id=? AND miner_hotkey=?`, now, endpointID, deploymentID, minerHotkey); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE edge_routes SET state='deactivated',updated_at_ns=? WHERE endpoint_id=? AND deployment_id=? AND miner_hotkey=?`, now, endpointID, deploymentID, minerHotkey); err != nil {
		return err
	}
	return tx.Commit()
}

// CompleteEndpointDeactivation closes the recoverable runtime incarnation only
// after Stop has succeeded (or when no runtime row ever existed).
func (s *Store) CompleteEndpointDeactivation(ctx context.Context, endpointID, deploymentID, minerHotkey string) error {
	var existingDeployment, existingMiner string
	err := s.db.QueryRowContext(ctx, `SELECT deployment_id,miner_hotkey FROM endpoint_incarnations WHERE endpoint_id=?`, endpointID).Scan(
		&existingDeployment, &existingMiner,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if existingDeployment != deploymentID || existingMiner != minerHotkey {
		return fmt.Errorf("endpoint incarnation %q conflicts with another exact owner", endpointID)
	}
	_, err = s.db.ExecContext(ctx, `UPDATE endpoint_incarnations SET active=0,updated_at_ns=? WHERE endpoint_id=? AND deployment_id=? AND miner_hotkey=?`,
		time.Now().UTC().UnixNano(), endpointID, deploymentID, minerHotkey)
	return err
}

func (s *Store) ActiveEndpoints(ctx context.Context) ([]Endpoint, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT endpoint_id,deployment_id,miner_hotkey,runtime_id,runtime_url,runtime_cleanup_path,runtime_cleanup_root,active FROM endpoint_incarnations WHERE active=1 ORDER BY endpoint_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var endpoints []Endpoint
	for rows.Next() {
		var endpoint Endpoint
		if err := rows.Scan(&endpoint.EndpointID, &endpoint.DeploymentID, &endpoint.MinerHotkey, &endpoint.RuntimeID, &endpoint.RuntimeURL, &endpoint.RuntimeCleanupPath, &endpoint.RuntimeCleanupRoot, &endpoint.Active); err != nil {
			return nil, err
		}
		endpoints = append(endpoints, endpoint)
	}
	return endpoints, rows.Err()
}

// EndpointIncarnation returns the private runtime cleanup record regardless of
// whether cleanup has completed. Callers use it to preserve the exact runtime
// identity across retry and restart boundaries; it must never be inferred from
// an untrusted deactivation request.
func (s *Store) EndpointIncarnation(ctx context.Context, endpointID string) (Endpoint, bool, error) {
	var endpoint Endpoint
	err := s.db.QueryRowContext(ctx, `SELECT endpoint_id,deployment_id,miner_hotkey,runtime_id,runtime_url,runtime_cleanup_path,runtime_cleanup_root,active FROM endpoint_incarnations WHERE endpoint_id=?`, endpointID).Scan(
		&endpoint.EndpointID, &endpoint.DeploymentID, &endpoint.MinerHotkey, &endpoint.RuntimeID, &endpoint.RuntimeURL, &endpoint.RuntimeCleanupPath, &endpoint.RuntimeCleanupRoot, &endpoint.Active,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Endpoint{}, false, nil
	}
	if err != nil {
		return Endpoint{}, false, err
	}
	return endpoint, true, nil
}

// CleanupAssignments returns every assignment not durably marked deactivated,
// including the crash window before an endpoint-incarnation row was written.
// Empty minerHotkey selects all miners for readiness/recovery reporting.
func (s *Store) CleanupAssignments(ctx context.Context, minerHotkey string) ([]Endpoint, error) {
	query := `SELECT endpoint_id,deployment_id,miner_hotkey FROM assignments WHERE status != 'deactivated'`
	var args []any
	if minerHotkey != "" {
		query += ` AND miner_hotkey=?`
		args = append(args, minerHotkey)
	}
	query += ` ORDER BY endpoint_id`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var endpoints []Endpoint
	for rows.Next() {
		var endpoint Endpoint
		if err := rows.Scan(&endpoint.EndpointID, &endpoint.DeploymentID, &endpoint.MinerHotkey); err != nil {
			return nil, err
		}
		endpoints = append(endpoints, endpoint)
	}
	return endpoints, rows.Err()
}

// AssignmentsWithoutIncarnation returns every exact assignment whose runtime
// cleanup identity was never persisted. Deactivated rows are deliberately
// included: a parent-version process could fence the assignment after the
// Docker daemon created its deterministic container but before this row was
// written. Once any incarnation exists (active cleanup or completed), it is
// excluded so recovery cannot reopen a finished lifecycle.
func (s *Store) AssignmentsWithoutIncarnation(ctx context.Context, minerHotkey string) ([]Endpoint, error) {
	query := `SELECT a.endpoint_id,a.deployment_id,a.miner_hotkey FROM assignments a
LEFT JOIN endpoint_incarnations e ON e.endpoint_id=a.endpoint_id WHERE e.endpoint_id IS NULL`
	var args []any
	if minerHotkey != "" {
		query += ` AND a.miner_hotkey=?`
		args = append(args, minerHotkey)
	}
	query += ` ORDER BY a.endpoint_id`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var endpoints []Endpoint
	for rows.Next() {
		var endpoint Endpoint
		if err := rows.Scan(&endpoint.EndpointID, &endpoint.DeploymentID, &endpoint.MinerHotkey); err != nil {
			return nil, err
		}
		endpoints = append(endpoints, endpoint)
	}
	return endpoints, rows.Err()
}

func (s *Store) SetTrust(ctx context.Context, minerHotkey string, value float64) error {
	if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > 1 {
		return fmt.Errorf("trust must be a finite value in [0,1]")
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO trust(miner_hotkey,value,updated_at_ns) VALUES(?,?,?)
ON CONFLICT(miner_hotkey) DO UPDATE SET value=excluded.value,updated_at_ns=excluded.updated_at_ns`, minerHotkey, value, time.Now().UTC().UnixNano())
	return err
}

func (s *Store) Trust(ctx context.Context, minerHotkey string) (float64, bool, error) {
	var value float64
	err := s.db.QueryRowContext(ctx, `SELECT value FROM trust WHERE miner_hotkey=?`, minerHotkey).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	return value, err == nil, err
}

func (s *Store) TrustSnapshot(ctx context.Context) (map[string]float64, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT miner_hotkey,value FROM trust ORDER BY miner_hotkey`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make(map[string]float64)
	for rows.Next() {
		var miner string
		var value float64
		if err := rows.Scan(&miner, &value); err != nil {
			return nil, err
		}
		values[miner] = value
	}
	return values, rows.Err()
}

func (s *Store) RecordObservation(ctx context.Context, observation Observation) error {
	if observation.MinerHotkey == "" || observation.Kind == "" || observation.LatencyMS < 0 || math.IsNaN(observation.Availability) ||
		math.IsInf(observation.Availability, 0) || observation.Availability < 0 || observation.Availability > 1 {
		return errors.New("invalid scoring observation")
	}
	if observation.ObservedAt.IsZero() {
		observation.ObservedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO observations(miner_hotkey,success,latency_ms,availability,kind,observed_at_ns) VALUES(?,?,?,?,?,?)`,
		observation.MinerHotkey, observation.Success, observation.LatencyMS, observation.Availability, observation.Kind, observation.ObservedAt.UTC().UnixNano())
	return err
}

func (s *Store) Observations(ctx context.Context, since time.Time) ([]Observation, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT miner_hotkey,success,latency_ms,availability,kind,observed_at_ns FROM observations WHERE observed_at_ns>=? ORDER BY observed_at_ns,id`, since.UTC().UnixNano())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []Observation
	for rows.Next() {
		var observation Observation
		var at int64
		if err := rows.Scan(&observation.MinerHotkey, &observation.Success, &observation.LatencyMS, &observation.Availability, &observation.Kind, &at); err != nil {
			return nil, err
		}
		observation.ObservedAt = time.Unix(0, at).UTC()
		values = append(values, observation)
	}
	return values, rows.Err()
}

func (s *Store) UpsertServiceBinding(ctx context.Context, binding ServiceBinding) error {
	return upsertServiceBinding(ctx, s.db, binding)
}

type sqlExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func upsertServiceBinding(ctx context.Context, exec sqlExecer, binding ServiceBinding) error {
	if binding.Role == "" || binding.Network == "" || binding.Hotkey == "" || binding.ServicePublicKey == "" || len(binding.BindingJSON) == 0 {
		return errors.New("incomplete service binding")
	}
	if !validBindingTransport(binding) {
		return errors.New("invalid role-specific service binding transport")
	}
	var uid any
	if binding.UID != nil {
		uid = *binding.UID
	}
	result, err := exec.ExecContext(ctx, `INSERT INTO service_bindings(role,network,netuid,hotkey,uid,service_public_key,transport,transport_certificate_sha256,generation,expires_at_block,binding_json,updated_at_ns)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(role,network,netuid,hotkey) DO UPDATE SET
uid=excluded.uid,service_public_key=excluded.service_public_key,transport=excluded.transport,transport_certificate_sha256=excluded.transport_certificate_sha256,generation=excluded.generation,expires_at_block=excluded.expires_at_block,binding_json=excluded.binding_json,updated_at_ns=excluded.updated_at_ns
WHERE excluded.generation > service_bindings.generation OR
  (excluded.generation = service_bindings.generation AND
   excluded.service_public_key = service_bindings.service_public_key AND
	 excluded.transport = service_bindings.transport AND
	 excluded.transport_certificate_sha256 = service_bindings.transport_certificate_sha256 AND
	 excluded.uid IS service_bindings.uid AND
	 excluded.expires_at_block = service_bindings.expires_at_block)`, binding.Role, binding.Network, binding.NetUID, binding.Hotkey, uid,
		binding.ServicePublicKey, binding.Transport, binding.TransportCertificateSHA256, binding.Generation, binding.ExpiresAtBlock, binding.BindingJSON, time.Now().UTC().UnixNano())
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New("service binding generation rollback")
	}
	return nil
}

func validBindingTransport(binding ServiceBinding) bool {
	switch binding.Role {
	case "validator":
		return binding.Transport == "local" && binding.TransportCertificateSHA256 == ""
	case "miner":
		if binding.Transport == "http" {
			return binding.TransportCertificateSHA256 == ""
		}
		decoded, err := hex.DecodeString(binding.TransportCertificateSHA256)
		return binding.Transport == "https" && err == nil && len(binding.TransportCertificateSHA256) == 64 && len(decoded) == 32 &&
			binding.TransportCertificateSHA256 == hex.EncodeToString(decoded)
	default:
		return false
	}
}

// UpsertMinerRegistration atomically publishes the durable hotkey binding and
// its exact HTTPS axon/certificate identity. A failed rotation therefore
// cannot advance one record without the other.
func (s *Store) UpsertMinerRegistration(ctx context.Context, binding ServiceBinding, registration MinerRegistration) error {
	if registration.Network == "" || registration.Hotkey == "" || registration.AxonURL == "" || registration.BridgeURL == "" ||
		registration.ServicePublicKey == "" || registration.Transport == "" || len(registration.BindingJSON) == 0 ||
		binding.Role != "miner" || !equalUID(registration.UID, binding.UID) || !bytes.Equal(registration.BindingJSON, binding.BindingJSON) ||
		registration.BindingGeneration != binding.Generation || registration.BindingExpiresAtBlock != binding.ExpiresAtBlock ||
		registration.Network != binding.Network || registration.NetUID != binding.NetUID || registration.Hotkey != binding.Hotkey ||
		registration.ServicePublicKey != binding.ServicePublicKey || registration.Transport != binding.Transport ||
		registration.TransportCertificateSHA256 != binding.TransportCertificateSHA256 {
		return errors.New("incomplete or mismatched durable miner registration")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := upsertServiceBinding(ctx, tx, binding); err != nil {
		return err
	}
	var uid any
	if registration.UID != nil {
		uid = *registration.UID
	}
	certificateDER := registration.TransportCertificateDER
	if certificateDER == nil {
		certificateDER = []byte{}
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO miner_registrations(network,netuid,hotkey,uid,axon_url,bridge_url,service_public_key,transport,transport_certificate_sha256,transport_certificate_der,binding_generation,binding_expires_at_block,binding_json,updated_at_ns)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(network,netuid,hotkey) DO UPDATE SET
uid=excluded.uid,axon_url=excluded.axon_url,bridge_url=excluded.bridge_url,service_public_key=excluded.service_public_key,transport=excluded.transport,
transport_certificate_sha256=excluded.transport_certificate_sha256,transport_certificate_der=excluded.transport_certificate_der,
binding_generation=excluded.binding_generation,binding_expires_at_block=excluded.binding_expires_at_block,binding_json=excluded.binding_json,updated_at_ns=excluded.updated_at_ns
WHERE excluded.binding_generation > miner_registrations.binding_generation OR
 (excluded.binding_generation = miner_registrations.binding_generation AND excluded.uid IS miner_registrations.uid AND
  excluded.axon_url = miner_registrations.axon_url AND excluded.bridge_url = miner_registrations.bridge_url AND
  excluded.service_public_key = miner_registrations.service_public_key AND excluded.transport = miner_registrations.transport AND
  excluded.transport_certificate_sha256 = miner_registrations.transport_certificate_sha256 AND
  excluded.transport_certificate_der = miner_registrations.transport_certificate_der AND
  excluded.binding_expires_at_block = miner_registrations.binding_expires_at_block)`,
		registration.Network, registration.NetUID, registration.Hotkey, uid, registration.AxonURL, registration.BridgeURL,
		registration.ServicePublicKey, registration.Transport, registration.TransportCertificateSHA256, certificateDER,
		registration.BindingGeneration, registration.BindingExpiresAtBlock, registration.BindingJSON, time.Now().UTC().UnixNano())
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New("miner registration generation rollback or same-generation identity conflict")
	}
	return tx.Commit()
}

func equalUID(left, right *uint16) bool {
	return (left == nil && right == nil) || (left != nil && right != nil && *left == *right)
}

func isConstraint(err error) bool {
	return err != nil && (contains(err.Error(), "constraint failed") || contains(err.Error(), "UNIQUE constraint"))
}

func contains(value, fragment string) bool {
	for i := 0; i+len(fragment) <= len(value); i++ {
		if value[i:i+len(fragment)] == fragment {
			return true
		}
	}
	return false
}
