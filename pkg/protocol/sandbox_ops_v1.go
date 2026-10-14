// SPDX-License-Identifier: AGPL-3.0-only

package protocol

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/organic"
	"github.com/misscomputer/misscomputer-subnet/pkg/sandbox"
)

// sandbox-ops-v1 documents (docs/sandbox-ops-v1.md): a separately versioned
// extension of sandbox-lease-v1 that runs bounded exec and file operations
// on one running lease. Each document has its own schema and signing domain,
// so no op signature verifies as a lease document, a web ticket or the
// other op document, even under the same key.
const (
	SandboxOpRequestSchema  = organic.SchemaPrefix + "sandbox-op-request"
	SandboxOpReceiptSchema  = organic.SchemaPrefix + "sandbox-op-receipt"
	SandboxOpsSchemaVersion = 1

	SandboxOpRequestSigningDomain = SandboxOpRequestSchema + "/v1/ed25519"
	SandboxOpReceiptSigningDomain = SandboxOpReceiptSchema + "/v1/ed25519"
)

// SandboxOpRequestV1 is one validator-signed operation on one running
// lease. Payload bytes (the exec command or a file chunk) are not members:
// they travel beside the document and are bound by payload_digest and
// payload_bytes. Members that an op does not use must be null.
type SandboxOpRequestV1 struct {
	ExecID         *string                `json:"exec_id"`
	ExpiresAt      string                 `json:"expires_at"`
	Generation     uint64                 `json:"generation"`
	IssuedAt       string                 `json:"issued_at"`
	LeaseDigest    string                 `json:"lease_digest"`
	LeaseID        string                 `json:"lease_id"`
	Limit          *uint64                `json:"limit"`
	MaxOutputBytes *uint64                `json:"max_output_bytes"`
	MinerID        string                 `json:"miner_id"`
	Mode           *uint32                `json:"mode"`
	Offset         *uint64                `json:"offset"`
	Op             string                 `json:"op"`
	OpNonce        string                 `json:"op_nonce"`
	Path           *string                `json:"path"`
	PayloadBytes   uint64                 `json:"payload_bytes"`
	PayloadDigest  *string                `json:"payload_digest"`
	Recursive      *bool                  `json:"recursive"`
	SandboxID      string                 `json:"sandbox_id"`
	Schema         string                 `json:"schema"`
	SchemaVersion  int                    `json:"schema_version"`
	Signature      string                 `json:"signature"`
	Stream         *string                `json:"stream"`
	Subnet         *StaticSubnetBindingV1 `json:"subnet"`
	TimeoutMS      *uint64                `json:"timeout_ms"`
	WorkloadKind   string                 `json:"workload_kind"`
}

// SandboxOpReceiptV1 is the miner-signed answer to one op request. Result
// bytes (a file or output chunk, a listing) travel beside it and are bound
// by result_digest and result_bytes.
type SandboxOpReceiptV1 struct {
	DocumentDigest string                 `json:"document_digest"`
	EOF            bool                   `json:"eof"`
	ErrorCode      *string                `json:"error_code"`
	Exec           *sandbox.ExecStatus    `json:"exec"`
	File           *sandbox.FileInfo      `json:"file"`
	Generation     uint64                 `json:"generation"`
	LeaseID        string                 `json:"lease_id"`
	MinerID        string                 `json:"miner_id"`
	NextOffset     *uint64                `json:"next_offset"`
	ObservedAt     string                 `json:"observed_at"`
	Op             string                 `json:"op"`
	OpID           string                 `json:"op_id"`
	ResultBytes    uint64                 `json:"result_bytes"`
	ResultDigest   *string                `json:"result_digest"`
	SandboxID      string                 `json:"sandbox_id"`
	Schema         string                 `json:"schema"`
	SchemaVersion  int                    `json:"schema_version"`
	Signature      string                 `json:"signature"`
	Stage          string                 `json:"stage"`
	Subnet         *StaticSubnetBindingV1 `json:"subnet"`
}

// SandboxOpIDV1 is the signed replay identity of an op:
// <lease_id>-op-<op_nonce>. A miner keys its durable op record by it.
func SandboxOpIDV1(r SandboxOpRequestV1) string { return r.LeaseID + "-op-" + r.OpNonce }

// SandboxContentDigestV1 is "sha256:" + hex SHA-256 of raw payload or
// result bytes.
func SandboxContentDigestV1(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// opMembers names, per op, the optional members it carries. Every other
// optional member must be null (payload_bytes 0).
type opMembers struct {
	execID, path, payload, offset, limit, stream, timeout, maxOutput, recursive bool
	allowRoot                                                                   bool
	maxLimit                                                                    uint64
}

var sandboxOpMembers = map[string]opMembers{
	sandbox.OpExecStart:  {payload: true, timeout: true, maxOutput: true},
	sandbox.OpExecRead:   {execID: true, offset: true, limit: true, stream: true, maxLimit: sandbox.MaxChunkBytes},
	sandbox.OpExecCancel: {execID: true},
	sandbox.OpFileWrite:  {path: true, payload: true, offset: true},
	sandbox.OpFileRead:   {path: true, offset: true, limit: true, maxLimit: sandbox.MaxChunkBytes},
	sandbox.OpFileStat:   {path: true, allowRoot: true},
	sandbox.OpFileList:   {path: true, offset: true, limit: true, allowRoot: true, maxLimit: sandbox.MaxListEntries},
	sandbox.OpFileRemove: {path: true, recursive: true},
	sandbox.OpFileMkdir:  {path: true, recursive: true},
}

func leaseIDNames(leaseID, sandboxID, minerID string, generation uint64) bool {
	prefix := sandboxIdentity(sandboxID, minerID, generation, "")
	return strings.HasPrefix(leaseID, prefix) && lowercaseHex(strings.TrimPrefix(leaseID, prefix), 32)
}

func opIDNames(opID, leaseID string) bool {
	prefix := leaseID + "-op-"
	return strings.HasPrefix(opID, prefix) && lowercaseHex(strings.TrimPrefix(opID, prefix), 32)
}

// Validate checks a received op request; the signature must be present.
func (r SandboxOpRequestV1) Validate() error {
	if err := validateSandboxSignature(r.Signature, "op request"); err != nil {
		return err
	}
	return r.validateUnsigned()
}

func (r SandboxOpRequestV1) validateUnsigned() error {
	if r.Schema != SandboxOpRequestSchema || r.SchemaVersion != SandboxOpsSchemaVersion || r.WorkloadKind != sandbox.WorkloadKind {
		return errors.New("sandbox op request schema or workload kind is invalid")
	}
	if !validSandboxIdentity(r.SandboxID, r.MinerID, r.Generation) || !leaseIDNames(r.LeaseID, r.SandboxID, r.MinerID, r.Generation) ||
		!organic.ValidDigest(r.LeaseDigest) || !lowercaseHex(r.OpNonce, 32) {
		return errors.New("sandbox op request identity is invalid")
	}
	members, known := sandboxOpMembers[r.Op]
	if !known {
		return errors.New("sandbox op is invalid")
	}
	if err := members.check(r); err != nil {
		return err
	}
	if err := validateSandboxWindow(r.IssuedAt, r.ExpiresAt, sandbox.MaxOpWindow, "op"); err != nil {
		return err
	}
	return validateSandboxBinding(r.Subnet, r.MinerID)
}

func (m opMembers) check(r SandboxOpRequestV1) error {
	for _, member := range []struct {
		name    string
		allowed bool
		present bool
	}{
		{"exec_id", m.execID, r.ExecID != nil}, {"path", m.path, r.Path != nil},
		{"payload_digest", m.payload, r.PayloadDigest != nil}, {"offset", m.offset, r.Offset != nil},
		{"limit", m.limit, r.Limit != nil}, {"stream", m.stream, r.Stream != nil},
		{"timeout_ms", m.timeout, r.TimeoutMS != nil}, {"max_output_bytes", m.maxOutput, r.MaxOutputBytes != nil},
		{"recursive", m.recursive, r.Recursive != nil},
	} {
		if member.allowed != member.present {
			return errors.New("sandbox op " + r.Op + " member " + member.name + " is required exactly when the op uses it")
		}
	}
	if m.execID && !opIDNames(*r.ExecID, r.LeaseID) {
		return errors.New("exec_id does not name an op of this lease")
	}
	if m.path {
		if err := sandbox.ValidOpPath(*r.Path, m.allowRoot); err != nil {
			return err
		}
	}
	if m.payload {
		if !organic.ValidDigest(*r.PayloadDigest) || r.PayloadBytes < 1 || r.PayloadBytes > sandbox.MaxChunkBytes {
			return errors.New("sandbox op payload must be bound by digest and hold 1..524288 bytes")
		}
	} else if r.PayloadBytes != 0 {
		return errors.New("sandbox op without payload declares payload_bytes")
	}
	if m.limit && (*r.Limit < 1 || *r.Limit > m.maxLimit) {
		return errors.New("sandbox op limit is out of bounds")
	}
	if m.stream && *r.Stream != sandbox.ExecStdout && *r.Stream != sandbox.ExecStderr {
		return errors.New("exec_read stream must be stdout or stderr")
	}
	if m.timeout && (*r.TimeoutMS < sandbox.MinExecTimeoutMS || *r.TimeoutMS > sandbox.MaxExecTimeoutMS) {
		return errors.New("exec timeout_ms is out of bounds")
	}
	if m.maxOutput && (*r.MaxOutputBytes < sandbox.MinExecOutputBytes || *r.MaxOutputBytes > sandbox.MaxExecOutputBytes) {
		return errors.New("exec max_output_bytes is out of bounds")
	}
	switch r.Op {
	case sandbox.OpFileWrite:
		// Offset 0 creates or truncates and needs the permission bits; a
		// later chunk appends and inherits them.
		if (*r.Offset == 0) != (r.Mode != nil) {
			return errors.New("file_write mode is required exactly at offset 0")
		}
		if *r.Offset > sandbox.MaxFileWriteBytes || *r.Offset+r.PayloadBytes > sandbox.MaxFileWriteBytes {
			return errors.New("file_write exceeds the maximum writable file size")
		}
	case sandbox.OpFileMkdir:
		if r.Mode == nil {
			return errors.New("file_mkdir mode is required")
		}
	default:
		if r.Mode != nil {
			return errors.New("sandbox op " + r.Op + " member mode is required exactly when the op uses it")
		}
	}
	if r.Mode != nil && *r.Mode > sandbox.MaxFileModeBits {
		return errors.New("sandbox op mode must hold permission bits only")
	}
	return nil
}

// SandboxOpPayloadMatchesV1 checks the envelope payload against the signed
// binding. An op without a payload must arrive with none.
func SandboxOpPayloadMatchesV1(r SandboxOpRequestV1, payload []byte) error {
	if r.PayloadDigest == nil {
		if payload != nil {
			return errors.New("sandbox_op_payload_unexpected")
		}
		return nil
	}
	if uint64(len(payload)) != r.PayloadBytes || SandboxContentDigestV1(payload) != *r.PayloadDigest {
		return errors.New("sandbox_op_payload_mismatch")
	}
	return nil
}

// sandboxOpStages lists the receipt stages that may answer each op family.
var (
	execOpStages = map[string]bool{sandbox.OpStageRunning: true, sandbox.OpStageExited: true, sandbox.OpStageCancelled: true,
		sandbox.OpStageTimedOut: true, sandbox.OpStageRefused: true, sandbox.OpStageFailed: true}
	fileOpStages = map[string]bool{sandbox.OpStageCompleted: true, sandbox.OpStageRefused: true, sandbox.OpStageFailed: true,
		sandbox.OpStageTimedOut: true}
	execStateOfStage = map[string]string{sandbox.OpStageRunning: sandbox.ExecStateRunning, sandbox.OpStageExited: sandbox.ExecStateExited,
		sandbox.OpStageCancelled: sandbox.ExecStateCancelled, sandbox.OpStageTimedOut: sandbox.ExecStateTimedOut}
)

func isExecOp(op string) bool {
	return op == sandbox.OpExecStart || op == sandbox.OpExecRead || op == sandbox.OpExecCancel
}

func opHasResult(op string) bool {
	return op == sandbox.OpExecRead || op == sandbox.OpFileRead || op == sandbox.OpFileList
}

// Validate checks a received op receipt; the signature must be present.
func (r SandboxOpReceiptV1) Validate() error {
	if err := validateSandboxSignature(r.Signature, "op receipt"); err != nil {
		return err
	}
	return r.validateUnsigned()
}

func (r SandboxOpReceiptV1) validateUnsigned() error {
	if r.Schema != SandboxOpReceiptSchema || r.SchemaVersion != SandboxOpsSchemaVersion {
		return errors.New("sandbox op receipt schema is invalid")
	}
	if !validSandboxIdentity(r.SandboxID, r.MinerID, r.Generation) || !leaseIDNames(r.LeaseID, r.SandboxID, r.MinerID, r.Generation) ||
		!opIDNames(r.OpID, r.LeaseID) || !organic.ValidDigest(r.DocumentDigest) || !sandbox.ValidOp(r.Op) {
		return errors.New("sandbox op receipt identity is invalid")
	}
	execOp := isExecOp(r.Op)
	if (execOp && !execOpStages[r.Stage]) || (!execOp && !fileOpStages[r.Stage]) {
		return errors.New("op receipt stage does not answer op")
	}
	// A file op that ran out of its budget reports op_deadline_exceeded; an
	// exec that hit its own timeout is a customer outcome with no code.
	wantCode := r.Stage == sandbox.OpStageRefused || r.Stage == sandbox.OpStageFailed || (!execOp && r.Stage == sandbox.OpStageTimedOut)
	if wantCode != (r.ErrorCode != nil) {
		return errors.New("op_receipt_error_code_invalid")
	}
	if r.ErrorCode != nil {
		if _, known := sandbox.OpErrorAttribution[*r.ErrorCode]; !known {
			return errors.New("op receipt error_code is unknown")
		}
		if !execOp && r.Stage == sandbox.OpStageTimedOut && *r.ErrorCode != sandbox.OpCodeDeadline {
			return errors.New("timed out file op must report op_deadline_exceeded")
		}
	}
	if err := r.validateExec(execOp); err != nil {
		return err
	}
	fileInfo := (r.Op == sandbox.OpFileWrite || r.Op == sandbox.OpFileStat || r.Op == sandbox.OpFileMkdir) && r.Stage == sandbox.OpStageCompleted
	if fileInfo != (r.File != nil) {
		return errors.New("op receipt file member must be present exactly for a completed write, stat or mkdir")
	}
	if r.File != nil && (!sandbox.ValidFileType(r.File.Type) || r.File.Mode > sandbox.MaxFileModeBits) {
		return errors.New("op receipt file member is invalid")
	}
	result := opHasResult(r.Op) && (r.Stage == sandbox.OpStageCompleted || (execOp && execStateOfStage[r.Stage] != ""))
	if result != (r.ResultDigest != nil) || result != (r.NextOffset != nil) {
		return errors.New("op receipt result is present exactly for a successful read or list")
	}
	if result {
		if !organic.ValidDigest(*r.ResultDigest) || r.ResultBytes > sandbox.MaxChunkBytes {
			return errors.New("op receipt result binding is invalid")
		}
	} else if r.ResultBytes != 0 || r.EOF {
		return errors.New("op receipt without a result declares result bytes or eof")
	}
	if _, err := parseStaticTime(r.ObservedAt); err != nil {
		return err
	}
	return validateSandboxBinding(r.Subnet, r.MinerID)
}

func (r SandboxOpReceiptV1) validateExec(execOp bool) error {
	wantState, sessionStage := execStateOfStage[r.Stage]
	switch {
	case !execOp || r.Stage == sandbox.OpStageRefused:
		if r.Exec != nil {
			return errors.New("op receipt names an exec it does not answer")
		}
		return nil
	case sessionStage:
		if r.Exec == nil || r.Exec.State != wantState {
			return errors.New("op receipt exec state contradicts its stage")
		}
	case r.Stage == sandbox.OpStageFailed:
		// A failure before the session existed has no exec member.
		if r.Exec == nil {
			return nil
		}
		if r.Exec.State != sandbox.ExecStateFailed {
			return errors.New("failed op receipt exec state must be failed")
		}
	}
	e := r.Exec
	if _, err := parseStaticTime(e.StartedAt); err != nil {
		return err
	}
	if (e.State == sandbox.ExecStateRunning) != (e.EndedAt == nil) {
		return errors.New("exec ended_at is present exactly for a terminal exec")
	}
	if e.EndedAt != nil {
		started, _ := parseStaticTime(e.StartedAt)
		ended, err := parseStaticTime(*e.EndedAt)
		if err != nil || ended.Before(started) {
			return errors.New("exec ended_at is invalid")
		}
	}
	if (e.State == sandbox.ExecStateExited) != (e.ExitCode != nil) || (e.ExitCode != nil && (*e.ExitCode < 0 || *e.ExitCode > 255)) {
		return errors.New("exec exit_code is present exactly for an exited exec, 0..255")
	}
	if e.StdoutRetained > e.StdoutBytes || e.StderrRetained > e.StderrBytes ||
		e.StdoutRetained > sandbox.MaxExecOutputBytes || e.StderrRetained > sandbox.MaxExecOutputBytes {
		return errors.New("exec retained output exceeds output or cap")
	}
	return nil
}

// SignSandboxOpRequestV1 signs r with the validator Go service key.
func SignSandboxOpRequestV1(r *SandboxOpRequestV1, key ed25519.PrivateKey) error {
	if r == nil {
		return errors.New("invalid sandbox op request signing input")
	}
	return signSandbox(SandboxOpRequestSigningDomain, r.validateUnsigned, *r, key, &r.Signature)
}

// SignSandboxOpReceiptV1 signs r with the miner Go service key.
func SignSandboxOpReceiptV1(r *SandboxOpReceiptV1, key ed25519.PrivateKey) error {
	if r == nil {
		return errors.New("invalid sandbox op receipt signing input")
	}
	return signSandbox(SandboxOpReceiptSigningDomain, r.validateUnsigned, *r, key, &r.Signature)
}

// VerifySandboxOpRequestV1Signature verifies the bound validator service key
// signature without a wall-clock or chain decision.
func VerifySandboxOpRequestV1Signature(r SandboxOpRequestV1, key ed25519.PublicKey) error {
	return verifySandbox(SandboxOpRequestSigningDomain, r.Validate, r, r.Signature, bindingValidatorKey(r.Subnet), key)
}

// VerifySandboxOpReceiptV1 verifies the bound miner service key signature.
func VerifySandboxOpReceiptV1(r SandboxOpReceiptV1, key ed25519.PublicKey) error {
	minerKey := ""
	if r.Subnet != nil {
		minerKey = r.Subnet.MinerServicePublicKey
	}
	return verifySandbox(SandboxOpReceiptSigningDomain, r.Validate, r, r.Signature, minerKey, key)
}

// VerifyBoundSandboxOpRequestV1 is the miner admission check of an op
// request: signature, admission window and request-local binding, exactly
// as for the lease documents. It does not decide whether the lease is
// running; see SandboxOpTargetsLeaseV1 and the miner's durable state.
func VerifyBoundSandboxOpRequestV1(r SandboxOpRequestV1, key ed25519.PublicKey, now time.Time, currentBlock uint64, network string, netuid uint16, callerHotkey, minerHotkey string, minerUID *uint16) error {
	if err := VerifySandboxOpRequestV1Signature(r, key); err != nil {
		return err
	}
	return sandboxAdmission(r.Subnet, r.MinerID, r.IssuedAt, r.ExpiresAt, now, currentBlock, network, netuid, callerHotkey, minerHotkey, minerUID)
}

// SandboxOpTargetsLeaseV1 is the identity fence between an op and the lease
// it drives: the op names that exact signed lease (digest and derived
// lease_id), the same sandbox, generation and miner, and the same parties.
// Another validator, a stale generation or a guessed lease_id fails.
func SandboxOpTargetsLeaseV1(r SandboxOpRequestV1, lease SandboxLeaseV1) error {
	digest, err := SandboxDigestV1(lease)
	if err != nil {
		return err
	}
	if r.LeaseDigest != digest || r.LeaseID != SandboxLeaseIDV1(lease) || r.SandboxID != lease.SandboxID ||
		r.Generation != lease.Generation || r.MinerID != lease.MinerID || !sameSandboxParties(r.Subnet, lease.Subnet) {
		return errors.New("sandbox op does not target the lease")
	}
	return nil
}

// SandboxOpReceiptAnswersV1 is the validator's acceptance check of a receipt
// and the result bytes that came with it, against the complete request.
func SandboxOpReceiptAnswersV1(r SandboxOpReceiptV1, request SandboxOpRequestV1, result []byte) error {
	digest, err := SandboxOpDigestV1(request)
	if err != nil {
		return err
	}
	if r.DocumentDigest != digest || r.Op != request.Op || r.OpID != SandboxOpIDV1(request) || r.LeaseID != request.LeaseID ||
		r.SandboxID != request.SandboxID || r.Generation != request.Generation || r.MinerID != request.MinerID ||
		!sameSandboxParties(r.Subnet, request.Subnet) {
		return errors.New("sandbox op receipt does not answer the request")
	}
	if r.ResultDigest == nil {
		if result != nil {
			return errors.New("sandbox op receipt carries no result but bytes were returned")
		}
		return nil
	}
	if uint64(len(result)) != r.ResultBytes || SandboxContentDigestV1(result) != *r.ResultDigest {
		return errors.New("sandbox op result does not match its receipt binding")
	}
	switch request.Op {
	case sandbox.OpFileRead, sandbox.OpExecRead:
		if r.ResultBytes > *request.Limit || *r.NextOffset != *request.Offset+r.ResultBytes {
			return errors.New("sandbox op read result contradicts its offset or limit")
		}
		if request.Op == sandbox.OpExecRead {
			retained := r.Exec.StdoutRetained
			if *request.Stream == sandbox.ExecStderr {
				retained = r.Exec.StderrRetained
			}
			terminal := r.Exec.State != sandbox.ExecStateRunning
			if (*r.NextOffset > retained && r.ResultBytes != 0) || r.EOF != (terminal && *r.NextOffset >= retained) {
				return errors.New("sandbox exec_read result contradicts the retained stream")
			}
		}
	case sandbox.OpFileList:
		var listing sandbox.ListResult
		if err := decodeListResult(result, &listing); err != nil {
			return err
		}
		if uint64(len(listing.Entries)) > *request.Limit || *r.NextOffset != *request.Offset+uint64(len(listing.Entries)) {
			return errors.New("sandbox file_list result contradicts its offset or limit")
		}
	}
	return nil
}

// SandboxExecNeverStartedV1 is the definitive non-start rule for an
// exec_start whose outcome is unknown (contract D13). It holds only when
// readReceipt is a verified, accepted answer to readRequest; readRequest is
// an exec_read or exec_cancel naming start's op ID on the same lease;
// the receipt refuses with exec_not_found; and the miner signed it at or
// after start.expires_at plus the issue skew. From then on start is
// inadmissible by the miner's own clock, and the miner records every
// admitted exec_start before any effect and keeps that record until lease
// cleanup, so exec_not_found means the exec never started and never will.
// An earlier exec_not_found is not definitive: start may still be in
// flight. A miner that later reports start as started has signed a
// contradiction of this receipt.
func SandboxExecNeverStartedV1(readReceipt SandboxOpReceiptV1, readRequest, start SandboxOpRequestV1) (bool, error) {
	if start.Op != sandbox.OpExecStart || (readRequest.Op != sandbox.OpExecRead && readRequest.Op != sandbox.OpExecCancel) ||
		readRequest.ExecID == nil || *readRequest.ExecID != SandboxOpIDV1(start) || readRequest.LeaseID != start.LeaseID ||
		readRequest.LeaseDigest != start.LeaseDigest || !sameSandboxParties(readRequest.Subnet, start.Subnet) {
		return false, errors.New("sandbox exec resolution request does not name the exec_start")
	}
	if err := SandboxOpReceiptAnswersV1(readReceipt, readRequest, nil); err != nil {
		return false, err
	}
	if readReceipt.Stage != sandbox.OpStageRefused || readReceipt.ErrorCode == nil || *readReceipt.ErrorCode != "exec_not_found" {
		return false, nil
	}
	observed, err := parseStaticTime(readReceipt.ObservedAt)
	if err != nil {
		return false, err
	}
	deadline, err := parseStaticTime(start.ExpiresAt)
	if err != nil {
		return false, err
	}
	return !observed.Before(deadline.Add(sandbox.IssueSkew)), nil
}

// DecodeSandboxListResultV1 strictly decodes a file_list result body and
// checks its entries: addressable names, sorted unique, valid file info.
func DecodeSandboxListResultV1(result []byte) (sandbox.ListResult, error) {
	var listing sandbox.ListResult
	return listing, decodeListResult(result, &listing)
}

func decodeListResult(result []byte, listing *sandbox.ListResult) error {
	if err := organic.DecodeStrict(result, listing); err != nil {
		return errors.New("sandbox file_list result is invalid")
	}
	return nil
}

// SandboxOpDigestV1 is "sha256:" + hex(SHA-256(canonical JSON of the
// complete signed document)), the static-v1 digest rule.
func SandboxOpDigestV1(document any) (string, error) {
	switch document.(type) {
	case SandboxOpRequestV1, SandboxOpReceiptV1:
		return staticDigest(document)
	}
	return "", errors.New("not a sandbox-ops-v1 document")
}
