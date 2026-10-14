// SPDX-License-Identifier: AGPL-3.0-only

package protocol_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/organic"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	"github.com/misscomputer/misscomputer-subnet/pkg/sandbox"
)

var updateSandboxOpsVectors = flag.Bool("update-sandbox-ops-vectors", false, "rewrite testdata/sandbox-ops-v1-vectors.json")

func u64(value uint64) *uint64 { return &value }
func u32(value uint32) *uint32 { return &value }
func str(value string) *string { return &value }
func boolean(value bool) *bool { return &value }

var opNow = sandboxNow.Add(time.Minute)

func opLease(t *testing.T) (validator, miner ed25519.PrivateKey, lease protocol.SandboxLeaseV1) {
	t.Helper()
	validator, miner = sandboxKeys()
	return validator, miner, sandboxLease(t, validator, miner, sandboxReservation(t, validator, miner), nil)
}

// unsignedOp returns an unsigned, valid request of op against lease with
// exactly the members that op uses.
func unsignedOp(t *testing.T, lease protocol.SandboxLeaseV1, op string) protocol.SandboxOpRequestV1 {
	t.Helper()
	digest, err := protocol.SandboxDigestV1(lease)
	if err != nil {
		t.Fatal(err)
	}
	leaseID := protocol.SandboxLeaseIDV1(lease)
	payload := protocol.SandboxContentDigestV1([]byte("payload"))
	r := protocol.SandboxOpRequestV1{
		ExpiresAt: stamp(opNow.Add(30 * time.Second)), Generation: lease.Generation, IssuedAt: stamp(opNow), LeaseDigest: digest,
		LeaseID: leaseID, MinerID: lease.MinerID, Op: op, OpNonce: strings.Repeat("d4", 16), SandboxID: lease.SandboxID,
		Schema: protocol.SandboxOpRequestSchema, SchemaVersion: 1, Subnet: lease.Subnet, WorkloadKind: sandbox.WorkloadKind,
	}
	execID := leaseID + "-op-" + strings.Repeat("e5", 16)
	switch op {
	case sandbox.OpExecStart:
		r.PayloadDigest, r.PayloadBytes, r.TimeoutMS, r.MaxOutputBytes = &payload, 7, u64(600000), u64(1<<20)
	case sandbox.OpExecRead:
		r.ExecID, r.Offset, r.Limit, r.Stream = &execID, u64(0), u64(65536), str(sandbox.ExecStdout)
	case sandbox.OpExecCancel:
		r.ExecID = &execID
	case sandbox.OpFileWrite:
		r.Path, r.PayloadDigest, r.PayloadBytes, r.Offset, r.Mode = str("/workspace/main.py"), &payload, 7, u64(0), u32(0o644)
	case sandbox.OpFileRead:
		r.Path, r.Offset, r.Limit = str("/workspace/main.py"), u64(0), u64(65536)
	case sandbox.OpFileStat:
		r.Path = str("/")
	case sandbox.OpFileList:
		r.Path, r.Offset, r.Limit = str("/workspace"), u64(0), u64(100)
	case sandbox.OpFileRemove:
		r.Path, r.Recursive = str("/workspace/build"), boolean(true)
	case sandbox.OpFileMkdir:
		r.Path, r.Mode, r.Recursive = str("/workspace/out"), u32(0o755), boolean(true)
	default:
		t.Fatalf("unknown op %s", op)
	}
	return r
}

func signedOp(t *testing.T, validator ed25519.PrivateKey, r protocol.SandboxOpRequestV1) protocol.SandboxOpRequestV1 {
	t.Helper()
	if err := protocol.SignSandboxOpRequestV1(&r, validator); err != nil {
		t.Fatal(err)
	}
	return r
}

func baseOpReceipt(t *testing.T, request protocol.SandboxOpRequestV1) protocol.SandboxOpReceiptV1 {
	t.Helper()
	digest, err := protocol.SandboxOpDigestV1(request)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.SandboxOpReceiptV1{
		DocumentDigest: digest, Generation: request.Generation, LeaseID: request.LeaseID, MinerID: request.MinerID,
		ObservedAt: stamp(opNow.Add(2 * time.Minute)), Op: request.Op, OpID: protocol.SandboxOpIDV1(request), SandboxID: request.SandboxID,
		Schema: protocol.SandboxOpReceiptSchema, SchemaVersion: 1, Stage: sandbox.OpStageCompleted, Subnet: request.Subnet,
	}
}

func opReceipt(t *testing.T, miner ed25519.PrivateKey, request protocol.SandboxOpRequestV1, mutate func(*protocol.SandboxOpReceiptV1)) protocol.SandboxOpReceiptV1 {
	t.Helper()
	r := baseOpReceipt(t, request)
	if mutate != nil {
		mutate(&r)
	}
	if err := protocol.SignSandboxOpReceiptV1(&r, miner); err != nil {
		t.Fatal(err)
	}
	return r
}

func runningExec(stdout, stderr uint64) *sandbox.ExecStatus {
	return &sandbox.ExecStatus{StartedAt: stamp(opNow), State: sandbox.ExecStateRunning,
		StdoutBytes: stdout, StdoutRetained: stdout, StderrBytes: stderr, StderrRetained: stderr}
}

func exitedExec(code int, stdout uint64) *sandbox.ExecStatus {
	e := runningExec(stdout, 0)
	e.State, e.ExitCode, e.EndedAt = sandbox.ExecStateExited, &code, str(stamp(opNow.Add(2*time.Second)))
	return e
}

func timedOutExec() *sandbox.ExecStatus {
	e := runningExec(5, 0)
	e.State, e.EndedAt = sandbox.ExecStateTimedOut, str(stamp(opNow.Add(time.Minute)))
	return e
}

func withResult(r *protocol.SandboxOpReceiptV1, body []byte, next uint64) {
	r.ResultDigest, r.ResultBytes, r.NextOffset = str(protocol.SandboxContentDigestV1(body)), uint64(len(body)), u64(next)
}

type sandboxOpsVectorSet struct {
	ExecPayload      string          `json:"exec_start_payload"`
	ExecRead         json.RawMessage `json:"exec_read"`
	ExecReadReceipt  json.RawMessage `json:"exec_read_receipt"`
	ExecReadResult   string          `json:"exec_read_result"`
	ExecStart        json.RawMessage `json:"exec_start"`
	ExecStartDigest  string          `json:"exec_start_digest"`
	FileList         json.RawMessage `json:"file_list"`
	FileListReceipt  json.RawMessage `json:"file_list_receipt"`
	FileListResult   string          `json:"file_list_result"`
	FileWrite        json.RawMessage `json:"file_write"`
	FileWritePayload string          `json:"file_write_payload"`
	FileWriteReceipt json.RawMessage `json:"file_write_receipt"`
	LeaseDigest      string          `json:"lease_digest"`
	Negative         []opNegative    `json:"negative"`
	OpID             string          `json:"exec_start_op_id"`
	RefusedReceipt   json.RawMessage `json:"exec_start_refused_receipt"`
}

// opNegative is a document every implementation must refuse. Except for the
// duplicate-member case, its signature is valid for its kind's domain and
// bound key, so the refusal must come from decoding or validation.
type opNegative struct {
	Document       string `json:"document"`
	Kind           string `json:"kind"`
	Name           string `json:"name"`
	SignatureValid bool   `json:"signature_valid"`
}

// resignedMembers returns document's canonical members after mutate, signed
// over the mutated members under domain, bypassing validation.
func resignedMembers(t *testing.T, key ed25519.PrivateKey, domain string, document any, mutate func(map[string]any)) string {
	t.Helper()
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	var members map[string]any
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err := decoder.Decode(&members); err != nil {
		t.Fatal(err)
	}
	mutate(members)
	members["signature"] = hex.EncodeToString(ed25519.Sign(key, signedMessage(t, domain, members)))
	return string(canonicalJSON(t, members))
}

func opNegatives(t *testing.T, validator, miner ed25519.PrivateKey, lease protocol.SandboxLeaseV1) []opNegative {
	t.Helper()
	read := signedOp(t, validator, unsignedOp(t, lease, sandbox.OpFileRead))
	stat := signedOp(t, validator, unsignedOp(t, lease, sandbox.OpFileStat))
	start := signedOp(t, validator, unsignedOp(t, lease, sandbox.OpExecStart))
	remove := signedOp(t, validator, unsignedOp(t, lease, sandbox.OpFileRemove))
	request := func(name string, document protocol.SandboxOpRequestV1, mutate func(map[string]any)) opNegative {
		return opNegative{Name: name, Kind: "request", SignatureValid: true,
			Document: resignedMembers(t, validator, protocol.SandboxOpRequestSigningDomain, document, mutate)}
	}
	receipt := func(name string, document protocol.SandboxOpReceiptV1, mutate func(map[string]any)) opNegative {
		return opNegative{Name: name, Kind: "receipt", SignatureValid: true,
			Document: resignedMembers(t, miner, protocol.SandboxOpReceiptSigningDomain, document, mutate)}
	}
	duplicate := string(canonicalJSON(t, read))
	duplicate = `{"path":"/etc/shadow",` + duplicate[1:]
	return []opNegative{
		request("request case-variant member", read, func(m map[string]any) { m["PATH"] = "/etc/shadow" }),
		{Name: "request duplicate member", Kind: "request", Document: duplicate},
		request("request path traversal", read, func(m map[string]any) { m["path"] = "/workspace/../etc/shadow" }),
		request("request path with a control byte", read, func(m map[string]any) { m["path"] = "/work\tspace" }),
		request("request member the op does not use", stat, func(m map[string]any) { m["limit"] = 1 }),
		request("request missing member", stat, func(m map[string]any) { delete(m, "recursive") }),
		request("request window over 60 s", stat, func(m map[string]any) { m["expires_at"] = stamp(opNow.Add(61 * time.Second)) }),
		request("request offset past 2^53-1", read, func(m map[string]any) { m["offset"] = json.Number("9007199254740992") }),
		request("request exec_id of another lease", signedOp(t, validator, unsignedOp(t, lease, sandbox.OpExecCancel)), func(m map[string]any) {
			m["exec_id"] = "sbx-" + strings.Repeat("1e", 16) + "-5Fminer-g1-" + strings.Repeat("b2", 16) + "-op-" + strings.Repeat("e5", 16)
		}),
		receipt("receipt stage does not answer op", baseOpReceipt(t, start), func(m map[string]any) {}),
		receipt("receipt case-variant member", opReceipt(t, miner, remove, nil), func(m map[string]any) { m["Stage"] = "failed" }),
		receipt("receipt result on a non-read op", opReceipt(t, miner, remove, nil), func(m map[string]any) {
			m["result_digest"], m["next_offset"] = protocol.SandboxContentDigestV1(nil), 0
		}),
		receipt("receipt unknown error code", opReceipt(t, miner, remove, nil), func(m map[string]any) {
			m["stage"], m["error_code"] = "refused", "tenant_mismatch"
		}),
		receipt("receipt exec ended after observed_at", opReceipt(t, miner, start, func(r *protocol.SandboxOpReceiptV1) {
			r.Stage, r.Exec = sandbox.OpStageExited, exitedExec(0, 0)
		}), func(m map[string]any) {
			m["exec"].(map[string]any)["ended_at"] = stamp(opNow.Add(time.Hour))
		}),
	}
}

// The op documents are pinned as cross-language vectors from the same test
// seeds and lease as sandbox-lease-v1-vectors.json: canonical bytes, digests
// and signatures must reproduce in every implementation.
func TestSandboxOpDocumentsMatchGoldenVectors(t *testing.T) {
	validator, miner, lease := opLease(t)
	leaseDigest, _ := protocol.SandboxDigestV1(lease)
	payload := []byte(`{"argv":["python","-m","pytest","-q"],"cwd":"/workspace","env":{},"stdin_b64":null}`)
	start := unsignedOp(t, lease, sandbox.OpExecStart)
	start.PayloadDigest, start.PayloadBytes = str(protocol.SandboxContentDigestV1(payload)), uint64(len(payload))
	start = signedOp(t, validator, start)
	startDigest, _ := protocol.SandboxOpDigestV1(start)

	read := unsignedOp(t, lease, sandbox.OpExecRead)
	read.OpNonce, read.ExecID = strings.Repeat("f6", 16), str(protocol.SandboxOpIDV1(start))
	read = signedOp(t, validator, read)
	output := []byte("3 passed in 0.42s\n")
	readReceipt := opReceipt(t, miner, read, func(r *protocol.SandboxOpReceiptV1) {
		r.Stage, r.Exec, r.EOF = sandbox.OpStageExited, exitedExec(0, uint64(len(output))), true
		withResult(r, output, uint64(len(output)))
	})

	list := unsignedOp(t, lease, sandbox.OpFileList)
	list.OpNonce = strings.Repeat("a7", 16)
	list = signedOp(t, validator, list)
	listing, err := organic.Canonical(sandbox.ListResult{Entries: []sandbox.ListEntry{
		{FileInfo: sandbox.FileInfo{Mode: 0o755, Size: 4096, Type: sandbox.FileTypeDirectory}, Name: "tests"},
		{FileInfo: sandbox.FileInfo{Mode: 0o777, Size: 7, Type: sandbox.FileTypeSymlink}, Name: "venv"},
	}, Unaddressable: 1})
	if err != nil {
		t.Fatal(err)
	}
	listReceipt := opReceipt(t, miner, list, func(r *protocol.SandboxOpReceiptV1) {
		r.EOF = true
		withResult(r, listing, 2)
	})

	writePayload := []byte("print('hello')\n")
	write := unsignedOp(t, lease, sandbox.OpFileWrite)
	write.OpNonce, write.PayloadDigest, write.PayloadBytes = strings.Repeat("c5", 16), str(protocol.SandboxContentDigestV1(writePayload)), uint64(len(writePayload))
	write = signedOp(t, validator, write)
	writeReceipt := opReceipt(t, miner, write, func(r *protocol.SandboxOpReceiptV1) {
		r.File = &sandbox.FileInfo{Mode: 0o644, Size: uint64(len(writePayload)), Type: sandbox.FileTypeFile}
	})
	refused := opReceipt(t, miner, start, func(r *protocol.SandboxOpReceiptV1) {
		r.Stage, r.ErrorCode = sandbox.OpStageRefused, str("sandbox_exited")
	})

	got := sandboxOpsVectorSet{
		ExecStart: canonicalJSON(t, start), ExecStartDigest: startDigest, ExecPayload: string(payload), OpID: protocol.SandboxOpIDV1(start),
		ExecRead: canonicalJSON(t, read), ExecReadReceipt: canonicalJSON(t, readReceipt), ExecReadResult: string(output),
		FileList: canonicalJSON(t, list), FileListReceipt: canonicalJSON(t, listReceipt), FileListResult: string(listing),
		LeaseDigest: leaseDigest, FileWrite: canonicalJSON(t, write), FileWritePayload: string(writePayload),
		FileWriteReceipt: canonicalJSON(t, writeReceipt), RefusedReceipt: canonicalJSON(t, refused),
		Negative: opNegatives(t, validator, miner, lease),
	}
	rendered, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	rendered = append(rendered, '\n')
	path := filepath.Join("testdata", "sandbox-ops-v1-vectors.json")
	if *updateSandboxOpsVectors {
		if err := os.WriteFile(path, rendered, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, rendered) {
		t.Fatalf("sandbox ops vectors changed; rerun with -update-sandbox-ops-vectors only for an intended contract change\n%s", rendered)
	}
	var vectors sandboxOpsVectorSet
	if err := json.Unmarshal(want, &vectors); err != nil {
		t.Fatal(err)
	}
	var decodedStart, decodedRead, decodedList, decodedWrite protocol.SandboxOpRequestV1
	var decodedReadReceipt, decodedListReceipt, decodedWriteReceipt, decodedRefused protocol.SandboxOpReceiptV1
	for raw, document := range map[*json.RawMessage]organic.Validator{
		&vectors.ExecStart: &decodedStart, &vectors.ExecRead: &decodedRead, &vectors.FileList: &decodedList,
		&vectors.ExecReadReceipt: &decodedReadReceipt, &vectors.FileListReceipt: &decodedListReceipt,
		&vectors.FileWrite: &decodedWrite, &vectors.FileWriteReceipt: &decodedWriteReceipt, &vectors.RefusedReceipt: &decodedRefused,
	} {
		if err := organic.DecodeStrict(*raw, document); err != nil {
			t.Fatalf("decode pinned vector: %v", err)
		}
	}
	if _, err := sandbox.DecodeExecCommand([]byte(vectors.ExecPayload)); err != nil {
		t.Fatalf("pinned exec payload: %v", err)
	}
	validatorKey, minerKey := validator.Public().(ed25519.PublicKey), miner.Public().(ed25519.PublicKey)
	for name, err := range map[string]error{
		"start":         protocol.VerifySandboxOpRequestV1Signature(decodedStart, validatorKey),
		"read":          protocol.VerifySandboxOpRequestV1Signature(decodedRead, validatorKey),
		"list":          protocol.VerifySandboxOpRequestV1Signature(decodedList, validatorKey),
		"read receipt":  protocol.VerifySandboxOpReceiptV1(decodedReadReceipt, minerKey),
		"list receipt":  protocol.VerifySandboxOpReceiptV1(decodedListReceipt, minerKey),
		"start fence":   protocol.SandboxOpTargetsLeaseV1(decodedStart, lease),
		"payload":       protocol.SandboxOpPayloadMatchesV1(decodedStart, []byte(vectors.ExecPayload)),
		"read answers":  protocol.SandboxOpReceiptAnswersV1(decodedReadReceipt, decodedRead, []byte(vectors.ExecReadResult)),
		"list answers":  protocol.SandboxOpReceiptAnswersV1(decodedListReceipt, decodedList, []byte(vectors.FileListResult)),
		"write payload": protocol.SandboxOpPayloadMatchesV1(decodedWrite, []byte(vectors.FileWritePayload)),
		"write answers": protocol.SandboxOpReceiptAnswersV1(decodedWriteReceipt, decodedWrite, nil),
		"refused":       protocol.SandboxOpReceiptAnswersV1(decodedRefused, decodedStart, nil),
		"write receipt": protocol.VerifySandboxOpReceiptV1(decodedWriteReceipt, minerKey),
	} {
		if err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(vectors.Negative) == 0 {
		t.Fatal("no negative vectors")
	}
	for _, negative := range vectors.Negative {
		key, domain := validatorKey, protocol.SandboxOpRequestSigningDomain
		var document organic.Validator = &protocol.SandboxOpRequestV1{}
		if negative.Kind == "receipt" {
			key, domain, document = minerKey, protocol.SandboxOpReceiptSigningDomain, &protocol.SandboxOpReceiptV1{}
		}
		if negative.SignatureValid {
			var members map[string]any
			decoder := json.NewDecoder(strings.NewReader(negative.Document))
			decoder.UseNumber()
			if err := decoder.Decode(&members); err != nil {
				t.Fatalf("%s: %v", negative.Name, err)
			}
			signature, _ := hex.DecodeString(members["signature"].(string))
			if !ed25519.Verify(key, signedMessage(t, domain, members), signature) {
				t.Fatalf("%s: negative vector signature must be valid so the refusal is semantic", negative.Name)
			}
		}
		if err := organic.DecodeStrict([]byte(negative.Document), document); err == nil {
			t.Errorf("negative vector %q decoded and validated", negative.Name)
		}
	}
}

// An op signature verifies only under the op request domain and the bound
// validator service key; a lease never decodes as an op.
func TestSandboxOpSignaturesAreDomainAndKeySeparated(t *testing.T) {
	validator, miner, lease := opLease(t)
	key := validator.Public().(ed25519.PublicKey)
	request := signedOp(t, validator, unsignedOp(t, lease, sandbox.OpExecCancel))
	if err := protocol.VerifySandboxOpRequestV1Signature(request, key); err != nil {
		t.Fatal(err)
	}
	for _, domain := range []string{protocol.SandboxLeaseSigningDomain, protocol.SandboxOpReceiptSigningDomain, protocol.SandboxReleaseSigningDomain} {
		forged := request
		forged.Signature = hex.EncodeToString(ed25519.Sign(validator, signedMessage(t, domain, request)))
		if protocol.VerifySandboxOpRequestV1Signature(forged, key) == nil {
			t.Errorf("op request verified under %s", domain)
		}
	}
	minerSigned := unsignedOp(t, lease, sandbox.OpExecCancel)
	if err := protocol.SignSandboxOpRequestV1(&minerSigned, miner); err != nil {
		t.Fatal(err)
	}
	if protocol.VerifySandboxOpRequestV1Signature(minerSigned, miner.Public().(ed25519.PublicKey)) == nil {
		t.Error("a request signed by a key other than the bound validator service key verified")
	}
	var asOp protocol.SandboxOpRequestV1
	if organic.DecodeStrict(canonicalJSON(t, lease), &asOp) == nil {
		t.Error("a lease decoded as an op request")
	}
}

// Each op carries exactly the members it uses: dropping a required member
// or adding one the op does not use fails validation and signing.
func TestSandboxOpMembersAreExactPerOp(t *testing.T) {
	validator, _, lease := opLease(t)
	leaseID := protocol.SandboxLeaseIDV1(lease)
	toggles := map[string]func(*protocol.SandboxOpRequestV1) bool{
		"exec_id": func(r *protocol.SandboxOpRequestV1) bool {
			had := r.ExecID != nil
			r.ExecID = map[bool]*string{false: str(leaseID + "-op-" + strings.Repeat("e5", 16)), true: nil}[had]
			return had
		},
		"path": func(r *protocol.SandboxOpRequestV1) bool {
			had := r.Path != nil
			r.Path = map[bool]*string{false: str("/workspace/x"), true: nil}[had]
			return had
		},
		"payload": func(r *protocol.SandboxOpRequestV1) bool {
			had := r.PayloadDigest != nil
			r.PayloadDigest, r.PayloadBytes = nil, 0
			if !had {
				r.PayloadDigest, r.PayloadBytes = str(protocol.SandboxContentDigestV1([]byte("x"))), 1
			}
			return had
		},
		"offset": func(r *protocol.SandboxOpRequestV1) bool {
			had := r.Offset != nil
			r.Offset = map[bool]*uint64{false: u64(0), true: nil}[had]
			return had
		},
		"limit": func(r *protocol.SandboxOpRequestV1) bool {
			had := r.Limit != nil
			r.Limit = map[bool]*uint64{false: u64(1), true: nil}[had]
			return had
		},
		"stream": func(r *protocol.SandboxOpRequestV1) bool {
			had := r.Stream != nil
			r.Stream = map[bool]*string{false: str(sandbox.ExecStderr), true: nil}[had]
			return had
		},
		"timeout_ms": func(r *protocol.SandboxOpRequestV1) bool {
			had := r.TimeoutMS != nil
			r.TimeoutMS = map[bool]*uint64{false: u64(1000), true: nil}[had]
			return had
		},
		"max_output_bytes": func(r *protocol.SandboxOpRequestV1) bool {
			had := r.MaxOutputBytes != nil
			r.MaxOutputBytes = map[bool]*uint64{false: u64(1024), true: nil}[had]
			return had
		},
		"mode": func(r *protocol.SandboxOpRequestV1) bool {
			had := r.Mode != nil
			r.Mode = map[bool]*uint32{false: u32(0o600), true: nil}[had]
			return had
		},
		"recursive": func(r *protocol.SandboxOpRequestV1) bool {
			had := r.Recursive != nil
			r.Recursive = map[bool]*bool{false: boolean(false), true: nil}[had]
			return had
		},
	}
	for _, op := range []string{sandbox.OpExecStart, sandbox.OpExecRead, sandbox.OpExecCancel, sandbox.OpFileWrite, sandbox.OpFileRead,
		sandbox.OpFileStat, sandbox.OpFileList, sandbox.OpFileRemove, sandbox.OpFileMkdir} {
		base := unsignedOp(t, lease, op)
		signedOp(t, validator, base)
		for member, toggle := range toggles {
			mutated := base
			had := toggle(&mutated)
			if err := protocol.SignSandboxOpRequestV1(&mutated, validator); err == nil {
				t.Errorf("%s: toggling %s (was present=%v) still signed", op, member, had)
			}
		}
	}
}

func TestSandboxOpRequestBounds(t *testing.T) {
	validator, miner, lease := opLease(t)
	sibling := sandboxLease(t, validator, miner, sandboxReservation(t, validator, miner), func(l *protocol.SandboxLeaseV1) {
		l.AssignmentNonce = strings.Repeat("c3", 16)
	})
	type mutation func(*protocol.SandboxOpRequestV1)
	cases := map[string]struct {
		op     string
		mutate mutation
	}{
		"window over 60s":           {sandbox.OpFileStat, func(r *protocol.SandboxOpRequestV1) { r.ExpiresAt = stamp(opNow.Add(61 * time.Second)) }},
		"window inverted":           {sandbox.OpFileStat, func(r *protocol.SandboxOpRequestV1) { r.ExpiresAt = r.IssuedAt }},
		"op unknown":                {sandbox.OpFileStat, func(r *protocol.SandboxOpRequestV1) { r.Op = "file_chmod" }},
		"nonce short":               {sandbox.OpFileStat, func(r *protocol.SandboxOpRequestV1) { r.OpNonce = "abc" }},
		"lease_id other sandbox":    {sandbox.OpFileStat, func(r *protocol.SandboxOpRequestV1) { r.SandboxID = "sbx-" + strings.Repeat("1e", 16) }},
		"lease_id other generation": {sandbox.OpFileStat, func(r *protocol.SandboxOpRequestV1) { r.Generation = 2 }},
		"lease digest invalid":      {sandbox.OpFileStat, func(r *protocol.SandboxOpRequestV1) { r.LeaseDigest = "sha256:00" }},
		"exec_id of sibling lease": {sandbox.OpExecCancel, func(r *protocol.SandboxOpRequestV1) {
			r.ExecID = str(protocol.SandboxLeaseIDV1(sibling) + "-op-" + strings.Repeat("e5", 16))
		}},
		"exec_id not an op":           {sandbox.OpExecCancel, func(r *protocol.SandboxOpRequestV1) { r.ExecID = str(r.LeaseID) }},
		"read limit zero":             {sandbox.OpFileRead, func(r *protocol.SandboxOpRequestV1) { r.Limit = u64(0) }},
		"read limit over chunk":       {sandbox.OpFileRead, func(r *protocol.SandboxOpRequestV1) { r.Limit = u64(sandbox.MaxChunkBytes + 1) }},
		"list limit over 1000":        {sandbox.OpFileList, func(r *protocol.SandboxOpRequestV1) { r.Limit = u64(1001) }},
		"exec_read stream invalid":    {sandbox.OpExecRead, func(r *protocol.SandboxOpRequestV1) { r.Stream = str("stdin") }},
		"timeout under 1s":            {sandbox.OpExecStart, func(r *protocol.SandboxOpRequestV1) { r.TimeoutMS = u64(999) }},
		"timeout over 24h":            {sandbox.OpExecStart, func(r *protocol.SandboxOpRequestV1) { r.TimeoutMS = u64(sandbox.MaxExecTimeoutMS + 1) }},
		"output cap under 1 KiB":      {sandbox.OpExecStart, func(r *protocol.SandboxOpRequestV1) { r.MaxOutputBytes = u64(1023) }},
		"output cap over 16 MiB":      {sandbox.OpExecStart, func(r *protocol.SandboxOpRequestV1) { r.MaxOutputBytes = u64(sandbox.MaxExecOutputBytes + 1) }},
		"payload zero bytes":          {sandbox.OpExecStart, func(r *protocol.SandboxOpRequestV1) { r.PayloadBytes = 0 }},
		"payload over chunk":          {sandbox.OpFileWrite, func(r *protocol.SandboxOpRequestV1) { r.PayloadBytes = sandbox.MaxChunkBytes + 1 }},
		"payload digest invalid":      {sandbox.OpFileWrite, func(r *protocol.SandboxOpRequestV1) { r.PayloadDigest = str("sha256:xyz") }},
		"payload bytes without bytes": {sandbox.OpFileStat, func(r *protocol.SandboxOpRequestV1) { r.PayloadBytes = 3 }},
		"write mode after offset 0":   {sandbox.OpFileWrite, func(r *protocol.SandboxOpRequestV1) { r.Offset = u64(7) }},
		"write offset 0 without mode": {sandbox.OpFileWrite, func(r *protocol.SandboxOpRequestV1) { r.Mode = nil }},
		"write past max file size": {sandbox.OpFileWrite, func(r *protocol.SandboxOpRequestV1) {
			r.Offset, r.Mode = u64(sandbox.MaxFileWriteBytes-3), nil
		}},
		"exec_read offset past the retained cap": {sandbox.OpExecRead, func(r *protocol.SandboxOpRequestV1) { r.Offset = u64(sandbox.MaxExecOutputBytes + 1) }},
		"file_read offset past 2^53-1":           {sandbox.OpFileRead, func(r *protocol.SandboxOpRequestV1) { r.Offset = u64(1 << 53) }},
		"file_read offset wraps":                 {sandbox.OpFileRead, func(r *protocol.SandboxOpRequestV1) { r.Offset = u64(^uint64(0)) }},
		"file_list cursor past the scan bound":   {sandbox.OpFileList, func(r *protocol.SandboxOpRequestV1) { r.Offset = u64(65537) }},
		"mode setuid":                            {sandbox.OpFileMkdir, func(r *protocol.SandboxOpRequestV1) { r.Mode = u32(0o4755) }},
		"mkdir without mode":                     {sandbox.OpFileMkdir, func(r *protocol.SandboxOpRequestV1) { r.Mode = nil }},
		"write to root":                          {sandbox.OpFileWrite, func(r *protocol.SandboxOpRequestV1) { r.Path = str("/") }},
		"remove root":                            {sandbox.OpFileRemove, func(r *protocol.SandboxOpRequestV1) { r.Path = str("/") }},
		"path traversal":                         {sandbox.OpFileRead, func(r *protocol.SandboxOpRequestV1) { r.Path = str("/workspace/../etc/shadow") }},
		"path relative":                          {sandbox.OpFileRead, func(r *protocol.SandboxOpRequestV1) { r.Path = str("etc/passwd") }},
		"binding names other miner": {sandbox.OpFileStat, func(r *protocol.SandboxOpRequestV1) {
			binding := *r.Subnet
			binding.MinerHotkey = "5Fother"
			r.Subnet = &binding
		}},
	}
	for name, test := range cases {
		request := unsignedOp(t, lease, test.op)
		test.mutate(&request)
		if err := protocol.SignSandboxOpRequestV1(&request, validator); err == nil {
			t.Errorf("%s: signed", name)
		}
	}
}

// The fence binds an op to one exact lease and its parties.
func TestSandboxOpMustTargetItsLease(t *testing.T) {
	validator, miner, lease := opLease(t)
	request := signedOp(t, validator, unsignedOp(t, lease, sandbox.OpFileStat))
	if err := protocol.SandboxOpTargetsLeaseV1(request, lease); err != nil {
		t.Fatal(err)
	}
	sibling := sandboxLease(t, validator, miner, sandboxReservation(t, validator, miner), func(l *protocol.SandboxLeaseV1) {
		l.AssignmentNonce = strings.Repeat("c3", 16)
	})
	retargeted := unsignedOp(t, lease, sandbox.OpFileStat)
	retargeted.LeaseID = protocol.SandboxLeaseIDV1(sibling)
	retargeted = signedOp(t, validator, retargeted)

	stranger := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x44}, 32))
	foreign := unsignedOp(t, lease, sandbox.OpFileStat)
	binding := *foreign.Subnet
	binding.ValidatorHotkey, binding.ValidatorServicePublicKey = "5Hstranger", hex.EncodeToString(stranger.Public().(ed25519.PublicKey))
	foreign.Subnet = &binding
	foreign = signedOp(t, stranger, foreign)

	rebound := unsignedOp(t, lease, sandbox.OpFileStat)
	fresh := *rebound.Subnet
	fresh.ChainBlock, fresh.ExpiresAtBlock = 140, 165
	rebound.Subnet = &fresh
	rebound = signedOp(t, validator, rebound)
	if err := protocol.SandboxOpTargetsLeaseV1(rebound, lease); err != nil {
		t.Fatalf("a fresh chain binding of the same parties must still target the lease: %v", err)
	}
	for name, err := range map[string]error{
		"digest of sibling lease": protocol.SandboxOpTargetsLeaseV1(request, sibling),
		"lease_id of sibling":     protocol.SandboxOpTargetsLeaseV1(retargeted, lease),
		"another validator party": protocol.SandboxOpTargetsLeaseV1(foreign, lease),
	} {
		if err == nil {
			t.Errorf("%s targeted the lease", name)
		}
	}
}

func TestBoundSandboxOpAdmission(t *testing.T) {
	validator, _, lease := opLease(t)
	key := validator.Public().(ed25519.PublicKey)
	request := signedOp(t, validator, unsignedOp(t, lease, sandbox.OpFileStat))
	uid := uint16(7)
	admit := func(now time.Time, caller string) error {
		return protocol.VerifyBoundSandboxOpRequestV1(request, key, now, 110, "test", 24, caller, "5Fminer", &uid)
	}
	if err := admit(opNow, "5Hvalidator"); err != nil {
		t.Fatal(err)
	}
	for name, err := range map[string]error{
		"before issue skew": admit(opNow.Add(-31*time.Second), "5Hvalidator"),
		"at expiry":         admit(opNow.Add(30*time.Second), "5Hvalidator"),
		"another caller":    admit(opNow, "5Hother"),
	} {
		if err == nil {
			t.Errorf("%s was admitted", name)
		}
	}
}

func TestSandboxOpPayloadBinding(t *testing.T) {
	validator, _, lease := opLease(t)
	write := signedOp(t, validator, unsignedOp(t, lease, sandbox.OpFileWrite))
	stat := signedOp(t, validator, unsignedOp(t, lease, sandbox.OpFileStat))
	if err := protocol.SandboxOpPayloadMatchesV1(write, []byte("payload")); err != nil {
		t.Fatal(err)
	}
	if err := protocol.SandboxOpPayloadMatchesV1(stat, nil); err != nil {
		t.Fatal(err)
	}
	for name, err := range map[string]error{
		"other bytes same length": protocol.SandboxOpPayloadMatchesV1(write, []byte("PAYLOAD")),
		"truncated":               protocol.SandboxOpPayloadMatchesV1(write, []byte("payloa")),
		"missing":                 protocol.SandboxOpPayloadMatchesV1(write, nil),
		"unexpected":              protocol.SandboxOpPayloadMatchesV1(stat, []byte{}),
	} {
		if err == nil {
			t.Errorf("%s payload matched", name)
		}
	}
}

func TestSandboxOpReceiptRules(t *testing.T) {
	validator, miner, lease := opLease(t)
	start := signedOp(t, validator, unsignedOp(t, lease, sandbox.OpExecStart))
	read := signedOp(t, validator, unsignedOp(t, lease, sandbox.OpExecRead))
	stat := signedOp(t, validator, unsignedOp(t, lease, sandbox.OpFileStat))
	remove := signedOp(t, validator, unsignedOp(t, lease, sandbox.OpFileRemove))
	type mutation func(*protocol.SandboxOpReceiptV1)
	valid := map[string]struct {
		request protocol.SandboxOpRequestV1
		mutate  mutation
	}{
		"exec running": {start, func(r *protocol.SandboxOpReceiptV1) { r.Stage, r.Exec = sandbox.OpStageRunning, runningExec(0, 0) }},
		"exec failed before start": {start, func(r *protocol.SandboxOpReceiptV1) {
			r.Stage, r.ErrorCode = sandbox.OpStageFailed, str(sandbox.OpCodeRuntimeFailed)
		}},
		"exec refused, container exited": {start, func(r *protocol.SandboxOpReceiptV1) {
			r.Stage, r.ErrorCode = sandbox.OpStageRefused, str("sandbox_exited")
		}},
		"exec timed out": {start, func(r *protocol.SandboxOpReceiptV1) { r.Stage, r.Exec = sandbox.OpStageTimedOut, timedOutExec() }},
		"stat completed": {stat, func(r *protocol.SandboxOpReceiptV1) {
			r.File = &sandbox.FileInfo{Mode: 0o755, Type: sandbox.FileTypeDirectory}
		}},
		"remove completed": {remove, nil},
		"remove over budget": {remove, func(r *protocol.SandboxOpReceiptV1) {
			r.Stage, r.ErrorCode = sandbox.OpStageTimedOut, str(sandbox.OpCodeDeadline)
		}},
		"read running empty": {read, func(r *protocol.SandboxOpReceiptV1) {
			r.Stage, r.Exec = sandbox.OpStageRunning, runningExec(0, 0)
			withResult(r, []byte{}, 0)
		}},
	}
	for _, test := range valid {
		opReceipt(t, miner, test.request, test.mutate)
	}
	invalid := map[string]struct {
		request protocol.SandboxOpRequestV1
		mutate  mutation
	}{
		"exec op completed":            {start, nil},
		"file op running":              {stat, func(r *protocol.SandboxOpReceiptV1) { r.Stage = sandbox.OpStageRunning }},
		"exec running without exec":    {start, func(r *protocol.SandboxOpReceiptV1) { r.Stage = sandbox.OpStageRunning }},
		"exec state contradicts stage": {start, func(r *protocol.SandboxOpReceiptV1) { r.Stage, r.Exec = sandbox.OpStageExited, runningExec(0, 0) }},
		"exited without exit code": {start, func(r *protocol.SandboxOpReceiptV1) {
			r.Stage, r.Exec = sandbox.OpStageExited, exitedExec(0, 0)
			r.Exec.ExitCode = nil
		}},
		"exit code over 255": {start, func(r *protocol.SandboxOpReceiptV1) { r.Stage, r.Exec = sandbox.OpStageExited, exitedExec(256, 0) }},
		"retained over produced": {start, func(r *protocol.SandboxOpReceiptV1) {
			r.Stage, r.Exec = sandbox.OpStageRunning, runningExec(10, 0)
			r.Exec.StdoutRetained = 11
		}},
		"running with ended_at": {start, func(r *protocol.SandboxOpReceiptV1) {
			r.Stage, r.Exec = sandbox.OpStageRunning, runningExec(0, 0)
			r.Exec.EndedAt = str(stamp(opNow))
		}},
		"refused names exec": {start, func(r *protocol.SandboxOpReceiptV1) {
			r.Stage, r.ErrorCode, r.Exec = sandbox.OpStageRefused, str("released"), runningExec(0, 0)
		}},
		"refused without code": {stat, func(r *protocol.SandboxOpReceiptV1) { r.Stage = sandbox.OpStageRefused }},
		"completed with code":  {remove, func(r *protocol.SandboxOpReceiptV1) { r.ErrorCode = str("path_not_found") }},
		"unknown code": {stat, func(r *protocol.SandboxOpReceiptV1) {
			r.Stage, r.ErrorCode = sandbox.OpStageRefused, str("tenant_mismatch")
		}},
		"file timeout wrong code": {remove, func(r *protocol.SandboxOpReceiptV1) { r.Stage, r.ErrorCode = sandbox.OpStageTimedOut, str("no_space") }},
		"exec timeout with code": {start, func(r *protocol.SandboxOpReceiptV1) {
			r.Stage, r.Exec, r.ErrorCode = sandbox.OpStageTimedOut, timedOutExec(), str(sandbox.OpCodeDeadline)
		}},
		"stat without file": {stat, nil},
		"remove with file":  {remove, func(r *protocol.SandboxOpReceiptV1) { r.File = &sandbox.FileInfo{Type: sandbox.FileTypeFile} }},
		"file mode over 0777": {stat, func(r *protocol.SandboxOpReceiptV1) {
			r.File = &sandbox.FileInfo{Mode: 0o1777, Type: sandbox.FileTypeDirectory}
		}},
		"read without result": {read, func(r *protocol.SandboxOpReceiptV1) { r.Stage, r.Exec = sandbox.OpStageRunning, runningExec(0, 0) }},
		"result on non-read":  {remove, func(r *protocol.SandboxOpReceiptV1) { withResult(r, []byte{}, 0) }},
		"eof without result":  {remove, func(r *protocol.SandboxOpReceiptV1) { r.EOF = true }},
		"result over chunk": {read, func(r *protocol.SandboxOpReceiptV1) {
			r.Stage, r.Exec = sandbox.OpStageRunning, runningExec(0, 0)
			withResult(r, []byte{}, 0)
			r.ResultBytes = sandbox.MaxChunkBytes + 1
		}},
		"ended_at after observed_at": {start, func(r *protocol.SandboxOpReceiptV1) {
			r.Stage, r.Exec = sandbox.OpStageExited, exitedExec(0, 0)
			r.Exec.EndedAt = str(stamp(opNow.Add(time.Hour)))
		}},
		"started_at after observed_at": {start, func(r *protocol.SandboxOpReceiptV1) {
			r.Stage, r.Exec = sandbox.OpStageRunning, runningExec(0, 0)
			r.Exec.StartedAt = stamp(opNow.Add(time.Hour))
		}},
		"next_offset past 2^53-1": {read, func(r *protocol.SandboxOpReceiptV1) {
			r.Stage, r.Exec = sandbox.OpStageRunning, runningExec(0, 0)
			withResult(r, []byte{}, 1<<53)
		}},
		"output total past 2^53-1": {start, func(r *protocol.SandboxOpReceiptV1) {
			r.Stage, r.Exec = sandbox.OpStageRunning, runningExec(0, 0)
			r.Exec.StdoutBytes = 1 << 53
		}},
		"op_id of another lease": {stat, func(r *protocol.SandboxOpReceiptV1) {
			r.File = &sandbox.FileInfo{Type: sandbox.FileTypeDirectory}
			r.OpID = "sbx-" + strings.Repeat("1e", 16) + "-op-" + strings.Repeat("d4", 16)
		}},
	}
	for name, test := range invalid {
		r := baseOpReceipt(t, test.request)
		if test.mutate != nil {
			test.mutate(&r)
		}
		if err := protocol.SignSandboxOpReceiptV1(&r, miner); err == nil {
			t.Errorf("%s: receipt signed", name)
		}
	}
}

// D13: an unknown exec_start outcome becomes a definitive non-start only
// through an exec_not_found the miner signed after the start's admission
// window closed.
func TestSandboxExecNeverStartedOnlyAfterTheAdmissionWindow(t *testing.T) {
	validator, miner, lease := opLease(t)
	start := signedOp(t, validator, unsignedOp(t, lease, sandbox.OpExecStart))
	read := unsignedOp(t, lease, sandbox.OpExecRead)
	read.OpNonce, read.ExecID = strings.Repeat("f6", 16), str(protocol.SandboxOpIDV1(start))
	read.IssuedAt, read.ExpiresAt = stamp(opNow.Add(time.Minute)), stamp(opNow.Add(90*time.Second))
	read = signedOp(t, validator, read)
	notFound := func(request protocol.SandboxOpRequestV1, observed time.Time) protocol.SandboxOpReceiptV1 {
		return opReceipt(t, miner, request, func(r *protocol.SandboxOpReceiptV1) {
			r.Stage, r.ErrorCode, r.ObservedAt = sandbox.OpStageRefused, str("exec_not_found"), stamp(observed)
		})
	}
	windowEnd := opNow.Add(30*time.Second + sandbox.IssueSkew)
	minerKey := miner.Public().(ed25519.PublicKey)
	forged := notFound(read, windowEnd)
	forged.Signature = strings.Repeat("ab", 64)
	if never, err := protocol.SandboxExecNeverStartedV1(forged, read, start, minerKey); err == nil || never {
		t.Fatalf("an unverified exec_not_found must not resolve the exec: %v %v", never, err)
	}
	if never, err := protocol.SandboxExecNeverStartedV1(notFound(read, windowEnd), read, start, minerKey); err != nil || !never {
		t.Fatalf("exec_not_found at the window end must be definitive: %v %v", never, err)
	}
	if never, err := protocol.SandboxExecNeverStartedV1(notFound(read, windowEnd.Add(-time.Nanosecond)), read, start, minerKey); err != nil || never {
		t.Fatalf("exec_not_found inside the window must not be definitive: %v %v", never, err)
	}
	running := opReceipt(t, miner, read, func(r *protocol.SandboxOpReceiptV1) {
		r.Stage, r.Exec, r.ObservedAt = sandbox.OpStageRunning, runningExec(0, 0), stamp(windowEnd)
		withResult(r, []byte{}, 0)
	})
	if never, err := protocol.SandboxExecNeverStartedV1(running, read, start, minerKey); err != nil || never {
		t.Fatalf("a running exec is not a non-start: %v %v", never, err)
	}
	otherExec := unsignedOp(t, lease, sandbox.OpExecCancel)
	otherExec.OpNonce = strings.Repeat("a9", 16)
	otherExec = signedOp(t, validator, otherExec)
	if _, err := protocol.SandboxExecNeverStartedV1(notFound(otherExec, windowEnd), otherExec, start, minerKey); err == nil {
		t.Fatal("a read of another exec resolved this exec_start")
	}
	if _, err := protocol.SandboxExecNeverStartedV1(notFound(read, windowEnd), read, signedOp(t, validator, unsignedOp(t, lease, sandbox.OpFileStat)), minerKey); err == nil {
		t.Fatal("a non-exec op was resolved as an exec_start")
	}
}

// The validator accepts a receipt only for the exact request and only with
// result bytes that match its binding and the request's cursor.
func TestSandboxOpReceiptMustAnswerRequestAndResult(t *testing.T) {
	validator, miner, lease := opLease(t)
	read := signedOp(t, validator, unsignedOp(t, lease, sandbox.OpFileRead))
	chunk := []byte("print('ok')\n")
	fileReceipt := func(next uint64) protocol.SandboxOpReceiptV1 {
		return opReceipt(t, miner, read, func(r *protocol.SandboxOpReceiptV1) {
			r.EOF = true
			withResult(r, chunk, next)
		})
	}
	if err := protocol.SandboxOpReceiptAnswersV1(fileReceipt(uint64(len(chunk))), read, chunk); err != nil {
		t.Fatal(err)
	}
	other := unsignedOp(t, lease, sandbox.OpFileRead)
	other.OpNonce = strings.Repeat("b8", 16)
	other = signedOp(t, validator, other)

	execRead := signedOp(t, validator, unsignedOp(t, lease, sandbox.OpExecRead))
	output := []byte("partial")
	execReceipt := func(exec *sandbox.ExecStatus, eof bool) protocol.SandboxOpReceiptV1 {
		stage := sandbox.OpStageRunning
		if exec.State == sandbox.ExecStateExited {
			stage = sandbox.OpStageExited
		}
		return opReceipt(t, miner, execRead, func(r *protocol.SandboxOpReceiptV1) {
			r.Stage, r.Exec, r.EOF = stage, exec, eof
			withResult(r, output, uint64(len(output)))
		})
	}
	if err := protocol.SandboxOpReceiptAnswersV1(execReceipt(exitedExec(0, uint64(len(output))), true), execRead, output); err != nil {
		t.Fatal(err)
	}
	if err := protocol.SandboxOpReceiptAnswersV1(execReceipt(runningExec(uint64(len(output)), 0), false), execRead, output); err != nil {
		t.Fatal(err)
	}

	list := signedOp(t, validator, unsignedOp(t, lease, sandbox.OpFileList))
	limitOne := unsignedOp(t, lease, sandbox.OpFileList)
	limitOne.Limit = u64(1)
	limitOne = signedOp(t, validator, limitOne)
	entries := func(names ...string) []byte {
		listing := sandbox.ListResult{Entries: []sandbox.ListEntry{}}
		for _, name := range names {
			listing.Entries = append(listing.Entries, sandbox.ListEntry{FileInfo: sandbox.FileInfo{Type: sandbox.FileTypeFile}, Name: name})
		}
		encoded, err := organic.Canonical(listing)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	listReceipt := func(request protocol.SandboxOpRequestV1, body []byte, next uint64) protocol.SandboxOpReceiptV1 {
		return opReceipt(t, miner, request, func(r *protocol.SandboxOpReceiptV1) { withResult(r, body, next) })
	}
	sorted, unsorted, nested := entries("a", "b"), entries("b", "a"), entries("a/b")
	if err := protocol.SandboxOpReceiptAnswersV1(listReceipt(list, sorted, 2), list, sorted); err != nil {
		t.Fatal(err)
	}
	for name, err := range map[string]error{
		"tampered result":           protocol.SandboxOpReceiptAnswersV1(fileReceipt(uint64(len(chunk))), read, []byte("print('no')\n")),
		"result withheld":           protocol.SandboxOpReceiptAnswersV1(fileReceipt(uint64(len(chunk))), read, nil),
		"another request":           protocol.SandboxOpReceiptAnswersV1(fileReceipt(uint64(len(chunk))), other, chunk),
		"cursor skips":              protocol.SandboxOpReceiptAnswersV1(fileReceipt(100), read, chunk),
		"exec eof while running":    protocol.SandboxOpReceiptAnswersV1(execReceipt(runningExec(uint64(len(output)), 0), true), execRead, output),
		"exec no eof at terminal":   protocol.SandboxOpReceiptAnswersV1(execReceipt(exitedExec(0, uint64(len(output))), false), execRead, output),
		"exec bytes past retained":  protocol.SandboxOpReceiptAnswersV1(execReceipt(exitedExec(0, 3), true), execRead, output),
		"list over request limit":   protocol.SandboxOpReceiptAnswersV1(listReceipt(limitOne, sorted, 2), limitOne, sorted),
		"list cursor contradiction": protocol.SandboxOpReceiptAnswersV1(listReceipt(list, sorted, 5), list, sorted),
		"list unsorted":             protocol.SandboxOpReceiptAnswersV1(listReceipt(list, unsorted, 2), list, unsorted),
		"list nested name":          protocol.SandboxOpReceiptAnswersV1(listReceipt(list, nested, 1), list, nested),
	} {
		if err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// Acceptance helpers take unverified, possibly hostile input: malformed
// receipts are errors, never panics, and an exec_start answer may not claim
// more retained output than the request allowed (lane 7 SR-28-04, SR-28-07).
func TestSandboxOpAcceptanceRejectsMalformedInputs(t *testing.T) {
	validator, miner, lease := opLease(t)
	read := signedOp(t, validator, unsignedOp(t, lease, sandbox.OpExecRead))
	malformed := baseOpReceipt(t, read)
	malformed.ResultDigest, malformed.Signature = str(protocol.SandboxContentDigestV1(nil)), strings.Repeat("ab", 64)
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("malformed receipt panicked: %v", recovered)
			}
		}()
		if protocol.SandboxOpReceiptAnswersV1(malformed, read, []byte{}) == nil {
			t.Fatal("malformed receipt accepted")
		}
	}()
	start := signedOp(t, validator, unsignedOp(t, lease, sandbox.OpExecStart))
	overCap := opReceipt(t, miner, start, func(r *protocol.SandboxOpReceiptV1) {
		r.Stage, r.Exec = sandbox.OpStageRunning, runningExec(*start.MaxOutputBytes+1, 0)
	})
	if protocol.SandboxOpReceiptAnswersV1(overCap, start, nil) == nil {
		t.Fatal("exec_start answer retaining more than max_output_bytes was accepted")
	}
	atCap := opReceipt(t, miner, start, func(r *protocol.SandboxOpReceiptV1) {
		r.Stage, r.Exec = sandbox.OpStageRunning, runningExec(*start.MaxOutputBytes, 0)
	})
	if err := protocol.SandboxOpReceiptAnswersV1(atCap, start, nil); err != nil {
		t.Fatal(err)
	}
}
