// SPDX-License-Identifier: AGPL-3.0-only

package sandboxops

import (
	"strings"
	"testing"

	"github.com/misscomputer/misscomputer-subnet/pkg/sandbox"
)

func u64(v uint64) *uint64 { return &v }

func readRequest() Request {
	path := "/work/out.txt"
	return Request{Protocol: Protocol, Op: sandbox.OpFileRead, Path: &path, Offset: u64(0), Limit: u64(4)}
}

// The helper's request decoder is the boundary the miner writes to; a
// request it accepts must be exactly one shape per op.
func TestDecodeRequestIsStrict(t *testing.T) {
	valid, err := Encode(readRequest())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeRequest(valid); err != nil {
		t.Fatalf("canonical request refused: %v", err)
	}
	for name, payload := range map[string]string{
		"unknown member": strings.Replace(string(valid), `"protocol"`, `"extra":1,"protocol"`, 1),
		"duplicate key":  strings.Replace(string(valid), `"op":"file_read"`, `"op":"file_read","op":"file_stat"`, 1),
		"member for op":  strings.Replace(string(valid), `"recursive":null`, `"recursive":true`, 1),
		"trailing data":  string(valid) + "{}",
		"wrong protocol": strings.Replace(string(valid), Protocol, "sandbox-ops-helper.v2", 1),
		"limit over cap": strings.Replace(string(valid), `"limit":4`, `"limit":524289`, 1),
		"path traversal": strings.Replace(string(valid), `/work/out.txt`, `/work/../etc`, 1),
	} {
		if _, err := DecodeRequest([]byte(payload)); err == nil {
			t.Errorf("%s: accepted %s", name, payload)
		}
	}
	// An exec ID names a capture directory, so it can never be a path.
	for _, id := range []string{"../x-op-y", "a/b-op-c", "dot.ted-op-x", "no-separator"} {
		status, err := Encode(Request{Protocol: Protocol, Op: OpExecStatus, ExecID: &id})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeRequest(status); err == nil {
			t.Errorf("exec id %q accepted", id)
		}
	}
}

// Guest code can answer in the helper's place, so a response must never
// claim a miner fault, carry a result with a failure, or exceed what was
// asked for.
func TestDecodeResponseRefusesWhatAGuestMustNotClaim(t *testing.T) {
	request := readRequest()
	size := uint64(4)
	ok := Response{Protocol: Protocol, Data: EncodeData([]byte("abcd")), Size: &size}
	encoded, err := Encode(ok)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecodeResponse(encoded, request); err != nil || string(got.Bytes()) != "abcd" {
		t.Fatalf("valid response: %v %q", err, got.Bytes())
	}
	failure := func(code string) Response { return Failure(code) }
	for name, response := range map[string]Response{
		"miner fault code":  failure(sandbox.OpCodeRuntimeFailed),
		"miner restart":     failure("miner_restart"),
		"lease state code":  failure("lease_expired"),
		"cap code":          failure("exec_limit_exceeded"),
		"failure w/ result": {Protocol: Protocol, Code: ok.Code, Data: ok.Data, Size: &size},
		"over the limit":    {Protocol: Protocol, Data: EncodeData([]byte("abcde")), Size: &size},
		"missing size":      {Protocol: Protocol, Data: ok.Data},
		"exec member":       {Protocol: Protocol, Data: ok.Data, Size: &size, Exec: &ExecObservation{State: sandbox.ExecStateRunning}},
	} {
		if name == "failure w/ result" {
			code := "path_not_found"
			response.Code = &code
		}
		payload, err := Encode(response)
		if err != nil {
			continue
		}
		if _, err := DecodeResponse(payload, request); err == nil {
			t.Errorf("%s: accepted %s", name, payload)
		}
	}
	for _, payload := range []string{
		strings.Replace(string(encoded), `"data_b64":"YWJjZA=="`, `"data_b64":"YWJjZA"`, 1),
		strings.Replace(string(encoded), `"protocol"`, `"Protocol"`, 1),
	} {
		if _, err := DecodeResponse([]byte(payload), request); err == nil {
			t.Errorf("accepted non-canonical %s", payload)
		}
	}
}

func TestExecObservationConsistency(t *testing.T) {
	three := 3
	for name, observation := range map[string]ExecObservation{
		"exited without code":  {State: sandbox.ExecStateExited},
		"running with code":    {State: sandbox.ExecStateRunning, ExitCode: &three},
		"retained over bytes":  {State: sandbox.ExecStateRunning, StdoutRetained: 2, StdoutBytes: 1},
		"retained over cap":    {State: sandbox.ExecStateRunning, StderrRetained: sandbox.MaxExecOutputBytes + 1, StderrBytes: sandbox.MaxExecOutputBytes + 1},
		"unknown state":        {State: "admitted"},
		"exit code over range": {State: sandbox.ExecStateExited, ExitCode: func() *int { v := 256; return &v }()},
	} {
		if observation.Validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
