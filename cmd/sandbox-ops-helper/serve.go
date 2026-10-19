// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"io"

	"github.com/misscomputer/misscomputer-subnet/cmd/sandbox-ops-helper/internal/fsroot"
	"github.com/misscomputer/misscomputer-subnet/pkg/sandbox"
	"github.com/misscomputer/misscomputer-subnet/pkg/sandboxops"
)

// captureRoot is the fixed in-sandbox exec capture directory (D14).
const captureRoot = sandboxops.CaptureRoot

// server performs one helper request. openFS opens the sandbox root for file
// operations (fsroot.Open, only "/"); execs serves exec operations under
// their capture root.
type server struct {
	openFS func() (fsroot.FS, error)
	execs  execRunner
}

// execRunner is the exec half of the helper: exec_linux.go on Linux, and an
// ops_unsupported stub elsewhere.
type execRunner interface {
	start(execID string, spec sandboxops.ExecSpec) sandboxops.Response
	read(execID, stream string, offset, limit uint64) sandboxops.Response
	cancel(execID string, force bool) sandboxops.Response
	status(execID string) sandboxops.Response
}

func openRoot() (fsroot.FS, error) { return fsroot.Open() }

// serveProcess serves exactly one request from in to out. A request that
// does not decode is answered sandbox_op_failed: the miner wrote it, so this
// is never a guest-visible state.
func serveProcess(in io.Reader, out io.Writer) int {
	s := &server{openFS: openRoot, execs: newExecRunner(captureRoot, selfExecutable)}
	return s.serve(in, out)
}

func (s *server) serve(in io.Reader, out io.Writer) int {
	response := sandboxops.Failure(sandbox.OpCodeSandboxFailed)
	payload, err := sandboxops.ReadBounded(in, sandboxops.MaxRequestBytes)
	if err == nil {
		var request sandboxops.Request
		if request, err = sandboxops.DecodeRequest(payload); err == nil {
			response = s.handle(request)
		}
	}
	encoded, err := sandboxops.Encode(response)
	if err != nil {
		encoded, _ = sandboxops.Encode(sandboxops.Failure(sandbox.OpCodeSandboxFailed))
	}
	if _, err := out.Write(append(encoded, '\n')); err != nil {
		return 1
	}
	return 0
}

func (s *server) handle(request sandboxops.Request) sandboxops.Response {
	switch request.Op {
	case sandbox.OpExecStart:
		return s.execs.start(*request.ExecID, *request.Exec)
	case sandbox.OpExecRead:
		return s.execs.read(*request.ExecID, *request.Stream, *request.Offset, *request.Limit)
	case sandbox.OpExecCancel:
		return s.execs.cancel(*request.ExecID, request.Force)
	case sandboxops.OpExecStatus:
		return s.execs.status(*request.ExecID)
	}
	fs, err := s.openFS()
	if err != nil {
		return sandboxops.Failure(fsroot.Code(err))
	}
	defer fs.Close()
	// The 30 s file-op budget (SyncOpBudget) is enforced here as well as by
	// the miner, so a slow walk reports op_deadline_exceeded itself.
	ctx, cancel := context.WithTimeout(context.Background(), sandbox.SyncOpBudget)
	defer cancel()
	response := sandboxops.Response{Protocol: sandboxops.Protocol}
	switch request.Op {
	case sandbox.OpFileStat:
		var info sandbox.FileInfo
		if info, err = fs.Stat(ctx, *request.Path); err == nil {
			response.File = &info
		}
	case sandbox.OpFileRead:
		var data []byte
		var size uint64
		if data, size, err = fs.ReadAt(ctx, *request.Path, *request.Offset, *request.Limit); err == nil {
			response.Data, response.Size = sandboxops.EncodeData(data), &size
		}
	case sandbox.OpFileWrite:
		var info sandbox.FileInfo
		if info, err = fs.WriteChunk(ctx, *request.Path, *request.Offset, request.Bytes(), request.Mode); err == nil {
			response.File = &info
		}
	case sandbox.OpFileList:
		var listing sandbox.ListResult
		var done bool
		if listing, done, err = fs.List(ctx, *request.Path, *request.Offset, *request.Limit); err == nil {
			response.Listing, response.EOF = &listing, done
		}
	case sandbox.OpFileRemove:
		err = fs.Remove(ctx, *request.Path, *request.Recursive)
	case sandbox.OpFileMkdir:
		var info sandbox.FileInfo
		if info, err = fs.Mkdir(ctx, *request.Path, *request.Mode, *request.Recursive); err == nil {
			response.File = &info
		}
	}
	if err != nil {
		return sandboxops.Failure(fsroot.Code(err))
	}
	return response
}
