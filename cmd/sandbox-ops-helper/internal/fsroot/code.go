// SPDX-License-Identifier: AGPL-3.0-only

package fsroot

import (
	"context"
	"errors"
	"syscall"

	"github.com/misscomputer/misscomputer-subnet/pkg/sandbox"
)

// Code maps an error from FS to its sandbox-ops-v1 receipt error code.
// Every error here originates inside the sandbox, where guest code shares
// the helper's identity and can starve or break it, so every code is
// non-fault (lane 7 B-6): an unrecognized error is sandbox_op_failed, never
// the miner fault op_runtime_failed, which is reserved for miner-side engine
// and transport failures.
func Code(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return sandbox.OpCodeDeadline
	case errors.Is(err, ErrUnsupported), errors.Is(err, syscall.ENOSYS):
		return sandbox.OpCodeOpsUnsupport
	case errors.Is(err, ErrNotFile), errors.Is(err, syscall.EISDIR):
		return "path_not_file"
	case errors.Is(err, ErrOffsetMismatch):
		return "offset_mismatch"
	case errors.Is(err, ErrTooLarge), errors.Is(err, syscall.EFBIG):
		return "file_too_large"
	case errors.Is(err, ErrDirectoryTooBig), errors.Is(err, ErrTreeTooDeep), errors.Is(err, syscall.ELOOP), errors.Is(err, syscall.EXDEV),
		errors.Is(err, syscall.ENAMETOOLONG):
		return "path_refused"
	case errors.Is(err, syscall.ENOENT):
		return "path_not_found"
	case errors.Is(err, syscall.ENOTDIR):
		return "path_not_directory"
	case errors.Is(err, syscall.EEXIST):
		return "path_exists"
	case errors.Is(err, syscall.ENOTEMPTY):
		return "directory_not_empty"
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM), errors.Is(err, syscall.EROFS):
		return "permission_denied"
	case errors.Is(err, syscall.ENOSPC), errors.Is(err, syscall.EDQUOT):
		return "no_space"
	case errors.Is(err, syscall.ENOMEM), errors.Is(err, syscall.EAGAIN), errors.Is(err, syscall.EMFILE),
		errors.Is(err, syscall.ENFILE):
		return sandbox.OpCodeResourcesExhausted
	}
	return sandbox.OpCodeSandboxFailed
}
