// SPDX-License-Identifier: AGPL-3.0-only

// Package fsroot is the in-sandbox resolver of the sandbox-ops-v1 helper
// (cmd/sandbox-ops-helper) for file operations (docs/sandbox-ops-v1.md). Every path is resolved relative to a
// root directory file descriptor with openat2(RESOLVE_IN_ROOT |
// RESOLVE_NO_MAGICLINKS): symlinks are followed as if the root were "/",
// ".." never rises above it, and procfs magic links are refused. A final
// component that is created, replaced or removed is handled with *at system
// calls on its parent directory descriptor and never followed. No path
// string is joined, cleaned or resolved in user space, so a concurrent
// symlink swap cannot redirect an operation outside the root.
//
// It runs only inside the sandbox isolation boundary, in the helper, with
// root "/" (OPS-D5, lane 7 R-1/B-9). Go's internal-package rule limits its
// importers to the helper, and Open takes no directory. Host-side access to
// a container's overlay trees, docker cp, or this resolver applied on the
// host to those trees is not permitted. Inside the sandbox the boundary is the
// sandbox itself; the resolver adds exact, race-free semantics (no
// write-through of a final symlink, no magic links, no FIFO hangs). Where
// openat2 is unavailable Open fails with ErrUnsupported; there is no
// fallback to unsafe resolution.
package fsroot

import (
	"context"
	"errors"

	"github.com/misscomputer/misscomputer-subnet/pkg/sandbox"
)

// Sentinel errors. Code maps them, and the system errors they wrap, to
// sandbox-ops-v1 receipt error codes.
var (
	ErrUnsupported     = errors.New("fsroot: openat2 in-root resolution is unavailable")
	ErrNotFile         = errors.New("fsroot: path is not a regular file")
	ErrOffsetMismatch  = errors.New("fsroot: write offset is not the current file size")
	ErrTooLarge        = errors.New("fsroot: file would exceed the maximum writable size")
	ErrDirectoryTooBig = errors.New("fsroot: directory exceeds the scan bound")
	ErrTreeTooDeep     = errors.New("fsroot: directory tree exceeds the removal depth bound")
)

// MaxDirectoryScan bounds the names one file_list reads to sort a
// directory; a larger directory is refused rather than listed partially.
const MaxDirectoryScan = sandbox.MaxListCursor

// MaxRemoveDepth bounds the directory nesting a recursive file_remove
// descends, and so the descriptors it holds open at once.
const MaxRemoveDepth = 256

// FS is the file-operation surface the helper serves.
type FS interface {
	Stat(ctx context.Context, path string) (sandbox.FileInfo, error)
	ReadAt(ctx context.Context, path string, offset, limit uint64) (data []byte, size uint64, err error)
	WriteChunk(ctx context.Context, path string, offset uint64, data []byte, mode *uint32) (sandbox.FileInfo, error)
	List(ctx context.Context, path string, offset, limit uint64) (sandbox.ListResult, bool, error)
	Remove(ctx context.Context, path string, recursive bool) error
	Mkdir(ctx context.Context, path string, mode uint32, parents bool) (sandbox.FileInfo, error)
	Close() error
}

var _ FS = (*Root)(nil)
