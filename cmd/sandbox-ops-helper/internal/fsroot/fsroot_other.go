// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package fsroot

import (
	"context"

	"github.com/misscomputer/misscomputer-subnet/pkg/sandbox"
)

// Root is unavailable outside Linux: there is no openat2 in-root
// resolution, and no fallback.
type Root struct{}

// Open always fails with ErrUnsupported outside Linux.
func Open() (*Root, error) { return nil, ErrUnsupported }

func (*Root) Stat(context.Context, string) (sandbox.FileInfo, error) {
	return sandbox.FileInfo{}, ErrUnsupported
}

func (*Root) ReadAt(context.Context, string, uint64, uint64) ([]byte, uint64, error) {
	return nil, 0, ErrUnsupported
}

func (*Root) WriteChunk(context.Context, string, uint64, []byte, *uint32) (sandbox.FileInfo, error) {
	return sandbox.FileInfo{}, ErrUnsupported
}

func (*Root) List(context.Context, string, uint64, uint64) (sandbox.ListResult, bool, error) {
	return sandbox.ListResult{}, false, ErrUnsupported
}

func (*Root) Remove(context.Context, string, bool) error { return ErrUnsupported }

func (*Root) Mkdir(context.Context, string, uint32, bool) (sandbox.FileInfo, error) {
	return sandbox.FileInfo{}, ErrUnsupported
}

func (*Root) Close() error { return nil }
