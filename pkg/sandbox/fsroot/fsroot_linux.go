// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package fsroot

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"sort"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/misscomputer/misscomputer-subnet/pkg/sandbox"
)

const resolveInRoot = unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS

// Root is an open sandbox root directory.
type Root struct {
	mu sync.RWMutex
	fd int
}

// Open opens dir as a sandbox root. It fails with ErrUnsupported when the
// kernel cannot resolve paths in-root.
func Open(dir string) (*Root, error) {
	fd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	probe, err := unix.Openat2(fd, ".", &unix.OpenHow{Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: resolveInRoot})
	if err != nil {
		_ = unix.Close(fd)
		if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EPERM) {
			return nil, ErrUnsupported
		}
		return nil, err
	}
	_ = unix.Close(probe)
	return &Root{fd: fd}, nil
}

// Close releases the root descriptor.
func (r *Root) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fd < 0 {
		return nil
	}
	err := unix.Close(r.fd)
	r.fd = -1
	return err
}

func relative(path string) string {
	if path == "/" {
		return "."
	}
	return strings.TrimPrefix(path, "/")
}

// openIn resolves path in-root with openat2. EAGAIN (a concurrent rename
// raced the resolution) is retried a bounded number of times.
func (r *Root) openIn(path string, flags int, mode uint32) (int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.fd < 0 {
		return -1, os.ErrClosed
	}
	how := unix.OpenHow{Flags: uint64(flags | unix.O_CLOEXEC), Mode: uint64(mode), Resolve: resolveInRoot}
	for attempt := 0; ; attempt++ {
		fd, err := unix.Openat2(r.fd, relative(path), &how)
		if errors.Is(err, unix.EAGAIN) && attempt < 8 {
			continue
		}
		return fd, err
	}
}

// openParent resolves the parent directory of path in-root and returns its
// descriptor and the final component, which the caller handles with *at
// calls and never follows.
func (r *Root) openParent(path string) (int, string, error) {
	index := strings.LastIndexByte(path, '/')
	parent, name := path[:index], path[index+1:]
	if parent == "" {
		parent = "/"
	}
	fd, err := r.openIn(parent, unix.O_PATH|unix.O_DIRECTORY, 0)
	return fd, name, err
}

func fileInfo(st *unix.Stat_t) sandbox.FileInfo {
	info := sandbox.FileInfo{Mode: st.Mode & sandbox.MaxFileModeBits, Size: uint64(st.Size), Type: sandbox.FileTypeOther}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		info.Type = sandbox.FileTypeFile
	case unix.S_IFDIR:
		info.Type = sandbox.FileTypeDirectory
	case unix.S_IFLNK:
		info.Type = sandbox.FileTypeSymlink
	}
	if st.Size < 0 {
		info.Size = 0
	}
	return info
}

func checkPath(path string, allowRoot bool) error {
	return sandbox.ValidOpPath(path, allowRoot)
}

// Stat describes path, following symlinks in-root.
func (r *Root) Stat(ctx context.Context, path string) (sandbox.FileInfo, error) {
	if err := checkPath(path, true); err != nil {
		return sandbox.FileInfo{}, err
	}
	if err := ctx.Err(); err != nil {
		return sandbox.FileInfo{}, err
	}
	fd, err := r.openIn(path, unix.O_PATH, 0)
	if err != nil {
		return sandbox.FileInfo{}, err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return sandbox.FileInfo{}, err
	}
	return fileInfo(&st), nil
}

// ReadAt returns at most limit bytes of the regular file at path from
// offset, and the file size. FIFOs, devices and sockets are refused without
// blocking.
func (r *Root) ReadAt(ctx context.Context, path string, offset, limit uint64) ([]byte, uint64, error) {
	if err := checkPath(path, false); err != nil {
		return nil, 0, err
	}
	if limit == 0 || limit > sandbox.MaxChunkBytes {
		return nil, 0, errors.New("fsroot: read limit is out of bounds")
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	fd, err := r.openIn(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, 0, err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, 0, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, 0, ErrNotFile
	}
	size := uint64(st.Size)
	if offset >= size {
		return []byte{}, size, nil
	}
	want := min(limit, size-offset)
	buffer := make([]byte, want)
	read := 0
	for read < len(buffer) {
		n, err := unix.Pread(fd, buffer[read:], int64(offset)+int64(read))
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, 0, err
		}
		if n == 0 {
			break
		}
		read += n
	}
	return buffer[:read], size, nil
}

// WriteChunk writes data at offset. Offset 0 atomically creates or replaces
// a regular file with exactly mode (temp file plus rename in the parent
// directory). A later offset must equal the current size and appends. A
// final-component symlink, directory or special file is refused, never
// written through.
func (r *Root) WriteChunk(ctx context.Context, path string, offset uint64, data []byte, mode *uint32) (sandbox.FileInfo, error) {
	if err := checkPath(path, false); err != nil {
		return sandbox.FileInfo{}, err
	}
	if len(data) == 0 || len(data) > sandbox.MaxChunkBytes || (offset == 0) != (mode != nil) || (mode != nil && *mode > sandbox.MaxFileModeBits) {
		return sandbox.FileInfo{}, errors.New("fsroot: write chunk, offset or mode is invalid")
	}
	if offset > sandbox.MaxFileWriteBytes || offset+uint64(len(data)) > sandbox.MaxFileWriteBytes {
		return sandbox.FileInfo{}, ErrTooLarge
	}
	if err := ctx.Err(); err != nil {
		return sandbox.FileInfo{}, err
	}
	parent, name, err := r.openParent(path)
	if err != nil {
		return sandbox.FileInfo{}, err
	}
	defer unix.Close(parent)
	if offset == 0 {
		return createReplace(parent, name, data, *mode)
	}
	fd, err := unix.Openat(parent, name, unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EISDIR) || errors.Is(err, unix.ENXIO) {
		return sandbox.FileInfo{}, ErrNotFile
	}
	if err != nil {
		return sandbox.FileInfo{}, err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return sandbox.FileInfo{}, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return sandbox.FileInfo{}, ErrNotFile
	}
	if uint64(st.Size) != offset {
		return sandbox.FileInfo{}, ErrOffsetMismatch
	}
	if err := pwriteAll(fd, data, int64(offset)); err != nil {
		return sandbox.FileInfo{}, err
	}
	if err := unix.Fstat(fd, &st); err != nil {
		return sandbox.FileInfo{}, err
	}
	return fileInfo(&st), nil
}

func pwriteAll(fd int, data []byte, offset int64) error {
	for written := 0; written < len(data); {
		n, err := unix.Pwrite(fd, data[written:], offset+int64(written))
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		written += n
	}
	return nil
}

func createReplace(parent int, name string, data []byte, mode uint32) (sandbox.FileInfo, error) {
	var existing unix.Stat_t
	switch err := unix.Fstatat(parent, name, &existing, unix.AT_SYMLINK_NOFOLLOW); {
	case err == nil && existing.Mode&unix.S_IFMT != unix.S_IFREG:
		return sandbox.FileInfo{}, ErrNotFile
	case err != nil && !errors.Is(err, unix.ENOENT):
		return sandbox.FileInfo{}, err
	}
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		return sandbox.FileInfo{}, err
	}
	temporary := ".sandbox-op-" + hex.EncodeToString(random[:]) + ".tmp"
	fd, err := unix.Openat(parent, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return sandbox.FileInfo{}, err
	}
	committed := false
	defer func() {
		_ = unix.Close(fd)
		if !committed {
			_ = unix.Unlinkat(parent, temporary, 0)
		}
	}()
	if err := pwriteAll(fd, data, 0); err != nil {
		return sandbox.FileInfo{}, err
	}
	if err := unix.Fchmod(fd, mode); err != nil {
		return sandbox.FileInfo{}, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return sandbox.FileInfo{}, err
	}
	// rename never follows the final component: a symlink that appeared
	// since the check above is replaced, not written through. A directory
	// that appeared makes the rename fail.
	if err := unix.Renameat(parent, temporary, parent, name); err != nil {
		if errors.Is(err, unix.EISDIR) || errors.Is(err, unix.ENOTEMPTY) || errors.Is(err, unix.EEXIST) {
			return sandbox.FileInfo{}, ErrNotFile
		}
		return sandbox.FileInfo{}, err
	}
	committed = true
	return fileInfo(&st), nil
}

// List returns at most limit addressable entries of the directory at path,
// sorted by name bytes, starting at entry offset, and whether the listing
// is exhausted. Symlinks are reported as symlinks, not followed.
func (r *Root) List(ctx context.Context, path string, offset, limit uint64) (sandbox.ListResult, bool, error) {
	if err := checkPath(path, true); err != nil {
		return sandbox.ListResult{}, false, err
	}
	if limit == 0 || limit > sandbox.MaxListEntries {
		return sandbox.ListResult{}, false, errors.New("fsroot: list limit is out of bounds")
	}
	fd, err := r.openIn(path, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return sandbox.ListResult{}, false, err
	}
	directory := os.NewFile(uintptr(fd), "sandbox-directory")
	defer directory.Close()
	names, err := readNames(ctx, directory)
	if err != nil {
		return sandbox.ListResult{}, false, err
	}
	result := sandbox.ListResult{Entries: []sandbox.ListEntry{}}
	addressable := names[:0]
	for _, name := range names {
		if sandbox.ValidOpPath("/"+name, false) != nil {
			result.Unaddressable++
			continue
		}
		addressable = append(addressable, name)
	}
	sort.Strings(addressable)
	if offset >= uint64(len(addressable)) {
		return result, true, nil
	}
	end := min(uint64(len(addressable)), offset+limit)
	for _, name := range addressable[offset:end] {
		if err := ctx.Err(); err != nil {
			return sandbox.ListResult{}, false, err
		}
		var st unix.Stat_t
		if err := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			if errors.Is(err, unix.ENOENT) {
				continue // removed while listing
			}
			return sandbox.ListResult{}, false, err
		}
		result.Entries = append(result.Entries, sandbox.ListEntry{FileInfo: fileInfo(&st), Name: name})
	}
	return result, end == uint64(len(addressable)), nil
}

func readNames(ctx context.Context, directory *os.File) ([]string, error) {
	var names []string
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		batch, err := directory.Readdirnames(1024)
		names = append(names, batch...)
		if len(names) > MaxDirectoryScan {
			return nil, ErrDirectoryTooBig
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return names, nil
			}
			return nil, err
		}
		if len(batch) == 0 {
			return names, nil
		}
	}
}

// Remove deletes the entry at path. A symlink is removed itself; a
// directory only when empty unless recursive. Recursive removal walks by
// directory descriptors and never follows a symlink.
func (r *Root) Remove(ctx context.Context, path string, recursive bool) error {
	if err := checkPath(path, false); err != nil {
		return err
	}
	parent, name, err := r.openParent(path)
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	return removeAt(ctx, parent, name, recursive, 0)
}

func removeAt(ctx context.Context, parent int, name string, recursive bool, depth int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var st unix.Stat_t
	if err := unix.Fstatat(parent, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return unix.Unlinkat(parent, name, 0)
	}
	if recursive {
		if depth >= MaxRemoveDepth {
			return ErrTreeTooDeep
		}
		fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		directory := os.NewFile(uintptr(fd), "sandbox-directory")
		// Read every name before deleting any, so deletion cannot make
		// the directory stream skip entries.
		children, err := readNames(ctx, directory)
		for _, child := range children {
			if err != nil {
				break
			}
			if childErr := removeAt(ctx, fd, child, true, depth+1); childErr != nil && !errors.Is(childErr, unix.ENOENT) {
				err = childErr
			}
		}
		directory.Close()
		if err != nil {
			return err
		}
	}
	return unix.Unlinkat(parent, name, unix.AT_REMOVEDIR)
}

// Mkdir creates the directory at path with exactly mode. With parents,
// missing ancestors are created with the same mode and an existing
// directory at path is not an error.
func (r *Root) Mkdir(ctx context.Context, path string, mode uint32, parents bool) (sandbox.FileInfo, error) {
	if err := checkPath(path, false); err != nil {
		return sandbox.FileInfo{}, err
	}
	if mode > sandbox.MaxFileModeBits {
		return sandbox.FileInfo{}, errors.New("fsroot: mode must hold permission bits only")
	}
	targets := []string{path}
	if parents {
		targets = targets[:0]
		for index := 1; index < len(path); index++ {
			if path[index] == '/' {
				targets = append(targets, path[:index])
			}
		}
		targets = append(targets, path)
	}
	for index, target := range targets {
		if err := ctx.Err(); err != nil {
			return sandbox.FileInfo{}, err
		}
		final := index == len(targets)-1
		if err := r.mkdirOne(target, mode, parents || !final); err != nil {
			return sandbox.FileInfo{}, err
		}
	}
	return r.Stat(ctx, path)
}

func (r *Root) mkdirOne(path string, mode uint32, existingOK bool) error {
	parent, name, err := r.openParent(path)
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	if err := unix.Mkdirat(parent, name, 0o700); err != nil {
		if !errors.Is(err, unix.EEXIST) || !existingOK {
			return err
		}
		// An existing ancestor must resolve, in-root, to a directory.
		fd, openErr := r.openIn(path, unix.O_PATH|unix.O_DIRECTORY, 0)
		if openErr != nil {
			return openErr
		}
		return unix.Close(fd)
	}
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return unix.Fchmod(fd, mode)
}
