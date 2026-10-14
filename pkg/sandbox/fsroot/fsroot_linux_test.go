// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package fsroot_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/sandbox"
	"github.com/misscomputer/misscomputer-subnet/pkg/sandbox/fsroot"
)

// hostileTree builds <tmp>/outside/secret and a sandbox root whose links
// point at it by absolute host path, by "..", and through a symlinked
// directory. It returns the opened root, the root path and the outside dir.
func hostileTree(t *testing.T) (*fsroot.Root, string, string) {
	t.Helper()
	base := t.TempDir()
	outside := filepath.Join(base, "outside")
	root := filepath.Join(base, "root")
	for _, dir := range []string{outside, filepath.Join(outside, "dir"), filepath.Join(root, "workspace")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("host secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "dir", "keep"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{
		"workspace/abs":     outside,                        // absolute host path
		"workspace/up":      "../../../../../../../outside", // climbs with ..
		"workspace/abssec":  filepath.Join(outside, "secret"),
		"workspace/hostdir": filepath.Join(outside, "dir"),
		"workspace/inside":  "/workspace/real.txt", // absolute, in-root
	} {
		if err := os.Symlink(target, filepath.Join(root, link)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "workspace", "real.txt"), []byte("inside"), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := fsroot.Open(root)
	if errors.Is(err, fsroot.ErrUnsupported) {
		t.Skip("kernel has no openat2 in-root resolution")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r, root, outside
}

func code(err error) string { return fsroot.Code(err) }

// Every symlink resolves as if the sandbox root were "/": no read, stat or
// write reaches the host tree, while a legitimate in-root absolute link works.
func TestSymlinksResolveInsideTheRoot(t *testing.T) {
	r, _, outside := hostileTree(t)
	ctx := context.Background()
	data, _, err := r.ReadAt(ctx, "/workspace/inside", 0, 64)
	if err != nil || string(data) != "inside" {
		t.Fatalf("in-root absolute link: %q %v", data, err)
	}
	for _, path := range []string{"/workspace/abs/secret", "/workspace/up/secret", "/workspace/abssec", "/workspace/hostdir/keep"} {
		if data, _, err := r.ReadAt(ctx, path, 0, 64); code(err) != "path_not_found" {
			t.Errorf("read %s escaped or failed oddly: %q %v", path, data, err)
		}
		if _, err := r.Stat(ctx, path); code(err) != "path_not_found" {
			t.Errorf("stat %s: %v", path, err)
		}
	}
	// A write under a symlinked directory pointing at the host lands
	// inside the root (or fails), never in the host directory.
	mode := uint32(0o644)
	if _, err := r.WriteChunk(ctx, "/workspace/hostdir/planted", 0, []byte("x"), &mode); code(err) != "path_not_found" {
		t.Errorf("write through host-dir link: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "dir", "planted")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("write escaped into the host directory")
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 2 {
		t.Fatalf("host tree changed: %v", entries)
	}
}

// A final-component symlink is never written through; replacing or
// appending to it is refused and its target is untouched.
func TestWriteRefusesFinalSymlinkAndSpecialFiles(t *testing.T) {
	r, root, outside := hostileTree(t)
	ctx := context.Background()
	mode := uint32(0o600)
	for _, offset := range []uint64{0, 11} {
		var m *uint32
		if offset == 0 {
			m = &mode
		}
		if _, err := r.WriteChunk(ctx, "/workspace/abssec", offset, []byte("pwned"), m); code(err) != "path_not_file" {
			t.Errorf("offset %d write through final symlink: %v", offset, err)
		}
	}
	if data, _ := os.ReadFile(filepath.Join(outside, "secret")); string(data) != "host secret" {
		t.Fatalf("host secret modified: %q", data)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "workspace", "fifo"), 0o644); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 2)
	go func() { _, _, err := r.ReadAt(ctx, "/workspace/fifo", 0, 64); done <- err }()
	go func() { _, err := r.WriteChunk(ctx, "/workspace/fifo", 1, []byte("x"), nil); done <- err }()
	for range 2 {
		select {
		case err := <-done:
			if code(err) != "path_not_file" {
				t.Errorf("fifo: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("a FIFO blocked the operation")
		}
	}
	if _, err := r.WriteChunk(ctx, "/workspace", 0, []byte("x"), &mode); code(err) != "path_not_file" {
		t.Errorf("write over a directory: %v", err)
	}
}

// Chunked writes: offset 0 creates or replaces with exactly the mode, later
// chunks must append at the current size.
func TestChunkedWrite(t *testing.T) {
	r, root, _ := hostileTree(t)
	ctx := context.Background()
	mode := uint32(0o640)
	info, err := r.WriteChunk(ctx, "/workspace/out.bin", 0, []byte("hello "), &mode)
	if err != nil || info.Size != 6 || info.Mode != 0o640 || info.Type != sandbox.FileTypeFile {
		t.Fatalf("create: %+v %v", info, err)
	}
	if _, err := r.WriteChunk(ctx, "/workspace/out.bin", 3, []byte("x"), nil); code(err) != "offset_mismatch" {
		t.Fatalf("overlapping chunk: %v", err)
	}
	if info, err = r.WriteChunk(ctx, "/workspace/out.bin", 6, []byte("world"), nil); err != nil || info.Size != 11 {
		t.Fatalf("append: %+v %v", info, err)
	}
	data, size, err := r.ReadAt(ctx, "/workspace/out.bin", 6, 3)
	if err != nil || string(data) != "wor" || size != 11 {
		t.Fatalf("ranged read: %q %d %v", data, size, err)
	}
	if data, _, _ = r.ReadAt(ctx, "/workspace/out.bin", 11, 3); len(data) != 0 {
		t.Fatalf("read at end: %q", data)
	}
	// offset 0 replaces atomically and leaves no temporary file behind.
	if _, err := r.WriteChunk(ctx, "/workspace/out.bin", 0, []byte("new"), &mode); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(filepath.Join(root, "workspace"))
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".tmp" {
			t.Fatalf("temporary file left behind: %s", entry.Name())
		}
	}
	if data, _ := os.ReadFile(filepath.Join(root, "workspace", "out.bin")); string(data) != "new" {
		t.Fatalf("replace: %q", data)
	}
	if _, err := r.WriteChunk(ctx, "/missing/out.bin", 0, []byte("x"), &mode); code(err) != "path_not_found" {
		t.Fatalf("missing parent: %v", err)
	}
	if _, err := r.WriteChunk(ctx, "/workspace/out.bin", sandbox.MaxFileWriteBytes, []byte("x"), nil); code(err) != "file_too_large" {
		t.Fatalf("past the write bound: %v", err)
	}
}

// List is sorted, reports symlinks as symlinks, pages by entry cursor, and
// counts names that v1 paths cannot address instead of renaming them.
func TestListPagesSortedAddressableEntries(t *testing.T) {
	r, root, _ := hostileTree(t)
	ctx := context.Background()
	for _, name := range []string{"caf\xc3\xa9", "new\nline"} {
		if err := os.WriteFile(filepath.Join(root, "workspace", name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	first, eof, err := r.List(ctx, "/workspace", 0, 3)
	if err != nil || eof || first.Unaddressable != 2 {
		t.Fatalf("first page: %+v eof=%v %v", first, eof, err)
	}
	names := []string{}
	for _, entry := range first.Entries {
		names = append(names, entry.Name+":"+entry.Type)
	}
	if want := []string{"abs:symlink", "abssec:symlink", "hostdir:symlink"}; !slices.Equal(names, want) {
		t.Fatalf("first page %v, want %v", names, want)
	}
	rest, eof, err := r.List(ctx, "/workspace", 3, 1000)
	if err != nil || !eof || len(rest.Entries) != 3 || rest.Entries[2].Name != "up" || rest.Entries[1].Type != sandbox.FileTypeFile {
		t.Fatalf("second page: %+v eof=%v %v", rest, eof, err)
	}
	if err := first.Validate(); err != nil {
		t.Fatalf("listing violates the result contract: %v", err)
	}
	if _, _, err := r.List(ctx, "/workspace/real.txt", 0, 10); code(err) != "path_not_directory" {
		t.Fatalf("list a file: %v", err)
	}
}

// Recursive remove walks by descriptor and deletes a symlink itself, never
// what it points at.
func TestRemoveNeverFollowsSymlinks(t *testing.T) {
	r, root, outside := hostileTree(t)
	ctx := context.Background()
	if err := r.Remove(ctx, "/workspace", false); code(err) != "directory_not_empty" {
		t.Fatalf("non-recursive remove of a full directory: %v", err)
	}
	if err := r.Remove(ctx, "/workspace/abs", true); err != nil {
		t.Fatalf("remove link: %v", err)
	}
	if err := r.Remove(ctx, "/workspace", true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, "workspace")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("workspace survived")
	}
	for _, path := range []string{"secret", "dir/keep"} {
		if _, err := os.Stat(filepath.Join(outside, path)); err != nil {
			t.Fatalf("host %s removed through a link: %v", path, err)
		}
	}
	if err := r.Remove(ctx, "/workspace", true); code(err) != "path_not_found" {
		t.Fatalf("remove missing: %v", err)
	}
	expired, cancel := context.WithCancel(ctx)
	cancel()
	if err := r.Remove(expired, "/anything", true); code(err) != sandbox.OpCodeDeadline {
		t.Fatalf("remove after deadline: %v", err)
	}
}

func TestMkdir(t *testing.T) {
	r, _, outside := hostileTree(t)
	ctx := context.Background()
	info, err := r.Mkdir(ctx, "/workspace/a/b/c", 0o750, true)
	if err != nil || info.Type != sandbox.FileTypeDirectory || info.Mode != 0o750 {
		t.Fatalf("mkdir -p: %+v %v", info, err)
	}
	if _, err := r.Mkdir(ctx, "/workspace/a/b/c", 0o750, true); err != nil {
		t.Fatalf("mkdir -p of an existing directory: %v", err)
	}
	if _, err := r.Mkdir(ctx, "/workspace/a", 0o750, false); code(err) != "path_exists" {
		t.Fatalf("mkdir existing: %v", err)
	}
	if _, err := r.Mkdir(ctx, "/workspace/real.txt/x", 0o750, true); code(err) != "path_not_directory" {
		t.Fatalf("mkdir under a file: %v", err)
	}
	if _, err := r.Mkdir(ctx, "/workspace/hostdir/new", 0o750, false); code(err) != "path_not_found" {
		t.Fatalf("mkdir through host-dir link: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "dir", "new")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("mkdir escaped into the host directory")
	}
}

// Opened at "/", procfs magic links are refused while an ordinary procfs
// symlink resolves. RESOLVE_IN_ROOT currently implies the refusal;
// RESOLVE_NO_MAGICLINKS keeps it if that kernel behavior changes. Plain
// openat2 without the resolve flags fails this test.
func TestMagicLinksAreRefused(t *testing.T) {
	r, err := fsroot.Open("/")
	if errors.Is(err, fsroot.ErrUnsupported) {
		t.Skip("kernel has no openat2 in-root resolution")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	ctx := context.Background()
	if _, err := os.Stat("/proc/self/root"); err != nil {
		t.Skip("procfs is not mounted")
	}
	if _, err := r.Stat(ctx, "/proc/self"); err != nil {
		t.Fatalf("ordinary procfs symlink: %v", err)
	}
	for _, path := range []string{"/proc/self/root", "/proc/self/root/etc", "/proc/self/cwd", "/proc/self/exe"} {
		if _, err := r.Stat(ctx, path); code(err) != "path_refused" {
			t.Errorf("magic link %s: %v", path, err)
		}
	}
}
