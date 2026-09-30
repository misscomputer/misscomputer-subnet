// SPDX-License-Identifier: AGPL-3.0-only

package static

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
)

const (
	// DefaultFetchConcurrency bounds concurrent blob downloads of one site.
	DefaultFetchConcurrency = 4
	// freeSpaceReserve is left free on the cache filesystem after a pin.
	freeSpaceReserve = int64(256 << 20)
	chunkSize        = 32 << 10
)

// Cache is the miner's content-addressed store of verified static files.
// A blob is present only after its length and SHA-256 matched a manifest
// entry, and it stays present only while a pinned site references it.
type Cache struct {
	root     string
	maxBytes int64

	mu        sync.Mutex
	refs      map[string]int
	sizes     map[string]int64
	occupancy int64
	locks     map[string]*sync.Mutex
}

// cacheDirectory is the only directory OpenCache creates or sweeps under the
// operator-configured root, so a misconfigured root cannot erase unrelated
// data.
const cacheDirectory = "misscomputer-static-v1"

// OpenCache prepares <root>/misscomputer-static-v1 and removes every blob
// and partial download in it: pins do not survive a restart, so nothing on
// disk is referenced yet and every served byte is re-fetched and re-hashed.
func OpenCache(root string, maxBytes int64) (*Cache, error) {
	if root == "" || maxBytes < 1 {
		return nil, errors.New("static cache needs a directory and a positive byte quota")
	}
	base, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	absolute := filepath.Join(base, cacheDirectory)
	for _, dir := range []string{"blobs", "tmp"} {
		path := filepath.Join(absolute, dir)
		if err := os.RemoveAll(path); err != nil {
			return nil, fmt.Errorf("sweep static cache: %w", err)
		}
		if err := os.MkdirAll(path, 0o700); err != nil {
			return nil, err
		}
	}
	return &Cache{
		root: absolute, maxBytes: maxBytes, refs: make(map[string]int), sizes: make(map[string]int64),
		locks: make(map[string]*sync.Mutex),
	}, nil
}

func (c *Cache) blobPath(sha string) string { return filepath.Join(c.root, "blobs", sha) }

// Occupancy is the number of bytes referenced by pinned sites.
func (c *Cache) Occupancy() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.occupancy
}

// PinOptions bounds one pin; zero values select the defaults.
type PinOptions struct {
	Concurrency int
}

// Pin verifies every file of a parsed manifest into the cache and returns
// the pinned site. Nothing is servable unless every listed blob matched its
// size and SHA-256; any failure releases what was reserved. ctx bounds the
// whole fetch.
func (c *Cache) Pin(ctx context.Context, blobs artifact.BlobOpener, siteDigest string, m Manifest, options PinOptions) (*Site, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	unique := make(map[string]int64, len(m.Files))
	var order []string
	for _, file := range m.Files {
		if _, seen := unique[file.BodySHA256]; !seen {
			order = append(order, file.BodySHA256)
		}
		unique[file.BodySHA256] = file.ContentLength
	}
	if err := c.reserve(unique); err != nil {
		return nil, err
	}
	site := &Site{Digest: siteDigest, Manifest: m, index: NewIndex(m), cache: c, blobs: unique}
	concurrency := options.Concurrency
	if concurrency < 1 {
		concurrency = DefaultFetchConcurrency
	}
	fetchCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	work := make(chan string)
	var once sync.Once
	var firstErr error
	var wait sync.WaitGroup
	for worker := 0; worker < concurrency; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for sha := range work {
				if err := c.ensure(fetchCtx, blobs, sha, unique[sha]); err != nil {
					once.Do(func() { firstErr = err; cancel() })
				}
			}
		}()
	}
dispatch:
	for _, sha := range order {
		select {
		case work <- sha:
		case <-fetchCtx.Done():
			break dispatch
		}
	}
	close(work)
	wait.Wait()
	if firstErr == nil && ctx.Err() != nil {
		firstErr = Fail(CodeFetchFailed, ctx.Err())
	}
	if firstErr != nil {
		site.Release()
		return nil, firstErr
	}
	return site, nil
}

// reserve adds one reference per unique blob, admitting the pin only if the
// referenced total stays within the cache quota and the filesystem has room.
func (c *Cache) reserve(unique map[string]int64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var added int64
	for sha, size := range unique {
		if c.refs[sha] > 0 && c.sizes[sha] != size {
			return failf(CodeManifestInvalid, "static_digest_length_inconsistent: cached digest")
		}
		if c.refs[sha] == 0 {
			added += size
		}
	}
	if c.occupancy+added > c.maxBytes {
		return Fail(CodeStorageExhausted, fmt.Errorf("static cache quota of %d bytes is exhausted", c.maxBytes))
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(c.root, &stat); err != nil {
		return Fail(CodeInternal, err)
	}
	if free := int64(stat.Bavail) * int64(stat.Bsize); free-added < freeSpaceReserve {
		return Fail(CodeStorageExhausted, errors.New("static cache filesystem lacks free space"))
	}
	for sha, size := range unique {
		c.refs[sha]++
		if c.refs[sha] == 1 {
			c.sizes[sha] = size
		}
	}
	c.occupancy += added
	return nil
}

func (c *Cache) release(unique map[string]int64) {
	c.mu.Lock()
	var remove []string
	for sha := range unique {
		c.refs[sha]--
		if c.refs[sha] <= 0 {
			c.occupancy -= c.sizes[sha]
			delete(c.refs, sha)
			delete(c.sizes, sha)
			remove = append(remove, sha)
		}
	}
	c.mu.Unlock()
	for _, sha := range remove {
		lock := c.blobLock(sha)
		lock.Lock()
		c.mu.Lock()
		referenced := c.refs[sha] > 0
		c.mu.Unlock()
		if !referenced {
			_ = os.Remove(c.blobPath(sha))
		}
		lock.Unlock()
	}
}

func (c *Cache) blobLock(sha string) *sync.Mutex {
	c.mu.Lock()
	defer c.mu.Unlock()
	lock := c.locks[sha]
	if lock == nil {
		lock = &sync.Mutex{}
		c.locks[sha] = lock
	}
	return lock
}

// ensure makes the blob present and verified. A present blob is rehashed
// rather than trusted; a mismatch is removed and fetched again.
func (c *Cache) ensure(ctx context.Context, blobs artifact.BlobOpener, sha string, size int64) error {
	lock := c.blobLock(sha)
	lock.Lock()
	defer lock.Unlock()
	path := c.blobPath(sha)
	if file, err := os.Open(path); err == nil {
		verifyErr := verifyReader(file, sha, size, io.Discard)
		file.Close()
		if verifyErr == nil {
			return nil
		}
		// A different pinned site may still be serving this blob. A new
		// requester's verification failure must never delete its bytes.
		c.mu.Lock()
		if c.refs[sha] > 1 {
			c.mu.Unlock()
			return Fail(CodeVerifyFailed, verifyErr)
		}
		removeErr := os.Remove(path)
		c.mu.Unlock()
		if removeErr != nil {
			return Fail(CodeInternal, removeErr)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return Fail(CodeInternal, err)
	}
	var reader io.ReadCloser = io.NopCloser(strings.NewReader(""))
	var err error
	if size > 0 {
		// A zero-length body is fully determined by its digest; verifyReader
		// still checks that the digest is the empty-string SHA-256.
		reader, err = blobs.OpenBounded(ctx, BlobKey(sha), size)
	}
	if err != nil {
		if artifact.IsOversize(err) {
			return failf(CodeVerifyFailed, "static blob exceeds its manifest size")
		}
		return Fail(CodeFetchFailed, err)
	}
	defer reader.Close()
	name := make([]byte, 16)
	if _, err := rand.Read(name); err != nil {
		return Fail(CodeInternal, err)
	}
	temporary := filepath.Join(c.root, "tmp", sha+"."+hex.EncodeToString(name))
	out, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return Fail(CodeInternal, err)
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(temporary)
		}
	}()
	copyErr := verifyReader(&contextReader{ctx: ctx, reader: reader}, sha, size, out)
	if copyErr == nil {
		copyErr = out.Sync()
	}
	if closeErr := out.Close(); copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		switch {
		case errors.Is(copyErr, errMismatch) || artifact.IsOversize(copyErr):
			return Fail(CodeVerifyFailed, copyErr)
		case ctx.Err() != nil:
			return Fail(CodeFetchFailed, ctx.Err())
		default:
			// A store read failure or a local write failure (ENOSPC maps to
			// resource_exhausted inside fail).
			return Fail(CodeFetchFailed, copyErr)
		}
	}
	if err := os.Chmod(temporary, 0o400); err != nil {
		return Fail(CodeInternal, err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return Fail(CodeInternal, err)
	}
	keep = true
	return nil
}

var errMismatch = errors.New("static blob does not match its manifest entry")

// verifyReader copies exactly size bytes whose SHA-256 is sha to out and
// fails on any other length or digest.
func verifyReader(reader io.Reader, sha string, size int64, out io.Writer) error {
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(hash, out), io.LimitReader(reader, size+1))
	if err != nil {
		return err
	}
	if written != size {
		return fmt.Errorf("%w: length %d differs from manifest size %d", errMismatch, written, size)
	}
	if hex.EncodeToString(hash.Sum(nil)) != sha {
		return fmt.Errorf("%w: digest differs from the manifest", errMismatch)
	}
	return nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

// Site is one pinned, fully verified site version. It never changes; a new
// version is a new pin for a new endpoint incarnation.
type Site struct {
	Digest   string
	Manifest Manifest
	index    *Index
	cache    *Cache
	blobs    map[string]int64
	once     sync.Once
}

// Resolve answers a request against the pinned manifest (§5.1 steps 2-7).
func (s *Site) Resolve(method, rawPath string, hasBody bool) Response {
	return s.index.Resolve(method, rawPath, hasBody)
}

// Index is the pinned site's response table.
func (s *Site) Index() *Index { return s.index }

// Release drops the site's blob references; unreferenced blobs are removed.
func (s *Site) Release() { s.once.Do(func() { s.cache.release(s.blobs) }) }

// Open implements BodySource from the pinned local copy.
func (s *Site) Open(file File) (io.ReadCloser, error) {
	return os.Open(s.cache.blobPath(file.BodySHA256))
}
