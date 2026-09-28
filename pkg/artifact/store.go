// SPDX-License-Identifier: AGPL-3.0-only

package artifact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// maxManifestBytes bounds an artifact manifest read before it is parsed.
const maxManifestBytes = 1 << 20

type Store interface {
	Put(ctx context.Context, key string, body []byte, contentType string) error
	Get(ctx context.Context, key string) ([]byte, error)
}

// BoundedGetter is an optional Store capability used when a caller knows a
// tighter object limit than the store-wide default. Implementations must stop
// reading once they can prove the object exceeds maximum bytes.
//
// Store remains unchanged so existing implementations retain compatibility.
type BoundedGetter interface {
	GetBounded(ctx context.Context, key string, maximum int64) ([]byte, error)
}

// ExactDeleter deletes one exact object key. Deliberately keeping deletion
// separate from Store lets production miners run with credentials that have
// no delete permission.
type ExactDeleter interface {
	Delete(ctx context.Context, key string) error
}

func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func BlobKey(digest string) string {
	return "v1/blobs/sha256/" + strings.TrimPrefix(digest, "sha256:")
}

func ManifestKey(digest string) string {
	return "v1/manifests/" + strings.TrimPrefix(digest, "sha256:") + ".json"
}

func getBounded(ctx context.Context, store Store, key string, maximum int64) ([]byte, error) {
	if bounded, ok := store.(BoundedGetter); ok {
		return bounded.GetBounded(ctx, key, maximum)
	}
	return store.Get(ctx, key)
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return err
	}
	return errors.New("manifest contains trailing JSON data")
}

func validateDigest(digest string) error {
	const prefix = "sha256:"
	if !strings.HasPrefix(digest, prefix) || len(digest) != len(prefix)+sha256.Size*2 {
		return errors.New("digest must be a lowercase sha256 value")
	}
	encoded := strings.TrimPrefix(digest, prefix)
	if encoded != strings.ToLower(encoded) {
		return errors.New("digest must use lowercase hexadecimal")
	}
	if _, err := hex.DecodeString(encoded); err != nil {
		return errors.New("digest contains invalid hexadecimal")
	}
	return nil
}

// DeleteExact deletes only the explicit keys supplied by the caller. It does
// not list, expand prefixes, interpret wildcards, or derive additional keys.
// Duplicate keys are harmless and each distinct key is attempted once.
func DeleteExact(ctx context.Context, store ExactDeleter, keys []string) error {
	if ctx == nil {
		return errors.New("artifact cleanup context is required")
	}
	if store == nil {
		return errors.New("artifact cleanup store is required")
	}
	seen := make(map[string]struct{}, len(keys))
	var failures []error
	for _, key := range keys {
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		if err := validateObjectKey(key); err != nil {
			failures = append(failures, err)
			continue
		}
		if err := store.Delete(ctx, key); err != nil {
			failures = append(failures, fmt.Errorf("delete artifact key %q: %w", safeErrorKey(key), err))
		}
	}
	return errors.Join(failures...)
}

type FileStore struct{ Root string }

func (s FileStore) Put(ctx context.Context, key string, body []byte, _ string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	path, err := s.path(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".upload-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err = tmp.Write(body); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func (s FileStore) Get(ctx context.Context, key string) ([]byte, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	path, err := s.path(key)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	body, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	return body, nil
}

// GetBounded reads one file while enforcing a caller-specific transfer bound.
// The initial size check avoids reading a known-oversize file; readBounded
// still protects against a file growing between Stat and Read.
func (s FileStore) GetBounded(ctx context.Context, key string, maximum int64) ([]byte, error) {
	if maximum < 1 {
		return nil, errors.New("artifact response limit must be positive")
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	path, err := s.path(key)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > maximum {
		return nil, errObjectTooLarge
	}
	body, err := readBounded(f, maximum)
	if err != nil {
		return nil, err
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	return body, nil
}

func (s FileStore) path(key string) (string, error) {
	if err := validateObjectKey(key); err != nil {
		return "", err
	}
	root := filepath.Clean(s.Root)
	objectPath := filepath.Join(root, filepath.FromSlash(key))
	relative, err := filepath.Rel(root, objectPath)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("invalid artifact key %q", safeErrorKey(key))
	}
	return objectPath, nil
}

func (s FileStore) Delete(ctx context.Context, key string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	path, err := s.path(key)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func validateObjectKey(key string) error {
	if key == "" || !utf8.ValidString(key) || strings.HasPrefix(key, "/") || strings.HasSuffix(key, "/") || strings.ContainsAny(key, "\\\r\n\x00") {
		return fmt.Errorf("invalid artifact key %q", safeErrorKey(key))
	}
	for _, segment := range strings.Split(key, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return fmt.Errorf("invalid artifact key %q", safeErrorKey(key))
		}
	}
	return nil
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return errors.New("artifact context is required")
	}
	return ctx.Err()
}

var errObjectTooLarge = errors.New("artifact object exceeds configured limit")

// readBounded reads at most maximum bytes into the returned allocation and
// probes one additional byte without calculating maximum+1, which avoids an
// integer overflow for caller-provided limits.
func readBounded(reader io.Reader, maximum int64) ([]byte, error) {
	if maximum < 1 {
		return nil, errors.New("artifact response limit must be positive")
	}
	body, err := io.ReadAll(io.LimitReader(reader, maximum))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) < maximum {
		return body, nil
	}
	var extra [1]byte
	n, err := io.ReadFull(reader, extra[:])
	if n != 0 {
		return nil, errObjectTooLarge
	}
	if errors.Is(err, io.EOF) {
		return body, nil
	}
	return nil, err
}
