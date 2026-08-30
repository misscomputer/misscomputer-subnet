// SPDX-License-Identifier: AGPL-3.0-only

package artifact

import (
	"bytes"
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
	"time"
	"unicode/utf8"
)

const (
	manifestMediaType = "application/vnd.misscomputer.manifest.v1+json"
	layerMediaType    = "application/vnd.misscomputer.layer.v1"
	maxManifestBytes  = 1 << 20
	maxManifestLayers = 1024
)

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

type Layer struct {
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	MediaType string `json:"media_type"`
}

type Manifest struct {
	SchemaVersion int               `json:"schema_version"`
	CreatedAt     time.Time         `json:"created_at"`
	WorkloadType  string            `json:"workload_type"`
	ImageDigest   string            `json:"image_digest"`
	Layers        []Layer           `json:"layers"`
	Annotations   map[string]string `json:"annotations,omitempty"`
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

func Publish(ctx context.Context, store Store, workloadType string, layers [][]byte, annotations map[string]string) (Manifest, error) {
	m, err := PrepareManifest(workloadType, layers, annotations, time.Now().UTC())
	if err != nil {
		return Manifest{}, err
	}
	return PublishPrepared(ctx, store, m, layers)
}

// PrepareManifest fixes the complete content-addressed artifact identity
// before any object-store side effect. Durable orchestrators can persist the
// returned manifest and exact keys first, closing the publish/crash orphan
// window without changing the existing artifact format.
func PrepareManifest(workloadType string, layers [][]byte, annotations map[string]string, createdAt time.Time) (Manifest, error) {
	if createdAt.IsZero() || createdAt.Location() != time.UTC {
		return Manifest{}, errors.New("artifact creation time must be a canonical UTC timestamp")
	}
	createdAt = createdAt.Round(0)
	if strings.TrimSpace(workloadType) == "" || workloadType != strings.TrimSpace(workloadType) {
		return Manifest{}, errors.New("artifact workload type is required and must not have surrounding whitespace")
	}
	if len(layers) == 0 || len(layers) > maxManifestLayers {
		return Manifest{}, fmt.Errorf("artifact must contain between 1 and %d layers", maxManifestLayers)
	}
	annotationCopy := make(map[string]string, len(annotations))
	for key, value := range annotations {
		annotationCopy[key] = value
	}
	if err := validateAnnotations(annotationCopy); err != nil {
		return Manifest{}, err
	}
	if len(annotationCopy) == 0 {
		annotationCopy = nil
	}
	m := Manifest{SchemaVersion: 1, CreatedAt: createdAt, WorkloadType: workloadType, Annotations: annotationCopy}
	for _, data := range layers {
		digest := Digest(data)
		m.Layers = append(m.Layers, Layer{Digest: digest, Size: int64(len(data)), MediaType: layerMediaType})
	}
	identity, err := manifestIdentity(m)
	if err != nil {
		return Manifest{}, err
	}
	m.ImageDigest = Digest(identity)
	if err := validateManifest(m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// PublishPrepared installs only the exact objects described by a previously
// prepared manifest. It rejects any layer mismatch before the first write.
func PublishPrepared(ctx context.Context, store Store, m Manifest, layers [][]byte) (Manifest, error) {
	if ctx == nil {
		return Manifest{}, errors.New("artifact publish context is required")
	}
	if store == nil {
		return Manifest{}, errors.New("artifact store is required")
	}
	if err := validateManifest(m); err != nil {
		return Manifest{}, err
	}
	identity, err := manifestIdentity(m)
	if err != nil || Digest(identity) != m.ImageDigest {
		return Manifest{}, errors.New("prepared manifest content does not match its image digest")
	}
	if len(layers) != len(m.Layers) {
		return Manifest{}, errors.New("prepared manifest layer count does not match payloads")
	}
	for index, data := range layers {
		layer := m.Layers[index]
		if layer.Digest != Digest(data) || layer.Size != int64(len(data)) || layer.MediaType != layerMediaType {
			return Manifest{}, fmt.Errorf("prepared manifest layer %d does not match payload", index)
		}
	}
	for index, data := range layers {
		if err := store.Put(ctx, BlobKey(m.Layers[index].Digest), data, "application/octet-stream"); err != nil {
			return Manifest{}, err
		}
	}
	b, err := json.Marshal(m)
	if err != nil {
		return Manifest{}, err
	}
	if err := store.Put(ctx, ManifestKey(m.ImageDigest), b, manifestMediaType); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

func Fetch(ctx context.Context, store Store, manifestKey, expectedDigest string) (Manifest, [][]byte, error) {
	if ctx == nil {
		return Manifest{}, nil, errors.New("artifact fetch context is required")
	}
	if store == nil {
		return Manifest{}, nil, errors.New("artifact store is required")
	}
	if err := validateDigest(expectedDigest); err != nil {
		return Manifest{}, nil, fmt.Errorf("invalid expected manifest digest: %w", err)
	}
	if manifestKey != ManifestKey(expectedDigest) {
		return Manifest{}, nil, fmt.Errorf("manifest key %q does not match expected digest", manifestKey)
	}
	b, err := getBounded(ctx, store, manifestKey, maxManifestBytes)
	if err != nil {
		return Manifest{}, nil, err
	}
	if len(b) == 0 || len(b) > maxManifestBytes {
		return Manifest{}, nil, fmt.Errorf("manifest size %d is outside the accepted range", len(b))
	}
	var m Manifest
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&m); err != nil {
		return Manifest{}, nil, fmt.Errorf("decode manifest: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return Manifest{}, nil, fmt.Errorf("decode manifest: %w", err)
	}
	canonical, err := json.Marshal(m)
	if err != nil {
		return Manifest{}, nil, fmt.Errorf("canonicalize manifest: %w", err)
	}
	if !bytes.Equal(b, canonical) {
		return Manifest{}, nil, errors.New("manifest is not in canonical encoding")
	}
	if err := validateManifest(m); err != nil {
		return Manifest{}, nil, err
	}
	if m.ImageDigest != expectedDigest {
		return Manifest{}, nil, fmt.Errorf("manifest digest mismatch: got %s want %s", m.ImageDigest, expectedDigest)
	}
	identity, err := manifestIdentity(m)
	if err != nil {
		return Manifest{}, nil, err
	}
	if Digest(identity) != expectedDigest {
		return Manifest{}, nil, fmt.Errorf("manifest content does not match digest %s", expectedDigest)
	}
	layers := make([][]byte, len(m.Layers))
	for i, layer := range m.Layers {
		layers[i], err = store.Get(ctx, BlobKey(layer.Digest))
		if err != nil {
			return Manifest{}, nil, err
		}
		if Digest(layers[i]) != layer.Digest {
			return Manifest{}, nil, fmt.Errorf("layer %d digest mismatch", i)
		}
		if int64(len(layers[i])) != layer.Size {
			return Manifest{}, nil, fmt.Errorf("layer %d size mismatch: got %d want %d", i, len(layers[i]), layer.Size)
		}
	}
	return m, layers, nil
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

func validateManifest(m Manifest) error {
	if m.SchemaVersion != 1 {
		return fmt.Errorf("unsupported artifact schema version %d", m.SchemaVersion)
	}
	if m.CreatedAt.IsZero() {
		return errors.New("manifest creation time is required")
	}
	if strings.TrimSpace(m.WorkloadType) == "" || m.WorkloadType != strings.TrimSpace(m.WorkloadType) {
		return errors.New("manifest workload type is invalid")
	}
	if err := validateDigest(m.ImageDigest); err != nil {
		return fmt.Errorf("invalid manifest image digest: %w", err)
	}
	if len(m.Layers) == 0 || len(m.Layers) > maxManifestLayers {
		return fmt.Errorf("manifest must contain between 1 and %d layers", maxManifestLayers)
	}
	for index, layer := range m.Layers {
		if err := validateDigest(layer.Digest); err != nil {
			return fmt.Errorf("invalid layer %d digest: %w", index, err)
		}
		if layer.Size < 0 {
			return fmt.Errorf("layer %d has a negative size", index)
		}
		if layer.MediaType != layerMediaType {
			return fmt.Errorf("layer %d has unsupported media type %q", index, layer.MediaType)
		}
	}
	return validateAnnotations(m.Annotations)
}

func validateAnnotations(annotations map[string]string) error {
	if len(annotations) > 128 {
		return errors.New("manifest has too many annotations")
	}
	for key, value := range annotations {
		if key == "" || len(key) > 256 || len(value) > 4096 || !utf8.ValidString(key) || !utf8.ValidString(value) {
			return errors.New("manifest annotation is invalid")
		}
	}
	return nil
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

func manifestIdentity(m Manifest) ([]byte, error) {
	m.ImageDigest = ""
	return json.Marshal(m)
}

// ArtifactKeys returns the exact content-addressed keys referenced by a
// verified manifest. The manifest key is first so cleanup removes the entry
// point before its layers. Duplicate layer digests are de-duplicated.
func ArtifactKeys(m Manifest) ([]string, error) {
	if err := validateManifest(m); err != nil {
		return nil, err
	}
	identity, err := manifestIdentity(m)
	if err != nil {
		return nil, err
	}
	if Digest(identity) != m.ImageDigest {
		return nil, errors.New("manifest content does not match its image digest")
	}
	keys := []string{ManifestKey(m.ImageDigest)}
	seen := map[string]struct{}{keys[0]: {}}
	for _, layer := range m.Layers {
		key := BlobKey(layer.Digest)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	return keys, nil
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
