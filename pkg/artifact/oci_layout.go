// SPDX-License-Identifier: AGPL-3.0-only

package artifact

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// BlobOpener streams one exact object. Implementations must fail before
// returning a reader when an object is known to exceed maximum, and the
// returned reader must fail rather than yield more than maximum bytes.
// Artifact layers are never buffered whole in memory.
type BlobOpener interface {
	OpenBounded(ctx context.Context, key string, maximum int64) (io.ReadCloser, error)
}

// Layout is an OCI image layout on local disk whose every blob has been
// verified against an artifact-manifest v2.
type Layout struct {
	Dir            string
	ArtifactDigest string
	ManifestDigest string
	ConfigDigest   string
	// RefName is the deterministic local reference recorded in index.json.
	RefName string
}

// LayoutRefName is the local image reference used for an artifact. It is a
// convenience handle for loading and cleanup; identity is always rechecked by
// digest after load.
func LayoutRefName(artifactDigest string) string {
	return "misscomputer/organic:a-" + strings.TrimPrefix(artifactDigest, "sha256:")
}

type ociDescriptor struct {
	MediaType string   `json:"mediaType"`
	Digest    string   `json:"digest"`
	Size      int64    `json:"size"`
	URLs      []string `json:"urls,omitempty"`
}

type ociManifest struct {
	SchemaVersion int             `json:"schemaVersion"`
	MediaType     string          `json:"mediaType"`
	Config        ociDescriptor   `json:"config"`
	Layers        []ociDescriptor `json:"layers"`
	Subject       *ociDescriptor  `json:"subject,omitempty"`
}

type ociConfig struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Config       struct {
		Entrypoint []string            `json:"Entrypoint"`
		Cmd        []string            `json:"Cmd"`
		Volumes    map[string]struct{} `json:"Volumes"`
	} `json:"config"`
	RootFS struct {
		Type    string   `json:"type"`
		DiffIDs []string `json:"diff_ids"`
	} `json:"rootfs"`
}

// MaterializeOCILayout writes a verified OCI image layout into dir, which
// must not already exist. It re-hashes the OCI manifest, config and every
// layer (length and SHA-256), checks the manifest/config/diff_id binding
// against m, and streams layers to disk. On any error the partial layout is
// removed. Store failures are returned unchanged; identity failures are
// *VerifyError.
func MaterializeOCILayout(ctx context.Context, blobs BlobOpener, artifactDigest string, m ManifestV2, dir string) (layout Layout, err error) {
	if ctx == nil || blobs == nil {
		return Layout{}, errors.New("artifact materialization context and blob store are required")
	}
	if err := validateDigest(artifactDigest); err != nil {
		return Layout{}, verifyErrorf("invalid artifact digest: %v", err)
	}
	_, digest, err := MarshalManifestV2(m)
	if err != nil {
		return Layout{}, &VerifyError{msg: err.Error()}
	}
	if digest != artifactDigest {
		return Layout{}, verifyErrorf("artifact manifest does not match digest %s", artifactDigest)
	}
	if !filepath.IsAbs(dir) {
		return Layout{}, errors.New("OCI layout directory must be absolute")
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return Layout{}, fmt.Errorf("create OCI layout: %w", err)
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(dir)
		}
	}()
	blobDir := filepath.Join(dir, "blobs", "sha256")
	if err := os.MkdirAll(blobDir, 0o700); err != nil {
		return Layout{}, fmt.Errorf("create OCI blob directory: %w", err)
	}

	manifestBytes, err := fetchSmallBlob(ctx, blobs, blobDir, m.OCIManifest)
	if err != nil {
		return Layout{}, err
	}
	if err := checkOCIManifest(manifestBytes, m); err != nil {
		return Layout{}, err
	}
	configBytes, err := fetchSmallBlob(ctx, blobs, blobDir, m.Config)
	if err != nil {
		return Layout{}, err
	}
	if err := checkOCIConfig(configBytes, m); err != nil {
		return Layout{}, err
	}
	for index, layer := range m.Layers {
		if err := fetchLayer(ctx, blobs, blobDir, index, layer); err != nil {
			return Layout{}, err
		}
	}

	refName := LayoutRefName(artifactDigest)
	index := map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.index.v1+json",
		"manifests": []map[string]any{{
			"mediaType": OCIManifestMediaType,
			"digest":    m.OCIManifest.Digest,
			"size":      m.OCIManifest.Size,
			"platform":  map[string]string{"architecture": "amd64", "os": "linux"},
			"annotations": map[string]string{
				"io.containerd.image.name":          "docker.io/" + refName,
				"org.opencontainers.image.ref.name": strings.SplitN(refName, ":", 2)[1],
			},
		}},
	}
	indexBytes, err := json.Marshal(index)
	if err != nil {
		return Layout{}, err
	}
	if err := writeFileExclusive(filepath.Join(dir, "index.json"), indexBytes); err != nil {
		return Layout{}, err
	}
	if err := writeFileExclusive(filepath.Join(dir, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`)); err != nil {
		return Layout{}, err
	}
	return Layout{
		Dir: dir, ArtifactDigest: artifactDigest, ManifestDigest: m.OCIManifest.Digest,
		ConfigDigest: m.Config.Digest, RefName: refName,
	}, nil
}

// WriteTar streams the layout as an uncompressed tar archive with the file
// set expected by `docker load` for OCI archives. Only the verified layout
// files are included, in a deterministic order.
func (l Layout) WriteTar(w io.Writer) error {
	entries, err := os.ReadDir(filepath.Join(l.Dir, "blobs", "sha256"))
	if err != nil {
		return err
	}
	names := []string{"oci-layout", "index.json"}
	for _, entry := range entries {
		if entry.Type().IsRegular() && validHexName(entry.Name()) {
			names = append(names, "blobs/sha256/"+entry.Name())
		}
	}
	archive := tar.NewWriter(w)
	for _, dirName := range []string{"blobs/", "blobs/sha256/"} {
		if err := archive.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: dirName, Mode: 0o755, Format: tar.FormatPAX}); err != nil {
			return err
		}
	}
	for _, name := range names {
		if err := addTarFile(archive, filepath.Join(l.Dir, filepath.FromSlash(name)), name); err != nil {
			return err
		}
	}
	return archive.Close()
}

// DiscardBlobs removes the verified blob copies once an image is loaded. The
// directory itself stays so the caller keeps its cleanup ownership marker.
func (l Layout) DiscardBlobs() error {
	for _, name := range []string{"blobs", "index.json", "oci-layout"} {
		if err := os.RemoveAll(filepath.Join(l.Dir, name)); err != nil {
			return err
		}
	}
	return nil
}

func addTarFile(archive *tar.Writer, path, name string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("OCI layout entry %s is not a regular file", name)
	}
	if err := archive.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: 0o644, Size: info.Size(), Format: tar.FormatPAX}); err != nil {
		return err
	}
	written, err := io.Copy(archive, file)
	if err != nil {
		return err
	}
	if written != info.Size() {
		return fmt.Errorf("OCI layout entry %s changed while archiving", name)
	}
	return nil
}

func validHexName(name string) bool {
	if len(name) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(name)
	return err == nil && strings.ToLower(name) == name
}

func checkOCIManifest(data []byte, m ManifestV2) error {
	var manifest ociManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return verifyErrorf("decode OCI manifest: %v", err)
	}
	if manifest.SchemaVersion != 2 || manifest.MediaType != OCIManifestMediaType {
		return verifyErrorf("OCI manifest is not an image manifest v1 document")
	}
	if manifest.Subject != nil {
		return verifyErrorf("OCI manifest must not declare a subject")
	}
	want := ociDescriptor{MediaType: m.Config.MediaType, Digest: m.Config.Digest, Size: m.Config.Size}
	if !sameDescriptor(manifest.Config, want) {
		return verifyErrorf("OCI manifest config descriptor does not match the artifact manifest")
	}
	if len(manifest.Layers) != len(m.Layers) {
		return verifyErrorf("OCI manifest has %d layers, artifact manifest has %d", len(manifest.Layers), len(m.Layers))
	}
	for index, layer := range m.Layers {
		want := ociDescriptor{MediaType: layer.MediaType, Digest: layer.Digest, Size: layer.Size}
		if !sameDescriptor(manifest.Layers[index], want) {
			return verifyErrorf("OCI manifest layer %d does not match the artifact manifest", index)
		}
	}
	return nil
}

func sameDescriptor(got, want ociDescriptor) bool {
	return len(got.URLs) == 0 && got.MediaType == want.MediaType && got.Digest == want.Digest && got.Size == want.Size
}

func checkOCIConfig(data []byte, m ManifestV2) error {
	var config ociConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return verifyErrorf("decode OCI config: %v", err)
	}
	if config.Architecture != m.Platform.Architecture || config.OS != m.Platform.OS {
		return verifyErrorf("OCI config platform %s/%s does not match the artifact manifest", config.OS, config.Architecture)
	}
	if config.RootFS.Type != "layers" || len(config.RootFS.DiffIDs) != len(m.Layers) {
		return verifyErrorf("OCI config rootfs does not describe the artifact layers")
	}
	for index, layer := range m.Layers {
		if config.RootFS.DiffIDs[index] != layer.DiffID {
			return verifyErrorf("OCI config diff_id %d does not match the artifact manifest", index)
		}
	}
	// small-v1 has a read-only root filesystem and no volumes; a VOLUME entry
	// would make the engine attach writable anonymous storage.
	if len(config.Config.Volumes) != 0 {
		return verifyErrorf("OCI config declares volumes")
	}
	if len(config.Config.Entrypoint) == 0 && len(config.Config.Cmd) == 0 {
		return verifyErrorf("OCI config has no entrypoint or command")
	}
	return nil
}

// fetchSmallBlob stores and returns a metadata blob after exact verification.
func fetchSmallBlob(ctx context.Context, blobs BlobOpener, blobDir string, descriptor ManifestV2Blob) ([]byte, error) {
	if descriptor.Size > MaxOCIMetadataBytes {
		return nil, verifyErrorf("OCI metadata blob %s exceeds %d bytes", descriptor.Digest, MaxOCIMetadataBytes)
	}
	var buffer bytes.Buffer
	if err := copyVerified(ctx, blobs, blobDir, descriptor.Digest, descriptor.Size, &buffer, nil); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func fetchLayer(ctx context.Context, blobs BlobOpener, blobDir string, index int, layer ManifestV2Layer) error {
	final := filepath.Join(blobDir, strings.TrimPrefix(layer.Digest, "sha256:"))
	if _, err := os.Lstat(final); err == nil {
		// A repeated digest in the same image was already fully verified.
		return nil
	}
	var diff *diffVerifier
	if layer.MediaType == OCILayerGzipType {
		diff = &diffVerifier{want: layer.DiffID, limit: layer.UncompressedSize, index: index}
	}
	if err := copyVerified(ctx, blobs, blobDir, layer.Digest, layer.Size, nil, diff); err != nil {
		return err
	}
	return nil
}

// copyVerified streams one blob into blobDir/<hex>. It commits the file only
// after its exact size and digest (and, for gzip layers, its decompressed
// diff_id and size) are verified. copyTo optionally receives a second copy.
func copyVerified(ctx context.Context, blobs BlobOpener, blobDir, digest string, size int64, copyTo io.Writer, diff *diffVerifier) (err error) {
	key := BlobKey(digest)
	reader, err := blobs.OpenBounded(ctx, key, size)
	if err != nil {
		if isOversize(err) {
			return verifyErrorf("blob %s exceeds its declared size", digest)
		}
		return err
	}
	defer reader.Close()
	tmp, err := os.CreateTemp(blobDir, ".partial-*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	hasher := sha256.New()
	writers := []io.Writer{tmp, hasher}
	if copyTo != nil {
		writers = append(writers, copyTo)
	}
	var sink io.Writer = io.MultiWriter(writers...)
	var pipeWriter *io.PipeWriter
	diffDone := make(chan error, 1)
	if diff != nil {
		var pipeReader *io.PipeReader
		pipeReader, pipeWriter = io.Pipe()
		sink = io.MultiWriter(sink, pipeWriter)
		go func() {
			result := diff.consume(pipeReader)
			// Drain so the compressed stream can finish even when the gzip
			// reader stops early; the digest check owns the verdict.
			_, _ = io.Copy(io.Discard, pipeReader)
			pipeReader.CloseWithError(result)
			diffDone <- result
		}()
	}
	written, copyErr := io.Copy(sink, &contextReader{ctx: ctx, reader: io.LimitReader(reader, size+1)})
	if pipeWriter != nil {
		_ = pipeWriter.Close()
		if diffErr := <-diffDone; copyErr == nil && written == size {
			if diffErr != nil {
				return diffErr
			}
		}
	}
	if copyErr != nil {
		if isOversize(copyErr) {
			return verifyErrorf("blob %s exceeds its declared size", digest)
		}
		return copyErr
	}
	if written != size {
		return verifyErrorf("blob %s size mismatch: got %d want %d", digest, written, size)
	}
	if got := "sha256:" + hex.EncodeToString(hasher.Sum(nil)); got != digest {
		return verifyErrorf("blob digest mismatch: got %s want %s", got, digest)
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(blobDir, strings.TrimPrefix(digest, "sha256:")))
}

type diffVerifier struct {
	want  string
	limit int64
	index int
}

func (d *diffVerifier) consume(compressed io.Reader) error {
	gz, err := gzip.NewReader(compressed)
	if err != nil {
		return verifyErrorf("layer %d is not valid gzip: %v", d.index, err)
	}
	defer gz.Close()
	hasher := sha256.New()
	n, err := io.Copy(hasher, io.LimitReader(gz, d.limit+1))
	if err != nil {
		return verifyErrorf("decompress layer %d: %v", d.index, err)
	}
	if n != d.limit {
		return verifyErrorf("layer %d uncompressed size mismatch: got %d want %d", d.index, n, d.limit)
	}
	var probe [1]byte
	if extra, probeErr := gz.Read(probe[:]); extra != 0 {
		return verifyErrorf("layer %d decompresses beyond its declared size", d.index)
	} else if probeErr != nil && !errors.Is(probeErr, io.EOF) {
		return verifyErrorf("layer %d has trailing data after its gzip stream: %v", d.index, probeErr)
	}
	if got := digestOfHash(hasher); got != d.want {
		return verifyErrorf("layer %d diff_id mismatch: got %s want %s", d.index, got, d.want)
	}
	return nil
}

func digestOfHash(h hash.Hash) string {
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
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

func writeFileExclusive(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

// OpenBounded streams one file without buffering it.
func (s FileStore) OpenBounded(ctx context.Context, key string, maximum int64) (io.ReadCloser, error) {
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
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if info.Size() > maximum {
		file.Close()
		return nil, errObjectTooLarge
	}
	return &boundedReadCloser{reader: file, closer: file, remaining: maximum}, nil
}

// boundedReadCloser yields at most remaining bytes and reports
// errObjectTooLarge if the underlying stream has more.
type boundedReadCloser struct {
	reader    io.Reader
	closer    io.Closer
	remaining int64
}

func (b *boundedReadCloser) Read(p []byte) (int, error) {
	if b.remaining <= 0 {
		var probe [1]byte
		n, err := b.reader.Read(probe[:])
		if n > 0 {
			return 0, errObjectTooLarge
		}
		if err == nil {
			return 0, nil
		}
		return 0, err
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.reader.Read(p)
	b.remaining -= int64(n)
	return n, err
}

func (b *boundedReadCloser) Close() error { return b.closer.Close() }
