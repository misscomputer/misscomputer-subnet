// SPDX-License-Identifier: AGPL-3.0-only

package artifact

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/misscomputer/misscomputer-subnet/pkg/assignment"
)

// Artifact-manifest v2 is the content-addressed description of one verified
// OCI image in the R2 artifact bucket. Its identity is the SHA-256 of the
// exact stored bytes: canonical JSON followed by exactly one newline. There
// is no self-digest and no timestamp, so identical images deduplicate.
const (
	ManifestV2Schema        = "miss.computer/misscomputer-subnet/artifact-manifest"
	ManifestV2SchemaVersion = 2
	ManifestV2MediaType     = "application/vnd.misscomputer.manifest.v2+json"
	WorkloadTypeOCIImageV1  = "oci-image-v1"

	OCIManifestMediaType = "application/vnd.oci.image.manifest.v1+json"
	OCIConfigMediaType   = "application/vnd.oci.image.config.v1+json"
	OCILayerMediaType    = "application/vnd.oci.image.layer.v1.tar"
	OCILayerGzipType     = "application/vnd.oci.image.layer.v1.tar+gzip"

	// MaxManifestV2Layers and MaxUncompressedImageBytes are the frozen
	// small-v1 image limits shared with the CLI and the promoter.
	MaxManifestV2Layers       = 127
	MaxUncompressedImageBytes = int64(1 << 30)
	// MaxOCIMetadataBytes bounds the OCI manifest and config blobs, which are
	// parsed in memory. It matches the registry-ecosystem manifest ceiling.
	MaxOCIMetadataBytes = int64(4 << 20)
)

// Descriptor names one exact OCI blob.
type Descriptor struct {
	Digest    string `json:"digest"`
	MediaType string `json:"media_type"`
	Size      int64  `json:"size"`
}

// LayerV2 binds one compressed layer blob to its uncompressed diff ID.
type LayerV2 struct {
	DiffID           string `json:"diff_id"`
	Digest           string `json:"digest"`
	MediaType        string `json:"media_type"`
	Size             int64  `json:"size"`
	UncompressedSize int64  `json:"uncompressed_size"`
}

type Platform struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
}

type ManifestV2 struct {
	Config            Descriptor `json:"config"`
	Layers            []LayerV2  `json:"layers"`
	OCIManifest       Descriptor `json:"oci_manifest"`
	Platform          Platform   `json:"platform"`
	Schema            string     `json:"schema"`
	SchemaVersion     int        `json:"schema_version"`
	UncompressedBytes int64      `json:"uncompressed_bytes"`
	WorkloadType      string     `json:"workload_type"`
}

// VerifyError marks content that is present but does not match its signed
// or content-addressed identity. Receipts attribute it as
// artifact_verify_failed, unlike store unavailability.
type VerifyError struct{ msg string }

func (e *VerifyError) Error() string { return e.msg }

func verifyErrorf(format string, args ...any) error {
	return &VerifyError{msg: fmt.Sprintf(format, args...)}
}

// IsVerifyError reports whether err is an artifact identity failure.
func IsVerifyError(err error) bool {
	var target *VerifyError
	return errors.As(err, &target)
}

// EncodeManifestV2 returns the exact stored bytes of a valid manifest.
func EncodeManifestV2(m ManifestV2) ([]byte, error) {
	if err := validateManifestV2(m); err != nil {
		return nil, err
	}
	canonical, err := assignment.CanonicalJSON(m)
	if err != nil {
		return nil, err
	}
	return append(canonical, '\n'), nil
}

// ParseManifestV2 accepts only the canonical stored encoding whose SHA-256
// equals expectedDigest. Unknown keys, duplicate keys, alternative spellings
// and whitespace all change the bytes and are rejected.
func ParseManifestV2(data []byte, expectedDigest string) (ManifestV2, error) {
	if err := validateDigest(expectedDigest); err != nil {
		return ManifestV2{}, fmt.Errorf("invalid expected artifact digest: %w", err)
	}
	if len(data) == 0 || len(data) > maxManifestBytes {
		return ManifestV2{}, verifyErrorf("artifact manifest size %d is outside the accepted range", len(data))
	}
	if Digest(data) != expectedDigest {
		return ManifestV2{}, verifyErrorf("artifact manifest bytes do not match digest %s", expectedDigest)
	}
	var m ManifestV2
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&m); err != nil {
		return ManifestV2{}, verifyErrorf("decode artifact manifest: %v", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return ManifestV2{}, verifyErrorf("decode artifact manifest: %v", err)
	}
	canonical, err := EncodeManifestV2(m)
	if err != nil {
		return ManifestV2{}, &VerifyError{msg: err.Error()}
	}
	if !bytes.Equal(canonical, data) {
		return ManifestV2{}, verifyErrorf("artifact manifest is not in canonical encoding")
	}
	return m, nil
}

// FetchManifestV2 reads one manifest by its content-addressed key. The key is
// derived from the digest, never trusted independently.
func FetchManifestV2(ctx context.Context, store Store, manifestKey, artifactDigest string) (ManifestV2, error) {
	if ctx == nil {
		return ManifestV2{}, errors.New("artifact fetch context is required")
	}
	if store == nil {
		return ManifestV2{}, errors.New("artifact store is required")
	}
	if err := validateDigest(artifactDigest); err != nil {
		return ManifestV2{}, verifyErrorf("invalid artifact digest: %v", err)
	}
	if manifestKey != ManifestKey(artifactDigest) {
		return ManifestV2{}, verifyErrorf("manifest key %q does not match artifact digest", safeErrorKey(manifestKey))
	}
	data, err := getBounded(ctx, store, manifestKey, maxManifestBytes)
	if err != nil {
		if isOversize(err) {
			return ManifestV2{}, verifyErrorf("artifact manifest exceeds %d bytes", maxManifestBytes)
		}
		return ManifestV2{}, err
	}
	return ParseManifestV2(data, artifactDigest)
}

func validateManifestV2(m ManifestV2) error {
	if m.Schema != ManifestV2Schema || m.SchemaVersion != ManifestV2SchemaVersion {
		return fmt.Errorf("unsupported artifact manifest %q version %d", m.Schema, m.SchemaVersion)
	}
	if m.WorkloadType != WorkloadTypeOCIImageV1 {
		return fmt.Errorf("unsupported artifact workload type %q", m.WorkloadType)
	}
	if m.Platform != (Platform{Architecture: "amd64", OS: "linux"}) {
		return fmt.Errorf("unsupported artifact platform %s/%s", m.Platform.OS, m.Platform.Architecture)
	}
	if err := validateDescriptor("OCI manifest", m.OCIManifest, OCIManifestMediaType, MaxOCIMetadataBytes); err != nil {
		return err
	}
	if err := validateDescriptor("OCI config", m.Config, OCIConfigMediaType, MaxOCIMetadataBytes); err != nil {
		return err
	}
	if len(m.Layers) == 0 || len(m.Layers) > MaxManifestV2Layers {
		return fmt.Errorf("artifact must contain between 1 and %d layers", MaxManifestV2Layers)
	}
	var total int64
	for index, layer := range m.Layers {
		if err := validateDigest(layer.Digest); err != nil {
			return fmt.Errorf("invalid layer %d digest: %w", index, err)
		}
		if err := validateDigest(layer.DiffID); err != nil {
			return fmt.Errorf("invalid layer %d diff_id: %w", index, err)
		}
		if layer.Size < 1 || layer.UncompressedSize < 1 {
			return fmt.Errorf("layer %d sizes must be positive", index)
		}
		switch layer.MediaType {
		case OCILayerMediaType:
			if layer.DiffID != layer.Digest || layer.UncompressedSize != layer.Size {
				return errors.New("tar_layer_identity_invalid")
			}
		case OCILayerGzipType:
		default:
			return fmt.Errorf("layer %d has unsupported media type %q", index, layer.MediaType)
		}
		if layer.UncompressedSize > MaxUncompressedImageBytes-total {
			return fmt.Errorf("artifact uncompressed size exceeds %d bytes", MaxUncompressedImageBytes)
		}
		total += layer.UncompressedSize
	}
	if m.UncompressedBytes != total {
		return errors.New("uncompressed_bytes_mismatch")
	}
	return nil
}

func validateDescriptor(name string, descriptor Descriptor, mediaType string, maximum int64) error {
	if err := validateDigest(descriptor.Digest); err != nil {
		return fmt.Errorf("invalid %s digest: %w", name, err)
	}
	if descriptor.MediaType != mediaType {
		return fmt.Errorf("%s has unsupported media type %q", name, descriptor.MediaType)
	}
	if descriptor.Size < 1 || descriptor.Size > maximum {
		return fmt.Errorf("%s size %d is outside 1..%d", name, descriptor.Size, maximum)
	}
	return nil
}

// IsOversize reports whether err is a store refusal of an object larger than
// the caller's bound. Content that exceeds its signed size is a verification
// failure, not store unavailability.
func IsOversize(err error) bool { return isOversize(err) }

func isOversize(err error) bool {
	var s3Err *S3Error
	return errors.Is(err, errObjectTooLarge) || (errors.As(err, &s3Err) && s3Err.Kind == S3ErrorResponseTooBig)
}

// Compatibility names preserve the public v2 contract API while the miner
// uses the shorter descriptor names internally.
const (
	ManifestV2Workload   = WorkloadTypeOCIImageV1
	MaxUncompressedBytes = MaxUncompressedImageBytes
)

type ManifestV2Blob = Descriptor
type ManifestV2Layer = LayerV2
type ManifestV2Platform = Platform

// Validate applies the same v2 rules as the Python ArtifactManifest model.
func (m ManifestV2) Validate() error { return validateManifestV2(m) }

// MarshalManifestV2 renders the stored bytes and their content digest.
func MarshalManifestV2(m ManifestV2) ([]byte, string, error) {
	encoded, err := EncodeManifestV2(m)
	if err != nil {
		return nil, "", err
	}
	if len(encoded) > maxManifestBytes {
		return nil, "", errors.New("artifact manifest exceeds 1 MiB")
	}
	return encoded, Digest(encoded), nil
}
