// SPDX-License-Identifier: AGPL-3.0-only

// Package static implements the static-site-v1 workload of the static-site
// contract: the content-addressed static-site-manifest v1, its bounded
// verifier, a verify-every-file local blob cache, and the pinned
// static-handler.v1 whose responses are a pure function of the verified
// manifest and the request method and path. No customer code runs here.
//
// The integration contract v0 (coordination.md) and the static-site contract
// are normative; this package must not diverge from their vectors.
package static

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
	"github.com/misscomputer/misscomputer-subnet/pkg/organic"
)

const (
	ManifestSchema        = organic.SchemaPrefix + "static-site-manifest"
	ManifestSchemaVersion = 1
	// HandlerVersion is the serving-semantics version every manifest names.
	HandlerVersion = "static-handler.v1"
	// WorkloadKind is the explicit static workload kind; it is never inferred
	// from a deployment.v4 ticket.
	WorkloadKind = "static-site-v1"
	// CapabilityFeature is advertised only by a miner that implements the
	// whole static-site contract; schedulers filter on it before placement.
	CapabilityFeature = "organic-static-v1"
	// FallbackKind is the only fallback rule of v1.
	FallbackKind = "spa-html-v1"

	// Hard limits (§1). A violation is a rejection, never a dynamic fallback.
	MaxManifestBytes  = 1 << 20
	MaxFiles          = 4096
	MaxTotalBytes     = int64(256 << 20)
	MaxFileBytes      = int64(16 << 20)
	MaxPathBytes      = 1024
	MaxSegmentBytes   = 255
	MaxDepth          = 32
	MaxContentTypeLen = 128

	// IndexPath answers "/"; every manifest lists it as HTML.
	IndexPath = "/index.html"
	indexName = "index.html"
	htmlType  = "text/html; charset=utf-8"
)

// contentTypes is static-producer-policy.v1 (§3.4): extension to type.
var contentTypes = map[string]string{
	"html": htmlType, "htm": htmlType,
	"css": "text/css; charset=utf-8",
	"js":  "text/javascript; charset=utf-8", "mjs": "text/javascript; charset=utf-8",
	"json": "application/json", "map": "application/json",
	"webmanifest": "application/manifest+json",
	"txt":         "text/plain; charset=utf-8",
	"csv":         "text/csv; charset=utf-8",
	"md":          "text/markdown; charset=utf-8",
	"xml":         "application/xml",
	"svg":         "image/svg+xml",
	"png":         "image/png",
	"jpg":         "image/jpeg", "jpeg": "image/jpeg",
	"gif":   "image/gif",
	"webp":  "image/webp",
	"avif":  "image/avif",
	"ico":   "image/x-icon",
	"woff":  "font/woff",
	"woff2": "font/woff2",
	"ttf":   "font/ttf",
	"otf":   "font/otf",
	"wasm":  "application/wasm",
	"pdf":   "application/pdf",
	"mp4":   "video/mp4",
	"webm":  "video/webm",
	"mp3":   "audio/mpeg",
}

// ContentTypeFor is the policy content type of a file path: the ASCII
// lowercased text after the last "." of the last segment, else
// application/octet-stream.
func ContentTypeFor(path string) string {
	last := lastSegment(path)
	if dot := strings.LastIndexByte(last, '.'); dot >= 0 {
		if value, ok := contentTypes[strings.ToLower(last[dot+1:])]; ok {
			return value
		}
	}
	return "application/octet-stream"
}

// File is one manifest entry.
type File struct {
	BodySHA256    string `json:"body_sha256"`
	ContentLength int64  `json:"content_length"`
	ContentType   string `json:"content_type"`
	Path          string `json:"path"`
}

// Fallback is the manifest-declared SPA rule.
type Fallback struct {
	Kind   string `json:"kind"`
	Target string `json:"target"`
}

// Manifest is static-site-manifest v1. Its identity, site_digest, is the
// SHA-256 of the stored bytes: canonical JSON plus one newline.
type Manifest struct {
	Fallback      *Fallback `json:"fallback"`
	Files         []File    `json:"files"`
	Handler       string    `json:"handler"`
	Schema        string    `json:"schema"`
	SchemaVersion int       `json:"schema_version"`
}

// ManifestKey is the artifact-store key of a site digest (§1).
func ManifestKey(siteDigest string) string {
	return "v1/static-sites/" + strings.TrimPrefix(siteDigest, "sha256:") + ".json"
}

// BlobKey is the shared content-addressed key of one file body.
func BlobKey(bodySHA256 string) string { return artifact.BlobKey("sha256:" + bodySHA256) }

// Digest is the site digest of stored manifest bytes.
func Digest(stored []byte) string {
	sum := sha256.Sum256(stored)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Encode returns the stored bytes and site digest of a valid manifest.
func Encode(m Manifest) ([]byte, string, error) {
	if err := m.Validate(); err != nil {
		return nil, "", err
	}
	stored, err := organic.CanonicalBytes(m)
	if err != nil {
		return nil, "", err
	}
	if len(stored) > MaxManifestBytes {
		return nil, "", failf(CodeLimitsExceeded, "stored manifest exceeds %d bytes", MaxManifestBytes)
	}
	return stored, Digest(stored), nil
}

// Parse accepts only stored bytes whose SHA-256 is siteDigest and that
// decode canonically into a manifest satisfying every §3/§4 rule and §1
// limit. Bytes that do not match the bound digest are static_verify_failed;
// matching bytes that break a rule are static_manifest_invalid or
// static_limits_exceeded.
func Parse(stored []byte, siteDigest string) (Manifest, error) {
	if !organic.ValidDigest(siteDigest) {
		return Manifest{}, Fail(CodeInternal, errors.New("expected site digest is invalid"))
	}
	if len(stored) == 0 || len(stored) > MaxManifestBytes || Digest(stored) != siteDigest {
		return Manifest{}, failf(CodeVerifyFailed, "site manifest bytes do not match %s", siteDigest)
	}
	var m Manifest
	if err := organic.DecodeCanonical(stored, &m); err != nil {
		return Manifest{}, Fail(CodeManifestInvalid, err)
	}
	return m, nil
}

// Validate enforces the §3.1 manifest rules and §1 limits.
func (m Manifest) Validate() error {
	if m.Schema != ManifestSchema || m.SchemaVersion != ManifestSchemaVersion || m.Handler != HandlerVersion {
		return failf(CodeManifestInvalid, "unsupported site manifest schema or handler")
	}
	if len(m.Files) == 0 {
		return failf(CodeManifestInvalid, "site manifest lists no files")
	}
	if len(m.Files) > MaxFiles {
		return failf(CodeLimitsExceeded, "site manifest lists more than %d files", MaxFiles)
	}
	var total int64
	folded := make(map[string]bool, len(m.Files))
	directories := make(map[string]bool)
	lengths := make(map[string]int64, len(m.Files))
	for index, file := range m.Files {
		if index > 0 && file.Path <= m.Files[index-1].Path {
			return failf(CodeManifestInvalid, "static_paths_not_ascending")
		}
		if len(file.Path) > MaxPathBytes || strings.Count(file.Path, "/") > MaxDepth {
			return failf(CodeLimitsExceeded, "site manifest path %d exceeds the path limits", index)
		}
		for _, segment := range strings.Split(file.Path, "/") {
			if len(segment) > MaxSegmentBytes {
				return failf(CodeLimitsExceeded, "site manifest path %d has a segment over %d bytes", index, MaxSegmentBytes)
			}
		}
		if !ValidFilePath(file.Path) {
			return failf(CodeManifestInvalid, "static_path_invalid: path %d", index)
		}
		if file.ContentLength > MaxFileBytes {
			return failf(CodeLimitsExceeded, "site manifest path %d exceeds %d bytes", index, MaxFileBytes)
		}
		if file.ContentLength < 0 || !organic.ValidHex64(file.BodySHA256) ||
			len(file.ContentType) > MaxContentTypeLen || file.ContentType != ContentTypeFor(file.Path) {
			return failf(CodeManifestInvalid, "static_content_type_invalid: path %d has an invalid length, digest or content type", index)
		}
		if size, seen := lengths[file.BodySHA256]; seen && size != file.ContentLength {
			return failf(CodeManifestInvalid, "static_digest_length_inconsistent: path %d", index)
		}
		lengths[file.BodySHA256] = file.ContentLength
		key := strings.ToLower(file.Path)
		if folded[key] {
			return failf(CodeManifestInvalid, "static_case_fold_collision: path %d", index)
		}
		folded[key] = true
		for cut := strings.LastIndexByte(key, '/'); cut > 0; cut = strings.LastIndexByte(key[:cut], '/') {
			directories[key[:cut]] = true
		}
		total += file.ContentLength
	}
	for key := range folded {
		if directories[key] {
			return failf(CodeManifestInvalid, "static_file_directory_collision")
		}
	}
	if total > MaxTotalBytes {
		return failf(CodeLimitsExceeded, "static_total_bytes_exceeded: more than %d bytes", MaxTotalBytes)
	}
	if !m.lists(IndexPath, htmlType) {
		return failf(CodeManifestInvalid, "static_index_missing: %s must be listed as HTML", IndexPath)
	}
	if m.Fallback != nil && (m.Fallback.Kind != FallbackKind || !m.lists(m.Fallback.Target, htmlType)) {
		return failf(CodeManifestInvalid, "static_fallback_invalid: must be %s naming a listed HTML file", FallbackKind)
	}
	return nil
}

// TotalBytes is the sum of every file's content_length.
func (m Manifest) TotalBytes() int64 {
	var total int64
	for _, file := range m.Files {
		total += file.ContentLength
	}
	return total
}

func (m Manifest) lists(path, contentType string) bool {
	for _, file := range m.Files {
		if file.Path == path {
			return file.ContentType == contentType
		}
	}
	return false
}
