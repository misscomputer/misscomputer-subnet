// SPDX-License-Identifier: AGPL-3.0-only

// Package ocitest builds small, fully valid linux/amd64 OCI images and their
// artifact-manifest v2 for tests. It replaces the synthetic workload layer
// as the local fixture for organic runtime tests; it plays the promoter's
// role only in tests.
package ocitest

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"sort"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
)

// File is one regular file placed in a single image layer.
type File struct {
	Mode int64
	Body []byte
}

// Spec describes the fixture image. Each entry in Layers becomes one layer;
// Gzip selects the compressed layer media type for every layer.
type Spec struct {
	Layers     []map[string]File
	Entrypoint []string
	Env        []string
	Volumes    []string
	Gzip       bool
	// DiffIDs, when set, replaces the computed diff IDs consistently in the
	// config and artifact manifest to model a promoter that skipped the
	// decompressed-content check.
	DiffIDs []string
}

// Image is a built fixture: every blob by digest plus the stored manifest.
type Image struct {
	Blobs          map[string][]byte
	Manifest       artifact.ManifestV2
	ManifestBytes  []byte
	ArtifactDigest string
	OCIManifest    []byte
	Config         []byte
}

// Build returns a deterministic image for spec.
func Build(spec Spec) (Image, error) {
	image := Image{Blobs: map[string][]byte{}}
	var diffIDs []string
	var layers []artifact.ManifestV2Layer
	var ociLayers []map[string]any
	var total int64
	for _, files := range spec.Layers {
		raw, err := layerTar(files)
		if err != nil {
			return Image{}, err
		}
		blob, mediaType := raw, artifact.OCILayerMediaType
		if spec.Gzip {
			var compressed bytes.Buffer
			writer, _ := gzip.NewWriterLevel(&compressed, gzip.BestSpeed)
			if _, err := writer.Write(raw); err != nil {
				return Image{}, err
			}
			if err := writer.Close(); err != nil {
				return Image{}, err
			}
			blob, mediaType = compressed.Bytes(), artifact.OCILayerGzipType
		}
		digest := artifact.Digest(blob)
		image.Blobs[digest] = blob
		diffIDs = append(diffIDs, artifact.Digest(raw))
		layers = append(layers, artifact.ManifestV2Layer{
			DiffID: artifact.Digest(raw), Digest: digest, MediaType: mediaType,
			Size: int64(len(blob)), UncompressedSize: int64(len(raw)),
		})
		ociLayers = append(ociLayers, map[string]any{"mediaType": mediaType, "digest": digest, "size": len(blob)})
		total += int64(len(raw))
	}
	if spec.DiffIDs != nil {
		diffIDs = spec.DiffIDs
		for index := range layers {
			layers[index].DiffID = spec.DiffIDs[index]
		}
	}
	volumes := map[string]struct{}{}
	for _, volume := range spec.Volumes {
		volumes[volume] = struct{}{}
	}
	containerConfig := map[string]any{"Entrypoint": spec.Entrypoint, "Env": spec.Env}
	if len(volumes) != 0 {
		containerConfig["Volumes"] = volumes
	}
	config, err := json.Marshal(map[string]any{
		"architecture": "amd64", "os": "linux", "config": containerConfig,
		"rootfs": map[string]any{"type": "layers", "diff_ids": diffIDs},
	})
	if err != nil {
		return Image{}, err
	}
	image.Config = config
	image.Blobs[artifact.Digest(config)] = config
	ociManifest, err := json.Marshal(map[string]any{
		"schemaVersion": 2, "mediaType": artifact.OCIManifestMediaType,
		"config": map[string]any{"mediaType": artifact.OCIConfigMediaType, "digest": artifact.Digest(config), "size": len(config)},
		"layers": ociLayers,
	})
	if err != nil {
		return Image{}, err
	}
	image.OCIManifest = ociManifest
	image.Blobs[artifact.Digest(ociManifest)] = ociManifest
	image.Manifest = artifact.ManifestV2{
		Config:      artifact.ManifestV2Blob{Digest: artifact.Digest(config), MediaType: artifact.OCIConfigMediaType, Size: int64(len(config))},
		Layers:      layers,
		OCIManifest: artifact.ManifestV2Blob{Digest: artifact.Digest(ociManifest), MediaType: artifact.OCIManifestMediaType, Size: int64(len(ociManifest))},
		Platform:    artifact.ManifestV2Platform{Architecture: "amd64", OS: "linux"},
		Schema:      artifact.ManifestV2Schema, SchemaVersion: 2,
		UncompressedBytes: total, WorkloadType: artifact.ManifestV2Workload,
	}
	image.ManifestBytes, image.ArtifactDigest, err = artifact.MarshalManifestV2(image.Manifest)
	if err != nil {
		return Image{}, err
	}
	return image, nil
}

// Publish writes every blob and the manifest at their content-addressed keys.
func (i Image) Publish(ctx context.Context, store artifact.Store) error {
	for digest, blob := range i.Blobs {
		if err := store.Put(ctx, artifact.BlobKey(digest), blob, "application/octet-stream"); err != nil {
			return err
		}
	}
	return store.Put(ctx, artifact.ManifestKey(i.ArtifactDigest), i.ManifestBytes, artifact.ManifestV2MediaType)
}

func layerTar(files map[string]File) ([]byte, error) {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	epoch := time.Unix(0, 0).UTC()
	for _, name := range names {
		file := files[name]
		mode := file.Mode
		if mode == 0 {
			mode = 0o644
		}
		if err := writer.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg, Name: name, Mode: mode, Size: int64(len(file.Body)), ModTime: epoch, Format: tar.FormatPAX,
		}); err != nil {
			return nil, err
		}
		if _, err := writer.Write(file.Body); err != nil {
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
