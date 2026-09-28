// SPDX-License-Identifier: AGPL-3.0-only

package artifact_test

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
	"github.com/misscomputer/misscomputer-subnet/pkg/artifact/ocitest"
)

func fixtureImage(t *testing.T, spec ocitest.Spec) ocitest.Image {
	t.Helper()
	if spec.Layers == nil {
		spec.Layers = []map[string]ocitest.File{
			{"app": {Mode: 0o755, Body: bytes.Repeat([]byte("organic-app "), 4096)}},
			{"etc/app.conf": {Body: []byte("mode=serve\n")}},
		}
		spec.Gzip = true
	}
	if spec.Entrypoint == nil {
		spec.Entrypoint = []string{"/app"}
	}
	image, err := ocitest.Build(spec)
	if err != nil {
		t.Fatal(err)
	}
	return image
}

func TestFetchManifestV2DerivesKeyFromDigestAndSeparatesUnavailability(t *testing.T) {
	image := fixtureImage(t, ocitest.Spec{})
	store := artifact.FileStore{Root: t.TempDir()}
	ctx := context.Background()
	if _, err := artifact.FetchManifestV2(ctx, store, artifact.ManifestKey(image.ArtifactDigest), image.ArtifactDigest); err == nil || artifact.IsVerifyError(err) {
		t.Fatalf("missing manifest error = %v, want unavailability", err)
	}
	if err := image.Publish(ctx, store); err != nil {
		t.Fatal(err)
	}
	if _, err := artifact.FetchManifestV2(ctx, store, "v1/manifests/other.json", image.ArtifactDigest); !artifact.IsVerifyError(err) {
		t.Fatalf("substituted key error = %v", err)
	}
	fetched, err := artifact.FetchManifestV2(ctx, store, artifact.ManifestKey(image.ArtifactDigest), image.ArtifactDigest)
	if err != nil || fetched.Config.Digest != image.Manifest.Config.Digest {
		t.Fatalf("fetch = %+v err=%v", fetched.Config, err)
	}
}

func TestMaterializeOCILayoutWritesLoadableVerifiedLayout(t *testing.T) {
	image := fixtureImage(t, ocitest.Spec{})
	store := artifact.FileStore{Root: t.TempDir()}
	if err := image.Publish(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "instance.oci")
	layout, err := artifact.MaterializeOCILayout(context.Background(), store, image.ArtifactDigest, image.Manifest, dir)
	if err != nil {
		t.Fatal(err)
	}
	if layout.ConfigDigest != image.Manifest.Config.Digest || layout.ManifestDigest != image.Manifest.OCIManifest.Digest {
		t.Fatalf("layout identity = %+v", layout)
	}
	var archive bytes.Buffer
	if err := layout.WriteTar(&archive); err != nil {
		t.Fatal(err)
	}
	entries := map[string][]byte{}
	reader := tar.NewReader(&archive)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(reader)
		entries[header.Name] = body
	}
	var index struct {
		Manifests []struct {
			Digest      string            `json:"digest"`
			Size        int64             `json:"size"`
			Annotations map[string]string `json:"annotations"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(entries["index.json"], &index); err != nil || len(index.Manifests) != 1 {
		t.Fatalf("index.json = %s err=%v", entries["index.json"], err)
	}
	if index.Manifests[0].Digest != image.Manifest.OCIManifest.Digest || index.Manifests[0].Size != image.Manifest.OCIManifest.Size {
		t.Fatalf("index does not point at the verified OCI manifest: %+v", index.Manifests[0])
	}
	if !strings.Contains(string(entries["oci-layout"]), `"imageLayoutVersion":"1.0.0"`) {
		t.Fatalf("oci-layout = %s", entries["oci-layout"])
	}
	var blobNames, want []string
	for name, body := range entries {
		if strings.HasPrefix(name, "blobs/sha256/") && len(name) > len("blobs/sha256/") {
			blobNames = append(blobNames, name)
			if artifact.Digest(body) != "sha256:"+strings.TrimPrefix(name, "blobs/sha256/") {
				t.Fatalf("archived blob %s does not match its name", name)
			}
		}
	}
	for digest := range image.Blobs {
		want = append(want, "blobs/sha256/"+strings.TrimPrefix(digest, "sha256:"))
	}
	sort.Strings(blobNames)
	sort.Strings(want)
	if strings.Join(blobNames, ",") != strings.Join(want, ",") {
		t.Fatalf("archived blobs %v, want %v", blobNames, want)
	}
}

func TestMaterializeOCILayoutRejectsEveryBrokenBinding(t *testing.T) {
	base := fixtureImage(t, ocitest.Spec{})
	other := fixtureImage(t, ocitest.Spec{Layers: []map[string]ocitest.File{{"other": {Body: []byte("other")}}}})
	withVolumes := fixtureImage(t, ocitest.Spec{Layers: []map[string]ocitest.File{{"app": {Body: []byte("x")}}}, Volumes: []string{"/data"}})
	wrongDiff := fixtureImage(t, ocitest.Spec{
		Layers: []map[string]ocitest.File{{"app": {Body: []byte("x")}}}, Gzip: true,
		DiffIDs: []string{artifact.Digest([]byte("not the layer"))},
	})
	firstLayer := base.Manifest.Layers[0].Digest
	for _, test := range []struct {
		name       string
		image      ocitest.Image
		manifest   func() artifact.ManifestV2
		tamper     func(blobs map[string][]byte)
		verifyFail bool
	}{
		{name: "tampered layer", image: base, verifyFail: true, tamper: func(blobs map[string][]byte) {
			changed := bytes.Clone(blobs[firstLayer])
			changed[len(changed)/2] ^= 0xff
			blobs[firstLayer] = changed
		}},
		{name: "layer longer than declared", image: base, verifyFail: true, tamper: func(blobs map[string][]byte) {
			blobs[firstLayer] = append(bytes.Clone(blobs[firstLayer]), 0)
		}},
		{name: "missing layer is unavailability", image: base, verifyFail: false, tamper: func(blobs map[string][]byte) {
			delete(blobs, firstLayer)
		}},
		{name: "diff_id does not match decompressed layer", image: wrongDiff, verifyFail: true},
		{name: "config declares volumes", image: withVolumes, verifyFail: true},
		{name: "OCI manifest lists other layers", image: base, verifyFail: true, manifest: func() artifact.ManifestV2 {
			m := base.Manifest
			m.OCIManifest = other.Manifest.OCIManifest
			return m
		}, tamper: func(blobs map[string][]byte) {
			for digest, blob := range other.Blobs {
				blobs[digest] = blob
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			manifest := test.image.Manifest
			if test.manifest != nil {
				manifest = test.manifest()
			}
			_, digest, err := artifact.MarshalManifestV2(manifest)
			if err != nil {
				t.Fatal(err)
			}
			blobs := map[string][]byte{}
			for digest, blob := range test.image.Blobs {
				blobs[digest] = blob
			}
			if test.tamper != nil {
				test.tamper(blobs)
			}
			store := artifact.FileStore{Root: t.TempDir()}
			for digest, blob := range blobs {
				if err := store.Put(context.Background(), artifact.BlobKey(digest), blob, ""); err != nil {
					t.Fatal(err)
				}
			}
			dir := filepath.Join(t.TempDir(), "instance.oci")
			_, err = artifact.MaterializeOCILayout(context.Background(), store, digest, manifest, dir)
			if err == nil || artifact.IsVerifyError(err) != test.verifyFail {
				t.Fatalf("materialize error = %v, want verify=%t", err, test.verifyFail)
			}
			if _, statErr := os.Lstat(dir); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("failed materialization left %s: %v", dir, statErr)
			}
		})
	}
}
