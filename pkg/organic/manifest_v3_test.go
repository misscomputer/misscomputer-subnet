// SPDX-License-Identifier: AGPL-3.0-only

package organic_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"

	"github.com/misscomputer/misscomputer-subnet/pkg/organic"
)

// Pinned by tests/python/test_assignment_manifest_v3.py over the same golden.
const goldenManifestV3MessageSHA256 = "a184d1ffff628b6074911d87c32812e2f3497e24b1b0941b8723122ebe24e967"

func TestManifestV3SignatureMessageMatchesPython(t *testing.T) {
	manifest := *decodeFixture(t, "active-assignment-manifest.v3", &organic.ActiveAssignmentManifestV3{})
	message, err := organic.ManifestV3SignatureMessage(manifest)
	if err != nil {
		t.Fatal(err)
	}
	prefix := []byte("miss.computer/misscomputer-subnet/active-assignment-manifest/v3/ed25519\x00")
	if !bytes.HasPrefix(message, prefix) {
		t.Fatal("v3 message is not under the v3 domain")
	}
	if sum := sha256.Sum256(message); hex.EncodeToString(sum[:]) != goldenManifestV3MessageSHA256 {
		t.Fatalf("v3 signature message drifted from Python: %x", sum)
	}
	encoded, err := organic.CanonicalBytes(manifest)
	if err != nil || !bytes.Equal(encoded, read(t, "fixtures", "active-assignment-manifest.v3.json")) {
		t.Fatalf("v3 golden does not re-encode byte for byte: %v", err)
	}
}

func TestManifestV3TestnetNetworkPair(t *testing.T) {
	manifest := *decodeFixture(t, "active-assignment-manifest.v3", &organic.ActiveAssignmentManifestV3{})
	manifest.Network = "test"
	manifest.NetUID = 581
	digest, err := organic.DigestWithout(manifest, "manifest_digest_sha256")
	if err != nil {
		t.Fatal(err)
	}
	manifest.ManifestDigestSHA256 = digest
	if _, err := organic.ManifestV3SignatureMessage(manifest); err != nil {
		t.Fatalf("test/581 v3 manifest was refused: %v", err)
	}

	for _, pair := range []struct {
		network string
		netuid  int
	}{
		{"test", 24},
		{"finney", 581},
	} {
		invalid := manifest
		invalid.Network = pair.network
		invalid.NetUID = pair.netuid
		invalid.ManifestDigestSHA256, err = organic.DigestWithout(invalid, "manifest_digest_sha256")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := organic.ManifestV3SignatureMessage(invalid); err == nil {
			t.Fatalf("mismatched network pair %s/%d was accepted", pair.network, pair.netuid)
		}
	}
}

func TestManifestV3OCIDeploymentIsTheV2Deployment(t *testing.T) {
	v2 := *decodeFixture(t, "active-assignment-manifest.v2", &organic.ActiveAssignmentManifestV2{})
	v3 := *decodeFixture(t, "active-assignment-manifest.v3", &organic.ActiveAssignmentManifestV3{})
	oci, static := v3.Deployments[0], v3.Deployments[1]

	projected, err := oci.OCIAssignmentV2()
	if err != nil || !reflect.DeepEqual(projected, v2.Deployments[0]) {
		t.Fatalf("OCI v3 deployment differs from the v2 golden: %v", err)
	}
	if _, err := static.OCIAssignmentV2(); err == nil || !strings.Contains(err.Error(), "static_assignment_not_in_v2") {
		t.Fatalf("static deployment projected to v2: %v", err)
	}
	if static.WorkloadKind != organic.WorkloadKindStaticSiteV1 || *static.SiteDigest != staticContractSite ||
		*static.ReleaseDigest != staticContractReleaseDigest || static.ArtifactDigest != nil || static.Health != nil {
		t.Fatal("static golden is not bound to the contract §3.5/§7.1 example")
	}
}

func TestManifestVersionsDoNotDecodeAsEachOther(t *testing.T) {
	if err := organic.DecodeCanonical(read(t, "fixtures", "active-assignment-manifest.v3.json"), &organic.ActiveAssignmentManifestV2{}); err == nil {
		t.Fatal("v2 decoder accepted a v3 manifest")
	}
	if err := organic.DecodeCanonical(read(t, "fixtures", "active-assignment-manifest.v2.json"), &organic.ActiveAssignmentManifestV3{}); err == nil {
		t.Fatal("v3 decoder accepted a v2 manifest")
	}
}
