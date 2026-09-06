// SPDX-License-Identifier: AGPL-3.0-only

package assignment

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func contractsRoot(t *testing.T) string {
	t.Helper()
	_, source, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(source), "..", "..", "contracts"))
}

func fixtureBytes(t *testing.T, name string) []byte {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join(contractsRoot(t), "fixtures", name))
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestGoldenSnapshotRoundTripsByteExactly(t *testing.T) {
	payload := fixtureBytes(t, "active-assignment-snapshot.v1.json")
	snapshot, err := Parse(payload)
	if err != nil {
		t.Fatalf("parse golden snapshot: %v", err)
	}
	encoded, err := Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, payload) {
		t.Fatalf("Go canonical bytes drifted from the Python fixture\nfixture: %s\nencoded: %s", payload, encoded)
	}
	if snapshot.SnapshotSequence != 1 || snapshot.StateRevision != 7 || len(snapshot.Deployments) != 2 {
		t.Fatalf("unexpected golden identity: %+v", snapshot)
	}
}

func TestSealReproducesGoldenDigestsFromFactsAlone(t *testing.T) {
	payload := fixtureBytes(t, "active-assignment-snapshot.v1.json")
	golden, err := Parse(payload)
	if err != nil {
		t.Fatal(err)
	}
	facts := golden
	facts.Schema, facts.Purpose, facts.Network, facts.ProbeScheme = "", "", "", ""
	facts.SchemaVersion, facts.NetUID = 0, 0
	facts.SnapshotDigestSHA256 = "tampered"
	facts.ProjectedAssignmentVectorDigestSHA256 = "tampered"
	// Reverse the order and blank every derived identity to prove Seal derives them.
	facts.Deployments = append([]Deployment(nil), golden.Deployments...)
	for i, j := 0, len(facts.Deployments)-1; i < j; i, j = i+1, j-1 {
		facts.Deployments[i], facts.Deployments[j] = facts.Deployments[j], facts.Deployments[i]
	}
	for index := range facts.Deployments {
		deployment := &facts.Deployments[index]
		deployment.ExpectedStatus, deployment.AttestationRequirement, deployment.ChallengePath = 0, "", ""
		deployment.Replicas = append([]Replica(nil), deployment.Replicas...)
		for r := range deployment.Replicas {
			deployment.Replicas[r].ReplicaID, deployment.Replicas[r].EndpointID, deployment.Replicas[r].RouteState = "", "", ""
		}
	}
	sealed, err := Seal(facts)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	encoded, err := Marshal(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, payload) {
		t.Fatalf("sealed snapshot drifted from the golden fixture\nencoded: %s", encoded)
	}
}

func TestProjectionMatchesCommittedManifestDeployments(t *testing.T) {
	snapshot, err := Parse(fixtureBytes(t, "active-assignment-snapshot.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	projected, err := Project(snapshot.Deployments)
	if err != nil {
		t.Fatal(err)
	}
	projectedJSON, err := CanonicalJSON(projected)
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Deployments             json.RawMessage `json:"deployments"`
		AssignmentVectorDigest  string          `json:"assignment_vector_digest_sha256"`
		ManifestDigest          string          `json:"manifest_digest_sha256"`
		TrustPolicyDigestSHA256 string          `json:"trust_policy_digest_sha256"`
	}
	if err := json.Unmarshal(fixtureBytes(t, "active-assignment-manifest.v1.json"), &manifest); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(projectedJSON, []byte(manifest.Deployments)) {
		t.Fatalf("projection drifted from the manifest fixture\nprojected: %s\nmanifest:  %s", projectedJSON, manifest.Deployments)
	}
	vectorDigest, err := digestOf(projected)
	if err != nil {
		t.Fatal(err)
	}
	if vectorDigest != manifest.AssignmentVectorDigest || vectorDigest != snapshot.ProjectedAssignmentVectorDigestSHA256 {
		t.Fatalf("vector digest mismatch: %s vs %s", vectorDigest, manifest.AssignmentVectorDigest)
	}
}

func TestEmptySnapshotIsValidAndEncodesAnEmptyVector(t *testing.T) {
	snapshot, err := Parse(fixtureBytes(t, "active-assignment-snapshot.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Deployments = nil
	sealed, err := Seal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := Marshal(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"deployments":[]`)) {
		t.Fatalf("empty deployments must encode as []: %s", encoded)
	}
	if _, err := Parse(encoded); err != nil {
		t.Fatalf("empty snapshot must parse: %v", err)
	}
}

func TestParseRejectsMalleabilityAndDrift(t *testing.T) {
	payload := fixtureBytes(t, "active-assignment-snapshot.v1.json")
	var generic any
	if err := json.Unmarshal(payload, &generic); err != nil {
		t.Fatal(err)
	}
	pretty, err := json.MarshalIndent(generic, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"pretty":          append(pretty, '\n'),
		"no newline":      bytes.TrimSuffix(payload, []byte("\n")),
		"empty":           nil,
		"unknown field":   bytes.Replace(payload, []byte(`"netuid":24`), []byte(`"challenge_value":"x","netuid":24`), 1),
		"non ascii":       bytes.Replace(payload, []byte("fixture-alpha"), []byte("fixture-\xc3\xa9"), 1),
		"trailing object": append(append([]byte(nil), payload...), []byte("{}\n")...),
		"digest drift":    bytes.Replace(payload, []byte(`"state_revision":7`), []byte(`"state_revision":8`), 1),
	}
	for name, data := range cases {
		if _, err := Parse(data); err == nil {
			t.Fatalf("%s must be rejected", name)
		}
	}
}

func TestGoRejectsEveryPythonNegativeFixture(t *testing.T) {
	root := filepath.Join(contractsRoot(t), "negative", "active-assignment-snapshot.v1")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no negative fixtures found")
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		payload, err := os.ReadFile(filepath.Join(root, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var wrapper struct {
			Case     string          `json:"case"`
			Code     string          `json:"code"`
			Document json.RawMessage `json:"document"`
		}
		if err := json.Unmarshal(payload, &wrapper); err != nil {
			t.Fatal(err)
		}
		var generic any
		if err := json.Unmarshal(wrapper.Document, &generic); err != nil {
			t.Fatal(err)
		}
		canonical, err := CanonicalJSON(generic)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Parse(append(canonical, '\n')); err == nil {
			t.Fatalf("negative fixture %s (%s) must be rejected by Go as well", wrapper.Case, wrapper.Code)
		}
	}
}

func TestValidateRejectsSmallOrderServiceKeys(t *testing.T) {
	snapshot, err := Parse(fixtureBytes(t, "active-assignment-snapshot.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Deployments[0].Replicas[0].MinerServicePublicKey = "01" + strings.Repeat("00", 30) + "80"
	if _, err := Seal(snapshot); err == nil || !strings.Contains(err.Error(), "ed25519_public_key_invalid") {
		t.Fatalf("small-order key must be rejected, got %v", err)
	}
}
