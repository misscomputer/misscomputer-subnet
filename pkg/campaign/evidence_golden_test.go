// SPDX-License-Identifier: AGPL-3.0-only

package campaign

import (
	"bytes"
	"os"
	"testing"
)

func TestPR15EvidenceDigestGoldenMatchesPythonCheckpointInput(t *testing.T) {
	payload, err := os.ReadFile("../../contracts/fixtures/pr15-campaign-evidence-golden.v1.json")
	if err != nil {
		t.Fatalf("read cross-language evidence golden: %v", err)
	}
	evidence, err := ParseEvidence(payload)
	if err != nil {
		t.Fatalf("parse cross-language evidence golden: %v", err)
	}
	const expected = "0689008395f53716794849f35fe80e8612de31d8858196a1a0071f1459ff349c"
	if evidence.EvidenceDigestSHA256 != expected {
		t.Fatalf("evidence digest = %s, want %s", evidence.EvidenceDigestSHA256, expected)
	}
	rendered, err := MarshalEvidence(evidence)
	if err != nil {
		t.Fatalf("marshal cross-language evidence golden: %v", err)
	}
	if !bytes.Equal(rendered, payload) {
		t.Fatal("Go evidence bytes differ from the shared canonical golden")
	}
}
