// SPDX-License-Identifier: AGPL-3.0-only

package playground

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/campaign"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
)

func TestRunControlExercisesBoundProductionFlow(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	bundle, err := RunControl(ctx, "control-integration")
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Schema != BundleSchema || bundle.SchemaVersion != BundleVersion || bundle.RunID != "control-integration" {
		t.Fatalf("unexpected bundle identity: %+v", bundle)
	}
	if bundle.Network != campaign.MainnetNetwork || bundle.NetUID != campaign.MainnetNetUID || bundle.Domain != campaign.MainnetDomain {
		t.Fatalf("unexpected subnet identity: %s/%d/%s", bundle.Network, bundle.NetUID, bundle.Domain)
	}
	if len(bundle.Miners) != 4 || len(bundle.Records) != controlRecordCount {
		t.Fatalf("miners=%d records=%d", len(bundle.Miners), len(bundle.Records))
	}

	targetOrdinals := make(map[string]map[uint64]bool, len(bundle.Miners))
	for _, record := range bundle.Records {
		evidence := record.CampaignEvidence
		if err := campaign.VerifyEvidence(evidence); err != nil {
			t.Fatalf("sequence %d evidence: %v", evidence.Sequence, err)
		}
		if evidence.ScoringEffect != campaign.ScoringEffectNone || evidence.AcceptanceObservationSource != campaign.ScoringSourceExisting {
			t.Fatalf("sequence %d crossed the evidence-only boundary", evidence.Sequence)
		}
		if len(record.Replicas) != 3 || len(evidence.AcceptedAssignments) != 3 {
			t.Fatalf("sequence %d replicas=%d assignments=%d", evidence.Sequence, len(record.Replicas), len(evidence.AcceptedAssignments))
		}
		if targetOrdinals[evidence.CoverageTargetMiner] == nil {
			targetOrdinals[evidence.CoverageTargetMiner] = make(map[uint64]bool)
		}
		targetOrdinals[evidence.CoverageTargetMiner][evidence.CoverageTargetOrdinal] = true
		seenTarget := false
		for _, replica := range record.Replicas {
			if replica.TicketVersion != protocol.BoundVersion || !replica.Success || replica.LatencyMS < 0 || replica.TransferredBytes != evidence.PayloadBytes {
				t.Fatalf("sequence %d invalid replica: %+v", evidence.Sequence, replica)
			}
			seenTarget = seenTarget || replica.MinerHotkey == evidence.CoverageTargetMiner
		}
		if !seenTarget {
			t.Fatalf("sequence %d omitted required target %s", evidence.Sequence, evidence.CoverageTargetMiner)
		}
	}
	for _, identity := range bundle.Miners {
		if !identity.Active || !identity.Eligible || !strings.HasPrefix(identity.Axon, "http://127.0.0.1:") {
			t.Fatalf("invalid local miner identity: %+v", identity)
		}
		ordinals := targetOrdinals[identity.Hotkey]
		if len(ordinals) != 3 || !ordinals[1] || !ordinals[2] || !ordinals[3] {
			t.Fatalf("target %s ordinals=%v", identity.Hotkey, ordinals)
		}
	}

	rendered, err := MarshalControlBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseControlBundle(rendered)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.BundleDigestSHA256 != bundle.BundleDigestSHA256 {
		t.Fatal("canonical round trip changed the bundle digest")
	}
}

func TestParseControlBundleRejectsTamperingAndNonCanonicalInput(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	bundle, err := RunControl(ctx, "control-rejection")
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := MarshalControlBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}

	var document map[string]any
	if err := json.Unmarshal(rendered, &document); err != nil {
		t.Fatal(err)
	}
	document["network"] = "tampered"
	tampered, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	tampered = append(tampered, '\n')
	if _, err := ParseControlBundle(tampered); err == nil {
		t.Fatal("digest-preserving tamper was accepted")
	}
	if _, err := ParseControlBundle(append([]byte(" "), rendered...)); err == nil {
		t.Fatal("non-canonical whitespace was accepted")
	}
	if _, err := ParseControlBundle(bytes.Replace(rendered, []byte("\n"), []byte("\n{}\n"), 1)); err == nil {
		t.Fatal("trailing document was accepted")
	}
}

func TestRunControlRejectsUnsafeRunIDs(t *testing.T) {
	t.Parallel()
	for _, runID := range []string{"", "-leading", "trailing-", "UPPER", strings.Repeat("a", 65)} {
		if _, err := RunControl(context.Background(), runID); err == nil {
			t.Fatalf("run ID %q was accepted", runID)
		}
	}
}
