// SPDX-License-Identifier: AGPL-3.0-only

package integration

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/campaign"
)

var integrationEpoch = time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

func TestCommittedRuntimeConfigExampleIsCanonicalAndInert(t *testing.T) {
	config, digest, err := LoadRuntimeConfig(filepath.Join("..", "..", "..", "configs", "synthetic-campaign.mainnet.example.json"))
	if err != nil || config.Campaign.Enabled || !validSHA256(digest) {
		t.Fatalf("example config=%+v digest=%q err=%v", config, digest, err)
	}
}

func TestExplicitCanonicalActivationAndWildcardReadiness(t *testing.T) {
	config := integrationConfig()
	digest, err := RuntimeConfigDigest(config)
	if err != nil || !validSHA256(digest) {
		t.Fatalf("runtime digest=%q err=%v", digest, err)
	}
	directory := t.TempDir()
	configPath := filepath.Join(directory, "campaign.json")
	payload, err := MarshalRuntimeConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	writePrivateTestFile(t, configPath, payload)
	loaded, loadedDigest, err := LoadRuntimeConfig(configPath)
	if err != nil || loadedDigest != digest || loaded.Campaign.CampaignID != config.Campaign.CampaignID {
		t.Fatalf("loaded=%+v digest=%q err=%v", loaded, loadedDigest, err)
	}

	proof := readinessProof(t, integrationEpoch)
	proofPayload, err := MarshalReadinessProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	proofPath := filepath.Join(directory, "readiness.json")
	writePrivateTestFile(t, proofPath, proofPayload)
	loadedProof, err := LoadReadinessProof(proofPath, integrationEpoch.Add(time.Minute))
	if err != nil || loadedProof.ProofDigestSHA256 != proof.ProofDigestSHA256 {
		t.Fatalf("proof=%+v err=%v", loadedProof, err)
	}
	environment := validEnvironment()
	if err := ValidateActivation(config, environment, loadedProof, integrationEpoch.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	disabled := config
	disabled.Campaign.Enabled = false
	if err := ValidateActivation(disabled, environment, loadedProof, integrationEpoch); !errors.Is(err, ErrInvalidRuntimeConfig) {
		t.Fatalf("disabled activation error=%v", err)
	}
	wrongEnvironment := environment
	wrongEnvironment.Network = "local"
	if err := ValidateActivation(config, wrongEnvironment, loadedProof, integrationEpoch); !errors.Is(err, ErrInvalidRuntimeConfig) {
		t.Fatalf("wrong environment error=%v", err)
	}
	wrongEnvironment = environment
	wrongEnvironment.EdgeProbeURL += "/"
	if err := ValidateActivation(config, wrongEnvironment, loadedProof, integrationEpoch); !errors.Is(err, ErrInvalidRuntimeConfig) {
		t.Fatalf("non-exact probe URL error=%v", err)
	}
	if _, err := ParseReadinessProof(proofPayload, proof.ExpiresAt); !errors.Is(err, ErrInvalidReadiness) {
		t.Fatalf("expired readiness error=%v", err)
	}

	tampered := append([]byte(nil), proofPayload...)
	tampered = bytes.Replace(tampered, []byte(`"public_probe_verified":true`), []byte(`"public_probe_verified":false`), 1)
	if _, err := ParseReadinessProof(tampered, integrationEpoch); !errors.Is(err, ErrInvalidReadiness) {
		t.Fatalf("tampered readiness error=%v", err)
	}
	writePrivateTestFile(t, configPath, append([]byte(" "), payload...))
	if _, _, err := LoadRuntimeConfig(configPath); !errors.Is(err, ErrInvalidRuntimeConfig) {
		t.Fatalf("noncanonical config error=%v", err)
	}
	if err := os.Chmod(configPath, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadRuntimeConfig(configPath); !errors.Is(err, ErrUnsafeFile) {
		t.Fatalf("writable control file error=%v", err)
	}
	realDirectory := filepath.Join(directory, "real")
	if err := os.Mkdir(realDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	realConfig := filepath.Join(realDirectory, "config.json")
	writePrivateTestFile(t, realConfig, payload)
	symlinkDirectory := filepath.Join(directory, "linked")
	if err := os.Symlink(realDirectory, symlinkDirectory); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadRuntimeConfig(filepath.Join(symlinkDirectory, "config.json")); !errors.Is(err, ErrUnsafeFile) {
		t.Fatalf("symlinked parent error=%v", err)
	}
}

func TestStateStoreRestartForwardRecoveryAndExclusiveLock(t *testing.T) {
	config := integrationConfig()
	digest, _ := RuntimeConfigDigest(config)
	missing := filepath.Join(t.TempDir(), "missing-state")
	if _, _, _, err := OpenStateStore(missing, config, digest, integrationEpoch); !errors.Is(err, ErrUnsafeFile) {
		t.Fatalf("unprovisioned state directory error=%v", err)
	}
	if _, err := os.Lstat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsafe state path was mutated: %v", err)
	}
	directory := newStateTestDirectory(t)
	store, state, runs, err := OpenStateStore(directory, config, digest, integrationEpoch)
	if err != nil || len(runs) != 0 || state.Mode != campaign.ModeRunning {
		t.Fatalf("state=%+v runs=%v err=%v", state, runs, err)
	}
	if _, _, _, err := OpenStateStore(directory, config, digest, integrationEpoch); !errors.Is(err, ErrStateLocked) {
		t.Fatalf("second writer error=%v", err)
	}
	engine, err := campaign.Restore(config.Campaign, state)
	if err != nil {
		t.Fatal(err)
	}
	if decision, err := engine.Schedule(integrationEpoch, []string{"MinerA", "MinerB", "MinerC"}); err != nil || decision.Reason != campaign.DecisionScheduled {
		t.Fatalf("schedule=%+v err=%v", decision, err)
	}
	if err := store.Save(engine.Snapshot(), []RunRecord{}); err != nil {
		t.Fatal(err)
	}
	_, _, revision, err := store.Current()
	if err != nil || revision != 2 {
		t.Fatalf("revision=%d err=%v", revision, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	payload, err := readPrivateFile(StatePath(directory), maximumRecordBytes)
	if err != nil {
		t.Fatal(err)
	}
	record, err := parseRecord(config, digest, payload)
	if err != nil {
		t.Fatal(err)
	}
	forward, forwardBytes, err := sealRecord(config, digest, record.Revision+1, record.State, record.Runs)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAtomicPrivate(directory, stateFileName, forwardBytes); err != nil {
		t.Fatal(err)
	}
	reopened, recovered, _, err := OpenStateStore(directory, config, digest, integrationEpoch.Add(time.Second))
	if err != nil || recovered.StateDigestSHA256 != forward.State.StateDigestSHA256 {
		t.Fatalf("forward recovery state=%+v err=%v", recovered, err)
	}
	_, _, revision, _ = reopened.Current()
	if revision != 3 {
		t.Fatalf("forward revision=%d", revision)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStateStoreRejectsCorruptStaleAndAmbiguousState(t *testing.T) {
	config := integrationConfig()
	digest, _ := RuntimeConfigDigest(config)

	t.Run("symlink directory", func(t *testing.T) {
		realDirectory := newStateTestDirectory(t)
		linkedDirectory := filepath.Join(t.TempDir(), "linked-state")
		if err := os.Symlink(realDirectory, linkedDirectory); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := OpenStateStore(linkedDirectory, config, digest, integrationEpoch); !errors.Is(err, ErrUnsafeFile) {
			t.Fatalf("symlink state directory error=%v", err)
		}
		if _, err := os.Lstat(filepath.Join(realDirectory, lockFileName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unsafe state directory was mutated: %v", err)
		}
	})

	t.Run("corrupt", func(t *testing.T) {
		directory := newStateTestDirectory(t)
		store, _, _, err := OpenStateStore(directory, config, digest, integrationEpoch)
		if err != nil {
			t.Fatal(err)
		}
		store.Close()
		payload, _ := os.ReadFile(StatePath(directory))
		payload[len(payload)/2] ^= 1
		writePrivateTestFile(t, StatePath(directory), payload)
		if _, _, _, err := OpenStateStore(directory, config, digest, integrationEpoch); !errors.Is(err, ErrCorruptState) {
			t.Fatalf("corrupt error=%v", err)
		}
	})

	t.Run("stale", func(t *testing.T) {
		directory := newStateTestDirectory(t)
		store, state, _, err := OpenStateStore(directory, config, digest, integrationEpoch)
		if err != nil {
			t.Fatal(err)
		}
		oldState, _ := os.ReadFile(StatePath(directory))
		engine, _ := campaign.Restore(config.Campaign, state)
		_, _ = engine.Schedule(integrationEpoch, []string{"MinerA", "MinerB", "MinerC"})
		if err := store.Save(engine.Snapshot(), []RunRecord{}); err != nil {
			t.Fatal(err)
		}
		store.Close()
		writePrivateTestFile(t, StatePath(directory), oldState)
		if _, _, _, err := OpenStateStore(directory, config, digest, integrationEpoch); !errors.Is(err, ErrStaleState) {
			t.Fatalf("stale error=%v", err)
		}
	})

	t.Run("same revision fork", func(t *testing.T) {
		directory := newStateTestDirectory(t)
		store, state, _, err := OpenStateStore(directory, config, digest, integrationEpoch)
		if err != nil {
			t.Fatal(err)
		}
		engine, _ := campaign.Restore(config.Campaign, state)
		if err := engine.Pause(integrationEpoch); err != nil {
			t.Fatal(err)
		}
		fork, forkBytes, err := sealRecord(config, digest, 1, engine.Snapshot(), []RunRecord{})
		if err != nil || fork.RecordDigestSHA256 == "" {
			t.Fatal(err)
		}
		store.Close()
		writePrivateTestFile(t, StatePath(directory), forkBytes)
		if _, _, _, err := OpenStateStore(directory, config, digest, integrationEpoch); !errors.Is(err, ErrAmbiguousState) {
			t.Fatalf("fork error=%v", err)
		}
	})

	t.Run("orphan temporary", func(t *testing.T) {
		directory := newStateTestDirectory(t)
		store, _, _, err := OpenStateStore(directory, config, digest, integrationEpoch)
		if err != nil {
			t.Fatal(err)
		}
		store.Close()
		writePrivateTestFile(t, filepath.Join(directory, temporaryPrefix+strings.Repeat("a", 24)), []byte("partial"))
		if _, _, _, err := OpenStateStore(directory, config, digest, integrationEpoch); !errors.Is(err, ErrAmbiguousState) {
			t.Fatalf("temporary error=%v", err)
		}
	})

	t.Run("orphan evidence temporary", func(t *testing.T) {
		directory := newStateTestDirectory(t)
		store, _, _, err := OpenStateStore(directory, config, digest, integrationEpoch)
		if err != nil {
			t.Fatal(err)
		}
		store.Close()
		evidencePath := filepath.Join(directory, evidenceDirectory)
		if err := os.Mkdir(evidencePath, 0o700); err != nil {
			t.Fatal(err)
		}
		writePrivateTestFile(t, filepath.Join(evidencePath, temporaryPrefix+strings.Repeat("b", 24)), []byte("partial"))
		if _, _, _, err := OpenStateStore(directory, config, digest, integrationEpoch); !errors.Is(err, ErrAmbiguousState) {
			t.Fatalf("evidence temporary error=%v", err)
		}
	})

	t.Run("initial anchor interruption reconciles once", func(t *testing.T) {
		directory := newStateTestDirectory(t)
		store, _, _, err := OpenStateStore(directory, config, digest, integrationEpoch)
		if err != nil {
			t.Fatal(err)
		}
		store.Close()
		if err := os.Remove(AnchorPath(directory)); err != nil {
			t.Fatal(err)
		}
		reopened, _, _, err := OpenStateStore(directory, config, digest, integrationEpoch)
		if err != nil {
			t.Fatalf("initial anchor reconciliation error=%v", err)
		}
		reopened.Close()
	})

	t.Run("later missing anchor is ambiguous", func(t *testing.T) {
		directory := newStateTestDirectory(t)
		store, state, _, err := OpenStateStore(directory, config, digest, integrationEpoch)
		if err != nil {
			t.Fatal(err)
		}
		engine, err := campaign.Restore(config.Campaign, state)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := engine.Schedule(integrationEpoch, []string{"MinerA", "MinerB", "MinerC"}); err != nil {
			t.Fatal(err)
		}
		if err := store.Save(engine.Snapshot(), []RunRecord{}); err != nil {
			t.Fatal(err)
		}
		store.Close()
		if err := os.Remove(AnchorPath(directory)); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := OpenStateStore(directory, config, digest, integrationEpoch); !errors.Is(err, ErrAmbiguousState) {
			t.Fatalf("missing later anchor error=%v", err)
		}
	})

	t.Run("started challenge without journal is corrupt", func(t *testing.T) {
		state, err := campaign.NewState(config.Campaign, integrationEpoch)
		if err != nil {
			t.Fatal(err)
		}
		engine, err := campaign.Restore(config.Campaign, state)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := engine.Schedule(integrationEpoch, []string{"MinerA", "MinerB", "MinerC"}); err != nil {
			t.Fatal(err)
		}
		if _, err := engine.StartNext(integrationEpoch); err != nil {
			t.Fatal(err)
		}
		if _, _, err := sealRecord(config, digest, 1, engine.Snapshot(), []RunRecord{}); !errors.Is(err, ErrCorruptState) {
			t.Fatalf("missing run journal error=%v", err)
		}
	})
}

func TestStateStoreRequiresManifestlessTerminalRunsToDropTheirJournal(t *testing.T) {
	config := integrationConfig()
	digest, _ := RuntimeConfigDigest(config)
	state, err := campaign.NewState(config.Campaign, integrationEpoch)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := campaign.Restore(config.Campaign, state)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Schedule(integrationEpoch, []string{"MinerA", "MinerB", "MinerC"}); err != nil {
		t.Fatal(err)
	}
	started, err := engine.StartNext(integrationEpoch)
	if err != nil || started.Challenge == nil {
		t.Fatalf("start=%+v err=%v", started, err)
	}
	journal := RunRecord{
		Sequence: started.Challenge.Sequence, DeploymentID: started.Challenge.DeploymentID,
		Phase: RunStarted, StartedAt: *started.Challenge.StartedAt, ArtifactKeys: []string{},
	}
	if _, _, err := sealRecord(config, digest, 1, engine.Snapshot(), []RunRecord{journal}); err != nil {
		t.Fatalf("clean pre-manifest journal: %v", err)
	}

	preManifestContamination := []struct {
		name   string
		mutate func(*RunRecord)
	}{
		{name: "artifact keys", mutate: func(run *RunRecord) { run.ArtifactKeys = []string{"blobs/sha256/invalid"} }},
		{name: "artifact bytes", mutate: func(run *RunRecord) { run.ArtifactBytes = 1 }},
		{name: "deployment cleanup", mutate: func(run *RunRecord) { run.DeploymentCleanupPending = true }},
		{name: "artifact cleanup", mutate: func(run *RunRecord) { run.ArtifactCleanupPending = true }},
		{name: "retention", mutate: func(run *RunRecord) { value := integrationEpoch.Add(time.Second); run.RetainUntil = &value }},
	}
	for _, test := range preManifestContamination {
		t.Run("started "+test.name, func(t *testing.T) {
			candidate := journal
			candidate.ArtifactKeys = append([]string(nil), journal.ArtifactKeys...)
			test.mutate(&candidate)
			if _, _, err := sealRecord(config, digest, 1, engine.Snapshot(), []RunRecord{candidate}); !errors.Is(err, ErrCorruptState) {
				t.Fatalf("contaminated pre-manifest journal error=%v", err)
			}
		})
	}

	if _, err := engine.Complete(started.Challenge.Sequence, integrationEpoch, campaign.OutcomeFailed, campaign.FailureCapacity); err != nil {
		t.Fatal(err)
	}
	if _, _, err := sealRecord(config, digest, 1, engine.Snapshot(), []RunRecord{}); err != nil {
		t.Fatalf("journal-free pre-manifest terminal state: %v", err)
	}
	retained := journal
	retained.Phase = RunRetained
	retained.LastFailureCode = campaign.FailureCapacity
	retainedCases := append([]struct {
		name   string
		mutate func(*RunRecord)
	}{{name: "journal", mutate: func(*RunRecord) {}}}, preManifestContamination...)
	for _, test := range retainedCases {
		t.Run("retained "+test.name, func(t *testing.T) {
			candidate := retained
			candidate.ArtifactKeys = append([]string(nil), retained.ArtifactKeys...)
			test.mutate(&candidate)
			if _, _, err := sealRecord(config, digest, 1, engine.Snapshot(), []RunRecord{candidate}); !errors.Is(err, ErrCorruptState) {
				t.Fatalf("manifestless retained journal error=%v", err)
			}
		})
	}
}

func integrationConfig() RuntimeConfig {
	config := DefaultRuntimeConfig()
	config.Campaign.Enabled = true
	config.Campaign.Cadence = campaign.CadencePolicy{MinimumDelayMillis: 1_000, MaximumDelayMillis: 1_000}
	config.Campaign.Limits = campaign.LimitPolicy{
		MaxConcurrent: 2, MaxPending: 3, MaxTrackedMiners: 16,
		ChallengeTimeoutMillis: 10_000, RetainedTerminalChallenges: 8,
	}
	config.Campaign.Coverage = campaign.CoveragePolicy{WindowMillis: int64((24 * time.Hour) / time.Millisecond), MinimumChallengesPerMiner: 3}
	config.Campaign.Workloads = []campaign.WorkloadPolicy{{Kind: "static", PayloadBytes: 1_024, Weight: 1}}
	config.TickIntervalMillis = 100
	config.Artifacts = ArtifactPolicy{
		MaxSingleBytes: 4_096, MaxRetainedBytes: 8_192, RetentionMillis: 1_000, CleanupTimeoutMillis: 1_000,
	}
	config.Retry = RetryPolicy{MaxAttempts: 3, InitialBackoffMillis: 100, MaximumBackoffMillis: 400}
	config.RetainedEvidence = 8
	return config
}

func readinessProof(t *testing.T, now time.Time) WildcardReadinessProof {
	t.Helper()
	proof, err := SealReadinessProof(WildcardReadinessProof{
		Version: ReadinessProofVersion, Network: campaign.MainnetNetwork, NetUID: campaign.MainnetNetUID,
		Domain: campaign.MainnetDomain, WildcardHost: "*." + campaign.MainnetDomain,
		DNSPreprovisioned: true, TunnelPreprovisioned: true, CertificatePreprovisioned: true, PublicProbeVerified: true,
		VerifiedAt: now.UTC(), ExpiresAt: now.Add(6 * time.Hour).UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func validEnvironment() ActivationEnvironment {
	return ActivationEnvironment{
		Network: campaign.MainnetNetwork, NetUID: campaign.MainnetNetUID, Domain: campaign.MainnetDomain,
		EdgeRequiresManagedWildcard: true, EdgeProbeURL: "https://{host}",
	}
}

func writePrivateTestFile(t *testing.T, path string, payload []byte) {
	t.Helper()
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

func newStateTestDirectory(t *testing.T) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}
