// SPDX-License-Identifier: AGPL-3.0-only

package integration

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
	"github.com/misscomputer/misscomputer-subnet/pkg/campaign"
)

const (
	stateRecordVersion = "synthetic-campaign-runtime-state.v1"
	stateAnchorVersion = "synthetic-campaign-runtime-anchor.v1"
	stateFileName      = "campaign-state.json"
	anchorFileName     = "campaign-anchor.json"
	lockFileName       = "campaign.lock"
	evidenceDirectory  = "evidence"
	temporaryPrefix    = ".campaign-write-"
	maximumRecordBytes = 96 << 20
)

var (
	ErrStateLocked    = errors.New("campaign state directory is already locked")
	ErrStaleState     = errors.New("stale campaign state was rejected")
	ErrAmbiguousState = errors.New("ambiguous campaign state was rejected")
	ErrCorruptState   = errors.New("corrupt campaign runtime state was rejected")
)

type RunPhase string

const (
	RunStarted           RunPhase = "started"
	RunArtifactPlanned   RunPhase = "artifact_planned"
	RunArtifactPublished RunPhase = "artifact_published"
	RunDeploying         RunPhase = "deploying"
	RunRetained          RunPhase = "retained"
)

// RunRecord is the durable side-effect journal for one challenge. It contains
// exact content-addressed cleanup authority but no raw errors or credentials.
type RunRecord struct {
	Sequence                   uint64               `json:"sequence"`
	DeploymentID               string               `json:"deployment_id"`
	Phase                      RunPhase             `json:"phase"`
	StartedAt                  time.Time            `json:"started_at"`
	Manifest                   *artifact.Manifest   `json:"manifest,omitempty"`
	ArtifactKeys               []string             `json:"artifact_keys"`
	ArtifactBytes              int64                `json:"artifact_bytes"`
	DeploymentCleanupPending   bool                 `json:"deployment_cleanup_pending"`
	ArtifactCleanupPending     bool                 `json:"artifact_cleanup_pending"`
	RetainUntil                *time.Time           `json:"retain_until,omitempty"`
	DeploymentCleanupAttempts  int                  `json:"deployment_cleanup_attempts"`
	DeploymentNextCleanupAt    *time.Time           `json:"deployment_next_cleanup_at,omitempty"`
	DeploymentCleanupExhausted bool                 `json:"deployment_cleanup_exhausted"`
	ArtifactCleanupAttempts    int                  `json:"artifact_cleanup_attempts"`
	ArtifactNextCleanupAt      *time.Time           `json:"artifact_next_cleanup_at,omitempty"`
	ArtifactCleanupExhausted   bool                 `json:"artifact_cleanup_exhausted"`
	LastFailureCode            campaign.FailureCode `json:"last_failure_code,omitempty"`
}

type stateRecord struct {
	Version             string         `json:"version"`
	RuntimeConfigDigest string         `json:"runtime_config_digest_sha256"`
	Revision            uint64         `json:"revision"`
	State               campaign.State `json:"state"`
	Runs                []RunRecord    `json:"runs"`
	RecordDigestSHA256  string         `json:"record_digest_sha256,omitempty"`
}

type stateAnchor struct {
	Version             string `json:"version"`
	RuntimeConfigDigest string `json:"runtime_config_digest_sha256"`
	Revision            uint64 `json:"revision"`
	StateDigestSHA256   string `json:"state_digest_sha256"`
	RecordDigestSHA256  string `json:"record_digest_sha256"`
	AnchorDigestSHA256  string `json:"anchor_digest_sha256,omitempty"`
}

type StateStore struct {
	mu            sync.Mutex
	directory     string
	config        RuntimeConfig
	runtimeDigest string
	revision      uint64
	recordDigest  string
	state         campaign.State
	runs          []RunRecord
	lock          *os.File
	poisoned      bool
}

func StatePath(directory string) string  { return filepath.Join(directory, stateFileName) }
func AnchorPath(directory string) string { return filepath.Join(directory, anchorFileName) }

func OpenStateStore(directory string, config RuntimeConfig, runtimeDigest string, now time.Time) (*StateStore, campaign.State, []RunRecord, error) {
	if err := ValidateRuntimeConfig(config); err != nil {
		return nil, campaign.State{}, nil, err
	}
	expectedDigest, err := RuntimeConfigDigest(config)
	if err != nil || runtimeDigest != expectedDigest {
		return nil, campaign.State{}, nil, ErrCorruptState
	}
	if now.IsZero() {
		return nil, campaign.State{}, nil, ErrCorruptState
	}
	clean, err := secureStateDirectory(directory)
	if err != nil {
		return nil, campaign.State{}, nil, err
	}
	lock, err := acquireStateLock(filepath.Join(clean, lockFileName))
	if err != nil {
		return nil, campaign.State{}, nil, err
	}
	store := &StateStore{directory: clean, config: config, runtimeDigest: runtimeDigest, lock: lock}
	fail := func(err error) (*StateStore, campaign.State, []RunRecord, error) {
		_ = store.Close()
		return nil, campaign.State{}, nil, err
	}
	if err := rejectTemporaryFiles(clean); err != nil {
		return fail(err)
	}
	if err := validateExistingEvidenceDirectory(clean); err != nil {
		return fail(err)
	}
	recordPayload, recordErr := readOptionalPrivateFile(StatePath(clean), maximumRecordBytes)
	anchorPayload, anchorErr := readOptionalPrivateFile(AnchorPath(clean), maximumConfigBytes)
	if recordErr != nil && !errors.Is(recordErr, os.ErrNotExist) {
		return fail(recordErr)
	}
	if anchorErr != nil && !errors.Is(anchorErr, os.ErrNotExist) {
		return fail(anchorErr)
	}
	if errors.Is(recordErr, os.ErrNotExist) && errors.Is(anchorErr, os.ErrNotExist) {
		state, stateErr := campaign.NewState(config.Campaign, now.UTC())
		if stateErr != nil {
			return fail(stateErr)
		}
		record, recordBytes, stateErr := sealRecord(config, runtimeDigest, 1, state, []RunRecord{})
		if stateErr != nil {
			return fail(stateErr)
		}
		anchor, anchorBytes, stateErr := sealAnchor(record)
		if stateErr != nil {
			return fail(stateErr)
		}
		if stateErr = writeAtomicPrivate(clean, stateFileName, recordBytes); stateErr == nil {
			stateErr = writeAtomicPrivate(clean, anchorFileName, anchorBytes)
		}
		if stateErr != nil {
			return fail(stateErr)
		}
		store.install(record)
		_ = anchor

		stateCopy, _ := cloneCampaignState(config.Campaign, state)
		return store, stateCopy, []RunRecord{}, nil
	}
	if errors.Is(recordErr, os.ErrNotExist) {
		return fail(ErrStaleState)
	}
	record, err := parseRecord(config, runtimeDigest, recordPayload)
	if err != nil {
		return fail(err)
	}
	if record.State.UpdatedAt.After(now.UTC()) {
		return fail(ErrStaleState)
	}
	if errors.Is(anchorErr, os.ErrNotExist) {
		if record.Revision != 1 {
			return fail(ErrAmbiguousState)
		}
		_, anchorBytes, sealErr := sealAnchor(record)
		if sealErr != nil {
			return fail(sealErr)
		}
		if sealErr = writeAtomicPrivate(clean, anchorFileName, anchorBytes); sealErr != nil {
			return fail(sealErr)
		}
	} else {
		anchor, parseErr := parseAnchor(runtimeDigest, anchorPayload)
		if parseErr != nil {
			return fail(parseErr)
		}
		switch {
		case record.Revision == anchor.Revision && record.RecordDigestSHA256 == anchor.RecordDigestSHA256 &&
			record.State.StateDigestSHA256 == anchor.StateDigestSHA256:
		case anchor.Revision != ^uint64(0) && record.Revision == anchor.Revision+1:
			_, anchorBytes, sealErr := sealAnchor(record)
			parseErr = sealErr
			if parseErr == nil {
				parseErr = writeAtomicPrivate(clean, anchorFileName, anchorBytes)
			}
			if parseErr != nil {
				return fail(parseErr)
			}
		case record.Revision < anchor.Revision:
			return fail(ErrStaleState)
		default:
			return fail(ErrAmbiguousState)
		}
	}
	store.install(record)
	stateCopy, err := cloneCampaignState(config.Campaign, record.State)
	if err != nil {
		return fail(err)
	}
	return store, stateCopy, cloneRuns(record.Runs), nil
}

func (store *StateStore) Close() error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.lock == nil {
		return nil
	}
	err := syscall.Flock(int(store.lock.Fd()), syscall.LOCK_UN)
	closeErr := store.lock.Close()
	store.lock = nil
	return errors.Join(err, closeErr)
}

func (store *StateStore) Current() (campaign.State, []RunRecord, uint64, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.poisoned || store.lock == nil {
		return campaign.State{}, nil, 0, ErrAmbiguousState
	}
	state, err := cloneCampaignState(store.config.Campaign, store.state)
	return state, cloneRuns(store.runs), store.revision, err
}

func (store *StateStore) Save(state campaign.State, runs []RunRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.poisoned || store.lock == nil {
		return ErrAmbiguousState
	}
	if state.NextSequence < store.state.NextSequence || state.UpdatedAt.Before(store.state.UpdatedAt) || store.revision == ^uint64(0) {
		return ErrStaleState
	}
	recordPayload, err := readPrivateFile(StatePath(store.directory), maximumRecordBytes)
	if err != nil {
		store.poisoned = true
		return err
	}
	onDisk, err := parseRecord(store.config, store.runtimeDigest, recordPayload)
	if err != nil || onDisk.Revision != store.revision || onDisk.RecordDigestSHA256 != store.recordDigest {
		store.poisoned = true
		return ErrAmbiguousState
	}
	anchorPayload, err := readPrivateFile(AnchorPath(store.directory), maximumConfigBytes)
	if err != nil {
		store.poisoned = true
		return err
	}
	anchor, err := parseAnchor(store.runtimeDigest, anchorPayload)
	if err != nil || anchor.Revision != store.revision || anchor.RecordDigestSHA256 != store.recordDigest ||
		anchor.StateDigestSHA256 != store.state.StateDigestSHA256 {
		store.poisoned = true
		return ErrAmbiguousState
	}
	record, recordBytes, err := sealRecord(store.config, store.runtimeDigest, store.revision+1, state, runs)
	if err != nil {
		return err
	}
	_, anchorBytes, err := sealAnchor(record)
	if err != nil {
		return err
	}
	if err = writeAtomicPrivate(store.directory, stateFileName, recordBytes); err != nil {
		return err
	}
	if err = writeAtomicPrivate(store.directory, anchorFileName, anchorBytes); err != nil {
		store.poisoned = true
		return err
	}
	store.install(record)
	return nil
}

func (store *StateStore) WriteEvidence(evidence campaign.Evidence) error {
	payload, err := campaign.MarshalEvidence(evidence)
	if err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.poisoned || store.lock == nil {
		return ErrAmbiguousState
	}
	if evidence.CampaignID != store.config.Campaign.CampaignID || evidence.ConfigDigestSHA256 != store.state.ConfigDigestSHA256 ||
		evidence.Sequence >= store.state.NextSequence {
		return ErrAmbiguousState
	}
	directory := filepath.Join(store.directory, evidenceDirectory)
	if err := ensurePrivateSubdirectory(directory); err != nil {
		return err
	}
	name := fmt.Sprintf("%020d.json", evidence.Sequence)
	path := filepath.Join(directory, name)
	existing, readErr := readOptionalPrivateFile(path, maximumConfigBytes)
	if readErr == nil {
		parsed, parseErr := campaign.ParseEvidence(existing)
		if parseErr != nil || parsed.EvidenceDigestSHA256 != evidence.EvidenceDigestSHA256 || !bytes.Equal(existing, payload) {
			return ErrAmbiguousState
		}
		return nil
	}
	if !errors.Is(readErr, os.ErrNotExist) {
		return readErr
	}
	if err := writeAtomicPrivate(directory, name, payload); err != nil {
		return err
	}
	return pruneEvidenceLocked(directory, store.config.RetainedEvidence)
}

func (store *StateStore) Evidence(sequence uint64) (campaign.Evidence, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if sequence == 0 || store.poisoned || store.lock == nil {
		return campaign.Evidence{}, ErrAmbiguousState
	}
	path := filepath.Join(store.directory, evidenceDirectory, fmt.Sprintf("%020d.json", sequence))
	payload, err := readPrivateFile(path, maximumConfigBytes)
	if err != nil {
		return campaign.Evidence{}, err
	}
	evidence, err := campaign.ParseEvidence(payload)
	if err != nil {
		return campaign.Evidence{}, err
	}
	if evidence.Sequence != sequence || evidence.CampaignID != store.config.Campaign.CampaignID || evidence.ConfigDigestSHA256 != store.state.ConfigDigestSHA256 ||
		evidence.Sequence >= store.state.NextSequence {
		return campaign.Evidence{}, ErrAmbiguousState
	}
	return evidence, nil
}

func (store *StateStore) install(record stateRecord) {
	store.revision = record.Revision
	store.recordDigest = record.RecordDigestSHA256
	store.state, _ = cloneCampaignState(store.config.Campaign, record.State)
	store.runs = cloneRuns(record.Runs)
}

func sealRecord(config RuntimeConfig, runtimeDigest string, revision uint64, state campaign.State, runs []RunRecord) (stateRecord, []byte, error) {
	record := stateRecord{
		Version: stateRecordVersion, RuntimeConfigDigest: runtimeDigest, Revision: revision,
		State: state, Runs: cloneRuns(runs),
	}
	sort.Slice(record.Runs, func(left, right int) bool { return record.Runs[left].Sequence < record.Runs[right].Sequence })
	if err := validateRecord(config, runtimeDigest, record, false); err != nil {
		return stateRecord{}, nil, err
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return stateRecord{}, nil, ErrCorruptState
	}
	record.RecordDigestSHA256 = sha256Hex(payload)
	payload, err = json.Marshal(record)
	if err != nil || len(payload)+1 > maximumRecordBytes {
		return stateRecord{}, nil, ErrCorruptState
	}
	return record, append(payload, '\n'), nil
}

func parseRecord(config RuntimeConfig, runtimeDigest string, payload []byte) (stateRecord, error) {
	if len(payload) == 0 || len(payload) > maximumRecordBytes {
		return stateRecord{}, ErrCorruptState
	}
	var record stateRecord
	if err := decodeExact(payload, &record); err != nil {
		return stateRecord{}, ErrCorruptState
	}
	if err := validateRecord(config, runtimeDigest, record, true); err != nil {
		return stateRecord{}, err
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(payload, append(canonical, '\n')) {
		return stateRecord{}, ErrCorruptState
	}
	return record, nil
}

func validateRecord(config RuntimeConfig, runtimeDigest string, record stateRecord, requireDigest bool) error {
	if record.Version != stateRecordVersion || record.RuntimeConfigDigest != runtimeDigest || !validSHA256(runtimeDigest) ||
		record.Revision == 0 || record.Runs == nil || campaign.VerifyState(config.Campaign, record.State) != nil {
		return corruptState("record identity, collections, or campaign state")
	}
	if requireDigest {
		if !validSHA256(record.RecordDigestSHA256) {
			return corruptState("record digest encoding")
		}
		candidate := record
		claimed := candidate.RecordDigestSHA256
		candidate.RecordDigestSHA256 = ""
		payload, err := json.Marshal(candidate)
		if err != nil || subtle.ConstantTimeCompare([]byte(claimed), []byte(sha256Hex(payload))) != 1 {
			return corruptState("record digest mismatch")
		}
	}
	var previous uint64
	challenges := make(map[uint64]campaign.Challenge, len(record.State.Challenges))
	for _, challenge := range record.State.Challenges {
		challenges[challenge.Sequence] = challenge
	}
	seenDeployments := make(map[string]struct{}, len(record.Runs))
	seenRuns := make(map[uint64]struct{}, len(record.Runs))
	var retainedArtifactBytes int64
	for _, run := range record.Runs {
		if run.Sequence <= previous || run.Sequence >= record.State.NextSequence || run.DeploymentID == "" ||
			!canonicalTime(run.StartedAt) || run.ArtifactKeys == nil || run.ArtifactBytes < 0 ||
			run.ArtifactBytes > config.Artifacts.MaxSingleBytes ||
			run.DeploymentCleanupAttempts < 0 || run.DeploymentCleanupAttempts > config.Retry.MaxAttempts ||
			run.ArtifactCleanupAttempts < 0 || run.ArtifactCleanupAttempts > config.Retry.MaxAttempts ||
			!validRunPhase(run.Phase) || !validFailureCode(run.LastFailureCode) {
			return corruptState("run identity, bounds, phase, or failure code")
		}
		if _, exists := seenDeployments[run.DeploymentID]; exists {
			return corruptState("duplicate run deployment")
		}
		seenDeployments[run.DeploymentID] = struct{}{}
		seenRuns[run.Sequence] = struct{}{}
		if run.ArtifactBytes > config.Artifacts.MaxRetainedBytes-retainedArtifactBytes {
			return corruptState("retained artifact byte bound")
		}
		retainedArtifactBytes += run.ArtifactBytes
		previous = run.Sequence
		challenge, retainedChallenge := challenges[run.Sequence]
		if retainedChallenge {
			if challenge.DeploymentID != run.DeploymentID || challenge.StartedAt == nil || !challenge.StartedAt.Equal(run.StartedAt) ||
				challenge.Status == campaign.StatusPending ||
				(challenge.Status == campaign.StatusRunning && run.Phase == RunRetained) ||
				(challenge.Status != campaign.StatusRunning && run.Phase != RunRetained) {
				return corruptState("run does not match retained challenge lifecycle")
			}
		} else if run.Phase != RunRetained {
			return corruptState("unretained challenge has an unfinished run journal")
		}
		if run.RetainUntil != nil && (!canonicalTime(*run.RetainUntil) || run.RetainUntil.Before(run.StartedAt)) {
			return corruptState("run retention time")
		}
		if run.DeploymentNextCleanupAt != nil && (!canonicalTime(*run.DeploymentNextCleanupAt) || run.DeploymentNextCleanupAt.Before(run.StartedAt)) {
			return corruptState("deployment cleanup time")
		}
		if run.ArtifactNextCleanupAt != nil && (!canonicalTime(*run.ArtifactNextCleanupAt) || run.ArtifactNextCleanupAt.Before(run.StartedAt)) {
			return corruptState("artifact cleanup time")
		}
		if run.DeploymentCleanupExhausted != (run.DeploymentCleanupAttempts == config.Retry.MaxAttempts) ||
			(run.DeploymentCleanupExhausted && run.DeploymentNextCleanupAt != nil) ||
			run.ArtifactCleanupExhausted != (run.ArtifactCleanupAttempts == config.Retry.MaxAttempts) ||
			(run.ArtifactCleanupExhausted && run.ArtifactNextCleanupAt != nil) {
			return corruptState("cleanup retry state")
		}
		if (!run.DeploymentCleanupPending && (run.DeploymentCleanupAttempts != 0 || run.DeploymentNextCleanupAt != nil || run.DeploymentCleanupExhausted)) ||
			(run.DeploymentCleanupAttempts == 0 && run.DeploymentNextCleanupAt != nil) ||
			(run.DeploymentCleanupAttempts > 0 && run.DeploymentCleanupAttempts < config.Retry.MaxAttempts && run.DeploymentNextCleanupAt == nil) ||
			(!run.ArtifactCleanupPending && (run.ArtifactCleanupAttempts != 0 || run.ArtifactNextCleanupAt != nil || run.ArtifactCleanupExhausted)) ||
			(run.ArtifactCleanupAttempts == 0 && run.ArtifactNextCleanupAt != nil) ||
			(run.ArtifactCleanupAttempts > 0 && run.ArtifactCleanupAttempts < config.Retry.MaxAttempts && run.ArtifactNextCleanupAt == nil) {
			return corruptState("cleanup retry ownership")
		}
		if run.Phase != RunRetained && (run.DeploymentCleanupPending || run.ArtifactCleanupPending ||
			run.DeploymentCleanupAttempts != 0 || run.ArtifactCleanupAttempts != 0 || run.LastFailureCode != campaign.FailureNone) {
			return corruptState("unfinished run carries cleanup state")
		}
		if run.Manifest == nil {
			// RunStarted is the sole pre-side-effect journal. Completion removes
			// it atomically with the terminal campaign state, so a manifestless
			// retained/cleanup record is always corrupt rather than cleanup
			// authority that can be guessed after the fact.
			if len(run.ArtifactKeys) != 0 || run.ArtifactBytes != 0 || run.ArtifactCleanupPending || run.RetainUntil != nil ||
				run.Phase == RunArtifactPlanned || run.Phase == RunArtifactPublished || run.Phase == RunDeploying || run.Phase == RunRetained {
				return corruptState("run without manifest carries artifact state")
			}
			continue
		}
		keys, err := artifact.ArtifactKeys(*run.Manifest)
		if err != nil || !equalStrings(keys, run.ArtifactKeys) || !canonicalTime(run.Manifest.CreatedAt) || run.Manifest.CreatedAt.Before(run.StartedAt) {
			return corruptState("artifact manifest identity or time")
		}
		var total int64
		for _, layer := range run.Manifest.Layers {
			if layer.Size < 0 || total > config.Artifacts.MaxSingleBytes-layer.Size {
				return corruptState("artifact layer byte bound")
			}
			total += layer.Size
		}
		if total != run.ArtifactBytes || run.Phase == RunStarted || (run.ArtifactCleanupPending && run.RetainUntil == nil) {
			return corruptState("artifact total, phase, or retention")
		}
		if run.Phase == RunRetained && run.DeploymentCleanupPending && !run.ArtifactCleanupPending {
			return corruptState("artifact cleanup cannot precede deployment cleanup")
		}
		if retainedChallenge && (run.Manifest.WorkloadType != challenge.Workload.Kind || len(run.Manifest.Layers) != 1 ||
			run.ArtifactBytes != int64(challenge.Workload.PayloadBytes) || len(run.Manifest.Annotations) != 3 ||
			run.Manifest.Annotations["build_id"] != challenge.Workload.BuildID ||
			run.Manifest.Annotations["campaign_id"] != record.State.CampaignID ||
			run.Manifest.Annotations["campaign_sequence"] != strconv.FormatUint(run.Sequence, 10)) {
			return corruptState("artifact does not match retained challenge")
		}
	}
	for _, challenge := range record.State.Challenges {
		_, hasRun := seenRuns[challenge.Sequence]
		if challenge.Status == campaign.StatusRunning && !hasRun {
			return corruptState("started challenge is missing its run journal")
		}
	}
	return nil
}

func sealAnchor(record stateRecord) (stateAnchor, []byte, error) {
	anchor := stateAnchor{
		Version: stateAnchorVersion, RuntimeConfigDigest: record.RuntimeConfigDigest, Revision: record.Revision,
		StateDigestSHA256: record.State.StateDigestSHA256, RecordDigestSHA256: record.RecordDigestSHA256,
	}
	payload, err := json.Marshal(anchor)
	if err != nil {
		return stateAnchor{}, nil, ErrCorruptState
	}
	anchor.AnchorDigestSHA256 = sha256Hex(payload)
	payload, err = json.Marshal(anchor)
	if err != nil {
		return stateAnchor{}, nil, ErrCorruptState
	}
	return anchor, append(payload, '\n'), nil
}

func parseAnchor(runtimeDigest string, payload []byte) (stateAnchor, error) {
	if len(payload) == 0 || len(payload) > maximumConfigBytes {
		return stateAnchor{}, ErrCorruptState
	}
	var anchor stateAnchor
	if err := decodeExact(payload, &anchor); err != nil || anchor.Version != stateAnchorVersion ||
		anchor.RuntimeConfigDigest != runtimeDigest || anchor.Revision == 0 || !validSHA256(anchor.StateDigestSHA256) ||
		!validSHA256(anchor.RecordDigestSHA256) || !validSHA256(anchor.AnchorDigestSHA256) {
		return stateAnchor{}, ErrCorruptState
	}
	candidate := anchor
	claimed := candidate.AnchorDigestSHA256
	candidate.AnchorDigestSHA256 = ""
	encoded, err := json.Marshal(candidate)
	if err != nil || subtle.ConstantTimeCompare([]byte(claimed), []byte(sha256Hex(encoded))) != 1 {
		return stateAnchor{}, ErrCorruptState
	}
	canonical, err := json.Marshal(anchor)
	if err != nil || !bytes.Equal(payload, append(canonical, '\n')) {
		return stateAnchor{}, ErrCorruptState
	}
	return anchor, nil
}

func secureStateDirectory(directory string) (string, error) {
	if directory == "" {
		return "", ErrUnsafeFile
	}
	clean, err := filepath.Abs(filepath.Clean(directory))
	if err != nil || clean == string(filepath.Separator) {
		return "", ErrUnsafeFile
	}
	if err := rejectSymlinkComponents(clean); err != nil {
		return "", err
	}
	info, err := os.Lstat(clean)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return "", ErrUnsafeFile
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return "", ErrUnsafeFile
	}
	return clean, nil
}

func ensurePrivateSubdirectory(directory string) error {
	if err := os.Mkdir(directory, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return ErrUnsafeFile
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return ErrUnsafeFile
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return ErrUnsafeFile
	}
	return nil
}

func validateExistingEvidenceDirectory(stateDirectory string) error {
	directory := filepath.Join(stateDirectory, evidenceDirectory)
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return ErrUnsafeFile
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return ErrUnsafeFile
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return ErrUnsafeFile
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, temporaryPrefix) {
			return ErrAmbiguousState
		}
		if entry.IsDir() || len(name) != 25 || !strings.HasSuffix(name, ".json") {
			return ErrAmbiguousState
		}
		if _, err := strconv.ParseUint(strings.TrimSuffix(name, ".json"), 10, 64); err != nil {
			return ErrAmbiguousState
		}
		fileInfo, err := os.Lstat(filepath.Join(directory, name))
		if err != nil || !fileInfo.Mode().IsRegular() || fileInfo.Mode()&os.ModeSymlink != 0 || !safeFileOwnerAndLinks(fileInfo, true) {
			return ErrUnsafeFile
		}
		if fileInfo.Size() < 1 || fileInfo.Size() > maximumConfigBytes {
			return ErrCorruptState
		}
	}
	return nil
}

func acquireStateLock(path string) (*os.File, error) {
	var before os.FileInfo
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || !safeFileOwnerAndLinks(info, true) {
			return nil, ErrUnsafeFile
		}
		before = info
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, ErrUnsafeFile
	}
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, ErrUnsafeFile
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, ErrUnsafeFile
	}
	info, err := file.Stat()
	if err != nil || !safeFileOwnerAndLinks(info, true) || (before != nil && !os.SameFile(before, info)) {
		file.Close()
		return nil, ErrUnsafeFile
	}
	final, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, final) {
		file.Close()
		return nil, ErrUnsafeFile
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, ErrStateLocked
	}
	return file, nil
}

func rejectTemporaryFiles(directory string) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return ErrUnsafeFile
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), temporaryPrefix) {
			return ErrAmbiguousState
		}
	}
	return nil
}

func readOptionalPrivateFile(path string, maximum int64) ([]byte, error) {
	payload, err := readPrivateFile(path, maximum)
	if errors.Is(err, os.ErrNotExist) {
		return nil, os.ErrNotExist
	}
	return payload, err
}

func readPrivateFile(path string, maximum int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, os.ErrNotExist
		}
		return nil, ErrUnsafeFile
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() < 1 || before.Size() > maximum ||
		!safeFileOwnerAndLinks(before, true) {
		return nil, ErrUnsafeFile
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrUnsafeFile
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !safeFileOwnerAndLinks(after, true) {
		return nil, ErrUnsafeFile
	}
	payload, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(payload)) > maximum {
		return nil, ErrUnsafeFile
	}
	final, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, final) {
		return nil, ErrUnsafeFile
	}
	return payload, nil
}

func writeAtomicPrivate(directory, name string, payload []byte) error {
	if filepath.Base(name) != name || len(payload) == 0 {
		return ErrUnsafeFile
	}
	target := filepath.Join(directory, name)
	if info, err := os.Lstat(target); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || !safeFileOwnerAndLinks(info, true) {
			return ErrUnsafeFile
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrUnsafeFile
	}
	random := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return err
	}
	temporaryName := temporaryPrefix + hex.EncodeToString(random)
	temporaryPath := filepath.Join(directory, temporaryName)
	file, err := os.OpenFile(temporaryPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	remove := true
	defer func() {
		if remove {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err = file.Chmod(0o600); err != nil {
		file.Close()
		return err
	}
	opened, statErr := file.Stat()
	if statErr != nil || opened.Mode().Perm() != 0o600 || !safeFileOwnerAndLinks(opened, true) {
		file.Close()
		return ErrUnsafeFile
	}
	if _, err = file.Write(payload); err == nil {
		err = file.Sync()
	}
	if err == nil {
		finalOpen, finalErr := file.Stat()
		named, namedErr := os.Lstat(temporaryPath)
		if finalErr != nil || namedErr != nil || !os.SameFile(finalOpen, named) || finalOpen.Mode().Perm() != 0o600 || !safeFileOwnerAndLinks(finalOpen, true) {
			err = ErrUnsafeFile
		}
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(temporaryPath, target); err != nil {
		return err
	}
	remove = false
	installed, err := os.Lstat(target)
	if err != nil || installed.Mode().Perm() != 0o600 || !safeFileOwnerAndLinks(installed, true) {
		return ErrUnsafeFile
	}
	directoryFile, err := os.Open(directory)
	if err != nil {
		return err
	}
	err = directoryFile.Sync()
	closeErr := directoryFile.Close()
	return errors.Join(err, closeErr)
}

func pruneEvidenceLocked(directory string, maximum int) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || len(name) != 25 || !strings.HasSuffix(name, ".json") {
			return ErrAmbiguousState
		}
		if _, err := strconv.ParseUint(strings.TrimSuffix(name, ".json"), 10, 64); err != nil {
			return ErrAmbiguousState
		}
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) <= maximum {
		return nil
	}
	for _, name := range names[:len(names)-maximum] {
		if err := os.Remove(filepath.Join(directory, name)); err != nil {
			return err
		}
	}
	directoryFile, err := os.Open(directory)
	if err != nil {
		return err
	}
	err = directoryFile.Sync()
	return errors.Join(err, directoryFile.Close())
}

func cloneCampaignState(config campaign.Config, state campaign.State) (campaign.State, error) {
	payload, err := campaign.MarshalState(config, state)
	if err != nil {
		return campaign.State{}, err
	}
	return campaign.ParseState(config, payload)
}

func cloneRuns(runs []RunRecord) []RunRecord {
	result := make([]RunRecord, len(runs))
	for index, run := range runs {
		result[index] = run
		if run.ArtifactKeys != nil {
			result[index].ArtifactKeys = make([]string, len(run.ArtifactKeys))
			copy(result[index].ArtifactKeys, run.ArtifactKeys)
		}
		if run.Manifest != nil {
			manifest := *run.Manifest
			manifest.Layers = append([]artifact.Layer(nil), run.Manifest.Layers...)
			if run.Manifest.Annotations != nil {
				manifest.Annotations = make(map[string]string, len(run.Manifest.Annotations))
				for key, value := range run.Manifest.Annotations {
					manifest.Annotations[key] = value
				}
			}
			result[index].Manifest = &manifest
		}
		result[index].RetainUntil = cloneTime(run.RetainUntil)
		result[index].DeploymentNextCleanupAt = cloneTime(run.DeploymentNextCleanupAt)
		result[index].ArtifactNextCleanupAt = cloneTime(run.ArtifactNextCleanupAt)
	}
	return result
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copyValue := *value
	return &copyValue
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func validRunPhase(phase RunPhase) bool {
	switch phase {
	case RunStarted, RunArtifactPlanned, RunArtifactPublished, RunDeploying, RunRetained:
		return true
	default:
		return false
	}
}

func validFailureCode(code campaign.FailureCode) bool {
	switch code {
	case campaign.FailureNone, campaign.FailureCapacity, campaign.FailureDeadline, campaign.FailureArtifact,
		campaign.FailureAssignment, campaign.FailureReceipt, campaign.FailureChallenge, campaign.FailureRouting,
		campaign.FailureCancelled, campaign.FailureOperatorDrain, campaign.FailureOperatorShutdown, campaign.FailureInternal:
		return true
	default:
		return false
	}
}

func corruptState(reason string) error {
	return fmt.Errorf("%w: %s", ErrCorruptState, reason)
}
