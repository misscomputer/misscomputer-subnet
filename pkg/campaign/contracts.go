// SPDX-License-Identifier: AGPL-3.0-only

// Package campaign defines the inert, restart-safe planning core for a
// continuous mainnet synthetic challenge campaign. It deliberately has no
// storage, network, DNS, artifact, chain, wallet, or activation integration.
package campaign

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	"github.com/misscomputer/misscomputer-subnet/pkg/workload"
)

const (
	ConfigVersion    = "synthetic-campaign-config.v1"
	StateVersion     = "synthetic-campaign-state.v1"
	ChallengeVersion = "synthetic-campaign-challenge.v1"
	EvidenceVersion  = "synthetic-campaign-evidence.v1"

	MainnetNetwork = "finney"
	MainnetNetUID  = uint16(24)
	MainnetDomain  = "on.miss.computer"

	AssignmentTicketVersion = "deployment.v3"
	ScoringEffectNone       = "none"
	ScoringSourceExisting   = "existing-validator-acceptance-observations"

	minimumPayloadBytes  = 1 << 10
	maximumPayloadBytes  = 1 << 30
	maximumStateBytes    = 64 << 20
	maximumEvidenceBytes = 1 << 20
)

var (
	ErrInvalidConfig       = errors.New("invalid campaign config")
	ErrInvalidState        = errors.New("invalid campaign state")
	ErrStateDigestMismatch = errors.New("campaign state digest mismatch")
	ErrInvalidStateBytes   = errors.New("campaign state encoding is not canonical")
	ErrInvalidEvidence     = errors.New("invalid campaign evidence")
)

// Config is policy only. It intentionally has no credential, provider,
// storage, wallet, RPC, or activation fields.
type Config struct {
	Version          string           `json:"version"`
	Enabled          bool             `json:"enabled"`
	CampaignID       string           `json:"campaign_id"`
	Network          string           `json:"network"`
	NetUID           uint16           `json:"netuid"`
	Domain           string           `json:"domain"`
	DeploymentPrefix string           `json:"deployment_prefix"`
	Cadence          CadencePolicy    `json:"cadence"`
	Limits           LimitPolicy      `json:"limits"`
	Coverage         CoveragePolicy   `json:"coverage"`
	RequiredReplicas int              `json:"required_replicas"`
	Workloads        []WorkloadPolicy `json:"workloads"`
}

type CadencePolicy struct {
	MinimumDelayMillis int64 `json:"minimum_delay_ms"`
	MaximumDelayMillis int64 `json:"maximum_delay_ms"`
}

type LimitPolicy struct {
	MaxConcurrent              int   `json:"max_concurrent"`
	MaxPending                 int   `json:"max_pending"`
	MaxTrackedMiners           int   `json:"max_tracked_miners"`
	ChallengeTimeoutMillis     int64 `json:"challenge_timeout_ms"`
	RetainedTerminalChallenges int   `json:"retained_terminal_challenges"`
}

type CoveragePolicy struct {
	WindowMillis              int64  `json:"window_ms"`
	MinimumChallengesPerMiner uint64 `json:"minimum_challenges_per_miner"`
}

// WorkloadPolicy is a weighted fixed-size mix. Fixed sizes make every planned
// challenge auditable and keep allocation bounds explicit.
type WorkloadPolicy struct {
	Kind         string `json:"kind"`
	PayloadBytes int    `json:"payload_bytes"`
	Weight       uint32 `json:"weight"`
}

func DefaultConfig() Config {
	return Config{
		Version: ConfigVersion, Enabled: false, CampaignID: "continuous-synthetic-v1",
		Network: MainnetNetwork, NetUID: MainnetNetUID, Domain: MainnetDomain,
		DeploymentPrefix: "syn",
		Cadence: CadencePolicy{
			MinimumDelayMillis: int64((5 * time.Minute) / time.Millisecond),
			MaximumDelayMillis: int64((15 * time.Minute) / time.Millisecond),
		},
		Limits: LimitPolicy{
			MaxConcurrent: 2, MaxPending: 4, MaxTrackedMiners: 4096,
			ChallengeTimeoutMillis:     int64((3 * time.Minute) / time.Millisecond),
			RetainedTerminalChallenges: 256,
		},
		Coverage: CoveragePolicy{
			WindowMillis:              int64((24 * time.Hour) / time.Millisecond),
			MinimumChallengesPerMiner: 3,
		},
		RequiredReplicas: 3,
		Workloads: []WorkloadPolicy{
			{Kind: "static", PayloadBytes: 10 << 20, Weight: 8},
			{Kind: "node", PayloadBytes: 100 << 20, Weight: 4},
			{Kind: "python", PayloadBytes: 300 << 20, Weight: 2},
			{Kind: "heavy", PayloadBytes: 1 << 30, Weight: 1},
		},
	}
}

func ValidateConfig(config Config) error {
	if config.Version != ConfigVersion {
		return invalidConfig("unsupported version")
	}
	if !validDNSLabel(config.CampaignID) {
		return invalidConfig("campaign ID must be a lowercase DNS label")
	}
	if config.Network != MainnetNetwork || config.NetUID != MainnetNetUID || config.Domain != MainnetDomain {
		return invalidConfig("campaign is restricted to the fixed mainnet network, netuid, and wildcard domain")
	}
	if !validSlug(config.DeploymentPrefix, 8) {
		return invalidConfig("deployment prefix must be a short lowercase DNS fragment")
	}
	// prefix + '-' + 16 hex sequence + '-' + 32 hex entropy
	if len(config.DeploymentPrefix)+1+16+1+32 > 63 {
		return invalidConfig("deployment prefix cannot produce a valid DNS label")
	}
	if config.Cadence.MinimumDelayMillis < 1_000 ||
		config.Cadence.MaximumDelayMillis < config.Cadence.MinimumDelayMillis ||
		config.Cadence.MaximumDelayMillis > int64((24*time.Hour)/time.Millisecond) {
		return invalidConfig("cadence must be bounded between one second and one day")
	}
	if config.Limits.MaxConcurrent < 1 || config.Limits.MaxConcurrent > 64 ||
		config.Limits.MaxPending < 1 || config.Limits.MaxPending > 256 ||
		config.Limits.MaxTrackedMiners < config.RequiredReplicas || config.Limits.MaxTrackedMiners > 4096 {
		return invalidConfig("concurrency, pending, or miner tracking bounds are invalid")
	}
	if config.Limits.ChallengeTimeoutMillis < 1_000 ||
		config.Limits.ChallengeTimeoutMillis > int64(time.Hour/time.Millisecond) {
		return invalidConfig("challenge timeout must be bounded between one second and one hour")
	}
	minimumRetention := config.Limits.MaxConcurrent + config.Limits.MaxPending
	if config.Limits.RetainedTerminalChallenges < minimumRetention || config.Limits.RetainedTerminalChallenges > 1024 {
		return invalidConfig("terminal history bound is invalid")
	}
	if config.Coverage.WindowMillis != int64((24*time.Hour)/time.Millisecond) ||
		config.Coverage.MinimumChallengesPerMiner < 3 || config.Coverage.MinimumChallengesPerMiner > 100_000 {
		return invalidConfig("coverage must guarantee at least three targets in exactly 24 hours")
	}
	if config.RequiredReplicas != 3 {
		return invalidConfig("mainnet campaign requires exactly three accepted replicas")
	}
	if len(config.Workloads) < 1 || len(config.Workloads) > 32 {
		return invalidConfig("workload mix must contain a bounded number of entries")
	}
	seenKinds := make(map[string]struct{}, len(config.Workloads))
	var totalWeight uint64
	for _, policy := range config.Workloads {
		if !validSlug(policy.Kind, 32) || policy.PayloadBytes < minimumPayloadBytes || policy.PayloadBytes > maximumPayloadBytes || policy.Weight == 0 {
			return invalidConfig("workload mix contains an invalid kind, size, or weight")
		}
		if _, duplicate := seenKinds[policy.Kind]; duplicate {
			return invalidConfig("workload kinds must be unique")
		}
		seenKinds[policy.Kind] = struct{}{}
		totalWeight += uint64(policy.Weight)
		if totalWeight > 1_000_000 {
			return invalidConfig("workload weight total is too large")
		}
	}
	return nil
}

func ConfigDigest(config Config) (string, error) {
	if err := ValidateConfig(config); err != nil {
		return "", err
	}
	payload, err := json.Marshal(config)
	if err != nil {
		return "", invalidConfig("configuration cannot be encoded")
	}
	return digestHex(payload), nil
}

type Mode string

const (
	ModeDisabled     Mode = "disabled"
	ModeRunning      Mode = "running"
	ModePaused       Mode = "paused"
	ModeDraining     Mode = "draining"
	ModeShuttingDown Mode = "shutting_down"
	ModeStopped      Mode = "stopped"
)

type ChallengeStatus string

const (
	StatusPending   ChallengeStatus = "pending"
	StatusRunning   ChallengeStatus = "running"
	StatusSucceeded ChallengeStatus = "succeeded"
	StatusFailed    ChallengeStatus = "failed"
	StatusCancelled ChallengeStatus = "cancelled"
)

type Outcome string

const (
	OutcomeSucceeded Outcome = "succeeded"
	OutcomeFailed    Outcome = "failed"
	OutcomeCancelled Outcome = "cancelled"
)

// FailureCode is deliberately closed and credential-free. Raw provider,
// transport, RPC, storage, or subprocess errors do not belong in campaign
// state or evidence.
type FailureCode string

const (
	FailureNone             FailureCode = ""
	FailureCapacity         FailureCode = "capacity"
	FailureDeadline         FailureCode = "deadline"
	FailureArtifact         FailureCode = "artifact"
	FailureAssignment       FailureCode = "assignment"
	FailureReceipt          FailureCode = "receipt"
	FailureChallenge        FailureCode = "challenge"
	FailureRouting          FailureCode = "routing"
	FailureCancelled        FailureCode = "cancelled"
	FailureOperatorDrain    FailureCode = "operator_drain"
	FailureOperatorShutdown FailureCode = "operator_shutdown"
	FailureInternal         FailureCode = "internal"
)

type State struct {
	Version            string          `json:"version"`
	CampaignID         string          `json:"campaign_id"`
	ConfigDigestSHA256 string          `json:"config_digest_sha256"`
	Mode               Mode            `json:"mode"`
	NextSequence       uint64          `json:"next_sequence"`
	WindowStartedAt    time.Time       `json:"window_started_at"`
	NextDueAt          *time.Time      `json:"next_due_at,omitempty"`
	Challenges         []Challenge     `json:"challenges"`
	Coverage           []MinerCoverage `json:"coverage"`
	UpdatedAt          time.Time       `json:"updated_at"`
	StateDigestSHA256  string          `json:"state_digest_sha256,omitempty"`
}

type Challenge struct {
	Version                 string              `json:"version"`
	Sequence                uint64              `json:"sequence"`
	DeploymentID            string              `json:"deployment_id"`
	RouteHost               string              `json:"route_host"`
	CoverageTargetMiner     string              `json:"coverage_target_miner"`
	CoverageWindowStartedAt time.Time           `json:"coverage_window_started_at"`
	CoverageTargetOrdinal   uint64              `json:"coverage_target_ordinal"`
	CoverageTargetRequired  bool                `json:"coverage_target_required"`
	Workload                workload.Spec       `json:"workload"`
	WorkloadSpecDigest      string              `json:"workload_spec_digest_sha256"`
	ChallengeSHA256         string              `json:"challenge_sha256"`
	Status                  ChallengeStatus     `json:"status"`
	ScheduledAt             time.Time           `json:"scheduled_at"`
	StartedAt               *time.Time          `json:"started_at,omitempty"`
	DeadlineAt              *time.Time          `json:"deadline_at,omitempty"`
	CompletedAt             *time.Time          `json:"completed_at,omitempty"`
	FailureCode             FailureCode         `json:"failure_code,omitempty"`
	Assignments             []AssignmentBinding `json:"accepted_assignments"`
}

// AssignmentBinding is the credential-safe projection of an already accepted
// deployment.v3 ticket. It binds campaign identity to the existing scheduler's
// generation, assignment nonce, replica, endpoint, manifest, and challenge.
type AssignmentBinding struct {
	TicketVersion   string    `json:"ticket_version"`
	DeploymentID    string    `json:"deployment_id"`
	BuildID         string    `json:"build_id"`
	ChallengePath   string    `json:"challenge_path"`
	ChallengeSHA256 string    `json:"challenge_sha256"`
	MinerHotkey     string    `json:"miner_hotkey"`
	MinerUID        *uint16   `json:"miner_uid,omitempty"`
	Generation      uint64    `json:"generation"`
	AssignmentNonce string    `json:"assignment_nonce"`
	ReplicaID       string    `json:"replica_id"`
	EndpointID      string    `json:"endpoint_id"`
	ImageDigest     string    `json:"image_digest"`
	ManifestKey     string    `json:"manifest_key"`
	AcceptedAt      time.Time `json:"accepted_at"`
}

type MinerCoverage struct {
	MinerHotkey           string     `json:"miner_hotkey"`
	WindowScheduled       uint64     `json:"window_scheduled"`
	LifetimeScheduled     uint64     `json:"lifetime_scheduled"`
	LifetimeCompleted     uint64     `json:"lifetime_completed"`
	LifetimeSucceeded     uint64     `json:"lifetime_succeeded"`
	LifetimeFailed        uint64     `json:"lifetime_failed"`
	Outstanding           uint64     `json:"outstanding"`
	LastScheduledSequence uint64     `json:"last_scheduled_sequence"`
	LastScheduledAt       *time.Time `json:"last_scheduled_at,omitempty"`
}

// Evidence excludes the raw hidden challenge, full subnet binding, service
// keys, TLS material, provider details, storage errors, and wallet/RPC data.
// It is not a direct score input: the central scorer additionally requires a
// complete finalized window that binds this digest to expected assignments and
// exact three-replica observations.
type Evidence struct {
	Version                     string              `json:"version"`
	CampaignID                  string              `json:"campaign_id"`
	Network                     string              `json:"network"`
	NetUID                      uint16              `json:"netuid"`
	ConfigDigestSHA256          string              `json:"config_digest_sha256"`
	StateDigestSHA256           string              `json:"state_digest_sha256"`
	Sequence                    uint64              `json:"sequence"`
	DeploymentID                string              `json:"deployment_id"`
	RouteHost                   string              `json:"route_host"`
	CoverageTargetMiner         string              `json:"coverage_target_miner"`
	CoverageWindowStartedAt     time.Time           `json:"coverage_window_started_at"`
	CoverageTargetOrdinal       uint64              `json:"coverage_target_ordinal"`
	CoverageTargetRequired      bool                `json:"coverage_target_required"`
	WorkloadKind                string              `json:"workload_kind"`
	PayloadBytes                int                 `json:"payload_bytes"`
	BuildID                     string              `json:"build_id"`
	ChallengePath               string              `json:"challenge_path"`
	ChallengeSHA256             string              `json:"challenge_sha256"`
	WorkloadSpecDigest          string              `json:"workload_spec_digest_sha256"`
	ScheduledAt                 time.Time           `json:"scheduled_at"`
	StartedAt                   *time.Time          `json:"started_at,omitempty"`
	CompletedAt                 time.Time           `json:"completed_at"`
	Outcome                     Outcome             `json:"outcome"`
	FailureCode                 FailureCode         `json:"failure_code,omitempty"`
	AcceptedAssignments         []AssignmentBinding `json:"accepted_assignments"`
	ScoringEffect               string              `json:"scoring_effect"`
	AcceptanceObservationSource string              `json:"acceptance_observation_source"`
	EvidenceDigestSHA256        string              `json:"evidence_digest_sha256,omitempty"`
}

func SealState(config Config, state State) (State, error) {
	candidate := cloneState(state)
	candidate.StateDigestSHA256 = ""
	payload, err := stateDigestPayload(config, candidate)
	if err != nil {
		return State{}, err
	}
	candidate.StateDigestSHA256 = digestHex(payload)
	return candidate, nil
}

func VerifyState(config Config, state State) error {
	if !validLowerHex(state.StateDigestSHA256, sha256.Size) {
		return ErrStateDigestMismatch
	}
	candidate := cloneState(state)
	claimed := candidate.StateDigestSHA256
	candidate.StateDigestSHA256 = ""
	payload, err := json.Marshal(candidate)
	if err != nil {
		return ErrStateDigestMismatch
	}
	expected := digestHex(payload)
	if subtle.ConstantTimeCompare([]byte(claimed), []byte(expected)) != 1 {
		return ErrStateDigestMismatch
	}
	return validateState(config, candidate, false)
}

func MarshalState(config Config, state State) ([]byte, error) {
	if err := VerifyState(config, state); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return nil, ErrInvalidStateBytes
	}
	return append(payload, '\n'), nil
}

// ParseState accepts only the exact canonical bytes emitted by MarshalState.
// This rejects duplicate keys, alternate field order, unknown fields,
// trailing values, and digest-preserving whitespace variations.
func ParseState(config Config, payload []byte) (State, error) {
	if len(payload) == 0 || len(payload) > maximumStateBytes {
		return State{}, ErrInvalidStateBytes
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var state State
	if err := decoder.Decode(&state); err != nil {
		return State{}, ErrInvalidStateBytes
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return State{}, ErrInvalidStateBytes
	}
	if err := VerifyState(config, state); err != nil {
		return State{}, err
	}
	canonical, err := MarshalState(config, state)
	if err != nil || !bytes.Equal(payload, canonical) {
		return State{}, ErrInvalidStateBytes
	}
	return state, nil
}

func SealEvidence(evidence Evidence) (Evidence, error) {
	candidate := cloneEvidence(evidence)
	candidate.EvidenceDigestSHA256 = ""
	if err := validateEvidence(candidate, false); err != nil {
		return Evidence{}, err
	}
	payload, err := json.Marshal(candidate)
	if err != nil {
		return Evidence{}, ErrInvalidEvidence
	}
	candidate.EvidenceDigestSHA256 = digestHex(payload)
	return candidate, nil
}

func VerifyEvidence(evidence Evidence) error {
	if !validLowerHex(evidence.EvidenceDigestSHA256, sha256.Size) {
		return ErrInvalidEvidence
	}
	candidate := cloneEvidence(evidence)
	claimed := candidate.EvidenceDigestSHA256
	candidate.EvidenceDigestSHA256 = ""
	payload, err := json.Marshal(candidate)
	if err != nil {
		return ErrInvalidEvidence
	}
	if subtle.ConstantTimeCompare([]byte(claimed), []byte(digestHex(payload))) != 1 {
		return ErrInvalidEvidence
	}
	return validateEvidence(candidate, false)
}

func MarshalEvidence(evidence Evidence) ([]byte, error) {
	if err := VerifyEvidence(evidence); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(evidence)
	if err != nil {
		return nil, ErrInvalidEvidence
	}
	return append(payload, '\n'), nil
}

// ParseEvidence accepts only the canonical bytes emitted by MarshalEvidence.
func ParseEvidence(payload []byte) (Evidence, error) {
	if len(payload) == 0 || len(payload) > maximumEvidenceBytes {
		return Evidence{}, ErrInvalidEvidence
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var evidence Evidence
	if err := decoder.Decode(&evidence); err != nil {
		return Evidence{}, ErrInvalidEvidence
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Evidence{}, ErrInvalidEvidence
	}
	if err := VerifyEvidence(evidence); err != nil {
		return Evidence{}, err
	}
	canonical, err := MarshalEvidence(evidence)
	if err != nil || !bytes.Equal(payload, canonical) {
		return Evidence{}, ErrInvalidEvidence
	}
	return evidence, nil
}

func stateDigestPayload(config Config, state State) ([]byte, error) {
	if err := validateState(config, state, false); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return nil, invalidState("state cannot be encoded")
	}
	return payload, nil
}

func validateState(config Config, state State, requireDigest bool) error {
	if err := ValidateConfig(config); err != nil {
		return err
	}
	configDigest, err := ConfigDigest(config)
	if err != nil {
		return err
	}
	if state.Version != StateVersion || state.CampaignID != config.CampaignID || state.ConfigDigestSHA256 != configDigest {
		return invalidState("state identity does not match its configuration")
	}
	if state.Challenges == nil || state.Coverage == nil {
		return invalidState("state collections must use canonical arrays")
	}
	if requireDigest && !validLowerHex(state.StateDigestSHA256, sha256.Size) {
		return invalidState("state digest is invalid")
	}
	if state.NextSequence == 0 || !canonicalTime(state.WindowStartedAt) || !canonicalTime(state.UpdatedAt) || state.UpdatedAt.Before(state.WindowStartedAt) {
		return invalidState("state sequence or timestamps are invalid")
	}
	if state.NextDueAt != nil && (!canonicalTime(*state.NextDueAt) || state.NextDueAt.Before(state.WindowStartedAt)) {
		return invalidState("next due timestamp is invalid")
	}
	if !config.Enabled {
		if state.Mode != ModeDisabled || state.NextDueAt != nil || state.NextSequence != 1 || len(state.Challenges) != 0 || len(state.Coverage) != 0 {
			return invalidState("disabled configuration must remain inert")
		}
	} else if state.Mode == ModeDisabled {
		return invalidState("enabled configuration cannot restore a disabled state")
	}
	switch state.Mode {
	case ModeDisabled, ModeDraining, ModeShuttingDown, ModeStopped:
		if state.NextDueAt != nil {
			return invalidState("non-scheduling mode cannot carry a next due timestamp")
		}
	case ModeRunning:
		if state.NextDueAt == nil {
			return invalidState("running state requires a next due timestamp")
		}
	case ModePaused:
	default:
		return invalidState("mode is invalid")
	}

	terminalCount := 0
	pendingCount := 0
	runningCount := 0
	outstanding := make(map[string]uint64)
	seenDeployments := make(map[string]struct{}, len(state.Challenges))
	seenBuilds := make(map[string]struct{}, len(state.Challenges))
	seenChallenges := make(map[string]struct{}, len(state.Challenges))
	seenAssignmentNonces := make(map[string]struct{})
	var priorSequence uint64
	for index := range state.Challenges {
		challenge := &state.Challenges[index]
		if challenge.Sequence <= priorSequence || challenge.Sequence >= state.NextSequence {
			return invalidState("challenge sequences are not strictly ordered below the high-water mark")
		}
		priorSequence = challenge.Sequence
		if err := validateChallenge(config, *challenge, state.UpdatedAt); err != nil {
			return err
		}
		if _, exists := seenDeployments[challenge.DeploymentID]; exists {
			return invalidState("deployment identities are not unique")
		}
		if _, exists := seenBuilds[challenge.Workload.BuildID]; exists {
			return invalidState("build identities are not unique")
		}
		if _, exists := seenChallenges[challenge.ChallengeSHA256]; exists {
			return invalidState("hidden challenges are not unique")
		}
		seenDeployments[challenge.DeploymentID] = struct{}{}
		seenBuilds[challenge.Workload.BuildID] = struct{}{}
		seenChallenges[challenge.ChallengeSHA256] = struct{}{}
		for _, binding := range challenge.Assignments {
			if _, exists := seenAssignmentNonces[binding.AssignmentNonce]; exists {
				return invalidState("accepted assignment nonce was reused across campaign challenges")
			}
			seenAssignmentNonces[binding.AssignmentNonce] = struct{}{}
		}
		switch challenge.Status {
		case StatusPending:
			pendingCount++
			outstanding[challenge.CoverageTargetMiner]++
		case StatusRunning:
			runningCount++
			outstanding[challenge.CoverageTargetMiner]++
		default:
			terminalCount++
		}
	}
	if terminalCount > config.Limits.RetainedTerminalChallenges || pendingCount > config.Limits.MaxPending || runningCount > config.Limits.MaxConcurrent {
		return invalidState("challenge history or backpressure bounds are exceeded")
	}
	if (state.Mode == ModeDraining || state.Mode == ModeShuttingDown) && runningCount == 0 {
		return invalidState("transitional mode must have work still in flight")
	}
	if state.Mode == ModeStopped && (pendingCount != 0 || runningCount != 0) {
		return invalidState("stopped state cannot retain nonterminal work")
	}
	if len(state.Coverage) > config.Limits.MaxTrackedMiners {
		return invalidState("miner coverage state exceeds its bound")
	}
	coverageSeen := make(map[string]struct{}, len(state.Coverage))
	priorMiner := ""
	for index := range state.Coverage {
		coverage := &state.Coverage[index]
		if !validHotkey(coverage.MinerHotkey) || (index > 0 && coverage.MinerHotkey <= priorMiner) {
			return invalidState("miner coverage identities are invalid or unordered")
		}
		priorMiner = coverage.MinerHotkey
		if coverage.LifetimeCompleted > coverage.LifetimeScheduled || coverage.LifetimeSucceeded > coverage.LifetimeCompleted ||
			coverage.LifetimeFailed != coverage.LifetimeCompleted-coverage.LifetimeSucceeded ||
			coverage.Outstanding != coverage.LifetimeScheduled-coverage.LifetimeCompleted ||
			coverage.WindowScheduled > coverage.LifetimeScheduled || coverage.Outstanding != outstanding[coverage.MinerHotkey] {
			return invalidState("miner coverage counters are inconsistent")
		}
		if coverage.LifetimeScheduled == 0 {
			if coverage.LastScheduledSequence != 0 || coverage.LastScheduledAt != nil {
				return invalidState("unused miner coverage has scheduling history")
			}
		} else if coverage.LastScheduledSequence == 0 || coverage.LastScheduledSequence >= state.NextSequence || coverage.LastScheduledAt == nil ||
			!canonicalTime(*coverage.LastScheduledAt) || coverage.LastScheduledAt.After(state.UpdatedAt) {
			return invalidState("miner coverage scheduling history is invalid")
		}
		coverageSeen[coverage.MinerHotkey] = struct{}{}
	}
	for miner := range outstanding {
		if _, exists := coverageSeen[miner]; !exists {
			return invalidState("challenge target is missing coverage state")
		}
	}
	return nil
}

func validateChallenge(config Config, challenge Challenge, updatedAt time.Time) error {
	if challenge.Version != ChallengeVersion || challenge.Sequence == 0 || !validHotkey(challenge.CoverageTargetMiner) {
		return invalidState("challenge identity is invalid")
	}
	if challenge.DeploymentID != expectedDeploymentID(config, challenge.Sequence, challenge.DeploymentID) ||
		challenge.RouteHost != challenge.DeploymentID+"."+config.Domain {
		return invalidState("challenge deployment DNS identity is invalid")
	}
	if !canonicalTime(challenge.CoverageWindowStartedAt) || !canonicalTime(challenge.ScheduledAt) ||
		challenge.ScheduledAt.Before(challenge.CoverageWindowStartedAt) || challenge.ScheduledAt.After(updatedAt) ||
		challenge.CoverageTargetOrdinal == 0 ||
		challenge.CoverageTargetRequired != (challenge.CoverageTargetOrdinal <= config.Coverage.MinimumChallengesPerMiner) {
		return invalidState("challenge coverage identity is invalid")
	}
	windowEnd := challenge.CoverageWindowStartedAt.Add(time.Duration(config.Coverage.WindowMillis) * time.Millisecond)
	if !challenge.ScheduledAt.Before(windowEnd) {
		return invalidState("challenge lies outside its coverage window")
	}
	if !validLowerHex(challenge.Workload.BuildID, 12) ||
		challenge.Workload.ChallengePath != "/__challenge/"+challenge.Workload.BuildID ||
		!validLowerHex(challenge.Workload.ChallengeValue, 32) ||
		challenge.ChallengeSHA256 != challengeValueDigest(challenge.Workload.ChallengeValue) ||
		!validLowerHex(challenge.WorkloadSpecDigest, sha256.Size) {
		return invalidState("workload build or challenge binding is invalid")
	}
	matchedPolicy := false
	for _, policy := range config.Workloads {
		if policy.Kind == challenge.Workload.Kind && policy.PayloadBytes == challenge.Workload.PayloadBytes {
			matchedPolicy = true
			break
		}
	}
	if !matchedPolicy {
		return invalidState("challenge workload is outside the configured mix")
	}
	specDigest, err := workloadSpecDigest(challenge.Workload)
	if err != nil || challenge.WorkloadSpecDigest != specDigest {
		return invalidState("workload specification digest is invalid")
	}
	if len(challenge.Assignments) > config.RequiredReplicas {
		return invalidState("accepted assignment count exceeds exact replica bound")
	}
	if challenge.Assignments == nil {
		return invalidState("accepted assignments must use a canonical array")
	}
	seenMiners := make(map[string]struct{}, len(challenge.Assignments))
	seenNonces := make(map[string]struct{}, len(challenge.Assignments))
	targetAccepted := false
	priorKey := ""
	artifactImageDigest := ""
	artifactManifestKey := ""
	for index, binding := range challenge.Assignments {
		if err := validateAssignment(challenge, binding); err != nil {
			return err
		}
		if binding.AcceptedAt.After(updatedAt) {
			return invalidState("accepted assignment timestamp follows state update")
		}
		key := assignmentSortKey(binding)
		if index > 0 && key <= priorKey {
			return invalidState("accepted assignments are not canonically ordered")
		}
		priorKey = key
		if _, exists := seenMiners[binding.MinerHotkey]; exists {
			return invalidState("accepted assignment miner identities are not unique")
		}
		if _, exists := seenNonces[binding.AssignmentNonce]; exists {
			return invalidState("accepted assignment nonces are not unique")
		}
		seenMiners[binding.MinerHotkey] = struct{}{}
		seenNonces[binding.AssignmentNonce] = struct{}{}
		if index == 0 {
			artifactImageDigest = binding.ImageDigest
			artifactManifestKey = binding.ManifestKey
		} else if binding.ImageDigest != artifactImageDigest || binding.ManifestKey != artifactManifestKey {
			return invalidState("accepted assignments do not share one artifact identity")
		}
		targetAccepted = targetAccepted || binding.MinerHotkey == challenge.CoverageTargetMiner
	}

	switch challenge.Status {
	case StatusPending:
		if challenge.StartedAt != nil || challenge.DeadlineAt != nil || challenge.CompletedAt != nil || challenge.FailureCode != FailureNone || len(challenge.Assignments) != 0 {
			return invalidState("pending challenge carries runtime state")
		}
	case StatusRunning:
		if !validRunningTimes(challenge) || challenge.CompletedAt != nil || challenge.FailureCode != FailureNone {
			return invalidState("running challenge timestamps or failure state are invalid")
		}
	case StatusSucceeded:
		if !validTerminalTimes(challenge) || challenge.FailureCode != FailureNone ||
			!challenge.CompletedAt.Before(*challenge.DeadlineAt) || len(challenge.Assignments) != config.RequiredReplicas || !targetAccepted {
			return invalidState("successful challenge lacks timely target and replica evidence")
		}
	case StatusFailed:
		if !validTerminalTimes(challenge) || !validFailureCode(challenge.FailureCode) ||
			challenge.FailureCode == FailureOperatorDrain || challenge.FailureCode == FailureOperatorShutdown ||
			(challenge.FailureCode == FailureDeadline && challenge.CompletedAt.Before(*challenge.DeadlineAt)) {
			return invalidState("failed challenge terminal contract is invalid")
		}
	case StatusCancelled:
		if challenge.StartedAt != nil || challenge.DeadlineAt != nil || challenge.CompletedAt == nil ||
			!canonicalTime(*challenge.CompletedAt) || challenge.CompletedAt.Before(challenge.ScheduledAt) || challenge.CompletedAt.After(updatedAt) ||
			(challenge.FailureCode != FailureCancelled && challenge.FailureCode != FailureOperatorDrain && challenge.FailureCode != FailureOperatorShutdown) || len(challenge.Assignments) != 0 {
			return invalidState("cancelled challenge terminal contract is invalid")
		}
	default:
		return invalidState("challenge status is invalid")
	}
	if challenge.StartedAt != nil && challenge.StartedAt.After(updatedAt) {
		return invalidState("challenge start timestamp follows state update")
	}
	if challenge.CompletedAt != nil && challenge.CompletedAt.After(updatedAt) {
		return invalidState("challenge completion timestamp follows state update")
	}
	return nil
}

func validateAssignment(challenge Challenge, binding AssignmentBinding) error {
	if binding.TicketVersion != AssignmentTicketVersion || binding.DeploymentID != challenge.DeploymentID ||
		binding.BuildID != challenge.Workload.BuildID || binding.ChallengePath != challenge.Workload.ChallengePath ||
		binding.ChallengeSHA256 != challenge.ChallengeSHA256 || !validHotkey(binding.MinerHotkey) ||
		binding.Generation == 0 || !validLowerHex(binding.AssignmentNonce, 16) ||
		!validImageDigest(binding.ImageDigest) || binding.ManifestKey != manifestKey(binding.ImageDigest) ||
		!canonicalTime(binding.AcceptedAt) || challenge.StartedAt == nil || binding.AcceptedAt.Before(*challenge.StartedAt) {
		return invalidState("accepted assignment does not match its campaign challenge")
	}
	if challenge.CompletedAt != nil && binding.AcceptedAt.After(*challenge.CompletedAt) {
		return invalidState("accepted assignment follows challenge completion")
	}
	identity := protocol.Ticket{
		DeploymentID: binding.DeploymentID, MinerID: binding.MinerHotkey,
		Generation: binding.Generation, AssignmentNonce: binding.AssignmentNonce,
	}
	expectedReplica := protocol.ReplicaID(identity)
	expectedEndpoint := protocol.EndpointID(identity)
	if binding.ReplicaID != expectedReplica || binding.EndpointID != expectedEndpoint {
		return invalidState("accepted assignment endpoint identity is invalid")
	}
	return nil
}

func validateEvidence(evidence Evidence, requireDigest bool) error {
	if evidence.Version != EvidenceVersion || !validDNSLabel(evidence.CampaignID) ||
		evidence.Network != MainnetNetwork || evidence.NetUID != MainnetNetUID ||
		!validLowerHex(evidence.ConfigDigestSHA256, sha256.Size) || !validLowerHex(evidence.StateDigestSHA256, sha256.Size) ||
		evidence.Sequence == 0 || !validDNSLabel(evidence.DeploymentID) || evidence.RouteHost != evidence.DeploymentID+"."+MainnetDomain ||
		!validHotkey(evidence.CoverageTargetMiner) || evidence.CoverageTargetOrdinal == 0 ||
		!validSlug(evidence.WorkloadKind, 32) || evidence.PayloadBytes < minimumPayloadBytes || evidence.PayloadBytes > maximumPayloadBytes ||
		!validLowerHex(evidence.BuildID, 12) || evidence.ChallengePath != "/__challenge/"+evidence.BuildID ||
		!validLowerHex(evidence.ChallengeSHA256, sha256.Size) || !validLowerHex(evidence.WorkloadSpecDigest, sha256.Size) ||
		!canonicalTime(evidence.CoverageWindowStartedAt) || !canonicalTime(evidence.ScheduledAt) || !canonicalTime(evidence.CompletedAt) ||
		evidence.CompletedAt.Before(evidence.ScheduledAt) || evidence.ScoringEffect != ScoringEffectNone ||
		evidence.AcceptanceObservationSource != ScoringSourceExisting || evidence.AcceptedAssignments == nil || len(evidence.AcceptedAssignments) > 3 {
		return ErrInvalidEvidence
	}
	if requireDigest && !validLowerHex(evidence.EvidenceDigestSHA256, sha256.Size) {
		return ErrInvalidEvidence
	}
	switch evidence.Outcome {
	case OutcomeSucceeded:
		if evidence.StartedAt == nil || evidence.FailureCode != FailureNone || len(evidence.AcceptedAssignments) != 3 {
			return ErrInvalidEvidence
		}
	case OutcomeFailed:
		if evidence.StartedAt == nil || !validFailureCode(evidence.FailureCode) {
			return ErrInvalidEvidence
		}
	case OutcomeCancelled:
		if evidence.StartedAt != nil || (evidence.FailureCode != FailureCancelled && evidence.FailureCode != FailureOperatorDrain && evidence.FailureCode != FailureOperatorShutdown) {
			return ErrInvalidEvidence
		}
	default:
		return ErrInvalidEvidence
	}
	if evidence.StartedAt != nil && (!canonicalTime(*evidence.StartedAt) || evidence.StartedAt.Before(evidence.ScheduledAt) || evidence.CompletedAt.Before(*evidence.StartedAt)) {
		return ErrInvalidEvidence
	}
	priorKey := ""
	seenMiners := make(map[string]struct{}, len(evidence.AcceptedAssignments))
	seenNonces := make(map[string]struct{}, len(evidence.AcceptedAssignments))
	targetAccepted := false
	artifactImageDigest := ""
	artifactManifestKey := ""
	for index, binding := range evidence.AcceptedAssignments {
		projection := Challenge{
			DeploymentID:    evidence.DeploymentID,
			Workload:        workload.Spec{BuildID: evidence.BuildID, ChallengePath: evidence.ChallengePath},
			ChallengeSHA256: evidence.ChallengeSHA256, StartedAt: evidence.StartedAt,
			CompletedAt: timePointer(evidence.CompletedAt),
		}
		if err := validateAssignment(projection, binding); err != nil {
			return ErrInvalidEvidence
		}
		key := assignmentSortKey(binding)
		if index > 0 && key <= priorKey {
			return ErrInvalidEvidence
		}
		priorKey = key
		if _, exists := seenMiners[binding.MinerHotkey]; exists {
			return ErrInvalidEvidence
		}
		if _, exists := seenNonces[binding.AssignmentNonce]; exists {
			return ErrInvalidEvidence
		}
		seenMiners[binding.MinerHotkey] = struct{}{}
		seenNonces[binding.AssignmentNonce] = struct{}{}
		if index == 0 {
			artifactImageDigest = binding.ImageDigest
			artifactManifestKey = binding.ManifestKey
		} else if binding.ImageDigest != artifactImageDigest || binding.ManifestKey != artifactManifestKey {
			return ErrInvalidEvidence
		}
		targetAccepted = targetAccepted || binding.MinerHotkey == evidence.CoverageTargetMiner
	}
	if evidence.Outcome == OutcomeSucceeded && !targetAccepted {
		return ErrInvalidEvidence
	}
	return nil
}

func validRunningTimes(challenge Challenge) bool {
	return challenge.StartedAt != nil && challenge.DeadlineAt != nil && canonicalTime(*challenge.StartedAt) && canonicalTime(*challenge.DeadlineAt) &&
		!challenge.StartedAt.Before(challenge.ScheduledAt) && challenge.DeadlineAt.After(*challenge.StartedAt)
}

func validTerminalTimes(challenge Challenge) bool {
	return validRunningTimes(challenge) && challenge.CompletedAt != nil && canonicalTime(*challenge.CompletedAt) &&
		!challenge.CompletedAt.Before(*challenge.StartedAt)
}

func validFailureCode(code FailureCode) bool {
	switch code {
	case FailureCapacity, FailureDeadline, FailureArtifact, FailureAssignment, FailureReceipt, FailureChallenge,
		FailureRouting, FailureCancelled, FailureOperatorDrain, FailureOperatorShutdown, FailureInternal:
		return true
	default:
		return false
	}
}

func invalidConfig(reason string) error { return fmt.Errorf("%w: %s", ErrInvalidConfig, reason) }
func invalidState(reason string) error  { return fmt.Errorf("%w: %s", ErrInvalidState, reason) }

func digestHex(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

func challengeValueDigest(value string) string { return digestHex([]byte(value)) }

func workloadSpecDigest(spec workload.Spec) (string, error) {
	payload, err := json.Marshal(spec)
	if err != nil {
		return "", err
	}
	return digestHex(payload), nil
}

func expectedDeploymentID(config Config, sequence uint64, actual string) string {
	prefix := fmt.Sprintf("%s-%016x-", config.DeploymentPrefix, sequence)
	if !strings.HasPrefix(actual, prefix) {
		return ""
	}
	suffix := strings.TrimPrefix(actual, prefix)
	if !validLowerHex(suffix, 16) {
		return ""
	}
	return prefix + suffix
}

func validImageDigest(value string) bool {
	return strings.HasPrefix(value, "sha256:") && validLowerHex(strings.TrimPrefix(value, "sha256:"), sha256.Size)
}

func manifestKey(imageDigest string) string {
	return artifact.ManifestKey(imageDigest)
}

func validLowerHex(value string, byteLength int) bool {
	if len(value) != byteLength*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == byteLength
}

func validDNSLabel(value string) bool {
	if len(value) < 1 || len(value) > 63 || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func validSlug(value string, maximum int) bool {
	return len(value) <= maximum && validDNSLabel(value)
}

func validHotkey(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func canonicalTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC
}

func assignmentSortKey(binding AssignmentBinding) string {
	return fmt.Sprintf("%020d\x00%s\x00%s", binding.Generation, binding.MinerHotkey, binding.AssignmentNonce)
}

func cloneState(state State) State {
	copyState := state
	copyState.NextDueAt = cloneTime(state.NextDueAt)
	if state.Challenges != nil {
		copyState.Challenges = make([]Challenge, len(state.Challenges))
		for index, challenge := range state.Challenges {
			copyState.Challenges[index] = cloneChallenge(challenge)
		}
	}
	if state.Coverage != nil {
		copyState.Coverage = make([]MinerCoverage, len(state.Coverage))
		for index, coverage := range state.Coverage {
			copyState.Coverage[index] = coverage
			copyState.Coverage[index].LastScheduledAt = cloneTime(coverage.LastScheduledAt)
		}
	}
	return copyState
}

func cloneChallenge(challenge Challenge) Challenge {
	copyChallenge := challenge
	copyChallenge.StartedAt = cloneTime(challenge.StartedAt)
	copyChallenge.DeadlineAt = cloneTime(challenge.DeadlineAt)
	copyChallenge.CompletedAt = cloneTime(challenge.CompletedAt)
	if challenge.Assignments != nil {
		copyChallenge.Assignments = make([]AssignmentBinding, len(challenge.Assignments))
		for index, binding := range challenge.Assignments {
			copyChallenge.Assignments[index] = cloneBinding(binding)
		}
	}
	return copyChallenge
}

func cloneBinding(binding AssignmentBinding) AssignmentBinding {
	copyBinding := binding
	if binding.MinerUID != nil {
		uid := *binding.MinerUID
		copyBinding.MinerUID = &uid
	}
	return copyBinding
}

func cloneEvidence(evidence Evidence) Evidence {
	copyEvidence := evidence
	copyEvidence.StartedAt = cloneTime(evidence.StartedAt)
	if evidence.AcceptedAssignments != nil {
		copyEvidence.AcceptedAssignments = make([]AssignmentBinding, len(evidence.AcceptedAssignments))
		for index, binding := range evidence.AcceptedAssignments {
			copyEvidence.AcceptedAssignments[index] = cloneBinding(binding)
		}
	}
	return copyEvidence
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copyValue := *value
	return &copyValue
}
