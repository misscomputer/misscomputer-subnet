// SPDX-License-Identifier: AGPL-3.0-only

// Package integration owns the explicitly activated, mainnet-only runtime
// boundary around the pure campaign state machine.
package integration

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/campaign"
)

const (
	RuntimeConfigVersion  = "synthetic-campaign-runtime.v1"
	ReadinessProofVersion = "synthetic-wildcard-readiness.v1"

	maximumConfigBytes = 1 << 20
	maximumProofBytes  = 64 << 10
)

var (
	ErrInvalidRuntimeConfig = errors.New("invalid campaign runtime config")
	ErrInvalidReadiness     = errors.New("invalid campaign wildcard readiness proof")
	ErrUnsafeFile           = errors.New("unsafe campaign control file")
)

type RuntimeConfig struct {
	Version            string          `json:"version"`
	Campaign           campaign.Config `json:"campaign"`
	TickIntervalMillis int64           `json:"tick_interval_ms"`
	Artifacts          ArtifactPolicy  `json:"artifacts"`
	Retry              RetryPolicy     `json:"retry"`
	RetainedEvidence   int             `json:"retained_evidence"`
}

type ArtifactPolicy struct {
	MaxSingleBytes       int64 `json:"max_single_bytes"`
	MaxRetainedBytes     int64 `json:"max_retained_bytes"`
	RetentionMillis      int64 `json:"retention_ms"`
	CleanupTimeoutMillis int64 `json:"cleanup_timeout_ms"`
}

type RetryPolicy struct {
	MaxAttempts          int   `json:"max_attempts"`
	InitialBackoffMillis int64 `json:"initial_backoff_ms"`
	MaximumBackoffMillis int64 `json:"maximum_backoff_ms"`
}

func DefaultRuntimeConfig() RuntimeConfig {
	return RuntimeConfig{
		Version: RuntimeConfigVersion, Campaign: campaign.DefaultConfig(), TickIntervalMillis: 1_000,
		Artifacts: ArtifactPolicy{
			MaxSingleBytes: 2 << 30, MaxRetainedBytes: 8 << 30,
			RetentionMillis:      int64(time.Hour / time.Millisecond),
			CleanupTimeoutMillis: int64((30 * time.Second) / time.Millisecond),
		},
		Retry: RetryPolicy{
			MaxAttempts: 5, InitialBackoffMillis: 1_000,
			MaximumBackoffMillis: int64(time.Minute / time.Millisecond),
		},
		RetainedEvidence: 1_024,
	}
}

func ValidateRuntimeConfig(config RuntimeConfig) error {
	if config.Version != RuntimeConfigVersion {
		return invalidRuntime("unsupported version")
	}
	if err := campaign.ValidateConfig(config.Campaign); err != nil {
		return fmt.Errorf("%w: campaign policy: %v", ErrInvalidRuntimeConfig, err)
	}
	if config.TickIntervalMillis < 100 || config.TickIntervalMillis > int64(time.Minute/time.Millisecond) ||
		config.TickIntervalMillis > config.Campaign.Cadence.MinimumDelayMillis {
		return invalidRuntime("tick interval is outside its bound")
	}
	if config.Artifacts.MaxSingleBytes < 1<<10 || config.Artifacts.MaxSingleBytes > 2<<30 ||
		config.Artifacts.MaxRetainedBytes < config.Artifacts.MaxSingleBytes || config.Artifacts.MaxRetainedBytes > 64<<30 {
		return invalidRuntime("artifact byte policy is outside its bound")
	}
	if config.Artifacts.RetentionMillis < 1_000 || config.Artifacts.RetentionMillis > int64((7*24*time.Hour)/time.Millisecond) ||
		config.Artifacts.CleanupTimeoutMillis < 1_000 || config.Artifacts.CleanupTimeoutMillis > int64((2*time.Minute)/time.Millisecond) {
		return invalidRuntime("artifact retention or cleanup timeout is outside its bound")
	}
	if config.Retry.MaxAttempts < 1 || config.Retry.MaxAttempts > 10 ||
		config.Retry.InitialBackoffMillis < 100 || config.Retry.InitialBackoffMillis > int64(time.Minute/time.Millisecond) ||
		config.Retry.MaximumBackoffMillis < config.Retry.InitialBackoffMillis || config.Retry.MaximumBackoffMillis > int64(time.Hour/time.Millisecond) {
		return invalidRuntime("retry policy is outside its bound")
	}
	if config.RetainedEvidence < config.Campaign.Limits.RetainedTerminalChallenges || config.RetainedEvidence > 100_000 {
		return invalidRuntime("evidence retention is outside its bound")
	}
	for _, workload := range config.Campaign.Workloads {
		if int64(workload.PayloadBytes) > config.Artifacts.MaxSingleBytes {
			return invalidRuntime("workload exceeds the single-artifact cost bound")
		}
	}
	return nil
}

func MarshalRuntimeConfig(config RuntimeConfig) ([]byte, error) {
	if err := ValidateRuntimeConfig(config); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(config)
	if err != nil {
		return nil, invalidRuntime("configuration cannot be encoded")
	}
	return append(payload, '\n'), nil
}

func RuntimeConfigDigest(config RuntimeConfig) (string, error) {
	payload, err := MarshalRuntimeConfig(config)
	if err != nil {
		return "", err
	}
	return sha256Hex(payload), nil
}

// LoadRuntimeConfig requires an explicitly named, canonical, regular control
// file. Merely setting unrelated local-workload flags never reaches this path.
func LoadRuntimeConfig(path string) (RuntimeConfig, string, error) {
	payload, err := readControlFile(path, maximumConfigBytes)
	if err != nil {
		return RuntimeConfig{}, "", err
	}
	var config RuntimeConfig
	if err := decodeExact(payload, &config); err != nil {
		return RuntimeConfig{}, "", invalidRuntime("configuration JSON is invalid")
	}
	canonical, err := MarshalRuntimeConfig(config)
	if err != nil {
		return RuntimeConfig{}, "", err
	}
	if !bytes.Equal(payload, canonical) {
		return RuntimeConfig{}, "", invalidRuntime("configuration bytes are not canonical")
	}
	digest, err := RuntimeConfigDigest(config)
	return config, digest, err
}

type WildcardReadinessProof struct {
	Version                   string    `json:"version"`
	Network                   string    `json:"network"`
	NetUID                    uint16    `json:"netuid"`
	Domain                    string    `json:"domain"`
	WildcardHost              string    `json:"wildcard_host"`
	DNSPreprovisioned         bool      `json:"dns_preprovisioned"`
	TunnelPreprovisioned      bool      `json:"tunnel_preprovisioned"`
	CertificatePreprovisioned bool      `json:"certificate_preprovisioned"`
	PublicProbeVerified       bool      `json:"public_probe_verified"`
	VerifiedAt                time.Time `json:"verified_at"`
	ExpiresAt                 time.Time `json:"expires_at"`
	ProofDigestSHA256         string    `json:"proof_digest_sha256,omitempty"`
}

type ActivationEnvironment struct {
	Network                     string
	NetUID                      uint16
	Domain                      string
	HostLabelPrefix             string
	EdgeRequiresManagedWildcard bool
	EdgeProbeURL                string
}

func SealReadinessProof(proof WildcardReadinessProof) (WildcardReadinessProof, error) {
	candidate := proof
	candidate.ProofDigestSHA256 = ""
	if err := validateReadiness(candidate, time.Time{}, false); err != nil {
		return WildcardReadinessProof{}, err
	}
	payload, err := json.Marshal(candidate)
	if err != nil {
		return WildcardReadinessProof{}, ErrInvalidReadiness
	}
	candidate.ProofDigestSHA256 = sha256Hex(payload)
	return candidate, nil
}

func MarshalReadinessProof(proof WildcardReadinessProof) ([]byte, error) {
	if err := verifyReadinessDigest(proof); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(proof)
	if err != nil {
		return nil, ErrInvalidReadiness
	}
	return append(payload, '\n'), nil
}

func ParseReadinessProof(payload []byte, now time.Time) (WildcardReadinessProof, error) {
	if len(payload) == 0 || len(payload) > maximumProofBytes {
		return WildcardReadinessProof{}, ErrInvalidReadiness
	}
	var proof WildcardReadinessProof
	if err := decodeExact(payload, &proof); err != nil {
		return WildcardReadinessProof{}, ErrInvalidReadiness
	}
	if err := verifyReadinessDigest(proof); err != nil {
		return WildcardReadinessProof{}, err
	}
	if err := validateReadiness(proof, now, true); err != nil {
		return WildcardReadinessProof{}, err
	}
	canonical, err := MarshalReadinessProof(proof)
	if err != nil || !bytes.Equal(payload, canonical) {
		return WildcardReadinessProof{}, ErrInvalidReadiness
	}
	return proof, nil
}

func LoadReadinessProof(path string, now time.Time) (WildcardReadinessProof, error) {
	payload, err := readControlFile(path, maximumProofBytes)
	if err != nil {
		return WildcardReadinessProof{}, err
	}
	return ParseReadinessProof(payload, now)
}

// ValidateActivation is the final fail-closed mainnet/wildcard gate. It only
// consumes pre-existing readiness evidence and never probes or mutates DNS,
// edge-provider, tunnel, certificate, storage, chain, wallet, or RPC state.
func ValidateActivation(config RuntimeConfig, environment ActivationEnvironment, proof WildcardReadinessProof, now time.Time) error {
	if err := ValidateRuntimeConfig(config); err != nil {
		return err
	}
	if !config.Campaign.Enabled {
		return invalidRuntime("campaign policy is disabled")
	}
	if environment.Network != campaign.MainnetNetwork || environment.NetUID != campaign.MainnetNetUID ||
		environment.Domain != campaign.MainnetDomain || environment.HostLabelPrefix != "" ||
		!environment.EdgeRequiresManagedWildcard || environment.EdgeProbeURL != "https://{host}" {
		return invalidRuntime("control service is not on the exact proven mainnet wildcard path")
	}
	if err := validateReadiness(proof, now, true); err != nil {
		return err
	}
	if err := verifyReadinessDigest(proof); err != nil {
		return err
	}
	return nil
}

func verifyReadinessDigest(proof WildcardReadinessProof) error {
	if !validSHA256(proof.ProofDigestSHA256) {
		return ErrInvalidReadiness
	}
	candidate := proof
	claimed := candidate.ProofDigestSHA256
	candidate.ProofDigestSHA256 = ""
	payload, err := json.Marshal(candidate)
	if err != nil {
		return ErrInvalidReadiness
	}
	if subtle.ConstantTimeCompare([]byte(claimed), []byte(sha256Hex(payload))) != 1 {
		return ErrInvalidReadiness
	}
	return nil
}

func validateReadiness(proof WildcardReadinessProof, now time.Time, checkFreshness bool) error {
	if proof.Version != ReadinessProofVersion || proof.Network != campaign.MainnetNetwork ||
		proof.NetUID != campaign.MainnetNetUID || proof.Domain != campaign.MainnetDomain ||
		proof.WildcardHost != "*."+campaign.MainnetDomain || !proof.DNSPreprovisioned ||
		!proof.TunnelPreprovisioned || !proof.CertificatePreprovisioned || !proof.PublicProbeVerified ||
		!canonicalTime(proof.VerifiedAt) || !canonicalTime(proof.ExpiresAt) || !proof.ExpiresAt.After(proof.VerifiedAt) ||
		proof.ExpiresAt.Sub(proof.VerifiedAt) > 24*time.Hour {
		return ErrInvalidReadiness
	}
	if checkFreshness {
		canonicalNow := now.UTC()
		if now.IsZero() || canonicalNow.Before(proof.VerifiedAt) || !canonicalNow.Before(proof.ExpiresAt) ||
			canonicalNow.Sub(proof.VerifiedAt) > 24*time.Hour {
			return ErrInvalidReadiness
		}
	}
	return nil
}

func readControlFile(path string, maximum int64) ([]byte, error) {
	if path == "" || maximum < 1 {
		return nil, ErrUnsafeFile
	}
	if err := rejectSymlinkComponents(path); err != nil {
		return nil, err
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm()&0o022 != 0 {
		return nil, ErrUnsafeFile
	}
	if before.Size() < 1 || before.Size() > maximum || !safeFileOwnerAndLinks(before, false) {
		return nil, ErrUnsafeFile
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrUnsafeFile
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !safeFileOwnerAndLinks(after, false) {
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

func rejectSymlinkComponents(path string) error {
	absolute, err := filepath.Abs(filepath.Clean(path))
	if err != nil || absolute == string(filepath.Separator) {
		return ErrUnsafeFile
	}
	volume := filepath.VolumeName(absolute)
	prefix := volume + string(filepath.Separator)
	relative := strings.TrimPrefix(absolute, prefix)
	current := prefix
	parts := strings.Split(relative, string(filepath.Separator))
	for index, part := range parts {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || (index < len(parts)-1 && !info.IsDir()) {
			return ErrUnsafeFile
		}
	}
	return nil
}

func safeFileOwnerAndLinks(info os.FileInfo, private bool) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
		return false
	}
	if private && info.Mode().Perm()&0o077 != 0 {
		return false
	}
	return true
}

func decodeExact(payload []byte, output any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data")
	}
	return nil
}

func canonicalTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Equal(value.Round(0))
}

func sha256Hex(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func invalidRuntime(reason string) error {
	return fmt.Errorf("%w: %s", ErrInvalidRuntimeConfig, reason)
}
