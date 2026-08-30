// SPDX-License-Identifier: AGPL-3.0-only

package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// Version is retained for the standalone deployment lab. Network-facing
	// neuron bridges reject it: only BoundVersion carries Bittensor identity.
	Version      = "deployment.v1"
	BoundVersion = "deployment.v3"
)

// SubnetBinding is signed as part of both the assignment ticket and receipt.
// It connects the Go service identities to one exact Bittensor subnet epoch
// and hotkey pair. MinerUID is an exact incarnation check when the SDK exposes
// it, while hotkeys remain the stable authorization identities across churn.
type SubnetBinding struct {
	Network         string  `json:"network"`
	NetUID          uint16  `json:"netuid"`
	ValidatorHotkey string  `json:"validator_hotkey"`
	MinerHotkey     string  `json:"miner_hotkey"`
	MinerUID        *uint16 `json:"miner_uid,omitempty"`
	// MinerAxonURL is the normalized assignment-time axon of the transport
	// that received this signed ticket. Restart recovery compares it exactly,
	// so the same hotkey/UID/service key appearing at a different axon can
	// never receive, or durably retire, another assignment's cleanup.
	// Version v3 requires this exact canonical URL; older tickets fail closed
	// in network bridges and restart recovery.
	MinerAxonURL              string  `json:"miner_axon_url"`
	MinerTransport            string  `json:"miner_transport"`
	MinerTLSCertificateSHA256 *string `json:"miner_tls_certificate_sha256"`
	ChainBlock                uint64  `json:"chain_block"`
	Epoch                     uint64  `json:"epoch"`
	ExpiresAtBlock            uint64  `json:"expires_at_block"`
	ValidatorServicePublicKey string  `json:"validator_service_public_key"`
	MinerServicePublicKey     string  `json:"miner_service_public_key"`
}

type ResourceLimits struct {
	CPUMillis int `json:"cpu_millis"`
	MemoryMB  int `json:"memory_mb"`
	DiskMB    int `json:"disk_mb"`
}

type HealthSpec struct {
	Path               string `json:"path"`
	ExpectedStatus     int    `json:"expected_status"`
	IntervalMillis     int    `json:"interval_millis"`
	TimeoutMillis      int    `json:"timeout_millis"`
	ConsecutiveFailure int    `json:"consecutive_failure"`
}

// AttestationPolicy is intentionally optional in v1. It reserves the wire
// shape needed to bind a later TEE measurement and key-broker policy.
type AttestationPolicy struct {
	Technology          string   `json:"technology,omitempty"`
	AllowedMeasurements []string `json:"allowed_measurements,omitempty"`
	KBSGrantID          string   `json:"kbs_grant_id,omitempty"`
}

type Ticket struct {
	Version           string             `json:"version"`
	DeploymentID      string             `json:"deployment_id"`
	Generation        uint64             `json:"generation"`
	ImageDigest       string             `json:"image_digest"`
	ManifestKey       string             `json:"manifest_key"`
	MinerID           string             `json:"miner_id"`
	RouteHost         string             `json:"route_host"`
	AssignmentNonce   string             `json:"assignment_nonce"`
	ChallengePath     string             `json:"challenge_path"`
	ChallengeSHA256   string             `json:"challenge_sha256"`
	Resources         ResourceLimits     `json:"resources"`
	Health            HealthSpec         `json:"health"`
	IssuedAt          time.Time          `json:"issued_at"`
	ExpiresAt         time.Time          `json:"expires_at"`
	Attestation       *AttestationPolicy `json:"attestation,omitempty"`
	EncryptedImageKey string             `json:"encrypted_image_key,omitempty"`
	Subnet            *SubnetBinding     `json:"subnet,omitempty"`
	Signature         string             `json:"signature,omitempty"`
}

type ReceiptStage string

const (
	StageAccepted ReceiptStage = "accepted"
	StageReady    ReceiptStage = "ready"
	StageFailed   ReceiptStage = "failed"
)

type Receipt struct {
	Version         string         `json:"version"`
	DeploymentID    string         `json:"deployment_id"`
	Generation      uint64         `json:"generation"`
	AssignmentNonce string         `json:"assignment_nonce"`
	MinerID         string         `json:"miner_id"`
	ReplicaID       string         `json:"replica_id"`
	EndpointID      string         `json:"endpoint_id"`
	ImageDigest     string         `json:"image_digest"`
	ManifestKey     string         `json:"manifest_key"`
	RouteHost       string         `json:"route_host"`
	Stage           ReceiptStage   `json:"stage"`
	AssignmentSeen  time.Time      `json:"assignment_seen"`
	PullStarted     time.Time      `json:"pull_started"`
	PullCompleted   time.Time      `json:"pull_completed"`
	RuntimeStarted  time.Time      `json:"runtime_started"`
	HealthPassed    time.Time      `json:"health_passed"`
	Error           string         `json:"error,omitempty"`
	Subnet          *SubnetBinding `json:"subnet,omitempty"`
	Signature       string         `json:"signature,omitempty"`
}

func SignTicket(t *Ticket, key ed25519.PrivateKey) error {
	if len(key) != ed25519.PrivateKeySize {
		return errors.New("invalid ticket signing key")
	}
	if t.Version == "" {
		t.Version = Version
	}
	b, err := unsignedJSON(*t)
	if err != nil {
		return err
	}
	t.Signature = hex.EncodeToString(ed25519.Sign(key, b))
	return nil
}

func VerifyTicket(t Ticket, key ed25519.PublicKey, now time.Time) error {
	if len(key) != ed25519.PublicKeySize {
		return errors.New("invalid ticket verification key")
	}
	if t.Version != Version && t.Version != BoundVersion {
		return fmt.Errorf("unsupported protocol version %q", t.Version)
	}
	if t.Version == BoundVersion {
		if err := ValidateSubnetBinding(t.Subnet); err != nil {
			return err
		}
	}
	if t.IssuedAt.IsZero() || !t.ExpiresAt.After(t.IssuedAt) || now.Before(t.IssuedAt.Add(-30*time.Second)) || !now.Before(t.ExpiresAt) {
		return errors.New("ticket is not currently valid")
	}
	return VerifyTicketSignature(t, key)
}

// VerifyTicketSignature verifies the immutable assignment authority without a
// wall-clock eligibility decision. Route deactivation uses this after ticket
// expiry so the authoritative control plane can always remove an exact old
// incarnation. Assignment and activation paths must still call VerifyTicket.
func VerifyTicketSignature(t Ticket, key ed25519.PublicKey) error {
	if len(key) != ed25519.PublicKeySize {
		return errors.New("invalid ticket verification key")
	}
	if t.Version != Version && t.Version != BoundVersion {
		return fmt.Errorf("unsupported protocol version %q", t.Version)
	}
	if t.Version == BoundVersion {
		if err := ValidateSubnetBinding(t.Subnet); err != nil {
			return err
		}
	}
	sig, err := hex.DecodeString(t.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		if err == nil {
			err = errors.New("signature must contain 64 bytes")
		}
		return fmt.Errorf("decode ticket signature: %w", err)
	}
	b, err := unsignedJSON(t)
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, b, sig) {
		return errors.New("invalid ticket signature")
	}
	return nil
}

func SignReceipt(r *Receipt, key ed25519.PrivateKey) error {
	if len(key) != ed25519.PrivateKeySize {
		return errors.New("invalid receipt signing key")
	}
	if r.Version == "" {
		r.Version = Version
	}
	b, err := unsignedJSON(*r)
	if err != nil {
		return err
	}
	r.Signature = hex.EncodeToString(ed25519.Sign(key, b))
	return nil
}

func VerifyReceipt(r Receipt, key ed25519.PublicKey) error {
	if len(key) != ed25519.PublicKeySize {
		return errors.New("invalid receipt verification key")
	}
	if r.Version != Version && r.Version != BoundVersion {
		return fmt.Errorf("unsupported protocol version %q", r.Version)
	}
	if r.Version == BoundVersion {
		if err := ValidateSubnetBinding(r.Subnet); err != nil {
			return err
		}
	}
	sig, err := hex.DecodeString(r.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		if err == nil {
			err = errors.New("signature must contain 64 bytes")
		}
		return fmt.Errorf("decode receipt signature: %w", err)
	}
	b, err := unsignedJSON(r)
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, b, sig) {
		return errors.New("invalid receipt signature")
	}
	return nil
}

// ValidateSubnetBinding validates shape only. VerifyBoundTicket additionally
// checks the request-local authenticated identities and current chain block.
func ValidateSubnetBinding(binding *SubnetBinding) error {
	if binding == nil {
		return errors.New("bound ticket is missing subnet identity")
	}
	if binding.Network == "" || binding.ValidatorHotkey == "" || binding.MinerHotkey == "" {
		return errors.New("subnet network and hotkeys are required")
	}
	if !validPublicKeyHex(binding.ValidatorServicePublicKey) || !validPublicKeyHex(binding.MinerServicePublicKey) {
		return errors.New("subnet service public keys must be lowercase 32-byte hex")
	}
	if binding.MinerAxonURL == "" {
		return errors.New("subnet miner axon URL is required")
	}
	if err := validateMinerAxonURL(binding.MinerAxonURL, binding.MinerTransport); err != nil {
		return err
	}
	switch binding.MinerTransport {
	case "https":
		if binding.MinerTLSCertificateSHA256 == nil || !validSHA256Hex(*binding.MinerTLSCertificateSHA256) {
			return errors.New("HTTPS subnet binding requires a canonical leaf certificate SHA-256")
		}
	case "http":
		if binding.MinerTLSCertificateSHA256 != nil {
			return errors.New("HTTP subnet binding cannot carry a TLS certificate pin")
		}
	default:
		return errors.New("subnet miner transport must be https or explicit mock http")
	}
	if binding.ExpiresAtBlock <= binding.ChainBlock {
		return errors.New("subnet block expiry must follow issuance block")
	}
	return nil
}

func validateMinerAxonURL(raw, transport string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed == nil || parsed.Scheme != transport || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" ||
		parsed.Fragment != "" || parsed.Opaque != "" || parsed.Path != "" || parsed.RawPath != "" {
		return errors.New("subnet miner axon must be a canonical transport URL without credentials, path, query, or fragment")
	}
	ip := net.ParseIP(parsed.Hostname())
	port, portErr := strconv.Atoi(parsed.Port())
	if portErr != nil || port < 1 || port > 65535 || parsed.Port() != strconv.Itoa(port) {
		return errors.New("subnet miner axon must use an explicit canonical valid port")
	}
	host := parsed.Hostname()
	if ip != nil {
		if !ip.IsGlobalUnicast() && !ip.IsLoopback() {
			return errors.New("subnet miner axon numeric IP is not unicast")
		}
		host = ip.String()
	} else if transport != "http" || !validMockAxonHostname(host) {
		return errors.New("HTTPS subnet miner axon must use a numeric IP")
	}
	expected := transport + "://" + net.JoinHostPort(host, strconv.Itoa(port))
	if raw != expected {
		return errors.New("subnet miner axon URL is not canonical")
	}
	return nil
}

func validMockAxonHostname(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func validSHA256Hex(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(value) == sha256.Size*2 && len(decoded) == sha256.Size && value == hex.EncodeToString(decoded)
}

func validPublicKeyHex(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(value) == ed25519.PublicKeySize*2 && len(decoded) == ed25519.PublicKeySize && value == hex.EncodeToString(decoded)
}

// VerifyBoundTicket prevents cross-subnet, cross-hotkey, stale-block, and UID
// replay after the btauth/1 ingress has authenticated callerHotkey. UID
// presence and value must exactly match the current metagraph identity used
// for the capability handshake.
func VerifyBoundTicket(t Ticket, key ed25519.PublicKey, now time.Time, currentBlock uint64, network string, netuid uint16, callerHotkey, minerHotkey string, minerUID *uint16) error {
	if t.Version != BoundVersion {
		return fmt.Errorf("network bridge requires protocol %q", BoundVersion)
	}
	if err := VerifyTicket(t, key, now); err != nil {
		return err
	}
	b := t.Subnet
	if b.Network != network || b.NetUID != netuid {
		return errors.New("ticket targets another Bittensor network or netuid")
	}
	if b.ValidatorHotkey != callerHotkey || b.MinerHotkey != minerHotkey || t.MinerID != minerHotkey {
		return errors.New("ticket hotkey identity mismatch")
	}
	if (minerUID == nil) != (b.MinerUID == nil) || (minerUID != nil && *minerUID != *b.MinerUID) {
		return errors.New("ticket miner UID mismatch")
	}
	if currentBlock+2 < b.ChainBlock || currentBlock >= b.ExpiresAtBlock {
		return errors.New("ticket is not valid at the current chain block")
	}
	if !publicKeyMatchesHex(key, b.ValidatorServicePublicKey) {
		return errors.New("ticket signer is not the bound validator service key")
	}
	return nil
}

func publicKeyMatchesHex(key ed25519.PublicKey, encoded string) bool {
	decoded, err := hex.DecodeString(encoded)
	return err == nil && len(decoded) == ed25519.PublicKeySize && string(decoded) == string(key)
}

// EqualSubnetBinding compares the value rather than pointer identity.
func EqualSubnetBinding(left, right *SubnetBinding) bool {
	if left == nil || right == nil {
		return left == right
	}
	leftJSON, _ := json.Marshal(left)
	rightJSON, _ := json.Marshal(right)
	return string(leftJSON) == string(rightJSON)
}

// EqualTicket compares the complete signed ticket value. EndpointID alone is
// intentionally insufficient: route, artifact, expiry, and subnet bindings
// are all part of the validator's exact signed assignment contract.
func EqualTicket(left, right Ticket) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

func ChallengeDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func ReplicaID(ticket Ticket) string {
	return ticket.DeploymentID + "-" + ticket.MinerID
}

func EndpointID(ticket Ticket) string {
	return fmt.Sprintf("%s-g%d-%s", ReplicaID(ticket), ticket.Generation, ticket.AssignmentNonce)
}

func unsignedJSON[T Ticket | Receipt](v T) ([]byte, error) {
	switch p := any(&v).(type) {
	case *Ticket:
		p.Signature = ""
	case *Receipt:
		p.Signature = ""
	}
	return json.Marshal(v)
}
