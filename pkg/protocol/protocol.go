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

// Ticket is the lifecycle value of one deployment.v4 assignment ticket that
// the scheduler, edge, ledger and durable miner state carry. It encodes,
// signs and verifies exactly as TicketV4 (see V4); no other assignment
// version exists.
type Ticket struct {
	Version         string         `json:"version"`
	DeploymentID    string         `json:"deployment_id"`
	Generation      uint64         `json:"generation"`
	ImageDigest     string         `json:"image_digest"`
	ManifestKey     string         `json:"manifest_key"`
	MinerID         string         `json:"miner_id"`
	RouteHost       string         `json:"route_host"`
	AssignmentNonce string         `json:"assignment_nonce"`
	IssuedAt        time.Time      `json:"issued_at"`
	ExpiresAt       time.Time      `json:"expires_at"`
	Subnet          *SubnetBinding `json:"subnet,omitempty"`
	Signature       string         `json:"signature,omitempty"`
	// Organic carries the deployment.v4 workload, resources and health.
	Organic *OrganicTicket `json:"-"`
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
	// LoadedImageConfigDigest and ErrorCode are the receipt v4 additions.
	LoadedImageConfigDigest *string `json:"-"`
	ErrorCode               *string `json:"-"`
}

func SignTicket(t *Ticket, key ed25519.PrivateKey) error {
	v4, err := t.V4()
	if err != nil {
		return err
	}
	if err := SignTicketV4(&v4, key); err != nil {
		return err
	}
	t.Signature = v4.Signature
	return nil
}

func VerifyTicket(t Ticket, key ed25519.PublicKey, now time.Time) error {
	v4, err := t.V4()
	if err != nil {
		return err
	}
	return VerifyTicketV4(v4, key, now)
}

// VerifyTicketSignature verifies the immutable assignment authority without a
// wall-clock eligibility decision. Route deactivation uses this after ticket
// expiry so the authoritative control plane can always remove an exact old
// incarnation. Assignment and activation paths must still call VerifyTicket.
func VerifyTicketSignature(t Ticket, key ed25519.PublicKey) error {
	v4, err := t.V4()
	if err != nil {
		return err
	}
	return VerifyTicketV4Signature(v4, key)
}

func SignReceipt(r *Receipt, key ed25519.PrivateKey) error {
	v4, err := r.V4()
	if err != nil {
		return err
	}
	if err := SignReceiptV4(&v4, key); err != nil {
		return err
	}
	r.Signature = v4.Signature
	return nil
}

func VerifyReceipt(r Receipt, key ed25519.PublicKey) error {
	v4, err := r.V4()
	if err != nil {
		return err
	}
	return VerifyReceiptV4(v4, key)
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
// replay after the btauth/1 ingress has authenticated callerHotkey: the
// signature by the bound validator service key inside the ticket window,
// then the request-local network, hotkey, UID and chain-block bindings. UID
// presence and value must exactly match the current metagraph identity used
// for the capability handshake.
func VerifyBoundTicket(t TicketV4, key ed25519.PublicKey, now time.Time, currentBlock uint64, network string, netuid uint16, callerHotkey, minerHotkey string, minerUID *uint16) error {
	if err := VerifyTicketV4(t, key, now); err != nil {
		return err
	}
	return verifyRequestBinding(t.Subnet, t.MinerID, currentBlock, network, netuid, callerHotkey, minerHotkey, minerUID)
}

// verifyRequestBinding checks a signed subnet binding against the
// request-local network, hotkeys, UID and chain block. Every assignment
// document version shares it.
func verifyRequestBinding(b *SubnetBinding, minerID string, currentBlock uint64, network string, netuid uint16, callerHotkey, minerHotkey string, minerUID *uint16) error {
	if b.Network != network || b.NetUID != netuid {
		return errors.New("ticket targets another Bittensor network or netuid")
	}
	if b.ValidatorHotkey != callerHotkey || b.MinerHotkey != minerHotkey || minerID != minerHotkey {
		return errors.New("ticket hotkey identity mismatch")
	}
	if (minerUID == nil) != (b.MinerUID == nil) || (minerUID != nil && *minerUID != *b.MinerUID) {
		return errors.New("ticket miner UID mismatch")
	}
	if currentBlock+2 < b.ChainBlock || currentBlock >= b.ExpiresAtBlock {
		return errors.New("ticket is not valid at the current chain block")
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

func ReplicaID(ticket Ticket) string {
	return ticket.DeploymentID + "-" + ticket.MinerID
}

func EndpointID(ticket Ticket) string {
	return fmt.Sprintf("%s-g%d-%s", ReplicaID(ticket), ticket.Generation, ticket.AssignmentNonce)
}
