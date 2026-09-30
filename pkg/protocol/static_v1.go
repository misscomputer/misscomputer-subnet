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
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/organic"
	"github.com/misscomputer/misscomputer-subnet/pkg/static"
)

// static-deployment-ticket v1 and static-deployment-receipt v1 (static-site
// contract §8). They are separate documents from deployment.v4: no v4
// member is reinterpreted as a site identity, and a v4 decoder rejects them.
const (
	StaticTicketSchema  = organic.SchemaPrefix + "static-deployment-ticket"
	StaticReceiptSchema = organic.SchemaPrefix + "static-deployment-receipt"
	StaticSchemaVersion = 1

	// Domain-separated signing contexts: a static signature never verifies as
	// any other document, including deployment.v4 signed by the same key.
	StaticTicketSigningDomain  = organic.SchemaPrefix + "static-deployment-ticket/v1/ed25519"
	StaticReceiptSigningDomain = organic.SchemaPrefix + "static-deployment-receipt/v1/ed25519"
)

// StaticSubnetBindingV1 carries exactly the SubnetBinding members with
// miner_uid always present (null when the metagraph has no UID).
type StaticSubnetBindingV1 struct {
	ChainBlock                uint64  `json:"chain_block"`
	Epoch                     uint64  `json:"epoch"`
	ExpiresAtBlock            uint64  `json:"expires_at_block"`
	MinerAxonURL              string  `json:"miner_axon_url"`
	MinerHotkey               string  `json:"miner_hotkey"`
	MinerServicePublicKey     string  `json:"miner_service_public_key"`
	MinerTLSCertificateSHA256 *string `json:"miner_tls_certificate_sha256"`
	MinerTransport            string  `json:"miner_transport"`
	MinerUID                  *uint16 `json:"miner_uid"`
	NetUID                    uint16  `json:"netuid"`
	Network                   string  `json:"network"`
	ValidatorHotkey           string  `json:"validator_hotkey"`
	ValidatorServicePublicKey string  `json:"validator_service_public_key"`
}

// Binding is the equivalent SubnetBinding, validated by the shared rules.
func (b *StaticSubnetBindingV1) Binding() *SubnetBinding {
	if b == nil {
		return nil
	}
	return &SubnetBinding{
		Network: b.Network, NetUID: b.NetUID, ValidatorHotkey: b.ValidatorHotkey, MinerHotkey: b.MinerHotkey,
		MinerUID: b.MinerUID, MinerAxonURL: b.MinerAxonURL, MinerTransport: b.MinerTransport,
		MinerTLSCertificateSHA256: b.MinerTLSCertificateSHA256, ChainBlock: b.ChainBlock, Epoch: b.Epoch,
		ExpiresAtBlock: b.ExpiresAtBlock, ValidatorServicePublicKey: b.ValidatorServicePublicKey,
		MinerServicePublicKey: b.MinerServicePublicKey,
	}
}

// StaticTicketV1 is one validator-signed assignment of one exact signed
// site release to one miner endpoint incarnation.
type StaticTicketV1 struct {
	AssignmentNonce            string                 `json:"assignment_nonce"`
	DeploymentID               string                 `json:"deployment_id"`
	ExpiresAt                  string                 `json:"expires_at"`
	Generation                 uint64                 `json:"generation"`
	IssuedAt                   string                 `json:"issued_at"`
	MinerID                    string                 `json:"miner_id"`
	ReleaseDigest              string                 `json:"release_digest"`
	RouteHost                  string                 `json:"route_host"`
	Schema                     string                 `json:"schema"`
	SchemaVersion              int                    `json:"schema_version"`
	ServerImplementationDigest string                 `json:"server_implementation_digest"`
	Signature                  string                 `json:"signature"`
	SiteDigest                 string                 `json:"site_digest"`
	SiteManifestKey            string                 `json:"site_manifest_key"`
	Subnet                     *StaticSubnetBindingV1 `json:"subnet"`
	WorkloadKind               string                 `json:"workload_kind"`
}

// StaticReceiptV1 is the miner-signed answer to one static ticket. A ready
// receipt asserts that every manifest file was fetched and verified and
// that the named handler serves exactly site_digest.
type StaticReceiptV1 struct {
	AssignmentNonce            string                 `json:"assignment_nonce"`
	AssignmentSeen             *string                `json:"assignment_seen"`
	DeploymentID               string                 `json:"deployment_id"`
	EndpointID                 string                 `json:"endpoint_id"`
	Error                      string                 `json:"error"`
	ErrorCode                  *string                `json:"error_code"`
	FetchCompleted             *string                `json:"fetch_completed"`
	FetchStarted               *string                `json:"fetch_started"`
	Generation                 uint64                 `json:"generation"`
	MinerID                    string                 `json:"miner_id"`
	ReleaseDigest              string                 `json:"release_digest"`
	ReplicaID                  string                 `json:"replica_id"`
	RouteHost                  string                 `json:"route_host"`
	Schema                     string                 `json:"schema"`
	SchemaVersion              int                    `json:"schema_version"`
	ServerImplementationDigest string                 `json:"server_implementation_digest"`
	ServingStarted             *string                `json:"serving_started"`
	Signature                  string                 `json:"signature"`
	SiteDigest                 string                 `json:"site_digest"`
	Stage                      ReceiptStage           `json:"stage"`
	Subnet                     *StaticSubnetBindingV1 `json:"subnet"`
	TicketDigest               string                 `json:"ticket_digest"`
	VerifiedFileCount          *int                   `json:"verified_file_count"`
	VerifiedTotalBytes         *int64                 `json:"verified_total_bytes"`
}

// StaticTime renders the canonical Go RFC3339Nano UTC form.
func StaticTime(value time.Time) *string {
	formatted := value.UTC().Format(time.RFC3339Nano)
	return &formatted
}

func parseStaticTime(value string) (time.Time, error) {
	if !organic.ValidTimestamp(value) {
		return time.Time{}, errors.New("timestamp is not canonical RFC3339Nano UTC")
	}
	return time.Parse(time.RFC3339Nano, value)
}

func validOptionalStaticTime(value *string) bool {
	return value == nil || organic.ValidTimestamp(*value)
}

// Validate checks a received static ticket; the signature must be present.
func (t StaticTicketV1) Validate() error {
	if !lowercaseHex(t.Signature, 128) {
		return errors.New("static ticket signature must be 128 lowercase hex")
	}
	return t.validateUnsigned()
}

func (t StaticTicketV1) validateUnsigned() error {
	if t.Schema != StaticTicketSchema || t.SchemaVersion != StaticSchemaVersion || t.WorkloadKind != static.WorkloadKind {
		return errors.New("static ticket schema or workload kind is invalid")
	}
	if !organic.ValidRouteLabel(t.DeploymentID) || t.Generation < 1 || !lowercaseHex(t.AssignmentNonce, 32) ||
		!organic.ValidHotkey(t.MinerID) || t.RouteHost != organic.RouteHost(t.DeploymentID) ||
		!organic.ValidDigest(t.SiteDigest) || !organic.ValidDigest(t.ReleaseDigest) ||
		!organic.ValidDigest(t.ServerImplementationDigest) {
		return errors.New("static ticket identity is invalid")
	}
	if t.SiteManifestKey != static.ManifestKey(t.SiteDigest) {
		return errors.New("site_manifest_key_mismatch")
	}
	issued, issuedErr := parseStaticTime(t.IssuedAt)
	expires, expiresErr := parseStaticTime(t.ExpiresAt)
	if issuedErr != nil || expiresErr != nil || !expires.After(issued) {
		return errors.New("ticket_window_invalid")
	}
	if err := ValidateSubnetBinding(t.Subnet.Binding()); err != nil {
		return err
	}
	if t.MinerID != t.Subnet.MinerHotkey {
		return errors.New("miner_id_mismatch")
	}
	return nil
}

// Validate checks a received static receipt; the signature must be present.
func (r StaticReceiptV1) Validate() error {
	if !lowercaseHex(r.Signature, 128) {
		return errors.New("static receipt signature must be 128 lowercase hex")
	}
	return r.validateUnsigned()
}

func (r StaticReceiptV1) validateUnsigned() error {
	if r.Schema != StaticReceiptSchema || r.SchemaVersion != StaticSchemaVersion {
		return errors.New("static receipt schema is invalid")
	}
	if !organic.ValidRouteLabel(r.DeploymentID) || r.Generation < 1 || !lowercaseHex(r.AssignmentNonce, 32) ||
		!organic.ValidHotkey(r.MinerID) || r.RouteHost != organic.RouteHost(r.DeploymentID) ||
		!organic.ValidDigest(r.SiteDigest) || !organic.ValidDigest(r.ReleaseDigest) ||
		!organic.ValidDigest(r.ServerImplementationDigest) || !organic.ValidDigest(r.TicketDigest) {
		return errors.New("static receipt identity is invalid")
	}
	replica := r.DeploymentID + "-" + r.MinerID
	if r.ReplicaID != replica || r.EndpointID != fmt.Sprintf("%s-g%d-%s", replica, r.Generation, r.AssignmentNonce) {
		return errors.New("receipt_identity_invalid")
	}
	if !validOptionalStaticTime(r.AssignmentSeen) || !validOptionalStaticTime(r.FetchStarted) ||
		!validOptionalStaticTime(r.FetchCompleted) || !validOptionalStaticTime(r.ServingStarted) {
		return errors.New("static receipt timestamp is not canonical")
	}
	if len(r.Error) > 512 || !printableASCII(r.Error) {
		return errors.New("receipt error must be at most 512 printable ASCII characters")
	}
	if (r.Stage == StageFailed) != (r.ErrorCode != nil) {
		return errors.New("receipt_error_code_invalid")
	}
	if r.ErrorCode != nil {
		if _, known := static.ReceiptErrorAttribution[*r.ErrorCode]; !known {
			return errors.New("receipt error_code is unknown")
		}
	}
	ready := r.Stage == StageReady
	switch r.Stage {
	case StageAccepted, StageReady, StageFailed:
	default:
		return errors.New("receipt stage is invalid")
	}
	if ready != (r.VerifiedFileCount != nil) || ready != (r.VerifiedTotalBytes != nil) {
		return errors.New("verified counts must be present exactly on ready")
	}
	if ready && (r.Error != "" || *r.VerifiedFileCount < 1 || *r.VerifiedFileCount > static.MaxFiles ||
		*r.VerifiedTotalBytes < 0 || *r.VerifiedTotalBytes > static.MaxTotalBytes) {
		return errors.New("ready_receipt_incomplete")
	}
	if err := ValidateSubnetBinding(r.Subnet.Binding()); err != nil {
		return err
	}
	if r.MinerID != r.Subnet.MinerHotkey {
		return errors.New("miner_id_mismatch")
	}
	return nil
}

// staticSigningMessage is domain || 0x00 || canonical(document without its
// signature member).
func staticSigningMessage(domain string, document any) ([]byte, error) {
	encoded, err := json.Marshal(document)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var members map[string]any
	if err := decoder.Decode(&members); err != nil {
		return nil, err
	}
	delete(members, "signature")
	canonical, err := organic.Canonical(members)
	if err != nil {
		return nil, err
	}
	message := make([]byte, 0, len(domain)+1+len(canonical))
	message = append(append(message, domain...), 0)
	return append(message, canonical...), nil
}

func signStatic(domain string, document any, key ed25519.PrivateKey) (string, error) {
	message, err := staticSigningMessage(domain, document)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(ed25519.Sign(key, message)), nil
}

func verifyStatic(domain string, document any, signature string, key ed25519.PublicKey) error {
	decoded, err := hex.DecodeString(signature)
	if err != nil || len(decoded) != ed25519.SignatureSize {
		return errors.New("signature must contain 64 bytes")
	}
	message, err := staticSigningMessage(domain, document)
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, message, decoded) {
		return errors.New("invalid static signature")
	}
	return nil
}

// SignStaticTicketV1 signs t with the validator Go service key.
func SignStaticTicketV1(t *StaticTicketV1, key ed25519.PrivateKey) error {
	if t == nil || len(key) != ed25519.PrivateKeySize {
		return errors.New("invalid static ticket signing input")
	}
	if err := t.validateUnsigned(); err != nil {
		return err
	}
	signature, err := signStatic(StaticTicketSigningDomain, *t, key)
	if err != nil {
		return err
	}
	t.Signature = signature
	return nil
}

// VerifyStaticTicketV1Signature verifies the immutable assignment authority
// without a wall-clock decision (ingress, status and deactivation).
func VerifyStaticTicketV1Signature(t StaticTicketV1, key ed25519.PublicKey) error {
	if err := t.Validate(); err != nil {
		return err
	}
	if len(key) != ed25519.PublicKeySize || !publicKeyMatchesHex(key, t.Subnet.ValidatorServicePublicKey) {
		return errors.New("static ticket signer is not the bound validator service key")
	}
	return verifyStatic(StaticTicketSigningDomain, t, t.Signature, key)
}

// VerifyBoundStaticTicketV1 is the admission check: signature, ticket
// window (30 s issue skew) and request-local network, hotkey, UID and chain
// block, exactly as VerifyBoundTicket.
func VerifyBoundStaticTicketV1(t StaticTicketV1, key ed25519.PublicKey, now time.Time, currentBlock uint64, network string, netuid uint16, callerHotkey, minerHotkey string, minerUID *uint16) error {
	if err := VerifyStaticTicketV1Signature(t, key); err != nil {
		return err
	}
	issued, _ := parseStaticTime(t.IssuedAt)
	expires, _ := parseStaticTime(t.ExpiresAt)
	if now.Before(issued.Add(-30*time.Second)) || !now.Before(expires) {
		return errors.New("ticket is not currently valid")
	}
	return verifyRequestBinding(t.Subnet.Binding(), t.MinerID, currentBlock, network, netuid, callerHotkey, minerHotkey, minerUID)
}

// SignStaticReceiptV1 signs r with the miner service key.
func SignStaticReceiptV1(r *StaticReceiptV1, key ed25519.PrivateKey) error {
	if r == nil || len(key) != ed25519.PrivateKeySize {
		return errors.New("invalid static receipt signing input")
	}
	if err := r.validateUnsigned(); err != nil {
		return err
	}
	signature, err := signStatic(StaticReceiptSigningDomain, *r, key)
	if err != nil {
		return err
	}
	r.Signature = signature
	return nil
}

// VerifyStaticReceiptV1 verifies the miner service-key signature of r.
func VerifyStaticReceiptV1(r StaticReceiptV1, key ed25519.PublicKey) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if len(key) != ed25519.PublicKeySize || !publicKeyMatchesHex(key, r.Subnet.MinerServicePublicKey) {
		return errors.New("static receipt signer is not the bound miner service key")
	}
	return verifyStatic(StaticReceiptSigningDomain, r, r.Signature, key)
}

// StaticReceiptMatchesTicketV1 is the scheduler's acceptance check: every
// bound member equals the retained ticket and ticket_digest names it.
func StaticReceiptMatchesTicketV1(t StaticTicketV1, r StaticReceiptV1) error {
	digest, err := StaticTicketDigestV1(t)
	if err != nil {
		return err
	}
	if r.DeploymentID != t.DeploymentID || r.Generation != t.Generation || r.AssignmentNonce != t.AssignmentNonce ||
		r.MinerID != t.MinerID || r.RouteHost != t.RouteHost || r.SiteDigest != t.SiteDigest ||
		r.ReleaseDigest != t.ReleaseDigest || r.ServerImplementationDigest != t.ServerImplementationDigest ||
		r.EndpointID != StaticEndpointIDV1(t) || r.TicketDigest != digest || !equalStaticBinding(r.Subnet, t.Subnet) {
		return errors.New("static receipt does not answer the ticket")
	}
	return nil
}

func equalStaticBinding(left, right *StaticSubnetBindingV1) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

// StaticReplicaIDV1 and StaticEndpointIDV1 use the deployment.v4 derivation,
// so runtime paths, probe authorization v1 and endpoint fences are shared.
func StaticReplicaIDV1(t StaticTicketV1) string { return t.DeploymentID + "-" + t.MinerID }

func StaticEndpointIDV1(t StaticTicketV1) string {
	return fmt.Sprintf("%s-g%d-%s", StaticReplicaIDV1(t), t.Generation, t.AssignmentNonce)
}

// StaticTicketDigestV1 is "sha256:" + hex(SHA-256(canonical JSON of the
// complete signed ticket)), without a trailing newline.
func StaticTicketDigestV1(t StaticTicketV1) (string, error) { return staticDigest(t) }

// StaticReceiptDigestV1 is computed as the ticket digest.
func StaticReceiptDigestV1(r StaticReceiptV1) (string, error) { return staticDigest(r) }

func staticDigest(document any) (string, error) {
	encoded, err := organic.Canonical(document)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
