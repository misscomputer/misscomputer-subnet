// SPDX-License-Identifier: AGPL-3.0-only

package protocol

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/assignment"
	"github.com/misscomputer/misscomputer-subnet/pkg/organic"
)

// OrganicVersion is the only assignment version accepted for organic apps.
// Network paths reject deployment.v1, .v2 and .v3.
const OrganicVersion = "deployment.v4"

// WorkloadV4 names the OCI image workload a deployment.v4 ticket assigns.
type WorkloadV4 struct {
	Kind           string        `json:"kind"`
	ContainerPort  int           `json:"container_port"`
	RuntimeProfile string        `json:"runtime_profile"`
	Env            WorkloadEnvV4 `json:"env"`
}

// WorkloadEnvV4 is exactly the environment the runtime sets on top of the
// image ENV; no identity, token or user variable is ever added.
type WorkloadEnvV4 struct {
	Host string `json:"HOST"`
	Port string `json:"PORT"`
}

// TicketV4 is the deployment.v4 assignment ticket: v3 without the synthetic
// challenge, with the OCI workload, the small-v1 resources and v4 health.
// Field order is the signed json.Marshal order; do not reorder.
type TicketV4 struct {
	Version         string               `json:"version"`
	DeploymentID    string               `json:"deployment_id"`
	Generation      uint64               `json:"generation"`
	ImageDigest     string               `json:"image_digest"`
	ManifestKey     string               `json:"manifest_key"`
	MinerID         string               `json:"miner_id"`
	RouteHost       string               `json:"route_host"`
	AssignmentNonce string               `json:"assignment_nonce"`
	Workload        WorkloadV4           `json:"workload"`
	Resources       organic.Resources    `json:"resources"`
	Health          organic.TicketHealth `json:"health"`
	IssuedAt        time.Time            `json:"issued_at"`
	ExpiresAt       time.Time            `json:"expires_at"`
	Subnet          *SubnetBinding       `json:"subnet"`
	Signature       string               `json:"signature,omitempty"`
}

// ReceiptV4 is the deployment.v4 receipt. Error is diagnostic only and never
// carries container output. Field order is the signed json.Marshal order.
type ReceiptV4 struct {
	Version                 string         `json:"version"`
	DeploymentID            string         `json:"deployment_id"`
	Generation              uint64         `json:"generation"`
	AssignmentNonce         string         `json:"assignment_nonce"`
	MinerID                 string         `json:"miner_id"`
	ReplicaID               string         `json:"replica_id"`
	EndpointID              string         `json:"endpoint_id"`
	ImageDigest             string         `json:"image_digest"`
	ManifestKey             string         `json:"manifest_key"`
	LoadedImageConfigDigest *string        `json:"loaded_image_config_digest"`
	RouteHost               string         `json:"route_host"`
	Stage                   ReceiptStage   `json:"stage"`
	ErrorCode               *string        `json:"error_code"`
	Error                   string         `json:"error"`
	AssignmentSeen          time.Time      `json:"assignment_seen"`
	PullStarted             time.Time      `json:"pull_started"`
	PullCompleted           time.Time      `json:"pull_completed"`
	RuntimeStarted          time.Time      `json:"runtime_started"`
	HealthPassed            time.Time      `json:"health_passed"`
	Subnet                  *SubnetBinding `json:"subnet"`
	Signature               string         `json:"signature,omitempty"`
}

// Validate checks a received ticket against the rules of the Python
// DeploymentTicketV4 model; the signature must be present.
func (t TicketV4) Validate() error {
	if !lowercaseHex(t.Signature, 128) {
		return errors.New("ticket signature must be 128 lowercase hex")
	}
	return t.validateUnsigned()
}

func (t TicketV4) validateUnsigned() error {
	if t.Version != OrganicVersion {
		return fmt.Errorf("network paths require %q", OrganicVersion)
	}
	if !organic.ValidRouteLabel(t.DeploymentID) || t.Generation < 1 || !organic.ValidDigest(t.ImageDigest) ||
		!organic.ValidHotkey(t.MinerID) || !organic.ValidHostname(t.RouteHost) || !lowercaseHex(t.AssignmentNonce, 32) {
		return errors.New("ticket identity is invalid")
	}
	if t.ManifestKey != organic.ManifestKey(t.ImageDigest) {
		return errors.New("manifest_key_mismatch")
	}
	workload := t.Workload
	if workload.Kind != organic.WorkloadKind || workload.RuntimeProfile != organic.RuntimeProfile ||
		workload.ContainerPort < 1 || workload.ContainerPort > 65535 || workload.Env.Host != "0.0.0.0" {
		return errors.New("ticket workload is invalid")
	}
	if workload.Env.Port != strconv.Itoa(workload.ContainerPort) {
		return errors.New("workload_port_env_mismatch")
	}
	if t.Resources != organic.SmallV1 {
		return errors.New("ticket resources must equal the small-v1 profile")
	}
	if err := t.Health.Validate(); err != nil {
		return err
	}
	if t.IssuedAt.IsZero() || !t.ExpiresAt.After(t.IssuedAt) {
		return errors.New("ticket_window_invalid")
	}
	if err := ValidateSubnetBinding(t.Subnet); err != nil {
		return err
	}
	if t.MinerID != t.Subnet.MinerHotkey {
		return errors.New("miner_id_mismatch")
	}
	return nil
}

// Validate checks a received receipt against the rules of the Python
// DeploymentReceiptV4 model; the signature must be present.
func (r ReceiptV4) Validate() error {
	if !lowercaseHex(r.Signature, 128) {
		return errors.New("receipt signature must be 128 lowercase hex")
	}
	return r.validateUnsigned()
}

func (r ReceiptV4) validateUnsigned() error {
	if r.Version != OrganicVersion {
		return fmt.Errorf("network paths require %q", OrganicVersion)
	}
	if !organic.ValidRouteLabel(r.DeploymentID) || r.Generation < 1 || !lowercaseHex(r.AssignmentNonce, 32) ||
		!organic.ValidHotkey(r.MinerID) || !organic.ValidDigest(r.ImageDigest) || !organic.ValidHostname(r.RouteHost) ||
		(r.LoadedImageConfigDigest != nil && !organic.ValidDigest(*r.LoadedImageConfigDigest)) {
		return errors.New("receipt identity is invalid")
	}
	if r.Stage != StageAccepted && r.Stage != StageReady && r.Stage != StageFailed {
		return errors.New("receipt stage is invalid")
	}
	if r.ErrorCode != nil {
		if _, known := organic.ReceiptErrorAttribution[*r.ErrorCode]; !known {
			return errors.New("receipt error_code is unknown")
		}
	}
	if len(r.Error) > 512 || !printableASCII(r.Error) {
		return errors.New("receipt error must be at most 512 printable ASCII characters")
	}
	replica := r.DeploymentID + "-" + r.MinerID
	if r.ReplicaID != replica || r.EndpointID != fmt.Sprintf("%s-g%d-%s", replica, r.Generation, r.AssignmentNonce) {
		return errors.New("receipt_identity_invalid")
	}
	if err := ValidateSubnetBinding(r.Subnet); err != nil {
		return err
	}
	if r.MinerID != r.Subnet.MinerHotkey {
		return errors.New("miner_id_mismatch")
	}
	if r.ManifestKey != organic.ManifestKey(r.ImageDigest) {
		return errors.New("manifest_key_mismatch")
	}
	if (r.Stage == StageFailed) != (r.ErrorCode != nil) {
		return errors.New("receipt_error_code_invalid")
	}
	if r.Stage == StageReady && (r.LoadedImageConfigDigest == nil || r.Error != "") {
		return errors.New("ready_receipt_incomplete")
	}
	return nil
}

func printableASCII(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] < 0x20 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func signedV4JSON[T TicketV4 | ReceiptV4](value T) ([]byte, error) {
	switch pointer := any(&value).(type) {
	case *TicketV4:
		pointer.Signature = ""
	case *ReceiptV4:
		pointer.Signature = ""
	}
	return json.Marshal(value)
}

// SignTicketV4 signs t with the validator Go service key over json.Marshal
// with an empty signature, exactly as deployment.v3.
func SignTicketV4(t *TicketV4, key ed25519.PrivateKey) error {
	if t == nil || len(key) != ed25519.PrivateKeySize {
		return errors.New("invalid ticket signing input")
	}
	if err := t.validateUnsigned(); err != nil {
		return err
	}
	payload, err := signedV4JSON(*t)
	if err != nil {
		return err
	}
	t.Signature = hex.EncodeToString(ed25519.Sign(key, payload))
	return nil
}

// VerifyTicketV4Signature verifies the immutable assignment authority
// without a wall-clock decision (route deactivation after expiry).
func VerifyTicketV4Signature(t TicketV4, key ed25519.PublicKey) error {
	if err := t.Validate(); err != nil {
		return err
	}
	if len(key) != ed25519.PublicKeySize || !publicKeyMatchesHex(key, t.Subnet.ValidatorServicePublicKey) {
		return errors.New("ticket signer is not the bound validator service key")
	}
	return verifyV4Signature(t, t.Signature, key)
}

// VerifyTicketV4 additionally bounds acceptance and route publication by the
// ticket window. Active routes survive expiry; only register/activate call it.
func VerifyTicketV4(t TicketV4, key ed25519.PublicKey, now time.Time) error {
	if err := VerifyTicketV4Signature(t, key); err != nil {
		return err
	}
	if now.Before(t.IssuedAt.Add(-30*time.Second)) || !now.Before(t.ExpiresAt) {
		return errors.New("ticket is not currently valid")
	}
	return nil
}

// SignReceiptV4 signs r with the miner service key.
func SignReceiptV4(r *ReceiptV4, key ed25519.PrivateKey) error {
	if r == nil || len(key) != ed25519.PrivateKeySize {
		return errors.New("invalid receipt signing input")
	}
	if err := r.validateUnsigned(); err != nil {
		return err
	}
	payload, err := signedV4JSON(*r)
	if err != nil {
		return err
	}
	r.Signature = hex.EncodeToString(ed25519.Sign(key, payload))
	return nil
}

// VerifyReceiptV4 verifies the miner service-key signature of r.
func VerifyReceiptV4(r ReceiptV4, key ed25519.PublicKey) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if len(key) != ed25519.PublicKeySize || !publicKeyMatchesHex(key, r.Subnet.MinerServicePublicKey) {
		return errors.New("receipt signer is not the bound miner service key")
	}
	return verifyV4Signature(r, r.Signature, key)
}

func verifyV4Signature[T TicketV4 | ReceiptV4](value T, signature string, key ed25519.PublicKey) error {
	decoded, err := hex.DecodeString(signature)
	if err != nil || len(decoded) != ed25519.SignatureSize {
		return errors.New("signature must contain 64 bytes")
	}
	payload, err := signedV4JSON(value)
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, payload, decoded) {
		return errors.New("invalid deployment.v4 signature")
	}
	return nil
}

// ReceiptMatchesTicketV4 is the scheduler's acceptance check: the receipt
// must answer exactly this ticket, and a ready receipt must report the
// artifact manifest's config digest as the loaded image identity.
func ReceiptMatchesTicketV4(t TicketV4, r ReceiptV4, artifactConfigDigest string) error {
	if r.DeploymentID != t.DeploymentID || r.Generation != t.Generation || r.AssignmentNonce != t.AssignmentNonce ||
		r.MinerID != t.MinerID || r.ImageDigest != t.ImageDigest || r.ManifestKey != t.ManifestKey ||
		r.RouteHost != t.RouteHost || !EqualSubnetBinding(r.Subnet, t.Subnet) {
		return errors.New("receipt does not answer the ticket")
	}
	if r.Stage == StageReady && (r.LoadedImageConfigDigest == nil || *r.LoadedImageConfigDigest != artifactConfigDigest) {
		return errors.New("loaded image config digest does not match the artifact")
	}
	return nil
}

// ReplicaIDV4 and EndpointIDV4 derive the existing identities from a v4 ticket.
func ReplicaIDV4(t TicketV4) string { return t.DeploymentID + "-" + t.MinerID }

func EndpointIDV4(t TicketV4) string {
	return fmt.Sprintf("%s-g%d-%s", ReplicaIDV4(t), t.Generation, t.AssignmentNonce)
}

// TicketDigestV4 is "sha256:" + hex(sha256(canonical JSON of the complete
// signed ticket)). Attestation v2 and the public manifest v2 bind to it.
func TicketDigestV4(t TicketV4) (string, error) {
	encoded, err := assignment.CanonicalJSON(t)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// ReceiptDigestV4 is "sha256:" + hex(sha256(canonical JSON of the complete
// signed receipt)). The public manifest v2 binds each replica to it.
func ReceiptDigestV4(r ReceiptV4) (string, error) {
	encoded, err := assignment.CanonicalJSON(r)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func lowercaseHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
