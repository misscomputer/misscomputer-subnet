// SPDX-License-Identifier: AGPL-3.0-only

package protocol

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/organic"
	"github.com/misscomputer/misscomputer-subnet/pkg/sandbox"
)

// sandbox-lease-v1 documents (docs/sandbox-lease-v1.md). They are separate
// from deployment.v4 and static-site-v1: each has its own schema and signing
// domain, so no sandbox signature verifies as any other document, even when
// the same validator or miner service key signs both.
const (
	SandboxReservationSchema = organic.SchemaPrefix + "sandbox-reservation-ticket"
	SandboxLeaseSchema       = organic.SchemaPrefix + "sandbox-lease-ticket"
	SandboxRenewalSchema     = organic.SchemaPrefix + "sandbox-lease-renewal"
	SandboxReleaseSchema     = organic.SchemaPrefix + "sandbox-lease-release"
	SandboxReceiptSchema     = organic.SchemaPrefix + "sandbox-lease-receipt"
	SandboxSchemaVersion     = 1

	SandboxReservationSigningDomain = SandboxReservationSchema + "/v1/ed25519"
	SandboxLeaseSigningDomain       = SandboxLeaseSchema + "/v1/ed25519"
	SandboxRenewalSigningDomain     = SandboxRenewalSchema + "/v1/ed25519"
	SandboxReleaseSigningDomain     = SandboxReleaseSchema + "/v1/ed25519"
	SandboxReceiptSigningDomain     = SandboxReceiptSchema + "/v1/ed25519"
)

var sandboxIDPattern = regexp.MustCompile(`^sbx-[0-9a-f]{32}$`)

// ValidSandboxID reports whether value is "sbx-" plus 32 lowercase hex.
func ValidSandboxID(value string) bool { return sandboxIDPattern.MatchString(value) }

// SandboxReservationV1 asks one miner to hold capacity for one sandbox
// identity until hold_expires_at. It names no workload and starts nothing.
type SandboxReservationV1 struct {
	Generation       uint64                 `json:"generation"`
	HoldExpiresAt    string                 `json:"hold_expires_at"`
	IssuedAt         string                 `json:"issued_at"`
	MinerID          string                 `json:"miner_id"`
	ReservationNonce string                 `json:"reservation_nonce"`
	Resources        sandbox.Resources      `json:"resources"`
	SandboxID        string                 `json:"sandbox_id"`
	Schema           string                 `json:"schema"`
	SchemaVersion    int                    `json:"schema_version"`
	Signature        string                 `json:"signature"`
	Subnet           *StaticSubnetBindingV1 `json:"subnet"`
	WorkloadKind     string                 `json:"workload_kind"`
}

// SandboxLeaseV1 commits exactly one held reservation to one digest-pinned
// OCI image under a hard, renewable expiry.
type SandboxLeaseV1 struct {
	AssignmentNonce   string                 `json:"assignment_nonce"`
	Env               map[string]string      `json:"env"` // always {} in v1; see sandbox.ValidateEnv
	Generation        uint64                 `json:"generation"`
	ImageDigest       string                 `json:"image_digest"`
	ImageReference    string                 `json:"image_reference"`
	Isolation         string                 `json:"isolation"`
	IssuedAt          string                 `json:"issued_at"`
	LeaseExpiresAt    string                 `json:"lease_expires_at"`
	MinerID           string                 `json:"miner_id"`
	Network           sandbox.NetworkPolicy  `json:"network"`
	ReservationDigest string                 `json:"reservation_digest"`
	Resources         sandbox.Resources      `json:"resources"`
	SandboxID         string                 `json:"sandbox_id"`
	Schema            string                 `json:"schema"`
	SchemaVersion     int                    `json:"schema_version"`
	SecretEnv         sandbox.SecretEnv      `json:"secret_env"`
	Signature         string                 `json:"signature"`
	Subnet            *StaticSubnetBindingV1 `json:"subnet"`
	WorkloadKind      string                 `json:"workload_kind"`
}

// SandboxRenewalV1 extends one lease. renewal_seq is strictly increasing
// per lease and lease_expires_at strictly later than the current expiry.
type SandboxRenewalV1 struct {
	Generation     uint64                 `json:"generation"`
	IssuedAt       string                 `json:"issued_at"`
	LeaseDigest    string                 `json:"lease_digest"`
	LeaseExpiresAt string                 `json:"lease_expires_at"`
	LeaseID        string                 `json:"lease_id"`
	MinerID        string                 `json:"miner_id"`
	RenewalSeq     uint64                 `json:"renewal_seq"`
	SandboxID      string                 `json:"sandbox_id"`
	Schema         string                 `json:"schema"`
	SchemaVersion  int                    `json:"schema_version"`
	Signature      string                 `json:"signature"`
	Subnet         *StaticSubnetBindingV1 `json:"subnet"`
}

// SandboxReleaseV1 cancels the hold and lease of one (sandbox_id,
// generation, miner) identity. It may arrive before the document it cancels
// and then fences that identity permanently.
type SandboxReleaseV1 struct {
	Generation    uint64                 `json:"generation"`
	IssuedAt      string                 `json:"issued_at"`
	MinerID       string                 `json:"miner_id"`
	Reason        string                 `json:"reason"`
	SandboxID     string                 `json:"sandbox_id"`
	Schema        string                 `json:"schema"`
	SchemaVersion int                    `json:"schema_version"`
	Signature     string                 `json:"signature"`
	Subnet        *StaticSubnetBindingV1 `json:"subnet"`
}

// SandboxReceiptV1 is the miner-signed answer to one validator document.
// The capacity members are self-reported diagnostics and never raise the
// capacity a validator places against.
type SandboxReceiptV1 struct {
	CapacityActive sandbox.Capacity       `json:"capacity_active"`
	CapacityHeld   sandbox.Capacity       `json:"capacity_held"`
	CapacityTotal  sandbox.Capacity       `json:"capacity_total"`
	DocumentDigest string                 `json:"document_digest"`
	DocumentSchema string                 `json:"document_schema"`
	ErrorCode      *string                `json:"error_code"`
	Generation     uint64                 `json:"generation"`
	LeaseID        *string                `json:"lease_id"`
	MinerID        string                 `json:"miner_id"`
	ObservedAt     string                 `json:"observed_at"`
	RenewalSeq     uint64                 `json:"renewal_seq"`
	SandboxID      string                 `json:"sandbox_id"`
	Schema         string                 `json:"schema"`
	SchemaVersion  int                    `json:"schema_version"`
	Signature      string                 `json:"signature"`
	Stage          string                 `json:"stage"`
	Subnet         *StaticSubnetBindingV1 `json:"subnet"`
}

// SandboxHoldIDV1 and SandboxLeaseIDV1 share the deployment.v4 endpoint
// derivation shape, so deterministic runtime naming applies unchanged.
func SandboxHoldIDV1(r SandboxReservationV1) string {
	return sandboxIdentity(r.SandboxID, r.MinerID, r.Generation, r.ReservationNonce)
}

func SandboxLeaseIDV1(l SandboxLeaseV1) string {
	return sandboxIdentity(l.SandboxID, l.MinerID, l.Generation, l.AssignmentNonce)
}

func sandboxIdentity(sandboxID, minerID string, generation uint64, nonce string) string {
	return fmt.Sprintf("%s-%s-g%d-%s", sandboxID, minerID, generation, nonce)
}

func validSandboxIdentity(sandboxID, minerID string, generation uint64) bool {
	return ValidSandboxID(sandboxID) && organic.ValidHotkey(minerID) && generation >= 1
}

func validateSandboxBinding(subnet *StaticSubnetBindingV1, minerID string) error {
	if err := ValidateSubnetBinding(subnet.Binding()); err != nil {
		return err
	}
	if subnet.MinerHotkey != minerID {
		return errors.New("miner_id_mismatch")
	}
	return nil
}

func validateSandboxWindow(issuedAt, expiresAt string, maximum time.Duration, name string) error {
	issued, issuedErr := parseStaticTime(issuedAt)
	expires, expiresErr := parseStaticTime(expiresAt)
	if issuedErr != nil || expiresErr != nil || !expires.After(issued) || expires.Sub(issued) > maximum {
		return errors.New(name + "_window_invalid")
	}
	return nil
}

func validateSandboxSignature(signature, kind string) error {
	if !lowercaseHex(signature, 128) {
		return errors.New("sandbox " + kind + " signature must be 128 lowercase hex")
	}
	return nil
}

// Validate checks a received reservation; the signature must be present.
func (r SandboxReservationV1) Validate() error {
	if err := validateSandboxSignature(r.Signature, "reservation"); err != nil {
		return err
	}
	return r.validateUnsigned()
}

func (r SandboxReservationV1) validateUnsigned() error {
	if r.Schema != SandboxReservationSchema || r.SchemaVersion != SandboxSchemaVersion || r.WorkloadKind != sandbox.WorkloadKind {
		return errors.New("sandbox reservation schema or workload kind is invalid")
	}
	if !validSandboxIdentity(r.SandboxID, r.MinerID, r.Generation) || !lowercaseHex(r.ReservationNonce, 32) {
		return errors.New("sandbox reservation identity is invalid")
	}
	if err := r.Resources.Validate(); err != nil {
		return err
	}
	if err := validateSandboxWindow(r.IssuedAt, r.HoldExpiresAt, sandbox.MaxHold, "hold"); err != nil {
		return err
	}
	return validateSandboxBinding(r.Subnet, r.MinerID)
}

// Validate checks a received lease; the signature must be present.
func (l SandboxLeaseV1) Validate() error {
	if err := validateSandboxSignature(l.Signature, "lease"); err != nil {
		return err
	}
	return l.validateUnsigned()
}

func (l SandboxLeaseV1) validateUnsigned() error {
	if l.Schema != SandboxLeaseSchema || l.SchemaVersion != SandboxSchemaVersion || l.WorkloadKind != sandbox.WorkloadKind {
		return errors.New("sandbox lease schema or workload kind is invalid")
	}
	if !validSandboxIdentity(l.SandboxID, l.MinerID, l.Generation) || !lowercaseHex(l.AssignmentNonce, 32) ||
		!organic.ValidDigest(l.ReservationDigest) {
		return errors.New("sandbox lease identity is invalid")
	}
	if digest, ok := sandbox.ImageDigest(l.ImageReference); !ok || digest != l.ImageDigest {
		return errors.New("image_reference must pin image_digest")
	}
	if !sandbox.ValidIsolation(l.Isolation) {
		return errors.New("sandbox isolation is invalid")
	}
	if err := l.Resources.Validate(); err != nil {
		return err
	}
	if err := l.Network.Validate(); err != nil {
		return err
	}
	if err := sandbox.ValidateEnv(l.Env); err != nil {
		return err
	}
	if err := l.SecretEnv.Validate(); err != nil {
		return err
	}
	if err := validateSandboxWindow(l.IssuedAt, l.LeaseExpiresAt, sandbox.MaxLeaseWindow, "lease"); err != nil {
		return err
	}
	return validateSandboxBinding(l.Subnet, l.MinerID)
}

// Validate checks a received renewal; the signature must be present.
func (r SandboxRenewalV1) Validate() error {
	if err := validateSandboxSignature(r.Signature, "renewal"); err != nil {
		return err
	}
	return r.validateUnsigned()
}

func (r SandboxRenewalV1) validateUnsigned() error {
	if r.Schema != SandboxRenewalSchema || r.SchemaVersion != SandboxSchemaVersion {
		return errors.New("sandbox renewal schema is invalid")
	}
	if !validSandboxIdentity(r.SandboxID, r.MinerID, r.Generation) || r.RenewalSeq < 1 || !organic.ValidDigest(r.LeaseDigest) {
		return errors.New("sandbox renewal identity is invalid")
	}
	prefix := sandboxIdentity(r.SandboxID, r.MinerID, r.Generation, "")
	if !strings.HasPrefix(r.LeaseID, prefix) || !lowercaseHex(strings.TrimPrefix(r.LeaseID, prefix), 32) {
		return errors.New("lease_id does not name the renewed sandbox")
	}
	if err := validateSandboxWindow(r.IssuedAt, r.LeaseExpiresAt, sandbox.MaxLeaseWindow, "renewal"); err != nil {
		return err
	}
	return validateSandboxBinding(r.Subnet, r.MinerID)
}

// Validate checks a received release; the signature must be present.
func (r SandboxReleaseV1) Validate() error {
	if err := validateSandboxSignature(r.Signature, "release"); err != nil {
		return err
	}
	return r.validateUnsigned()
}

func (r SandboxReleaseV1) validateUnsigned() error {
	if r.Schema != SandboxReleaseSchema || r.SchemaVersion != SandboxSchemaVersion {
		return errors.New("sandbox release schema is invalid")
	}
	if !validSandboxIdentity(r.SandboxID, r.MinerID, r.Generation) || !sandbox.ValidReleaseReason(r.Reason) {
		return errors.New("sandbox release identity is invalid")
	}
	if _, err := parseStaticTime(r.IssuedAt); err != nil {
		return err
	}
	return validateSandboxBinding(r.Subnet, r.MinerID)
}

// sandboxReceiptStages lists the stages that may answer each document.
var sandboxReceiptStages = map[string]map[string]bool{
	SandboxReservationSchema: {sandbox.StageHeld: true, sandbox.StageRefused: true},
	SandboxLeaseSchema: {sandbox.StageAccepted: true, sandbox.StageReady: true, sandbox.StageFailed: true,
		sandbox.StageReleased: true, sandbox.StageExpired: true},
	SandboxRenewalSchema: {sandbox.StageAccepted: true, sandbox.StageReady: true, sandbox.StageFailed: true, sandbox.StageReleased: true, sandbox.StageExpired: true},
	SandboxReleaseSchema: {sandbox.StageReleased: true},
}

// Validate checks a received receipt; the signature must be present.
func (r SandboxReceiptV1) Validate() error {
	if err := validateSandboxSignature(r.Signature, "receipt"); err != nil {
		return err
	}
	return r.validateUnsigned()
}

func (r SandboxReceiptV1) validateUnsigned() error {
	if r.Schema != SandboxReceiptSchema || r.SchemaVersion != SandboxSchemaVersion {
		return errors.New("sandbox receipt schema is invalid")
	}
	if !validSandboxIdentity(r.SandboxID, r.MinerID, r.Generation) || !organic.ValidDigest(r.DocumentDigest) {
		return errors.New("sandbox receipt identity is invalid")
	}
	stages, known := sandboxReceiptStages[r.DocumentSchema]
	if !known || !stages[r.Stage] {
		return errors.New("receipt stage does not answer document_schema")
	}
	failing := r.Stage == sandbox.StageRefused || r.Stage == sandbox.StageFailed
	if failing != (r.ErrorCode != nil) {
		return errors.New("receipt_error_code_invalid")
	}
	if r.ErrorCode != nil {
		if _, known := sandbox.ReceiptErrorAttribution[*r.ErrorCode]; !known {
			return errors.New("receipt error_code is unknown")
		}
	}
	switch r.DocumentSchema {
	case SandboxReservationSchema:
		if r.LeaseID != nil || r.RenewalSeq != 0 {
			return errors.New("reservation receipt names a lease")
		}
	case SandboxLeaseSchema, SandboxRenewalSchema:
		if r.LeaseID == nil {
			return errors.New("lease receipt must name its lease")
		}
	}
	if r.LeaseID != nil {
		prefix := sandboxIdentity(r.SandboxID, r.MinerID, r.Generation, "")
		if !strings.HasPrefix(*r.LeaseID, prefix) || !lowercaseHex(strings.TrimPrefix(*r.LeaseID, prefix), 32) {
			return errors.New("receipt lease_id does not name the sandbox")
		}
	}
	if !r.CapacityHeld.Plus(r.CapacityActive).Within(r.CapacityTotal) ||
		!r.CapacityHeld.Within(r.CapacityTotal) || !r.CapacityActive.Within(r.CapacityTotal) {
		return errors.New("receipt_capacity_invalid")
	}
	if _, err := parseStaticTime(r.ObservedAt); err != nil {
		return err
	}
	return validateSandboxBinding(r.Subnet, r.MinerID)
}

// SignSandboxReservationV1 signs r with the validator Go service key.
func SignSandboxReservationV1(r *SandboxReservationV1, key ed25519.PrivateKey) error {
	if r == nil {
		return errors.New("invalid sandbox reservation signing input")
	}
	return signSandbox(SandboxReservationSigningDomain, r.validateUnsigned, *r, key, &r.Signature)
}

// SignSandboxLeaseV1 signs l with the validator Go service key.
func SignSandboxLeaseV1(l *SandboxLeaseV1, key ed25519.PrivateKey) error {
	if l == nil {
		return errors.New("invalid sandbox lease signing input")
	}
	return signSandbox(SandboxLeaseSigningDomain, l.validateUnsigned, *l, key, &l.Signature)
}

// SignSandboxRenewalV1 signs r with the validator Go service key.
func SignSandboxRenewalV1(r *SandboxRenewalV1, key ed25519.PrivateKey) error {
	if r == nil {
		return errors.New("invalid sandbox renewal signing input")
	}
	return signSandbox(SandboxRenewalSigningDomain, r.validateUnsigned, *r, key, &r.Signature)
}

// SignSandboxReleaseV1 signs r with the validator Go service key.
func SignSandboxReleaseV1(r *SandboxReleaseV1, key ed25519.PrivateKey) error {
	if r == nil {
		return errors.New("invalid sandbox release signing input")
	}
	return signSandbox(SandboxReleaseSigningDomain, r.validateUnsigned, *r, key, &r.Signature)
}

// SignSandboxReceiptV1 signs r with the miner Go service key.
func SignSandboxReceiptV1(r *SandboxReceiptV1, key ed25519.PrivateKey) error {
	if r == nil {
		return errors.New("invalid sandbox receipt signing input")
	}
	return signSandbox(SandboxReceiptSigningDomain, r.validateUnsigned, *r, key, &r.Signature)
}

func signSandbox(domain string, validate func() error, document any, key ed25519.PrivateKey, signature *string) error {
	if len(key) != ed25519.PrivateKeySize {
		return errors.New("invalid sandbox signing key")
	}
	if err := validate(); err != nil {
		return err
	}
	signed, err := signStatic(domain, document, key)
	if err != nil {
		return err
	}
	*signature = signed
	return nil
}

func verifySandbox(domain string, validate func() error, document any, signature, boundKey string, key ed25519.PublicKey) error {
	if err := validate(); err != nil {
		return err
	}
	if len(key) != ed25519.PublicKeySize || !publicKeyMatchesHex(key, boundKey) {
		return errors.New("sandbox document signer is not the bound service key")
	}
	return verifyStatic(domain, document, signature, key)
}

// VerifySandboxReservationV1Signature verifies the bound validator service
// key signature without a wall-clock or chain decision.
func VerifySandboxReservationV1Signature(r SandboxReservationV1, key ed25519.PublicKey) error {
	return verifySandbox(SandboxReservationSigningDomain, r.Validate, r, r.Signature, bindingValidatorKey(r.Subnet), key)
}

// VerifySandboxLeaseV1Signature verifies the bound validator service key
// signature without a wall-clock or chain decision.
func VerifySandboxLeaseV1Signature(l SandboxLeaseV1, key ed25519.PublicKey) error {
	return verifySandbox(SandboxLeaseSigningDomain, l.Validate, l, l.Signature, bindingValidatorKey(l.Subnet), key)
}

// VerifySandboxRenewalV1Signature verifies the bound validator service key
// signature without a wall-clock or chain decision.
func VerifySandboxRenewalV1Signature(r SandboxRenewalV1, key ed25519.PublicKey) error {
	return verifySandbox(SandboxRenewalSigningDomain, r.Validate, r, r.Signature, bindingValidatorKey(r.Subnet), key)
}

// VerifySandboxReleaseV1Signature verifies the bound validator service key
// signature without a wall-clock or chain decision.
func VerifySandboxReleaseV1Signature(r SandboxReleaseV1, key ed25519.PublicKey) error {
	return verifySandbox(SandboxReleaseSigningDomain, r.Validate, r, r.Signature, bindingValidatorKey(r.Subnet), key)
}

// VerifySandboxReceiptV1 verifies the bound miner service key signature.
func VerifySandboxReceiptV1(r SandboxReceiptV1, key ed25519.PublicKey) error {
	minerKey := ""
	if r.Subnet != nil {
		minerKey = r.Subnet.MinerServicePublicKey
	}
	return verifySandbox(SandboxReceiptSigningDomain, r.Validate, r, r.Signature, minerKey, key)
}

func bindingValidatorKey(subnet *StaticSubnetBindingV1) string {
	if subnet == nil {
		return ""
	}
	return subnet.ValidatorServicePublicKey
}

// sandboxAdmission is the window and request-local binding check shared by
// every validator-signed sandbox document: issued_at may lead now by at most
// the issue skew, an expiring document must not have expired, and the
// network, hotkeys, UID and chain block must match the authenticated request.
func sandboxAdmission(subnet *StaticSubnetBindingV1, minerID, issuedAt, expiresAt string, now time.Time, currentBlock uint64, network string, netuid uint16, callerHotkey, minerHotkey string, minerUID *uint16) error {
	issued, _ := parseStaticTime(issuedAt)
	if now.Before(issued.Add(-sandbox.IssueSkew)) {
		return errors.New("sandbox document is not yet valid")
	}
	if expiresAt != "" {
		expires, _ := parseStaticTime(expiresAt)
		if !now.Before(expires) {
			return errors.New("sandbox document has expired")
		}
	}
	return verifyRequestBinding(subnet.Binding(), minerID, currentBlock, network, netuid, callerHotkey, minerHotkey, minerUID)
}

// VerifyBoundSandboxReservationV1 is the miner admission check of a
// reservation: signature, hold window and request-local binding.
func VerifyBoundSandboxReservationV1(r SandboxReservationV1, key ed25519.PublicKey, now time.Time, currentBlock uint64, network string, netuid uint16, callerHotkey, minerHotkey string, minerUID *uint16) error {
	if err := VerifySandboxReservationV1Signature(r, key); err != nil {
		return err
	}
	return sandboxAdmission(r.Subnet, r.MinerID, r.IssuedAt, r.HoldExpiresAt, now, currentBlock, network, netuid, callerHotkey, minerHotkey, minerUID)
}

// VerifyBoundSandboxLeaseV1 is the miner admission check of a lease.
func VerifyBoundSandboxLeaseV1(l SandboxLeaseV1, key ed25519.PublicKey, now time.Time, currentBlock uint64, network string, netuid uint16, callerHotkey, minerHotkey string, minerUID *uint16) error {
	if err := VerifySandboxLeaseV1Signature(l, key); err != nil {
		return err
	}
	return sandboxAdmission(l.Subnet, l.MinerID, l.IssuedAt, l.LeaseExpiresAt, now, currentBlock, network, netuid, callerHotkey, minerHotkey, minerUID)
}

// VerifyBoundSandboxRenewalV1 is the miner admission check of a renewal.
func VerifyBoundSandboxRenewalV1(r SandboxRenewalV1, key ed25519.PublicKey, now time.Time, currentBlock uint64, network string, netuid uint16, callerHotkey, minerHotkey string, minerUID *uint16) error {
	if err := VerifySandboxRenewalV1Signature(r, key); err != nil {
		return err
	}
	return sandboxAdmission(r.Subnet, r.MinerID, r.IssuedAt, r.LeaseExpiresAt, now, currentBlock, network, netuid, callerHotkey, minerHotkey, minerUID)
}

// VerifyBoundSandboxReleaseV1 is the miner admission check of a release. A
// release has no expiry: replaying it only re-applies the same fence.
func VerifyBoundSandboxReleaseV1(r SandboxReleaseV1, key ed25519.PublicKey, now time.Time, currentBlock uint64, network string, netuid uint16, callerHotkey, minerHotkey string, minerUID *uint16) error {
	if err := VerifySandboxReleaseV1Signature(r, key); err != nil {
		return err
	}
	return sandboxAdmission(r.Subnet, r.MinerID, r.IssuedAt, "", now, currentBlock, network, netuid, callerHotkey, minerHotkey, minerUID)
}

// SandboxLeaseCommitsReservationV1 checks that l commits exactly r: the
// reservation digest, identity, resources and the validator and miner
// service identities are the same. A lease that fails it is equivocation.
func SandboxLeaseCommitsReservationV1(r SandboxReservationV1, l SandboxLeaseV1) error {
	digest, err := SandboxDigestV1(r)
	if err != nil {
		return err
	}
	if l.ReservationDigest != digest || l.SandboxID != r.SandboxID || l.Generation != r.Generation || l.MinerID != r.MinerID ||
		l.Resources != r.Resources || !sameSandboxParties(l.Subnet, r.Subnet) {
		return errors.New("sandbox lease does not commit the reservation")
	}
	return nil
}

func sameSandboxParties(left, right *StaticSubnetBindingV1) bool {
	return left != nil && right != nil && left.Network == right.Network && left.NetUID == right.NetUID &&
		left.ValidatorHotkey == right.ValidatorHotkey && left.ValidatorServicePublicKey == right.ValidatorServicePublicKey &&
		left.MinerHotkey == right.MinerHotkey && left.MinerServicePublicKey == right.MinerServicePublicKey
}

// SandboxReceiptAnswersV1 is the validator's acceptance check: the receipt
// names the exact document digest, schema and identity, and its miner and
// validator service identities are the document's.
func SandboxReceiptAnswersV1(r SandboxReceiptV1, documentSchema, documentDigest, sandboxID, minerID string, generation uint64, subnet *StaticSubnetBindingV1) error {
	if r.DocumentSchema != documentSchema || r.DocumentDigest != documentDigest || r.SandboxID != sandboxID ||
		r.MinerID != minerID || r.Generation != generation || !sameSandboxParties(r.Subnet, subnet) {
		return errors.New("sandbox receipt does not answer the document")
	}
	return nil
}

// SandboxDigestV1 is "sha256:" + hex(SHA-256(canonical JSON of the complete
// signed document)), the static-v1 digest rule.
func SandboxDigestV1(document any) (string, error) {
	switch document.(type) {
	case SandboxReservationV1, SandboxLeaseV1, SandboxRenewalV1, SandboxReleaseV1, SandboxReceiptV1:
		return staticDigest(document)
	}
	return "", errors.New("not a sandbox-lease-v1 document")
}
