// SPDX-License-Identifier: AGPL-3.0-only

package static

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"regexp"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/organic"
)

// The static-site release (§7.1) and its dedicated trust policy (§7.2). A
// release is signed by the static release authority, never by a validator,
// miner or customer key; site_digest alone authorizes nothing. This file is
// not part of the handler implementation digest: it decides which site may be
// served, not how a site is served.

const (
	ReleaseSchema     = organic.SchemaPrefix + "static-site-release"
	TrustPolicySchema = organic.SchemaPrefix + "static-site-release-trust-policy"
	// ProducerPolicyVersion is the only producer policy this build implements.
	ProducerPolicyVersion = "static-producer-policy.v1"

	MaxReleaseBytes     = 16 << 10
	MaxTrustPolicyBytes = 256 << 10
	maxReleaseKeys      = 16
)

var (
	releaseDomain        = []byte("miss.computer/misscomputer-subnet/static-site-release/v1/ed25519")
	keyIDPattern         = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9_-]{0,62}[a-z0-9])?$`)
	policyVersionPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$`)
	signatureHexPattern  = regexp.MustCompile(`^[0-9a-f]{128}$`)
)

// ReleaseCode is the stable failure vocabulary of release verification. The
// values equal the public validator's static-index abstention codes.
type ReleaseCode string

const (
	ReleaseTrustPolicyInvalid           ReleaseCode = "trust_policy_invalid"
	ReleaseTrustPolicyDigestMismatch    ReleaseCode = "trust_policy_digest_mismatch"
	ReleaseInvalid                      ReleaseCode = "release_invalid"
	ReleaseDigestMismatch               ReleaseCode = "release_digest_mismatch"
	ReleaseBindingMismatch              ReleaseCode = "release_binding_mismatch"
	ReleaseSignerUntrusted              ReleaseCode = "signer_untrusted"
	ReleaseSignerOutsideValidity        ReleaseCode = "signer_outside_validity"
	ReleaseSignatureInvalid             ReleaseCode = "signature_invalid"
	ReleaseProducerPolicyUnsupported    ReleaseCode = "producer_policy_unsupported"
	ReleaseServerImplementationMismatch ReleaseCode = "server_implementation_mismatch"
)

// ReleaseError carries one ReleaseCode.
type ReleaseError struct {
	Code ReleaseCode
	Err  error
}

func (e *ReleaseError) Error() string { return string(e.Code) + ": " + e.Err.Error() }

func (e *ReleaseError) Unwrap() error { return e.Err }

func releaseFail(code ReleaseCode, message string) error {
	return &ReleaseError{Code: code, Err: errors.New(message)}
}

// Release is static-site-release v1.
type Release struct {
	IssuedAt                   string `json:"issued_at"`
	ProducerPolicyVersion      string `json:"producer_policy_version"`
	Schema                     string `json:"schema"`
	SchemaVersion              int    `json:"schema_version"`
	ServerImplementationDigest string `json:"server_implementation_digest"`
	Signature                  string `json:"signature"`
	SignerKeyID                string `json:"signer_key_id"`
	SiteDigest                 string `json:"site_digest"`
}

func (r Release) Validate() error {
	if r.Schema != ReleaseSchema || r.SchemaVersion != 1 || !organic.ValidTimestamp(r.IssuedAt) ||
		!policyVersionPattern.MatchString(r.ProducerPolicyVersion) || !organic.ValidDigest(r.ServerImplementationDigest) ||
		!signatureHexPattern.MatchString(r.Signature) || !keyIDPattern.MatchString(r.SignerKeyID) ||
		!organic.ValidDigest(r.SiteDigest) {
		return errors.New("static site release fields are invalid")
	}
	return nil
}

// ReleaseMessage is the only byte string a release key signs: the domain,
// NUL, and the canonical release without its signature member.
func ReleaseMessage(r Release) ([]byte, error) {
	unsigned := map[string]any{
		"issued_at": r.IssuedAt, "producer_policy_version": r.ProducerPolicyVersion, "schema": r.Schema,
		"schema_version": r.SchemaVersion, "server_implementation_digest": r.ServerImplementationDigest,
		"signer_key_id": r.SignerKeyID, "site_digest": r.SiteDigest,
	}
	encoded, err := organic.Canonical(unsigned)
	if err != nil {
		return nil, err
	}
	return append(append(append([]byte{}, releaseDomain...), 0), encoded...), nil
}

// ReleaseKey is one trusted release key with its validity window.
type ReleaseKey struct {
	Algorithm       string `json:"algorithm"`
	KeyID           string `json:"key_id"`
	PublicKeyHex    string `json:"public_key_hex"`
	ValidFromEpoch  int64  `json:"valid_from_epoch"`
	ValidUntilEpoch int64  `json:"valid_until_epoch"`
}

// TrustPolicy is static-site-release-trust-policy v1; the threshold is 1.
type TrustPolicy struct {
	DigestSHA256  string       `json:"digest_sha256"`
	PolicyID      string       `json:"policy_id"`
	Schema        string       `json:"schema"`
	SchemaVersion int          `json:"schema_version"`
	TrustedKeys   []ReleaseKey `json:"trusted_keys"`
}

func (p TrustPolicy) Validate() error {
	if p.Schema != TrustPolicySchema || p.SchemaVersion != 1 || !keyIDPattern.MatchString(p.PolicyID) ||
		!organic.ValidHex64(p.DigestSHA256) || len(p.TrustedKeys) < 1 || len(p.TrustedKeys) > maxReleaseKeys {
		return errors.New("static release trust policy fields are invalid")
	}
	ids, keys := map[string]bool{}, map[string]bool{}
	for _, key := range p.TrustedKeys {
		if key.Algorithm != "ed25519" || !keyIDPattern.MatchString(key.KeyID) || !organic.ValidHex64(key.PublicKeyHex) ||
			key.ValidFromEpoch < 0 || key.ValidUntilEpoch <= key.ValidFromEpoch || ids[key.KeyID] || keys[key.PublicKeyHex] {
			return errors.New("static release trust policy key is invalid or duplicated")
		}
		ids[key.KeyID], keys[key.PublicKeyHex] = true, true
	}
	self, err := organic.DigestWithout(p, "digest_sha256")
	if err != nil || self != p.DigestSHA256 {
		return errors.New("static release trust policy self-digest does not match")
	}
	return nil
}

// ParseTrustPolicy accepts only canonical stored policy bytes whose
// self-digest equals pinnedDigestSHA256, the out-of-band pin.
func ParseTrustPolicy(stored []byte, pinnedDigestSHA256 string) (TrustPolicy, error) {
	var policy TrustPolicy
	if len(stored) > MaxTrustPolicyBytes {
		return TrustPolicy{}, releaseFail(ReleaseTrustPolicyInvalid, "trust policy exceeds its size limit")
	}
	if err := organic.DecodeCanonical(stored, &policy); err != nil {
		return TrustPolicy{}, &ReleaseError{Code: ReleaseTrustPolicyInvalid, Err: err}
	}
	if policy.DigestSHA256 != pinnedDigestSHA256 {
		return TrustPolicy{}, releaseFail(ReleaseTrustPolicyDigestMismatch, "trust policy is not the pinned policy")
	}
	return policy, nil
}

// ParseRelease accepts only stored release bytes whose SHA-256 is
// releaseDigest and that decode canonically.
func ParseRelease(stored []byte, releaseDigest string) (Release, error) {
	if len(stored) == 0 || len(stored) > MaxReleaseBytes || Digest(stored) != releaseDigest {
		return Release{}, releaseFail(ReleaseDigestMismatch, "release bytes do not match the bound release digest")
	}
	var release Release
	if err := organic.DecodeCanonical(stored, &release); err != nil {
		return Release{}, &ReleaseError{Code: ReleaseInvalid, Err: err}
	}
	return release, nil
}

// VerifyRelease applies §7.2: the release binds siteDigest, a policy key
// valid at issued_at signed it, this build implements its producer policy,
// and it authorizes exactly this build's handler implementation.
func VerifyRelease(r Release, policy TrustPolicy, siteDigest string) error {
	if r.SiteDigest != siteDigest {
		return releaseFail(ReleaseBindingMismatch, "release names another site")
	}
	var key *ReleaseKey
	for index := range policy.TrustedKeys {
		if policy.TrustedKeys[index].KeyID == r.SignerKeyID {
			key = &policy.TrustedKeys[index]
		}
	}
	if key == nil {
		return releaseFail(ReleaseSignerUntrusted, "release signer is not in the trust policy")
	}
	issued, err := time.Parse(time.RFC3339Nano, r.IssuedAt)
	if err != nil {
		return &ReleaseError{Code: ReleaseInvalid, Err: err}
	}
	if seconds := issued.Unix(); seconds < key.ValidFromEpoch || seconds >= key.ValidUntilEpoch {
		return releaseFail(ReleaseSignerOutsideValidity, "release was issued outside its key's validity window")
	}
	public, _ := hex.DecodeString(key.PublicKeyHex)
	signature, _ := hex.DecodeString(r.Signature)
	message, err := ReleaseMessage(r)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(public), message, signature) {
		return releaseFail(ReleaseSignatureInvalid, "release signature does not verify")
	}
	if r.ProducerPolicyVersion != ProducerPolicyVersion {
		return releaseFail(ReleaseProducerPolicyUnsupported, "release names an unimplemented producer policy")
	}
	if r.ServerImplementationDigest != ServerImplementationDigest {
		return releaseFail(ReleaseServerImplementationMismatch, "release authorizes another handler implementation")
	}
	return nil
}

// ReleaseCodeOf returns the code carried by err, or "".
func ReleaseCodeOf(err error) ReleaseCode {
	var coded *ReleaseError
	if errors.As(err, &coded) {
		return coded.Code
	}
	return ""
}
