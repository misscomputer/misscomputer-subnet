// SPDX-License-Identifier: AGPL-3.0-only

package protocol

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"
)

// Probe attestation constants mirror the Python miner-probe-attestation v1
// contract in misscomputer_subnet.assignment_probe. Header names are the
// canonical wire spellings; Go's HTTP layer compares them case-insensitively.
const (
	ProbeNonceHeader              = "X-Miss-Probe-Nonce"
	ProbeAttestationHeader        = "X-Miss-Probe-Attestation"
	ProbeAttestationSchema        = "miss.computer/misscomputer-subnet/miner-probe-attestation"
	ProbeAttestationSchemaVersion = 1
	ProbeAttestationPurpose       = "miner_probe_response_attestation_v1"
	ProbeAttestationAlgorithm     = "ed25519"
	// MaxProbeAttestationBytes bounds the canonical JSON form; the Python
	// verifier rejects longer documents and base64 headers above twice this.
	MaxProbeAttestationBytes = 8 * 1024
)

var probeAttestationSignatureDomain = []byte(
	"miss.computer/misscomputer-subnet/miner-probe-attestation/v1/ed25519",
)

// ProbeAttestation is the miner service-key statement binding one probe nonce
// to one served challenge payload. Field declaration order is the canonical
// sorted-key order, so encoding/json emits byte-for-byte the same document the
// Python verifier canonicalizes with sort_keys and "," / ":" separators; every
// field is validated to the schema's ASCII patterns before it is encoded.
type ProbeAttestation struct {
	Algorithm             string `json:"algorithm"`
	AssignmentNonce       string `json:"assignment_nonce"`
	DeploymentID          string `json:"deployment_id"`
	EndpointID            string `json:"endpoint_id"`
	Generation            uint64 `json:"generation"`
	MinerHotkey           string `json:"miner_hotkey"`
	MinerServicePublicKey string `json:"miner_service_public_key"`
	MinerUID              uint16 `json:"miner_uid"`
	ProbeNonce            string `json:"probe_nonce"`
	Purpose               string `json:"purpose"`
	ResponseBodySHA256    string `json:"response_body_sha256"`
	ResponseStatus        int    `json:"response_status"`
	RouteHost             string `json:"route_host"`
	Schema                string `json:"schema"`
	SchemaVersion         int    `json:"schema_version"`
	SignatureHex          string `json:"signature_hex,omitempty"`
}

// CanonicalProbeNonce reports whether one probe nonce header value is exactly
// the canonical 64-character lowercase-hex encoding of 32 fresh random bytes.
func CanonicalProbeNonce(value string) bool {
	return lowercaseHex(value, 64)
}

// BuildProbeAttestation derives the only statement a miner service key may
// sign for one probe: that the bound assignment identity served the ticket's
// exact signed challenge body for one caller-chosen nonce. It fails closed on
// unbound or legacy tickets and on any response digest other than the signed
// challenge digest, so the producer can never become a general signing oracle.
func BuildProbeAttestation(ticket Ticket, probeNonce, responseBodySHA256 string) (ProbeAttestation, error) {
	if ticket.Version != BoundVersion || ticket.Subnet == nil {
		return ProbeAttestation{}, errors.New("probe attestation requires a bound assignment ticket")
	}
	binding := ticket.Subnet
	if binding.MinerUID == nil {
		return ProbeAttestation{}, errors.New("probe attestation requires the bound miner UID")
	}
	if ticket.MinerID != binding.MinerHotkey {
		return ProbeAttestation{}, errors.New("probe attestation ticket identity mismatch")
	}
	if !lowercaseHex(responseBodySHA256, 64) || responseBodySHA256 != ticket.ChallengeSHA256 {
		return ProbeAttestation{}, errors.New("probe attestation body digest must equal the signed challenge digest")
	}
	attestation := ProbeAttestation{
		Algorithm:             ProbeAttestationAlgorithm,
		AssignmentNonce:       ticket.AssignmentNonce,
		DeploymentID:          ticket.DeploymentID,
		EndpointID:            EndpointID(ticket),
		Generation:            ticket.Generation,
		MinerHotkey:           binding.MinerHotkey,
		MinerServicePublicKey: binding.MinerServicePublicKey,
		MinerUID:              *binding.MinerUID,
		ProbeNonce:            probeNonce,
		Purpose:               ProbeAttestationPurpose,
		ResponseBodySHA256:    responseBodySHA256,
		ResponseStatus:        http.StatusOK,
		RouteHost:             ticket.RouteHost,
		Schema:                ProbeAttestationSchema,
		SchemaVersion:         ProbeAttestationSchemaVersion,
	}
	if err := attestation.validate(false); err != nil {
		return ProbeAttestation{}, err
	}
	return attestation, nil
}

// ProbeAttestationSigningMessage returns the only domain-separated bytes a
// miner service key signs: the domain, one NUL, and the canonical unsigned
// attestation document without its signature_hex member.
func ProbeAttestationSigningMessage(attestation ProbeAttestation) ([]byte, error) {
	if err := attestation.validate(attestation.SignatureHex != ""); err != nil {
		return nil, err
	}
	attestation.SignatureHex = ""
	document, err := json.Marshal(attestation)
	if err != nil {
		return nil, err
	}
	message := make([]byte, 0, len(probeAttestationSignatureDomain)+1+len(document))
	message = append(message, probeAttestationSignatureDomain...)
	message = append(message, 0x00)
	return append(message, document...), nil
}

// SignProbeAttestation signs one canonical unsigned attestation in place.
func SignProbeAttestation(attestation *ProbeAttestation, key ed25519.PrivateKey) error {
	if attestation == nil || len(key) != ed25519.PrivateKeySize {
		return errors.New("invalid probe attestation signing input")
	}
	if attestation.SignatureHex != "" {
		return errors.New("probe attestation is already signed")
	}
	if err := attestation.validate(false); err != nil {
		return err
	}
	if hex.EncodeToString(key.Public().(ed25519.PublicKey)) != attestation.MinerServicePublicKey {
		return errors.New("probe attestation signer is not the bound miner service key")
	}
	message, err := ProbeAttestationSigningMessage(*attestation)
	if err != nil {
		return err
	}
	attestation.SignatureHex = hex.EncodeToString(ed25519.Sign(key, message))
	return nil
}

// VerifyProbeAttestation checks the canonical shape and the domain-separated
// Ed25519 signature under the attested miner service public key.
func VerifyProbeAttestation(attestation ProbeAttestation, key ed25519.PublicKey) error {
	if len(key) != ed25519.PublicKeySize {
		return errors.New("invalid probe attestation verification key")
	}
	if err := attestation.validate(true); err != nil {
		return err
	}
	if hex.EncodeToString(key) != attestation.MinerServicePublicKey {
		return errors.New("probe attestation key does not match the attested service key")
	}
	signature, err := hex.DecodeString(attestation.SignatureHex)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("probe attestation signature is invalid")
	}
	message, err := ProbeAttestationSigningMessage(attestation)
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, message, signature) {
		return errors.New("probe attestation signature is invalid")
	}
	return nil
}

// EncodeProbeAttestationHeader renders one signed attestation as the base64
// canonical-JSON response header value.
func EncodeProbeAttestationHeader(attestation ProbeAttestation) (string, error) {
	if err := attestation.validate(true); err != nil {
		return "", err
	}
	document, err := json.Marshal(attestation)
	if err != nil {
		return "", err
	}
	if len(document) > MaxProbeAttestationBytes {
		return "", errors.New("probe attestation exceeds the canonical size bound")
	}
	return base64.StdEncoding.EncodeToString(document), nil
}

// DecodeProbeAttestationHeader parses one header value and fails closed unless
// it is canonical base64 of the exact canonical signed JSON document.
func DecodeProbeAttestationHeader(value string) (ProbeAttestation, error) {
	if value == "" || len(value) > MaxProbeAttestationBytes*2 {
		return ProbeAttestation{}, errors.New("probe attestation header size is invalid")
	}
	document, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(document) == 0 || len(document) > MaxProbeAttestationBytes ||
		base64.StdEncoding.EncodeToString(document) != value {
		return ProbeAttestation{}, errors.New("probe attestation header encoding is invalid")
	}
	var attestation ProbeAttestation
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&attestation); err != nil {
		return ProbeAttestation{}, errors.New("probe attestation document is invalid")
	}
	if decoder.More() {
		return ProbeAttestation{}, errors.New("probe attestation document is invalid")
	}
	if err := attestation.validate(true); err != nil {
		return ProbeAttestation{}, err
	}
	canonical, err := json.Marshal(attestation)
	if err != nil || !bytes.Equal(canonical, document) {
		return ProbeAttestation{}, errors.New("probe attestation document is not canonical")
	}
	return attestation, nil
}

func (a ProbeAttestation) validate(requireSignature bool) error {
	if a.Schema != ProbeAttestationSchema || a.SchemaVersion != ProbeAttestationSchemaVersion ||
		a.Purpose != ProbeAttestationPurpose || a.Algorithm != ProbeAttestationAlgorithm {
		return errors.New("probe attestation contract identity is invalid")
	}
	if !CanonicalProbeNonce(a.ProbeNonce) {
		return errors.New("probe attestation nonce must be 64 lowercase hex characters")
	}
	if !probeRouteHost(a.RouteHost) {
		return errors.New("probe attestation route host is invalid")
	}
	if !probeDNSLabel(a.DeploymentID) {
		return errors.New("probe attestation deployment ID is invalid")
	}
	if a.Generation < 1 || a.Generation > math.MaxInt64 {
		return errors.New("probe attestation generation is out of range")
	}
	if !lowercaseHex(a.AssignmentNonce, 32) {
		return errors.New("probe attestation assignment nonce is invalid")
	}
	if !probeHotkey(a.MinerHotkey) {
		return errors.New("probe attestation miner hotkey is invalid")
	}
	if !lowercaseHex(a.MinerServicePublicKey, 64) {
		return errors.New("probe attestation miner service public key is invalid")
	}
	expectedEndpoint := fmt.Sprintf("%s-%s-g%d-%s", a.DeploymentID, a.MinerHotkey, a.Generation, a.AssignmentNonce)
	if a.EndpointID != expectedEndpoint || len(a.EndpointID) < 3 || len(a.EndpointID) > 320 {
		return errors.New("probe attestation endpoint identity is invalid")
	}
	if a.ResponseStatus != http.StatusOK {
		return errors.New("probe attestation response status must be 200")
	}
	if !lowercaseHex(a.ResponseBodySHA256, 64) {
		return errors.New("probe attestation response body digest is invalid")
	}
	if requireSignature {
		if !lowercaseHex(a.SignatureHex, 128) {
			return errors.New("probe attestation signature encoding is invalid")
		}
	} else if a.SignatureHex != "" && !lowercaseHex(a.SignatureHex, 128) {
		return errors.New("probe attestation signature encoding is invalid")
	}
	return nil
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

func probeHotkey(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'z') &&
			(character < 'A' || character > 'Z') {
			return false
		}
	}
	return true
}

func probeDNSLabel(value string) bool {
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

func probeRouteHost(value string) bool {
	if len(value) > 253 {
		return false
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if !probeDNSLabel(label) {
			return false
		}
	}
	return true
}
