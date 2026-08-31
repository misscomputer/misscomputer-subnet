// SPDX-License-Identifier: AGPL-3.0-only

package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixtureLabelDigest mirrors tests/python/assignment_probe_context.label_digest.
func fixtureLabelDigest(label string) string {
	sum := sha256.Sum256([]byte(label))
	return hex.EncodeToString(sum[:])
}

// fixtureMinerKey mirrors the deterministic fixture key derivation: the seed
// is the SHA-256 of the fixed label, never real secret material.
func fixtureMinerKey(hotkey string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("miner-service-" + hotkey))
	return ed25519.NewKeyFromSeed(seed[:])
}

func fixtureAttestationTicket() Ticket {
	key := fixtureMinerKey("MinerA")
	uid := uint16(10)
	challengeValue := fixtureLabelDigest("challenge-value-fixture-alpha")
	return Ticket{
		Version:         BoundVersion,
		DeploymentID:    "fixture-alpha",
		Generation:      1,
		MinerID:         "MinerA",
		RouteHost:       "fixture-alpha.mock.local",
		AssignmentNonce: fixtureLabelDigest("nonce-fixture-alpha-MinerA-1")[:32],
		ChallengePath:   "/__challenge/" + fixtureLabelDigest("build-fixture-alpha")[:24],
		ChallengeSHA256: ChallengeDigest(challengeValue),
		Subnet: &SubnetBinding{
			Network:               "finney",
			NetUID:                24,
			ValidatorHotkey:       "ValidatorA",
			MinerHotkey:           "MinerA",
			MinerUID:              &uid,
			MinerServicePublicKey: hex.EncodeToString(key.Public().(ed25519.PublicKey)),
		},
	}
}

func signedFixtureAttestation(t *testing.T) ProbeAttestation {
	t.Helper()
	ticket := fixtureAttestationTicket()
	attestation, err := BuildProbeAttestation(
		ticket,
		fixtureLabelDigest("assignment-probe-fixture-nonce"),
		ticket.ChallengeSHA256,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := SignProbeAttestation(&attestation, fixtureMinerKey("MinerA")); err != nil {
		t.Fatal(err)
	}
	return attestation
}

// TestProbeAttestationReproducesCommittedPythonFixtureBytes proves the Go
// producer emits byte-for-byte the canonical JSON and Ed25519 signature that
// the Python verifier committed as the deterministic v1 fixture.
func TestProbeAttestationReproducesCommittedPythonFixtureBytes(t *testing.T) {
	committed, err := os.ReadFile(filepath.Join("..", "..", "contracts", "fixtures", "miner-probe-attestation.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	attestation := signedFixtureAttestation(t)
	produced, err := json.Marshal(attestation)
	if err != nil {
		t.Fatal(err)
	}
	produced = append(produced, '\n')
	if !bytes.Equal(produced, committed) {
		t.Fatalf("Go canonical attestation diverges from the committed Python fixture:\n got %s\nwant %s", produced, committed)
	}
	var document map[string]any
	if err := json.Unmarshal(committed, &document); err != nil {
		t.Fatal(err)
	}
	if attestation.SignatureHex != document["signature_hex"] {
		t.Fatalf("Go signature %q does not match committed fixture signature %q", attestation.SignatureHex, document["signature_hex"])
	}
	key := fixtureMinerKey("MinerA").Public().(ed25519.PublicKey)
	if err := VerifyProbeAttestation(attestation, key); err != nil {
		t.Fatal(err)
	}
}

func TestProbeAttestationSigningMessageUsesDomainSeparatedUnsignedDocument(t *testing.T) {
	attestation := signedFixtureAttestation(t)
	message, err := ProbeAttestationSigningMessage(attestation)
	if err != nil {
		t.Fatal(err)
	}
	domain := "miss.computer/misscomputer-subnet/miner-probe-attestation/v1/ed25519"
	if !bytes.HasPrefix(message, append([]byte(domain), 0x00)) {
		t.Fatalf("signing message lacks the NUL-separated domain: %q", message[:80])
	}
	if bytes.Contains(message, []byte("signature_hex")) {
		t.Fatal("signing message must exclude signature_hex")
	}
	unsigned := attestation
	unsigned.SignatureHex = ""
	document, err := json.Marshal(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(message[len(domain)+1:], document) {
		t.Fatal("signing message body is not the canonical unsigned document")
	}
}

func TestProbeAttestationHeaderRoundTripIsCanonical(t *testing.T) {
	attestation := signedFixtureAttestation(t)
	header, err := EncodeProbeAttestationHeader(attestation)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeProbeAttestationHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != attestation {
		t.Fatalf("decoded attestation differs: %+v", decoded)
	}
}

func TestProbeAttestationHeaderDecodeRejectsNonCanonicalInput(t *testing.T) {
	attestation := signedFixtureAttestation(t)
	header, err := EncodeProbeAttestationHeader(attestation)
	if err != nil {
		t.Fatal(err)
	}
	document, err := json.Marshal(attestation)
	if err != nil {
		t.Fatal(err)
	}
	reordered := strings.Replace(string(document), `{"algorithm":"ed25519",`, `{`, 1)
	reordered = strings.TrimSuffix(reordered, "}") + `,"algorithm":"ed25519"}`
	rejected := map[string]string{
		"empty":              "",
		"not base64":         "!!!",
		"base64 whitespace":  header[:8] + "\n" + header[8:],
		"trailing garbage":   header + "A",
		"not json":           base64.StdEncoding.EncodeToString([]byte("not-json")),
		"unknown field":      base64.StdEncoding.EncodeToString([]byte(strings.TrimSuffix(string(document), "}") + `,"extra":1}`)),
		"trailing json":      base64.StdEncoding.EncodeToString(append(append([]byte{}, document...), []byte("{}")...)),
		"non-canonical keys": base64.StdEncoding.EncodeToString([]byte(reordered)),
		"whitespace json":    base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(document), `{"algorithm"`, `{ "algorithm"`, 1))),
		"oversized":          base64.StdEncoding.EncodeToString(append(append([]byte{}, document[:len(document)-1]...), bytes.Repeat([]byte(" "), MaxProbeAttestationBytes)...)),
	}
	if strings.HasSuffix(header, "=") {
		rejected["unpadded base64"] = strings.TrimRight(header, "=")
	}
	for name, value := range rejected {
		if _, err := DecodeProbeAttestationHeader(value); err == nil {
			t.Fatalf("%s header was accepted", name)
		}
	}
}

func TestBuildProbeAttestationFailsClosedOnUnboundOrMismatchedTickets(t *testing.T) {
	nonce := fixtureLabelDigest("assignment-probe-fixture-nonce")
	base := fixtureAttestationTicket()
	for name, mutate := range map[string]func(*Ticket){
		"legacy version":   func(ticket *Ticket) { ticket.Version = Version },
		"missing subnet":   func(ticket *Ticket) { ticket.Subnet = nil },
		"missing uid":      func(ticket *Ticket) { ticket.Subnet.MinerUID = nil },
		"identity split":   func(ticket *Ticket) { ticket.MinerID = "MinerB" },
		"bad hotkey":       func(ticket *Ticket) { ticket.MinerID = "Miner_A"; ticket.Subnet.MinerHotkey = "Miner_A" },
		"bad deployment":   func(ticket *Ticket) { ticket.DeploymentID = "Fixture-Alpha" },
		"bad route host":   func(ticket *Ticket) { ticket.RouteHost = "single-label" },
		"bad nonce":        func(ticket *Ticket) { ticket.AssignmentNonce = "short" },
		"zero generation":  func(ticket *Ticket) { ticket.Generation = 0 },
		"bad service key":  func(ticket *Ticket) { ticket.Subnet.MinerServicePublicKey = "zz" },
		"uppercase digest": func(ticket *Ticket) { ticket.ChallengeSHA256 = strings.ToUpper(ticket.ChallengeSHA256) },
	} {
		ticket := base
		binding := *base.Subnet
		ticket.Subnet = &binding
		mutate(&ticket)
		if _, err := BuildProbeAttestation(ticket, nonce, ticket.ChallengeSHA256); err == nil {
			t.Fatalf("%s ticket was accepted", name)
		}
	}
	if _, err := BuildProbeAttestation(base, nonce, fixtureLabelDigest("some-other-body")); err == nil {
		t.Fatal("digest other than the signed challenge digest was accepted")
	}
	if _, err := BuildProbeAttestation(base, strings.ToUpper(nonce), base.ChallengeSHA256); err == nil {
		t.Fatal("mixed-case probe nonce was accepted")
	}
	if _, err := BuildProbeAttestation(base, nonce[:63], base.ChallengeSHA256); err == nil {
		t.Fatal("wrong-length probe nonce was accepted")
	}
}

func TestSignProbeAttestationRejectsForeignKeyAndDoubleSigning(t *testing.T) {
	attestation := signedFixtureAttestation(t)
	if err := SignProbeAttestation(&attestation, fixtureMinerKey("MinerA")); err == nil {
		t.Fatal("double signing was accepted")
	}
	unsigned := attestation
	unsigned.SignatureHex = ""
	if err := SignProbeAttestation(&unsigned, fixtureMinerKey("MinerB")); err == nil {
		t.Fatal("signing with a key other than the bound service key was accepted")
	}
}

func TestVerifyProbeAttestationRejectsTamperingAndForeignKeys(t *testing.T) {
	attestation := signedFixtureAttestation(t)
	key := fixtureMinerKey("MinerA").Public().(ed25519.PublicKey)
	for name, mutate := range map[string]func(*ProbeAttestation){
		"probe nonce":      func(a *ProbeAttestation) { a.ProbeNonce = fixtureLabelDigest("another-nonce") },
		"route host":       func(a *ProbeAttestation) { a.RouteHost = "fixture-beta.mock.local" },
		"deployment":       func(a *ProbeAttestation) { a.DeploymentID = "fixture-beta" },
		"generation":       func(a *ProbeAttestation) { a.Generation = 2 },
		"assignment nonce": func(a *ProbeAttestation) { a.AssignmentNonce = strings.Repeat("ab", 16) },
		"uid":              func(a *ProbeAttestation) { a.MinerUID = 11 },
		"body digest":      func(a *ProbeAttestation) { a.ResponseBodySHA256 = fixtureLabelDigest("other-body") },
		"signature":        func(a *ProbeAttestation) { a.SignatureHex = strings.Repeat("00", 64) },
	} {
		tampered := attestation
		mutate(&tampered)
		// Keep the endpoint derivation canonical so the signature check, not
		// shape validation, is what rejects the tampered statement.
		tampered.EndpointID = fmt.Sprintf(
			"%s-%s-g%d-%s",
			tampered.DeploymentID, tampered.MinerHotkey, tampered.Generation, tampered.AssignmentNonce,
		)
		if err := VerifyProbeAttestation(tampered, key); err == nil {
			t.Fatalf("tampered %s was accepted", name)
		}
	}
	foreign := fixtureMinerKey("MinerB").Public().(ed25519.PublicKey)
	if err := VerifyProbeAttestation(attestation, foreign); err == nil {
		t.Fatal("foreign verification key was accepted")
	}
}

func TestCanonicalProbeNonceRejectsNonCanonicalValues(t *testing.T) {
	valid := fixtureLabelDigest("assignment-probe-fixture-nonce")
	if !CanonicalProbeNonce(valid) {
		t.Fatal("canonical nonce rejected")
	}
	for _, value := range []string{
		"", valid[:63], valid + "0", strings.ToUpper(valid),
		valid[:32] + strings.ToUpper(valid[32:]), strings.Repeat("g", 64), valid[:63] + "G",
	} {
		if CanonicalProbeNonce(value) {
			t.Fatalf("non-canonical nonce %q accepted", value)
		}
	}
}
