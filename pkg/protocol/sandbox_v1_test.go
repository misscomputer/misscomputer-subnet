// SPDX-License-Identifier: AGPL-3.0-only

package protocol_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/organic"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	"github.com/misscomputer/misscomputer-subnet/pkg/sandbox"
)

var updateSandboxVectors = flag.Bool("update-sandbox-vectors", false, "rewrite testdata/sandbox-lease-v1-vectors.json")

var sandboxNow = time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)

func sandboxKeys() (validator, miner ed25519.PrivateKey) {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, 32)), ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, 32))
}

func sandboxBinding(validator, miner ed25519.PrivateKey) *protocol.StaticSubnetBindingV1 {
	pin := strings.Repeat("3a", 32)
	uid := uint16(7)
	return &protocol.StaticSubnetBindingV1{
		Network: "test", NetUID: 24, ValidatorHotkey: "5Hvalidator", MinerHotkey: "5Fminer", MinerUID: &uid,
		MinerAxonURL: "https://8.8.8.8:8091", MinerTransport: "https", MinerTLSCertificateSHA256: &pin,
		ChainBlock: 100, Epoch: 10, ExpiresAtBlock: 125,
		ValidatorServicePublicKey: hex.EncodeToString(validator.Public().(ed25519.PublicKey)),
		MinerServicePublicKey:     hex.EncodeToString(miner.Public().(ed25519.PublicKey)),
	}
}

var sandboxResources = sandbox.Resources{CPUMillis: 1000, MemoryMiB: 4096, DiskMiB: 10240, PIDs: 512}

func stamp(value time.Time) string { return *protocol.StaticTime(value) }

func sandboxReservation(t *testing.T, validator, miner ed25519.PrivateKey) protocol.SandboxReservationV1 {
	t.Helper()
	r := protocol.SandboxReservationV1{
		Generation: 1, HoldExpiresAt: stamp(sandboxNow.Add(time.Minute)), IssuedAt: stamp(sandboxNow), MinerID: "5Fminer",
		ReservationNonce: strings.Repeat("a1", 16), Resources: sandboxResources, SandboxID: "sbx-" + strings.Repeat("0f", 16),
		Schema: protocol.SandboxReservationSchema, SchemaVersion: 1, Subnet: sandboxBinding(validator, miner), WorkloadKind: sandbox.WorkloadKind,
	}
	if err := protocol.SignSandboxReservationV1(&r, validator); err != nil {
		t.Fatal(err)
	}
	return r
}

func sandboxLease(t *testing.T, validator, miner ed25519.PrivateKey, reservation protocol.SandboxReservationV1, mutate func(*protocol.SandboxLeaseV1)) protocol.SandboxLeaseV1 {
	t.Helper()
	digest, err := protocol.SandboxDigestV1(reservation)
	if err != nil {
		t.Fatal(err)
	}
	image := "sha256:" + strings.Repeat("c4", 32)
	l := protocol.SandboxLeaseV1{
		AssignmentNonce: strings.Repeat("b2", 16), Env: map[string]string{}, Generation: reservation.Generation,
		ImageDigest: image, ImageReference: "docker.io/swebench/sweb.eval.x86_64.django_1776_django-12345@" + image,
		Isolation: sandbox.IsolationGVisor, IssuedAt: stamp(sandboxNow.Add(10 * time.Second)), LeaseExpiresAt: stamp(sandboxNow.Add(10 * time.Minute)),
		MinerID: reservation.MinerID, Network: sandbox.NetworkPolicy{Mode: sandbox.NetworkPublic, Allow: []string{}},
		ReservationDigest: digest, Resources: reservation.Resources, SandboxID: reservation.SandboxID,
		Schema: protocol.SandboxLeaseSchema, SchemaVersion: 1, SecretEnv: sandbox.SecretEnv{Delivery: sandbox.SecretDeliveryNone, Names: []string{}},
		Subnet: sandboxBinding(validator, miner), WorkloadKind: sandbox.WorkloadKind,
	}
	if mutate != nil {
		mutate(&l)
	}
	if err := protocol.SignSandboxLeaseV1(&l, validator); err != nil {
		t.Fatal(err)
	}
	return l
}

func sandboxRenewal(t *testing.T, validator, miner ed25519.PrivateKey, lease protocol.SandboxLeaseV1, seq uint64, expires time.Time) protocol.SandboxRenewalV1 {
	t.Helper()
	digest, err := protocol.SandboxDigestV1(lease)
	if err != nil {
		t.Fatal(err)
	}
	r := protocol.SandboxRenewalV1{
		Generation: lease.Generation, IssuedAt: stamp(expires.Add(-10 * time.Minute)), LeaseDigest: digest, LeaseExpiresAt: stamp(expires),
		LeaseID: protocol.SandboxLeaseIDV1(lease), MinerID: lease.MinerID, RenewalSeq: seq, SandboxID: lease.SandboxID,
		Schema: protocol.SandboxRenewalSchema, SchemaVersion: 1, Subnet: sandboxBinding(validator, miner),
	}
	if err := protocol.SignSandboxRenewalV1(&r, validator); err != nil {
		t.Fatal(err)
	}
	return r
}

func sandboxRelease(t *testing.T, validator, miner ed25519.PrivateKey, sandboxID string, generation uint64) protocol.SandboxReleaseV1 {
	t.Helper()
	r := protocol.SandboxReleaseV1{
		Generation: generation, IssuedAt: stamp(sandboxNow.Add(time.Minute)), MinerID: "5Fminer", Reason: sandbox.ReleaseCustomerDelete,
		SandboxID: sandboxID, Schema: protocol.SandboxReleaseSchema, SchemaVersion: 1, Subnet: sandboxBinding(validator, miner),
	}
	if err := protocol.SignSandboxReleaseV1(&r, validator); err != nil {
		t.Fatal(err)
	}
	return r
}

func sandboxReceipt(t *testing.T, miner ed25519.PrivateKey, subnet *protocol.StaticSubnetBindingV1, document any, schema, stage string, code *string, leaseID *string) protocol.SandboxReceiptV1 {
	t.Helper()
	digest, err := protocol.SandboxDigestV1(document)
	if err != nil {
		t.Fatal(err)
	}
	r := protocol.SandboxReceiptV1{
		CapacityActive: sandbox.Capacity{}, CapacityHeld: sandbox.Capacity{}.Add(sandboxResources),
		CapacityTotal:  sandbox.Capacity{CPUMillis: 8000, MemoryMiB: 32768, DiskMiB: 204800, Sandboxes: 8},
		DocumentDigest: digest, DocumentSchema: schema, ErrorCode: code, Generation: 1, LeaseID: leaseID, MinerID: "5Fminer",
		ObservedAt: stamp(sandboxNow.Add(time.Second)), SandboxID: "sbx-" + strings.Repeat("0f", 16), Schema: protocol.SandboxReceiptSchema,
		SchemaVersion: 1, Stage: stage, Subnet: subnet,
	}
	if err := protocol.SignSandboxReceiptV1(&r, miner); err != nil {
		t.Fatal(err)
	}
	return r
}

type sandboxVectorSet struct {
	// The seeds are test-only Ed25519 keys so other implementations can
	// reproduce every signature.
	MinerSeed                 string          `json:"miner_test_seed"`
	MinerServicePublicKey     string          `json:"miner_service_public_key"`
	Reservation               json.RawMessage `json:"reservation"`
	ReservationDigest         string          `json:"reservation_digest"`
	Lease                     json.RawMessage `json:"lease"`
	LeaseDigest               string          `json:"lease_digest"`
	LeaseID                   string          `json:"lease_id"`
	Renewal                   json.RawMessage `json:"renewal"`
	Release                   json.RawMessage `json:"release"`
	Receipt                   json.RawMessage `json:"receipt"`
	ValidatorSeed             string          `json:"validator_test_seed"`
	ValidatorServicePublicKey string          `json:"validator_service_public_key"`
}

func canonicalJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	encoded, err := organic.Canonical(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// The signed documents are pinned as cross-language vectors: Ed25519 is
// deterministic, so the same keys and members must reproduce the same
// canonical bytes, digests and signatures in every implementation.
func TestSandboxDocumentsMatchGoldenVectors(t *testing.T) {
	validator, miner := sandboxKeys()
	reservation := sandboxReservation(t, validator, miner)
	lease := sandboxLease(t, validator, miner, reservation, nil)
	renewal := sandboxRenewal(t, validator, miner, lease, 1, sandboxNow.Add(20*time.Minute))
	release := sandboxRelease(t, validator, miner, reservation.SandboxID, 1)
	leaseID := protocol.SandboxLeaseIDV1(lease)
	receipt := sandboxReceipt(t, miner, lease.Subnet, lease, protocol.SandboxLeaseSchema, sandbox.StageReady, nil, &leaseID)
	reservationDigest, _ := protocol.SandboxDigestV1(reservation)
	leaseDigest, _ := protocol.SandboxDigestV1(lease)
	got := sandboxVectorSet{
		MinerSeed: hex.EncodeToString(miner.Seed()), ValidatorSeed: hex.EncodeToString(validator.Seed()),
		MinerServicePublicKey: lease.Subnet.MinerServicePublicKey, ValidatorServicePublicKey: lease.Subnet.ValidatorServicePublicKey,
		Reservation: canonicalJSON(t, reservation), ReservationDigest: reservationDigest,
		Lease: canonicalJSON(t, lease), LeaseDigest: leaseDigest, LeaseID: leaseID,
		Renewal: canonicalJSON(t, renewal), Release: canonicalJSON(t, release), Receipt: canonicalJSON(t, receipt),
	}
	rendered, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	rendered = append(rendered, '\n')
	path := filepath.Join("testdata", "sandbox-lease-v1-vectors.json")
	if *updateSandboxVectors {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, rendered, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, rendered) {
		t.Fatalf("sandbox vectors changed; rerun with -update-sandbox-vectors only for an intended contract change\n%s", rendered)
	}
	// The pinned documents decode strictly and verify as themselves.
	var vectors sandboxVectorSet
	if err := json.Unmarshal(want, &vectors); err != nil {
		t.Fatal(err)
	}
	validatorKey, minerKey := validator.Public().(ed25519.PublicKey), miner.Public().(ed25519.PublicKey)
	var decodedReservation protocol.SandboxReservationV1
	var decodedLease protocol.SandboxLeaseV1
	var decodedRenewal protocol.SandboxRenewalV1
	var decodedRelease protocol.SandboxReleaseV1
	var decodedReceipt protocol.SandboxReceiptV1
	for raw, document := range map[*json.RawMessage]organic.Validator{
		&vectors.Reservation: &decodedReservation, &vectors.Lease: &decodedLease, &vectors.Renewal: &decodedRenewal,
		&vectors.Release: &decodedRelease, &vectors.Receipt: &decodedReceipt,
	} {
		if err := organic.DecodeStrict(*raw, document); err != nil {
			t.Fatalf("decode pinned vector: %v", err)
		}
	}
	for name, pair := range map[string][2]any{"reservation": {decodedReservation, vectors.ReservationDigest}, "lease": {decodedLease, vectors.LeaseDigest}} {
		if digest, err := protocol.SandboxDigestV1(pair[0]); err != nil || digest != pair[1] {
			t.Fatalf("%s digest %s, want %s (%v)", name, digest, pair[1], err)
		}
	}
	for name, err := range map[string]error{
		"reservation": protocol.VerifySandboxReservationV1Signature(decodedReservation, validatorKey),
		"lease":       protocol.VerifySandboxLeaseV1Signature(decodedLease, validatorKey),
		"renewal":     protocol.VerifySandboxRenewalV1Signature(decodedRenewal, validatorKey),
		"release":     protocol.VerifySandboxReleaseV1Signature(decodedRelease, validatorKey),
		"receipt":     protocol.VerifySandboxReceiptV1(decodedReceipt, minerKey),
		"commit":      protocol.SandboxLeaseCommitsReservationV1(decodedReservation, decodedLease),
		"answers":     protocol.SandboxReceiptAnswersV1(decodedReceipt, decodedLease),
	} {
		if err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func signedMessage(t *testing.T, domain string, document any) []byte {
	t.Helper()
	encoded, _ := json.Marshal(document)
	var members map[string]any
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err := decoder.Decode(&members); err != nil {
		t.Fatal(err)
	}
	delete(members, "signature")
	canonical, err := organic.Canonical(members)
	if err != nil {
		t.Fatal(err)
	}
	return append(append([]byte(domain), 0), canonical...)
}

// A sandbox signature verifies only under its own domain: the same key
// signing the same members for any sibling sandbox domain, a static domain
// or the undomained deployment.v4 rule never authorizes it.
func TestSandboxSignaturesAreDomainSeparated(t *testing.T) {
	validator, miner := sandboxKeys()
	validatorKey := validator.Public().(ed25519.PublicKey)
	reservation := sandboxReservation(t, validator, miner)
	lease := sandboxLease(t, validator, miner, reservation, nil)
	domains := []string{
		protocol.SandboxReservationSigningDomain, protocol.SandboxLeaseSigningDomain, protocol.SandboxRenewalSigningDomain,
		protocol.SandboxReleaseSigningDomain, protocol.SandboxReceiptSigningDomain,
		protocol.StaticTicketSigningDomain, protocol.StaticReceiptSigningDomain,
	}
	for _, domain := range domains {
		forgedReservation, forgedLease := reservation, lease
		forgedReservation.Signature = hex.EncodeToString(ed25519.Sign(validator, signedMessage(t, domain, reservation)))
		forgedLease.Signature = hex.EncodeToString(ed25519.Sign(validator, signedMessage(t, domain, lease)))
		if err := protocol.VerifySandboxReservationV1Signature(forgedReservation, validatorKey); (err == nil) != (domain == protocol.SandboxReservationSigningDomain) {
			t.Fatalf("reservation under %s: %v", domain, err)
		}
		if err := protocol.VerifySandboxLeaseV1Signature(forgedLease, validatorKey); (err == nil) != (domain == protocol.SandboxLeaseSigningDomain) {
			t.Fatalf("lease under %s: %v", domain, err)
		}
	}
	unsigned := lease
	unsigned.Signature = ""
	undomained, _ := json.Marshal(unsigned)
	forged := lease
	forged.Signature = hex.EncodeToString(ed25519.Sign(validator, undomained))
	if protocol.VerifySandboxLeaseV1Signature(forged, validatorKey) == nil {
		t.Fatal("an undomained deployment.v4-style signature verified as a sandbox lease")
	}
	// The miner key cannot issue validator documents even with the right domain.
	byMiner := lease
	byMiner.Signature = hex.EncodeToString(ed25519.Sign(miner, signedMessage(t, protocol.SandboxLeaseSigningDomain, lease)))
	if protocol.VerifySandboxLeaseV1Signature(byMiner, validatorKey) == nil || protocol.VerifySandboxLeaseV1Signature(byMiner, miner.Public().(ed25519.PublicKey)) == nil {
		t.Fatal("a miner-signed lease verified")
	}
	changed := lease
	changed.ImageDigest = "sha256:" + strings.Repeat("00", 32)
	changed.ImageReference = "docker.io/library/busybox@" + changed.ImageDigest
	if protocol.VerifySandboxLeaseV1Signature(changed, validatorKey) == nil {
		t.Fatal("a lease for another image verified")
	}
}

// Sandbox documents and the existing web documents never decode as each
// other, so no deployment.v4 or static decoder can admit a sandbox lease and
// the sandbox decoders admit neither existing ticket.
func TestSandboxDocumentsAndWebTicketsDoNotCrossDecode(t *testing.T) {
	validator, miner := sandboxKeys()
	reservation := sandboxReservation(t, validator, miner)
	lease := sandboxLease(t, validator, miner, reservation, nil)
	for _, fixture := range []string{"deployment-ticket.v4.json", "static-deployment-ticket.v1.json", "deployment-receipt.v4.json", "static-deployment-receipt.v1.json"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "contracts", "fixtures", fixture))
		if err != nil {
			t.Fatal(err)
		}
		for _, target := range []organic.Validator{&protocol.SandboxReservationV1{}, &protocol.SandboxLeaseV1{}, &protocol.SandboxReceiptV1{}} {
			if organic.DecodeStrict(raw, target) == nil {
				t.Fatalf("%s decoded as %T", fixture, target)
			}
		}
	}
	for _, document := range []any{reservation, lease} {
		raw := canonicalJSON(t, document)
		if organic.DecodeStrict(raw, &protocol.StaticTicketV1{}) == nil {
			t.Fatalf("%T decoded as a static ticket", document)
		}
		var v4 protocol.TicketV4
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&v4) == nil {
			t.Fatalf("%T decoded as a deployment.v4 ticket", document)
		}
	}
}

// The v1 lease contract carries every egress mode and a declared customer
// environment; it is not an egress-deny-only or environment-less contract.
// Values never travel in a signed document: secret_env binds only names and
// a bundle digest.
func TestSandboxLeaseCarriesNetworkModesAndSecretDeclarations(t *testing.T) {
	validator, miner := sandboxKeys()
	reservation := sandboxReservation(t, validator, miner)
	bundle := "sha256:" + strings.Repeat("5e", 32)
	accepted := map[string]func(*protocol.SandboxLeaseV1){
		"none": func(l *protocol.SandboxLeaseV1) {
			l.Network = sandbox.NetworkPolicy{Mode: sandbox.NetworkNone, Allow: []string{}}
		},
		"public": func(l *protocol.SandboxLeaseV1) {
			l.Network = sandbox.NetworkPolicy{Mode: sandbox.NetworkPublic, Allow: []string{}}
		},
		"allowlist": func(l *protocol.SandboxLeaseV1) {
			l.Network = sandbox.NetworkPolicy{Mode: sandbox.NetworkAllowlist, Allow: []string{"10.0.0.0/8", "2001:db8::/32", "api.example.com", "pypi.org"}}
		},
		"sealed secrets": func(l *protocol.SandboxLeaseV1) {
			l.SecretEnv = sandbox.SecretEnv{Delivery: sandbox.SecretDeliverySealedBundle, Names: []string{"MODEL_API_KEY", "REGISTRY_TOKEN"}, BundleDigest: &bundle}
		},
		// Every customer variable is declared here, so the bound is the whole
		// customer environment: 128 names, the earlier plain env limit.
		"full declared environment": func(l *protocol.SandboxLeaseV1) {
			l.SecretEnv = sandbox.SecretEnv{Delivery: sandbox.SecretDeliverySealedBundle, Names: envNames(128), BundleDigest: &bundle}
		},
		"kata":        func(l *protocol.SandboxLeaseV1) { l.Isolation = sandbox.IsolationKata },
		"firecracker": func(l *protocol.SandboxLeaseV1) { l.Isolation = sandbox.IsolationFirecracker },
	}
	for name, mutate := range accepted {
		lease := sandboxLease(t, validator, miner, reservation, mutate)
		if err := protocol.VerifySandboxLeaseV1Signature(lease, validator.Public().(ed25519.PublicKey)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestSandboxDocumentsRejectInvalidMembers(t *testing.T) {
	validator, miner := sandboxKeys()
	reservation := sandboxReservation(t, validator, miner)
	bundle := "sha256:" + strings.Repeat("5e", 32)
	reservationCases := map[string]func(*protocol.SandboxReservationV1){
		"hold window over two minutes": func(r *protocol.SandboxReservationV1) {
			r.HoldExpiresAt = stamp(sandboxNow.Add(2*time.Minute + time.Nanosecond))
		},
		"hold expires at issue": func(r *protocol.SandboxReservationV1) { r.HoldExpiresAt = r.IssuedAt },
		"miner id mismatch":     func(r *protocol.SandboxReservationV1) { r.MinerID = "5Fother" },
		"sandbox id shape":      func(r *protocol.SandboxReservationV1) { r.SandboxID = "hello-k3j9x0q2ab" },
		"generation zero":       func(r *protocol.SandboxReservationV1) { r.Generation = 0 },
		"cpu below one vcpu":    func(r *protocol.SandboxReservationV1) { r.Resources.CPUMillis = 999 },
		"memory above 64 GiB":   func(r *protocol.SandboxReservationV1) { r.Resources.MemoryMiB = 65537 },
		"disk below 5 GiB":      func(r *protocol.SandboxReservationV1) { r.Resources.DiskMiB = 5119 },
		"static workload kind":  func(r *protocol.SandboxReservationV1) { r.WorkloadKind = "static" },
		"non-canonical time":    func(r *protocol.SandboxReservationV1) { r.IssuedAt = "2026-10-13T12:00:00.000Z" },
	}
	for name, mutate := range reservationCases {
		candidate := reservation
		candidate.Signature = ""
		mutate(&candidate)
		if protocol.SignSandboxReservationV1(&candidate, validator) == nil {
			t.Errorf("reservation %s was signed", name)
		}
	}
	base := sandboxLease(t, validator, miner, reservation, nil)
	leaseCases := map[string]func(*protocol.SandboxLeaseV1){
		"lease window over fifteen minutes": func(l *protocol.SandboxLeaseV1) {
			l.LeaseExpiresAt = stamp(sandboxNow.Add(15*time.Minute + 11*time.Second))
		},
		"tag instead of digest":         func(l *protocol.SandboxLeaseV1) { l.ImageReference = "docker.io/library/python:3.12" },
		"reference pins another digest": func(l *protocol.SandboxLeaseV1) { l.ImageDigest = "sha256:" + strings.Repeat("00", 32) },
		"uppercase repository":          func(l *protocol.SandboxLeaseV1) { l.ImageReference = "docker.io/Library/x@" + l.ImageDigest },
		"runc isolation":                func(l *protocol.SandboxLeaseV1) { l.Isolation = "runc" },
		"egress-deny-v1 legacy value":   func(l *protocol.SandboxLeaseV1) { l.Network.Mode = "egress-deny-v1" },
		"null allow":                    func(l *protocol.SandboxLeaseV1) { l.Network.Allow = nil },
		"allow outside allowlist":       func(l *protocol.SandboxLeaseV1) { l.Network.Allow = []string{"pypi.org"} },
		"empty allowlist": func(l *protocol.SandboxLeaseV1) {
			l.Network = sandbox.NetworkPolicy{Mode: sandbox.NetworkAllowlist, Allow: []string{}}
		},
		"unsorted allowlist": func(l *protocol.SandboxLeaseV1) {
			l.Network = sandbox.NetworkPolicy{Mode: sandbox.NetworkAllowlist, Allow: []string{"pypi.org", "api.example.com"}}
		},
		"wildcard hostname": func(l *protocol.SandboxLeaseV1) {
			l.Network = sandbox.NetworkPolicy{Mode: sandbox.NetworkAllowlist, Allow: []string{"*.example.com"}}
		},
		"non-canonical cidr": func(l *protocol.SandboxLeaseV1) {
			l.Network = sandbox.NetworkPolicy{Mode: sandbox.NetworkAllowlist, Allow: []string{"10.1.2.3/8"}}
		},
		"null env":        func(l *protocol.SandboxLeaseV1) { l.Env = nil },
		"plain env value": func(l *protocol.SandboxLeaseV1) { l.Env = map[string]string{"TASK": "django-12345"} },
		"secret names without delivery": func(l *protocol.SandboxLeaseV1) {
			l.SecretEnv = sandbox.SecretEnv{Delivery: sandbox.SecretDeliveryNone, Names: []string{"TOKEN"}}
		},
		"sealed bundle without digest": func(l *protocol.SandboxLeaseV1) {
			l.SecretEnv = sandbox.SecretEnv{Delivery: sandbox.SecretDeliverySealedBundle, Names: []string{"TOKEN"}}
		},
		"too many declared names": func(l *protocol.SandboxLeaseV1) {
			l.SecretEnv = sandbox.SecretEnv{Delivery: sandbox.SecretDeliverySealedBundle, Names: envNames(129), BundleDigest: &bundle}
		},
		"unknown delivery":           func(l *protocol.SandboxLeaseV1) { l.SecretEnv.Delivery = "plaintext" },
		"invalid reservation digest": func(l *protocol.SandboxLeaseV1) { l.ReservationDigest = "sha256:abc" },
	}
	for name, mutate := range leaseCases {
		candidate := base
		candidate.Env = map[string]string{}
		candidate.Signature = ""
		mutate(&candidate)
		if protocol.SignSandboxLeaseV1(&candidate, validator) == nil {
			t.Errorf("lease %s was signed", name)
		}
	}
	renewal := sandboxRenewal(t, validator, miner, base, 1, sandboxNow.Add(20*time.Minute))
	renewalCases := map[string]func(*protocol.SandboxRenewalV1){
		"sequence zero":    func(r *protocol.SandboxRenewalV1) { r.RenewalSeq = 0 },
		"lease of another": func(r *protocol.SandboxRenewalV1) { r.LeaseID = strings.Replace(r.LeaseID, "5Fminer", "5Fother", 1) },
		"lease id without nonce": func(r *protocol.SandboxRenewalV1) {
			r.LeaseID = r.LeaseID[:len(r.LeaseID)-32] + strings.Repeat("Z", 32)
		},
		"window too long":    func(r *protocol.SandboxRenewalV1) { r.IssuedAt = stamp(sandboxNow) },
		"missing subnet":     func(r *protocol.SandboxRenewalV1) { r.Subnet = nil },
		"generation changed": func(r *protocol.SandboxRenewalV1) { r.Generation = 2 },
	}
	for name, mutate := range renewalCases {
		candidate := renewal
		candidate.Signature = ""
		mutate(&candidate)
		if protocol.SignSandboxRenewalV1(&candidate, validator) == nil {
			t.Errorf("renewal %s was signed", name)
		}
	}
	release := sandboxRelease(t, validator, miner, reservation.SandboxID, 1)
	for name, mutate := range map[string]func(*protocol.SandboxReleaseV1){
		"free-text reason": func(r *protocol.SandboxReleaseV1) { r.Reason = "because" },
		"miner mismatch":   func(r *protocol.SandboxReleaseV1) { r.MinerID = "5Fother" },
	} {
		candidate := release
		candidate.Signature = ""
		mutate(&candidate)
		if protocol.SignSandboxReleaseV1(&candidate, validator) == nil {
			t.Errorf("release %s was signed", name)
		}
	}
}

func TestSandboxReceiptRules(t *testing.T) {
	validator, miner := sandboxKeys()
	reservation := sandboxReservation(t, validator, miner)
	lease := sandboxLease(t, validator, miner, reservation, nil)
	leaseID := protocol.SandboxLeaseIDV1(lease)
	code := "capacity_exhausted"
	held := sandboxReceipt(t, miner, reservation.Subnet, reservation, protocol.SandboxReservationSchema, sandbox.StageHeld, nil, nil)
	if err := protocol.VerifySandboxReceiptV1(held, miner.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	if protocol.VerifySandboxReceiptV1(held, validator.Public().(ed25519.PublicKey)) == nil {
		t.Fatal("a receipt verified under the validator key")
	}
	if err := protocol.SandboxReceiptAnswersV1(held, reservation); err != nil {
		t.Fatal(err)
	}
	if protocol.SandboxReceiptAnswersV1(held, lease) == nil {
		t.Fatal("a reservation receipt answered a lease")
	}
	invalid := map[string]func(*protocol.SandboxReceiptV1){
		"refused without code":      func(r *protocol.SandboxReceiptV1) { r.Stage = sandbox.StageRefused },
		"held with code":            func(r *protocol.SandboxReceiptV1) { r.ErrorCode = &code },
		"ready answers reservation": func(r *protocol.SandboxReceiptV1) { r.Stage = sandbox.StageReady },
		"reservation names a lease": func(r *protocol.SandboxReceiptV1) { r.LeaseID = &leaseID },
		"lease receipt without lease": func(r *protocol.SandboxReceiptV1) {
			r.DocumentSchema = protocol.SandboxLeaseSchema
			r.Stage = sandbox.StageReady
		},
		"unknown error code": func(r *protocol.SandboxReceiptV1) {
			unknown := "out_of_coffee"
			r.Stage, r.ErrorCode = sandbox.StageRefused, &unknown
		},
		"over capacity":     func(r *protocol.SandboxReceiptV1) { r.CapacityActive = r.CapacityTotal },
		"negative capacity": func(r *protocol.SandboxReceiptV1) { r.CapacityHeld.Sandboxes = -1 },
		"unknown document":  func(r *protocol.SandboxReceiptV1) { r.DocumentSchema = protocol.StaticTicketSchema },
		"lease of other miner": func(r *protocol.SandboxReceiptV1) {
			other := strings.Replace(leaseID, "5Fminer", "5Fother", 1)
			r.DocumentSchema, r.Stage, r.LeaseID = protocol.SandboxLeaseSchema, sandbox.StageReady, &other
		},
	}
	for name, mutate := range invalid {
		candidate := held
		candidate.Signature = ""
		mutate(&candidate)
		if protocol.SignSandboxReceiptV1(&candidate, miner) == nil {
			t.Errorf("receipt %s was signed", name)
		}
	}
}

// A miner's signature and the exact document digest do not make a receipt
// consistent with the lease ID or renewal sequence inside that document.
func TestSandboxReceiptRejectsDocumentContradictions(t *testing.T) {
	validator, miner := sandboxKeys()
	reservation := sandboxReservation(t, validator, miner)
	lease := sandboxLease(t, validator, miner, reservation, nil)
	leaseID := protocol.SandboxLeaseIDV1(lease)
	otherID := leaseID[:len(leaseID)-1] + "0"
	if otherID == leaseID {
		otherID = leaseID[:len(leaseID)-1] + "1"
	}
	t.Run("wrong lease id", func(t *testing.T) {
		wrongLease := sandboxReceipt(t, miner, lease.Subnet, lease, protocol.SandboxLeaseSchema, sandbox.StageReady, nil, &otherID)
		if err := protocol.SandboxReceiptAnswersV1(wrongLease, lease); err == nil {
			t.Fatal("signed receipt with another lease ID answered the lease")
		}
	})
	renewal := sandboxRenewal(t, validator, miner, lease, 1, sandboxNow.Add(15*time.Minute))
	t.Run("stale renewal sequence", func(t *testing.T) {
		stale := sandboxReceipt(t, miner, renewal.Subnet, renewal, protocol.SandboxRenewalSchema, sandbox.StageReady, nil, &leaseID)
		if err := protocol.SandboxReceiptAnswersV1(stale, renewal); err == nil {
			t.Fatal("signed receipt with stale sequence confirmed the renewal")
		}
		// A terminal reply can accurately report that the renewal was not
		// applied and therefore still carry the prior durable sequence.
		stale.Stage, stale.Signature = sandbox.StageExpired, ""
		if err := protocol.SignSandboxReceiptV1(&stale, miner); err != nil {
			t.Fatal(err)
		}
		if err := protocol.SandboxReceiptAnswersV1(stale, renewal); err != nil {
			t.Fatalf("terminal reply with prior sequence: %v", err)
		}
	})
}

// Admission binds every validator document to its window, the issuing
// validator's service key and the authenticated request identity.
func TestBoundSandboxAdmission(t *testing.T) {
	validator, miner := sandboxKeys()
	key := validator.Public().(ed25519.PublicKey)
	reservation := sandboxReservation(t, validator, miner)
	uid := uint16(7)
	admit := func(now time.Time, block uint64, caller string, uidValue *uint16, signer ed25519.PublicKey) error {
		return protocol.VerifyBoundSandboxReservationV1(reservation, signer, now, block, "test", 24, caller, "5Fminer", uidValue)
	}
	if err := admit(sandboxNow, 110, "5Hvalidator", &uid, key); err != nil {
		t.Fatal(err)
	}
	_, stranger, _ := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0x33}, 64)))
	for name, err := range map[string]error{
		"before issue skew":     admit(sandboxNow.Add(-31*time.Second), 110, "5Hvalidator", &uid, key),
		"at hold expiry":        admit(sandboxNow.Add(time.Minute), 110, "5Hvalidator", &uid, key),
		"expired chain binding": admit(sandboxNow, 125, "5Hvalidator", &uid, key),
		"another caller":        admit(sandboxNow, 110, "5Hother", &uid, key),
		"uid mismatch":          admit(sandboxNow, 110, "5Hvalidator", nil, key),
		"unbound signer":        admit(sandboxNow, 110, "5Hvalidator", &uid, stranger.Public().(ed25519.PublicKey)),
	} {
		if err == nil {
			t.Errorf("%s was admitted", name)
		}
	}
	release := sandboxRelease(t, validator, miner, reservation.SandboxID, 1)
	if err := protocol.VerifyBoundSandboxReleaseV1(release, key, sandboxNow.Add(24*time.Hour), 110, "test", 24, "5Hvalidator", "5Fminer", &uid); err != nil {
		t.Fatalf("a release has no wall-clock expiry: %v", err)
	}
	lease := sandboxLease(t, validator, miner, reservation, nil)
	if protocol.VerifyBoundSandboxLeaseV1(lease, key, sandboxNow.Add(10*time.Minute), 110, "test", 24, "5Hvalidator", "5Fminer", &uid) == nil {
		t.Fatal("an expired lease was admitted")
	}
	renewal := sandboxRenewal(t, validator, miner, lease, 1, sandboxNow.Add(20*time.Minute))
	if err := protocol.VerifyBoundSandboxRenewalV1(renewal, key, sandboxNow.Add(12*time.Minute), 110, "test", 24, "5Hvalidator", "5Fminer", &uid); err != nil {
		t.Fatal(err)
	}
}

// A lease must commit exactly the reservation it names.
func TestSandboxLeaseMustCommitItsReservation(t *testing.T) {
	validator, miner := sandboxKeys()
	reservation := sandboxReservation(t, validator, miner)
	for name, mutate := range map[string]func(*protocol.SandboxLeaseV1){
		"more resources":     func(l *protocol.SandboxLeaseV1) { l.Resources.MemoryMiB = 8192 },
		"another generation": func(l *protocol.SandboxLeaseV1) { l.Generation = 2 },
		"another reservation": func(l *protocol.SandboxLeaseV1) {
			l.ReservationDigest = "sha256:" + strings.Repeat("77", 32)
		},
	} {
		lease := sandboxLease(t, validator, miner, reservation, mutate)
		if protocol.SandboxLeaseCommitsReservationV1(reservation, lease) == nil {
			t.Errorf("%s committed the reservation", name)
		}
	}
	_, otherValidator, _ := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0x44}, 64)))
	foreign := sandboxLease(t, otherValidator, miner, reservation, nil)
	if protocol.SandboxLeaseCommitsReservationV1(reservation, foreign) == nil {
		t.Fatal("another validator's lease committed the reservation")
	}
}

func envNames(n int) []string {
	names := make([]string, n)
	for i := range names {
		names[i] = fmt.Sprintf("VAR_%03d", i)
	}
	return names
}

// Signed documents are persisted and may be logged, and a customer may put a
// secret in any variable, so a lease that carries an environment value is
// refused even when the validator key signed it under the lease domain: no
// receiving miner may admit, store or act on it.
func TestSandboxLeaseRefusesPlainEnvironmentValues(t *testing.T) {
	validator, miner := sandboxKeys()
	validatorKey := validator.Public().(ed25519.PublicKey)
	reservation := sandboxReservation(t, validator, miner)
	lease := sandboxLease(t, validator, miner, reservation, nil)
	uid := uint16(7)
	admit := func(l protocol.SandboxLeaseV1) error {
		return protocol.VerifyBoundSandboxLeaseV1(l, validatorKey, sandboxNow.Add(time.Minute), 110, "test", 24, "5Hvalidator", "5Fminer", &uid)
	}
	if err := admit(lease); err != nil {
		t.Fatal(err)
	}
	carrying := lease
	carrying.Env = map[string]string{"MODEL_API_KEY": "sk-live-not-a-real-key"}
	carrying.Signature = hex.EncodeToString(ed25519.Sign(validator, signedMessage(t, protocol.SandboxLeaseSigningDomain, carrying)))
	if err := protocol.VerifySandboxLeaseV1Signature(carrying, validatorKey); err == nil {
		t.Fatal("a validator-signed lease carrying an environment value verified")
	}
	if err := admit(carrying); err == nil {
		t.Fatal("a validator-signed lease carrying an environment value was admitted")
	}
	resigned := carrying
	resigned.Signature = ""
	if protocol.SignSandboxLeaseV1(&resigned, validator) == nil {
		t.Fatal("a lease carrying an environment value was signed")
	}
}
