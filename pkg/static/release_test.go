// SPDX-License-Identifier: AGPL-3.0-only

package static_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/misscomputer/misscomputer-subnet/pkg/organic"
	"github.com/misscomputer/misscomputer-subnet/pkg/static"
)

// contractRelease is the static-site contract §7.1 example: seed 32 × 0x07,
// §3.5 site, implementation digest sha256:abab…ab.
const contractRelease = `{"issued_at":"2026-09-30T00:00:00Z","producer_policy_version":"static-producer-policy.v2","schema":"miss.computer/misscomputer-subnet/static-site-release","schema_version":1,"server_implementation_digest":"sha256:abababababababababababababababababababababababababababababababab","signature":"5bab1ba140424869a6c97d61b28364253cd278aae288108abd82dba2cc6e8ac81f809edab150ae2d8acddc498715953a8b57a5cd19f5ef5bc2d3eaafb83f170c","signer_key_id":"static-release-example","site_digest":"sha256:9db3b2a4b3f18c1d31fd7d3348f83e1dfde21163d5aca540fd2f63d6b88ab77f"}` + "\n"

const (
	contractReleaseDigest = "sha256:a3ea17b8d08367ae5e971b7ee495cfae6d6bbaff9483f4396fe21189086ae19c"
	exampleSiteDigest     = "sha256:9db3b2a4b3f18c1d31fd7d3348f83e1dfde21163d5aca540fd2f63d6b88ab77f"
)

func seedKey(b byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, 32)) }

func trustPolicy(t *testing.T, keys ...static.ReleaseKey) (static.TrustPolicy, []byte) {
	t.Helper()
	policy := static.TrustPolicy{Schema: static.TrustPolicySchema, SchemaVersion: 1, PolicyID: "static-release-test", TrustedKeys: keys}
	digest, err := organic.DigestWithout(policy, "digest_sha256")
	if err != nil {
		t.Fatal(err)
	}
	policy.DigestSHA256 = digest
	stored, err := organic.CanonicalBytes(policy)
	if err != nil {
		t.Fatal(err)
	}
	return policy, stored
}

func releaseKey(id string, key ed25519.PrivateKey) static.ReleaseKey {
	return static.ReleaseKey{
		Algorithm: "ed25519", KeyID: id, PublicKeyHex: hex.EncodeToString(key.Public().(ed25519.PublicKey)),
		ValidFromEpoch: 1790000000, ValidUntilEpoch: 1800000000,
	}
}

func signRelease(t *testing.T, r static.Release, key ed25519.PrivateKey) static.Release {
	t.Helper()
	message, err := static.ReleaseMessage(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Signature = hex.EncodeToString(ed25519.Sign(key, message))
	return r
}

// The contract's release bytes verify through the Go message and digest
// rules; only the implementation pin (abab…, not this build) refuses it.
func TestContractReleaseVerifiesUpToTheImplementationPin(t *testing.T) {
	release, err := static.ParseRelease([]byte(contractRelease), contractReleaseDigest)
	if err != nil {
		t.Fatal(err)
	}
	policy, stored := trustPolicy(t, releaseKey("static-release-example", seedKey(7)))
	if _, err := static.ParseTrustPolicy(stored, policy.DigestSHA256); err != nil {
		t.Fatal(err)
	}
	if code := static.ReleaseCodeOf(static.VerifyRelease(release, policy, exampleSiteDigest)); code != static.ReleaseServerImplementationMismatch {
		t.Fatalf("contract release: %q", code)
	}
}

// Every §7.2 refusal carries the public validator's abstention code.
func TestVerifyReleaseRefusals(t *testing.T) {
	signer, other := seedKey(7), seedKey(9)
	policy, _ := trustPolicy(t, releaseKey("static-release-a", signer))
	good := static.Release{
		IssuedAt: "2026-09-30T00:00:00Z", ProducerPolicyVersion: static.ProducerPolicyVersion, Schema: static.ReleaseSchema,
		SchemaVersion: 1, ServerImplementationDigest: static.ServerImplementationDigest, SignerKeyID: "static-release-a",
		SiteDigest: exampleSiteDigest,
	}
	if err := static.VerifyRelease(signRelease(t, good, signer), policy, exampleSiteDigest); err != nil {
		t.Fatal(err)
	}
	mutate := func(change func(*static.Release)) static.Release {
		r := good
		change(&r)
		return signRelease(t, r, signer)
	}
	cases := []struct {
		name    string
		release static.Release
		site    string
		want    static.ReleaseCode
	}{
		{"other site", signRelease(t, good, signer), "sha256:" + string(bytes.Repeat([]byte("0"), 64)), static.ReleaseBindingMismatch},
		{"unknown signer", mutate(func(r *static.Release) { r.SignerKeyID = "static-release-b" }), exampleSiteDigest, static.ReleaseSignerUntrusted},
		{"before validity", mutate(func(r *static.Release) { r.IssuedAt = "2026-09-21T00:00:00Z" }), exampleSiteDigest, static.ReleaseSignerOutsideValidity},
		{"at validity end", mutate(func(r *static.Release) { r.IssuedAt = "2027-01-15T08:00:00Z" }), exampleSiteDigest, static.ReleaseSignerOutsideValidity},
		{"wrong key", signRelease(t, good, other), exampleSiteDigest, static.ReleaseSignatureInvalid},
		{"field changed after signing", func() static.Release {
			r := signRelease(t, good, signer)
			r.ServerImplementationDigest = "sha256:" + string(bytes.Repeat([]byte("c"), 64))
			return r
		}(), exampleSiteDigest, static.ReleaseSignatureInvalid},
		{"legacy producer policy", mutate(func(r *static.Release) { r.ProducerPolicyVersion = "static-producer-policy.v1" }), exampleSiteDigest, static.ReleaseProducerPolicyUnsupported},
		{"other handler", mutate(func(r *static.Release) {
			r.ServerImplementationDigest = "sha256:" + string(bytes.Repeat([]byte("c"), 64))
		}), exampleSiteDigest, static.ReleaseServerImplementationMismatch},
	}
	for _, c := range cases {
		if code := static.ReleaseCodeOf(static.VerifyRelease(c.release, policy, c.site)); code != c.want {
			t.Errorf("%s: code %q, want %q", c.name, code, c.want)
		}
	}
}

// Stored bytes are pinned: the release by its digest, the policy by its
// out-of-band self-digest.
func TestStoredReleaseAndPolicyPins(t *testing.T) {
	if _, err := static.ParseRelease([]byte(contractRelease), exampleSiteDigest); static.ReleaseCodeOf(err) != static.ReleaseDigestMismatch {
		t.Fatalf("release under another digest: %v", err)
	}
	spaced := []byte(contractRelease[:len(contractRelease)-1] + " \n")
	if _, err := static.ParseRelease(spaced, static.Digest(spaced)); static.ReleaseCodeOf(err) != static.ReleaseInvalid {
		t.Fatalf("non-canonical release: %v", err)
	}
	policy, stored := trustPolicy(t, releaseKey("static-release-a", seedKey(7)))
	if _, err := static.ParseTrustPolicy(stored, hex.EncodeToString(make([]byte, 32))); static.ReleaseCodeOf(err) != static.ReleaseTrustPolicyDigestMismatch {
		t.Fatalf("unpinned policy: %v", err)
	}
	policy.PolicyID = "static-release-edited"
	edited, _ := organic.CanonicalBytes(policy)
	if _, err := static.ParseTrustPolicy(edited, policy.DigestSHA256); static.ReleaseCodeOf(err) != static.ReleaseTrustPolicyInvalid {
		t.Fatalf("policy edited without resealing: %v", err)
	}
}
