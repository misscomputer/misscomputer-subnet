// SPDX-License-Identifier: AGPL-3.0-only

package protocol_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/organic"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	"github.com/misscomputer/misscomputer-subnet/pkg/static"
)

func staticTicket(t *testing.T, validator, miner ed25519.PrivateKey) protocol.StaticTicketV1 {
	t.Helper()
	now := time.Now().UTC()
	pin := strings.Repeat("3a", 32)
	site := "sha256:" + strings.Repeat("9d", 32)
	ticket := protocol.StaticTicketV1{
		AssignmentNonce: strings.Repeat("ab", 16), DeploymentID: "hello-k3j9x0q2ab",
		IssuedAt: *protocol.StaticTime(now), ExpiresAt: *protocol.StaticTime(now.Add(5 * time.Minute)), Generation: 1,
		MinerID: "5Fminer", ReleaseDigest: "sha256:" + strings.Repeat("9b", 32), RouteHost: "hello-k3j9x0q2ab.on.miss.computer",
		Schema: protocol.StaticTicketSchema, SchemaVersion: 1, ServerImplementationDigest: static.ServerImplementationDigest,
		SiteDigest: site, SiteManifestKey: static.ManifestKey(site), WorkloadKind: static.WorkloadKind,
		Subnet: &protocol.StaticSubnetBindingV1{
			Network: "test", NetUID: 24, ValidatorHotkey: "5Hvalidator", MinerHotkey: "5Fminer",
			MinerAxonURL: "https://8.8.8.8:8091", MinerTransport: "https", MinerTLSCertificateSHA256: &pin,
			ChainBlock: 100, Epoch: 10, ExpiresAtBlock: 125,
			ValidatorServicePublicKey: hex.EncodeToString(validator.Public().(ed25519.PublicKey)),
			MinerServicePublicKey:     hex.EncodeToString(miner.Public().(ed25519.PublicKey)),
		},
	}
	if err := protocol.SignStaticTicketV1(&ticket, validator); err != nil {
		t.Fatal(err)
	}
	return ticket
}

// A static signature is bound to its own domain: neither a v4-style
// signature nor a receipt-domain signature by the same key authorizes a
// static ticket, and a changed site is never authorized.
func TestStaticTicketSignatureIsDomainSeparatedAndBindsTheSite(t *testing.T) {
	_, validator, _ := ed25519.GenerateKey(rand.Reader)
	_, miner, _ := ed25519.GenerateKey(rand.Reader)
	ticket := staticTicket(t, validator, miner)
	key := validator.Public().(ed25519.PublicKey)
	if err := protocol.VerifyStaticTicketV1Signature(ticket, key); err != nil {
		t.Fatal(err)
	}
	changed := ticket
	changed.SiteDigest = "sha256:" + strings.Repeat("00", 32)
	changed.SiteManifestKey = static.ManifestKey(changed.SiteDigest)
	if protocol.VerifyStaticTicketV1Signature(changed, key) == nil {
		t.Fatal("a ticket for another site verified")
	}
	unsigned := ticket
	unsigned.Signature = ""
	v4Style, _ := json.Marshal(unsigned)
	forged := ticket
	forged.Signature = hex.EncodeToString(ed25519.Sign(validator, v4Style))
	if protocol.VerifyStaticTicketV1Signature(forged, key) == nil {
		t.Fatal("an undomained signature verified")
	}
	var members map[string]any
	_ = json.Unmarshal(v4Style, &members)
	delete(members, "signature")
	canonical, err := organic.Canonical(members)
	if err != nil {
		t.Fatal(err)
	}
	for domain, valid := range map[string]bool{protocol.StaticTicketSigningDomain: true, protocol.StaticReceiptSigningDomain: false} {
		forged.Signature = hex.EncodeToString(ed25519.Sign(validator, append(append([]byte(domain), 0), canonical...)))
		if err := protocol.VerifyStaticTicketV1Signature(forged, key); (err == nil) != valid {
			t.Fatalf("domain %s: verify error %v, want valid=%v", domain, err, valid)
		}
	}
}

// Old peers reject a static ticket neutrally: the deployment.v4 decoders
// never accept its bytes (§12).
func TestDeploymentV4DecodersRejectStaticTickets(t *testing.T) {
	_, validator, _ := ed25519.GenerateKey(rand.Reader)
	_, miner, _ := ed25519.GenerateKey(rand.Reader)
	encoded, err := json.Marshal(staticTicket(t, validator, miner))
	if err != nil {
		t.Fatal(err)
	}
	var lifecycle protocol.Ticket
	if json.Unmarshal(encoded, &lifecycle) == nil {
		t.Fatal("deployment.v4 lifecycle decoder accepted a static ticket")
	}
}
