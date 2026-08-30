// SPDX-License-Identifier: AGPL-3.0-only

package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestTicketSignatureAndTampering(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	ticket := Ticket{DeploymentID: "d1", ImageDigest: "sha256:abc", IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
	if err := SignTicket(&ticket, priv); err != nil {
		t.Fatal(err)
	}
	if err := VerifyTicket(ticket, pub, now); err != nil {
		t.Fatal(err)
	}
	ticket.ImageDigest = "sha256:tampered"
	if err := VerifyTicket(ticket, pub, now); err == nil {
		t.Fatal("tampered ticket verified")
	}
}
