// SPDX-License-Identifier: AGPL-3.0-only

package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"
)

func TestBoundTicketRejectsHotkeyUIDBlockAndOldVersionReplay(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uid := uint16(7)
	pin := hex.EncodeToString(make([]byte, 32))
	now := time.Now().UTC()
	ticket := Ticket{
		Version: BoundVersion, DeploymentID: "bound", Generation: 2, ImageDigest: "sha256:abc", ManifestKey: "manifest",
		MinerID: "miner-hotkey", RouteHost: "bound.test", AssignmentNonce: "nonce", ChallengePath: "/challenge",
		ChallengeSHA256: ChallengeDigest("secret"), Resources: ResourceLimits{CPUMillis: 1, MemoryMB: 16, DiskMB: 16},
		Health:   HealthSpec{Path: "/healthz", ExpectedStatus: 200, IntervalMillis: 1, TimeoutMillis: 1, ConsecutiveFailure: 1},
		IssuedAt: now, ExpiresAt: now.Add(time.Minute),
		Subnet: &SubnetBinding{
			Network: "test", NetUID: 24, ValidatorHotkey: "validator-hotkey", MinerHotkey: "miner-hotkey", MinerUID: &uid,
			MinerAxonURL: "https://8.8.8.8:8091", MinerTransport: "https", MinerTLSCertificateSHA256: &pin,
			ChainBlock: 100, Epoch: 10, ExpiresAtBlock: 112, ValidatorServicePublicKey: hex.EncodeToString(publicKey),
			MinerServicePublicKey: hex.EncodeToString(make([]byte, ed25519.PublicKeySize)),
		},
	}
	if err := SignTicket(&ticket, privateKey); err != nil {
		t.Fatal(err)
	}
	if err := VerifyBoundTicket(ticket, publicKey, now, 101, "test", 24, "validator-hotkey", "miner-hotkey", &uid); err != nil {
		t.Fatalf("valid bound ticket rejected: %v", err)
	}
	wrongUID := uint16(8)
	cases := []struct {
		name      string
		block     uint64
		validator string
		miner     string
		uid       *uint16
		network   string
	}{
		{"wrong validator", 101, "other", "miner-hotkey", &uid, "test"},
		{"wrong miner", 101, "validator-hotkey", "other", &uid, "test"},
		{"wrong uid", 101, "validator-hotkey", "miner-hotkey", &wrongUID, "test"},
		{"missing uid", 101, "validator-hotkey", "miner-hotkey", nil, "test"},
		{"expired block", 112, "validator-hotkey", "miner-hotkey", &uid, "test"},
		{"wrong network", 101, "validator-hotkey", "miner-hotkey", &uid, "finney"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if err := VerifyBoundTicket(ticket, publicKey, now, test.block, test.network, 24, test.validator, test.miner, test.uid); err == nil {
				t.Fatal("expected identity replay rejection")
			}
		})
	}
	ticket.Version = Version
	if err := SignTicket(&ticket, privateKey); err != nil {
		t.Fatal(err)
	}
	if err := VerifyBoundTicket(ticket, publicKey, now, 101, "test", 24, "validator-hotkey", "miner-hotkey", &uid); err == nil {
		t.Fatal("legacy ticket was accepted on the neuron bridge")
	}
}

func TestBoundTicketRejectsTransportDowngradeAndMalformedPin(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pin := hex.EncodeToString(make([]byte, 32))
	now := time.Now().UTC()
	ticket := Ticket{
		Version: BoundVersion, DeploymentID: "bound", Generation: 1, MinerID: "miner", AssignmentNonce: "nonce",
		IssuedAt: now, ExpiresAt: now.Add(time.Minute),
		Subnet: &SubnetBinding{
			Network: "test", NetUID: 24, ValidatorHotkey: "validator", MinerHotkey: "miner",
			MinerAxonURL: "https://8.8.8.8:8091", MinerTransport: "https", MinerTLSCertificateSHA256: &pin,
			ChainBlock: 1, ExpiresAtBlock: 2, ValidatorServicePublicKey: hex.EncodeToString(publicKey),
			MinerServicePublicKey: hex.EncodeToString(make([]byte, ed25519.PublicKeySize)),
		},
	}
	if err := SignTicket(&ticket, privateKey); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Ticket){
		func(value *Ticket) { value.Subnet.MinerTransport = "" },
		func(value *Ticket) { value.Subnet.MinerTransport = "http" },
		func(value *Ticket) { bad := "ABC" + pin[3:]; value.Subnet.MinerTLSCertificateSHA256 = &bad },
		func(value *Ticket) { value.Subnet.MinerTLSCertificateSHA256 = nil },
		func(value *Ticket) { value.Version = "deployment.v2" },
	} {
		copyTicket := ticket
		copyBinding := *ticket.Subnet
		copyTicket.Subnet = &copyBinding
		mutate(&copyTicket)
		if err := VerifyTicketSignature(copyTicket, publicKey); err == nil {
			t.Fatal("transport downgrade or legacy version was accepted")
		}
	}
}

func TestSubnetBindingRejectsUnsafeOrNoncanonicalAxonURL(t *testing.T) {
	pin := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	base := SubnetBinding{
		Network: "test", ValidatorHotkey: "validator", MinerHotkey: "miner", MinerAxonURL: "https://8.8.8.8:8091",
		MinerTransport: "https", MinerTLSCertificateSHA256: &pin, ChainBlock: 1, ExpiresAtBlock: 2,
		ValidatorServicePublicKey: hex.EncodeToString(make([]byte, ed25519.PublicKeySize)),
		MinerServicePublicKey:     hex.EncodeToString(make([]byte, ed25519.PublicKeySize)),
	}
	for _, raw := range []string{
		"http://8.8.8.8:8091", "https://user@8.8.8.8:8091", "https://8.8.8.8:8091/",
		"https://8.8.8.8:8091?", "https://8.8.8.8:8091#fragment", "https://miner.example:8091",
		"https://[2606:4700:4700:0:0:0:0:1111]:8091",
	} {
		binding := base
		binding.MinerAxonURL = raw
		if err := ValidateSubnetBinding(&binding); err == nil {
			t.Fatalf("unsafe or noncanonical axon URL %q was accepted", raw)
		}
	}
	binding := base
	binding.MinerAxonURL = "https://[2606:4700:4700::1111]:8091"
	if err := ValidateSubnetBinding(&binding); err != nil {
		t.Fatalf("canonical IPv6 axon rejected: %v", err)
	}
	mockBinding := base
	mockBinding.MinerAxonURL = "http://miner-1:8091"
	mockBinding.MinerTransport = "http"
	mockBinding.MinerTLSCertificateSHA256 = nil
	if err := ValidateSubnetBinding(&mockBinding); err != nil {
		t.Fatalf("explicit mock HTTP hostname binding rejected: %v", err)
	}
}
