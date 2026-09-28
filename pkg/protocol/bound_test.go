// SPDX-License-Identifier: AGPL-3.0-only

package protocol

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

func goldenTicketV4(t *testing.T) (TicketV4, ed25519.PrivateKey) {
	t.Helper()
	validatorKey, _, _ := bridgeKeys(t)
	var ticket TicketV4
	if err := json.Unmarshal(readContractFixture(t, "deployment-ticket.v4.json"), &ticket); err != nil {
		t.Fatal(err)
	}
	return ticket, validatorKey
}

func TestBoundTicketRejectsHotkeyUIDBlockAndNetworkReplay(t *testing.T) {
	ticket, validatorKey := goldenTicketV4(t)
	publicKey := validatorKey.Public().(ed25519.PublicKey)
	binding := ticket.Subnet
	uid := *binding.MinerUID
	wrongUID := uid + 1
	valid := func(block uint64, network, validator, miner string, minerUID *uint16) error {
		return VerifyBoundTicket(ticket, publicKey, ticket.IssuedAt, block, network, binding.NetUID, validator, miner, minerUID)
	}
	if err := valid(binding.ChainBlock+1, binding.Network, binding.ValidatorHotkey, binding.MinerHotkey, &uid); err != nil {
		t.Fatalf("valid bound ticket rejected: %v", err)
	}
	for _, test := range []struct {
		name      string
		block     uint64
		network   string
		validator string
		miner     string
		uid       *uint16
	}{
		{"wrong validator", binding.ChainBlock + 1, binding.Network, "5Other", binding.MinerHotkey, &uid},
		{"wrong miner", binding.ChainBlock + 1, binding.Network, binding.ValidatorHotkey, "5Other", &uid},
		{"wrong uid", binding.ChainBlock + 1, binding.Network, binding.ValidatorHotkey, binding.MinerHotkey, &wrongUID},
		{"missing uid", binding.ChainBlock + 1, binding.Network, binding.ValidatorHotkey, binding.MinerHotkey, nil},
		{"expired block", binding.ExpiresAtBlock, binding.Network, binding.ValidatorHotkey, binding.MinerHotkey, &uid},
		{"future block", binding.ChainBlock - 3, binding.Network, binding.ValidatorHotkey, binding.MinerHotkey, &uid},
		{"wrong network", binding.ChainBlock + 1, "test", binding.ValidatorHotkey, binding.MinerHotkey, &uid},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := valid(test.block, test.network, test.validator, test.miner, test.uid); err == nil {
				t.Fatal("expected identity replay rejection")
			}
		})
	}
}

// Tickets permit exactly thirty seconds of issuer clock lead.
func TestTicketPermitsOnlyExplicitThirtySecondFutureClockSkew(t *testing.T) {
	ticket, validatorKey := goldenTicketV4(t)
	publicKey := validatorKey.Public().(ed25519.PublicKey)
	earliest := ticket.IssuedAt.Add(-30 * time.Second)
	if err := VerifyTicketV4(ticket, publicKey, earliest); err != nil {
		t.Fatalf("exact permitted clock skew rejected: %v", err)
	}
	if err := VerifyTicketV4(ticket, publicKey, earliest.Add(-time.Nanosecond)); err == nil {
		t.Fatal("ticket beyond permitted future clock skew verified")
	}
	if err := VerifyTicketV4(ticket, publicKey, ticket.ExpiresAt); err == nil {
		t.Fatal("ticket verified at its expiry instant")
	}
}

func TestBoundTicketRejectsTransportDowngradeAndMalformedPin(t *testing.T) {
	ticket, validatorKey := goldenTicketV4(t)
	publicKey := validatorKey.Public().(ed25519.PublicKey)
	pin := *ticket.Subnet.MinerTLSCertificateSHA256
	for name, mutate := range map[string]func(*TicketV4){
		"empty transport":      func(value *TicketV4) { value.Subnet.MinerTransport = "" },
		"http with https pin":  func(value *TicketV4) { value.Subnet.MinerTransport = "http" },
		"uppercase pin":        func(value *TicketV4) { bad := "ABC" + pin[3:]; value.Subnet.MinerTLSCertificateSHA256 = &bad },
		"missing https pin":    func(value *TicketV4) { value.Subnet.MinerTLSCertificateSHA256 = nil },
		"legacy version label": func(value *TicketV4) { value.Version = "deployment.v2" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := ticket
			binding := *ticket.Subnet
			candidate.Subnet = &binding
			mutate(&candidate)
			if err := VerifyTicketV4Signature(candidate, publicKey); err == nil {
				t.Fatal("transport downgrade or legacy version was accepted")
			}
		})
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
