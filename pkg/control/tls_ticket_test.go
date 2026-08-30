// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/ledger"
	"github.com/misscomputer/misscomputer-subnet/pkg/miner"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
)

type tlsBoundAssigner struct {
	key      ed25519.PublicKey
	identity miner.SubnetIdentity
}

func (a tlsBoundAssigner) ID() string                           { return a.identity.Hotkey }
func (a tlsBoundAssigner) PublicKey() ed25519.PublicKey         { return a.key }
func (a tlsBoundAssigner) SubnetIdentity() miner.SubnetIdentity { return a.identity }
func (a tlsBoundAssigner) Assign(context.Context, protocol.Ticket) (miner.Result, error) {
	return miner.Result{}, nil
}
func (a tlsBoundAssigner) Deactivate(context.Context, string) error { return nil }

func TestSchedulerSignsExactMinerHTTPSPinIntoBoundTicket(t *testing.T) {
	validatorPublic, validatorPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	minerPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uid := uint16(7)
	pin := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	assigner := tlsBoundAssigner{
		key: minerPublic,
		identity: miner.SubnetIdentity{
			Hotkey: "miner", UID: &uid, AxonURL: "https://8.8.8.8:8091", Transport: "https", TransportCertificateSHA256: pin,
		},
	}
	scheduler := &Scheduler{SigningKey: validatorPrivate}
	scheduler.SetSubnet(protocol.SubnetBinding{
		Network: "test", NetUID: 24, ValidatorHotkey: "validator", ChainBlock: 100, ExpiresAtBlock: 112,
		ValidatorServicePublicKey: hex.EncodeToString(validatorPublic),
	})
	now := time.Now().UTC()
	ticket, err := scheduler.ticket(DeployRequest{DeploymentID: "app"}, assigner, "app.example", 1, now)
	if err != nil {
		t.Fatal(err)
	}
	if ticket.Version != protocol.BoundVersion || ticket.Subnet == nil || ticket.Subnet.MinerAxonURL != assigner.identity.AxonURL ||
		ticket.Subnet.MinerTransport != "https" || ticket.Subnet.MinerTLSCertificateSHA256 == nil || *ticket.Subnet.MinerTLSCertificateSHA256 != pin {
		t.Fatalf("ticket lost the exact miner HTTPS transport identity: %+v", ticket.Subnet)
	}
	if err := protocol.VerifyTicketSignature(ticket, validatorPublic); err != nil {
		t.Fatalf("bound TLS ticket signature invalid: %v", err)
	}
}

func TestReservedCandidateCannotMixWithLaterSubnetPublication(t *testing.T) {
	validatorPublic, validatorPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	oldMinerPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newMinerPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	oldUID, newUID := uint16(7), uint16(9)
	oldCandidate := tlsBoundAssigner{
		key: oldMinerPublic,
		identity: miner.SubnetIdentity{
			Hotkey: "rebound-miner", UID: &oldUID, AxonURL: "https://8.8.8.7:8091", Transport: "https",
			TransportCertificateSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	}
	newCandidate := tlsBoundAssigner{
		key: newMinerPublic,
		identity: miner.SubnetIdentity{
			Hotkey: "rebound-miner", UID: &newUID, AxonURL: "https://8.8.8.9:8091", Transport: "https",
			TransportCertificateSHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		},
	}
	scheduler := &Scheduler{SigningKey: validatorPrivate, Ledger: ledger.New()}
	oldSubnet := protocol.SubnetBinding{
		Network: "test", NetUID: 24, ValidatorHotkey: "validator", ChainBlock: 100, Epoch: 8, ExpiresAtBlock: 112,
		ValidatorServicePublicKey: hex.EncodeToString(validatorPublic),
	}
	if err := scheduler.InstallPublication("old-publication", oldSubnet, []miner.Assigner{oldCandidate}); err != nil {
		t.Fatal(err)
	}
	state, err := scheduler.beginDeployment(DeployRequest{DeploymentID: "atomic-pub"}, "atomic-pub.test", 1)
	if err != nil {
		t.Fatal(err)
	}
	reserved, _ := scheduler.reserveInitialCandidate(state)
	if reserved == nil || string(reserved.candidate.PublicKey()) != string(oldMinerPublic) || reserved.publicationID != "old-publication" {
		t.Fatal("old publication candidate was not reserved")
	}

	// Deterministic interleaving from SOL-005-R1-GO-PAIR: install a rebound
	// publication after reservation but before ticket signing.
	newSubnet := protocol.SubnetBinding{
		Network: "test", NetUID: 24, ValidatorHotkey: "validator", ChainBlock: 101, Epoch: 8, ExpiresAtBlock: 113,
		ValidatorServicePublicKey: hex.EncodeToString(validatorPublic),
	}
	if err := scheduler.InstallPublication("new-publication", newSubnet, []miner.Assigner{newCandidate}); err != nil {
		t.Fatal(err)
	}
	ticket, err := scheduler.ticketForReservation(
		state.request, reserved, state.routeHost, state.generation, time.Now().UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if ticket.Subnet == nil || ticket.Subnet.ChainBlock != 100 || ticket.Subnet.MinerUID == nil || *ticket.Subnet.MinerUID != oldUID || ticket.Subnet.MinerAxonURL != oldCandidate.identity.AxonURL {
		t.Fatalf("reserved old candidate was signed with a mixed publication: %+v", ticket.Subnet)
	}
}

func TestConcurrentPublicationInstallAndReservationNeverMix(t *testing.T) {
	validatorPublic, validatorPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	makeCandidate := func(uid uint16, octet byte) tlsBoundAssigner {
		public, _, keyErr := ed25519.GenerateKey(rand.Reader)
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		return tlsBoundAssigner{
			key: public,
			identity: miner.SubnetIdentity{
				Hotkey: "atomic-miner", UID: &uid, AxonURL: fmt.Sprintf("https://8.8.8.%d:8091", octet), Transport: "https",
				TransportCertificateSHA256: fmt.Sprintf("%064x", octet),
			},
		}
	}
	first, second := makeCandidate(7, 7), makeCandidate(9, 9)
	makeSubnet := func(block uint64) protocol.SubnetBinding {
		return protocol.SubnetBinding{
			Network: "test", NetUID: 24, ValidatorHotkey: "validator", ChainBlock: block,
			Epoch: block / 12, ExpiresAtBlock: block + 12,
			ValidatorServicePublicKey: hex.EncodeToString(validatorPublic),
		}
	}
	scheduler := &Scheduler{SigningKey: validatorPrivate, Ledger: ledger.New()}
	if err := scheduler.InstallPublication("first", makeSubnet(100), []miner.Assigner{first}); err != nil {
		t.Fatal(err)
	}
	state, err := scheduler.beginDeployment(DeployRequest{DeploymentID: "atomic-race"}, "atomic-race.test", 1)
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var writer sync.WaitGroup
	writer.Add(1)
	go func() {
		defer writer.Done()
		for index := 0; ; index++ {
			select {
			case <-stop:
				return
			default:
			}
			if index%2 == 0 {
				_ = scheduler.InstallPublication("first", makeSubnet(100), []miner.Assigner{first})
			} else {
				_ = scheduler.InstallPublication("second", makeSubnet(101), []miner.Assigner{second})
			}
		}
	}()
	defer func() {
		close(stop)
		writer.Wait()
	}()
	for index := 0; index < 2_000; index++ {
		reservation, _ := scheduler.reserveInitialCandidate(state)
		if reservation == nil || reservation.subnet == nil {
			t.Fatal("publication reservation unexpectedly empty")
		}
		identity := reservation.candidate.(tlsBoundAssigner).identity
		if identity.UID == nil {
			t.Fatal("publication candidate UID unexpectedly empty")
		}
		switch reservation.publicationID {
		case "first":
			if reservation.subnet.ChainBlock != 100 || *identity.UID != 7 {
				t.Fatalf("mixed first publication: subnet=%+v identity=%+v", reservation.subnet, identity)
			}
		case "second":
			if reservation.subnet.ChainBlock != 101 || *identity.UID != 9 {
				t.Fatalf("mixed second publication: subnet=%+v identity=%+v", reservation.subnet, identity)
			}
		default:
			t.Fatalf("unknown publication reservation %q", reservation.publicationID)
		}
		scheduler.releaseReservation(state, reservation.candidate.ID())
	}
}
