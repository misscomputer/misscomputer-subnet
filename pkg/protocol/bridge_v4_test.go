// SPDX-License-Identifier: AGPL-3.0-only

package protocol

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type bridgeVectors struct {
	Keys struct {
		MinerService struct {
			SeedHex string `json:"seed_hex"`
		} `json:"miner_service"`
		ValidatorService struct {
			SeedHex string `json:"seed_hex"`
		} `json:"validator_service"`
	} `json:"keys"`
	Ticket struct {
		TicketDigest string `json:"ticket_digest"`
	} `json:"ticket"`
}

func readContractFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "contracts", "fixtures", name))
	if err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSuffix(raw, []byte("\n"))
}

func bridgeKeys(t *testing.T) (validator, miner ed25519.PrivateKey, vectors bridgeVectors) {
	t.Helper()
	if err := json.Unmarshal(readContractFixture(t, "organic-contract-vectors.v1.json"), &vectors); err != nil {
		t.Fatal(err)
	}
	key := func(seedHex string) ed25519.PrivateKey {
		seed, err := hex.DecodeString(seedHex)
		if err != nil || len(seed) != ed25519.SeedSize {
			t.Fatalf("vector seed is invalid: %v", err)
		}
		return ed25519.NewKeyFromSeed(seed)
	}
	return key(vectors.Keys.ValidatorService.SeedHex), key(vectors.Keys.MinerService.SeedHex), vectors
}

// The golden deployment.v4 ticket and receipt decode into the lifecycle
// types, keep their exact signed bytes, and sign/verify/match through the
// lifecycle functions every caller uses.
func TestLifecycleTypesCarryGoldenDeploymentV4Exactly(t *testing.T) {
	validatorKey, minerKey, vectors := bridgeKeys(t)
	ticketJSON := readContractFixture(t, "deployment-ticket.v4.json")
	receiptJSON := readContractFixture(t, "deployment-receipt.v4.json")
	var ticket Ticket
	var golden TicketV4
	if err := json.Unmarshal(ticketJSON, &ticket); err != nil {
		t.Fatalf("lifecycle ticket rejected the golden v4 ticket: %v", err)
	}
	if err := json.Unmarshal(ticketJSON, &golden); err != nil {
		t.Fatal(err)
	}
	if ticket.Organic == nil || ticket.Organic.Workload.ContainerPort != golden.Workload.ContainerPort {
		t.Fatalf("lifecycle ticket lost the v4 body: %+v", ticket)
	}
	lifecycleJSON, err := json.Marshal(ticket)
	if err != nil {
		t.Fatal(err)
	}
	goldenJSON, _ := json.Marshal(golden)
	if !bytes.Equal(lifecycleJSON, goldenJSON) {
		t.Fatalf("lifecycle encoding differs from TicketV4:\n%s\n%s", lifecycleJSON, goldenJSON)
	}
	if digest, err := TicketDigest(ticket); err != nil || digest != vectors.Ticket.TicketDigest {
		t.Fatalf("lifecycle ticket digest = %s, %v", digest, err)
	}
	validator := validatorKey.Public().(ed25519.PublicKey)
	if err := VerifyTicket(ticket, validator, ticket.IssuedAt); err != nil {
		t.Fatalf("lifecycle verification of the golden ticket: %v", err)
	}
	resigned := ticket
	resigned.Signature = ""
	if err := SignTicket(&resigned, validatorKey); err != nil || resigned.Signature != ticket.Signature {
		t.Fatalf("lifecycle signing bytes differ from the golden ticket: %v", err)
	}
	tampered := ticket
	tampered.Organic = &OrganicTicket{Workload: golden.Workload, Resources: golden.Resources, Health: golden.Health}
	tampered.Organic.Workload.ContainerPort, tampered.Organic.Workload.Env.Port = 9090, "9090"
	if err := VerifyTicketSignature(tampered, validator); err == nil {
		t.Fatal("a tampered v4 workload verified")
	}

	var receipt Receipt
	if err := json.Unmarshal(receiptJSON, &receipt); err != nil {
		t.Fatalf("lifecycle receipt rejected the golden v4 receipt: %v", err)
	}
	if err := VerifyReceipt(receipt, minerKey.Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("lifecycle verification of the golden receipt: %v", err)
	}
	if receipt.LoadedImageConfigDigest == nil {
		t.Fatal("ready receipt lost loaded_image_config_digest")
	}
	if err := ReceiptMatchesTicket(ticket, receipt, *receipt.LoadedImageConfigDigest); err != nil {
		t.Fatalf("golden receipt does not answer the golden ticket: %v", err)
	}
	resignedReceipt := receipt
	resignedReceipt.Signature = ""
	if err := SignReceipt(&resignedReceipt, minerKey); err != nil || resignedReceipt.Signature != receipt.Signature {
		t.Fatalf("lifecycle receipt signing bytes differ: %v", err)
	}
}

// A deployment.v4 value can never carry or smuggle a synthetic challenge,
// and no other assignment version encodes, signs or decodes.
func TestDeploymentV4FailsClosedOnLegacyShapes(t *testing.T) {
	validatorKey, _, _ := bridgeKeys(t)
	ticketJSON := readContractFixture(t, "deployment-ticket.v4.json")
	for name, mutate := range map[string]func(map[string]any){
		"challenge path":   func(doc map[string]any) { doc["challenge_path"] = "/__challenge/x" },
		"challenge digest": func(doc map[string]any) { doc["challenge_sha256"] = strings.Repeat("a", 64) },
		"unknown field":    func(doc map[string]any) { doc["image"] = "nginx" },
		"v3 health shape": func(doc map[string]any) {
			doc["health"] = map[string]any{"path": "/", "expected_status": 200, "interval_millis": 1, "timeout_millis": 1, "consecutive_failure": 1}
		},
	} {
		t.Run("decode "+name, func(t *testing.T) {
			var document map[string]any
			if err := json.Unmarshal(ticketJSON, &document); err != nil {
				t.Fatal(err)
			}
			mutate(document)
			encoded, _ := json.Marshal(document)
			var ticket Ticket
			if err := json.Unmarshal(encoded, &ticket); err == nil {
				t.Fatal("lifecycle ticket decoded a non-v4 shape as deployment.v4")
			}
		})
	}
	var ticket Ticket
	if err := json.Unmarshal(ticketJSON, &ticket); err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"deployment.v1", "deployment.v3", ""} {
		downgraded := ticket
		downgraded.Version = version
		if _, err := json.Marshal(downgraded); err == nil {
			t.Fatalf("v4 workload encoded under %q", version)
		}
		if err := SignTicket(&downgraded, validatorKey); err == nil {
			t.Fatalf("a %q ticket was signed", version)
		}
		code := "internal"
		if _, err := json.Marshal(Receipt{Version: version, ErrorCode: &code}); err == nil {
			t.Fatalf("v4 error_code encoded under %q", version)
		}
	}
	downgraded := ticket
	downgraded.Version = "deployment.v3"
	if err := ReceiptMatchesTicket(downgraded, Receipt{Version: OrganicVersion}, ""); err == nil {
		t.Fatal("receipt matching accepted a non-v4 ticket")
	}
}

// Network verification accepts exactly the subnet-bound versions, and the
// golden deployment.v4 ticket passes every identity check.
func TestVerifyBoundTicketAcceptsDeploymentV4(t *testing.T) {
	validatorKey, _, _ := bridgeKeys(t)
	var ticket Ticket
	if err := json.Unmarshal(readContractFixture(t, "deployment-ticket.v4.json"), &ticket); err != nil {
		t.Fatal(err)
	}
	binding := ticket.Subnet
	verify := func(candidate Ticket) error {
		v4, err := candidate.V4()
		if err != nil {
			return err
		}
		return VerifyBoundTicket(v4, validatorKey.Public().(ed25519.PublicKey), candidate.IssuedAt, binding.ChainBlock+1,
			binding.Network, binding.NetUID, binding.ValidatorHotkey, binding.MinerHotkey, binding.MinerUID)
	}
	if err := verify(ticket); err != nil {
		t.Fatalf("golden v4 ticket failed bound verification: %v", err)
	}
	for _, version := range []string{"deployment.v1", "deployment.v2", "deployment.v3"} {
		legacy := ticket
		legacy.Version, legacy.Organic = version, nil
		if err := verify(legacy); err == nil {
			t.Fatalf("%s ticket passed bound verification", version)
		}
	}
	expired, _ := ticket.V4()
	if err := VerifyBoundTicket(expired, validatorKey.Public().(ed25519.PublicKey), ticket.ExpiresAt.Add(time.Second), binding.ChainBlock+1,
		binding.Network, binding.NetUID, binding.ValidatorHotkey, binding.MinerHotkey, binding.MinerUID); err == nil {
		t.Fatal("expired v4 ticket passed bound verification")
	}
}

// A version-less JSON overlay merges into a v4 receipt with encoding/json
// semantics, which the miner uses to stamp v4 evidence by wire name.
func TestReceiptOverlayMergesIntoDeploymentV4(t *testing.T) {
	receipt := Receipt{Version: OrganicVersion, DeploymentID: "hello", Stage: StageReady}
	if err := json.Unmarshal([]byte(`{"loaded_image_config_digest":"sha256:`+strings.Repeat("b", 64)+`","error_code":null}`), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.DeploymentID != "hello" || receipt.LoadedImageConfigDigest == nil || *receipt.LoadedImageConfigDigest != "sha256:"+strings.Repeat("b", 64) {
		t.Fatalf("overlay did not merge: %+v", receipt)
	}
	if err := json.Unmarshal([]byte(`{"challenge_path":"/c"}`), &receipt); err == nil {
		t.Fatal("a v4 receipt accepted an unknown field")
	}
	legacy := Receipt{Version: "deployment.v3"}
	if err := json.Unmarshal([]byte(`{"error_code":"internal"}`), &legacy); err == nil {
		t.Fatal("a deployment.v3 receipt decoded")
	}
}
