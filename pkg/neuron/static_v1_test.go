// SPDX-License-Identifier: AGPL-3.0-only

package neuron

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/misscomputer/misscomputer-subnet/pkg/organic"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	"github.com/misscomputer/misscomputer-subnet/pkg/static"
)

func staticContracts(t *testing.T) string {
	t.Helper()
	_, source, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(source), "..", "..", "contracts"))
}

func readStatic(t *testing.T, parts ...string) []byte {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join(append([]string{staticContracts(t)}, parts...)...))
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

var staticGoContracts = map[string]func() organic.Validator{
	"static-site-manifest.v1":      func() organic.Validator { return &static.Manifest{} },
	"static-deployment-ticket.v1":  func() organic.Validator { return &protocol.StaticTicketV1{} },
	"static-deployment-receipt.v1": func() organic.Validator { return &protocol.StaticReceiptV1{} },
	"static-deploy.v1":             func() organic.Validator { return &StaticDeploySynapseV1{} },
	"static-local-assign.v1":       func() organic.Validator { return &LocalStaticAssignRequestV1{} },
	"static-bridge-assign.v1":      func() organic.Validator { return &BridgeStaticAssignRequestV1{} },
	"static-deploy-response.v1":    func() organic.Validator { return &StaticDeployResponseV1{} },
	"static-status.v1":             func() organic.Validator { return &StaticStatusSynapseV1{} },
	"static-status-response.v1":    func() organic.Validator { return &StaticStatusResponseV1{} },
}

// The Python-generated static goldens decode canonically in Go, and Go
// verifies their signatures and re-derives every identity in the vectors.
func TestStaticGoldensAreGoCanonicalAndVerify(t *testing.T) {
	for stem, factory := range staticGoContracts {
		t.Run(stem, func(t *testing.T) {
			if err := organic.DecodeCanonical(readStatic(t, "fixtures", stem+".json"), factory()); err != nil {
				t.Fatal(err)
			}
		})
	}
	var vectors struct {
		Keys struct {
			Miner struct {
				PublicKeyHex string `json:"public_key_hex"`
			} `json:"miner_service"`
			Validator struct {
				PublicKeyHex string `json:"public_key_hex"`
			} `json:"validator_service"`
		} `json:"keys"`
		Site struct {
			SiteDigest      string `json:"site_digest"`
			SiteManifestKey string `json:"site_manifest_key"`
			StoredBytes     int    `json:"stored_bytes"`
		} `json:"site_manifest"`
		Ticket struct {
			TicketDigest string `json:"ticket_digest"`
		} `json:"ticket"`
		Receipt struct {
			EndpointID    string `json:"endpoint_id"`
			ReceiptDigest string `json:"receipt_digest"`
		} `json:"receipt"`
	}
	if err := json.Unmarshal(readStatic(t, "fixtures", "static-contract-vectors.v1.json"), &vectors); err != nil {
		t.Fatal(err)
	}
	stored := readStatic(t, "fixtures", "static-site-manifest.v1.json")
	if _, err := static.Parse(stored, vectors.Site.SiteDigest); err != nil || len(stored) != vectors.Site.StoredBytes ||
		static.ManifestKey(vectors.Site.SiteDigest) != vectors.Site.SiteManifestKey {
		t.Fatalf("site manifest identity: %v", err)
	}
	key := func(hexKey string) ed25519.PublicKey {
		decoded, err := hex.DecodeString(hexKey)
		if err != nil {
			t.Fatal(err)
		}
		return decoded
	}
	var ticket protocol.StaticTicketV1
	var receipt protocol.StaticReceiptV1
	_ = organic.DecodeCanonical(readStatic(t, "fixtures", "static-deployment-ticket.v1.json"), &ticket)
	_ = organic.DecodeCanonical(readStatic(t, "fixtures", "static-deployment-receipt.v1.json"), &receipt)
	if err := protocol.VerifyStaticTicketV1Signature(ticket, key(vectors.Keys.Validator.PublicKeyHex)); err != nil {
		t.Fatal(err)
	}
	if err := protocol.VerifyStaticReceiptV1(receipt, key(vectors.Keys.Miner.PublicKeyHex)); err != nil {
		t.Fatal(err)
	}
	if err := protocol.StaticReceiptMatchesTicketV1(ticket, receipt); err != nil {
		t.Fatal(err)
	}
	ticketDigest, _ := protocol.StaticTicketDigestV1(ticket)
	receiptDigest, _ := protocol.StaticReceiptDigestV1(receipt)
	if ticketDigest != vectors.Ticket.TicketDigest || receiptDigest != vectors.Receipt.ReceiptDigest ||
		protocol.StaticEndpointIDV1(ticket) != vectors.Receipt.EndpointID {
		t.Fatalf("digests %s %s, vectors %+v %+v", ticketDigest, receiptDigest, vectors.Ticket, vectors.Receipt)
	}
}

// Go rejects every static negative document Python rejects.
func TestStaticNegativeCorpusIsRejected(t *testing.T) {
	checked := 0
	for stem, factory := range staticGoContracts {
		files, _ := filepath.Glob(filepath.Join(staticContracts(t), "negative", stem, "*.json"))
		for _, file := range files {
			var wrapper struct {
				Case     string          `json:"case"`
				Code     string          `json:"code"`
				Document json.RawMessage `json:"document"`
				Expect   string          `json:"expect"`
			}
			payload, err := os.ReadFile(file)
			if err != nil || json.Unmarshal(payload, &wrapper) != nil {
				t.Fatalf("unreadable negative fixture %s", file)
			}
			t.Run(stem+"/"+wrapper.Case, func(t *testing.T) {
				err := organic.DecodeStrict(wrapper.Document, factory())
				if err == nil {
					t.Fatalf("Go accepted a document Python rejects with %s", wrapper.Code)
				}
				if wrapper.Expect == "model" && !strings.Contains(err.Error(), wrapper.Code) {
					t.Fatalf("rejected for %q, want %s", err, wrapper.Code)
				}
			})
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no static negative fixtures found")
	}
}
