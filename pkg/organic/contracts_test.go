// SPDX-License-Identifier: AGPL-3.0-only

package organic_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
	"github.com/misscomputer/misscomputer-subnet/pkg/neuron"
	"github.com/misscomputer/misscomputer-subnet/pkg/organic"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
)

// contracts maps the public miner and verifier contract stems to their Go
// mirrors. Operator-only contracts are owned and tested in the private repo.
var contracts = map[string]func() organic.Validator{
	"artifact-manifest.v2":           func() organic.Validator { return &artifact.ManifestV2{} },
	"deployment-ticket.v4":           func() organic.Validator { return &protocol.TicketV4{} },
	"deployment-receipt.v4":          func() organic.Validator { return &protocol.ReceiptV4{} },
	"deploy.v3":                      func() organic.Validator { return &neuron.DeploySynapseV3{} },
	"deploy-response.v3":             func() organic.Validator { return &neuron.DeployResponseV3{} },
	"status-response.v3":             func() organic.Validator { return &neuron.StatusResponseV3{} },
	"bridge-assign.v3":               func() organic.Validator { return &neuron.BridgeAssignRequestV3{} },
	"edge-runtime-request.v1":        func() organic.Validator { return &organic.EdgeRuntimeRequest{} },
	"active-assignment-manifest.v2":  func() organic.Validator { return &organic.ActiveAssignmentManifestV2{} },
	"active-assignment-manifest.v3":  func() organic.Validator { return &organic.ActiveAssignmentManifestV3{} },
	"organic-probe-authorization.v1": func() organic.Validator { return &organic.ProbeAuthorization{} },
	"miner-probe-attestation.v2":     func() organic.Validator { return &organic.ProbeAttestationV2{} },
}

type vectorFile struct {
	Keys struct {
		MinerService        keyVector `json:"miner_service"`
		ValidatorService    keyVector `json:"validator_service"`
		ValidatorHotkeySS58 string    `json:"validator_hotkey_ss58"`
	} `json:"keys"`
	ArtifactManifest struct {
		ArtifactDigest string `json:"artifact_digest"`
		ManifestKey    string `json:"manifest_key"`
	} `json:"artifact_manifest"`
	Ticket struct {
		TicketDigest string `json:"ticket_digest"`
	} `json:"ticket"`
	EdgeRuntimeRequest struct {
		HeaderValue   string `json:"header_value"`
		MessageSHA256 string `json:"message_sha256"`
	} `json:"edge_runtime_request"`
	OrganicProbeAuthorization struct {
		MessageHex string `json:"message_hex"`
	} `json:"organic_probe_authorization"`
	MinerProbeAttestation struct {
		MessageSHA256 string `json:"message_sha256"`
	} `json:"miner_probe_attestation"`
}

type keyVector struct {
	PublicKeyHex string `json:"public_key_hex"`
	SeedHex      string `json:"seed_hex"`
}

func (k keyVector) private(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	seed, err := hex.DecodeString(k.SeedHex)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(seed)
	if hex.EncodeToString(key.Public().(ed25519.PublicKey)) != k.PublicKeyHex {
		t.Fatal("vector seed does not derive its public key")
	}
	return key
}

func (k keyVector) public(t *testing.T) ed25519.PublicKey {
	return k.private(t).Public().(ed25519.PublicKey)
}

func contractsRoot(t *testing.T) string {
	t.Helper()
	_, source, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(source), "..", "..", "contracts"))
}

func read(t *testing.T, parts ...string) []byte {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join(append([]string{contractsRoot(t)}, parts...)...))
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	var vectors vectorFile
	if err := json.Unmarshal(read(t, "fixtures", "organic-contract-vectors.v1.json"), &vectors); err != nil {
		t.Fatal(err)
	}
	return vectors
}

func decodeFixture[T organic.Validator](t *testing.T, stem string, out T) T {
	t.Helper()
	if err := organic.DecodeCanonical(read(t, "fixtures", stem+".json"), out); err != nil {
		t.Fatalf("%s: %v", stem, err)
	}
	return out
}

func TestGoldenFixturesRoundTripByteForByte(t *testing.T) {
	for stem, factory := range contracts {
		t.Run(stem, func(t *testing.T) {
			decodeFixture(t, stem, factory())
		})
	}
}

func TestNegativeCorpusIsRejected(t *testing.T) {
	directories, err := os.ReadDir(filepath.Join(contractsRoot(t), "negative"))
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, directory := range directories {
		factory, organicContract := contracts[directory.Name()]
		if !organicContract {
			continue
		}
		files, err := filepath.Glob(filepath.Join(contractsRoot(t), "negative", directory.Name(), "*.json"))
		if err != nil {
			t.Fatal(err)
		}
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
			t.Run(directory.Name()+"/"+wrapper.Case, func(t *testing.T) {
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
		t.Fatal("no organic negative fixtures found")
	}
}

func TestCrossLanguageDigests(t *testing.T) {
	vectors := loadVectors(t)
	payload := read(t, "fixtures", "artifact-manifest.v2.json")
	manifest, err := artifact.ParseManifestV2(payload, vectors.ArtifactManifest.ArtifactDigest)
	if err != nil {
		t.Fatal(err)
	}
	rendered, digest, err := artifact.MarshalManifestV2(manifest)
	if err != nil || string(rendered) != string(payload) || digest != vectors.ArtifactManifest.ArtifactDigest ||
		organic.ManifestKey(digest) != vectors.ArtifactManifest.ManifestKey {
		t.Fatalf("artifact digest drifted: %s %v", digest, err)
	}
	if _, err := artifact.ParseManifestV2(payload, "sha256:"+strings.Repeat("0", 64)); err == nil {
		t.Fatal("manifest bytes were accepted under another artifact digest")
	}

	ticket := decodeFixture(t, "deployment-ticket.v4", &protocol.TicketV4{})
	if digest, err := protocol.TicketDigestV4(*ticket); err != nil || digest != vectors.Ticket.TicketDigest {
		t.Fatalf("ticket digest drifted: %s %v", digest, err)
	}
	// Pinned by the Python receipt_digest test over the same golden receipt.
	receipt := decodeFixture(t, "deployment-receipt.v4", &protocol.ReceiptV4{})
	if digest, err := protocol.ReceiptDigestV4(*receipt); err != nil ||
		digest != "sha256:a0f5a1fd445a49c6709e64210ed618df211549c52562f0bf302258b05ef92e27" {
		t.Fatalf("receipt digest drifted: %s %v", digest, err)
	}

}

func TestTicketAndReceiptSignaturesVerifyInGo(t *testing.T) {
	vectors := loadVectors(t)
	ticket := *decodeFixture(t, "deployment-ticket.v4", &protocol.TicketV4{})
	receipt := *decodeFixture(t, "deployment-receipt.v4", &protocol.ReceiptV4{})
	validator := vectors.Keys.ValidatorService.public(t)
	miner := vectors.Keys.MinerService.public(t)
	if err := protocol.VerifyTicketV4(ticket, validator, ticket.IssuedAt); err != nil {
		t.Fatalf("golden ticket signature: %v", err)
	}
	if err := protocol.VerifyTicketV4(ticket, validator, ticket.ExpiresAt); err == nil {
		t.Fatal("expired ticket accepted for acceptance")
	}
	if err := protocol.VerifyReceiptV4(receipt, miner); err != nil {
		t.Fatalf("golden receipt signature: %v", err)
	}
	if err := protocol.VerifyReceiptV4(receipt, validator); err == nil {
		t.Fatal("receipt verified under the validator key")
	}
	manifest := decodeFixture(t, "artifact-manifest.v2", &artifact.ManifestV2{})
	if err := protocol.ReceiptMatchesTicketV4(ticket, receipt, manifest.Config.Digest); err != nil {
		t.Fatal(err)
	}
	if err := protocol.ReceiptMatchesTicketV4(ticket, receipt, manifest.OCIManifest.Digest); err == nil {
		t.Fatal("receipt accepted with a foreign loaded image config digest")
	}

	resigned := ticket
	resigned.Signature = ""
	if err := protocol.SignTicketV4(&resigned, vectors.Keys.ValidatorService.private(t)); err != nil ||
		resigned.Signature != ticket.Signature {
		t.Fatalf("Go signing bytes differ from the golden ticket: %v", err)
	}
	tampered := ticket
	tampered.Workload.ContainerPort, tampered.Workload.Env.Port = 9090, "9090"
	if err := protocol.VerifyTicketV4Signature(tampered, validator); err == nil {
		t.Fatal("tampered ticket verified")
	}
}

func TestEdgeRuntimeRequestSignature(t *testing.T) {
	vectors := loadVectors(t)
	request := *decodeFixture(t, "edge-runtime-request.v1", &organic.EdgeRuntimeRequest{})
	message, err := organic.EdgeRuntimeRequestMessage(request)
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(message); hex.EncodeToString(sum[:]) != vectors.EdgeRuntimeRequest.MessageSHA256 {
		t.Fatal("edge runtime request message drifted from Python")
	}
	header, err := organic.SignEdgeRuntimeRequest(request, vectors.Keys.ValidatorService.private(t))
	if err != nil || header != vectors.EdgeRuntimeRequest.HeaderValue {
		t.Fatalf("edge header drifted from Python: %q %v", header, err)
	}
	key := vectors.Keys.ValidatorService.public(t)
	signedAt := time.Unix(0, request.Timestamp)
	received := request
	received.Timestamp, received.Nonce = 0, ""
	for name, now := range map[string]time.Time{
		"at signing":       signedAt,
		"freshness edge":   signedAt.Add(organic.EdgeRequestFreshness),
		"future skew edge": signedAt.Add(-organic.EdgeRequestFutureSkew),
	} {
		if _, err := organic.VerifyEdgeRuntimeRequest(received, header, key, now); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	for name, now := range map[string]time.Time{
		"stale":  signedAt.Add(organic.EdgeRequestFreshness + time.Nanosecond),
		"future": signedAt.Add(-organic.EdgeRequestFutureSkew - time.Nanosecond),
	} {
		if _, err := organic.VerifyEdgeRuntimeRequest(received, header, key, now); err == nil || !strings.Contains(err.Error(), "stale") {
			t.Fatalf("%s request accepted: %v", name, err)
		}
	}
	for name, mutate := range map[string]func(*organic.EdgeRuntimeRequest){
		"query":    func(r *organic.EdgeRuntimeRequest) { r.Query = "page=3&sort=desc" },
		"method":   func(r *organic.EdgeRuntimeRequest) { r.Method = "PUT" },
		"body":     func(r *organic.EdgeRuntimeRequest) { r.BodySHA256 = strings.Repeat("0", 64) },
		"endpoint": func(r *organic.EdgeRuntimeRequest) { r.EndpointID += "x" },
	} {
		changed := received
		mutate(&changed)
		if _, err := organic.VerifyEdgeRuntimeRequest(changed, header, key, signedAt); err == nil {
			t.Fatalf("%s change verified", name)
		}
	}
}

func TestPublicValidatorSignatureMessages(t *testing.T) {
	vectors := loadVectors(t)
	authorization := *decodeFixture(t, "organic-probe-authorization.v1", &organic.ProbeAuthorization{})
	message, err := organic.OrganicProbeMessage(authorization)
	if err != nil || hex.EncodeToString(message) != vectors.OrganicProbeAuthorization.MessageHex {
		t.Fatalf("probe authorization message drifted from Python: %v", err)
	}

	attestation := *decodeFixture(t, "miner-probe-attestation.v2", &organic.ProbeAttestationV2{})
	message, err = organic.ProbeAttestationV2Message(attestation)
	if sum := sha256.Sum256(message); err != nil || hex.EncodeToString(sum[:]) != vectors.MinerProbeAttestation.MessageSHA256 {
		t.Fatalf("attestation message drifted from Python: %v", err)
	}
	if err := organic.VerifyProbeAttestationV2(attestation, vectors.Keys.MinerService.public(t)); err != nil {
		t.Fatal(err)
	}
	if err := organic.VerifyProbeAttestationV2(attestation, vectors.Keys.ValidatorService.public(t)); err == nil {
		t.Fatal("attestation verified under the validator key")
	}
	unsigned := attestation
	unsigned.SignatureHex = ""
	if err := organic.SignProbeAttestationV2(&unsigned, vectors.Keys.MinerService.private(t)); err != nil ||
		unsigned.SignatureHex != attestation.SignatureHex {
		t.Fatalf("Go attestation signature differs from Python: %v", err)
	}
	ticket := *decodeFixture(t, "deployment-ticket.v4", &protocol.TicketV4{})
	if digest, _ := protocol.TicketDigestV4(ticket); attestation.TicketDigest != digest ||
		attestation.EndpointID != protocol.EndpointIDV4(ticket) {
		t.Fatal("attestation is not bound to the golden ticket incarnation")
	}
	header, err := organic.ResponseHeaderSHA256([][2]string{{"Content-Type", "text/plain; charset=utf-8"}, {"Content-Length", "12"}})
	if err != nil || header != attestation.ResponseHeaderSHA256 {
		t.Fatalf("response header digest drifted from Python: %v", err)
	}
}
