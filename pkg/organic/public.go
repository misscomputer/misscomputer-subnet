// SPDX-License-Identifier: AGPL-3.0-only

package organic

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var (
	organicProbeDomain         = []byte("miss.computer/misscomputer-subnet/organic-probe/v1")
	probeAttestationV2Domain   = []byte("miss.computer/misscomputer-subnet/miner-probe-attestation/v2")
	secondsTimestampPattern    = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
	maxManifestV2Deployments   = 4096
	maxManifestV2ReplicaRecord = 8
)

// OrganicHealthProbe is the sanitized public health predicate.
type OrganicHealthProbe struct {
	Method           string  `json:"method"`
	Path             string  `json:"path"`
	ExpectedStatuses []int   `json:"expected_statuses"`
	ResponseMarker   *string `json:"response_marker"`
}

// OrganicAssignedReplica is one active miner route after verified cutover.
type OrganicAssignedReplica struct {
	MinerUID                  int    `json:"miner_uid"`
	MinerHotkey               string `json:"miner_hotkey"`
	MinerServicePublicKey     string `json:"miner_service_public_key"`
	MinerTLSCertificateSHA256 string `json:"miner_tls_certificate_sha256"`
	Generation                int64  `json:"generation"`
	AssignmentNonce           string `json:"assignment_nonce"`
	ReplicaID                 string `json:"replica_id"`
	EndpointID                string `json:"endpoint_id"`
	TicketDigest              string `json:"ticket_digest"`
	ReceiptDigest             string `json:"receipt_digest"`
	ChainBlock                int64  `json:"chain_block"`
	ExpiresAtBlock            int64  `json:"expires_at_block"`
	ActivatedAtEpoch          int64  `json:"activated_at_epoch"`
	ExpiresAtEpoch            int64  `json:"expires_at_epoch"`
	RouteState                string `json:"route_state"`
}

// OrganicDeploymentAssignment is one published organic app route.
type OrganicDeploymentAssignment struct {
	DeploymentID           string                   `json:"deployment_id"`
	RouteHost              string                   `json:"route_host"`
	ArtifactDigest         string                   `json:"artifact_digest"`
	Health                 OrganicHealthProbe       `json:"health"`
	AttestationRequirement string                   `json:"attestation_requirement"`
	Replicas               []OrganicAssignedReplica `json:"replicas"`
	AssignmentDigestSHA256 string                   `json:"assignment_digest_sha256"`
}

// ActiveAssignmentManifestV2 is the public snapshot of organic assignments.
// It carries no synthetic challenge, customer secret or origin identity.
type ActiveAssignmentManifestV2 struct {
	Schema                            string                        `json:"schema"`
	SchemaVersion                     int                           `json:"schema_version"`
	Purpose                           string                        `json:"purpose"`
	Network                           string                        `json:"network"`
	NetUID                            int                           `json:"netuid"`
	CentralAuthorityFingerprintSHA256 string                        `json:"central_authority_fingerprint_sha256"`
	TrustPolicyDigestSHA256           string                        `json:"trust_policy_digest_sha256"`
	FinalizedHeight                   int64                         `json:"finalized_height"`
	FinalizedBlockHash                string                        `json:"finalized_block_hash"`
	FinalizedEpoch                    int64                         `json:"finalized_epoch"`
	Sequence                          int64                         `json:"sequence"`
	PreviousManifestDigestSHA256      *string                       `json:"previous_manifest_digest_sha256"`
	IssuedAtEpoch                     int64                         `json:"issued_at_epoch"`
	ExpiresAtEpoch                    int64                         `json:"expires_at_epoch"`
	RouteHostSuffix                   string                        `json:"route_host_suffix"`
	ProbeScheme                       string                        `json:"probe_scheme"`
	ProbePort                         int                           `json:"probe_port"`
	Deployments                       []OrganicDeploymentAssignment `json:"deployments"`
	AssignmentVectorDigestSHA256      string                        `json:"assignment_vector_digest_sha256"`
	ManifestDigestSHA256              string                        `json:"manifest_digest_sha256"`
}

func (r OrganicAssignedReplica) validate(deploymentID string) error {
	if !between(int64(r.MinerUID), 0, 65535) || !ValidHotkey(r.MinerHotkey) || !ValidHex64(r.MinerServicePublicKey) ||
		!ValidHex64(r.MinerTLSCertificateSHA256) || r.Generation < 1 || !hex32Pattern.MatchString(r.AssignmentNonce) ||
		!ValidDigest(r.TicketDigest) || !ValidDigest(r.ReceiptDigest) || r.ChainBlock < 0 || r.ExpiresAtBlock < 1 ||
		r.ActivatedAtEpoch < 0 || r.ExpiresAtEpoch < 1 || r.RouteState != "active" {
		return errors.New("manifest replica fields are invalid")
	}
	if r.ExpiresAtBlock <= r.ChainBlock {
		return errors.New("replica_block_window_invalid")
	}
	if r.ExpiresAtEpoch <= r.ActivatedAtEpoch {
		return errors.New("replica_activation_window_invalid")
	}
	if r.TicketDigest == r.ReceiptDigest {
		return errors.New("replica_digest_collision")
	}
	replica := deploymentID + "-" + r.MinerHotkey
	if r.ReplicaID != replica || r.EndpointID != fmt.Sprintf("%s-g%d-%s", replica, r.Generation, r.AssignmentNonce) {
		return errors.New("assignment_replica_identity_invalid")
	}
	return nil
}

func (a OrganicDeploymentAssignment) validate() error {
	if !ValidRouteLabel(a.DeploymentID) || !ValidHostname(a.RouteHost) || !ValidDigest(a.ArtifactDigest) ||
		a.AttestationRequirement != "miner_service_key_v2" || !ValidHex64(a.AssignmentDigestSHA256) {
		return errors.New("manifest assignment fields are invalid")
	}
	if err := validateProbe(a.Health.Method, a.Health.Path, a.Health.ExpectedStatuses, a.Health.ResponseMarker); err != nil {
		return err
	}
	if len(a.Replicas) < 1 || len(a.Replicas) > maxManifestV2ReplicaRecord {
		return errors.New("assignment must list 1-8 replicas")
	}
	sorted := sort.SliceIsSorted(a.Replicas, func(i, j int) bool {
		left, right := a.Replicas[i], a.Replicas[j]
		return left.MinerUID < right.MinerUID || (left.MinerUID == right.MinerUID && left.MinerHotkey < right.MinerHotkey)
	})
	for index, replica := range a.Replicas {
		if err := replica.validate(a.DeploymentID); err != nil {
			return err
		}
		if index > 0 && a.Replicas[index-1].MinerUID == replica.MinerUID && a.Replicas[index-1].MinerHotkey == replica.MinerHotkey {
			sorted = false
		}
	}
	if !sorted {
		return errors.New("assignment_replicas_not_canonical")
	}
	digest, err := DigestWithout(a, "assignment_digest_sha256")
	if err != nil || digest != a.AssignmentDigestSHA256 {
		return errors.New("assignment_digest_sha256_mismatch")
	}
	return nil
}

func (m ActiveAssignmentManifestV2) Validate() error {
	if err := validSchema(m.Schema, "active-assignment-manifest"); err != nil || m.SchemaVersion != 2 ||
		m.Purpose != "active_assignment_manifest_publication_v2" || m.Network != "finney" || m.NetUID != 24 {
		return errors.New("unsupported active assignment manifest schema")
	}
	if !ValidHex64(m.CentralAuthorityFingerprintSHA256) || !ValidHex64(m.TrustPolicyDigestSHA256) ||
		m.FinalizedHeight < 0 || !ValidHex64(m.FinalizedBlockHash) || m.FinalizedEpoch < 0 || m.Sequence < 1 ||
		(m.PreviousManifestDigestSHA256 != nil && !ValidHex64(*m.PreviousManifestDigestSHA256)) ||
		m.IssuedAtEpoch < 0 || m.ExpiresAtEpoch < 1 || !ValidHostname(m.RouteHostSuffix) || m.ProbeScheme != "https" ||
		!between(int64(m.ProbePort), 1, 65535) || !ValidHex64(m.AssignmentVectorDigestSHA256) ||
		!ValidHex64(m.ManifestDigestSHA256) || m.Deployments == nil || len(m.Deployments) > maxManifestV2Deployments {
		return errors.New("active assignment manifest fields are invalid")
	}
	if m.ExpiresAtEpoch <= m.IssuedAtEpoch {
		return errors.New("manifest_validity_window_invalid")
	}
	if (m.Sequence == 1) != (m.PreviousManifestDigestSHA256 == nil) {
		return errors.New("manifest_previous_link_invalid")
	}
	endpoints := map[string]bool{}
	for index, deployment := range m.Deployments {
		if err := deployment.validate(); err != nil {
			return err
		}
		if index > 0 && m.Deployments[index-1].DeploymentID >= deployment.DeploymentID {
			return errors.New("manifest_deployments_not_canonical")
		}
		if deployment.RouteHost != deployment.DeploymentID+"."+m.RouteHostSuffix {
			return errors.New("manifest_route_host_invalid")
		}
		for _, replica := range deployment.Replicas {
			if replica.ExpiresAtBlock <= m.FinalizedHeight {
				return errors.New("manifest_replica_block_expired")
			}
			if replica.ExpiresAtEpoch <= m.IssuedAtEpoch {
				return errors.New("manifest_replica_expired")
			}
			if endpoints[replica.EndpointID] {
				return errors.New("manifest_endpoint_duplicate")
			}
			endpoints[replica.EndpointID] = true
		}
	}
	vector, err := DigestHex(m.Deployments)
	if err != nil || vector != m.AssignmentVectorDigestSHA256 {
		return errors.New("assignment_vector_digest_sha256_mismatch")
	}
	digest, err := DigestWithout(m, "manifest_digest_sha256")
	if err != nil || digest != m.ManifestDigestSHA256 {
		return errors.New("manifest_digest_sha256_mismatch")
	}
	return nil
}

// ProbeAuthorization is a validator-hotkey (sr25519) authorization for one
// targeted hidden probe. The edge verifies validator membership, the
// signature over OrganicProbeMessage, 30 s freshness and a one-time nonce,
// then strips the header before contacting the app.
type ProbeAuthorization struct {
	Schema          string `json:"schema"`
	SchemaVersion   int    `json:"schema_version"`
	ValidatorHotkey string `json:"validator_hotkey"`
	EndpointID      string `json:"endpoint_id"`
	Generation      int64  `json:"generation"`
	Method          string `json:"method"`
	Path            string `json:"path"`
	Nonce           string `json:"nonce"`
	IssuedAt        string `json:"issued_at"`
	Signature       string `json:"signature"`
}

func (p ProbeAuthorization) Validate() error {
	if err := validSchema(p.Schema, "organic-probe-authorization"); err != nil || p.SchemaVersion != 1 {
		return errors.New("unsupported probe authorization schema")
	}
	if !ValidHotkey(p.ValidatorHotkey) || len(p.EndpointID) < 3 || len(p.EndpointID) > endpointIDMaxBytes ||
		p.Generation < 1 || (p.Method != "GET" && p.Method != "HEAD") || len(p.Path) > 1024 ||
		!healthPathPattern.MatchString(p.Path) || !ValidHex64(p.Nonce) ||
		!secondsTimestampPattern.MatchString(p.IssuedAt) || !ValidTimestamp(p.IssuedAt) ||
		!signaturePattern.MatchString(p.Signature) {
		return errors.New("probe authorization fields are invalid")
	}
	return nil
}

// OrganicProbeMessage is domain || 0x00 || canonical({endpoint_id,
// generation, issued_at, method, nonce, path}); the validator hotkey signs it.
func OrganicProbeMessage(p ProbeAuthorization) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	encoded, err := Canonical(map[string]any{
		"endpoint_id": p.EndpointID, "generation": p.Generation, "issued_at": p.IssuedAt,
		"method": p.Method, "nonce": p.Nonce, "path": p.Path,
	})
	if err != nil {
		return nil, err
	}
	return append(append(append([]byte{}, organicProbeDomain...), 0), encoded...), nil
}

// ProbeAttestationV2 is the miner service-key statement for one validator
// probe of one organic endpoint incarnation.
type ProbeAttestationV2 struct {
	Schema               string `json:"schema"`
	SchemaVersion        int    `json:"schema_version"`
	EndpointID           string `json:"endpoint_id"`
	Generation           int64  `json:"generation"`
	TicketDigest         string `json:"ticket_digest"`
	ArtifactDigest       string `json:"artifact_digest"`
	ValidatorHotkey      string `json:"validator_hotkey"`
	ProbeNonce           string `json:"probe_nonce"`
	RequestMethod        string `json:"request_method"`
	RequestPath          string `json:"request_path"`
	ResponseStatus       int    `json:"response_status"`
	ResponseBodySHA256   string `json:"response_body_sha256"`
	ResponseHeaderSHA256 string `json:"response_header_sha256"`
	ObservedAt           string `json:"observed_at"`
	SignatureHex         string `json:"signature_hex"`
}

func (a ProbeAttestationV2) Validate() error {
	if err := validSchema(a.Schema, "miner-probe-attestation"); err != nil || a.SchemaVersion != 2 {
		return errors.New("unsupported probe attestation schema")
	}
	if len(a.EndpointID) < 3 || len(a.EndpointID) > endpointIDMaxBytes || a.Generation < 1 ||
		!ValidDigest(a.TicketDigest) || !ValidDigest(a.ArtifactDigest) || !ValidHotkey(a.ValidatorHotkey) ||
		!ValidHex64(a.ProbeNonce) || (a.RequestMethod != "GET" && a.RequestMethod != "HEAD") ||
		len(a.RequestPath) > 1024 || !healthPathPattern.MatchString(a.RequestPath) ||
		!between(int64(a.ResponseStatus), 100, 599) || !ValidHex64(a.ResponseBodySHA256) ||
		!ValidHex64(a.ResponseHeaderSHA256) || !ValidTimestamp(a.ObservedAt) || !signaturePattern.MatchString(a.SignatureHex) {
		return errors.New("probe attestation fields are invalid")
	}
	if !strings.Contains(a.EndpointID, fmt.Sprintf("-g%d-", a.Generation)) {
		return errors.New("attestation_endpoint_generation_mismatch")
	}
	return nil
}

// ProbeAttestationV2Message is domain || 0x00 || canonical(the twelve signed
// fields); schema, schema_version and signature_hex are not signed.
func ProbeAttestationV2Message(a ProbeAttestationV2) ([]byte, error) {
	if a.SignatureHex == "" {
		a.SignatureHex = strings.Repeat("0", 128)
	}
	if err := a.Validate(); err != nil {
		return nil, err
	}
	encoded, err := Canonical(map[string]any{
		"artifact_digest": a.ArtifactDigest, "endpoint_id": a.EndpointID, "generation": a.Generation,
		"observed_at": a.ObservedAt, "probe_nonce": a.ProbeNonce, "request_method": a.RequestMethod,
		"request_path": a.RequestPath, "response_body_sha256": a.ResponseBodySHA256,
		"response_header_sha256": a.ResponseHeaderSHA256, "response_status": a.ResponseStatus,
		"ticket_digest": a.TicketDigest, "validator_hotkey": a.ValidatorHotkey,
	})
	if err != nil {
		return nil, err
	}
	return append(append(append([]byte{}, probeAttestationV2Domain...), 0), encoded...), nil
}

// SignProbeAttestationV2 signs an unsigned attestation in place.
func SignProbeAttestationV2(a *ProbeAttestationV2, key ed25519.PrivateKey) error {
	if a == nil || len(key) != ed25519.PrivateKeySize || a.SignatureHex != "" {
		return errors.New("invalid probe attestation signing input")
	}
	message, err := ProbeAttestationV2Message(*a)
	if err != nil {
		return err
	}
	a.SignatureHex = hex.EncodeToString(ed25519.Sign(key, message))
	return nil
}

// VerifyProbeAttestationV2 checks the signature under the published miner
// service key of the probed endpoint.
func VerifyProbeAttestationV2(a ProbeAttestationV2, key ed25519.PublicKey) error {
	message, err := ProbeAttestationV2Message(a)
	if err != nil {
		return err
	}
	signature, err := hex.DecodeString(a.SignatureHex)
	if err != nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, message, signature) {
		return errors.New("attestation_signature_invalid")
	}
	return nil
}

// ResponseHeaderSHA256 digests end-to-end response headers as the canonical
// JSON list of [lowercase name, value] pairs, stably sorted by name.
func ResponseHeaderSHA256(headers [][2]string) (string, error) {
	pairs := make([][]string, len(headers))
	for index, header := range headers {
		pairs[index] = []string{strings.ToLower(header[0]), header[1]}
	}
	sort.SliceStable(pairs, func(i, j int) bool { return pairs[i][0] < pairs[j][0] })
	encoded, err := Canonical(pairs)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}
