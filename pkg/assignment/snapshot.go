// SPDX-License-Identifier: AGPL-3.0-only

// Package assignment holds the Go side of the active-assignment snapshot
// contract (active-assignment-snapshot v1). The runtime is the producer of
// this document, so the canonical encoding, self digests, and every
// invariant the Python consumer enforces are reproduced here and locked to
// the shared golden fixture byte-for-byte.
//
// The snapshot is credential-safe by construction: it carries the challenge
// digest, ticket digest, and receipt digest only, never the raw challenge
// value, retained ticket or receipt bytes, axons, TLS pins, or keys.
package assignment

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
)

const (
	// Schema, SchemaVersion and Purpose mirror misscomputer_subnet.assignment_snapshot.
	Schema        = "miss.computer/misscomputer-subnet/active-assignment-snapshot"
	SchemaVersion = 1
	Purpose       = "active_assignment_snapshot_v1"
	Network       = "finney"
	NetUID        = 24
	ProbeScheme   = "https"
	RouteState    = "active"
	// AttestationRequirement is the only mainnet attestation requirement.
	AttestationRequirement = "miner_service_key_v1"
	// TicketMaxFutureSkewSeconds bounds ticket issuance after the capture instant.
	TicketMaxFutureSkewSeconds = 30
	// MaxSnapshotBytes matches the Python parser ceiling.
	MaxSnapshotBytes = 64 * 1024 * 1024
	MaxDeployments   = 4096
	MaxReplicas      = 8
	maxEpoch         = uint64(1<<63 - 1)
)

var (
	digestPattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hex24Pattern      = regexp.MustCompile(`^[0-9a-f]{24}$`)
	hex32Pattern      = regexp.MustCompile(`^[0-9a-f]{32}$`)
	hotkeyPattern     = regexp.MustCompile(`^[A-Za-z0-9]{1,128}$`)
	deploymentPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	routeHostPattern  = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
	imageDigestRegexp = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// smallOrderEd25519 lists the small-order encodings with the sign bit cleared,
// exactly as misscomputer_subnet.ed25519_trust rejects them.
var smallOrderEd25519 = map[string]struct{}{
	"0000000000000000000000000000000000000000000000000000000000000000": {},
	"0100000000000000000000000000000000000000000000000000000000000000": {},
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05": {},
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a": {},
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f": {},
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f": {},
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f": {},
}

// Replica is one route-active replica: exact incarnation, identity, digests
// and timing. Field order is the canonical sorted-key order.
type Replica struct {
	AssignmentNonce       string `json:"assignment_nonce"`
	ChainBlock            uint64 `json:"chain_block"`
	EndpointID            string `json:"endpoint_id"`
	ExpiresAtBlock        uint64 `json:"expires_at_block"`
	Generation            uint64 `json:"generation"`
	MinerHotkey           string `json:"miner_hotkey"`
	MinerServicePublicKey string `json:"miner_service_public_key"`
	MinerUID              uint16 `json:"miner_uid"`
	ReceiptDigestSHA256   string `json:"receipt_digest_sha256"`
	ReplicaID             string `json:"replica_id"`
	RouteActivatedAtEpoch uint64 `json:"route_activated_at_epoch"`
	RouteState            string `json:"route_state"`
	TicketDigestSHA256    string `json:"ticket_digest_sha256"`
	TicketExpiresAtEpoch  uint64 `json:"ticket_expires_at_epoch"`
	TicketIssuedAtEpoch   uint64 `json:"ticket_issued_at_epoch"`
}

// Deployment is one route-active deployment with its replicas.
type Deployment struct {
	AttestationRequirement   string    `json:"attestation_requirement"`
	BuildID                  string    `json:"build_id"`
	CampaignSequence         uint64    `json:"campaign_sequence"`
	ChallengePath            string    `json:"challenge_path"`
	ChallengeSHA256          string    `json:"challenge_sha256"`
	DeploymentID             string    `json:"deployment_id"`
	ExpectedStatus           int       `json:"expected_status"`
	ImageDigest              string    `json:"image_digest"`
	Replicas                 []Replica `json:"replicas"`
	RouteHost                string    `json:"route_host"`
	WorkloadSpecDigestSHA256 string    `json:"workload_spec_digest_sha256"`
}

// Snapshot is one consistent, credential-safe capture of every route-active
// assignment held by the scheduler at one durable state revision.
type Snapshot struct {
	CapturedAtEpoch                       uint64       `json:"captured_at_epoch"`
	CentralAuthorityFingerprintSHA256     string       `json:"central_authority_fingerprint_sha256"`
	Deployments                           []Deployment `json:"deployments"`
	FinalizedBlockHash                    string       `json:"finalized_block_hash"`
	FinalizedEpoch                        uint64       `json:"finalized_epoch"`
	FinalizedHeight                       uint64       `json:"finalized_height"`
	NetUID                                uint16       `json:"netuid"`
	Network                               string       `json:"network"`
	ProbePort                             uint16       `json:"probe_port"`
	ProbeScheme                           string       `json:"probe_scheme"`
	ProjectedAssignmentVectorDigestSHA256 string       `json:"projected_assignment_vector_digest_sha256"`
	Purpose                               string       `json:"purpose"`
	RouteHostSuffix                       string       `json:"route_host_suffix"`
	Schema                                string       `json:"schema"`
	SchemaVersion                         int          `json:"schema_version"`
	SnapshotDigestSHA256                  string       `json:"snapshot_digest_sha256"`
	SnapshotSequence                      uint64       `json:"snapshot_sequence"`
	StateRevision                         uint64       `json:"state_revision"`
}

// ManifestReplica is the active-assignment-manifest v1 replica projection.
type ManifestReplica struct {
	AssignmentNonce       string `json:"assignment_nonce"`
	ChainBlock            uint64 `json:"chain_block"`
	EndpointID            string `json:"endpoint_id"`
	ExpiresAtBlock        uint64 `json:"expires_at_block"`
	Generation            uint64 `json:"generation"`
	MinerHotkey           string `json:"miner_hotkey"`
	MinerServicePublicKey string `json:"miner_service_public_key"`
	MinerUID              uint16 `json:"miner_uid"`
	ReceiptDigestSHA256   string `json:"receipt_digest_sha256"`
	ReplicaID             string `json:"replica_id"`
	RouteState            string `json:"route_state"`
	TicketDigestSHA256    string `json:"ticket_digest_sha256"`
	TicketExpiresAtEpoch  uint64 `json:"ticket_expires_at_epoch"`
	TicketIssuedAtEpoch   uint64 `json:"ticket_issued_at_epoch"`
}

// ManifestDeployment is the active-assignment-manifest v1 deployment
// projection, sealed by its own assignment digest.
type ManifestDeployment struct {
	AssignmentDigestSHA256   string            `json:"assignment_digest_sha256"`
	AttestationRequirement   string            `json:"attestation_requirement"`
	BuildID                  string            `json:"build_id"`
	CampaignSequence         uint64            `json:"campaign_sequence"`
	ChallengePath            string            `json:"challenge_path"`
	ChallengeSHA256          string            `json:"challenge_sha256"`
	DeploymentID             string            `json:"deployment_id"`
	ExpectedStatus           int               `json:"expected_status"`
	ImageDigest              string            `json:"image_digest"`
	Replicas                 []ManifestReplica `json:"replicas"`
	RouteHost                string            `json:"route_host"`
	WorkloadSpecDigestSHA256 string            `json:"workload_spec_digest_sha256"`
}

// CanonicalJSON renders any JSON-encodable value as the sorted-key, compact,
// ASCII-only encoding shared with the Python contracts (no trailing newline).
func CanonicalJSON(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var generic any
	if err := decoder.Decode(&generic); err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(generic); err != nil {
		return nil, err
	}
	out := bytes.TrimSuffix(buffer.Bytes(), []byte("\n"))
	for _, b := range out {
		if b > 0x7f {
			return nil, errors.New("canonical json must be ascii")
		}
	}
	return out, nil
}

func digestOf(value any) (string, error) {
	canonical, err := CanonicalJSON(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// digestWithout returns the digest of value's canonical document with the
// named field removed, exactly as the Python self-digest is computed.
func digestWithout(value any, field string) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var document map[string]any
	if err := decoder.Decode(&document); err != nil {
		return "", err
	}
	delete(document, field)
	return digestOf(document)
}

// Marshal renders the snapshot's canonical file/wire bytes: canonical JSON
// plus exactly one trailing newline. Digests are not recomputed here; use
// Seal to produce a sealed snapshot.
func Marshal(snapshot Snapshot) ([]byte, error) {
	if snapshot.Deployments == nil {
		snapshot.Deployments = []Deployment{}
	}
	canonical, err := CanonicalJSON(snapshot)
	if err != nil {
		return nil, err
	}
	return append(canonical, '\n'), nil
}

// Project derives the active-assignment-manifest v1 deployments vector from
// the snapshot's deployments. It is the only projection and drops exactly the
// activation timing the manifest contract does not carry.
func Project(deployments []Deployment) ([]ManifestDeployment, error) {
	projected := make([]ManifestDeployment, 0, len(deployments))
	for _, deployment := range deployments {
		replicas := make([]ManifestReplica, 0, len(deployment.Replicas))
		for _, replica := range deployment.Replicas {
			replicas = append(replicas, ManifestReplica{
				AssignmentNonce:       replica.AssignmentNonce,
				ChainBlock:            replica.ChainBlock,
				EndpointID:            replica.EndpointID,
				ExpiresAtBlock:        replica.ExpiresAtBlock,
				Generation:            replica.Generation,
				MinerHotkey:           replica.MinerHotkey,
				MinerServicePublicKey: replica.MinerServicePublicKey,
				MinerUID:              replica.MinerUID,
				ReceiptDigestSHA256:   replica.ReceiptDigestSHA256,
				ReplicaID:             replica.ReplicaID,
				RouteState:            replica.RouteState,
				TicketDigestSHA256:    replica.TicketDigestSHA256,
				TicketExpiresAtEpoch:  replica.TicketExpiresAtEpoch,
				TicketIssuedAtEpoch:   replica.TicketIssuedAtEpoch,
			})
		}
		sort.SliceStable(replicas, func(i, j int) bool {
			if replicas[i].MinerUID != replicas[j].MinerUID {
				return replicas[i].MinerUID < replicas[j].MinerUID
			}
			return replicas[i].MinerHotkey < replicas[j].MinerHotkey
		})
		item := ManifestDeployment{
			AttestationRequirement:   deployment.AttestationRequirement,
			BuildID:                  deployment.BuildID,
			CampaignSequence:         deployment.CampaignSequence,
			ChallengePath:            deployment.ChallengePath,
			ChallengeSHA256:          deployment.ChallengeSHA256,
			DeploymentID:             deployment.DeploymentID,
			ExpectedStatus:           deployment.ExpectedStatus,
			ImageDigest:              deployment.ImageDigest,
			Replicas:                 replicas,
			RouteHost:                deployment.RouteHost,
			WorkloadSpecDigestSHA256: deployment.WorkloadSpecDigestSHA256,
		}
		digest, err := digestWithout(item, "assignment_digest_sha256")
		if err != nil {
			return nil, err
		}
		item.AssignmentDigestSHA256 = digest
		projected = append(projected, item)
	}
	sort.SliceStable(projected, func(i, j int) bool {
		return projected[i].DeploymentID < projected[j].DeploymentID
	})
	return projected, nil
}

// Seal fills the constant identity fields and both derived digests, sorts
// deployments and replicas canonically, and validates the result. Callers
// supply only facts; no digest is ever accepted from the caller.
func Seal(snapshot Snapshot) (Snapshot, error) {
	// A value copy of Snapshot still shares its slice backing arrays. Detach the
	// full deployment tree before deriving fields or canonicalizing its order.
	snapshot.Deployments = cloneDeployments(snapshot.Deployments)
	snapshot.Schema = Schema
	snapshot.SchemaVersion = SchemaVersion
	snapshot.Purpose = Purpose
	snapshot.Network = Network
	snapshot.NetUID = NetUID
	snapshot.ProbeScheme = ProbeScheme
	for index := range snapshot.Deployments {
		deployment := &snapshot.Deployments[index]
		deployment.ExpectedStatus = 200
		deployment.AttestationRequirement = AttestationRequirement
		deployment.ChallengePath = "/__challenge/" + deployment.BuildID
		for r := range deployment.Replicas {
			replica := &deployment.Replicas[r]
			replica.RouteState = RouteState
			replica.ReplicaID = deployment.DeploymentID + "-" + replica.MinerHotkey
			replica.EndpointID = fmt.Sprintf("%s-g%d-%s", replica.ReplicaID, replica.Generation, replica.AssignmentNonce)
		}
		replicas := deployment.Replicas
		sort.SliceStable(replicas, func(i, j int) bool {
			if replicas[i].MinerUID != replicas[j].MinerUID {
				return replicas[i].MinerUID < replicas[j].MinerUID
			}
			return replicas[i].MinerHotkey < replicas[j].MinerHotkey
		})
	}
	sort.SliceStable(snapshot.Deployments, func(i, j int) bool {
		return snapshot.Deployments[i].DeploymentID < snapshot.Deployments[j].DeploymentID
	})
	projected, err := Project(snapshot.Deployments)
	if err != nil {
		return Snapshot{}, err
	}
	vectorDigest, err := digestOf(projected)
	if err != nil {
		return Snapshot{}, err
	}
	snapshot.ProjectedAssignmentVectorDigestSHA256 = vectorDigest
	snapshot.SnapshotDigestSHA256 = ""
	selfDigest, err := digestWithout(snapshot, "snapshot_digest_sha256")
	if err != nil {
		return Snapshot{}, err
	}
	snapshot.SnapshotDigestSHA256 = selfDigest
	if err := Validate(snapshot); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

func cloneDeployments(deployments []Deployment) []Deployment {
	if deployments == nil {
		return []Deployment{}
	}
	cloned := make([]Deployment, len(deployments))
	copy(cloned, deployments)
	for index := range deployments {
		if deployments[index].Replicas == nil {
			continue
		}
		cloned[index].Replicas = make([]Replica, len(deployments[index].Replicas))
		copy(cloned[index].Replicas, deployments[index].Replicas)
	}
	return cloned
}

// Parse accepts exactly the canonical bytes of one valid snapshot. Unknown
// fields, non-canonical encodings, digest mismatches and every invariant
// violation are rejected, mirroring the Python parser.
func Parse(data []byte) (Snapshot, error) {
	if len(data) == 0 || len(data) > MaxSnapshotBytes {
		return Snapshot{}, errors.New("document_size_invalid")
	}
	for _, b := range data {
		if b > 0x7f {
			return Snapshot{}, errors.New("document_invalid")
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var snapshot Snapshot
	if err := decoder.Decode(&snapshot); err != nil {
		return Snapshot{}, fmt.Errorf("document_invalid: %w", err)
	}
	if decoder.More() {
		return Snapshot{}, errors.New("document_invalid")
	}
	if err := Validate(snapshot); err != nil {
		return Snapshot{}, err
	}
	canonical, err := Marshal(snapshot)
	if err != nil {
		return Snapshot{}, err
	}
	if !bytes.Equal(canonical, data) {
		return Snapshot{}, errors.New("document_not_canonical")
	}
	return snapshot, nil
}

func validEd25519PublicKey(value string) bool {
	if !digestPattern.MatchString(value) {
		return false
	}
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 32 {
		return false
	}
	cleared := append([]byte(nil), raw...)
	cleared[31] &= 0x7f
	_, small := smallOrderEd25519[hex.EncodeToString(cleared)]
	return !small
}

func validateReplica(deploymentID string, replica Replica) error {
	if !hex32Pattern.MatchString(replica.AssignmentNonce) {
		return errors.New("replica_assignment_nonce_invalid")
	}
	if !hotkeyPattern.MatchString(replica.MinerHotkey) {
		return errors.New("replica_miner_hotkey_invalid")
	}
	if !validEd25519PublicKey(replica.MinerServicePublicKey) {
		return errors.New("ed25519_public_key_invalid")
	}
	if replica.Generation < 1 || replica.Generation > maxEpoch || replica.ChainBlock > maxEpoch ||
		replica.ExpiresAtBlock < 1 || replica.ExpiresAtBlock > maxEpoch ||
		replica.TicketIssuedAtEpoch > maxEpoch || replica.TicketExpiresAtEpoch < 1 ||
		replica.TicketExpiresAtEpoch > maxEpoch || replica.RouteActivatedAtEpoch > maxEpoch {
		return errors.New("replica_integer_out_of_range")
	}
	if !digestPattern.MatchString(replica.TicketDigestSHA256) || !digestPattern.MatchString(replica.ReceiptDigestSHA256) {
		return errors.New("replica_digest_invalid")
	}
	if replica.RouteState != RouteState {
		return errors.New("replica_route_state_invalid")
	}
	expectedReplica := deploymentID + "-" + replica.MinerHotkey
	expectedEndpoint := fmt.Sprintf("%s-g%d-%s", expectedReplica, replica.Generation, replica.AssignmentNonce)
	if replica.ReplicaID != expectedReplica || replica.EndpointID != expectedEndpoint {
		return errors.New("deployment_replica_identity_invalid")
	}
	if replica.ExpiresAtBlock <= replica.ChainBlock {
		return errors.New("replica_block_window_invalid")
	}
	if replica.TicketExpiresAtEpoch <= replica.TicketIssuedAtEpoch {
		return errors.New("replica_ticket_window_invalid")
	}
	if replica.TicketDigestSHA256 == replica.ReceiptDigestSHA256 {
		return errors.New("replica_digest_binding_invalid")
	}
	if replica.RouteActivatedAtEpoch < replica.TicketIssuedAtEpoch {
		return errors.New("replica_activation_order_invalid")
	}
	return nil
}

func validateDeployment(deployment Deployment) error {
	if !deploymentPattern.MatchString(deployment.DeploymentID) || len(deployment.DeploymentID) > 63 {
		return errors.New("deployment_id_invalid")
	}
	if deployment.CampaignSequence < 1 || deployment.CampaignSequence > maxEpoch {
		return errors.New("deployment_campaign_sequence_invalid")
	}
	if !routeHostPattern.MatchString(deployment.RouteHost) || len(deployment.RouteHost) > 253 {
		return errors.New("deployment_route_host_invalid")
	}
	if !hex24Pattern.MatchString(deployment.BuildID) {
		return errors.New("deployment_build_id_invalid")
	}
	if deployment.ChallengePath != "/__challenge/"+deployment.BuildID {
		return errors.New("deployment_challenge_path_invalid")
	}
	if !digestPattern.MatchString(deployment.ChallengeSHA256) || !digestPattern.MatchString(deployment.WorkloadSpecDigestSHA256) {
		return errors.New("deployment_digest_invalid")
	}
	if deployment.ExpectedStatus != 200 {
		return errors.New("deployment_expected_status_invalid")
	}
	if !imageDigestRegexp.MatchString(deployment.ImageDigest) {
		return errors.New("deployment_image_digest_invalid")
	}
	if deployment.AttestationRequirement != AttestationRequirement {
		return errors.New("deployment_attestation_requirement_invalid")
	}
	if len(deployment.Replicas) < 1 || len(deployment.Replicas) > MaxReplicas {
		return errors.New("deployment_replica_count_invalid")
	}
	uids := make(map[uint16]struct{}, len(deployment.Replicas))
	hotkeys := make(map[string]struct{}, len(deployment.Replicas))
	nonces := make(map[string]struct{}, len(deployment.Replicas))
	for index, replica := range deployment.Replicas {
		if err := validateReplica(deployment.DeploymentID, replica); err != nil {
			return err
		}
		if index > 0 {
			previous := deployment.Replicas[index-1]
			if previous.MinerUID > replica.MinerUID || (previous.MinerUID == replica.MinerUID && previous.MinerHotkey >= replica.MinerHotkey) {
				return errors.New("deployment_replicas_not_canonical")
			}
		}
		if _, seen := uids[replica.MinerUID]; seen {
			return errors.New("deployment_replica_uid_duplicate")
		}
		if _, seen := hotkeys[replica.MinerHotkey]; seen {
			return errors.New("deployment_replica_hotkey_duplicate")
		}
		if _, seen := nonces[replica.AssignmentNonce]; seen {
			return errors.New("deployment_replica_nonce_duplicate")
		}
		uids[replica.MinerUID] = struct{}{}
		hotkeys[replica.MinerHotkey] = struct{}{}
		nonces[replica.AssignmentNonce] = struct{}{}
	}
	return nil
}

// Validate enforces every snapshot invariant, including both derived digests.
func Validate(snapshot Snapshot) error {
	if snapshot.Schema != Schema || snapshot.SchemaVersion != SchemaVersion || snapshot.Purpose != Purpose {
		return errors.New("snapshot_identity_invalid")
	}
	if snapshot.Network != Network || snapshot.NetUID != NetUID {
		return errors.New("snapshot_network_invalid")
	}
	if !digestPattern.MatchString(snapshot.CentralAuthorityFingerprintSHA256) || !digestPattern.MatchString(snapshot.FinalizedBlockHash) {
		return errors.New("snapshot_digest_invalid")
	}
	if snapshot.SnapshotSequence < 1 || snapshot.SnapshotSequence > maxEpoch || snapshot.StateRevision > maxEpoch ||
		snapshot.CapturedAtEpoch > maxEpoch || snapshot.FinalizedHeight > maxEpoch || snapshot.FinalizedEpoch > maxEpoch {
		return errors.New("snapshot_integer_out_of_range")
	}
	if !routeHostPattern.MatchString(snapshot.RouteHostSuffix) || len(snapshot.RouteHostSuffix) > 253 {
		return errors.New("snapshot_route_host_suffix_invalid")
	}
	if snapshot.ProbeScheme != ProbeScheme || snapshot.ProbePort < 1 {
		return errors.New("snapshot_probe_invalid")
	}
	if len(snapshot.Deployments) > MaxDeployments {
		return errors.New("snapshot_deployment_count_invalid")
	}
	routeHosts := make(map[string]struct{}, len(snapshot.Deployments))
	nonces := make(map[string]struct{})
	endpoints := make(map[string]struct{})
	uidToHotkey := make(map[uint16]string)
	hotkeyToUID := make(map[string]uint16)
	for index, deployment := range snapshot.Deployments {
		if err := validateDeployment(deployment); err != nil {
			return err
		}
		if index > 0 && snapshot.Deployments[index-1].DeploymentID >= deployment.DeploymentID {
			return errors.New("snapshot_deployments_not_canonical")
		}
		if _, seen := routeHosts[deployment.RouteHost]; seen {
			return errors.New("snapshot_route_host_duplicate")
		}
		routeHosts[deployment.RouteHost] = struct{}{}
		if deployment.RouteHost != deployment.DeploymentID+"."+snapshot.RouteHostSuffix {
			return errors.New("snapshot_route_host_invalid")
		}
		for _, replica := range deployment.Replicas {
			if !(replica.ChainBlock <= snapshot.FinalizedHeight && snapshot.FinalizedHeight < replica.ExpiresAtBlock) {
				return errors.New("snapshot_replica_block_window_invalid")
			}
			if replica.TicketExpiresAtEpoch <= snapshot.CapturedAtEpoch {
				return errors.New("snapshot_replica_ticket_expired")
			}
			if replica.TicketIssuedAtEpoch > snapshot.CapturedAtEpoch+TicketMaxFutureSkewSeconds {
				return errors.New("snapshot_replica_ticket_issued_after_capture")
			}
			if replica.RouteActivatedAtEpoch > snapshot.CapturedAtEpoch {
				return errors.New("snapshot_replica_activated_after_capture")
			}
			if hotkey, seen := uidToHotkey[replica.MinerUID]; seen && hotkey != replica.MinerHotkey {
				return errors.New("snapshot_miner_identity_conflict")
			}
			if uid, seen := hotkeyToUID[replica.MinerHotkey]; seen && uid != replica.MinerUID {
				return errors.New("snapshot_miner_identity_conflict")
			}
			uidToHotkey[replica.MinerUID] = replica.MinerHotkey
			hotkeyToUID[replica.MinerHotkey] = replica.MinerUID
			if _, seen := nonces[replica.AssignmentNonce]; seen {
				return errors.New("snapshot_assignment_nonce_duplicate")
			}
			nonces[replica.AssignmentNonce] = struct{}{}
			if _, seen := endpoints[replica.EndpointID]; seen {
				return errors.New("snapshot_endpoint_duplicate")
			}
			endpoints[replica.EndpointID] = struct{}{}
		}
	}
	projected, err := Project(snapshot.Deployments)
	if err != nil {
		return err
	}
	vectorDigest, err := digestOf(projected)
	if err != nil {
		return err
	}
	if snapshot.ProjectedAssignmentVectorDigestSHA256 != vectorDigest {
		return errors.New("projected_assignment_vector_digest_sha256_mismatch")
	}
	selfDigest, err := digestWithout(snapshot, "snapshot_digest_sha256")
	if err != nil {
		return err
	}
	if snapshot.SnapshotDigestSHA256 != selfDigest {
		return errors.New("snapshot_digest_sha256_mismatch")
	}
	return nil
}
