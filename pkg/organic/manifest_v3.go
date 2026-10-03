// SPDX-License-Identifier: AGPL-3.0-only

package organic

import (
	"errors"
	"sort"
)

// Active assignment manifest v3 (static-site contract §11.1): the v2 header and
// publication pipeline under its own purpose and signing domain, with every
// deployment naming an explicit workload kind.
const (
	ManifestV3Purpose         = "active_assignment_manifest_publication_v3"
	ManifestV3SigningDomain   = "miss.computer/misscomputer-subnet/active-assignment-manifest/v3/ed25519"
	WorkloadKindOCIImageV1    = "oci-image-v1"
	WorkloadKindStaticSiteV1  = "static-site-v1"
	attestationRequirementV2  = "miner_service_key_v2"
	manifestV3DeploymentLimit = 4096
)

// OrganicDeploymentAssignmentV3 is one published v3 route. An oci-image-v1
// deployment carries the v2 members and null static bindings; a
// static-site-v1 deployment carries null artifact_digest and health and its
// bound site, release and server implementation digests. Replicas are v2
// replicas; for static they name static ticket and receipt v1 digests.
type OrganicDeploymentAssignmentV3 struct {
	DeploymentID               string                   `json:"deployment_id"`
	RouteHost                  string                   `json:"route_host"`
	WorkloadKind               string                   `json:"workload_kind"`
	ArtifactDigest             *string                  `json:"artifact_digest"`
	Health                     *OrganicHealthProbe      `json:"health"`
	SiteDigest                 *string                  `json:"site_digest"`
	ReleaseDigest              *string                  `json:"release_digest"`
	ServerImplementationDigest *string                  `json:"server_implementation_digest"`
	AttestationRequirement     string                   `json:"attestation_requirement"`
	Replicas                   []OrganicAssignedReplica `json:"replicas"`
	AssignmentDigestSHA256     string                   `json:"assignment_digest_sha256"`
}

// ActiveAssignmentManifestV3 is the public snapshot of OCI and static
// assignments. v2 keeps being published for OCI deployments only.
type ActiveAssignmentManifestV3 struct {
	Schema                            string                          `json:"schema"`
	SchemaVersion                     int                             `json:"schema_version"`
	Purpose                           string                          `json:"purpose"`
	Network                           string                          `json:"network"`
	NetUID                            int                             `json:"netuid"`
	CentralAuthorityFingerprintSHA256 string                          `json:"central_authority_fingerprint_sha256"`
	TrustPolicyDigestSHA256           string                          `json:"trust_policy_digest_sha256"`
	FinalizedHeight                   int64                           `json:"finalized_height"`
	FinalizedBlockHash                string                          `json:"finalized_block_hash"`
	FinalizedEpoch                    int64                           `json:"finalized_epoch"`
	Sequence                          int64                           `json:"sequence"`
	PreviousManifestDigestSHA256      *string                         `json:"previous_manifest_digest_sha256"`
	IssuedAtEpoch                     int64                           `json:"issued_at_epoch"`
	ExpiresAtEpoch                    int64                           `json:"expires_at_epoch"`
	RouteHostSuffix                   string                          `json:"route_host_suffix"`
	ProbeScheme                       string                          `json:"probe_scheme"`
	ProbePort                         int                             `json:"probe_port"`
	Deployments                       []OrganicDeploymentAssignmentV3 `json:"deployments"`
	AssignmentVectorDigestSHA256      string                          `json:"assignment_vector_digest_sha256"`
	ManifestDigestSHA256              string                          `json:"manifest_digest_sha256"`
}

func validOptionalDigest(value *string) bool { return value != nil && ValidDigest(*value) }

func (a OrganicDeploymentAssignmentV3) validate() error {
	if !ValidRouteLabel(a.DeploymentID) || !ValidHostname(a.RouteHost) ||
		a.AttestationRequirement != attestationRequirementV2 || !ValidHex64(a.AssignmentDigestSHA256) {
		return errors.New("manifest assignment fields are invalid")
	}
	switch a.WorkloadKind {
	case WorkloadKindOCIImageV1:
		if !validOptionalDigest(a.ArtifactDigest) || a.Health == nil ||
			a.SiteDigest != nil || a.ReleaseDigest != nil || a.ServerImplementationDigest != nil {
			return errors.New("assignment_workload_bindings_invalid")
		}
		if err := validateProbe(a.Health.Method, a.Health.Path, a.Health.ExpectedStatuses, a.Health.ResponseMarker); err != nil {
			return err
		}
	case WorkloadKindStaticSiteV1:
		if a.ArtifactDigest != nil || a.Health != nil || !validOptionalDigest(a.SiteDigest) ||
			!validOptionalDigest(a.ReleaseDigest) || !validOptionalDigest(a.ServerImplementationDigest) {
			return errors.New("assignment_workload_bindings_invalid")
		}
	default:
		return errors.New("assignment_workload_kind_invalid")
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

// Validate applies the v2 manifest rules to a v3 manifest.
func (m ActiveAssignmentManifestV3) Validate() error {
	if err := validSchema(m.Schema, "active-assignment-manifest"); err != nil || m.SchemaVersion != 3 ||
		m.Purpose != ManifestV3Purpose || !((m.Network == "finney" && m.NetUID == 24) ||
		(m.Network == "test" && m.NetUID == 581)) {
		return errors.New("unsupported active assignment manifest schema")
	}
	if !ValidHex64(m.CentralAuthorityFingerprintSHA256) || !ValidHex64(m.TrustPolicyDigestSHA256) ||
		m.FinalizedHeight < 0 || !ValidHex64(m.FinalizedBlockHash) || m.FinalizedEpoch < 0 || m.Sequence < 1 ||
		(m.PreviousManifestDigestSHA256 != nil && !ValidHex64(*m.PreviousManifestDigestSHA256)) ||
		m.IssuedAtEpoch < 0 || m.ExpiresAtEpoch < 1 || !ValidHostname(m.RouteHostSuffix) || m.ProbeScheme != "https" ||
		!between(int64(m.ProbePort), 1, 65535) || !ValidHex64(m.AssignmentVectorDigestSHA256) ||
		!ValidHex64(m.ManifestDigestSHA256) || m.Deployments == nil || len(m.Deployments) > manifestV3DeploymentLimit {
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

// ManifestV3SignatureMessage is the only byte string a central manifest key
// signs for a v3 manifest: the v3 domain, NUL, and the canonical manifest.
func ManifestV3SignatureMessage(m ActiveAssignmentManifestV3) ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	encoded, err := Canonical(m)
	if err != nil {
		return nil, err
	}
	return append(append([]byte(ManifestV3SigningDomain), 0), encoded...), nil
}

// OCIAssignmentV2 is the v2 deployment an oci-image-v1 v3 deployment
// corresponds to (OCI v3 = v2): the static members dropped and the assignment
// digest resealed. A static deployment has no v2 form and is never published
// in manifest v2.
func (a OrganicDeploymentAssignmentV3) OCIAssignmentV2() (OrganicDeploymentAssignment, error) {
	if err := a.validate(); err != nil {
		return OrganicDeploymentAssignment{}, err
	}
	if a.WorkloadKind != WorkloadKindOCIImageV1 {
		return OrganicDeploymentAssignment{}, errors.New("static_assignment_not_in_v2")
	}
	v2 := OrganicDeploymentAssignment{
		DeploymentID:           a.DeploymentID,
		RouteHost:              a.RouteHost,
		ArtifactDigest:         *a.ArtifactDigest,
		Health:                 *a.Health,
		AttestationRequirement: a.AttestationRequirement,
		Replicas:               append([]OrganicAssignedReplica(nil), a.Replicas...),
	}
	digest, err := DigestWithout(v2, "assignment_digest_sha256")
	if err != nil {
		return OrganicDeploymentAssignment{}, err
	}
	v2.AssignmentDigestSHA256 = digest
	return v2, v2.validate()
}
