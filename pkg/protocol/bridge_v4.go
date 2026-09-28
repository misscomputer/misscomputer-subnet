// SPDX-License-Identifier: AGPL-3.0-only

package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/misscomputer/misscomputer-subnet/pkg/organic"
)

// The lifecycle types Ticket and Receipt are exactly deployment.v4: they
// encode, decode, sign and verify with the frozen TicketV4/ReceiptV4 wire
// shape. deployment.v1-v3 and their synthetic challenge were never live and
// have no decoder.

// OrganicTicket holds the deployment.v4 ticket objects that the
// version-neutral lifecycle identity fields do not cover.
type OrganicTicket struct {
	Workload  WorkloadV4
	Resources organic.Resources
	Health    organic.TicketHealth
}

// V4 returns the exact deployment.v4 document of t. It fails closed on any
// other version; a missing Organic body yields zero objects that TicketV4
// validation rejects.
func (t Ticket) V4() (TicketV4, error) {
	if t.Version != OrganicVersion {
		return TicketV4{}, fmt.Errorf("ticket version %q is not %q", t.Version, OrganicVersion)
	}
	v4 := TicketV4{
		Version: t.Version, DeploymentID: t.DeploymentID, Generation: t.Generation, ImageDigest: t.ImageDigest,
		ManifestKey: t.ManifestKey, MinerID: t.MinerID, RouteHost: t.RouteHost, AssignmentNonce: t.AssignmentNonce,
		IssuedAt: t.IssuedAt, ExpiresAt: t.ExpiresAt, Subnet: t.Subnet, Signature: t.Signature,
	}
	if t.Organic != nil {
		v4.Workload, v4.Resources, v4.Health = t.Organic.Workload, t.Organic.Resources, t.Organic.Health
	}
	return v4, nil
}

// TicketFromV4 is the lifecycle value of a deployment.v4 ticket; V4 inverts it.
func TicketFromV4(v4 TicketV4) Ticket {
	return Ticket{
		Version: v4.Version, DeploymentID: v4.DeploymentID, Generation: v4.Generation, ImageDigest: v4.ImageDigest,
		ManifestKey: v4.ManifestKey, MinerID: v4.MinerID, RouteHost: v4.RouteHost, AssignmentNonce: v4.AssignmentNonce,
		IssuedAt: v4.IssuedAt, ExpiresAt: v4.ExpiresAt, Subnet: v4.Subnet, Signature: v4.Signature,
		Organic: &OrganicTicket{Workload: v4.Workload, Resources: v4.Resources, Health: v4.Health},
	}
}

// MarshalJSON encodes t as its TicketV4 document.
func (t Ticket) MarshalJSON() ([]byte, error) {
	v4, err := t.V4()
	if err != nil {
		return nil, err
	}
	return json.Marshal(v4)
}

// UnmarshalJSON decodes strictly as TicketV4, so any other version, a
// synthetic challenge field or any unknown field is rejected. A document
// without "version" merges into a receiver that is already deployment.v4.
func (t *Ticket) UnmarshalJSON(data []byte) error {
	version, err := documentVersion(data, t.Version)
	if err != nil {
		return err
	}
	if version != OrganicVersion {
		return fmt.Errorf("ticket version %q is not %q", version, OrganicVersion)
	}
	var current TicketV4
	if t.Version == OrganicVersion {
		if current, err = t.V4(); err != nil {
			return err
		}
	}
	if err := decodeStrict(data, &current); err != nil {
		return fmt.Errorf("decode deployment.v4 ticket: %w", err)
	}
	*t = TicketFromV4(current)
	return nil
}

// V4 returns the exact deployment.v4 document of r.
func (r Receipt) V4() (ReceiptV4, error) {
	if r.Version != OrganicVersion {
		return ReceiptV4{}, fmt.Errorf("receipt version %q is not %q", r.Version, OrganicVersion)
	}
	return ReceiptV4{
		Version: r.Version, DeploymentID: r.DeploymentID, Generation: r.Generation, AssignmentNonce: r.AssignmentNonce,
		MinerID: r.MinerID, ReplicaID: r.ReplicaID, EndpointID: r.EndpointID, ImageDigest: r.ImageDigest,
		ManifestKey: r.ManifestKey, LoadedImageConfigDigest: r.LoadedImageConfigDigest, RouteHost: r.RouteHost,
		Stage: r.Stage, ErrorCode: r.ErrorCode, Error: r.Error, AssignmentSeen: r.AssignmentSeen,
		PullStarted: r.PullStarted, PullCompleted: r.PullCompleted, RuntimeStarted: r.RuntimeStarted,
		HealthPassed: r.HealthPassed, Subnet: r.Subnet, Signature: r.Signature,
	}, nil
}

// ReceiptFromV4 is the lifecycle value of a deployment.v4 receipt.
func ReceiptFromV4(v4 ReceiptV4) Receipt {
	return Receipt{
		Version: v4.Version, DeploymentID: v4.DeploymentID, Generation: v4.Generation, AssignmentNonce: v4.AssignmentNonce,
		MinerID: v4.MinerID, ReplicaID: v4.ReplicaID, EndpointID: v4.EndpointID, ImageDigest: v4.ImageDigest,
		ManifestKey: v4.ManifestKey, LoadedImageConfigDigest: v4.LoadedImageConfigDigest, RouteHost: v4.RouteHost,
		Stage: v4.Stage, ErrorCode: v4.ErrorCode, Error: v4.Error, AssignmentSeen: v4.AssignmentSeen,
		PullStarted: v4.PullStarted, PullCompleted: v4.PullCompleted, RuntimeStarted: v4.RuntimeStarted,
		HealthPassed: v4.HealthPassed, Subnet: v4.Subnet, Signature: v4.Signature,
	}
}

// MarshalJSON encodes r as its ReceiptV4 document.
func (r Receipt) MarshalJSON() ([]byte, error) {
	v4, err := r.V4()
	if err != nil {
		return nil, err
	}
	return json.Marshal(v4)
}

// UnmarshalJSON decodes strictly as ReceiptV4. A document without "version"
// merges into a receiver that is already deployment.v4, matching
// encoding/json's default merge semantics.
func (r *Receipt) UnmarshalJSON(data []byte) error {
	version, err := documentVersion(data, r.Version)
	if err != nil {
		return err
	}
	if version != OrganicVersion {
		return fmt.Errorf("receipt version %q is not %q", version, OrganicVersion)
	}
	var current ReceiptV4
	if r.Version == OrganicVersion {
		if current, err = r.V4(); err != nil {
			return err
		}
	}
	if err := decodeStrict(data, &current); err != nil {
		return fmt.Errorf("decode deployment.v4 receipt: %w", err)
	}
	*r = ReceiptFromV4(current)
	return nil
}

func documentVersion(data []byte, current string) (string, error) {
	var probe struct {
		Version *string `json:"version"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return "", err
	}
	if probe.Version != nil {
		return *probe.Version, nil
	}
	return current, nil
}

func decodeStrict(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

// ReceiptMatchesTicket is ReceiptMatchesTicketV4 over lifecycle values.
func ReceiptMatchesTicket(t Ticket, r Receipt, artifactConfigDigest string) error {
	ticket, err := t.V4()
	if err != nil {
		return err
	}
	receipt, err := r.V4()
	if err != nil {
		return err
	}
	return ReceiptMatchesTicketV4(ticket, receipt, artifactConfigDigest)
}

// TicketDigest is TicketDigestV4 over a lifecycle deployment.v4 ticket.
func TicketDigest(t Ticket) (string, error) {
	ticket, err := t.V4()
	if err != nil {
		return "", err
	}
	return TicketDigestV4(ticket)
}
