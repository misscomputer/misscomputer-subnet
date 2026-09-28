// SPDX-License-Identifier: AGPL-3.0-only

package neuron

import (
	"errors"

	"github.com/misscomputer/misscomputer-subnet/pkg/organic"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
)

// OrganicSynapseVersion is carried by every validator<->miner message that
// embeds a deployment.v4 ticket or receipt (and by every status response).
// Messages embedding neither keep SynapseVersion.
const OrganicSynapseVersion = organic.SynapseVersion

// FeatureOrganicOCIV1 advertises the organic OCI runtime. A miner that does
// not advertise it is ineligible for organic assignment (fail closed).
const FeatureOrganicOCIV1 = organic.CapabilityFeature

// DeploySynapseV3 mirrors misscomputer_subnet.organic_contracts.DeploySynapseV3.
type DeploySynapseV3 struct {
	Protocol         string            `json:"protocol"`
	RequestID        string            `json:"request_id"`
	CurrentBlock     uint64            `json:"current_block"`
	CallerHotkey     string            `json:"caller_hotkey"`
	ValidatorBinding ServiceKeyBinding `json:"validator_binding"`
	Ticket           protocol.TicketV4 `json:"ticket"`
}

// MinerResultV4 is the miner's answer to one deployment.v4 assignment.
type MinerResultV4 struct {
	Receipt    protocol.ReceiptV4 `json:"receipt"`
	EndpointID string             `json:"endpoint_id"`
}

type DeployResponseV3 struct {
	Protocol   string        `json:"protocol"`
	RequestID  string        `json:"request_id"`
	Result     MinerResultV4 `json:"result"`
	Idempotent bool          `json:"idempotent"`
}

// StatusResponseV3 always carries receipt; it is null only while the
// assignment is absent or processing (and may be null once deactivated).
type StatusResponseV3 struct {
	Protocol  string              `json:"protocol"`
	RequestID string              `json:"request_id"`
	Status    string              `json:"status"`
	Receipt   *protocol.ReceiptV4 `json:"receipt"`
}

type BridgeAssignRequestV3 struct {
	Protocol  string            `json:"protocol"`
	RequestID string            `json:"request_id"`
	Ticket    protocol.TicketV4 `json:"ticket"`
}

// LocalAssignRequestV3 is accepted only over the authenticated loopback
// bridge: the co-located Python miner forwards one verified DeploySynapseV3.
// BindingVerified is an assertion by the Python btauth verifier; Go still
// verifies every ticket binding.
type LocalAssignRequestV3 struct {
	Protocol         string            `json:"protocol"`
	RequestID        string            `json:"request_id"`
	CurrentBlock     uint64            `json:"current_block"`
	CallerHotkey     string            `json:"caller_hotkey"`
	BindingVerified  bool              `json:"binding_verified"`
	ValidatorBinding ServiceKeyBinding `json:"validator_binding"`
	Ticket           protocol.TicketV4 `json:"ticket"`
}

func (r LocalAssignRequestV3) Validate() error {
	if err := validEnvelope(r.Protocol, r.RequestID); err != nil {
		return err
	}
	if !organic.ValidHotkey(r.CallerHotkey) {
		return errors.New("caller_hotkey is invalid")
	}
	return r.Ticket.Validate()
}

// MinerResultFromV4 converts one lifecycle result of a deployment.v4
// assignment into its subnet-synapse.v3 wire form.
func MinerResultFromV4(receipt protocol.Receipt) (MinerResultV4, error) {
	v4, err := receipt.V4()
	if err != nil {
		return MinerResultV4{}, err
	}
	return MinerResultV4{Receipt: v4, EndpointID: v4.EndpointID}, nil
}

func validEnvelope(protocolVersion, requestID string) error {
	if protocolVersion != OrganicSynapseVersion {
		return errors.New("organic envelopes require subnet-synapse.v3")
	}
	if len(requestID) < 1 || len(requestID) > 2048 {
		return errors.New("request_id must be 1-2048 bytes")
	}
	return nil
}

func (s DeploySynapseV3) Validate() error {
	if err := validEnvelope(s.Protocol, s.RequestID); err != nil {
		return err
	}
	if !organic.ValidHotkey(s.CallerHotkey) {
		return errors.New("caller_hotkey is invalid")
	}
	return s.Ticket.Validate()
}

func (r DeployResponseV3) Validate() error {
	if err := validEnvelope(r.Protocol, r.RequestID); err != nil {
		return err
	}
	if r.Result.EndpointID != r.Result.Receipt.EndpointID {
		return errors.New("result_endpoint_mismatch")
	}
	return r.Result.Receipt.Validate()
}

var minerStatuses = map[string]bool{"absent": true, "processing": true, "accepted": true, "ready": true, "failed": true, "deactivated": true}

func (r StatusResponseV3) Validate() error {
	if err := validEnvelope(r.Protocol, r.RequestID); err != nil {
		return err
	}
	if !minerStatuses[r.Status] {
		return errors.New("status is invalid")
	}
	switch r.Status {
	case "accepted", "ready", "failed":
		if r.Receipt == nil || string(r.Receipt.Stage) != r.Status {
			return errors.New("status_receipt_mismatch")
		}
	case "absent", "processing":
		if r.Receipt != nil {
			return errors.New("status_receipt_mismatch")
		}
	}
	if r.Receipt != nil {
		return r.Receipt.Validate()
	}
	return nil
}

func (r BridgeAssignRequestV3) Validate() error {
	if err := validEnvelope(r.Protocol, r.RequestID); err != nil {
		return err
	}
	return r.Ticket.Validate()
}
