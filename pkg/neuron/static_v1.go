// SPDX-License-Identifier: AGPL-3.0-only

package neuron

import (
	"errors"

	"github.com/misscomputer/misscomputer-subnet/pkg/organic"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	"github.com/misscomputer/misscomputer-subnet/pkg/static"
)

// StaticSynapseVersion is the only envelope that carries static tickets and
// receipts (static-site contract §9). subnet-synapse.v3 never carries one,
// and a miner without FeatureOrganicStaticV1 is never sent one.
const StaticSynapseVersion = "subnet-static-synapse.v1"

// FeatureOrganicStaticV1 advertises the whole static-site-v1 workload.
const FeatureOrganicStaticV1 = static.CapabilityFeature

// StaticDeploySynapseV1 is the validator-to-miner static assignment: the
// shape of DeploySynapseV3 with one static-deployment-ticket v1.
type StaticDeploySynapseV1 struct {
	Protocol         string                  `json:"protocol"`
	RequestID        string                  `json:"request_id"`
	CurrentBlock     uint64                  `json:"current_block"`
	CallerHotkey     string                  `json:"caller_hotkey"`
	ValidatorBinding ServiceKeyBinding       `json:"validator_binding"`
	Ticket           protocol.StaticTicketV1 `json:"ticket"`
}

// LocalStaticAssignRequestV1 is the loopback bridge form: the co-located
// Python miner forwards one btauth-verified StaticDeploySynapseV1 plus its
// binding assertion; Go still verifies every ticket binding.
type LocalStaticAssignRequestV1 struct {
	Protocol         string                  `json:"protocol"`
	RequestID        string                  `json:"request_id"`
	CurrentBlock     uint64                  `json:"current_block"`
	CallerHotkey     string                  `json:"caller_hotkey"`
	BindingVerified  bool                    `json:"binding_verified"`
	ValidatorBinding ServiceKeyBinding       `json:"validator_binding"`
	Ticket           protocol.StaticTicketV1 `json:"ticket"`
}

// StaticDeployResponseV1 answers one static assignment with its signed
// receipt, including failed receipts so their error_code reaches the
// assigning validator.
type StaticDeployResponseV1 struct {
	Protocol   string                   `json:"protocol"`
	RequestID  string                   `json:"request_id"`
	EndpointID string                   `json:"endpoint_id"`
	Receipt    protocol.StaticReceiptV1 `json:"receipt"`
	Idempotent bool                     `json:"idempotent"`
}

// StaticStatusSynapseV1 asks for one static endpoint incarnation owned by
// the caller.
type StaticStatusSynapseV1 struct {
	Protocol     string `json:"protocol"`
	RequestID    string `json:"request_id"`
	CurrentBlock uint64 `json:"current_block"`
	CallerHotkey string `json:"caller_hotkey"`
	EndpointID   string `json:"endpoint_id"`
}

// StaticStatusResponseV1 mirrors StatusResponseV3 rules with a static
// receipt: null for absent/processing, stage-matched for ready/failed.
type StaticStatusResponseV1 struct {
	Protocol  string                    `json:"protocol"`
	RequestID string                    `json:"request_id"`
	Status    string                    `json:"status"`
	Receipt   *protocol.StaticReceiptV1 `json:"receipt"`
}

func validStaticEnvelope(protocolVersion, requestID string) error {
	if protocolVersion != StaticSynapseVersion {
		return errors.New("static envelopes require subnet-static-synapse.v1")
	}
	if len(requestID) < 1 || len(requestID) > 2048 {
		return errors.New("request_id must be 1-2048 bytes")
	}
	return nil
}

func (s StaticDeploySynapseV1) Validate() error {
	if err := validStaticEnvelope(s.Protocol, s.RequestID); err != nil {
		return err
	}
	if !organic.ValidHotkey(s.CallerHotkey) {
		return errors.New("caller_hotkey is invalid")
	}
	return s.Ticket.Validate()
}

func (r LocalStaticAssignRequestV1) Validate() error {
	if err := validStaticEnvelope(r.Protocol, r.RequestID); err != nil {
		return err
	}
	if !organic.ValidHotkey(r.CallerHotkey) {
		return errors.New("caller_hotkey is invalid")
	}
	return r.Ticket.Validate()
}

func (r StaticDeployResponseV1) Validate() error {
	if err := validStaticEnvelope(r.Protocol, r.RequestID); err != nil {
		return err
	}
	if r.EndpointID != r.Receipt.EndpointID {
		return errors.New("result_endpoint_mismatch")
	}
	return r.Receipt.Validate()
}

func (s StaticStatusSynapseV1) Validate() error {
	if err := validStaticEnvelope(s.Protocol, s.RequestID); err != nil {
		return err
	}
	if !organic.ValidHotkey(s.CallerHotkey) || s.EndpointID == "" || len(s.EndpointID) > 256 {
		return errors.New("static status identity is invalid")
	}
	return nil
}

func (r StaticStatusResponseV1) Validate() error {
	if err := validStaticEnvelope(r.Protocol, r.RequestID); err != nil {
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
