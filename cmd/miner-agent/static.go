// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/bridge"
	"github.com/misscomputer/misscomputer-subnet/pkg/durable"
	"github.com/misscomputer/misscomputer-subnet/pkg/miner"
	"github.com/misscomputer/misscomputer-subnet/pkg/neuron"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	"github.com/misscomputer/misscomputer-subnet/pkg/static"
)

// openStaticSites enables the static-site-v1 workload only when explicitly
// requested; the default leaves it, and its capability, absent.
func openStaticSites(mode, cacheDir string, maxBytes int64, fetchTimeout time.Duration, concurrency int) (*miner.StaticSites, error) {
	switch mode {
	case "off":
		return nil, nil
	case "on":
	default:
		return nil, fmt.Errorf("unsupported --static-sites mode %q", mode)
	}
	if cacheDir == "" || maxBytes < static.MaxTotalBytes {
		return nil, fmt.Errorf("--static-sites on requires --static-cache-dir and --static-cache-max-bytes >= %d", static.MaxTotalBytes)
	}
	cache, err := static.OpenCache(cacheDir, maxBytes)
	if err != nil {
		return nil, err
	}
	return miner.NewStaticSites(cache, fetchTimeout, concurrency), nil
}

// assignStatic accepts only subnet-static-synapse.v1 envelopes. A signed
// failed receipt is answered as a result so its error_code reaches the
// assigning validator; a refusal before admission is a bridge error.
func (a *api) assignStatic(w http.ResponseWriter, req *http.Request) {
	body, err := io.ReadAll(io.LimitReader(req.Body, bridge.MaxBodyBytes+1))
	if err != nil || len(body) > bridge.MaxBodyBytes {
		bridge.WriteError(w, http.StatusBadRequest, "invalid_request", "assignment body is unreadable or too large", false)
		return
	}
	if a.agent.Static == nil {
		bridge.WriteError(w, http.StatusNotImplemented, "static_disabled", "static sites are not enabled on this miner", false)
		return
	}
	var input neuron.LocalStaticAssignRequestV1
	if err := decodeJSON(bytes.NewReader(body), &input); err != nil {
		bridge.WriteError(w, http.StatusBadRequest, "invalid_request", err.Error(), false)
		return
	}
	if !input.BindingVerified {
		bridge.WriteError(w, http.StatusForbidden, "binding_unverified", "validator hotkey service binding was not verified", false)
		return
	}
	if err := input.Validate(); err != nil {
		bridge.WriteError(w, http.StatusBadRequest, "invalid_request", err.Error(), false)
		return
	}
	key, err := a.acceptValidatorBinding(req, input.CurrentBlock, input.CallerHotkey, input.ValidatorBinding)
	if err != nil {
		status, code, retryable := assignmentError(err)
		bridge.WriteError(w, status, code, err.Error(), retryable)
		return
	}
	result, err := a.agent.AssignBoundStaticV1(req.Context(), input.Ticket, key, input.CurrentBlock, a.network, a.netuid, input.CallerHotkey, a.hotkey, a.uid)
	if err != nil && (result.Receipt.Stage != protocol.StageFailed || result.Receipt.Signature == "") {
		status, code, retryable := assignmentError(err)
		bridge.WriteError(w, status, code, err.Error(), retryable)
		return
	}
	writeJSON(w, http.StatusOK, neuron.StaticDeployResponseV1{
		Protocol: neuron.StaticSynapseVersion, RequestID: input.RequestID, EndpointID: result.EndpointID,
		Receipt: result.Receipt, Idempotent: result.Idempotent,
	})
}

// acceptValidatorBinding applies the assignBound validator-binding checks
// shared by every assignment kind and returns the bound service key.
func (a *api) acceptValidatorBinding(req *http.Request, currentBlock uint64, callerHotkey string, binding neuron.ServiceKeyBinding) (ed25519.PublicKey, error) {
	if binding.Protocol != neuron.ServiceBindingVersion || binding.Role != "validator" || binding.Network != a.network || binding.NetUID != a.netuid || binding.Hotkey != callerHotkey || binding.ServicePublicKey == "" {
		return nil, &bridgeError{http.StatusForbidden, "identity_mismatch", errors.New("validator binding does not match the authenticated caller")}
	}
	if err := neuron.ValidateServiceBindingTransport(binding, false); err != nil {
		return nil, &bridgeError{http.StatusForbidden, "identity_mismatch", err}
	}
	keyBytes, err := hex.DecodeString(binding.ServicePublicKey)
	if err != nil || len(keyBytes) != ed25519.PublicKeySize {
		return nil, &bridgeError{http.StatusBadRequest, "invalid_service_key", errors.New("validator service key is invalid")}
	}
	if currentBlock < binding.ValidFromBlock || currentBlock >= binding.ExpiresAtBlock {
		return nil, &bridgeError{http.StatusGone, "expired_binding", errors.New("validator service binding is not current")}
	}
	if err := a.store.UpsertServiceBinding(req.Context(), durable.ServiceBinding{
		Role: binding.Role, Network: binding.Network, NetUID: binding.NetUID, Hotkey: binding.Hotkey, UID: binding.UID,
		ServicePublicKey: binding.ServicePublicKey, Generation: binding.Generation, ExpiresAtBlock: binding.ExpiresAtBlock,
		Transport: binding.Transport, TransportCertificateSHA256: optionalString(binding.TransportCertificateSHA256),
		BindingJSON: neuron.BindingJSON(binding),
	}); err != nil {
		return nil, &bridgeError{http.StatusConflict, "binding_rollback", err}
	}
	return ed25519.PublicKey(keyBytes), nil
}

// staticStatus answers one caller-owned static endpoint.
func (a *api) staticStatus(w http.ResponseWriter, req *http.Request) {
	var input neuron.StaticStatusSynapseV1
	if err := decodeJSON(req.Body, &input); err != nil {
		bridge.WriteError(w, http.StatusBadRequest, "invalid_request", err.Error(), false)
		return
	}
	if err := input.Validate(); err != nil {
		bridge.WriteError(w, http.StatusBadRequest, "version_mismatch", err.Error(), false)
		return
	}
	record, found, err := a.agent.StaticRecord(req.Context(), input.EndpointID)
	if err != nil {
		bridge.WriteError(w, http.StatusInternalServerError, "state_error", err.Error(), true)
		return
	}
	response := neuron.StaticStatusResponseV1{Protocol: neuron.StaticSynapseVersion, RequestID: input.RequestID, Status: "absent"}
	if found {
		if record.Ticket.Subnet == nil || record.Ticket.Subnet.ValidatorHotkey != input.CallerHotkey {
			bridge.WriteError(w, http.StatusForbidden, "identity_mismatch", "assignment belongs to another validator", false)
			return
		}
		response.Status, response.Receipt = record.Status, record.Receipt
		if record.Status == "processing" {
			response.Receipt = nil
		}
	}
	writeJSON(w, http.StatusOK, response)
}

// deactivateStatic handles the kind-neutral deactivation synapse for a
// static endpoint: exact deployment and validator ownership, then the
// agent's fence-first retirement. It reports whether the endpoint is static.
func (a *api) deactivateStatic(w http.ResponseWriter, req *http.Request, input neuron.DeactivateSynapse) bool {
	record, found, err := a.agent.StaticRecord(req.Context(), input.EndpointID)
	if err != nil {
		bridge.WriteError(w, http.StatusInternalServerError, "state_error", err.Error(), true)
		return true
	}
	if !found {
		return false
	}
	if record.Ticket.DeploymentID != input.DeploymentID || record.Ticket.Subnet == nil || record.Ticket.Subnet.ValidatorHotkey != input.CallerHotkey {
		bridge.WriteError(w, http.StatusForbidden, "identity_mismatch", "deactivation does not own this endpoint", false)
		return true
	}
	if err := a.agent.Deactivate(req.Context(), input.EndpointID); err != nil {
		bridge.WriteError(w, http.StatusBadGateway, "cleanup_failed", err.Error(), true)
		return true
	}
	writeJSON(w, http.StatusOK, neuron.DeactivateResponse{Protocol: neuron.SynapseVersion, RequestID: input.RequestID, Status: "deactivated"})
	return true
}
