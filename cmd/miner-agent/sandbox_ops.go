// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/bridge"
	"github.com/misscomputer/misscomputer-subnet/pkg/durable"
	"github.com/misscomputer/misscomputer-subnet/pkg/miner"
	"github.com/misscomputer/misscomputer-subnet/pkg/neuron"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	"github.com/misscomputer/misscomputer-subnet/pkg/sandboxbackend"
	"github.com/misscomputer/misscomputer-subnet/pkg/sandboxops"
)

// sandboxOpsSynapseVersion is the loopback envelope of sandbox-ops-v1 op
// requests between the Python miner neuron and this agent.
const sandboxOpsSynapseVersion = "subnet-sandbox-ops-synapse.v1"

// maxSandboxOpsConfigBytes bounds the --sandbox-ops-config file.
const maxSandboxOpsConfigBytes = 16 << 10

// sandboxOpsFile is the --sandbox-ops-config document: the pinned helper and
// the ops parameters the frozen ops section has not adopted yet, so an
// operator who enables ops must state each one.
type sandboxOpsFile struct {
	HelperDir         string `json:"helper_dir"`
	HelperSHA256      string `json:"helper_sha256"`
	StartResolutionMS int64  `json:"start_resolution_ms"`
	StateTimeoutMS    int64  `json:"state_timeout_ms"`
	KillGraceMS       int64  `json:"kill_grace_ms"`
	MaxInFlight       int    `json:"max_in_flight"`
	MaxInFlightBytes  int    `json:"max_in_flight_bytes"`
	MaxOutcomes       int    `json:"max_outcomes"`
}

// sandboxOpsSettings is a loaded --sandbox-ops on configuration.
type sandboxOpsSettings struct {
	helper sandboxbackend.OpsHelper
	config miner.SandboxOpsConfig
}

// loadSandboxOps validates --sandbox-ops and --sandbox-ops-config. With
// "off" (the default) no ops route, table, mount or capability exists and a
// configuration file is refused, so a configured helper is never silently
// unused.
func loadSandboxOps(mode, path, leases string) (*sandboxOpsSettings, error) {
	switch mode {
	case "off":
		if path != "" {
			return nil, errors.New("--sandbox-ops-config requires --sandbox-ops on")
		}
		return nil, nil
	case "on":
	default:
		return nil, fmt.Errorf("unsupported --sandbox-ops mode %q", mode)
	}
	if leases != "on" {
		return nil, errors.New("--sandbox-ops on requires --sandbox-leases on")
	}
	if path == "" {
		return nil, errors.New("--sandbox-ops on requires --sandbox-ops-config")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("sandbox ops config: %w", err)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxSandboxOpsConfigBytes+1))
	if err != nil || len(raw) > maxSandboxOpsConfigBytes {
		return nil, errors.New("sandbox ops config is unreadable or too large")
	}
	var parsed sandboxOpsFile
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&parsed); err != nil {
		return nil, fmt.Errorf("sandbox ops config: %w", err)
	}
	ms := func(value int64) time.Duration { return time.Duration(value) * time.Millisecond }
	return &sandboxOpsSettings{
		helper: sandboxbackend.OpsHelper{Dir: parsed.HelperDir, SHA256: parsed.HelperSHA256},
		config: miner.SandboxOpsConfig{
			StartResolution: ms(parsed.StartResolutionMS), StateTimeout: ms(parsed.StateTimeoutMS), KillGrace: ms(parsed.KillGraceMS),
			MaxInFlight: parsed.MaxInFlight, MaxInFlightBytes: parsed.MaxInFlightBytes, MaxOutcomes: parsed.MaxOutcomes,
		},
	}, nil
}

// enableSandboxOps enables the ops store and lane. It runs only after both
// startup Recover steps succeeded, before the server serves (OPS-U6).
func enableSandboxOps(ctx context.Context, lane *miner.SandboxLane, store *durable.Store, settings *sandboxOpsSettings) error {
	leases, err := store.EnableSandboxLeases(ctx)
	if err != nil {
		return err
	}
	ops, err := leases.EnableSandboxOps(ctx, time.Now)
	if err != nil {
		return err
	}
	return lane.EnableOps(ops, settings.config)
}

// sandboxOpsRequest is one validator op request forwarded by the miner
// neuron after it authenticated the validator and verified its binding.
type sandboxOpsRequest struct {
	Protocol         string                      `json:"protocol"`
	RequestID        string                      `json:"request_id"`
	CurrentBlock     uint64                      `json:"current_block"`
	CallerHotkey     string                      `json:"caller_hotkey"`
	BindingVerified  bool                        `json:"binding_verified"`
	ValidatorBinding neuron.ServiceKeyBinding    `json:"validator_binding"`
	Document         protocol.SandboxOpRequestV1 `json:"document"`
	Payload          *string                     `json:"payload_b64"`
}

// sandboxOpsResponse carries the signed receipt and its result bytes.
type sandboxOpsResponse struct {
	Protocol  string                      `json:"protocol"`
	RequestID string                      `json:"request_id"`
	Receipt   protocol.SandboxOpReceiptV1 `json:"receipt"`
	Result    *string                     `json:"result_b64"`
}

func decodeChunk(encoded *string) ([]byte, error) {
	if encoded == nil {
		return nil, nil
	}
	data, err := base64.StdEncoding.Strict().DecodeString(*encoded)
	if err != nil || base64.StdEncoding.EncodeToString(data) != *encoded {
		return nil, errors.New("payload_b64 is not canonical base64")
	}
	return data, nil
}

// sandboxOps serves POST /v1/sandbox/ops. Every answer without a receipt is
// one of sandbox_conflict, sandbox_lane_closed, sandbox_ops_busy (retryable)
// or the existing validation and admission errors.
func (a *api) sandboxOps(w http.ResponseWriter, req *http.Request) {
	var input sandboxOpsRequest
	if err := decodeJSON(io.LimitReader(req.Body, bridge.MaxBodyBytes), &input); err != nil {
		bridge.WriteError(w, http.StatusBadRequest, "invalid_request", err.Error(), false)
		return
	}
	if input.Protocol != sandboxOpsSynapseVersion || input.RequestID == "" {
		bridge.WriteError(w, http.StatusBadRequest, "version_mismatch", "only "+sandboxOpsSynapseVersion+" op requests are accepted", false)
		return
	}
	if !input.BindingVerified {
		bridge.WriteError(w, http.StatusForbidden, "binding_unverified", "validator hotkey service binding was not verified", false)
		return
	}
	payload, err := decodeChunk(input.Payload)
	if err != nil {
		bridge.WriteError(w, http.StatusBadRequest, "invalid_request", err.Error(), false)
		return
	}
	key, err := a.acceptValidatorBinding(req, input.CurrentBlock, input.CallerHotkey, input.ValidatorBinding)
	if err != nil {
		status, code, retryable := assignmentError(err)
		bridge.WriteError(w, status, code, err.Error(), retryable)
		return
	}
	receipt, result, err := a.sandbox.Op(req.Context(), input.Document, payload, miner.SandboxRequest{
		ValidatorKey: key, CurrentBlock: input.CurrentBlock, Network: a.network, NetUID: a.netuid,
		CallerHotkey: input.CallerHotkey, MinerHotkey: a.hotkey, MinerUID: a.uid,
	})
	switch {
	case errors.Is(err, durable.ErrSandboxConflict):
		bridge.WriteError(w, http.StatusConflict, "sandbox_conflict", err.Error(), false)
	case errors.Is(err, miner.ErrSandboxLaneClosed):
		bridge.WriteError(w, http.StatusServiceUnavailable, "sandbox_lane_closed", err.Error(), true)
	case errors.Is(err, miner.ErrSandboxOpsBusy):
		bridge.WriteError(w, http.StatusServiceUnavailable, "sandbox_ops_busy", err.Error(), true)
	case errors.Is(err, durable.ErrSandboxOpExpired):
		bridge.WriteError(w, http.StatusGone, "expired_assignment", err.Error(), false)
	case err != nil && strings.HasPrefix(err.Error(), "sandbox_op_payload"):
		bridge.WriteError(w, http.StatusBadRequest, "sandbox_op_payload_mismatch", err.Error(), false)
	case err != nil:
		status, code, retryable := assignmentError(err)
		bridge.WriteError(w, status, code, err.Error(), retryable)
	default:
		var encoded *string
		if result != nil {
			encoded = sandboxops.EncodeData(result)
		}
		writeJSON(w, http.StatusOK, sandboxOpsResponse{Protocol: sandboxOpsSynapseVersion, RequestID: input.RequestID, Receipt: receipt, Result: encoded})
	}
}
