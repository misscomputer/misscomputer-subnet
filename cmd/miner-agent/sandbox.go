// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/bridge"
	"github.com/misscomputer/misscomputer-subnet/pkg/durable"
	"github.com/misscomputer/misscomputer-subnet/pkg/miner"
	"github.com/misscomputer/misscomputer-subnet/pkg/neuron"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
)

// sandboxSynapseVersion is the loopback envelope of sandbox-lease-v1
// documents between the Python miner neuron and this agent.
const sandboxSynapseVersion = "subnet-sandbox-synapse.v1"

// sandboxSweepInterval bounds how long a lapsed hold or an unrenewed lease
// past its grace keeps capacity before the sweep reclaims it.
const sandboxSweepInterval = 10 * time.Second

// openSandboxLeases enables the sandbox-lease-v1 workload only when
// explicitly requested. No isolation backend ships yet, so "on" refuses to
// start rather than run customer code under an unselected runtime; with
// "off" (the default) no sandbox route, table or capability exists.
func openSandboxLeases(mode string) (*miner.SandboxLane, error) {
	switch mode {
	case "off":
		return nil, nil
	case "on":
		return nil, errors.New("--sandbox-leases on requires a sandbox isolation backend, and none is available in this build")
	default:
		return nil, fmt.Errorf("unsupported --sandbox-leases mode %q", mode)
	}
}

// registerSandboxRoutes adds the sandbox routes. It is called only for an
// enabled lane, so a miner without one serves exactly the routes it did
// before the lane existed.
func (a *api) registerSandboxRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/sandbox/reservations", sandboxHandler(a, a.sandbox.Reserve))
	mux.HandleFunc("POST /v1/sandbox/leases", sandboxHandler(a, a.sandbox.Commit))
	mux.HandleFunc("POST /v1/sandbox/renewals", sandboxHandler(a, a.sandbox.Renew))
	mux.HandleFunc("POST /v1/sandbox/releases", sandboxHandler(a, a.sandbox.Release))
}

// sandboxRequest is one validator document forwarded by the miner neuron
// after it authenticated the validator (btauth/1) and verified its hotkey
// service binding.
type sandboxRequest[T any] struct {
	Protocol         string                   `json:"protocol"`
	RequestID        string                   `json:"request_id"`
	CurrentBlock     uint64                   `json:"current_block"`
	CallerHotkey     string                   `json:"caller_hotkey"`
	BindingVerified  bool                     `json:"binding_verified"`
	ValidatorBinding neuron.ServiceKeyBinding `json:"validator_binding"`
	Document         T                        `json:"document"`
}

// sandboxResponse carries the signed receipt, including refused and failed
// receipts, whose error_code the validator attributes.
type sandboxResponse struct {
	Protocol  string                    `json:"protocol"`
	RequestID string                    `json:"request_id"`
	Receipt   protocol.SandboxReceiptV1 `json:"receipt"`
}

func sandboxHandler[T any](a *api, apply func(context.Context, T, miner.SandboxRequest) (protocol.SandboxReceiptV1, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		var input sandboxRequest[T]
		if err := decodeJSON(io.LimitReader(req.Body, bridge.MaxBodyBytes), &input); err != nil {
			bridge.WriteError(w, http.StatusBadRequest, "invalid_request", err.Error(), false)
			return
		}
		if input.Protocol != sandboxSynapseVersion || input.RequestID == "" {
			bridge.WriteError(w, http.StatusBadRequest, "version_mismatch", "only "+sandboxSynapseVersion+" sandbox documents are accepted", false)
			return
		}
		if !input.BindingVerified {
			bridge.WriteError(w, http.StatusForbidden, "binding_unverified", "validator hotkey service binding was not verified", false)
			return
		}
		key, err := a.acceptValidatorBinding(req, input.CurrentBlock, input.CallerHotkey, input.ValidatorBinding)
		if err != nil {
			status, code, retryable := assignmentError(err)
			bridge.WriteError(w, status, code, err.Error(), retryable)
			return
		}
		receipt, err := apply(req.Context(), input.Document, miner.SandboxRequest{
			ValidatorKey: key, CurrentBlock: input.CurrentBlock, Network: a.network, NetUID: a.netuid,
			CallerHotkey: input.CallerHotkey, MinerHotkey: a.hotkey, MinerUID: a.uid,
		})
		if errors.Is(err, durable.ErrSandboxConflict) {
			bridge.WriteError(w, http.StatusConflict, "sandbox_conflict", err.Error(), false)
			return
		}
		if errors.Is(err, miner.ErrSandboxCleanupPending) {
			// The fence is durable; the release is acknowledged with a
			// receipt only once its sandbox is destroyed.
			bridge.WriteError(w, http.StatusServiceUnavailable, "cleanup_pending", err.Error(), true)
			return
		}
		if err != nil {
			status, code, retryable := assignmentError(err)
			bridge.WriteError(w, status, code, err.Error(), retryable)
			return
		}
		writeJSON(w, http.StatusOK, sandboxResponse{Protocol: sandboxSynapseVersion, RequestID: input.RequestID, Receipt: receipt})
	}
}

// sweepSandboxes reclaims lapsed holds and unrenewed leases until ctx ends.
func sweepSandboxes(ctx context.Context, lane *miner.SandboxLane) {
	ticker := time.NewTicker(sandboxSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := lane.Sweep(ctx); err != nil {
				slog.Warn("sandbox sweep", "error", err)
			}
		}
	}
}
