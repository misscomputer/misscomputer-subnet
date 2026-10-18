// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/bridge"
	"github.com/misscomputer/misscomputer-subnet/pkg/durable"
	"github.com/misscomputer/misscomputer-subnet/pkg/miner"
	"github.com/misscomputer/misscomputer-subnet/pkg/neuron"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	"github.com/misscomputer/misscomputer-subnet/pkg/sandbox"
	"github.com/misscomputer/misscomputer-subnet/pkg/sandboxbackend"
	"github.com/misscomputer/misscomputer-subnet/pkg/sandboxhost"
)

// sandboxSynapseVersion is the loopback envelope of sandbox-lease-v1
// documents between the Python miner neuron and this agent.
const sandboxSynapseVersion = "subnet-sandbox-synapse.v1"

// sandboxSweepInterval bounds how long a lapsed hold or an unrenewed lease
// past its grace keeps capacity before the sweep reclaims it.
const sandboxSweepInterval = 10 * time.Second

// sandboxRecoveryTimeout bounds the sandbox lane's restart recovery, which
// may remove every sandbox the backend still runs; it is separate from the
// agent's own cleanup budget.
const sandboxRecoveryTimeout = 5 * time.Minute

// sandboxOptions is the --sandbox-* configuration.
type sandboxOptions struct {
	// Mode is --sandbox-leases: off (the default) or on.
	Mode string
	// HostProfile is the sandbox-host-profile.v1 document the host's
	// provisioner wrote; every backend value comes from it.
	HostProfile string
	// DeploymentCgroup is the cgroup v2 path deployment.v4 replicas run in,
	// which sandboxes must not share.
	DeploymentCgroup string
	// DaemonConfig is the dedicated sandbox daemon's configuration file.
	DaemonConfig string
}

// openSandboxLeases enables the sandbox-lease-v1 workload only when
// explicitly requested. With "off" (the default) no sandbox route, table or
// capability exists, and any --sandbox-* setting is refused so that a
// configured backend is never silently unused. With "on" the agent starts
// only if the whole host preflight report passes: the gVisor backend's
// engine checks and pkg/sandboxhost's host checks, with the deployment
// replicas' cgroup and the agent's own kept disjoint from the sandbox and
// engine slices; then the lane verifies its budget against the backend.
func openSandboxLeases(ctx context.Context, options sandboxOptions, agent *miner.Agent, store *durable.Store) (*miner.SandboxLane, error) {
	switch options.Mode {
	case "off":
		if options != (sandboxOptions{Mode: "off"}) {
			return nil, errors.New("--sandbox-* settings require --sandbox-leases on")
		}
		return nil, nil
	case "on":
	default:
		return nil, fmt.Errorf("unsupported --sandbox-leases mode %q", options.Mode)
	}
	if options.HostProfile == "" || options.DeploymentCgroup == "" || options.DaemonConfig == "" {
		return nil, errors.New("--sandbox-leases on requires --sandbox-host-profile, --sandbox-deployment-cgroup and --sandbox-daemon-config")
	}
	profile, err := sandboxhost.LoadProfile(options.HostProfile)
	if err != nil {
		return nil, fmt.Errorf("sandbox host profile: %w", err)
	}
	if err := verifyDeploymentCgroup(profile.CgroupRoot, options.DeploymentCgroup); err != nil {
		return nil, err
	}
	agentCgroup, err := selfCgroup()
	if err != nil {
		return nil, err
	}
	backend, report, err := sandboxbackend.OpenFromProfile(ctx, profile, options.DaemonConfig, sandboxhost.Host{}, []string{options.DeploymentCgroup})
	if report.Mode != "" {
		slog.Info("sandbox host preflight report", "verdict", report.Verdict, "report", report)
	}
	if err != nil {
		return nil, fmt.Errorf("sandbox host preflight: %w", err)
	}
	leases, err := store.EnableSandboxLeases(ctx)
	if err != nil {
		return nil, err
	}
	a := profile.Aggregate
	return miner.NewSandboxLane(ctx, agent, leases, backend, miner.SandboxLaneConfig{
		Budget:     sandbox.Capacity{CPUMillis: a.CPUMillis, MemoryMiB: a.MemoryMiB, DiskMiB: a.DiskMiB, Sandboxes: a.Sandboxes},
		CgroupRoot: profile.CgroupRoot, AgentCgroup: agentCgroup, DeploymentCgroup: options.DeploymentCgroup,
	})
}

// verifyDeploymentCgroup requires the deployment replicas' cgroup to be a
// clean absolute cgroup v2 path that exists, so that keeping sandboxes
// disjoint from it is not vacuous. That replicas actually run in it is not
// observed here.
func verifyDeploymentCgroup(root, cgroup string) error {
	if !path.IsAbs(cgroup) || path.Clean(cgroup) != cgroup || cgroup == "/" {
		return fmt.Errorf("--sandbox-deployment-cgroup %q must be a clean absolute cgroup path other than /", cgroup)
	}
	info, err := os.Stat(filepath.Join(root, cgroup, "cgroup.procs"))
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("--sandbox-deployment-cgroup %s is not a cgroup under %s", cgroup, root)
	}
	return nil
}

// selfCgroup is this process's cgroup v2 path.
func selfCgroup() (string, error) {
	raw, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", fmt.Errorf("read agent cgroup: %w", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if cgroup, ok := strings.CutPrefix(line, "0::"); ok {
			return cgroup, nil
		}
	}
	return "", errors.New("the miner agent is not in a cgroup v2 hierarchy")
}

// registerSandboxRoutes adds the sandbox routes. It is called only for an
// enabled lane, so a miner without one serves exactly the routes it did
// before the lane existed.
func (a *api) registerSandboxRoutes(mux *http.ServeMux) {
	if a.sandboxReservationReplay {
		mux.HandleFunc("POST /v1/sandbox/reservations/replay", sandboxHandler(a, a.sandbox.ReplayReservation))
	}
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
		for _, refusal := range []struct {
			err    error
			status int
			code   string
		}{
			{durable.ErrSandboxReplayAbsent, http.StatusNotFound, "sandbox_replay_hold_absent"},
			{durable.ErrSandboxReplayFenced, http.StatusConflict, "sandbox_replay_fenced"},
			{durable.ErrSandboxReplayNotHeld, http.StatusConflict, "sandbox_replay_not_held"},
		} {
			if errors.Is(err, refusal.err) {
				bridge.WriteError(w, refusal.status, refusal.code, err.Error(), false)
				return
			}
		}
		if errors.Is(err, miner.ErrSandboxLaneClosed) {
			bridge.WriteError(w, http.StatusServiceUnavailable, "sandbox_lane_closed", err.Error(), true)
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
