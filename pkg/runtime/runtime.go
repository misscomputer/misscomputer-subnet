// SPDX-License-Identifier: AGPL-3.0-only

package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type Instance struct {
	ID  string
	URL string
}

// CleanupPlan is the complete private identity needed to clean a runtime
// incarnation after the creating process disappears. LayerPath is empty for
// backends whose deterministic instance ID is enough; DockerOCIRuntime
// records its exact per-instance state directory.
type CleanupPlan struct {
	InstanceID string
	LayerPath  string
	LayerRoot  string
}

type cleanupPlanner interface {
	PlanCleanup(endpointID string) (CleanupPlan, error)
}

type cleanupStopper interface {
	StopCleanup(ctx context.Context, plan CleanupPlan) error
}

// PrepareCleanup resolves and validates the identity that the agent must make
// durable before creating a replica of endpointID. Backends without a planner
// inherit the deterministic ID-only contract; Docker additionally supplies
// its exact instance state path.
func PrepareCleanup(backend Stopper, endpointID string) (CleanupPlan, error) {
	expectedID := InstanceName(endpointID)
	plan := CleanupPlan{InstanceID: expectedID}
	if planner, ok := backend.(cleanupPlanner); ok {
		var err error
		plan, err = planner.PlanCleanup(endpointID)
		if err != nil {
			return CleanupPlan{}, err
		}
	}
	return validateCleanupIdentity(plan, expectedID)
}

func validateCleanupIdentity(plan CleanupPlan, expectedID string) (CleanupPlan, error) {
	if plan.InstanceID != expectedID {
		return CleanupPlan{}, fmt.Errorf("runtime cleanup identity %q is not deterministic %q", plan.InstanceID, expectedID)
	}
	if (plan.LayerPath == "") != (plan.LayerRoot == "") {
		return CleanupPlan{}, fmt.Errorf("runtime cleanup layer path and ownership root must be paired")
	}
	return plan, nil
}

// StopCleanup restores persisted backend-specific cleanup metadata when the
// runtime supports it, otherwise it stops the deterministic instance ID.
func StopCleanup(ctx context.Context, backend Stopper, plan CleanupPlan) error {
	if plan.InstanceID == "" {
		return fmt.Errorf("runtime cleanup identity is empty")
	}
	if plan.LayerPath != "" {
		if stopper, ok := backend.(cleanupStopper); ok {
			return stopper.StopCleanup(ctx, plan)
		}
	}
	return backend.Stop(ctx, plan.InstanceID)
}

// InstanceName derives a runtime-safe, collision-resistant name from the
// scheduler-controlled endpoint incarnation, so generation and assignment
// nonce changes always produce a distinct runtime identity.
func InstanceName(endpointID string) string {
	const maxPrefix = 48
	var normalized strings.Builder
	for _, char := range endpointID {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '_' || char == '.' || char == '-' {
			normalized.WriteRune(char)
		} else {
			normalized.WriteByte('-')
		}
	}
	prefix := strings.Trim(normalized.String(), ".-_")
	if prefix == "" {
		prefix = "endpoint"
	}
	if len(prefix) > maxPrefix {
		prefix = prefix[:maxPrefix]
	}
	sum := sha256.Sum256([]byte(endpointID))
	return "miss-" + prefix + "-" + hex.EncodeToString(sum[:6])
}

func canonicalDirectory(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)
	resolved, err := filepath.EvalSymlinks(abs)
	if err == nil {
		return filepath.Clean(resolved), nil
	}
	if os.IsNotExist(err) {
		return abs, nil
	}
	return "", err
}

func containerNotFound(output []byte) bool {
	message := strings.ToLower(string(output))
	return strings.Contains(message, "no such container") || strings.Contains(message, "no such object")
}

func containerRemovalInProgress(output []byte) bool {
	message := strings.ToLower(string(output))
	return strings.Contains(message, "removal") && strings.Contains(message, "in progress")
}

func waitForContainerRemoval(ctx context.Context, binary, instanceID string) error {
	for {
		out, err := exec.CommandContext(ctx, binary, "inspect", instanceID).CombinedOutput()
		if err != nil {
			if containerNotFound(out) {
				return nil
			}
			if ctx.Err() != nil {
				return fmt.Errorf("wait for docker removal: %w", ctx.Err())
			}
			return fmt.Errorf("docker inspect during removal: %w: %s", err, strings.TrimSpace(string(out)))
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("wait for docker removal: %w", ctx.Err())
		case <-timer.C:
		}
	}
}
