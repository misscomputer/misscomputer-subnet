// SPDX-License-Identifier: AGPL-3.0-only

package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	"github.com/misscomputer/misscomputer-subnet/pkg/workload"
)

type Instance struct {
	ID  string
	URL string
}

// CleanupPlan is the complete private identity needed to clean a runtime
// incarnation after the creating process disappears. LayerPath is empty for
// backends, such as LocalRuntime, whose deterministic instance ID is enough.
type CleanupPlan struct {
	InstanceID string
	LayerPath  string
	LayerRoot  string
}

type Runtime interface {
	// Deploy must create the endpoint at InstanceName(protocol.EndpointID(ticket)).
	// The miner persists that identity before calling Deploy so a daemon-side
	// object remains recoverable even if this call never returns.
	Deploy(ctx context.Context, ticket protocol.Ticket, manifest artifact.Manifest, layers [][]byte) (Instance, error)
	Stop(ctx context.Context, instanceID string) error
}

type cleanupPlanner interface {
	PlanCleanup(ticket protocol.Ticket) (CleanupPlan, error)
}

type cleanupStopper interface {
	StopCleanup(ctx context.Context, plan CleanupPlan) error
}

type cleanupRecoverer interface {
	RecoverCleanup(ctx context.Context, ticket protocol.Ticket) (CleanupPlan, error)
}

// PrepareCleanup resolves and validates the identity that the agent must make
// durable before Deploy. Custom runtimes inherit the deterministic ID-only
// contract; production Docker additionally supplies its exact layer path.
func PrepareCleanup(backend Runtime, ticket protocol.Ticket) (CleanupPlan, error) {
	expectedID := InstanceName(protocol.EndpointID(ticket))
	plan := CleanupPlan{InstanceID: expectedID}
	if planner, ok := backend.(cleanupPlanner); ok {
		var err error
		plan, err = planner.PlanCleanup(ticket)
		if err != nil {
			return CleanupPlan{}, err
		}
	}
	return validateCleanupIdentity(plan, expectedID)
}

// RecoverCleanup inspects backend state when an older assignment has no
// persisted runtime incarnation. Docker uses this hook to recover the exact
// parent-version randomized bind source before the container is stopped;
// other runtimes retain the deterministic ID-only behavior.
func RecoverCleanup(ctx context.Context, backend Runtime, ticket protocol.Ticket) (CleanupPlan, error) {
	expectedID := InstanceName(protocol.EndpointID(ticket))
	if recoverer, ok := backend.(cleanupRecoverer); ok {
		plan, err := recoverer.RecoverCleanup(ctx, ticket)
		if err != nil {
			return CleanupPlan{}, err
		}
		return validateCleanupIdentity(plan, expectedID)
	}
	return PrepareCleanup(backend, ticket)
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
func StopCleanup(ctx context.Context, backend Runtime, plan CleanupPlan) error {
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
// scheduler-controlled endpoint incarnation. Both local and Docker runtimes
// use this helper so generation and assignment nonce changes always produce a
// distinct runtime identity.
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

type LocalRuntime struct {
	mu      sync.Mutex
	servers map[string]*httptest.Server
}

func NewLocalRuntime() *LocalRuntime {
	return &LocalRuntime{servers: make(map[string]*httptest.Server)}
}

func (r *LocalRuntime) Deploy(_ context.Context, ticket protocol.Ticket, _ artifact.Manifest, layers [][]byte) (Instance, error) {
	if len(layers) == 0 {
		return Instance{}, fmt.Errorf("workload has no layers")
	}
	spec, err := workload.Decode(layers[len(layers)-1])
	if err != nil {
		return Instance{}, err
	}
	if spec.ChallengePath != ticket.ChallengePath || protocol.ChallengeDigest(spec.ChallengeValue) != ticket.ChallengeSHA256 {
		return Instance{}, fmt.Errorf("workload challenge does not match signed ticket")
	}
	server := httptest.NewServer(workload.Handler(spec))
	id := InstanceName(protocol.EndpointID(ticket))
	r.mu.Lock()
	if previous := r.servers[id]; previous != nil {
		r.mu.Unlock()
		server.Close()
		return Instance{}, fmt.Errorf("runtime instance %q already exists", id)
	}
	r.servers[id] = server
	r.mu.Unlock()
	return Instance{ID: id, URL: server.URL}, nil
}

func (r *LocalRuntime) Stop(_ context.Context, instanceID string) error {
	r.mu.Lock()
	server := r.servers[instanceID]
	delete(r.servers, instanceID)
	r.mu.Unlock()
	if server != nil {
		server.Close()
	}
	return nil
}

// DockerRuntime is the production-shaped runtime backend. The manifest must
// carry docker.image and the image itself must implement /healthz and the
// signed challenge path. Artifact verification happens before Deploy.
type DockerRuntime struct {
	Binary   string
	StateDir string
	mu       sync.Mutex
	layers   map[string]string
}

func NewDockerRuntime(binary, stateDir string) *DockerRuntime {
	return &DockerRuntime{Binary: binary, StateDir: stateDir, layers: make(map[string]string)}
}

func (r *DockerRuntime) stateDirectory() string {
	if r.StateDir != "" {
		return r.StateDir
	}
	return filepath.Join(os.TempDir(), "misscomputer-layers")
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

func (r *DockerRuntime) layerPath(instanceID string) (string, error) {
	if instanceID == "" || instanceID == "." || instanceID == ".." {
		return "", fmt.Errorf("invalid runtime instance identity %q", instanceID)
	}
	for _, char := range instanceID {
		if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '_' || char == '.' || char == '-') {
			return "", fmt.Errorf("invalid runtime instance identity %q", instanceID)
		}
	}
	stateDir, err := canonicalDirectory(r.stateDirectory())
	if err != nil {
		return "", fmt.Errorf("resolve runtime state directory: %w", err)
	}
	return filepath.Join(stateDir, instanceID+".layer"), nil
}

func (r *DockerRuntime) PlanCleanup(ticket protocol.Ticket) (CleanupPlan, error) {
	instanceID := InstanceName(protocol.EndpointID(ticket))
	layerPath, err := r.layerPath(instanceID)
	if err != nil {
		return CleanupPlan{}, err
	}
	return CleanupPlan{InstanceID: instanceID, LayerPath: layerPath, LayerRoot: filepath.Dir(layerPath)}, nil
}

// RecoverCleanup reads the deterministic container's workload bind before
// stopping it. Parent c8b46e6 materialized verified-*.layer files, so deriving
// the current <instance>.layer path would delete the wrong file. Only one
// read-only bind at the exact workload destination and directly beneath the
// configured state root is accepted.
func (r *DockerRuntime) RecoverCleanup(ctx context.Context, ticket protocol.Ticket) (CleanupPlan, error) {
	planned, err := r.PlanCleanup(ticket)
	if err != nil {
		return CleanupPlan{}, err
	}
	binary := r.Binary
	if binary == "" {
		binary = "docker"
	}
	out, err := exec.CommandContext(ctx, binary, "inspect", "--format", "{{json .Mounts}}", planned.InstanceID).CombinedOutput()
	if err != nil {
		if containerNotFound(out) {
			if _, statErr := os.Lstat(planned.LayerPath); statErr == nil {
				if validateErr := validateCleanupLayer(planned, false); validateErr != nil {
					return CleanupPlan{}, validateErr
				}
				return planned, nil
			} else if !os.IsNotExist(statErr) {
				return CleanupPlan{}, fmt.Errorf("inspect deterministic cleanup layer: %w", statErr)
			}
			legacy, scanErr := legacyLayerFiles(planned.LayerRoot)
			if scanErr != nil {
				return CleanupPlan{}, scanErr
			}
			if len(legacy) != 0 {
				// Without the container mount there is no exact owner mapping for a
				// parent-version randomized file. Never guess or falsely complete.
				return CleanupPlan{}, fmt.Errorf("runtime %q is absent but %d unattributable legacy layer files remain", planned.InstanceID, len(legacy))
			}
			// A current-version crash can precede both layer creation and daemon
			// launch. No deterministic or legacy file exists, so the planned
			// identity is safe for an idempotent absence confirmation.
			return planned, nil
		}
		return CleanupPlan{}, fmt.Errorf("docker inspect cleanup mount: %w: %s", err, strings.TrimSpace(string(out)))
	}
	var mounts []struct {
		Type        string `json:"Type"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
		RW          bool   `json:"RW"`
	}
	if err := json.Unmarshal(out, &mounts); err != nil {
		return CleanupPlan{}, fmt.Errorf("decode docker cleanup mounts: %w", err)
	}
	var workloadMounts []struct {
		Type        string `json:"Type"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
		RW          bool   `json:"RW"`
	}
	for _, mount := range mounts {
		if mount.Destination == "/app/workload.layer" {
			workloadMounts = append(workloadMounts, mount)
		}
	}
	if len(workloadMounts) != 1 || workloadMounts[0].Type != "bind" || workloadMounts[0].RW {
		return CleanupPlan{}, fmt.Errorf("runtime %q has no unique read-only workload bind", planned.InstanceID)
	}
	recovered := CleanupPlan{
		InstanceID: planned.InstanceID,
		LayerPath:  workloadMounts[0].Source,
		LayerRoot:  planned.LayerRoot,
	}
	if err := validateCleanupLayer(recovered, false); err != nil {
		return CleanupPlan{}, err
	}
	return recovered, nil
}

func (r *DockerRuntime) Deploy(ctx context.Context, ticket protocol.Ticket, manifest artifact.Manifest, layers [][]byte) (Instance, error) {
	binary := r.Binary
	if binary == "" {
		binary = "docker"
	}
	image := manifest.Annotations["docker.image"]
	if image == "" {
		return Instance{}, fmt.Errorf("manifest lacks docker.image annotation")
	}
	if !strings.HasPrefix(image, "sha256:") && !strings.Contains(image, "@sha256:") {
		return Instance{}, fmt.Errorf("docker.image must be pinned by image ID or repository digest")
	}
	if len(layers) == 0 {
		return Instance{}, fmt.Errorf("workload has no layers")
	}
	spec, err := workload.Decode(layers[len(layers)-1])
	if err != nil {
		return Instance{}, err
	}
	if spec.ChallengePath != ticket.ChallengePath || protocol.ChallengeDigest(spec.ChallengeValue) != ticket.ChallengeSHA256 {
		return Instance{}, fmt.Errorf("workload challenge does not match signed ticket")
	}
	uniqueLayer := layers[len(layers)-1]
	if len(manifest.Layers) == 0 || artifact.Digest(uniqueLayer) != manifest.Layers[len(manifest.Layers)-1].Digest {
		return Instance{}, fmt.Errorf("unique workload layer does not match manifest")
	}
	stateDir := r.stateDirectory()
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return Instance{}, fmt.Errorf("create runtime state directory: %w", err)
	}
	name := InstanceName(protocol.EndpointID(ticket))
	layerPath, err := r.layerPath(name)
	if err != nil {
		return Instance{}, err
	}
	layerFile, err := os.OpenFile(layerPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return Instance{}, fmt.Errorf("create verified layer: %w", err)
	}
	removeLayer := true
	defer func() {
		if removeLayer {
			_ = os.Remove(layerPath)
		}
	}()
	if _, err := layerFile.Write(uniqueLayer); err != nil {
		layerFile.Close()
		return Instance{}, fmt.Errorf("materialize verified layer: %w", err)
	}
	if err := layerFile.Close(); err != nil {
		return Instance{}, fmt.Errorf("close verified layer: %w", err)
	}
	if err := os.Chmod(layerPath, 0o444); err != nil {
		return Instance{}, fmt.Errorf("protect verified layer: %w", err)
	}
	// Track the layer under the deterministic container name before docker run
	// starts. A CLI invocation that fails or is killed by cancellation can
	// still leave a running daemon-side container, so cleanup ownership must
	// begin at creation time, not at first success.
	r.mu.Lock()
	if r.layers == nil {
		r.layers = make(map[string]string)
	}
	r.layers[name] = layerPath
	r.mu.Unlock()
	removeLayer = false
	cmd := exec.CommandContext(ctx, binary, "run", "-d", "--rm", "--name", name,
		"--cpus", fmt.Sprintf("%.3f", float64(ticket.Resources.CPUMillis)/1000),
		"--memory", fmt.Sprintf("%dm", ticket.Resources.MemoryMB), "-p", "127.0.0.1::8080",
		"--mount", "type=bind,src="+layerPath+",dst=/app/workload.layer,readonly",
		"-e", "WORKLOAD_LAYER=/app/workload.layer",
		"-e", "EXPECTED_LAYER_DIGEST="+manifest.Layers[len(manifest.Layers)-1].Digest, image)
	out, err := cmd.CombinedOutput()
	if err != nil {
		runErr := fmt.Errorf("docker run: %w: %s", err, strings.TrimSpace(string(out)))
		// The daemon may have created the container even though the CLI
		// failed or was killed mid-flight. Stop it with a fresh bounded
		// context; an already-absent container is an idempotent success. If
		// even Stop fails, bookkeeping stays retained for a Cleanup retry.
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if cleanupErr := r.Stop(cleanupCtx, name); cleanupErr != nil {
			return Instance{}, fmt.Errorf("%w; cleanup: %v", runErr, cleanupErr)
		}
		return Instance{}, runErr
	}
	port, err := exec.CommandContext(ctx, binary, "port", name, "8080/tcp").Output()
	if err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if cleanupErr := r.Stop(cleanupCtx, name); cleanupErr != nil {
			return Instance{}, fmt.Errorf("docker port: %w; cleanup: %v", err, cleanupErr)
		}
		return Instance{}, fmt.Errorf("docker port: %w", err)
	}
	return Instance{ID: name, URL: "http://" + strings.TrimSpace(string(port))}, nil
}

func (r *DockerRuntime) Stop(ctx context.Context, instanceID string) error {
	return r.stop(ctx, CleanupPlan{InstanceID: instanceID})
}

func (r *DockerRuntime) StopCleanup(ctx context.Context, plan CleanupPlan) error {
	if err := validateCleanupLayer(plan, true); err != nil {
		return err
	}
	return r.stop(ctx, plan)
}

func (r *DockerRuntime) stop(ctx context.Context, plan CleanupPlan) error {
	instanceID := plan.InstanceID
	if plan.LayerPath == "" {
		r.mu.Lock()
		plan.LayerPath = r.layers[instanceID]
		r.mu.Unlock()
		if plan.LayerPath == "" {
			var pathErr error
			plan.LayerPath, pathErr = r.layerPath(instanceID)
			if pathErr != nil {
				return pathErr
			}
		}
		plan.LayerRoot = filepath.Dir(plan.LayerPath)
	}
	if err := validateCleanupLayer(plan, true); err != nil {
		return err
	}
	binary := r.Binary
	if binary == "" {
		binary = "docker"
	}
	out, err := exec.CommandContext(ctx, binary, "stop", instanceID).CombinedOutput()
	removing := err != nil && containerRemovalInProgress(out)
	if err != nil && !containerNotFound(out) && !removing {
		return fmt.Errorf("docker stop: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if err == nil || removing {
		if err := waitForContainerRemoval(ctx, binary, instanceID); err != nil {
			return err
		}
	}
	layerPath := plan.LayerPath
	if layerPath != "" {
		if removeErr := os.Remove(layerPath); removeErr != nil && !os.IsNotExist(removeErr) {
			return fmt.Errorf("remove verified layer: %w", removeErr)
		}
		r.mu.Lock()
		if r.layers[instanceID] == layerPath {
			delete(r.layers, instanceID)
		}
		r.mu.Unlock()
	}
	return nil
}

func validateCleanupLayer(plan CleanupPlan, allowMissing bool) error {
	if plan.InstanceID == "" || plan.LayerPath == "" || plan.LayerRoot == "" || !filepath.IsAbs(plan.LayerPath) || !filepath.IsAbs(plan.LayerRoot) {
		return fmt.Errorf("invalid persisted cleanup metadata for runtime %q", plan.InstanceID)
	}
	root, err := canonicalDirectory(plan.LayerRoot)
	if err != nil {
		return fmt.Errorf("resolve cleanup ownership root: %w", err)
	}
	path := filepath.Clean(plan.LayerPath)
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == "." || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.Dir(relative) != "." {
		return fmt.Errorf("cleanup layer path for runtime %q is outside its ownership root", plan.InstanceID)
	}
	base := filepath.Base(path)
	legacy := isLegacyLayerBase(base)
	if base != plan.InstanceID+".layer" && !legacy {
		return fmt.Errorf("cleanup layer path for runtime %q has a mismatched filename", plan.InstanceID)
	}
	info, err := os.Lstat(path)
	if err != nil {
		if allowMissing && os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("inspect cleanup layer for runtime %q: %w", plan.InstanceID, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("cleanup layer for runtime %q is not a regular file", plan.InstanceID)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("resolve cleanup layer for runtime %q: %w", plan.InstanceID, err)
	}
	resolvedRelative, err := filepath.Rel(root, resolved)
	if err != nil || resolvedRelative != relative {
		return fmt.Errorf("cleanup layer for runtime %q escapes its ownership root", plan.InstanceID)
	}
	return nil
}

func isLegacyLayerBase(base string) bool {
	if !strings.HasPrefix(base, "verified-") || !strings.HasSuffix(base, ".layer") || len(base) <= len("verified-.layer") {
		return false
	}
	middle := strings.TrimSuffix(strings.TrimPrefix(base, "verified-"), ".layer")
	for _, character := range middle {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9') {
			return false
		}
	}
	return true
}

func legacyLayerFiles(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan legacy cleanup layers: %w", err)
	}
	var paths []string
	for _, entry := range entries {
		if isLegacyLayerBase(entry.Name()) {
			paths = append(paths, filepath.Join(root, entry.Name()))
		}
	}
	return paths, nil
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

// Cleanup retries all endpoint-derived runtime instances still retained by
// this backend. It is a final lab/process ownership sweep, not a substitute
// for normal scheduler deactivation.
func (r *DockerRuntime) Cleanup(ctx context.Context) error {
	r.mu.Lock()
	instanceIDs := make([]string, 0, len(r.layers))
	for instanceID := range r.layers {
		instanceIDs = append(instanceIDs, instanceID)
	}
	r.mu.Unlock()
	var firstErr error
	for _, instanceID := range instanceIDs {
		if err := r.Stop(ctx, instanceID); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
