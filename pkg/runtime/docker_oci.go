// SPDX-License-Identifier: AGPL-3.0-only

package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
)

// Launch is one authorised organic replica start. Manifest has already been
// fetched by ArtifactDigest; the runtime re-verifies every blob it uses.
type Launch struct {
	InstanceID     string
	ArtifactDigest string
	Manifest       artifact.ManifestV2
	Blobs          artifact.BlobOpener
	Workload       protocol.WorkloadV4
	Profile        Profile
}

// Started describes a running replica and the image identity it runs.
type Started struct {
	Instance Instance
	// LoadedImageConfigDigest is set only after the engine's loaded image was
	// proven to be Manifest.Config (directly or via the OCI manifest digest).
	LoadedImageConfigDigest string
	ImageReadyAt            time.Time
}

// Stopper is the cleanup capability shared by every runtime backend.
type Stopper interface {
	Stop(ctx context.Context, instanceID string) error
}

// OCIRuntime runs organic OCI images. Launch must create the replica at
// l.InstanceID; on error the caller cleans up that deterministic identity
// through StopCleanup, exactly as for runtime creation today. Running
// reports whether the replica's process is still alive.
type OCIRuntime interface {
	Stopper
	Launch(ctx context.Context, l Launch) (Started, error)
	Running(ctx context.Context, instanceID string) (bool, error)
}

const (
	DefaultOrganicNetwork = "misscomputer-organic"
	DefaultOrganicBridge  = "miss-organic0"
	imageMarkerName       = "image.json"
	maxDockerOutputBytes  = 16 << 10
)

// DockerOCIRuntime materialises verified OCI layouts, loads them into the
// local Docker engine, and runs them with the small-v1 isolation profile on
// an internal, inter-container-isolated bridge network. The agent reaches
// the app at the container IP; containers have no route off the network.
type DockerOCIRuntime struct {
	Binary   string
	StateDir string
	Network  string
	// Bridge is the fixed host interface name of Network, used to deny
	// container-initiated connections to host addresses.
	Bridge string
	// IPTables is the iptables binary for host isolation.
	IPTables string

	mu     sync.Mutex
	images map[string]*sync.Mutex
}

func NewDockerOCIRuntime(binary, stateDir, network, bridge string) *DockerOCIRuntime {
	return &DockerOCIRuntime{Binary: binary, StateDir: stateDir, Network: network, Bridge: bridge}
}

func (r *DockerOCIRuntime) binary() string {
	if r.Binary == "" {
		return "docker"
	}
	return r.Binary
}

func (r *DockerOCIRuntime) stateRoot() (string, error) {
	root := r.StateDir
	if root == "" {
		root = filepath.Join(os.TempDir(), "misscomputer-oci")
	}
	return canonicalDirectory(root)
}

func (r *DockerOCIRuntime) instanceDir(instanceID string) (string, string, error) {
	if err := validInstanceID(instanceID); err != nil {
		return "", "", err
	}
	root, err := r.stateRoot()
	if err != nil {
		return "", "", fmt.Errorf("resolve runtime state directory: %w", err)
	}
	return filepath.Join(root, instanceID+".oci"), root, nil
}

// PlanCleanup returns the deterministic container name and per-instance
// state directory that the agent persists before Launch.
func (r *DockerOCIRuntime) PlanCleanup(endpointID string) (CleanupPlan, error) {
	instanceID := InstanceName(endpointID)
	dir, root, err := r.instanceDir(instanceID)
	if err != nil {
		return CleanupPlan{}, err
	}
	return CleanupPlan{InstanceID: instanceID, LayerPath: dir, LayerRoot: root}, nil
}

type imageMarker struct {
	ArtifactDigest string `json:"artifact_digest"`
	RefName        string `json:"ref_name"`
}

// Launch runs the complete fetch → verify → load → identity → run sequence.
func (r *DockerOCIRuntime) Launch(ctx context.Context, l Launch) (Started, error) {
	if r.Network == "" {
		return Started{}, Fail(CodeInternal, errors.New("organic runtime network is not configured"))
	}
	if l.Blobs == nil {
		return Started{}, Fail(CodeInternal, errors.New("artifact blob store is not streaming-capable"))
	}
	if l.Profile != SmallV1 || l.Workload.RuntimeProfile != SmallV1.Name {
		return Started{}, Fail(CodeInternal, fmt.Errorf("unsupported runtime profile %q", l.Profile.Name))
	}
	dir, root, err := r.instanceDir(l.InstanceID)
	if err != nil {
		return Started{}, Fail(CodeInternal, err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return Started{}, Fail(localCode(err), fmt.Errorf("create runtime state directory: %w", err))
	}
	layout, err := artifact.MaterializeOCILayout(ctx, l.Blobs, l.ArtifactDigest, l.Manifest, dir)
	if err != nil {
		if ctx.Err() != nil {
			return Started{}, ctx.Err()
		}
		switch {
		case artifact.IsVerifyError(err):
			return Started{}, Fail(CodeArtifactVerifyFailed, err)
		case errors.Is(err, syscall.ENOSPC):
			return Started{}, Fail(CodeResourceExhausted, err)
		case errors.Is(err, os.ErrExist):
			return Started{}, Fail(CodeInternal, fmt.Errorf("runtime instance %q already exists", l.InstanceID))
		}
		return Started{}, Fail(CodeArtifactFetchFailed, err)
	}
	marker, err := json.Marshal(imageMarker{ArtifactDigest: l.ArtifactDigest, RefName: layout.RefName})
	if err != nil {
		return Started{}, Fail(CodeInternal, err)
	}
	// Record the image reference before loading so cleanup after any crash
	// can release it.
	if err := os.WriteFile(filepath.Join(dir, imageMarkerName), marker, 0o600); err != nil {
		return Started{}, Fail(localCode(err), err)
	}

	lock := r.imageLock(l.ArtifactDigest)
	lock.Lock()
	defer lock.Unlock()
	if err := r.load(ctx, layout); err != nil {
		return Started{}, err
	}
	imageID, err := r.verifyLoaded(ctx, layout)
	if err != nil {
		return Started{}, err
	}
	readyAt := time.Now().UTC()
	if err := layout.DiscardBlobs(); err != nil {
		return Started{}, Fail(CodeInternal, fmt.Errorf("discard verified layout: %w", err))
	}
	if out, err := r.run(ctx, l, imageID); err != nil {
		if ctx.Err() != nil {
			return Started{}, ctx.Err()
		}
		code := CodeContainerCreateFailed
		if strings.Contains(strings.ToLower(string(out)), "no space left") {
			code = CodeResourceExhausted
		}
		return Started{}, Fail(code, fmt.Errorf("docker run: %w: %s", err, boundedOutput(out)))
	}
	ip, err := r.containerIP(ctx, l.InstanceID)
	if err != nil {
		return Started{}, Fail(CodeContainerCreateFailed, err)
	}
	return Started{
		Instance:                Instance{ID: l.InstanceID, URL: "http://" + ip + ":" + strconv.Itoa(l.Workload.ContainerPort)},
		LoadedImageConfigDigest: l.Manifest.Config.Digest,
		ImageReadyAt:            readyAt,
	}, nil
}

// runArgs is the exact small-v1 container specification (contract §7.1).
func (r *DockerOCIRuntime) runArgs(l Launch, imageID string) []string {
	p := l.Profile
	port := strconv.Itoa(l.Workload.ContainerPort)
	return []string{
		"run", "--detach", "--rm", "--pull", "never", "--platform", p.Platform,
		"--name", l.InstanceID,
		"--network", r.Network,
		"--cpus", fmt.Sprintf("%.3f", float64(p.Resources.CPUMillis)/1000),
		"--memory", fmt.Sprintf("%dm", p.Resources.MemoryMB),
		"--memory-swap", fmt.Sprintf("%dm", p.Resources.MemoryMB),
		"--pids-limit", strconv.Itoa(p.Resources.PIDs),
		"--read-only",
		"--tmpfs", fmt.Sprintf("/tmp:rw,noexec,nosuid,size=%dm", p.Resources.TmpfsMB),
		"--user", p.User,
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--ipc", "private",
		"--log-driver", "json-file",
		"--log-opt", "max-size=" + p.LogMaxSize,
		"--log-opt", "max-file=" + strconv.Itoa(p.LogMaxFile),
		"--env", "PORT=" + port,
		"--env", "HOST=0.0.0.0",
		imageID,
	}
}

func (r *DockerOCIRuntime) run(ctx context.Context, l Launch, imageID string) ([]byte, error) {
	return exec.CommandContext(ctx, r.binary(), r.runArgs(l, imageID)...).CombinedOutput()
}

func (r *DockerOCIRuntime) load(ctx context.Context, layout artifact.Layout) error {
	cmd := exec.CommandContext(ctx, r.binary(), "load", "--quiet")
	reader, writer := io.Pipe()
	cmd.Stdin = reader
	var output bytes.Buffer
	cmd.Stdout = &limitedBuffer{buffer: &output, limit: maxDockerOutputBytes}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return Fail(CodeImageLoadFailed, fmt.Errorf("start docker load: %w", err))
	}
	archiveErr := make(chan error, 1)
	go func() {
		err := layout.WriteTar(writer)
		writer.CloseWithError(err)
		archiveErr <- err
	}()
	waitErr := cmd.Wait()
	reader.Close()
	tarErr := <-archiveErr
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if tarErr != nil && !errors.Is(tarErr, io.ErrClosedPipe) {
		return Fail(localCode(tarErr), fmt.Errorf("stream OCI layout: %w", tarErr))
	}
	if waitErr != nil {
		code := CodeImageLoadFailed
		if strings.Contains(strings.ToLower(output.String()), "no space left") {
			code = CodeResourceExhausted
		}
		return Fail(code, fmt.Errorf("docker load: %w: %s", waitErr, boundedOutput(output.Bytes())))
	}
	return nil
}

// verifyLoaded proves the engine's image for the layout reference is the
// verified image. The classic image store reports the config digest as the
// image ID; the containerd image store reports the manifest digest. Both
// bind exactly the verified config, so either is accepted and any other ID
// is an identity mismatch.
func (r *DockerOCIRuntime) verifyLoaded(ctx context.Context, layout artifact.Layout) (string, error) {
	out, err := exec.CommandContext(ctx, r.binary(), "image", "inspect", "--format", "{{.Id}} {{.Os}} {{.Architecture}}", layout.RefName).CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", Fail(CodeImageLoadFailed, fmt.Errorf("inspect loaded image: %w: %s", err, boundedOutput(out)))
	}
	fields := strings.Fields(string(out))
	if len(fields) != 3 {
		return "", Fail(CodeImageIdentityMismatch, errors.New("loaded image inspection is malformed"))
	}
	if fields[1] != "linux" || fields[2] != "amd64" {
		return "", Fail(CodeImageIdentityMismatch, fmt.Errorf("loaded image platform %s/%s", fields[1], fields[2]))
	}
	if fields[0] != layout.ConfigDigest && fields[0] != layout.ManifestDigest {
		return "", Fail(CodeImageIdentityMismatch, fmt.Errorf("loaded image %s is neither config %s nor manifest %s", fields[0], layout.ConfigDigest, layout.ManifestDigest))
	}
	return fields[0], nil
}

func (r *DockerOCIRuntime) containerIP(ctx context.Context, instanceID string) (string, error) {
	out, err := exec.CommandContext(ctx, r.binary(), "inspect", "--format", "{{json .NetworkSettings.Networks}}", instanceID).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("inspect container network: %w: %s", err, boundedOutput(out))
	}
	var networks map[string]struct {
		IPAddress string `json:"IPAddress"`
	}
	if err := json.Unmarshal(out, &networks); err != nil {
		return "", fmt.Errorf("decode container networks: %w", err)
	}
	if len(networks) != 1 || networks[r.Network].IPAddress == "" {
		return "", fmt.Errorf("container is not attached only to %s", r.Network)
	}
	return networks[r.Network].IPAddress, nil
}

// Running reports whether the container process is alive. With --rm an
// exited container disappears, which also reports false.
func (r *DockerOCIRuntime) Running(ctx context.Context, instanceID string) (bool, error) {
	out, err := exec.CommandContext(ctx, r.binary(), "inspect", "--format", "{{.State.Running}}", instanceID).CombinedOutput()
	if err != nil {
		if containerNotFound(out) {
			return false, nil
		}
		return false, fmt.Errorf("inspect container state: %w: %s", err, boundedOutput(out))
	}
	return strings.TrimSpace(string(out)) == "true", nil
}

func (r *DockerOCIRuntime) Stop(ctx context.Context, instanceID string) error {
	dir, root, err := r.instanceDir(instanceID)
	if err != nil {
		return err
	}
	return r.StopCleanup(ctx, CleanupPlan{InstanceID: instanceID, LayerPath: dir, LayerRoot: root})
}

// StopCleanup removes the container, releases the image when no other
// container on this engine uses it, and deletes the instance state. Every
// step is idempotent so a failed attempt can be retried after restart.
func (r *DockerOCIRuntime) StopCleanup(ctx context.Context, plan CleanupPlan) error {
	if err := validateInstanceDir(plan); err != nil {
		return err
	}
	marker, err := readImageMarker(plan.LayerPath)
	if err != nil {
		return err
	}
	if err := r.removeContainer(ctx, plan.InstanceID); err != nil {
		return err
	}
	if marker != nil {
		if err := r.releaseImage(ctx, *marker); err != nil {
			return err
		}
	}
	if err := os.RemoveAll(plan.LayerPath); err != nil {
		return fmt.Errorf("remove runtime instance state: %w", err)
	}
	return nil
}

func (r *DockerOCIRuntime) removeContainer(ctx context.Context, instanceID string) error {
	out, err := exec.CommandContext(ctx, r.binary(), "rm", "--force", instanceID).CombinedOutput()
	if err == nil || containerNotFound(out) {
		return waitForContainerRemoval(ctx, r.binary(), instanceID)
	}
	if containerRemovalInProgress(out) {
		return waitForContainerRemoval(ctx, r.binary(), instanceID)
	}
	return fmt.Errorf("docker rm: %w: %s", err, boundedOutput(out))
}

// releaseImage removes the artifact's local reference only when no other
// container was created from it. The per-artifact lock orders this against
// a concurrent Launch between load and container creation.
func (r *DockerOCIRuntime) releaseImage(ctx context.Context, marker imageMarker) error {
	if marker.RefName != artifact.LayoutRefName(marker.ArtifactDigest) {
		return fmt.Errorf("runtime image marker is inconsistent")
	}
	lock := r.imageLock(marker.ArtifactDigest)
	lock.Lock()
	defer lock.Unlock()
	out, err := exec.CommandContext(ctx, r.binary(), "ps", "--all", "--quiet", "--filter", "ancestor="+marker.RefName).CombinedOutput()
	if err != nil {
		if imageNotFound(out) {
			return nil
		}
		return fmt.Errorf("list image users: %w: %s", err, boundedOutput(out))
	}
	if strings.TrimSpace(string(out)) != "" {
		return nil
	}
	out, err = exec.CommandContext(ctx, r.binary(), "image", "rm", marker.RefName).CombinedOutput()
	if err != nil && !imageNotFound(out) && !imageInUse(out) {
		return fmt.Errorf("docker image rm: %w: %s", err, boundedOutput(out))
	}
	return nil
}

func (r *DockerOCIRuntime) imageLock(artifactDigest string) *sync.Mutex {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.images == nil {
		r.images = make(map[string]*sync.Mutex)
	}
	lock := r.images[artifactDigest]
	if lock == nil {
		lock = &sync.Mutex{}
		r.images[artifactDigest] = lock
	}
	return lock
}

// EnsureNetwork creates or validates the organic network: a bridge that is
// internal (no route off the host), with inter-container communication
// disabled and a fixed host interface name.
func (r *DockerOCIRuntime) EnsureNetwork(ctx context.Context) error {
	if r.Network == "" || r.Bridge == "" || len(r.Bridge) > 15 {
		return errors.New("organic runtime network and a bridge name of at most 15 characters are required")
	}
	format := `{{.Driver}} {{.Internal}} {{.EnableIPv6}} {{index .Options "com.docker.network.bridge.enable_icc"}} {{index .Options "com.docker.network.bridge.name"}}`
	out, err := exec.CommandContext(ctx, r.binary(), "network", "inspect", "--format", format, r.Network).CombinedOutput()
	if err != nil {
		if !strings.Contains(strings.ToLower(string(out)), "not found") {
			return fmt.Errorf("inspect organic network: %w: %s", err, boundedOutput(out))
		}
		create := exec.CommandContext(ctx, r.binary(), "network", "create", "--driver", "bridge", "--internal",
			"--opt", "com.docker.network.bridge.enable_icc=false",
			"--opt", "com.docker.network.bridge.name="+r.Bridge, r.Network)
		if out, err := create.CombinedOutput(); err != nil {
			return fmt.Errorf("create organic network: %w: %s", err, boundedOutput(out))
		}
		out, err = exec.CommandContext(ctx, r.binary(), "network", "inspect", "--format", format, r.Network).CombinedOutput()
		if err != nil {
			return fmt.Errorf("inspect organic network: %w: %s", err, boundedOutput(out))
		}
	}
	want := "bridge true false false " + r.Bridge
	if got := strings.TrimSpace(string(out)); got != want {
		return fmt.Errorf("organic network %s is %q, want %q", r.Network, got, want)
	}
	return nil
}

// HostIsolationRule is the iptables INPUT rule that drops connections a
// container initiates to any host address on the organic bridge. Replies to
// host-initiated health and proxy connections remain allowed by conntrack.
func (r *DockerOCIRuntime) HostIsolationRule() []string {
	return []string{"INPUT", "-i", r.Bridge, "-m", "conntrack", "--ctstate", "NEW", "-j", "DROP"}
}

// EnsureHostIsolation checks for, and when enforce is set installs, the
// HostIsolationRule. The internal network already removes every route off
// the host; this closes the remaining path to host services via the bridge
// gateway address.
func (r *DockerOCIRuntime) EnsureHostIsolation(ctx context.Context, enforce bool) error {
	binary := r.IPTables
	if binary == "" {
		binary = findIPTables()
	}
	rule := r.HostIsolationRule()
	check := append([]string{"-C"}, rule...)
	if out, err := exec.CommandContext(ctx, binary, check...).CombinedOutput(); err == nil {
		return nil
	} else if !enforce {
		return fmt.Errorf("host isolation rule is missing (iptables -I %s): %s", strings.Join(rule, " "), boundedOutput(out))
	}
	insert := append([]string{"-I", rule[0], "1"}, rule[1:]...)
	if out, err := exec.CommandContext(ctx, binary, insert...).CombinedOutput(); err != nil {
		return fmt.Errorf("install host isolation rule: %w: %s", err, boundedOutput(out))
	}
	return nil
}

func findIPTables() string {
	if path, err := exec.LookPath("iptables"); err == nil {
		return path
	}
	for _, candidate := range []string{"/usr/sbin/iptables", "/sbin/iptables"} {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return "iptables"
}

func readImageMarker(dir string) (*imageMarker, error) {
	data, err := os.ReadFile(filepath.Join(dir, imageMarkerName))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read runtime image marker: %w", err)
	}
	var marker imageMarker
	if err := json.Unmarshal(data, &marker); err != nil {
		return nil, fmt.Errorf("decode runtime image marker: %w", err)
	}
	return &marker, nil
}

func validateInstanceDir(plan CleanupPlan) error {
	if err := validInstanceID(plan.InstanceID); err != nil {
		return err
	}
	if !filepath.IsAbs(plan.LayerPath) || !filepath.IsAbs(plan.LayerRoot) {
		return fmt.Errorf("invalid persisted cleanup metadata for runtime %q", plan.InstanceID)
	}
	root, err := canonicalDirectory(plan.LayerRoot)
	if err != nil {
		return fmt.Errorf("resolve cleanup ownership root: %w", err)
	}
	if filepath.Clean(plan.LayerPath) != filepath.Join(root, plan.InstanceID+".oci") {
		return fmt.Errorf("cleanup state for runtime %q is not its exact instance directory", plan.InstanceID)
	}
	info, err := os.Lstat(plan.LayerPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect cleanup state for runtime %q: %w", plan.InstanceID, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("cleanup state for runtime %q is not a directory", plan.InstanceID)
	}
	return nil
}

func validInstanceID(instanceID string) error {
	if instanceID == "" || instanceID == "." || instanceID == ".." {
		return fmt.Errorf("invalid runtime instance identity %q", instanceID)
	}
	for _, char := range instanceID {
		if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '_' || char == '.' || char == '-') {
			return fmt.Errorf("invalid runtime instance identity %q", instanceID)
		}
	}
	return nil
}

func localCode(err error) FailureCode {
	if errors.Is(err, syscall.ENOSPC) {
		return CodeResourceExhausted
	}
	return CodeInternal
}

func imageNotFound(output []byte) bool {
	message := strings.ToLower(string(output))
	return strings.Contains(message, "no such image") || strings.Contains(message, "image not known") ||
		(strings.Contains(message, "not found") && strings.Contains(message, "image"))
}

func imageInUse(output []byte) bool {
	message := strings.ToLower(string(output))
	return strings.Contains(message, "conflict") && strings.Contains(message, "container")
}

func boundedOutput(output []byte) string {
	text := strings.TrimSpace(string(output))
	if len(text) > 512 {
		text = text[:512] + "..."
	}
	return text
}

type limitedBuffer struct {
	buffer *bytes.Buffer
	limit  int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if remaining := b.limit - b.buffer.Len(); remaining > 0 {
		if len(p) > remaining {
			b.buffer.Write(p[:remaining])
		} else {
			b.buffer.Write(p)
		}
	}
	return len(p), nil
}
