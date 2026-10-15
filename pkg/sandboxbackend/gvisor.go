// SPDX-License-Identifier: AGPL-3.0-only

// Package sandboxbackend implements miner.SandboxBackend: sandbox-lease-v1
// sandboxes run under a pinned gVisor (runsc) runtime on a Docker daemon
// dedicated to them (docs/miner-sandbox-gvisor-backend.md). Every host
// property the backend relies on is checked when it opens, and every
// container it starts is inspected for the enforced limits before Create
// reports success; nothing falls back to runc or to another daemon.
package sandboxbackend

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/miner"
	"github.com/misscomputer/misscomputer-subnet/pkg/netpolicy"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	"github.com/misscomputer/misscomputer-subnet/pkg/sandbox"
	"golang.org/x/sys/unix"
)

// PinnedDockerVersion is the only Docker server version the backend runs
// on: the version the disposable gVisor gate (docs/gvisor-disposable-gate.md)
// proved the runsc writable-layer quota with.
const PinnedDockerVersion = "28.0.4"

// Container labels. Every sandbox container carries them; the lease ID label
// ties a container to its durable lease for orphan reconciliation.
const (
	LabelSandbox     = "computer.miss.sandbox"
	LabelLeaseID     = "computer.miss.sandbox.lease-id"
	LabelLeaseDigest = "computer.miss.sandbox.lease-digest"
	LabelImageDigest = "computer.miss.sandbox.image-digest"
	LabelImageID     = "computer.miss.sandbox.image-id"
	sandboxLabelV1   = "v1"
)

// Runtime arguments the backend admits on the runsc registration. The
// writable-layer quota holds only with --overlay2=none and --systemd-cgroup
// (docs/gvisor-disposable-gate.md), so both are required; any other
// argument could weaken isolation (host networking, host UDS or FIFO
// access, device proxies, unsafe test flags) and is refused.
var (
	requiredRuntimeArgs = []string{"--overlay2=none", "--systemd-cgroup"}
	allowedRuntimeArgs  = map[string]bool{
		"--overlay2=none": true, "--systemd-cgroup": true, "--platform=systrap": true, "--platform=kvm": true,
	}
)

// sandboxCapabilities is the complete capability set of a sandbox's
// processes inside the gVisor sentry. It is empty: any capability needs a
// security review before it is added here and to the backend document.
var sandboxCapabilities = []string{}

const (
	cgroupFSMagic   = 0x63677270
	logFiles        = 2
	sandboxHostname = "sandbox"
	removalTimeout  = 2 * time.Minute
	pullAttempts    = 3
)

var (
	slicePattern  = regexp.MustCompile(`^[A-Za-z0-9_]+(?:-[A-Za-z0-9_]+)*\.slice$`)
	sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Config is the operator configuration of the backend. Every member is
// trusted configuration; Open verifies each against the host before the
// backend is usable.
type Config struct {
	// DockerHost is unix://<absolute socket path> of the dedicated daemon.
	// The default daemon socket is refused.
	DockerHost string
	// Runtime is the name the daemon registers runsc under.
	Runtime string
	// RunscPath and RunscSHA256 pin the runsc binary. SentryPath and
	// SentrySHA256 pin the sentry binary that releases which exec a
	// separate sentry run as the sandbox process; when empty, the sandbox
	// process must be runsc itself.
	RunscPath, RunscSHA256   string
	SentryPath, SentrySHA256 string
	// DataRoot is the daemon's data root: a filesystem dedicated to it whose
	// size covers DiskMiB plus every sandbox's image and log allowance.
	DataRoot string
	// Slice is the systemd slice every sandbox runs in (the --cgroup-parent);
	// its cgroup v2 directory must have finite cpu.max, memory.max and
	// pids.max.
	Slice string
	// CgroupRoot is the cgroup v2 mount and ProcRoot the procfs of the
	// daemon's PID namespace; both default to the host paths.
	CgroupRoot, ProcRoot string
	// DiskMiB is the writable-layer budget of all sandboxes together and
	// Sandboxes their count limit.
	DiskMiB, Sandboxes int
	// ImageMaxMiB bounds the stored size of one sandbox's image and LogMiB
	// its container log; both are reserved on the data root per sandbox.
	ImageMaxMiB, LogMiB int
}

// GVisor is the gVisor-on-dedicated-Docker sandbox backend.
type GVisor struct {
	config      Config
	engine      *engine
	sliceCgroup string
	slicePIDs   int
	// sandboxExe is the resolved path of the binary every sandbox process
	// must execute: the sentry, or runsc when no sentry is configured, and
	// sandboxFile the file Open hashed there, so that a binary replaced or
	// rewritten after Open is not accepted by path.
	sandboxExe  string
	sandboxFile fs.FileInfo
	// runscFile is the runsc binary Open hashed; with sandboxFile it
	// identifies runtime processes by file, not by name.
	runscFile fs.FileInfo
	// lookup resolves a registry host before any pull.
	lookup func(ctx context.Context, host string) ([]netip.Addr, error)
	// hostAddresses lists the addresses assigned to this host's
	// interfaces; Open sets interfaceAddresses.
	hostAddresses func() ([]netip.Addr, error)
	// localReserve is the part of the create budget the steps after a pull
	// run under; zero means localStepReserve (contract D15(d)).
	localReserve time.Duration
	mu           sync.Mutex
	images       map[string]*imageLock
	// startSlot admits one sandbox at a time from its start through its
	// verification, so a sandbox whose workload exited is never checked
	// while another is starting and has processes the engine does not yet
	// report (contract D11-C1 under concurrency, SR-26-16/INT-26-13).
	startSlot chan struct{}
	// cgroups records, per instance, the cgroup the kernel readback found
	// its process in. It keeps an instance's cgroup attributed to it while
	// its workload winds down or its container is removed.
	cgroups map[string]string
}

type imageLock struct {
	mu   sync.Mutex
	refs int
}

var _ miner.SandboxBackend = (*GVisor)(nil)

// Open validates config against the host and the daemon and returns the
// backend. It changes nothing on the host. Every failure refuses the
// backend: a property that cannot be verified is not enforced.
func Open(ctx context.Context, config Config) (*GVisor, error) {
	if config.CgroupRoot == "" {
		config.CgroupRoot = miner.DefaultCgroupRoot
	}
	if config.ProcRoot == "" {
		config.ProcRoot = "/proc"
	}
	socket, err := dedicatedSocket(config.DockerHost)
	if err != nil {
		return nil, err
	}
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	sliceCgroup, err := SliceCgroup(config.Slice)
	if err != nil {
		return nil, err
	}
	file, err := verifyBinary(config.RunscPath, config.RunscSHA256)
	if err != nil {
		return nil, err
	}
	runscFile := file
	if config.SentryPath != "" {
		if file, err = verifyBinary(config.SentryPath, config.SentrySHA256); err != nil {
			return nil, err
		}
	}
	exe := config.RunscPath
	if config.SentryPath != "" {
		exe = config.SentryPath
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return nil, err
	}
	b := &GVisor{config: config, engine: newEngine(socket), sliceCgroup: sliceCgroup, sandboxExe: exe, sandboxFile: file, runscFile: runscFile, lookup: lookupHost, hostAddresses: interfaceAddresses}
	if err := b.verifyDaemon(ctx); err != nil {
		return nil, err
	}
	if err := b.verifyDataRoot(); err != nil {
		return nil, err
	}
	if b.slicePIDs, err = b.verifySlice(); err != nil {
		return nil, err
	}
	return b, nil
}

func validateConfig(c Config) error {
	if c.Runtime == "" || c.Runtime == "runc" {
		return errors.New("sandbox runtime must name the registered runsc runtime")
	}
	if !filepath.IsAbs(c.RunscPath) || filepath.Clean(c.RunscPath) != c.RunscPath || !sha256Pattern.MatchString(c.RunscSHA256) {
		return errors.New("runsc path must be a clean absolute path pinned by a lowercase SHA-256")
	}
	if (c.SentryPath == "") != (c.SentrySHA256 == "") {
		return errors.New("sentry path and sentry SHA-256 are configured together")
	}
	if c.SentryPath != "" && (!filepath.IsAbs(c.SentryPath) || filepath.Clean(c.SentryPath) != c.SentryPath || !sha256Pattern.MatchString(c.SentrySHA256)) {
		return errors.New("sentry path must be a clean absolute path pinned by a lowercase SHA-256")
	}
	if !filepath.IsAbs(c.DataRoot) || filepath.Clean(c.DataRoot) != c.DataRoot || c.DataRoot == "/" {
		return errors.New("sandbox data root must be a clean absolute path other than /")
	}
	if !filepath.IsAbs(c.CgroupRoot) || !filepath.IsAbs(c.ProcRoot) {
		return errors.New("cgroup and proc roots must be absolute")
	}
	if c.DiskMiB <= 0 || c.Sandboxes <= 0 || c.ImageMaxMiB <= 0 || c.LogMiB < logFiles {
		return fmt.Errorf("sandbox disk, count and image limits must be positive and the log limit at least %d MiB", logFiles)
	}
	return nil
}

// dedicatedSocket accepts only unix://<absolute path> naming a socket other
// than the default daemon's, after resolving symlinks.
func dedicatedSocket(host string) (string, error) {
	socket, ok := strings.CutPrefix(host, "unix://")
	if !ok || !filepath.IsAbs(socket) || filepath.Clean(socket) != socket {
		return "", errors.New("sandbox docker host must be unix://<absolute socket path>")
	}
	resolved, err := filepath.EvalSymlinks(socket)
	if err != nil {
		return "", fmt.Errorf("sandbox docker socket: %w", err)
	}
	for _, shared := range []string{"/var/run/docker.sock", "/run/docker.sock"} {
		if other, err := filepath.EvalSymlinks(shared); (err == nil && other == resolved) || resolved == shared {
			return "", fmt.Errorf("sandbox docker socket %s is the default daemon's; sandboxes need a dedicated daemon", socket)
		}
	}
	return resolved, nil
}

// SliceCgroup is the cgroup v2 path systemd gives slice: "a-b.slice" lives
// at "/a.slice/a-b.slice".
func SliceCgroup(slice string) (string, error) {
	if !slicePattern.MatchString(slice) || slice == "-.slice" {
		return "", fmt.Errorf("sandbox slice %q is not a systemd slice unit name", slice)
	}
	parts := strings.Split(strings.TrimSuffix(slice, ".slice"), "-")
	cgroup := ""
	for index := range parts {
		cgroup += "/" + strings.Join(parts[:index+1], "-") + ".slice"
	}
	return cgroup, nil
}

// verifyBinary hashes file without following a final symlink and returns
// the identity of the file it hashed.
func verifyBinary(file, want string) (fs.FileInfo, error) {
	fd, err := unix.Open(file, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open pinned binary %s: %w", file, err)
	}
	handle := os.NewFile(uintptr(fd), file)
	defer handle.Close()
	info, err := handle.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("pinned binary %s is not a regular file", file)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, handle); err != nil {
		return nil, fmt.Errorf("hash pinned binary %s: %w", file, err)
	}
	if got := hex.EncodeToString(hash.Sum(nil)); got != want {
		return nil, fmt.Errorf("binary %s has SHA-256 %s, pinned %s", file, got, want)
	}
	return info, nil
}

type daemonInfo struct {
	DockerRootDir string `json:"DockerRootDir"`
	Driver        string `json:"Driver"`
	// DriverStatus is the storage driver's [name, value] pairs.
	DriverStatus  [][]string `json:"DriverStatus"`
	CgroupDriver  string     `json:"CgroupDriver"`
	CgroupVersion string     `json:"CgroupVersion"`
	Runtimes      map[string]struct {
		Path        string   `json:"path"`
		RuntimeArgs []string `json:"runtimeArgs"`
	} `json:"Runtimes"`
	RegistryConfig struct {
		InsecureRegistryCIDRs []string `json:"InsecureRegistryCIDRs"`
		IndexConfigs          map[string]struct {
			Secure  bool     `json:"Secure"`
			Mirrors []string `json:"Mirrors"`
		} `json:"IndexConfigs"`
		Mirrors []string `json:"Mirrors"`
	} `json:"RegistryConfig"`
	Containerd *struct {
		Address    string `json:"Address"`
		Namespaces struct {
			Containers string `json:"Containers"`
			Plugins    string `json:"Plugins"`
		} `json:"Namespaces"`
	} `json:"Containerd"`
}

func (b *GVisor) verifyDaemon(ctx context.Context) error {
	var version struct {
		Version string `json:"Version"`
	}
	if err := b.engine.call(ctx, http.MethodGet, "/version", nil, nil, &version); err != nil {
		return fmt.Errorf("sandbox docker daemon: %w", err)
	}
	if version.Version != PinnedDockerVersion {
		return fmt.Errorf("sandbox docker daemon is %q; only %s is reviewed", version.Version, PinnedDockerVersion)
	}
	var info daemonInfo
	if err := b.engine.call(ctx, http.MethodGet, "/info", nil, nil, &info); err != nil {
		return fmt.Errorf("sandbox docker daemon info: %w", err)
	}
	if info.DockerRootDir != b.config.DataRoot || info.Driver != "overlay2" || info.CgroupDriver != "systemd" || info.CgroupVersion != "2" {
		return fmt.Errorf("sandbox docker daemon root=%q storage=%q cgroup=%q/v%s, want root=%q overlay2 systemd/v2",
			info.DockerRootDir, info.Driver, info.CgroupDriver, info.CgroupVersion, b.config.DataRoot)
	}
	if driver := driverStatus(info); driver["Backing Filesystem"] != "xfs" || driver["Supports d_type"] != "true" {
		return fmt.Errorf("sandbox docker daemon overlay2 is backed by %q with d_type %q, want xfs with d_type",
			driver["Backing Filesystem"], driver["Supports d_type"])
	}
	if err := verifyContainerd(info); err != nil {
		return err
	}
	if err := verifyRegistryConfig(info); err != nil {
		return err
	}
	var networks []struct {
		Name   string `json:"Name"`
		Driver string `json:"Driver"`
	}
	if err := b.engine.call(ctx, http.MethodGet, "/networks", nil, nil, &networks); err != nil {
		return fmt.Errorf("list sandbox daemon networks: %w", err)
	}
	for _, network := range networks {
		if !(network.Name == "none" && network.Driver == "null") && !(network.Name == "host" && network.Driver == "host") {
			return fmt.Errorf("sandbox docker daemon manages network %q (%s); it must run with no bridge and only host and none", network.Name, network.Driver)
		}
	}
	runtime, ok := info.Runtimes[b.config.Runtime]
	if !ok || runtime.Path != b.config.RunscPath {
		return fmt.Errorf("sandbox docker daemon does not register runtime %q at %s", b.config.Runtime, b.config.RunscPath)
	}
	seen := map[string]bool{}
	for _, arg := range runtime.RuntimeArgs {
		if !allowedRuntimeArgs[arg] {
			return fmt.Errorf("runtime %q has unreviewed argument %q", b.config.Runtime, arg)
		}
		seen[arg] = true
	}
	for _, arg := range requiredRuntimeArgs {
		if !seen[arg] {
			return fmt.Errorf("runtime %q lacks required argument %s", b.config.Runtime, arg)
		}
	}
	var containers []listedContainer
	if err := b.engine.call(ctx, http.MethodGet, "/containers/json", url.Values{"all": {"1"}}, nil, &containers); err != nil {
		return fmt.Errorf("list sandbox daemon containers: %w", err)
	}
	for _, container := range containers {
		if container.Labels[LabelSandbox] != sandboxLabelV1 {
			return fmt.Errorf("sandbox docker daemon runs container %s that is not a sandbox; the daemon must be dedicated", container.ID)
		}
	}
	return nil
}

// driverStatus indexes the storage driver's reported [name, value] pairs.
func driverStatus(info daemonInfo) map[string]string {
	status := map[string]string{}
	for _, pair := range info.DriverStatus {
		if len(pair) == 2 {
			status[pair[0]] = pair[1]
		}
	}
	return status
}

// defaultContainerdSockets are the sockets of a host's shared containerd and
// of the containerd a Docker daemon starts for itself.
var defaultContainerdSockets = []string{
	"/run/containerd/containerd.sock", "/var/run/containerd/containerd.sock",
	"/run/docker/containerd/containerd.sock", "/var/run/docker/containerd/containerd.sock",
}

// verifyContainerd requires the daemon to use a containerd of its own: a
// socket other than the shared or daemon-managed default, and namespaces
// other than the default engine's. Where that containerd keeps its data is
// not visible through the Engine API.
func verifyContainerd(info daemonInfo) error {
	c := info.Containerd
	if c == nil || !filepath.IsAbs(c.Address) {
		return errors.New("sandbox docker daemon does not report a dedicated containerd")
	}
	address := filepath.Clean(c.Address)
	if resolved, err := filepath.EvalSymlinks(address); err == nil {
		address = resolved
	}
	for _, shared := range defaultContainerdSockets {
		if resolved, err := filepath.EvalSymlinks(shared); address == shared || (err == nil && resolved == address) {
			return fmt.Errorf("sandbox docker daemon uses the default containerd at %s", c.Address)
		}
	}
	if c.Namespaces.Containers == "" || c.Namespaces.Containers == "moby" || c.Namespaces.Plugins == "" || c.Namespaces.Plugins == "plugins.moby" {
		return errors.New("sandbox docker daemon shares the default engine's containerd namespaces")
	}
	return nil
}

// verifyRegistryConfig requires the daemon to pull only over TLS from the
// registry a reference names: no insecure registry beyond the loopback
// prefixes Docker always lists (publicRegistry refuses loopback hosts), no
// mirror, and Docker Hub as its only, secure index.
func verifyRegistryConfig(info daemonInfo) error {
	registries := info.RegistryConfig
	for _, cidr := range registries.InsecureRegistryCIDRs {
		if cidr != "127.0.0.0/8" && cidr != "::1/128" {
			return fmt.Errorf("sandbox docker daemon trusts insecure registry %s", cidr)
		}
	}
	if len(registries.Mirrors) != 0 {
		return errors.New("sandbox docker daemon pulls through registry mirrors")
	}
	for name, index := range registries.IndexConfigs {
		if name != "docker.io" || !index.Secure || len(index.Mirrors) != 0 {
			return fmt.Errorf("sandbox docker daemon has registry index %q that is insecure, mirrored or not Docker Hub", name)
		}
	}
	return nil
}

// verifyDataRoot requires the data root to be a filesystem with room for
// every sandbox's writable layer, image and logs. Writable layers are
// quota-limited per container (StorageOpt), images by ImageMaxMiB and logs
// by rotation, so the data root cannot outgrow its filesystem.
func (b *GVisor) verifyDataRoot() error {
	var stat unix.Statfs_t
	if err := unix.Statfs(b.config.DataRoot, &stat); err != nil {
		return fmt.Errorf("sandbox data root: %w", err)
	}
	sizeMiB := int64(stat.Blocks) * int64(stat.Bsize) >> 20
	need := int64(b.config.DiskMiB) + int64(b.config.Sandboxes)*int64(b.config.ImageMaxMiB+b.config.LogMiB)
	if need > sizeMiB {
		return fmt.Errorf("sandbox data root holds %d MiB; disk, image and log budgets need %d MiB", sizeMiB, need)
	}
	return nil
}

// verifySlice requires the slice's cgroup directory to be a real cgroup v2
// directory with a finite pids.max. The lane checks its cpu.max and
// memory.max (miner.VerifySandboxCgroup).
func (b *GVisor) verifySlice() (int, error) {
	dir := filepath.Join(b.config.CgroupRoot, b.sliceCgroup)
	var stat unix.Statfs_t
	if err := unix.Statfs(dir, &stat); err != nil {
		return 0, fmt.Errorf("sandbox slice cgroup %s: %w", b.sliceCgroup, err)
	}
	if stat.Type != cgroupFSMagic {
		return 0, fmt.Errorf("sandbox slice %s is not on a cgroup v2 filesystem", b.sliceCgroup)
	}
	value, err := readSmall(filepath.Join(dir, "pids.max"))
	if err != nil {
		return 0, err
	}
	pids, err := strconv.Atoi(value)
	if err != nil || pids <= 0 {
		return 0, fmt.Errorf("sandbox slice pids.max %q is not a finite limit", value)
	}
	return pids, nil
}

// Budget reports the slice cgroup and the disk and count limits.
func (b *GVisor) Budget(context.Context) (miner.SandboxBudget, error) {
	return miner.SandboxBudget{Cgroup: b.sliceCgroup, DiskMiB: b.config.DiskMiB, Sandboxes: b.config.Sandboxes}, nil
}

// Unsupported refuses what this backend cannot enforce exactly: any
// isolation other than gVisor, any network other than none, and a sandbox
// asking for more processes than the whole slice allows.
func (b *GVisor) Unsupported(lease protocol.SandboxLeaseV1) string {
	switch {
	case lease.Isolation != sandbox.IsolationGVisor:
		return "isolation_unsupported"
	case lease.Network.Mode != sandbox.NetworkNone:
		return "network_policy_unsupported"
	case lease.Resources.PIDs > b.slicePIDs:
		return "resources_unsupported"
	}
	return ""
}

type listedContainer struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	Labels map[string]string `json:"Labels"`
}

type inspectedContainer struct {
	ID    string `json:"Id"`
	Name  string `json:"Name"`
	Image string `json:"Image"`
	State struct {
		Status     string `json:"Status"`
		Running    bool   `json:"Running"`
		Pid        int    `json:"Pid"`
		Error      string `json:"Error"`
		StartedAt  string `json:"StartedAt"`
		FinishedAt string `json:"FinishedAt"`
	} `json:"State"`
	Config struct {
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	HostConfig hostConfig `json:"HostConfig"`
	Mounts     []struct {
		Type string `json:"Type"`
	} `json:"Mounts"`
}

type hostConfig struct {
	Runtime         string            `json:"Runtime"`
	NetworkMode     string            `json:"NetworkMode"`
	CgroupParent    string            `json:"CgroupParent"`
	NanoCpus        int64             `json:"NanoCpus"`
	Memory          int64             `json:"Memory"`
	MemorySwap      int64             `json:"MemorySwap"`
	PidsLimit       *int64            `json:"PidsLimit"`
	StorageOpt      map[string]string `json:"StorageOpt"`
	LogConfig       logConfig         `json:"LogConfig"`
	CapDrop         []string          `json:"CapDrop"`
	CapAdd          []string          `json:"CapAdd"`
	SecurityOpt     []string          `json:"SecurityOpt"`
	Privileged      bool              `json:"Privileged"`
	ReadonlyRootfs  bool              `json:"ReadonlyRootfs"`
	IpcMode         string            `json:"IpcMode"`
	PidMode         string            `json:"PidMode"`
	UTSMode         string            `json:"UTSMode"`
	UsernsMode      string            `json:"UsernsMode"`
	CgroupnsMode    string            `json:"CgroupnsMode"`
	PublishAllPorts bool              `json:"PublishAllPorts"`
	PortBindings    map[string]any    `json:"PortBindings"`
	RestartPolicy   struct {
		Name string `json:"Name"`
	} `json:"RestartPolicy"`
	Binds   []string `json:"Binds"`
	Devices []any    `json:"Devices"`
	// Init is set to false; the backend sets none of the rest, and each
	// must stay at its empty default.
	Init              *bool             `json:"Init"`
	Sysctls           map[string]string `json:"Sysctls"`
	Tmpfs             map[string]string `json:"Tmpfs"`
	Annotations       map[string]string `json:"Annotations"`
	DeviceCgroupRules []string          `json:"DeviceCgroupRules"`
	DeviceRequests    []any             `json:"DeviceRequests"`
	VolumesFrom       []string          `json:"VolumesFrom"`
	VolumeDriver      string            `json:"VolumeDriver"`
	Links             []string          `json:"Links"`
	GroupAdd          []string          `json:"GroupAdd"`
	ExtraHosts        []string          `json:"ExtraHosts"`
	DNS               []string          `json:"Dns"`
	DNSOptions        []string          `json:"DnsOptions"`
	DNSSearch         []string          `json:"DnsSearch"`
	OomScoreAdj       int               `json:"OomScoreAdj"`
}

type logConfig struct {
	Type   string            `json:"Type"`
	Config map[string]string `json:"Config"`
}

// spec is the exact container a lease runs as.
type spec struct {
	labels map[string]string
	host   hostConfig
}

func (b *GVisor) spec(lease protocol.SandboxLeaseV1, leaseDigest, imageID string) spec {
	pids := int64(lease.Resources.PIDs)
	memory := int64(lease.Resources.MemoryMiB) << 20
	logSize := b.config.LogMiB / logFiles
	return spec{
		labels: map[string]string{
			LabelSandbox: sandboxLabelV1, LabelLeaseID: protocol.SandboxLeaseIDV1(lease), LabelLeaseDigest: leaseDigest,
			LabelImageDigest: lease.ImageDigest, LabelImageID: imageID,
		},
		host: hostConfig{
			Runtime: b.config.Runtime, NetworkMode: "none", CgroupParent: b.config.Slice,
			NanoCpus: int64(lease.Resources.CPUMillis) * 1_000_000, Memory: memory, MemorySwap: memory, PidsLimit: &pids,
			StorageOpt: map[string]string{"size": strconv.Itoa(lease.Resources.DiskMiB) + "m"},
			LogConfig:  logConfig{Type: "json-file", Config: map[string]string{"max-size": strconv.Itoa(logSize) + "m", "max-file": strconv.Itoa(logFiles)}},
			CapDrop:    []string{"ALL"}, CapAdd: append([]string(nil), sandboxCapabilities...),
			SecurityOpt: []string{"no-new-privileges"}, IpcMode: "private",
			RestartPolicy: struct {
				Name string `json:"Name"`
			}{Name: "no"},
		},
	}
}

// Create starts the sandbox of lease as container instanceID. It is
// idempotent: an existing container with this lease's labels is started if
// needed and verified again. A refusal that is not the miner's fault (an
// image the registry does not serve, or one the backend cannot account
// for) is a *miner.SandboxRefusal.
func (b *GVisor) Create(ctx context.Context, instanceID string, lease protocol.SandboxLeaseV1) error {
	leaseDigest, err := protocol.SandboxDigestV1(lease)
	if err != nil {
		return err
	}
	if code := b.Unsupported(lease); code != "" {
		return &miner.SandboxRefusal{Code: code}
	}
	budget, err := b.newCreateBudget(ctx)
	if err != nil {
		return err
	}
	defer budget.close()
	existing, found, err := b.inspect(budget.local(), instanceID)
	if err != nil {
		return err
	}
	if !found {
		if err := b.createContainer(budget, instanceID, lease, leaseDigest); err != nil {
			return err
		}
	}
	// Every step from here runs under the local deadline that started when
	// the last pull returned (or at the start, without a pull).
	ctx = budget.local()
	if !found {
		if existing, found, err = b.inspect(ctx, instanceID); err != nil {
			return err
		} else if !found {
			return fmt.Errorf("sandbox %s vanished after creation", instanceID)
		}
	}
	if existing.Config.Labels[LabelLeaseID] != protocol.SandboxLeaseIDV1(lease) || existing.Config.Labels[LabelLeaseDigest] != leaseDigest {
		return fmt.Errorf("container %s exists for another lease", instanceID)
	}
	release, err := b.acquireStart(ctx)
	if err != nil {
		return err
	}
	defer release()
	s := b.spec(lease, leaseDigest, existing.Config.Labels[LabelImageID])
	if !existing.State.Running && !workloadExited(existing) {
		if existing.State.Status != "created" {
			return fmt.Errorf("sandbox %s is %s, not running", instanceID, existing.State.Status)
		}
		// The full engine configuration is read back before the start
		// request (contract D23 precondition): a container the engine did
		// not configure as asked is never started.
		if err := b.verifyEngine(existing, s); err != nil {
			return err
		}
		if err := b.engine.call(ctx, http.MethodPost, "/containers/"+url.PathEscape(instanceID)+"/start", nil, nil, nil); err != nil {
			startErr := fmt.Errorf("start sandbox %s: %w", instanceID, err)
			if engineStatus(err) == 0 {
				// The daemon gave no answer: the miner's fault.
				return startErr
			}
			return b.startRefused(ctx, instanceID, existing.ID, s, startErr)
		}
		if existing, found, err = b.inspect(ctx, instanceID); err != nil {
			return err
		} else if !found {
			return fmt.Errorf("sandbox %s vanished after start", instanceID)
		}
	}
	if err := b.verifyEngine(existing, s); err != nil {
		return err
	}
	cgroup, err := b.verifyProcess(existing, s)
	if err == nil {
		b.recordCgroup(instanceID, cgroup)
		return nil
	}
	if !errors.Is(err, errProcessVanished) {
		// A value read from the live process that differs from the lease:
		// a miner fault even if the process exits afterwards.
		return err
	}
	// The workload may have exited by itself before or during the kernel
	// readback (contract D11-C2).
	return b.settleExit(ctx, instanceID, existing.ID, s, err)
}

func (b *GVisor) recordCgroup(instanceID, cgroup string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cgroups == nil {
		b.cgroups = map[string]string{}
	}
	b.cgroups[instanceID] = cgroup
}

// ExitAttribution is the per-instance record of a workload whose process
// was gone at the kernel readback (contract D11): the decision and what the
// last inspection showed.
type ExitAttribution struct {
	Instance, ContainerID string
	// Decision is "exited" (served), "running" (a later readback of the
	// live process passed) or "fault: <condition>".
	Decision                      string
	Inspections                   int
	Status, StartedAt, FinishedAt string
	Pid                           int
	StartError                    bool
	SliceQuiet                    bool
	Settled, SettleBound          time.Duration
}

func (r ExitAttribution) log() {
	slog.Info("sandbox exit attribution", "sandbox", r.Instance, "container_id", r.ContainerID, "decision", r.Decision,
		"inspections", r.Inspections, "status", r.Status, "started_at", r.StartedAt, "finished_at", r.FinishedAt,
		"pid", r.Pid, "start_error", r.StartError, "slice_quiet", r.SliceQuiet,
		"settled", r.Settled.String(), "settle_bound", r.SettleBound.String())
}

// settleExit decides a sandbox whose process was gone at the kernel
// readback. The engine records the exit, and the runtime tears down its
// processes, asynchronously, so the inspection, and the slice check of an
// exited workload, are repeated every startSettleInterval for at most
// startSettleBound. The workload is served only when an inspection shows
// it exited by itself (D11-C1) with its configuration intact and nothing
// left below the slice; while the engine still reports it running, the
// kernel readback is repeated, and any value it reads that differs from
// the lease is a miner fault (D11-C2). A state the engine reports as
// failed, or no exit within the bound, is a miner fault.
func (b *GVisor) settleExit(ctx context.Context, instanceID, containerID string, s spec, vanished error) error {
	record := ExitAttribution{Instance: instanceID, ContainerID: containerID, SettleBound: startSettleBound}
	// Logged as decided, not as first built.
	defer func() { record.log() }()
	fault := func(condition string, err error) error {
		record.Decision = "fault: " + condition
		return fmt.Errorf("sandbox %s %s: %w", instanceID, condition, err)
	}
	begun := time.Now()
	last := vanished
	for {
		again, found, err := b.inspect(ctx, instanceID)
		record.Inspections++
		if err != nil || !found || again.ID != containerID {
			if err == nil {
				err = last
			}
			return fault("re-inspection not answered", err)
		}
		record.Status, record.StartedAt, record.FinishedAt = again.State.Status, again.State.StartedAt, again.State.FinishedAt
		record.Pid, record.StartError = again.State.Pid, again.State.Error != ""
		switch {
		case workloadExited(again):
			if err := b.verifyEngine(again, s); err != nil {
				return fault("engine configuration", err)
			}
			quiet := b.sliceQuiet(ctx, instanceID)
			record.SliceQuiet = quiet == nil
			if quiet == nil {
				record.Decision, record.Settled = "exited", time.Since(begun)
				return b.exited(again)
			}
			if !errors.Is(quiet, errProcessesRemain) {
				return fault("slice unreadable", quiet)
			}
			last = quiet
		case again.State.Running || again.State.Pid > 0:
			// The engine has not recorded the exit yet, or the process
			// is in fact running: read it again.
			cgroup, err := b.verifyProcess(again, s)
			if err == nil {
				b.recordCgroup(instanceID, cgroup)
				record.Decision, record.Settled = "running", time.Since(begun)
				return nil
			}
			if !errors.Is(err, errProcessVanished) {
				return fault("live process differs from the lease", err)
			}
			last = err
		default:
			// Stopped without a clean exit: a start the engine or runtime
			// failed, or an exit time not after the start.
			return fault("did not exit by itself", last)
		}
		record.Settled = time.Since(begun)
		if record.Settled >= startSettleBound {
			return fault("did not settle", last)
		}
		timer := time.NewTimer(startSettleInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fault("did not settle", ctx.Err())
		case <-timer.C:
		}
	}
}

// Settling of a start the engine refused: the runtime tears down the
// processes of a failed start asynchronously, so the D23 process checks are
// repeated every startSettleInterval for at most startSettleBound.
const (
	startSettleBound    = 2 * time.Second
	startSettleInterval = 50 * time.Millisecond
)

// StartAttribution is the per-instance record of a start the engine
// answered with an error (contract D23): the decision and every input it
// was made from. It reads no message text, exit code or exit time.
type StartAttribution struct {
	Instance, ContainerID string
	// Decision is "never_started" (non-fault image_unavailable) or
	// "fault: <condition>".
	Decision          string
	StartStatus       int
	ReinspectAnswered bool
	Running           bool
	Pid               int
	StartedAt         string
	SliceQuiet        bool
	// RuntimeReferences are the host processes whose arguments or cgroup
	// named the container ID at the last observation.
	RuntimeReferences []int
	// ScanError is the last host process scan failure, if the scan never
	// completed.
	ScanError   string
	Settled     time.Duration
	SettleBound time.Duration
	CleanedUp   bool
}

func (r StartAttribution) log() {
	slog.Info("sandbox start attribution", "sandbox", r.Instance, "container_id", r.ContainerID, "decision", r.Decision,
		"start_status", r.StartStatus, "reinspect_answered", r.ReinspectAnswered, "running", r.Running, "pid", r.Pid,
		"started_at", r.StartedAt, "slice_quiet", r.SliceQuiet, "runtime_references", r.RuntimeReferences,
		"scan_error", r.ScanError, "settled", r.Settled.String(), "settle_bound", r.SettleBound.String(), "cleaned_up", r.CleanedUp,
		"per_process_checks", "not_run")
}

// startRefused classifies a start request the engine answered with an
// error (contract D23). The failure is the image's (image_unavailable) only
// when a fresh inspection shows the workload never started, the engine
// configuration still matches, no process of the instance remains below
// the slice or anywhere on the host referring to the container, and the
// never-started container is removed. Anything else is the miner's fault
// and returns startErr. The caller holds the start slot.
func (b *GVisor) startRefused(ctx context.Context, instanceID, containerID string, s spec, startErr error) error {
	record := StartAttribution{Instance: instanceID, ContainerID: containerID, StartStatus: engineStatus(startErr), SettleBound: startSettleBound}
	// Logged as decided, not as first built.
	defer func() { record.log() }()
	fault := func(condition string, err error) error {
		record.Decision = "fault: " + condition
		if err != nil {
			return fmt.Errorf("%w (%s: %w)", startErr, condition, err)
		}
		return fmt.Errorf("%w (%s)", startErr, condition)
	}
	again, found, err := b.inspect(ctx, instanceID)
	if err != nil || !found {
		return fault("re-inspection not answered", err)
	}
	record.ReinspectAnswered = true
	record.Running, record.Pid, record.StartedAt = again.State.Running, again.State.Pid, again.State.StartedAt
	if again.ID != containerID || again.Config.Labels[LabelLeaseID] != s.labels[LabelLeaseID] || again.Config.Labels[LabelLeaseDigest] != s.labels[LabelLeaseDigest] {
		return fault("another container", nil)
	}
	if !neverStarted(again) {
		return fault("workload started", nil)
	}
	if err := b.verifyEngine(again, s); err != nil {
		return fault("engine configuration", err)
	}
	begun := time.Now()
	for {
		quiet := b.sliceQuiet(ctx, instanceID)
		references, refErr := b.runtimeReferences(containerID)
		record.SliceQuiet, record.RuntimeReferences, record.ScanError = quiet == nil, references, ""
		if quiet != nil && !errors.Is(quiet, errProcessesRemain) {
			return fault("slice unreadable", quiet)
		}
		if refErr != nil {
			record.ScanError = refErr.Error()
		}
		record.Settled = time.Since(begun)
		if quiet == nil && refErr == nil && len(references) == 0 {
			break
		}
		if record.Settled >= startSettleBound {
			switch {
			case refErr != nil:
				// A scan that never completed cannot show nothing remains.
				return fault("host processes unreadable", refErr)
			case quiet == nil:
				quiet = fmt.Errorf("host processes %v refer to container %s", references, containerID)
			}
			return fault("processes of the instance remain", quiet)
		}
		timer := time.NewTimer(startSettleInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fault("processes of the instance remain", ctx.Err())
		case <-timer.C:
		}
	}
	if err := b.Destroy(ctx, instanceID); err != nil {
		return fault("cleanup", err)
	}
	record.CleanedUp = true
	record.Decision = "never_started"
	return &miner.SandboxRefusal{Code: "image_unavailable"}
}

// neverStarted reports an inspection showing a workload the engine never
// started: not running, no PID, and no start time.
func neverStarted(c inspectedContainer) bool {
	if c.State.Running || c.State.Pid != 0 {
		return false
	}
	if c.State.StartedAt == "" {
		return true
	}
	started, err := time.Parse(time.RFC3339Nano, c.State.StartedAt)
	return err == nil && started.IsZero()
}

// runtimeReferences returns the host processes of the instance outside
// the slice walk: any process whose cgroup path contains the
// engine-assigned container ID (generated by the engine at create; the
// image cannot choose it), and any runtime process (the runsc or sentry
// binary Open hashed, by file identity) whose command-line arguments
// contain it. Arguments of other programs are not evidence: an operator's
// shell or tool may name a container it inspects. A process that exits
// during the scan is skipped; any other read failure is returned, and the
// caller retries within the settle bound.
func (b *GVisor) runtimeReferences(containerID string) ([]int, error) {
	if len(containerID) < 12 {
		return nil, fmt.Errorf("container ID %q is too short to match processes by", containerID)
	}
	entries, err := os.ReadDir(b.config.ProcRoot)
	if err != nil {
		return nil, err
	}
	var references []int
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		dir := filepath.Join(b.config.ProcRoot, entry.Name())
		cgroup, err := readBounded(filepath.Join(dir, "cgroup"), 64<<10)
		if gone(err) {
			continue
		} else if err != nil {
			return nil, fmt.Errorf("process %d cgroup: %w", pid, err)
		}
		if strings.Contains(cgroup, containerID) {
			references = append(references, pid)
			continue
		}
		cmdline, err := readBounded(filepath.Join(dir, "cmdline"), 1<<20)
		if gone(err) {
			continue
		} else if err != nil {
			return nil, fmt.Errorf("process %d command line: %w", pid, err)
		}
		if !strings.Contains(cmdline, containerID) {
			continue
		}
		runtime, alive, err := b.runtimeProcess(dir)
		if err != nil {
			return nil, fmt.Errorf("process %d executable: %w", pid, err)
		}
		if alive && runtime {
			references = append(references, pid)
		}
	}
	return references, nil
}

// runtimeProcess reports whether the process in dir executes the runsc or
// sentry binary Open hashed, and whether it still exists. A process whose
// executable was deleted or replaced cannot be told apart from a runtime
// process, so it counts as one.
func (b *GVisor) runtimeProcess(dir string) (runtime, alive bool, err error) {
	exe := filepath.Join(dir, "exe")
	file, err := os.Stat(exe)
	if err == nil {
		return os.SameFile(file, b.sandboxFile) || (b.runscFile != nil && os.SameFile(file, b.runscFile)), true, nil
	}
	if !gone(err) {
		return false, false, err
	}
	if _, linkErr := os.Readlink(exe); linkErr == nil {
		// The link reads but its target is gone: a deleted executable.
		return true, true, nil
	} else if gone(linkErr) {
		return false, false, nil
	} else {
		return false, false, linkErr
	}
}

// gone reports a /proc read of a process that no longer exists.
func gone(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, unix.ESRCH)
}

// readBounded reads file, failing if it is larger than limit.
func readBounded(file string, limit int64) (string, error) {
	handle, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer handle.Close()
	raw, err := io.ReadAll(io.LimitReader(handle, limit+1))
	if err != nil {
		return "", err
	}
	if int64(len(raw)) > limit {
		return "", fmt.Errorf("%s is larger than %d bytes", file, limit)
	}
	return string(raw), nil
}

// localStepReserve is the part of the create budget kept for the steps
// after a pull (contract D15(d)): image inspection, container create, the
// start slot and start, the engine and kernel readbacks, and the D23
// re-inspection, settle (startSettleBound) and removal. Those normally take
// seconds; a hung engine call is cut by this reserve rather than by its own
// two-minute answer timeout. The pull gets the budget minus this reserve.
const localStepReserve = 2 * time.Minute

// createBudget splits the deadline the lane gives Create (contract
// D15(d)): the registry phase runs until the budget's deadline minus the
// local reserve, and the local steps run under their own deadline of that
// reserve, started fresh when a pull returns, so a pull cannot consume
// them. Pull share plus local reserve never exceed the budget.
type createBudget struct {
	parent       context.Context
	pullDeadline time.Time // zero when the lane gave no deadline
	reserve      time.Duration
	localCtx     context.Context
	cancelLocal  func()
}

func (b *GVisor) newCreateBudget(parent context.Context) (*createBudget, error) {
	reserve := b.localReserve
	if reserve <= 0 {
		reserve = localStepReserve
	}
	budget := &createBudget{parent: parent, reserve: reserve}
	if deadline, ok := parent.Deadline(); ok {
		if left := time.Until(deadline); left <= reserve {
			return nil, fmt.Errorf("create budget of %v leaves no pull share beside the %v local-step reserve", left.Round(time.Millisecond), reserve)
		}
		budget.pullDeadline = deadline.Add(-reserve)
	}
	budget.restartLocal()
	return budget, nil
}

// pull returns the context of the registry phase.
func (c *createBudget) pull() (context.Context, context.CancelFunc) {
	if c.pullDeadline.IsZero() {
		return context.WithCancel(c.parent)
	}
	return context.WithDeadline(c.parent, c.pullDeadline)
}

// restartLocal starts a fresh local deadline. It does not inherit the
// lane's deadline, only an explicit cancellation of the lane's context.
func (c *createBudget) restartLocal() {
	c.close()
	local, cancel := context.WithTimeout(context.WithoutCancel(c.parent), c.reserve)
	stop := context.AfterFunc(c.parent, func() {
		if errors.Is(c.parent.Err(), context.Canceled) {
			cancel()
		}
	})
	c.localCtx = local
	c.cancelLocal = func() {
		stop()
		cancel()
	}
}

func (c *createBudget) local() context.Context { return c.localCtx }

func (c *createBudget) close() {
	if c.cancelLocal != nil {
		c.cancelLocal()
	}
}

// errProcessVanished marks a kernel readback that found no process to read:
// the engine reported none running, or its /proc or cgroup entries were gone.
var errProcessVanished = errors.New("sandbox process vanished")

// vanished marks err as errProcessVanished when it says an entry no longer
// exists. Any other error, and any value read, is not a vanished process.
func vanished(err error) error {
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, unix.ESRCH) {
		return fmt.Errorf("%w: %w", errProcessVanished, err)
	}
	return err
}

// workloadExited reports a container the engine started whose workload has
// since exited by itself, with any exit code and including an OOM kill
// within the lease limit (contract D11-C1). A start the engine or runtime
// failed records State.Error and is not an exit.
func workloadExited(c inspectedContainer) bool {
	started, startErr := time.Parse(time.RFC3339Nano, c.State.StartedAt)
	finished, finishErr := time.Parse(time.RFC3339Nano, c.State.FinishedAt)
	return !c.State.Running && c.State.Pid == 0 && c.State.Status == "exited" && c.State.Error == "" &&
		startErr == nil && finishErr == nil && started.Year() > 1 && finished.After(started)
}

// errProcessesRemain marks a slice that still holds processes outside other
// sandboxes' cgroups.
var errProcessesRemain = errors.New("processes remain below the slice")

// acquireStart waits for the start slot; the returned func frees it.
func (b *GVisor) acquireStart(ctx context.Context) (func(), error) {
	b.mu.Lock()
	if b.startSlot == nil {
		b.startSlot = make(chan struct{}, 1)
	}
	slot := b.startSlot
	b.mu.Unlock()
	select {
	case slot <- struct{}{}:
		return func() { <-slot }, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("wait to start a sandbox: %w", ctx.Err())
	}
}

// sliceQuiet requires that no process remains anywhere below the slice
// once a sandbox's workload exited, except in the cgroups of other
// sandboxes: those the engine reports running, and those whose process the
// kernel readback found while their container exists (contract D11-C1).
// Cgroup names are not trusted to tell which instance a process belongs
// to. The caller holds the start slot, so no other sandbox is starting.
func (b *GVisor) sliceQuiet(ctx context.Context, instanceID string) error {
	owned, err := b.liveSandboxCgroups(ctx, instanceID)
	if err != nil {
		return err
	}
	b.mu.Lock()
	for instance, cgroup := range b.cgroups {
		if instance != instanceID {
			owned = append(owned, cgroup)
		}
	}
	b.mu.Unlock()
	root := filepath.Join(b.config.CgroupRoot, b.sliceCgroup)
	return filepath.WalkDir(root, func(dir string, entry fs.DirEntry, err error) error {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil || !entry.IsDir() {
			return err
		}
		cgroup := b.sliceCgroup + strings.TrimPrefix(dir, root)
		for _, live := range owned {
			if cgroup == live || strings.HasPrefix(cgroup, live+"/") {
				return fs.SkipDir
			}
		}
		procs, err := readSmall(filepath.Join(dir, "cgroup.procs"))
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if procs != "" {
			return fmt.Errorf("%w: sandbox %s exited but processes remain in cgroup %s", errProcessesRemain, instanceID, cgroup)
		}
		return nil
	})
}

// liveSandboxCgroups returns the cgroups below the slice of the processes of
// every running sandbox other than instanceID.
func (b *GVisor) liveSandboxCgroups(ctx context.Context, instanceID string) ([]string, error) {
	instances, err := b.Instances(ctx)
	if err != nil {
		return nil, err
	}
	var owned []string
	for _, instance := range instances {
		if instance.Name == instanceID {
			continue
		}
		c, found, err := b.inspect(ctx, instance.Name)
		if err != nil {
			return nil, err
		}
		if !found || !c.State.Running || c.State.Pid <= 0 {
			continue
		}
		cgroup, err := processCgroup(filepath.Join(b.config.ProcRoot, strconv.Itoa(c.State.Pid), "cgroup"))
		if err == nil && strings.HasPrefix(cgroup, b.sliceCgroup+"/") {
			owned = append(owned, cgroup)
		}
	}
	return owned, nil
}

// exited accepts a sandbox whose workload exited before its process could
// be read back (contract D11): no customer code remains to contain, so the
// lease is served and stays leased until release or expiry. Its engine
// configuration was verified; the kernel readbacks did not run.
func (b *GVisor) exited(c inspectedContainer) error {
	slog.Info("sandbox workload exited before the kernel readback; per-process checks not_run",
		"sandbox", strings.TrimPrefix(c.Name, "/"), "started_at", c.State.StartedAt)
	return nil
}

// createContainer pulls and verifies the lease's image and creates, but
// does not start, its container. The image lock spans the image check and
// the container creation, so a concurrent Destroy cannot remove the image
// in between.
func (b *GVisor) createContainer(budget *createBudget, instanceID string, lease protocol.SandboxLeaseV1, leaseDigest string) error {
	for attempt := 1; ; attempt++ {
		imageID, err := b.pullImage(budget, lease)
		if err != nil {
			return err
		}
		ctx := budget.local()
		unlock := b.lockImage(imageID)
		missing := false
		if _, _, err := b.verifiedImage(ctx, imageID, lease); engineStatus(err) == http.StatusNotFound {
			missing = true
		} else if err != nil {
			unlock()
			return err
		}
		if !missing {
			err = b.engine.call(ctx, http.MethodPost, "/containers/create",
				url.Values{"name": {instanceID}, "platform": {"linux/amd64"}}, b.createBody(b.spec(lease, leaseDigest, imageID), imageID), nil)
			missing = engineStatus(err) == http.StatusNotFound
		}
		unlock()
		switch {
		case missing && attempt < pullAttempts:
			// A concurrent Destroy released the image between pull and lock.
			continue
		case engineStatus(err) == http.StatusConflict:
			// A concurrent or earlier Create made the container; the caller
			// verifies its labels.
			return nil
		case err != nil:
			return fmt.Errorf("create sandbox %s: %w", instanceID, err)
		case missing:
			return fmt.Errorf("create sandbox %s: image %s keeps disappearing", instanceID, imageID)
		}
		return nil
	}
}

func (b *GVisor) createBody(s spec, imageID string) map[string]any {
	return map[string]any{
		"Image": imageID, "Hostname": sandboxHostname, "Labels": s.labels,
		"AttachStdin": false, "AttachStdout": false, "AttachStderr": false, "Tty": false, "OpenStdin": false,
		"HostConfig": map[string]any{
			"Runtime": s.host.Runtime, "NetworkMode": s.host.NetworkMode, "CgroupParent": s.host.CgroupParent,
			"NanoCpus": s.host.NanoCpus, "Memory": s.host.Memory, "MemorySwap": s.host.MemorySwap, "PidsLimit": *s.host.PidsLimit,
			"StorageOpt": s.host.StorageOpt, "LogConfig": s.host.LogConfig,
			"CapDrop": s.host.CapDrop, "CapAdd": s.host.CapAdd, "SecurityOpt": s.host.SecurityOpt,
			"IpcMode": s.host.IpcMode, "RestartPolicy": map[string]any{"Name": "no"},
			"Privileged": false, "ReadonlyRootfs": false, "AutoRemove": false, "PublishAllPorts": false,
			// Explicit, because the daemon applies its own init default
			// when Init is unset: the image's process is PID 1.
			"Init": false,
		},
	}
}

// pullImage pulls the lease's image by digest and returns its engine ID
// once verifiedImage accepts it.
func (b *GVisor) pullImage(budget *createBudget, lease protocol.SandboxLeaseV1) (string, error) {
	name, err := normalizedRepository(lease.ImageReference)
	if err != nil {
		return "", &miner.SandboxRefusal{Code: "image_unavailable"}
	}
	limit := int64(b.config.ImageMaxMiB) << 20
	if err := b.pullHeadroom(); err != nil {
		return "", err
	}
	// The registry phase (resolving its host and the pull itself) runs
	// under the pull deadline: the registry controls how long it takes.
	pullCtx, cancelPull := budget.pull()
	defer cancelPull()
	pullExpired := func() bool {
		return errors.Is(pullCtx.Err(), context.DeadlineExceeded) && budget.parent.Err() == nil
	}
	if err := b.publicRegistry(pullCtx, name); err != nil {
		if pullExpired() {
			return "", &miner.SandboxRefusal{Code: "image_unavailable"}
		}
		return "", err
	}
	err = b.engine.pull(pullCtx, name, lease.ImageDigest, limit)
	// The steps after the pull get the whole local reserve, however long
	// the pull took.
	budget.restartLocal()
	ctx := budget.local()
	if err != nil {
		switch {
		case errors.Is(err, errPullTooLarge):
			// The pull may have completed before it was stopped.
			if discardErr := b.discardImage(ctx, name+"@"+lease.ImageDigest); discardErr != nil {
				return "", discardErr
			}
			return "", &miner.SandboxRefusal{Code: "image_unavailable"}
		case pullExpired():
			// The registry did not deliver the image within the pull
			// deadline (contract D15(d)).
			return "", &miner.SandboxRefusal{Code: "image_unavailable"}
		case pullCtx.Err() != nil:
			return "", pullCtx.Err()
		case engineStatus(err) != 0:
			// The engine answered the pull with a failure. Registry answers
			// and transport failures to the registry reach the backend only
			// as engine messages whose text, and length, the registry can
			// choose, so none is the miner's fault (contract D15(c)), nor is
			// a progress stream that breaks off or never completes. Running
			// out of space after pullHeadroom held is the image outgrowing
			// its limit.
			if status := engineStatus(err); status >= 200 && status <= 299 {
				// The stream failed after the engine accepted the pull,
				// which may have stored the image.
				if discardErr := b.discardImage(ctx, name+"@"+lease.ImageDigest); discardErr != nil {
					return "", discardErr
				}
			}
			return "", &miner.SandboxRefusal{Code: "image_unavailable"}
		}
		// The dedicated daemon gave no answer: the miner's fault.
		return "", fmt.Errorf("pull %s: %w", lease.ImageReference, err)
	}
	imageID, size, err := b.verifiedImage(ctx, name+"@"+lease.ImageDigest, lease)
	if err != nil {
		if imageID != "" {
			// Do not keep an image no sandbox may run.
			_ = b.releaseImage(ctx, imageID)
		}
		return "", err
	}
	if size > limit {
		_ = b.releaseImage(ctx, imageID)
		return "", &miner.SandboxRefusal{Code: "image_unavailable"}
	}
	return imageID, nil
}

// pullHeadroom requires the free space on the data root that the per-image
// limit reserves for a pull. Its absence is the miner's fault, observed
// locally; with it, a pull that runs out of space is the image's doing.
func (b *GVisor) pullHeadroom() error {
	var stat unix.Statfs_t
	if err := unix.Statfs(b.config.DataRoot, &stat); err != nil {
		return fmt.Errorf("sandbox data root: %w", err)
	}
	if free := int64(stat.Bavail) * int64(stat.Bsize) >> 20; free < int64(b.config.ImageMaxMiB) {
		return fmt.Errorf("sandbox data root has %d MiB free, below the %d MiB a pull reserves", free, b.config.ImageMaxMiB)
	}
	return nil
}

type inspectedImage struct {
	ID           string   `json:"Id"`
	RepoDigests  []string `json:"RepoDigests"`
	Os           string   `json:"Os"`
	Architecture string   `json:"Architecture"`
	Size         int64    `json:"Size"`
	Config       struct {
		Volumes    map[string]any `json:"Volumes"`
		Entrypoint []string       `json:"Entrypoint"`
		Cmd        []string       `json:"Cmd"`
	} `json:"Config"`
}

// imageCommand is the argv a container of image runs: the image's
// entrypoint followed by its command. The leases set neither, and an
// entrypoint of the single empty string clears the entrypoint, as the
// engine's --entrypoint "" does.
func imageCommand(image inspectedImage) []string {
	entrypoint := image.Config.Entrypoint
	if len(entrypoint) == 1 && entrypoint[0] == "" {
		entrypoint = nil
	}
	return append(append([]string{}, entrypoint...), image.Config.Cmd...)
}

// verifiedImage inspects image (a reference or an ID) and requires that the
// engine recorded it under the lease's exact repository and digest, for
// linux/amd64, without image-defined volumes, whose bytes no quota would
// count, and with a command to run.
func (b *GVisor) verifiedImage(ctx context.Context, image string, lease protocol.SandboxLeaseV1) (string, int64, error) {
	var inspected inspectedImage
	if err := b.engine.call(ctx, http.MethodGet, "/images/"+image+"/json", nil, nil, &inspected); err != nil {
		if engineStatus(err) == http.StatusNotFound {
			return "", 0, err
		}
		return "", 0, fmt.Errorf("inspect image %s: %w", image, err)
	}
	name, err := normalizedRepository(lease.ImageReference)
	if err != nil {
		return "", 0, err
	}
	pinned := false
	for _, reference := range inspected.RepoDigests {
		repository, digest, ok := strings.Cut(reference, "@")
		if !ok {
			continue
		}
		if normalized, err := normalizedRepository(repository + "@" + digest); err == nil && normalized == name && digest == lease.ImageDigest {
			pinned = true
		}
	}
	if !pinned || !strings.HasPrefix(inspected.ID, "sha256:") {
		return inspected.ID, 0, fmt.Errorf("engine image %s is not recorded as %s", inspected.ID, lease.ImageReference)
	}
	if inspected.Os != "linux" || inspected.Architecture != "amd64" {
		return inspected.ID, 0, &miner.SandboxRefusal{Code: "image_unavailable"}
	}
	if len(inspected.Config.Volumes) != 0 {
		return inspected.ID, 0, &miner.SandboxRefusal{Code: "resources_unsupported"}
	}
	if command := imageCommand(inspected); len(command) == 0 || command[0] == "" {
		// The engine would refuse to create the container, an answer that
		// must not count against the miner: the image cannot run as a lease
		// (contract D19).
		return inspected.ID, 0, &miner.SandboxRefusal{Code: "image_unavailable"}
	}
	return inspected.ID, inspected.Size, nil
}

// publicRegistry refuses, before the engine is asked to pull, a registry
// the daemon would reach on the miner's own host or private networks:
// localhost and other local-only names, any IP literal, and any host name
// that resolves to an address
// in the special-purpose prefixes of pkg/netpolicy (loopback, link-local,
// RFC 1918, CGNAT, ULA, unspecified and the rest). The daemon resolves the
// name again, and may follow registry redirects, so this does not replace
// host-level pull egress policy; it keeps a signed image reference from
// naming a host-local service.
func (b *GVisor) publicRegistry(ctx context.Context, repository string) error {
	domain, _, _ := strings.Cut(repository, "/")
	host := domain
	if split, _, err := net.SplitHostPort(domain); err == nil {
		host = split
	}
	if host == "docker.io" {
		host = "registry-1.docker.io"
	}
	if _, err := netip.ParseAddr(host); err == nil || !publicHostName(host) {
		return &miner.SandboxRefusal{Code: "image_unavailable"}
	}
	addresses, err := b.lookup(ctx, host)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return &miner.SandboxRefusal{Code: "image_unavailable"}
	}
	if len(addresses) == 0 {
		return &miner.SandboxRefusal{Code: "image_unavailable"}
	}
	for _, address := range addresses {
		if _, err := netpolicy.CanonicalPublicAddress(address.String()); err != nil {
			return &miner.SandboxRefusal{Code: "image_unavailable"}
		}
	}
	// A public address assigned to this host would make the daemon pull
	// from a service on the miner's own host (contract D8 item 2b). Read
	// fresh for every pull, since addresses change; not knowing them
	// refuses the pull as the miner's fault.
	own, err := b.hostAddresses()
	if err != nil {
		return fmt.Errorf("list this host's addresses before a pull: %w", err)
	}
	for _, address := range addresses {
		for _, assigned := range own {
			if address.Unmap() == assigned.Unmap() {
				return &miner.SandboxRefusal{Code: "image_unavailable"}
			}
		}
	}
	return nil
}

// interfaceAddresses lists the addresses assigned to the interfaces of
// this process's network namespace, unmapped and without zones.
func interfaceAddresses() ([]netip.Addr, error) {
	assigned, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	addresses := make([]netip.Addr, 0, len(assigned))
	for _, entry := range assigned {
		network, ok := entry.(*net.IPNet)
		if !ok {
			return nil, fmt.Errorf("interface address %v is not an IP network", entry)
		}
		address, ok := netip.AddrFromSlice(network.IP)
		if !ok {
			return nil, fmt.Errorf("interface address %v is not an IP", network.IP)
		}
		addresses = append(addresses, address.Unmap())
	}
	return addresses, nil
}

// publicHostName refuses registry names that only resolve on the miner's
// own host or site, whatever its resolver answers: single-label names,
// absolute names, and the localhost, mDNS, home and .internal namespaces.
func publicHostName(host string) bool {
	host = strings.ToLower(host)
	if !strings.Contains(host, ".") || strings.HasSuffix(host, ".") {
		return false
	}
	for _, suffix := range []string{".localhost", ".local", ".internal", ".home.arpa"} {
		if strings.HasSuffix(host, suffix) {
			return false
		}
	}
	return true
}

func lookupHost(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// normalizedRepository returns the fully qualified repository of a digest
// reference: "busybox@sha256:..." is "docker.io/library/busybox".
func normalizedRepository(reference string) (string, error) {
	if _, ok := sandbox.ImageDigest(reference); !ok {
		return "", fmt.Errorf("image reference %q is not digest-pinned", reference)
	}
	name, _, _ := strings.Cut(reference, "@")
	domain, rest, found := strings.Cut(name, "/")
	if !found || !(strings.ContainsAny(domain, ".:") || domain == "localhost") {
		domain, rest = "docker.io", name
	}
	if domain == "index.docker.io" {
		domain = "docker.io"
	}
	if domain == "docker.io" && !strings.Contains(rest, "/") {
		rest = "library/" + rest
	}
	return domain + "/" + rest, nil
}

func (b *GVisor) inspect(ctx context.Context, instanceID string) (inspectedContainer, bool, error) {
	var container inspectedContainer
	err := b.engine.call(ctx, http.MethodGet, "/containers/"+url.PathEscape(instanceID)+"/json", nil, nil, &container)
	if engineStatus(err) == http.StatusNotFound {
		return inspectedContainer{}, false, nil
	}
	if err != nil {
		return inspectedContainer{}, false, fmt.Errorf("inspect sandbox %s: %w", instanceID, err)
	}
	return container, true, nil
}

// verifyEngine proves the engine's recorded configuration of the container
// is exactly s.
func (b *GVisor) verifyEngine(c inspectedContainer, s spec) error {
	h := c.HostConfig
	wantLog := s.host.LogConfig
	switch {
	case c.Image != s.labels[LabelImageID] || !strings.HasPrefix(c.Image, "sha256:"):
		return fmt.Errorf("sandbox %s runs image %s, not the verified %s", c.Name, c.Image, s.labels[LabelImageID])
	case h.Runtime != s.host.Runtime:
		return fmt.Errorf("sandbox %s runtime is %q, not %q", c.Name, h.Runtime, s.host.Runtime)
	case h.NetworkMode != "none" || h.CgroupParent != s.host.CgroupParent || h.IpcMode != "private" || h.PidMode != "" ||
		h.UTSMode != "" || h.UsernsMode != "" || (h.CgroupnsMode != "" && h.CgroupnsMode != "private") || h.PublishAllPorts || len(h.PortBindings) != 0:
		return fmt.Errorf("sandbox %s namespaces, ports or cgroup parent differ from the sandbox spec", c.Name)
	case h.NanoCpus != s.host.NanoCpus || h.Memory != s.host.Memory || h.MemorySwap != s.host.MemorySwap ||
		h.PidsLimit == nil || *h.PidsLimit != *s.host.PidsLimit || h.StorageOpt["size"] != s.host.StorageOpt["size"] || len(h.StorageOpt) != 1:
		return fmt.Errorf("sandbox %s resource limits differ from the lease", c.Name)
	case h.LogConfig.Type != wantLog.Type || len(h.LogConfig.Config) != len(wantLog.Config) ||
		h.LogConfig.Config["max-size"] != wantLog.Config["max-size"] || h.LogConfig.Config["max-file"] != wantLog.Config["max-file"]:
		return fmt.Errorf("sandbox %s log bounds differ from the sandbox spec", c.Name)
	case h.Privileged || h.ReadonlyRootfs || len(h.Binds) != 0 || len(h.Devices) != 0 || len(c.Mounts) != 0 || h.RestartPolicy.Name != "no":
		return fmt.Errorf("sandbox %s has privileges, mounts, devices or a restart policy", c.Name)
	case !sameSet(h.CapDrop, s.host.CapDrop) || !sameSet(h.CapAdd, s.host.CapAdd) || !sameSet(h.SecurityOpt, s.host.SecurityOpt):
		return fmt.Errorf("sandbox %s capabilities or security options differ from the sandbox spec", c.Name)
	case h.Init == nil || *h.Init || len(h.Sysctls) != 0 || len(h.Tmpfs) != 0 || len(h.Annotations) != 0 ||
		len(h.DeviceCgroupRules) != 0 || len(h.DeviceRequests) != 0 || len(h.VolumesFrom) != 0 || h.VolumeDriver != "" ||
		len(h.Links) != 0 || len(h.GroupAdd) != 0 || len(h.ExtraHosts) != 0 || len(h.DNS) != 0 || len(h.DNSOptions) != 0 ||
		len(h.DNSSearch) != 0 || h.OomScoreAdj != 0:
		return fmt.Errorf("sandbox %s has host settings the sandbox spec does not set", c.Name)
	}
	return nil
}

// verifyProcess proves the kernel's view of the running sandbox process:
// the pinned gVisor binary Open hashed, in a cgroup below the slice whose
// cpu.max, memory.max and pids.max equal the lease's, with no swap
// (lease.child_limits_match), and returns that cgroup. It reports
// errProcessVanished only when there was no process left to read; a
// mismatch it read is a plain error.
func (b *GVisor) verifyProcess(c inspectedContainer, s spec) (string, error) {
	if !c.State.Running || c.State.Pid <= 0 {
		return "", fmt.Errorf("%w: sandbox %s is %s, not running: %q", errProcessVanished, c.Name, c.State.Status, c.State.Error)
	}
	proc := filepath.Join(b.config.ProcRoot, strconv.Itoa(c.State.Pid))
	exe, err := os.Readlink(filepath.Join(proc, "exe"))
	if err != nil {
		return "", fmt.Errorf("sandbox %s process executable: %w", c.Name, vanished(err))
	}
	if exe != b.sandboxExe {
		return "", fmt.Errorf("sandbox %s process runs %s, not the pinned gVisor binary %s", c.Name, exe, b.sandboxExe)
	}
	if file, err := os.Stat(filepath.Join(proc, "exe")); err != nil {
		return "", fmt.Errorf("sandbox %s process executable: %w", c.Name, vanished(err))
	} else if !os.SameFile(file, b.sandboxFile) || !file.ModTime().Equal(b.sandboxFile.ModTime()) || file.Size() != b.sandboxFile.Size() {
		return "", fmt.Errorf("sandbox %s process runs a %s replaced or rewritten since the backend opened", c.Name, b.sandboxExe)
	}
	cgroup, err := processCgroup(filepath.Join(proc, "cgroup"))
	if err != nil {
		return "", fmt.Errorf("sandbox %s: %w", c.Name, vanished(err))
	}
	if !strings.HasPrefix(cgroup, b.sliceCgroup+"/") {
		return "", fmt.Errorf("sandbox %s process cgroup %s is outside slice %s", c.Name, cgroup, b.sliceCgroup)
	}
	dir := filepath.Join(b.config.CgroupRoot, cgroup)
	limits := map[string]string{}
	for _, name := range []string{"memory.max", "memory.swap.max", "pids.max", "cpu.max"} {
		if limits[name], err = readSmall(filepath.Join(dir, name)); err != nil {
			return "", fmt.Errorf("sandbox %s cgroup %s: %w", c.Name, cgroup, vanished(err))
		}
	}
	memory, swap, pids, cpu := limits["memory.max"], limits["memory.swap.max"], limits["pids.max"], limits["cpu.max"]
	var quota, period int64
	if fields := strings.Fields(cpu); len(fields) == 2 {
		quota, _ = strconv.ParseInt(fields[0], 10, 64)
		period, _ = strconv.ParseInt(fields[1], 10, 64)
	}
	millis := s.host.NanoCpus / 1_000_000
	if memory != strconv.FormatInt(s.host.Memory, 10) || swap != "0" || pids != strconv.FormatInt(*s.host.PidsLimit, 10) ||
		quota <= 0 || period <= 0 || quota*1000 != millis*period {
		return "", fmt.Errorf("sandbox %s kernel limits cpu.max=%q memory.max=%q memory.swap.max=%q pids.max=%q differ from the lease",
			c.Name, cpu, memory, swap, pids)
	}
	return cgroup, nil
}

// processCgroup returns the cgroup v2 path of a process.
func processCgroup(file string) (string, error) {
	raw, err := readSmall(file)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(raw, "\n") {
		if cgroup, ok := strings.CutPrefix(line, "0::"); ok && path.IsAbs(cgroup) && path.Clean(cgroup) == cgroup {
			return cgroup, nil
		}
	}
	return "", errors.New("process is not in a cgroup v2 hierarchy")
}

func readSmall(file string) (string, error) {
	handle, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer handle.Close()
	raw, err := io.ReadAll(io.LimitReader(handle, 4097))
	if err != nil {
		return "", err
	}
	if len(raw) > 4096 {
		return "", fmt.Errorf("%s is too large", file)
	}
	return strings.TrimSpace(string(raw)), nil
}

func sameSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	seen := map[string]int{}
	for _, value := range left {
		seen[value]++
	}
	for _, value := range right {
		if seen[value] == 0 {
			return false
		}
		seen[value]--
	}
	return true
}

// Destroy removes the container, its anonymous volumes and log, and then its
// image unless another container still uses it. It is idempotent.
func (b *GVisor) Destroy(ctx context.Context, instanceID string) error {
	existing, found, err := b.inspect(ctx, instanceID)
	if err != nil {
		return err
	}
	if !found {
		b.forgetCgroup(instanceID)
		return nil
	}
	if existing.Config.Labels[LabelSandbox] != sandboxLabelV1 {
		return fmt.Errorf("container %s is not a sandbox", instanceID)
	}
	if err := b.removeContainer(ctx, instanceID); err != nil {
		return err
	}
	b.forgetCgroup(instanceID)
	if imageID := existing.Image; strings.HasPrefix(imageID, "sha256:") {
		return b.releaseImage(ctx, imageID)
	}
	return nil
}

// forgetCgroup drops the recorded cgroup of an instance whose container is
// gone.
func (b *GVisor) forgetCgroup(instanceID string) {
	b.mu.Lock()
	delete(b.cgroups, instanceID)
	b.mu.Unlock()
}

func (b *GVisor) removeContainer(ctx context.Context, instanceID string) error {
	ctx, cancel := context.WithTimeout(ctx, removalTimeout)
	defer cancel()
	err := b.engine.call(ctx, http.MethodDelete, "/containers/"+url.PathEscape(instanceID), url.Values{"force": {"1"}, "v": {"1"}}, nil, nil)
	if err != nil && engineStatus(err) != http.StatusNotFound && engineStatus(err) != http.StatusConflict {
		return fmt.Errorf("remove sandbox %s: %w", instanceID, err)
	}
	// 409 is a removal already in progress; wait for it like any other.
	for {
		if _, found, err := b.inspect(ctx, instanceID); err != nil {
			return err
		} else if !found {
			return nil
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("wait for sandbox %s removal: %w", instanceID, ctx.Err())
		case <-timer.C:
		}
	}
}

// discardImage releases the image recorded under reference, if any.
func (b *GVisor) discardImage(ctx context.Context, reference string) error {
	var inspected inspectedImage
	err := b.engine.call(ctx, http.MethodGet, "/images/"+reference+"/json", nil, nil, &inspected)
	if engineStatus(err) == http.StatusNotFound {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect image %s: %w", reference, err)
	}
	return b.releaseImage(ctx, inspected.ID)
}

// releaseImage removes imageID when no container on the daemon uses it.
func (b *GVisor) releaseImage(ctx context.Context, imageID string) error {
	unlock := b.lockImage(imageID)
	defer unlock()
	filters, _ := json.Marshal(map[string][]string{"ancestor": {imageID}})
	var users []listedContainer
	if err := b.engine.call(ctx, http.MethodGet, "/containers/json", url.Values{"all": {"1"}, "filters": {string(filters)}}, nil, &users); err != nil {
		if engineStatus(err) == http.StatusNotFound {
			return nil
		}
		return fmt.Errorf("list users of image %s: %w", imageID, err)
	}
	if len(users) != 0 {
		return nil
	}
	// force removes every repository reference of the ID; no container uses it.
	err := b.engine.call(ctx, http.MethodDelete, "/images/"+imageID, url.Values{"force": {"1"}}, nil, nil)
	if err != nil && engineStatus(err) != http.StatusNotFound && engineStatus(err) != http.StatusConflict {
		return fmt.Errorf("remove image %s: %w", imageID, err)
	}
	return nil
}

func (b *GVisor) lockImage(imageID string) func() {
	b.mu.Lock()
	if b.images == nil {
		b.images = map[string]*imageLock{}
	}
	entry := b.images[imageID]
	if entry == nil {
		entry = &imageLock{}
		b.images[imageID] = entry
	}
	entry.refs++
	b.mu.Unlock()
	entry.mu.Lock()
	return func() {
		entry.mu.Unlock()
		b.mu.Lock()
		if entry.refs--; entry.refs == 0 {
			delete(b.images, imageID)
		}
		b.mu.Unlock()
	}
}

// Instances lists every sandbox container on the daemon.
func (b *GVisor) Instances(ctx context.Context) ([]miner.SandboxInstance, error) {
	filters, _ := json.Marshal(map[string][]string{"label": {LabelSandbox}})
	var containers []listedContainer
	if err := b.engine.call(ctx, http.MethodGet, "/containers/json", url.Values{"all": {"1"}, "filters": {string(filters)}}, nil, &containers); err != nil {
		return nil, err
	}
	instances := make([]miner.SandboxInstance, 0, len(containers))
	for _, container := range containers {
		if len(container.Names) != 1 {
			return nil, fmt.Errorf("sandbox container %s has %d names", container.ID, len(container.Names))
		}
		instances = append(instances, miner.SandboxInstance{
			Name: strings.TrimPrefix(container.Names[0], "/"), LeaseID: container.Labels[LabelLeaseID],
		})
	}
	return instances, nil
}

// Reclaim removes every image no container uses. The lane calls it before
// it serves, when no Create can be between its pull and its container.
func (b *GVisor) Reclaim(ctx context.Context) error {
	filters, _ := json.Marshal(map[string][]string{"dangling": {"false"}})
	return b.engine.call(ctx, http.MethodPost, "/images/prune", url.Values{"filters": {string(filters)}}, nil, nil)
}
