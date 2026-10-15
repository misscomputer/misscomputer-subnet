// SPDX-License-Identifier: AGPL-3.0-only

package sandboxbackend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/sandboxhost"
)

// ConfigFromProfile derives the backend configuration from a validated
// sandbox-host-profile.v1 document, the provisioner's record of the host.
// The profile's Docker version must be the one this backend is reviewed for.
func ConfigFromProfile(p sandboxhost.Profile) (Config, error) {
	if err := p.Validate(); err != nil {
		return Config{}, err
	}
	if p.Engine.DockerVersion != PinnedDockerVersion {
		return Config{}, fmt.Errorf("host profile pins docker %q; only %s is reviewed", p.Engine.DockerVersion, PinnedDockerVersion)
	}
	return Config{
		DockerHost: p.DockerHost, Runtime: p.Runtime.Name,
		RunscPath: p.Runtime.Path, RunscSHA256: p.Runtime.SHA256,
		SentryPath: p.Runtime.SentryPath, SentrySHA256: p.Runtime.SentrySHA256,
		DataRoot: p.DockerDataRoot, Slice: p.LeaseSlice, CgroupRoot: p.CgroupRoot,
		DiskMiB: p.Aggregate.DiskMiB, Sandboxes: p.Aggregate.Sandboxes,
		ImageMaxMiB: p.Aggregate.ImageMaxMiB, LogMiB: p.Aggregate.LogMiB, PIDsMax: p.PerLease.PIDsMax,
		Layout: &Layout{
			RunRoot: p.RunRoot, DataFS: p.DataRoot,
			ContainerdAddress: p.Containerd.Address, ContainerdNamespace: p.Containerd.Namespace,
			ContainerdPluginsNamespace: p.Containerd.PluginsNamespace,
			RuntimeArgs:                slices.Clone(p.Runtime.Args),
			LogMaxSizeMiB:              p.PerLease.LogMaxSizeMiB, LogMaxFile: p.PerLease.LogMaxFile,
		},
	}, nil
}

// OpenFromProfile opens the backend for a host described by profile and
// returns it only when the whole preflight report passes: this backend's
// engine checks, with daemonConfig as the dedicated daemon's configuration
// file, and the host checks of pkg/sandboxhost observed by host, with the
// cgroups in exclusive kept disjoint from the sandbox and engine slices
// (contract host_preflight_contract.lane1_startup_rule). The report is
// returned either way. The backend also observes every sandbox it serves
// with host and logs one instance report per Create.
func OpenFromProfile(ctx context.Context, profile sandboxhost.Profile, daemonConfig string, host sandboxhost.Host, exclusive []string) (*GVisor, sandboxhost.Report, error) {
	config, err := ConfigFromProfile(profile)
	if err != nil {
		return nil, sandboxhost.Report{}, err
	}
	config.Layout.DaemonConfig = daemonConfig
	if host.Proc != "" {
		config.ProcRoot = host.Proc
	}
	b, err := newGVisor(config)
	if err != nil {
		return nil, sandboxhost.Report{}, err
	}
	// The whole report is built even when an engine check fails, so the
	// operator sees every check that did not pass.
	checks := append(b.EngineChecks(ctx), host.Preflight(profile, exclusive)...)
	report, err := sandboxhost.BuildReport(sandboxhost.ModePreflight, profile, checks, sandboxhost.Environment{})
	if err != nil {
		return nil, report, err
	}
	if err := sandboxhost.RequirePass(report); err != nil {
		return nil, report, err
	}
	b.profile = &profile
	b.observeInstance = func(pid int) []sandboxhost.Check { return host.ObserveInstance(profile, pid) }
	return b, report, nil
}

// checkRecorder collects checks with their catalog classes.
type checkRecorder struct{ checks []sandboxhost.Check }

func catalogClass(id string) string {
	for _, entry := range sandboxhost.Catalog() {
		if entry.ID == id {
			return entry.Class
		}
	}
	return ""
}

// evidence makes text a valid check evidence: printable ASCII of at most
// 512 bytes.
func evidence(text string) string {
	var b strings.Builder
	for _, r := range text {
		if r < 0x20 || r > 0x7e {
			r = '?'
		}
		b.WriteRune(r)
	}
	out := b.String()
	if len(out) > 512 {
		out = out[:509] + "..."
	}
	return out
}

func (r *checkRecorder) add(id string, err error, passEvidence string) {
	status, text := sandboxhost.StatusPass, passEvidence
	if err != nil {
		status, text = sandboxhost.StatusFail, err.Error()
	}
	r.checks = append(r.checks, sandboxhost.Check{ID: id, Class: catalogClass(id), Status: status, Evidence: evidence(text)})
}

func (r *checkRecorder) notRun(id, why string) {
	r.checks = append(r.checks, sandboxhost.Check{ID: id, Class: catalogClass(id), Status: sandboxhost.StatusNotRun, Evidence: evidence(why)})
}

// defaultDockerSockets are the default daemon's sockets.
var defaultDockerSockets = []string{"/var/run/docker.sock", "/run/docker.sock"}

// EngineChecks records the preflight checks of the host check catalog this
// backend owns (the engine.* ids observed through the dedicated daemon's
// Engine API and its files). Without a Layout, the parts that compare with
// the host profile are skipped and the two configured checks are not run;
// Open then refuses only a failure. With a Layout every part runs.
func (b *GVisor) EngineChecks(ctx context.Context) []sandboxhost.Check {
	var r checkRecorder
	layout := b.config.Layout
	var version struct {
		Version string `json:"Version"`
	}
	versionErr := b.engine.call(ctx, http.MethodGet, "/version", nil, nil, &version)
	var info daemonInfo
	infoErr := b.engine.call(ctx, http.MethodGet, "/info", nil, nil, &info)
	if infoErr != nil {
		infoErr = fmt.Errorf("sandbox docker daemon info: %w", infoErr)
	}

	socketErr := b.checkSocket(ctx, info, infoErr)
	r.add("engine.socket_dedicated", socketErr, "dedicated socket "+b.config.DockerHost+", not the default daemon's")

	if versionErr != nil {
		versionErr = fmt.Errorf("sandbox docker daemon: %w", versionErr)
	} else if version.Version != PinnedDockerVersion {
		versionErr = fmt.Errorf("sandbox docker daemon is %q; only %s is reviewed", version.Version, PinnedDockerVersion)
	}
	r.add("engine.version_pinned", versionErr, "server "+version.Version)

	wrongDaemon := func() error {
		return fmt.Errorf("sandbox docker daemon root=%q storage=%q cgroup=%q/v%s, want root=%q overlay2 systemd/v2",
			info.DockerRootDir, info.Driver, info.CgroupDriver, info.CgroupVersion, b.config.DataRoot)
	}
	dataErr := infoErr
	if dataErr == nil && info.DockerRootDir != b.config.DataRoot {
		dataErr = wrongDaemon()
	}
	if dataErr == nil && layout != nil {
		dataErr = sameDevice(info.DockerRootDir, layout.DataFS)
	}
	r.add("engine.data_root_on_data_fs", dataErr, "DockerRootDir="+info.DockerRootDir+" on the data filesystem")

	storageErr := infoErr
	if storageErr == nil && info.Driver != "overlay2" {
		storageErr = wrongDaemon()
	} else if storageErr == nil {
		if driver := driverStatus(info); driver["Backing Filesystem"] != "xfs" || driver["Supports d_type"] != "true" {
			storageErr = fmt.Errorf("sandbox docker daemon overlay2 is backed by %q with d_type %q, want xfs with d_type",
				driver["Backing Filesystem"], driver["Supports d_type"])
		}
	}
	r.add("engine.storage_overlay2_xfs", storageErr, "overlay2 on xfs with d_type")

	cgroupErr := infoErr
	if cgroupErr == nil && (info.CgroupDriver != "systemd" || info.CgroupVersion != "2") {
		cgroupErr = wrongDaemon()
	}
	r.add("engine.cgroup_driver_systemd_v2", cgroupErr, "CgroupDriver=systemd CgroupVersion=2")

	containerdErr := infoErr
	if containerdErr == nil {
		containerdErr = verifyContainerd(info)
	}
	if containerdErr == nil && layout != nil {
		containerdErr = verifyContainerdLayout(info, layout)
	}
	r.add("engine.containerd_dedicated", containerdErr, "dedicated containerd socket and namespaces; metadata on the data filesystem")

	var networks []struct {
		Name   string `json:"Name"`
		Driver string `json:"Driver"`
	}
	networkErr := b.engine.call(ctx, http.MethodGet, "/networks", nil, nil, &networks)
	if networkErr != nil {
		networkErr = fmt.Errorf("list sandbox daemon networks: %w", networkErr)
	}
	for _, network := range networks {
		if networkErr == nil && !(network.Name == "none" && network.Driver == "null") && !(network.Name == "host" && network.Driver == "host") {
			networkErr = fmt.Errorf("sandbox docker daemon manages network %q (%s); it must run with no bridge and only host and none", network.Name, network.Driver)
		}
	}
	r.add("engine.network_management_off", networkErr, "networks host and none only (no bridge)")

	runtimeErr := infoErr
	if runtimeErr == nil {
		runtimeErr = b.verifyRuntime(info)
	}
	r.add("engine.runtime_runsc_pinned", runtimeErr, "runtime "+b.config.Runtime+" registered at "+b.config.RunscPath+", binary SHA-256 verified at open")

	registryErr := infoErr
	if registryErr == nil {
		registryErr = verifyRegistryConfig(info)
	}
	r.add("engine.insecure_registries_empty", registryErr, "no insecure registry beyond the built-in loopback CIDRs, no mirrors, Docker Hub index secure")

	var containers []listedContainer
	labelErr := b.engine.call(ctx, http.MethodGet, "/containers/json", url.Values{"all": {"1"}}, nil, &containers)
	if labelErr != nil {
		labelErr = fmt.Errorf("list sandbox daemon containers: %w", labelErr)
	}
	for _, container := range containers {
		if labelErr == nil && container.Labels[LabelSandbox] != sandboxLabelV1 {
			labelErr = fmt.Errorf("sandbox docker daemon runs container %s that is not a sandbox; the daemon must be dedicated", container.ID)
		}
	}
	r.add("engine.no_unlabelled_containers", labelErr, fmt.Sprintf("%d containers, all sandboxes", len(containers)))

	if layout == nil || layout.DaemonConfig == "" {
		r.notRun("engine.firewall_management_off", "no daemon configuration file given")
		r.notRun("engine.default_bounded_logs", "no daemon configuration file given")
		return r.checks
	}
	daemon, configErr := readDaemonConfig(layout.DaemonConfig)
	firewallErr := configErr
	if firewallErr == nil {
		firewallErr = daemon.firewallOff()
	}
	r.add("engine.firewall_management_off", firewallErr, layout.DaemonConfig+": iptables, ip6tables, ip-forward and ip-masq false, bridge none (setting, not observed)")
	logsErr := errors.Join(infoErr, configErr)
	if logsErr == nil && info.LoggingDriver != "json-file" {
		logsErr = fmt.Errorf("sandbox docker daemon logging driver is %q, want json-file", info.LoggingDriver)
	}
	if logsErr == nil {
		logsErr = daemon.boundedLogs(layout.LogMaxSizeMiB, layout.LogMaxFile)
	}
	r.add("engine.default_bounded_logs", logsErr, fmt.Sprintf("LoggingDriver=json-file (observed); %s default max-size %dm max-file %d (setting)",
		layout.DaemonConfig, layout.LogMaxSizeMiB, layout.LogMaxFile))
	return r.checks
}

// checkSocket requires the dedicated socket to be the configured one, not
// the default daemon's, and with a Layout to lie under the run root with
// mode 0660 owned by root, answered by an engine other than the default
// daemon's.
func (b *GVisor) checkSocket(ctx context.Context, info daemonInfo, infoErr error) error {
	socket, err := dedicatedSocket(b.config.DockerHost)
	if err != nil || b.config.Layout == nil {
		return err
	}
	if rel, err := filepath.Rel(b.config.Layout.RunRoot, socket); err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return fmt.Errorf("sandbox docker socket %s is not under the run root %s", socket, b.config.Layout.RunRoot)
	}
	stat, err := os.Stat(socket)
	if err != nil {
		return fmt.Errorf("sandbox docker socket: %w", err)
	}
	owner, ok := stat.Sys().(*syscall.Stat_t)
	if stat.Mode()&os.ModeSocket == 0 || stat.Mode().Perm() != 0o660 || !ok || owner.Uid != 0 || owner.Gid != 0 {
		return fmt.Errorf("sandbox docker socket %s is %v, want a socket of mode 0660 owned by root:root", socket, stat.Mode())
	}
	if infoErr != nil {
		return infoErr
	}
	for _, shared := range defaultDockerSockets {
		if _, err := os.Stat(shared); err != nil {
			continue
		}
		var other daemonInfo
		probe, cancel := context.WithTimeout(ctx, 10*time.Second)
		otherErr := newEngine(shared).call(probe, http.MethodGet, "/info", nil, nil, &other)
		cancel()
		if otherErr == nil && other.ID != "" && other.ID == info.ID {
			return fmt.Errorf("the default daemon socket %s reaches the sandbox engine %s", shared, info.ID)
		}
	}
	return nil
}

// verifyRuntime requires the daemon to register runsc at the pinned path
// with only reviewed arguments, including the required ones, and with a
// Layout exactly the profile's arguments.
func (b *GVisor) verifyRuntime(info daemonInfo) error {
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
	if b.config.Layout != nil && !slices.Equal(runtime.RuntimeArgs, b.config.Layout.RuntimeArgs) {
		return fmt.Errorf("runtime %q arguments %v differ from the host profile's %v", b.config.Runtime, runtime.RuntimeArgs, b.config.Layout.RuntimeArgs)
	}
	return nil
}

// verifyContainerdLayout requires the daemon's containerd to be the
// profile's, with its metadata store on the data filesystem.
func verifyContainerdLayout(info daemonInfo, layout *Layout) error {
	c := info.Containerd
	if c.Address != layout.ContainerdAddress || c.Namespaces.Containers != layout.ContainerdNamespace || c.Namespaces.Plugins != layout.ContainerdPluginsNamespace {
		return fmt.Errorf("sandbox docker daemon containerd %s %s/%s differs from the host profile's %s %s/%s",
			c.Address, c.Namespaces.Containers, c.Namespaces.Plugins, layout.ContainerdAddress, layout.ContainerdNamespace, layout.ContainerdPluginsNamespace)
	}
	meta := filepath.Join(layout.DataFS, "containerd", "io.containerd.metadata.v1.bolt", "meta.db")
	if err := sameDevice(meta, layout.DataFS); err != nil {
		return fmt.Errorf("dedicated containerd metadata: %w", err)
	}
	return nil
}

// sameDevice requires path to exist on the filesystem mounted at mount.
func sameDevice(path, mount string) error {
	inner, err := os.Stat(path)
	if err != nil {
		return err
	}
	outer, err := os.Stat(mount)
	if err != nil {
		return err
	}
	a, okA := inner.Sys().(*syscall.Stat_t)
	b, okB := outer.Sys().(*syscall.Stat_t)
	if !okA || !okB || a.Dev != b.Dev {
		return fmt.Errorf("%s is not on the data filesystem %s", path, mount)
	}
	return nil
}

// daemonConfig is the part of a dockerd configuration file the configured
// engine checks read.
type daemonConfig struct {
	IPTables   *bool             `json:"iptables"`
	IP6Tables  *bool             `json:"ip6tables"`
	IPForward  *bool             `json:"ip-forward"`
	IPMasq     *bool             `json:"ip-masq"`
	Bridge     string            `json:"bridge"`
	LogDriver  string            `json:"log-driver"`
	LogOptions map[string]string `json:"log-opts"`
}

func readDaemonConfig(name string) (daemonConfig, error) {
	file, err := os.Open(name)
	if err != nil {
		return daemonConfig{}, fmt.Errorf("daemon configuration: %w", err)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 1<<20))
	if err != nil {
		return daemonConfig{}, fmt.Errorf("daemon configuration: %w", err)
	}
	var config daemonConfig
	if err := json.Unmarshal(raw, &config); err != nil {
		return daemonConfig{}, fmt.Errorf("daemon configuration %s: %w", name, err)
	}
	return config, nil
}

func (c daemonConfig) firewallOff() error {
	for name, value := range map[string]*bool{"iptables": c.IPTables, "ip6tables": c.IP6Tables, "ip-forward": c.IPForward, "ip-masq": c.IPMasq} {
		if value == nil || *value {
			return fmt.Errorf("daemon configuration does not set %s false", name)
		}
	}
	if c.Bridge != "none" {
		return fmt.Errorf("daemon configuration bridge is %q, want none", c.Bridge)
	}
	return nil
}

func (c daemonConfig) boundedLogs(maxSizeMiB, maxFile int) error {
	want := map[string]string{"max-size": strconv.Itoa(maxSizeMiB) + "m", "max-file": strconv.Itoa(maxFile)}
	if c.LogDriver != "json-file" || len(c.LogOptions) != len(want) || c.LogOptions["max-size"] != want["max-size"] || c.LogOptions["max-file"] != want["max-file"] {
		return fmt.Errorf("daemon configuration log driver %q options %v, want json-file %v", c.LogDriver, c.LogOptions, want)
	}
	return nil
}
