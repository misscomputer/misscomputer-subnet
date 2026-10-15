// SPDX-License-Identifier: AGPL-3.0-only

package sandboxbackend

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/misscomputer/misscomputer-subnet/pkg/sandboxhost"
)

// layoutFor is the host layout of the scripted host: the fake daemon's
// socket directory as the run root, the host root as the data filesystem
// (the daemon's data root lies below it) with containerd's metadata store
// on it, and a dedicated daemon configuration file. The socket is made
// mode 0660; its owner is root only when the tests run as root.
func layoutFor(h *host) *Layout {
	h.t.Helper()
	root := filepath.Dir(h.config.DataRoot)
	writeFile(h.t, filepath.Join(root, "containerd", "io.containerd.metadata.v1.bolt", "meta.db"), "bolt")
	socket := strings.TrimPrefix(h.config.DockerHost, "unix://")
	if err := os.Chmod(socket, 0o660); err != nil {
		h.t.Fatal(err)
	}
	daemon := filepath.Join(root, "daemon.json")
	writeFile(h.t, daemon, `{"iptables": false, "ip6tables": false, "ip-forward": false, "ip-masq": false, "bridge": "none",
		"log-driver": "json-file", "log-opts": {"max-size": "2m", "max-file": "2"}}`)
	return &Layout{
		RunRoot: filepath.Dir(socket), DataFS: root,
		ContainerdAddress: "/run/mc-sandbox/containerd/containerd.sock", ContainerdNamespace: "mc-sandbox", ContainerdPluginsNamespace: "mc-sandbox-plugins",
		RuntimeArgs: []string{"--systemd-cgroup", "--overlay2=none"}, LogMaxSizeMiB: 2, LogMaxFile: 2, DaemonConfig: daemon,
	}
}

func checkByID(checks []sandboxhost.Check, id string) (sandboxhost.Check, bool) {
	for _, c := range checks {
		if c.ID == id {
			return c, true
		}
	}
	return sandboxhost.Check{}, false
}

// laneOnePreflightIDs are the catalog's preflight ids owned by lane 1 that
// the backend records; lease.image_volumes_refused is reported (as a gap)
// by pkg/sandboxhost.
func laneOnePreflightIDs() []string {
	var ids []string
	for _, entry := range sandboxhost.Catalog() {
		if entry.Owner == "lane1" && slices.Contains(entry.Modes, sandboxhost.ModePreflight) && entry.ID != "lease.image_volumes_refused" {
			ids = append(ids, entry.ID)
		}
	}
	return ids
}

// With the host layout, the backend records every lane 1 preflight check
// of the catalog exactly once, with its catalog class, and on a host that
// matches the profile they all pass (the socket owner only as root).
func TestEngineChecksCoverTheCatalogAndPassOnAMatchingHost(t *testing.T) {
	h := newHost(t)
	b := h.backend()
	b.config.Layout = layoutFor(h)
	checks := b.EngineChecks(context.Background())
	want := laneOnePreflightIDs()
	if len(checks) != len(want) {
		t.Fatalf("recorded %d checks, want the %d lane 1 preflight ids %v", len(checks), len(want), want)
	}
	for _, id := range want {
		c, ok := checkByID(checks, id)
		switch {
		case !ok:
			t.Errorf("%s not recorded", id)
		case c.Class != catalogClass(id):
			t.Errorf("%s class %s, want %s", id, c.Class, catalogClass(id))
		case id == "engine.socket_dedicated" && os.Geteuid() != 0:
			if c.Status != sandboxhost.StatusFail || !strings.Contains(c.Evidence, "root:root") {
				t.Errorf("socket owned by uid %d: %s %s, want a failure naming root:root", os.Geteuid(), c.Status, c.Evidence)
			}
		case c.Status != sandboxhost.StatusPass:
			t.Errorf("%s %s: %s", id, c.Status, c.Evidence)
		}
	}
}

// Each lane 1 check fails for its own reason, and only that check fails.
func TestEngineChecksFailForTheirOwnReason(t *testing.T) {
	for _, test := range []struct {
		id     string
		mutate func(*host, *Layout)
		want   string
	}{
		{id: "engine.socket_dedicated", mutate: func(h *host, l *Layout) { l.RunRoot = filepath.Join(l.RunRoot, "elsewhere") }, want: "not under the run root"},
		{id: "engine.socket_dedicated", mutate: func(h *host, _ *Layout) {
			if err := os.Chmod(strings.TrimPrefix(h.config.DockerHost, "unix://"), 0o666); err != nil {
				h.t.Fatal(err)
			}
		}, want: "mode 0660"},
		{id: "engine.version_pinned", mutate: func(h *host, _ *Layout) { h.engine.version = "28.1.0" }, want: "only " + PinnedDockerVersion},
		{id: "engine.data_root_on_data_fs", mutate: func(h *host, _ *Layout) {
			h.config.DataRoot, h.engine.info["DockerRootDir"] = "/proc", "/proc"
		}, want: "not on the data filesystem"},
		{id: "engine.storage_overlay2_xfs", mutate: func(h *host, _ *Layout) {
			h.engine.info["DriverStatus"] = [][]string{{"Backing Filesystem", "extfs"}, {"Supports d_type", "true"}}
		}, want: "want xfs"},
		{id: "engine.cgroup_driver_systemd_v2", mutate: func(h *host, _ *Layout) { h.engine.info["CgroupDriver"] = "cgroupfs" }, want: "want root="},
		{id: "engine.containerd_dedicated", mutate: func(_ *host, l *Layout) { l.ContainerdNamespace = "other" }, want: "differs from the host profile"},
		{id: "engine.containerd_dedicated", mutate: func(_ *host, l *Layout) {
			_ = os.RemoveAll(filepath.Join(l.DataFS, "containerd"))
		}, want: "containerd metadata"},
		{id: "engine.network_management_off", mutate: func(h *host, _ *Layout) {
			h.engine.networks = append(h.engine.networks, map[string]string{"Name": "bridge", "Driver": "bridge"})
		}, want: "no bridge"},
		{id: "engine.firewall_management_off", mutate: func(h *host, l *Layout) {
			writeFile(h.t, l.DaemonConfig, `{"iptables": true, "ip6tables": false, "ip-forward": false, "ip-masq": false, "bridge": "none", "log-driver": "json-file", "log-opts": {"max-size": "2m", "max-file": "2"}}`)
		}, want: "iptables false"},
		{id: "engine.runtime_runsc_pinned", mutate: func(_ *host, l *Layout) { l.RuntimeArgs = []string{"--overlay2=none", "--systemd-cgroup"} }, want: "differ from the host profile"},
		{id: "engine.default_bounded_logs", mutate: func(h *host, _ *Layout) { h.engine.info["LoggingDriver"] = "journald" }, want: "want json-file"},
		{id: "engine.default_bounded_logs", mutate: func(_ *host, l *Layout) { l.LogMaxSizeMiB = 8 }, want: "options"},
		{id: "engine.insecure_registries_empty", mutate: func(h *host, _ *Layout) {
			h.engine.info["RegistryConfig"].(map[string]any)["Mirrors"] = []string{"https://mirror.internal.example/"}
		}, want: "mirrors"},
		{id: "engine.no_unlabelled_containers", mutate: func(h *host, _ *Layout) {
			h.engine.containers["web"] = &engineContainer{Name: "web", Labels: map[string]string{}}
		}, want: "must be dedicated"},
	} {
		t.Run(test.id+" "+test.want, func(t *testing.T) {
			h := newHost(t)
			layout := layoutFor(h)
			test.mutate(h, layout)
			b := h.backend()
			b.config.Layout = layout
			for _, c := range b.EngineChecks(context.Background()) {
				failed := c.Status != sandboxhost.StatusPass
				if c.ID == "engine.socket_dedicated" && os.Geteuid() != 0 && test.id != c.ID {
					continue // fails on its owner when not root; covered above
				}
				switch {
				case c.ID == test.id && (!failed || !strings.Contains(c.Evidence, test.want)):
					t.Errorf("%s %s: %s, want a failure containing %q", c.ID, c.Status, c.Evidence, test.want)
				case c.ID != test.id && failed:
					t.Errorf("%s also failed: %s", c.ID, c.Evidence)
				}
			}
		})
	}
}

// The two configured checks are not run without the daemon configuration,
// and Open does not refuse a host for a check that did not run.
func TestEngineChecksWithoutALayout(t *testing.T) {
	h := newHost(t)
	checks := h.backend().EngineChecks(context.Background())
	for _, id := range []string{"engine.firewall_management_off", "engine.default_bounded_logs"} {
		if c, ok := checkByID(checks, id); !ok || c.Status != sandboxhost.StatusNotRun {
			t.Errorf("%s = %+v, want not_run", id, c)
		}
	}
	if _, err := Open(context.Background(), h.config); err != nil {
		t.Fatalf("Open = %v on a host whose observed engine checks pass", err)
	}
}

// testProfile is a valid host profile whose backend values match the
// scripted host.
func testProfile(h *host, layout *Layout) sandboxhost.Profile {
	h.t.Helper()
	raw := `{"schema": "miss.computer/misscomputer-subnet/sandbox-host-profile", "schema_version": 1,
		"docker_host": "` + h.config.DockerHost + `",
		"containerd": {"address": "` + layout.ContainerdAddress + `", "namespace": "mc-sandbox", "plugins_namespace": "mc-sandbox-plugins"},
		"data_root": "` + layout.DataFS + `", "docker_data_root": "` + h.config.DataRoot + `", "run_root": "` + layout.RunRoot + `",
		"runtime": {"name": "runsc", "path": "` + h.config.RunscPath + `", "sha256": "` + h.config.RunscSHA256 + `",
			"sentry_path": "` + h.config.SentryPath + `", "sentry_sha256": "` + h.config.SentrySHA256 + `",
			"args": ["--systemd-cgroup", "--overlay2=none"], "release": "release-20261005.0"},
		"engine": {"docker_version": "` + PinnedDockerVersion + `", "egress_table": "mcsbx_engine_egress"},
		"cgroup_root": "` + h.config.CgroupRoot + `", "lease_slice": "mcsbxlease.slice", "engine_slice": "mcsbxengine.slice",
		"aggregate": {"cpu_millis": 2000, "memory_mib": 2048, "pids": 8192, "data_fs_mib": 4096, "run_tmpfs_mib": 64,
			"image_reserve_mib": 512, "engine_overhead_mib": 512, "image_max_mib": 64, "log_mib": 4, "disk_mib": 1024, "sandboxes": 2},
		"per_lease": {"default_writable_mib": 64, "log_max_size_mib": 2, "log_max_file": 2, "pids_max": 4096,
			"mounts": "none", "image_volumes": "refuse", "network_modes": ["none"], "isolation": ["gvisor"]}}`
	profile, err := sandboxhost.DecodeProfile([]byte(raw))
	if err != nil {
		h.t.Fatal(err)
	}
	return profile
}

// The profile is the backend's only configuration source, and a profile
// pinning another Docker version is refused.
func TestConfigFromProfile(t *testing.T) {
	h := newHost(t)
	layout := layoutFor(h)
	profile := testProfile(h, layout)
	config, err := ConfigFromProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	if config.DockerHost != h.config.DockerHost || config.DataRoot != h.config.DataRoot || config.Slice != "mcsbxlease.slice" ||
		config.PIDsMax != 4096 || config.DiskMiB != 1024 || config.Sandboxes != 2 || config.ImageMaxMiB != 64 || config.LogMiB != 4 ||
		config.Layout.DataFS != layout.DataFS || config.Layout.RunRoot != layout.RunRoot || config.Layout.LogMaxSizeMiB != 2 {
		t.Fatalf("config %+v layout %+v does not follow the profile", config, config.Layout)
	}
	profile.Engine.DockerVersion = "28.1.0"
	if _, err := ConfigFromProfile(profile); err == nil || !strings.Contains(err.Error(), "only "+PinnedDockerVersion) {
		t.Fatalf("ConfigFromProfile = %v for another docker version", err)
	}
}

// OpenFromProfile merges this backend's engine checks with the host checks
// into one preflight report and refuses the backend unless it passes. The
// scripted host is not a provisioned host, so the host checks fail and no
// backend is returned; the report still records every lane 1 check once.
func TestOpenFromProfileRefusesUnlessTheReportPasses(t *testing.T) {
	h := newHost(t)
	layout := layoutFor(h)
	profile := testProfile(h, layout)
	backend, report, err := OpenFromProfile(context.Background(), profile, layout.DaemonConfig,
		sandboxhost.Host{Proc: h.config.ProcRoot, ListNFTable: func(string, bool) (string, error) { return "", errors.New("no nft here") }}, nil)
	if backend != nil || !errors.Is(err, sandboxhost.ErrNotPassed) {
		t.Fatalf("OpenFromProfile = %v, %v, want no backend and a failed report", backend, err)
	}
	if report.Mode != sandboxhost.ModePreflight || report.Verdict != sandboxhost.StatusFail {
		t.Fatalf("report mode %q verdict %q", report.Mode, report.Verdict)
	}
	for _, id := range laneOnePreflightIDs() {
		c, ok := checkByID(report.Checks, id)
		if !ok || c.Status == sandboxhost.StatusNotRun {
			t.Errorf("report %s = %+v, want it recorded by the backend", id, c)
		}
	}
	if c, ok := checkByID(report.Checks, "cgroup.lease_slice_finite"); !ok || c.Status != sandboxhost.StatusFail {
		t.Errorf("host check cgroup.lease_slice_finite = %+v, want the scripted host to fail it", c)
	}
}

// A served sandbox is observed by lane 2's instance checks and logged as
// one instance report; a failed observation of a live process is a miner
// fault, and one of a process that ended in between is the D11 path.
func TestCreateObservesAndReportsTheInstance(t *testing.T) {
	scope := "/mc.slice/" + testSlice + "/docker-1.scope"
	resources := testLease(nil).Resources
	pass := func(int) []sandboxhost.Check {
		return []sandboxhost.Check{
			{ID: "lease.runtime_processes_in_finite_cgroups", Class: sandboxhost.ObservedState, Status: sandboxhost.StatusPass, Evidence: "runsc in lease slice"},
			{ID: "lease.host_netns_lo_only_no_routes", Class: sandboxhost.ObservedState, Status: sandboxhost.StatusPass, Evidence: "only lo"},
		}
	}
	netFails := func(h *host, removeProcess bool) func(int) []sandboxhost.Check {
		return func(pid int) []sandboxhost.Check {
			if removeProcess {
				if err := os.RemoveAll(filepath.Join(h.config.ProcRoot, strconv.Itoa(pid))); err != nil {
					h.t.Fatal(err)
				}
				h.engine.mu.Lock()
				for _, c := range h.engine.containers {
					c.Status, c.FinishedAt = "exited", "2026-10-14T12:00:02.5Z"
				}
				h.engine.mu.Unlock()
			}
			checks := pass(pid)
			checks[1].Status, checks[1].Evidence = sandboxhost.StatusFail, "interfaces [lo eth0], want only lo"
			return checks
		}
	}
	for _, test := range []struct {
		name     string
		observe  func(h *host) func(int) []sandboxhost.Check
		want     string // "" for served
		decision string // the instance report's decision, "" for none
	}{
		{name: "observation passes", observe: func(*host) func(int) []sandboxhost.Check { return pass }, decision: "running"},
		{name: "live process fails the observation", observe: func(h *host) func(int) []sandboxhost.Check { return netFails(h, false) },
			want: "host observation lease.host_netns_lo_only_no_routes fail"},
		{name: "process ends during the observation", observe: func(h *host) func(int) []sandboxhost.Check { return netFails(h, true) },
			decision: "exited"},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newHost(t)
			h.process(h.sentry, scope, resources)
			b := h.backend()
			layout := layoutFor(h)
			profile := testProfile(h, layout)
			b.profile, b.observeInstance = &profile, test.observe(h)
			logs := captureLogs(t)
			lease := testLease(nil)
			err := b.Create(context.Background(), instanceOf(lease), lease)
			switch {
			case test.want == "" && err != nil:
				t.Fatalf("create = %v, want served", err)
			case test.want != "" && (err == nil || refusalCode(err) != "" || !strings.Contains(err.Error(), test.want)):
				t.Fatalf("create = %v, want a miner fault containing %q", err, test.want)
			}
			got := logs("sandbox instance report")
			if exited := logs("sandbox exit attribution"); (test.decision == "exited") != (len(exited) == 1) {
				t.Errorf("exit records %v, want one only when the process ended", exited)
			}
			if test.decision == "" {
				if len(got) != 0 {
					t.Fatalf("instance reports %v for a fault", got)
				}
				return
			}
			if len(got) != 1 || got[0]["decision"] != test.decision {
				t.Fatalf("instance reports %v, want one %q", got, test.decision)
			}
			report := got[0]["report"].(map[string]any)
			if report["mode"] != sandboxhost.ModeInstance || report["verdict"] == nil {
				t.Fatalf("report %v is not an instance report", report)
			}
			statuses := map[string]string{}
			for _, raw := range report["checks"].([]any) {
				c := raw.(map[string]any)
				statuses[c["id"].(string)] = c["status"].(string)
			}
			want := map[string]string{"lease.engine_config_matches": "pass", "lease.sentry_pinned_exe": "pass",
				"lease.child_limits_match": "pass", "lease.host_netns_lo_only_no_routes": "pass"}
			if test.decision == "exited" {
				want = map[string]string{"lease.engine_config_matches": "pass", "lease.sentry_pinned_exe": "not_run",
					"lease.child_limits_match": "not_run", "lease.host_netns_lo_only_no_routes": "not_run"}
			}
			for id, status := range want {
				if statuses[id] != status {
					t.Errorf("instance report %s = %q, want %q", id, statuses[id], status)
				}
			}
		})
	}
}

// Every create logs how it used its budget (contract D15(d), SR-34-02).
func TestCreateLogsItsBudgetUse(t *testing.T) {
	h := newHost(t)
	records := captureRecords(t, "sandbox create timing")
	lease := testLease(nil)
	if err := h.backend().Create(context.Background(), instanceOf(lease), lease); err != nil {
		t.Fatal(err)
	}
	got := records()
	if len(got) != 1 || got[0]["outcome"] != "ok" || got[0]["sandbox"] != instanceOf(lease) || got[0]["local_reserve"] != localStepReserve.String() {
		t.Fatalf("timing records %v", got)
	}
	for _, key := range []string{"pull_elapsed", "pull_share", "local_elapsed"} {
		if _, ok := got[0][key].(string); !ok {
			t.Errorf("timing record lacks %s: %v", key, got[0])
		}
	}
}
