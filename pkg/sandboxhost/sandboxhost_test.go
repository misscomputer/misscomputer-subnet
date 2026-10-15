// SPDX-License-Identifier: AGPL-3.0-only

package sandboxhost

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type vectors struct {
	Valid       map[string]any `json:"valid"`
	ValidDigest string         `json:"valid_digest"`
	Invalid     []struct {
		Name  string   `json:"name"`
		Path  []string `json:"path"`
		Value any      `json:"value"`
	} `json:"invalid"`
}

func loadVectors(t *testing.T) vectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/profile-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func encode(t *testing.T, doc map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// The same vectors drive scripts/sandbox-host/report.py, so the Go and
// Python sides accept, reject and hash profiles identically.
func TestProfileVectorsMatchPythonReportTool(t *testing.T) {
	v := loadVectors(t)
	profile, err := DecodeProfile(encode(t, v.Valid))
	if err != nil {
		t.Fatal(err)
	}
	if digest, err := profile.Digest(); err != nil || digest != v.ValidDigest {
		t.Fatalf("digest %q, %v; want %q", digest, err, v.ValidDigest)
	}
	for _, c := range v.Invalid {
		t.Run(c.Name, func(t *testing.T) {
			var doc map[string]any
			if err := json.Unmarshal(encode(t, v.Valid), &doc); err != nil {
				t.Fatal(err)
			}
			target := doc
			for _, key := range c.Path[:len(c.Path)-1] {
				target = target[key].(map[string]any)
			}
			target[c.Path[len(c.Path)-1]] = c.Value
			if _, err := DecodeProfile(encode(t, doc)); err == nil {
				t.Fatal("profile accepted")
			}
		})
	}
}

func complete(mode string) []Check {
	var checks []Check
	for _, entry := range Catalog() {
		if entry.inMode(mode) {
			status := StatusPass
			if entry.Class == Unenforced {
				status = StatusGap
			}
			checks = append(checks, Check{ID: entry.ID, Class: entry.Class, Status: status, Evidence: "observed"})
		}
	}
	return checks
}

func TestBuildReportDerivesVerdictAndRejectsRelabelledEvidence(t *testing.T) {
	profile, err := DecodeProfile(encode(t, loadVectors(t).Valid))
	if err != nil {
		t.Fatal(err)
	}
	report, err := BuildReport(ModePreflight, profile, complete(ModePreflight), Environment{})
	if err != nil || RequirePass(report) != nil || len(report.Unenforced) == 0 {
		t.Fatalf("complete report: %s, %v", report.Verdict, err)
	}

	report, err = BuildReport(ModePreflight, profile, complete(ModePreflight)[1:], Environment{})
	if err != nil {
		t.Fatal(err)
	}
	if err := RequirePass(report); !errors.Is(err, ErrNotPassed) || !strings.Contains(err.Error(), "host.cgroup2_mount_authentic not_run") {
		t.Fatalf("missing check: %v", err)
	}

	// An unenforced check left not_run must fail the verdict (SR-27-10).
	notRun := complete(ModePreflight)
	for i := range notRun {
		if notRun[i].Class == Unenforced {
			notRun[i].Status = StatusNotRun
			break
		}
	}
	if report, err := BuildReport(ModePreflight, profile, notRun, Environment{}); err != nil || report.Passed() || RequirePass(report) == nil {
		t.Fatalf("unenforced check not_run passed: %s, %v", report.Verdict, err)
	}
	if _, err := BuildReport(ModePreflight, profile, append(complete(ModePreflight), complete(ModePreflight)[0]), Environment{}); err == nil || !strings.Contains(err.Error(), "recorded twice") {
		t.Fatalf("duplicate check accepted: %v", err)
	}
	// RequirePass derives the verdict; a decoded report claiming pass over a failed check is refused.
	forged, err := BuildReport(ModePreflight, profile, complete(ModePreflight), Environment{})
	if err != nil {
		t.Fatal(err)
	}
	forged.Checks[0].Status = StatusFail
	raw, err := json.Marshal(forged)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Report
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Verdict != StatusPass || RequirePass(decoded) == nil {
		t.Fatalf("decoded report with stored verdict %q over a failed check passed RequirePass", decoded.Verdict)
	}

	relabel := map[string]func([]Check){
		"observation as setting": func(checks []Check) {
			for i := range checks {
				if checks[i].Class == ObservedState {
					checks[i].Class = Configured
					return
				}
			}
		},
		"gap as enforcement": func(checks []Check) {
			for i := range checks {
				if checks[i].Class == Unenforced {
					checks[i].Status = StatusPass
					return
				}
			}
		},
		"lab effect in live preflight": func(checks []Check) {
			checks[0] = Check{ID: "effect.writable_layer_quota", Class: ObservedEffect, Status: StatusPass}
		},
	}
	for name, mutate := range relabel {
		checks := complete(ModePreflight)
		mutate(checks)
		if _, err := BuildReport(ModePreflight, profile, checks, Environment{}); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// fakeHost builds a procfs and cgroup tree in a temporary directory, the
// way an agent container sees the host's procfs at a non-default mount.
type fakeHost struct {
	t            *testing.T
	proc, cgroup string
}

func newFakeHost(t *testing.T) *fakeHost {
	dir := t.TempDir()
	f := &fakeHost{t: t, proc: filepath.Join(dir, "proc"), cgroup: filepath.Join(dir, "cgroup")}
	f.write(f.proc, "self/cgroup", "0::/system.slice/agent.service\n")
	f.write(f.proc, "self/mountinfo", "")
	f.write(f.proc, "net/unix", "Num RefCount Protocol Flags Type St Inode Path\n")
	return f
}

func (f *fakeHost) write(root, name, content string) {
	f.t.Helper()
	full := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fakeHost) slice(name, cpu, memory, swap, pids string) {
	for file, value := range map[string]string{"cpu.max": cpu, "memory.max": memory, "memory.swap.max": swap, "pids.max": pids} {
		f.write(f.cgroup, name+"/"+file, value+"\n")
	}
}

func (f *fakeHost) process(pid, exe, cgroup string) {
	f.write(f.proc, pid+"/cgroup", "0::"+cgroup+"\n")
	if err := os.Symlink(exe, filepath.Join(f.proc, pid, "exe")); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fakeHost) profile() Profile {
	f.t.Helper()
	v := loadVectors(f.t)
	v.Valid["cgroup_root"] = f.cgroup
	profile, err := DecodeProfile(encode(f.t, v.Valid))
	if err != nil {
		f.t.Fatal(err)
	}
	return profile
}

func find(checks []Check, id string) Check {
	for _, c := range checks {
		if c.ID == id {
			return c
		}
	}
	return Check{ID: id, Status: "absent"}
}

func TestPreflightReadsActualSliceLimits(t *testing.T) {
	f := newFakeHost(t)
	f.slice("mcsbxlease.slice", "200000 100000", "1073741824", "0", "1024")
	f.slice("mcsbxengine.slice", "max 100000", "1610612736", "0", "4096")
	checks := Host{Proc: f.proc, ListNFTable: func(string) (string, error) { return egressListing, nil }}.Preflight(f.profile(), []string{"/deploy.slice"})
	for _, id := range []string{"cgroup.lease_slice_finite", "cgroup.lease_slice_swap_zero", "cgroup.engine_slice_finite", "cgroup.pids_finite_covers_sum", "cgroup.disjoint_from_caller", "network.engine_egress_restricted"} {
		if c := find(checks, id); c.Status != StatusPass {
			t.Errorf("%s: %+v", id, c)
		}
	}
	// A temporary directory is neither cgroup2 nor xfs, and nothing listens
	// on the engine sockets: those checks must fail, never pass vacuously.
	for _, id := range []string{"host.cgroup2_mount_authentic", "storage.data_fs_xfs_prjquota", "storage.run_root_tmpfs_finite", "cgroup.engine_processes_member", "budget.within_observed"} {
		if c := find(checks, id); c.Status != StatusFail {
			t.Errorf("%s: %+v", id, c)
		}
	}
	report, err := BuildReport(ModePreflight, f.profile(), checks, Environment{})
	if err != nil || report.Passed() {
		t.Fatalf("report %v passed=%v", err, report.Passed())
	}
}

func TestPreflightRejectsUnboundedSharedOrSubstitutedSlices(t *testing.T) {
	finiteLease := func(f *fakeHost) { f.slice("mcsbxlease.slice", "200000 100000", "1073741824", "0", "1024") }
	cases := map[string]struct {
		setup     func(f *fakeHost)
		exclusive []string
		id, want  string
	}{
		"memory max":               {func(f *fakeHost) { f.slice("mcsbxlease.slice", "200000 100000", "max", "0", "1024") }, nil, "cgroup.lease_slice_finite", "not all finite"},
		"swap allowed":             {func(f *fakeHost) { f.slice("mcsbxlease.slice", "200000 100000", "1073741824", "max", "1024") }, nil, "cgroup.lease_slice_swap_zero", "memory.swap.max=-1"},
		"pids below sum":           {func(f *fakeHost) { f.slice("mcsbxlease.slice", "200000 100000", "1073741824", "0", "128") }, nil, "cgroup.pids_finite_covers_sum", "= 256"},
		"agent inside lease slice": {finiteLease, []string{"/mcsbxlease.slice/agent.scope"}, "cgroup.disjoint_from_caller", "overlaps"},
		"symlinked slice": {func(f *fakeHost) {
			f.slice("elsewhere.slice", "200000 100000", "1073741824", "0", "1024")
			if err := os.Symlink(filepath.Join(f.cgroup, "elsewhere.slice"), filepath.Join(f.cgroup, "mcsbxlease.slice")); err != nil {
				f.t.Fatal(err)
			}
		}, nil, "cgroup.lease_slice_finite", "open cgroup"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFakeHost(t)
			f.slice("mcsbxengine.slice", "max 100000", "1610612736", "0", "4096")
			c.setup(f)
			got := find(Host{Proc: f.proc, ListNFTable: func(string) (string, error) { return egressListing, nil }}.Preflight(f.profile(), c.exclusive), c.id)
			if got.Status != StatusFail || !strings.Contains(got.Evidence, c.want) {
				t.Fatalf("%+v", got)
			}
		})
	}
}

func TestPreflightRequiresEngineSocketHoldersInEngineSlice(t *testing.T) {
	f := newFakeHost(t)
	profile := f.profile()
	f.write(f.proc, "net/unix", "Num RefCount Protocol Flags Type St Inode Path\n"+
		"0: 00000002 00000000 00010000 0001 01 101 "+profile.DockerSocket()+"\n"+
		"0: 00000002 00000000 00010000 0001 01 102 "+profile.Containerd.Address+"\n")
	f.process("10", "/usr/bin/dockerd", "/mcsbxengine.slice/mcsbxdockerd.service")
	f.process("11", "/run/mcsbx/bin/containerd/containerd", "/system.slice/containerd.service")
	for pid, inode := range map[string]string{"10": "101", "11": "102"} {
		if err := os.MkdirAll(filepath.Join(f.proc, pid, "fd"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("socket:["+inode+"]", filepath.Join(f.proc, pid, "fd", "3")); err != nil {
			t.Fatal(err)
		}
	}
	got := find(Host{Proc: f.proc, ListNFTable: func(string) (string, error) { return egressListing, nil }}.Preflight(profile, nil), "cgroup.engine_processes_member")
	if got.Status != StatusFail || !strings.Contains(got.Evidence, "PID 11") || !strings.Contains(got.Evidence, "/system.slice/containerd.service") {
		t.Fatalf("containerd outside the engine slice: %+v", got)
	}
}

func TestObserveInstanceReadsTheSentryNetworkNamespaceAndRuntimeCgroups(t *testing.T) {
	const loOnly = "Inter-|   Receive\n face |bytes\n    lo: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"
	const routeHeader = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
	const v6lo = "00000000000000000000000000000001 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000001 00000000 80200001       lo\n"
	const scope = "/mcsbxlease.slice/docker-a.scope"
	cases := map[string]struct {
		dev, route, v6, goferCgroup string
		failID, want                string
	}{
		"isolated":        {loOnly, routeHeader, v6lo, scope, "", ""},
		"extra interface": {loOnly + "  eth0: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n", routeHeader, v6lo, scope, "lease.host_netns_lo_only_no_routes", "want only lo"},
		"ipv4 route":      {loOnly, routeHeader + "lo\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n", v6lo, scope, "lease.host_netns_lo_only_no_routes", "IPv4 routes"},
		"ipv6 route":      {loOnly, routeHeader, strings.Replace(v6lo, "      lo", "    eth0", 1), scope, "lease.host_netns_lo_only_no_routes", "IPv6 route via eth0"},
		"gofer unbounded": {loOnly, routeHeader, v6lo, "/user.slice/session-1.scope", "lease.runtime_processes_in_finite_cgroups", "unbounded cgroup /user.slice"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFakeHost(t)
			profile := f.profile()
			f.process("40", profile.Runtime.SentryPath, scope)
			f.process("41", profile.Runtime.Path, c.goferCgroup)
			f.process("42", "/usr/bin/bash", "/user.slice/session-1.scope") // not a runtime process
			f.write(f.proc, "40/net/dev", c.dev)
			f.write(f.proc, "40/net/route", c.route)
			f.write(f.proc, "40/net/ipv6_route", c.v6)
			checks := Host{Proc: f.proc}.ObserveInstance(profile, 40)
			for _, check := range checks {
				wantFail := check.ID == c.failID
				if (check.Status == StatusFail) != wantFail || (wantFail && !strings.Contains(check.Evidence, c.want)) {
					t.Errorf("%+v", check)
				}
			}
			if _, err := BuildReport(ModeInstance, profile, checks, Environment{}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

const egressListing = `table inet mcsbx_engine_egress {
	chain output {
		type filter hook output priority filter; policy accept;
		socket cgroupv2 level 1 "mcsbxengine.slice" ip daddr 127.0.0.53 meta l4proto { tcp, udp } th dport 53 accept
		socket cgroupv2 level 1 "mcsbxengine.slice" fib daddr type local counter packets 0 bytes 0 reject with icmpx admin-prohibited
		socket cgroupv2 level 1 "mcsbxengine.slice" ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.168.0.0/16, 198.18.0.0/15, 224.0.0.0/3 } counter packets 0 bytes 0 reject with icmpx admin-prohibited
		socket cgroupv2 level 1 "mcsbxengine.slice" ip6 daddr { ::/127, ::ffff:0.0.0.0/96, 64:ff9b::/96, 64:ff9b:1::/48, fc00::/7, fe80::/10, ff00::/8 } counter packets 0 bytes 0 reject with icmpx admin-prohibited
	}
}
`

func TestPreflightReadsBackTheEngineEgressRestriction(t *testing.T) {
	cases := map[string]struct {
		listing string
		err     error
		want    string
	}{
		"restricted":         {egressListing, nil, ""},
		"table absent":       {"", errors.New("No such file or directory"), "No such file"},
		"stale slice id":     {strings.ReplaceAll(egressListing, `"mcsbxengine.slice"`, "4242"), nil, "stale cgroup"},
		"metadata reachable": {strings.Replace(egressListing, "169.254.0.0/16, ", "", 1), nil, "169.254.0.0/16"},
		"extra accept rule":  {strings.Replace(egressListing, "accept\n", "accept\n\t\tsocket cgroupv2 level 1 \"mcsbxengine.slice\" ip daddr 10.0.0.5 accept\n", 1), nil, "unexpected engine egress rule"},
		"input hook only":    {strings.Replace(egressListing, "hook output", "hook input", 1), nil, "no output hook"},
		// SR-27-08: a public address on a host interface is covered by no fixed prefix.
		"host's own addresses reachable": {strings.Replace(egressListing, "\t\tsocket cgroupv2 level 1 \"mcsbxengine.slice\" fib daddr type local counter packets 0 bytes 0 reject with icmpx admin-prohibited\n", "", 1), nil, "fib daddr type local"},
		"local reject for IPv4 only":     {strings.Replace(egressListing, "\"mcsbxengine.slice\" fib daddr", "\"mcsbxengine.slice\" meta nfproto ipv4 fib daddr", 1), nil, "fib daddr type local"},
	}
	// Every denied prefix is required on its own (SR-27-10).
	for _, prefix := range egressDenied {
		listing := egressListing
		for _, form := range []string{prefix, strings.Replace(prefix, "::ffff:0:0/96", "::ffff:0.0.0.0/96", 1)} {
			listing = strings.Replace(listing, " "+form+",", "", 1)
			listing = strings.Replace(listing, ", "+form+" }", " }", 1)
		}
		cases["missing "+prefix] = struct {
			listing string
			err     error
			want    string
		}{listing, nil, "does not reject " + prefix}
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFakeHost(t)
			host := Host{Proc: f.proc, ListNFTable: func(table string) (string, error) {
				if table != "mcsbx_engine_egress" {
					t.Fatalf("listed table %q", table)
				}
				return c.listing, c.err
			}}
			got := find(host.Preflight(f.profile(), nil), "network.engine_egress_restricted")
			if wantPass := c.want == ""; (got.Status == StatusPass) != wantPass || !strings.Contains(got.Evidence, c.want) {
				t.Fatalf("%+v", got)
			}
		})
	}
}
