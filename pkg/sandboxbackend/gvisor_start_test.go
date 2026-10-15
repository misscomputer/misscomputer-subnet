// SPDX-License-Identifier: AGPL-3.0-only

package sandboxbackend

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// startFailure is the message of the never-started shapes the disposable
// host recorded (lane-2 run 38661083069), whose prefix a host-side runtime
// failure shares.
const startFailure = "OCI runtime start failed: starting container: starting root container: starting sandbox: creating process: failed to load /no/such/command: no such file or directory"

// A start request the engine answers with an error is the image's
// (image_unavailable) only in the never-started shape with nothing of the
// instance left anywhere and the container removed (contract D23); every
// other case stays a miner fault. Message text, exit code and exit time do
// not decide: the same text is non-fault never started and a fault started.
func TestCreateAttributesAStartTheEngineRefused(t *testing.T) {
	// neverStarted leaves the container "created" with no start time, as
	// the host recorded; the engine still sets an exit time.
	neverStarted := func(message string) func(*engineContainer) (int, string) {
		return func(c *engineContainer) (int, string) {
			c.Error, c.FinishedAt = message, "2026-10-15T00:38:35.15270573Z"
			return http.StatusInternalServerError, message
		}
	}
	// reference scripts a host process outside the slice with the given
	// executable (a function of the host, "" for none), arguments and
	// cgroup; "%s" is the engine's container ID.
	reference := func(pid string, exe func(*host) string, cmdline, cgroup string) func(*host, string) {
		return func(h *host, id string) {
			dir := filepath.Join(h.config.ProcRoot, pid)
			writeFile(h.t, filepath.Join(dir, "cmdline"), strings.ReplaceAll(cmdline, "%s", id))
			writeFile(h.t, filepath.Join(dir, "cgroup"), "0::"+strings.ReplaceAll(cgroup, "%s", id)+"\n")
			if exe != nil {
				if err := os.Symlink(exe(h), filepath.Join(dir, "exe")); err != nil {
					h.t.Fatal(err)
				}
			}
		}
	}
	runsc := func(h *host) string { return h.config.RunscPath }
	// operatorTool is a program that is neither runsc nor the sentry.
	operatorTool := func(h *host) string {
		tool := filepath.Join(h.t.TempDir(), "docker")
		writeFile(h.t, tool, "operator tool")
		return tool
	}
	deleted := func(h *host) string { return filepath.Join(h.t.TempDir(), "runsc (deleted)") }
	for _, test := range []struct {
		name    string
		applied func(*engineContainer)
		refuse  func(*engineContainer) (int, string)
		setup   func(h *host, containerID string)
		drop    bool
		// want is "" for image_unavailable, else the miner fault.
		want string
		// decision is the recorded D23 decision; "" when the start never
		// reached D23.
		decision string
	}{
		{name: "missing command", refuse: neverStarted(startFailure), decision: "never_started"},
		{name: "not executable", refuse: neverStarted(strings.Replace(startFailure, "no such file or directory", "permission denied", 1)), decision: "never_started"},
		{name: "wrong architecture", refuse: neverStarted(strings.Replace(startFailure, "no such file or directory", "exec format error", 1)), decision: "never_started"},
		{name: "host-sounding text", refuse: neverStarted("OCI runtime start failed: cgroup: permission denied"), decision: "never_started"},
		{name: "no text at all", refuse: neverStarted(""), decision: "never_started"},
		{name: "no exit time", refuse: func(c *engineContainer) (int, string) {
			c.Error = startFailure
			return http.StatusInternalServerError, startFailure
		}, decision: "never_started"},
		// The same text in a started shape is not never-started.
		{name: "same text, workload started and exited", refuse: func(c *engineContainer) (int, string) {
			c.Status, c.Error, c.StartedAt, c.FinishedAt = "exited", startFailure, "2026-10-15T00:38:35.1Z", "2026-10-15T00:38:35.2Z"
			return http.StatusInternalServerError, startFailure
		}, want: "workload started", decision: "fault: workload started"},
		{name: "same text, workload running", refuse: func(c *engineContainer) (int, string) {
			c.Status, c.Error, c.StartedAt = "running", startFailure, "2026-10-15T00:38:35.1Z"
			return http.StatusInternalServerError, startFailure
		}, want: "workload started", decision: "fault: workload started"},
		{name: "running with no start time", refuse: func(c *engineContainer) (int, string) {
			c.Status, c.Error = "running", startFailure
			return http.StatusInternalServerError, startFailure
		}, want: "workload started", decision: "fault: workload started"},
		{name: "daemon gives no answer to the start", refuse: func(*engineContainer) (int, string) { return -1, "" }, want: "start sandbox"},
		{name: "re-inspection not answered", refuse: neverStarted(startFailure), drop: true,
			want: "re-inspection not answered", decision: "fault: re-inspection not answered"},
		{name: "engine configuration changed by the failed start", refuse: func(c *engineContainer) (int, string) {
			c.Host["Runtime"] = "runc"
			return neverStarted(startFailure)(c)
		}, want: "runtime is", decision: "fault: engine configuration"},
		{name: "process remains below the slice", refuse: neverStarted(startFailure), setup: func(h *host, _ string) {
			writeFile(h.t, filepath.Join(h.config.CgroupRoot, "mc.slice", testSlice, "docker-x.scope", "cgroup.procs"), "4243\n")
		}, want: "processes remain", decision: "fault: processes of the instance remain"},
		{name: "runsc in the engine slice names the container", refuse: neverStarted(startFailure),
			setup: reference("5000", runsc, "runsc\x00--root\x00/run/runsc\x00delete\x00%s\x00", "/mc-engine.slice/containerd.service"),
			want:  "refer to container", decision: "fault: processes of the instance remain"},
		{name: "process with a deleted executable names the container", refuse: neverStarted(startFailure),
			setup: reference("5003", deleted, "runsc\x00delete\x00%s\x00", "/mc-engine.slice/containerd.service"),
			want:  "refer to container", decision: "fault: processes of the instance remain"},
		{name: "process cgroup outside the slice names the container", refuse: neverStarted(startFailure),
			setup: reference("5001", nil, "sleep\x00", "/system.slice/docker-%s.scope"),
			want:  "refer to container", decision: "fault: processes of the instance remain"},
		// An operator's shell or tool may name the container it inspects;
		// its arguments are not a process of the instance.
		{name: "operator tool names the container", refuse: neverStarted(startFailure),
			setup:    reference("5004", operatorTool, "docker\x00logs\x00%s\x00", "/user.slice/session-1.scope"),
			decision: "never_started"},
		{name: "host process table unreadable", refuse: neverStarted(startFailure), setup: func(h *host, _ string) {
			if err := os.MkdirAll(filepath.Join(h.config.ProcRoot, "5002", "cgroup"), 0o755); err != nil {
				h.t.Fatal(err)
			}
		}, want: "host processes unreadable", decision: "fault: host processes unreadable"},
		{name: "cleanup fails", refuse: neverStarted(startFailure), setup: func(h *host, _ string) { h.engine.failDelete = true },
			want: "cleanup", decision: "fault: cleanup"},
		{name: "engine misconfigured before the start", applied: func(c *engineContainer) { c.Host["Runtime"] = "runc" },
			refuse: neverStarted(startFailure), want: "runtime is"},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newHost(t)
			lease := testLease(nil)
			instance := instanceOf(lease)
			containerID := containerIDOf(instance)
			h.engine.applied, h.engine.refuseStart = test.applied, test.refuse
			if test.drop {
				h.engine.dropInspect = func(c *engineContainer) bool { return c.Error != "" }
			}
			if test.setup != nil {
				test.setup(h, containerID)
			}
			records := captureAttributions(t)
			err := h.backend().Create(context.Background(), instance, lease)
			switch {
			case test.want == "" && refusalCode(err) != "image_unavailable":
				t.Fatalf("create = %v, want image_unavailable", err)
			case test.want != "" && (err == nil || refusalCode(err) != "" || !strings.Contains(err.Error(), test.want)):
				t.Fatalf("create = %v, want a miner fault containing %q", err, test.want)
			}
			if test.want == "" && (len(h.engine.containers) != 0 || len(h.engine.images) != 0) {
				t.Fatalf("never-started sandbox left %d containers and %d images", len(h.engine.containers), len(h.engine.images))
			}
			if test.applied != nil && h.engine.starts != 0 {
				t.Fatalf("engine was asked to start a container it misconfigured")
			}
			got := records()
			if test.decision == "" {
				if len(got) != 0 {
					t.Fatalf("recorded %d D23 decisions for a start that never reached D23", len(got))
				}
				return
			}
			if len(got) != 1 || got[0]["decision"] != test.decision || got[0]["container_id"] != containerID || got[0]["sandbox"] != instance {
				t.Fatalf("records = %v, want one %q decision for %s", got, test.decision, containerID)
			}
		})
	}
}

// The runtime tears down a failed start asynchronously: a runtime process
// naming the container, or a process entry that cannot be read, that is
// gone within the settle bound does not make the never-started failure a
// fault, and the record shows what was finally observed.
func TestCreateWaitsForAFailedStartToSettle(t *testing.T) {
	for name, transient := range map[string]func(h *host, dir, containerID string){
		"runsc naming the container exits": func(h *host, dir, containerID string) {
			writeFile(t, filepath.Join(dir, "cmdline"), "runsc\x00delete\x00"+containerID+"\x00")
			writeFile(t, filepath.Join(dir, "cgroup"), "0::/mc-engine.slice/containerd.service\n")
			if err := os.Symlink(h.config.RunscPath, filepath.Join(dir, "exe")); err != nil {
				t.Error(err)
			}
		},
		"unreadable process entry goes away": func(_ *host, dir, _ string) {
			if err := os.MkdirAll(filepath.Join(dir, "cgroup"), 0o755); err != nil {
				t.Error(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHost(t)
			lease := testLease(nil)
			instance := instanceOf(lease)
			dir := filepath.Join(h.config.ProcRoot, "5000")
			h.engine.refuseStart = func(c *engineContainer) (int, string) {
				c.Error = startFailure
				transient(h, dir, containerIDOf(instance))
				time.AfterFunc(200*time.Millisecond, func() { _ = os.RemoveAll(dir) })
				return http.StatusInternalServerError, startFailure
			}
			records := captureAttributions(t)
			if err := h.backend().Create(context.Background(), instance, lease); refusalCode(err) != "image_unavailable" {
				t.Fatalf("create = %v, want image_unavailable once the runtime settled", err)
			}
			got := records()
			if len(got) != 1 {
				t.Fatalf("records = %v, want one", got)
			}
			record := got[0]
			settled, err := time.ParseDuration(record["settled"].(string))
			if err != nil || settled < 200*time.Millisecond || settled > startSettleBound {
				t.Fatalf("settled %v (%v), want between the entry going away and the bound", record["settled"], err)
			}
			for key, want := range map[string]any{
				"decision": "never_started", "start_status": float64(http.StatusInternalServerError), "reinspect_answered": true,
				"running": false, "pid": float64(0), "slice_quiet": true, "runtime_references": nil, "scan_error": "",
				"cleaned_up": true, "settle_bound": startSettleBound.String(), "per_process_checks": "not_run",
			} {
				if record[key] != want {
					t.Errorf("record %s = %v, want %v", key, record[key], want)
				}
			}
		})
	}
}

// captureAttributions records the D23 attribution events logged until the
// returned func is called.
func captureAttributions(t *testing.T) func() []map[string]any {
	t.Helper()
	return captureRecords(t, "sandbox start attribution")
}

// captureRecords records the events with message msg logged until the
// returned func is called.
func captureRecords(t *testing.T, msg string) func() []map[string]any {
	t.Helper()
	logs := captureLogs(t)
	return func() []map[string]any { return logs(msg) }
}

// captureLogs records every event logged until the returned func, which
// selects the events with one message, is called.
func captureLogs(t *testing.T) func(msg string) []map[string]any {
	t.Helper()
	var buffer bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buffer, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return func(msg string) []map[string]any {
		var records []map[string]any
		for _, line := range strings.Split(strings.TrimSpace(buffer.String()), "\n") {
			var record map[string]any
			if json.Unmarshal([]byte(line), &record) == nil && record["msg"] == msg {
				records = append(records, record)
			}
		}
		return records
	}
}
