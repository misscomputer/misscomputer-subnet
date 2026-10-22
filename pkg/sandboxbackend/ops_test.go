// SPDX-License-Identifier: AGPL-3.0-only

package sandboxbackend

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/misscomputer/misscomputer-subnet/pkg/miner"
	"github.com/misscomputer/misscomputer-subnet/pkg/sandboxops"
)

// fakeOpsEngine scripts the attached-exec and ping endpoints: helper answers
// the stdin of each exec the way the helper in the container would.
type fakeOpsEngine struct {
	helper func(stdin []byte) (stdout, stderr []byte, exit int)
	bodies []map[string]any
	stdins [][]byte
	exits  map[string]int
	// pingDown fails the liveness check; dropCreate drops the exec create
	// connection without an answer.
	pingDown, dropCreate bool
	// runningInspects is how many inspects still report a finished exec
	// running, as dockerd can right after the stream closed.
	runningInspects int
}

func (e *fakeEngine) serveOps(w http.ResponseWriter, r *http.Request) bool {
	o, p := e.ops, r.URL.Path
	// The ops-mode image probe (D1) addresses its container by the ID the
	// create answered, which the engine accepts wherever it accepts a name,
	// and stats the helper target, which no fake image holds.
	if id, tail, ok := strings.Cut(strings.TrimPrefix(p, "/containers/"), "/"); strings.HasPrefix(p, "/containers/") && (ok || r.Method == http.MethodDelete) {
		if !ok {
			id, tail = strings.TrimPrefix(p, "/containers/"), ""
		}
		if r.Method == http.MethodHead && tail == "archive" {
			reply(w, 404, map[string]string{"message": "Could not find the file " + r.URL.Query().Get("path") + " in container " + id})
			return true
		}
		for name := range e.containers {
			if containerIDOf(name) == id {
				r.URL.Path = strings.TrimSuffix("/containers/"+name+"/"+tail, "/")
				e.mu.Unlock()
				defer e.mu.Lock()
				e.serve(w, r)
				return true
			}
		}
	}
	switch {
	case r.Method == http.MethodGet && p == "/_ping":
		if o == nil || o.pingDown {
			reply(w, 500, map[string]string{"message": "down"})
		} else {
			w.WriteHeader(200)
		}
	case o == nil:
		return false
	case r.Method == http.MethodPost && strings.HasPrefix(p, "/containers/") && strings.HasSuffix(p, "/exec"):
		if o.dropCreate {
			panic(http.ErrAbortHandler)
		}
		c, ok := e.containers[strings.TrimSuffix(strings.TrimPrefix(p, "/containers/"), "/exec")]
		if !ok {
			reply(w, 404, map[string]string{"message": "No such container"})
			return true
		}
		if c.Status != "running" {
			reply(w, 409, map[string]string{"message": "Container is not running"})
			return true
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		o.bodies = append(o.bodies, body)
		id := fmt.Sprintf("exec%d", len(o.bodies))
		reply(w, 201, map[string]string{"Id": id})
	case r.Method == http.MethodPost && strings.HasPrefix(p, "/exec/") && strings.HasSuffix(p, "/start"):
		id := strings.TrimSuffix(strings.TrimPrefix(p, "/exec/"), "/start")
		helper := o.helper
		// dockerd reads the start options before it upgrades.
		var options map[string]any
		_ = json.NewDecoder(r.Body).Decode(&options)
		e.mu.Unlock()
		defer e.mu.Lock()
		conn, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return true
		}
		defer conn.Close()
		_, _ = buffered.WriteString("HTTP/1.1 101 UPGRADED\r\nContent-Type: application/vnd.docker.raw-stream\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
		_ = buffered.Flush()
		stdin, _ := io.ReadAll(buffered.Reader)
		stdout, stderr, exit := helper(stdin)
		for _, frame := range []struct {
			stream byte
			data   []byte
		}{{2, stderr}, {1, stdout}} {
			if len(frame.data) == 0 {
				continue
			}
			var header [8]byte
			header[0] = frame.stream
			binary.BigEndian.PutUint32(header[4:], uint32(len(frame.data)))
			_, _ = conn.Write(header[:])
			_, _ = conn.Write(frame.data)
		}
		e.mu.Lock()
		o.stdins = append(o.stdins, stdin)
		if o.exits == nil {
			o.exits = map[string]int{}
		}
		o.exits[id] = exit
		e.mu.Unlock()
	case r.Method == http.MethodGet && strings.HasPrefix(p, "/exec/") && strings.HasSuffix(p, "/json"):
		running := o.runningInspects > 0
		if running {
			o.runningInspects--
		}
		reply(w, 200, map[string]any{"Running": running, "ExitCode": o.exits[strings.TrimSuffix(strings.TrimPrefix(p, "/exec/"), "/json")]})
	default:
		return false
	}
	return true
}

// pinnedHelper writes a helper directory the B-2 pin accepts: root-owned
// 0555 directory and file under root-owned, non-writable ancestors, seen
// through a read-only bind mount (MCR-04). It is created in the test's
// temporary directory, never in the checkout, so only a root test run that
// may mount and whose TMPDIR has such ancestors can create one (a
// world-writable /tmp cannot); every other run skips with the reason.
func pinnedHelper(t *testing.T, content string) OpsHelper {
	t.Helper()
	helper, _ := pinnedHelperSource(t, content)
	return helper
}

// pinnedHelperSource is pinnedHelper that also returns the writable source
// directory the read-only pinned directory binds, so a test can change the
// pinned files the way a host process can.
func pinnedHelperSource(t *testing.T, content string) (OpsHelper, string) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("a root-owned helper pin needs a root test run")
	}
	parent := t.TempDir()
	requirePrivateMounts(t, parent)
	source, pinned := filepath.Join(parent, "source"), filepath.Join(parent, "pinned")
	for _, dir := range []string{source, pinned} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(source, sandboxops.HelperName), content)
	mustChmod(t, filepath.Join(source, sandboxops.HelperName), 0o555)
	mustChmod(t, source, 0o555)
	if err := unix.Mount(source, pinned, "", unix.MS_BIND, ""); err != nil {
		t.Skipf("a read-only helper mount needs a test run that may mount: %v", err)
	}
	t.Cleanup(func() { _ = unix.Unmount(pinned, unix.MNT_DETACH) })
	if err := unix.Mount("", pinned, "", unix.MS_REMOUNT|unix.MS_BIND|unix.MS_RDONLY, ""); err != nil {
		t.Fatal(err)
	}
	helper := OpsHelper{Dir: pinned, SHA256: digestOf(content)}
	if err := verifyHelper(helper); err != nil && strings.Contains(err.Error(), "ancestor") {
		t.Skipf("TMPDIR's ancestors cannot hold a pinned helper (use a root-owned, non-writable TMPDIR): %v", err)
	}
	return helper, source
}

// requirePrivateMounts skips t unless the bind mounts a test makes under dir
// stay in a mount namespace of the test process's own and do not propagate
// out of it. A root run in the host's mount namespace, or under a mount that
// shares its propagation with it, would leave its mounts on the host if the
// test died before its cleanup. Run root tests under
// `unshare -m --propagation private`.
func requirePrivateMounts(t *testing.T, dir string) {
	t.Helper()
	const how = "the helper fixture's bind mounts need a private mount namespace (unshare -m --propagation private)"
	self, errSelf := os.Readlink("/proc/self/ns/mnt")
	initial, errInitial := os.Readlink("/proc/1/ns/mnt")
	if errSelf != nil || errInitial != nil || self == initial {
		t.Skipf("%s: this test shares the mount namespace of process 1", how)
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	mountinfo, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Skipf("%s: %v", how, err)
	}
	unescape := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	point, shared := "", false
	for _, line := range strings.Split(string(mountinfo), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}
		at := unescape.Replace(fields[4])
		if (at != "/" && resolved != at && !strings.HasPrefix(resolved, at+"/")) || len(at) < len(point) {
			continue
		}
		// A later line at the same mount point is mounted on top.
		point, shared = at, false
		for _, optional := range fields[6:] {
			if optional == "-" {
				break
			}
			shared = shared || strings.HasPrefix(optional, "shared:")
		}
	}
	if point == "" || shared {
		t.Skipf("%s: the mount at %q of %s shares its propagation", how, point, resolved)
	}
}

func mustChmod(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// opsMode puts b in ops mode with a verified pin, without the runtime check
// EnableOps makes through the engine (TestEnableOpsChecksTheRuntimeAndTheHelperPin),
// for tests whose engine scripts no /info answer.
func opsMode(t *testing.T, b *GVisor, helper OpsHelper) {
	t.Helper()
	if err := verifyHelper(helper); err != nil {
		t.Fatal(err)
	}
	b.opsHelper = &helper
}

// runscMountOptions are the mount options the pinned runsc
// release-20261005.0 reports in its OCI features (`runsc features`, whose
// list is KnownMountOptions in runsc/specutils/fs.go at that tag); rro is not
// among them.
var runscMountOptions = []string{"acl", "async", "atime", "bind", "defaults", "dev", "diratime", "dirsync", "exec", "iversion", "loud", "mand",
	"noacl", "noatime", "nodev", "nodiratime", "noexec", "noiversion", "nomand", "norelatime", "nostrictatime", "nosuid", "private", "rbind",
	"relatime", "remount", "ro", "rprivate", "rslave", "runbindable", "rw", "silent", "slave", "strictatime", "suid", "sync", "unbindable"}

// Amendment A1 (XA-09): the helper mount must be read-only and rprivate,
// which the backend requests and reads back, so EnableOps no longer refuses
// for nosuid or nodev. Before it enables ops it reads the daemon's runtime
// registration once more, refuses a runtime registered with an argument
// outside the reviewed set (set-ID execution, flag overrides, host-file
// passthrough) and a runtime whose cached OCI features list rro or are not
// shown (MCR-03), and then checks the helper pin, its read-only mount
// included (MCR-04). Each refusal names its own reason and leaves ops off.
func TestEnableOpsChecksTheRuntimeAndTheHelperPin(t *testing.T) {
	const runsc = "/opt/mc-sandbox/bin/runsc"
	reviewed := []string{"--systemd-cgroup", "--overlay2=none"}
	features := func(options []string) map[string]string {
		raw, err := json.Marshal(map[string]any{"ociVersionMin": "1.0.0", "ociVersionMax": "1.2.1", "mountOptions": options})
		if err != nil {
			t.Fatal(err)
		}
		return map[string]string{"org.opencontainers.runtime-spec.features": string(raw)}
	}
	registered := func(args []string, status map[string]string) map[string]any {
		return map[string]any{"runsc": map[string]any{"path": runsc, "runtimeArgs": args, "status": status}}
	}
	backend := func(t *testing.T, status int, runtimes map[string]any) (*GVisor, *scriptedEngine) {
		e := &scriptedEngine{answer: func(c engineCall) (int, any, http.Header) {
			if c.Method == http.MethodGet && c.Path == "/info" && status == 200 {
				return 200, map[string]any{"ID": "SANDBOX-ENGINE-ID", "Runtimes": runtimes}, nil
			}
			return 500, map[string]string{"message": "scripted refusal of " + c.String()}, nil
		}}
		b := scriptedBackend(t, e)
		b.config.RunscPath = runsc
		return b, e
	}
	absent := OpsHelper{Dir: "/nonexistent/ops-helper", SHA256: digestOf("helper binary")}
	for _, tc := range []struct {
		name     string
		status   int
		runtimes map[string]any
		want     string
	}{
		{"features list rro", 200, registered(reviewed, features(append(slices.Clone(runscMountOptions), "rro"))), "rro"},
		{"no features reported", 200, registered(reviewed, nil), "no OCI features"},
		{"features do not decode", 200, registered(reviewed, map[string]string{"org.opencontainers.runtime-spec.features": "{"}), "decode"},
		{"runtime not registered", 200, map[string]any{}, "does not register"},
		{"set-ID argument", 200, registered(append(slices.Clone(reviewed), "--allow-suid"), features(runscMountOptions)), "unreviewed argument"},
		{"flag-override argument", 200, registered(append(slices.Clone(reviewed), "--allow-flag-override"), features(runscMountOptions)), "unreviewed argument"},
		{"host-file passthrough argument", 200, registered(append(slices.Clone(reviewed), "--host-uds=all"), features(runscMountOptions)), "unreviewed argument"},
		{"daemon info refused", 500, nil, "daemon info"},
		// The runtime passes with the pinned runsc's features; the pin
		// refuses next.
		{"reviewed runtime, no helper", 200, registered(reviewed, features(runscMountOptions)), "ops helper directory " + absent.Dir},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := backend(t, tc.status, tc.runtimes)
			if err := b.EnableOps(absent); err == nil || !strings.Contains(err.Error(), tc.want) || b.opsHelper != nil {
				t.Fatalf("EnableOps = %v (ops on %v), want a refusal containing %q", err, b.opsHelper != nil, tc.want)
			}
		})
	}

	helper, source := pinnedHelperSource(t, "helper binary")
	t.Run("helper on a writable mount", func(t *testing.T) {
		b, _ := backend(t, 200, registered(reviewed, features(runscMountOptions)))
		if err := b.EnableOps(OpsHelper{Dir: source, SHA256: helper.SHA256}); err == nil || !strings.Contains(err.Error(), "writable mount") || b.opsHelper != nil {
			t.Fatalf("EnableOps = %v, want the writable mount refusal", err)
		}
	})
	t.Run("pinned helper", func(t *testing.T) {
		b, e := backend(t, 200, registered(reviewed, features(runscMountOptions)))
		if err := b.EnableOps(helper); err != nil || b.opsHelper == nil || *b.opsHelper != helper {
			t.Fatalf("EnableOps = %v, want ops on with the pinned helper", err)
		}
		if calls := e.log(); len(calls) != 1 || calls[0].String() != "GET /info" {
			t.Fatalf("engine calls %q, want one GET /info", calls)
		}
	})
}

// The ops-mode readback accepts exactly the pinned read-only rprivate bind,
// as both the requested mount and the container's one mount; the rest of
// the engine configuration is verifyEngine's.
func TestHelperMountReadbackIsExactlyThePinnedMount(t *testing.T) {
	helper := &OpsHelper{Dir: "/srv/mc-ops-helper", SHA256: digestOf("helper binary")}
	readback := func(change func(requested, mounted map[string]any) []any) inspectedContainer {
		requested := map[string]any{"Type": "bind", "Source": helper.Dir, "Target": "/.misscomputer", "ReadOnly": true,
			"BindOptions": map[string]any{"Propagation": "rprivate"}}
		mounted := map[string]any{"Type": "bind", "Source": helper.Dir, "Destination": "/.misscomputer", "Mode": "", "RW": false,
			"Propagation": "rprivate"}
		mounts := []any{mounted}
		if change != nil {
			if extra := change(requested, mounted); extra != nil {
				mounts = extra
			}
		}
		raw, err := json.Marshal(map[string]any{"Name": "/sandbox", "HostConfig": map[string]any{"Mounts": []any{requested}}, "Mounts": mounts})
		if err != nil {
			t.Fatal(err)
		}
		var c inspectedContainer
		if err := json.Unmarshal(raw, &c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	if err := verifyHelperMount(readback(nil), helper); err != nil {
		t.Fatalf("the pinned mount was refused: %v", err)
	}
	for name, change := range map[string]func(requested, mounted map[string]any) []any{
		"writable":                  func(_, m map[string]any) []any { m["RW"] = true; return nil },
		"other source":              func(_, m map[string]any) []any { m["Source"] = "/srv/other"; return nil },
		"other destination":         func(_, m map[string]any) []any { m["Destination"] = "/"; return nil },
		"shared":                    func(_, m map[string]any) []any { m["Propagation"] = "rshared"; return nil },
		"volume":                    func(_, m map[string]any) []any { m["Type"] = "volume"; return nil },
		"requested writable":        func(r, _ map[string]any) []any { r["ReadOnly"] = false; return nil },
		"requested without options": func(r, _ map[string]any) []any { delete(r, "BindOptions"); return nil },
		"requested elsewhere":       func(r, _ map[string]any) []any { r["Target"] = "/usr/bin"; return nil },
		"no mount":                  func(_, _ map[string]any) []any { return []any{} },
		"a second mount": func(_, m map[string]any) []any {
			return []any{m, map[string]any{"Type": "bind", "Source": "/", "Destination": "/host", "RW": false, "Propagation": "rprivate"}}
		},
	} {
		if err := verifyHelperMount(readback(change), helper); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// mountAsAsked makes the engine apply the requested helper mount the way
// dockerd reports it, then lets change alter it.
func mountAsAsked(change func(map[string]any)) func(*engineContainer) {
	return func(c *engineContainer) {
		requested, _ := c.Host["Mounts"].([]any)
		for _, raw := range requested {
			m := raw.(map[string]any)
			mounted := map[string]any{"Type": m["Type"], "Source": m["Source"], "Destination": m["Target"], "RW": !m["ReadOnly"].(bool),
				"Propagation": m["BindOptions"].(map[string]any)["Propagation"]}
			if change != nil {
				change(mounted)
			}
			c.Mounts = append(c.Mounts, mounted)
		}
	}
}

// Ops mode adds exactly one read-only rprivate directory mount of the
// pinned helper, and the readback must show exactly that mount; without ops
// the create body has no mount at all.
func TestOpsModeMountsOnlyThePinnedHelperDirectory(t *testing.T) {
	helper := pinnedHelper(t, "helper binary")
	off := newHost(t)
	if err := off.backend().Create(context.Background(), instanceOf(testLease(nil)), testLease(nil)); err != nil {
		t.Fatal(err)
	}
	if _, has := off.engine.created[0]["HostConfig"].(map[string]any)["Mounts"]; has {
		t.Fatal("a create without ops carries a Mounts member")
	}

	h := newHost(t)
	h.engine.applied = mountAsAsked(nil)
	b := h.backend()
	opsMode(t, b, helper)
	if err := b.Create(context.Background(), instanceOf(testLease(nil)), testLease(nil)); err != nil {
		t.Fatal(err)
	}
	// The first create is the image probe (D1, ops_defenses_test.go), which
	// carries no mount and is removed again.
	if len(h.engine.created) != 2 || h.engine.created[0]["HostConfig"].(map[string]any)["Mounts"] != nil || len(h.engine.containers) != 1 {
		t.Fatalf("ops creates = %v, containers left %d", h.engine.created, len(h.engine.containers))
	}
	mounts := h.engine.created[1]["HostConfig"].(map[string]any)["Mounts"].([]any)
	want := map[string]any{"Type": "bind", "Source": helper.Dir, "Target": "/.misscomputer", "ReadOnly": true, "BindOptions": map[string]any{"Propagation": "rprivate"}}
	if len(mounts) != 1 || fmt.Sprint(mounts[0]) != fmt.Sprint(want) {
		t.Fatalf("ops create mounts = %v", mounts)
	}

	// A readback that differs from the pinned mount stops the create before
	// the start (each difference: TestHelperMountReadbackIsExactlyThePinnedMount).
	h = newHost(t)
	h.engine.applied = mountAsAsked(func(m map[string]any) { m["RW"] = true })
	b = h.backend()
	opsMode(t, b, helper)
	if err := b.Create(context.Background(), instanceOf(testLease(nil)), testLease(nil)); err == nil || h.engine.starts != 0 {
		t.Fatalf("misapplied helper mount: err=%v starts=%d", err, h.engine.starts)
	}
}

// The B-2 pin refuses a helper that is not exactly the pinned, root-owned,
// read-only binary alone in its directory on a read-only mount, and is
// checked again before every create. Each case changes the pinned files
// through their writable source, as a host process could, or names a view
// of them that is not read-only.
func TestOpsHelperPinRefusesAnythingButThePinnedBinary(t *testing.T) {
	helper := pinnedHelper(t, "helper binary")
	if err := verifyHelper(helper); err != nil {
		t.Fatalf("pinned helper refused: %v", err)
	}
	if err := verifyHelper(OpsHelper{Dir: helper.Dir, SHA256: digestOf("other")}); err == nil {
		t.Fatal("wrong digest accepted")
	}
	for _, tc := range []struct {
		name   string
		change func(t *testing.T, pinned OpsHelper, source string) OpsHelper
		want   string
	}{
		{"writable helper", func(t *testing.T, p OpsHelper, s string) OpsHelper {
			mustChmod(t, filepath.Join(s, sandboxops.HelperName), 0o755)
			return p
		}, "mode exactly 0555"},
		{"setuid helper", func(t *testing.T, p OpsHelper, s string) OpsHelper {
			mustChmod(t, filepath.Join(s, sandboxops.HelperName), os.ModeSetuid|0o555)
			return p
		}, "mode exactly 0555"},
		{"writable dir", func(t *testing.T, p OpsHelper, s string) OpsHelper { mustChmod(t, s, 0o755); return p }, "mode 0555"},
		{"extra file", func(t *testing.T, p OpsHelper, s string) OpsHelper {
			mustChmod(t, s, 0o755)
			writeFile(t, filepath.Join(s, "extra"), "x")
			mustChmod(t, s, 0o555)
			return p
		}, "must hold only"},
		{"symlinked helper", func(t *testing.T, p OpsHelper, s string) OpsHelper {
			// The link is the directory's only entry, so only the
			// O_NOFOLLOW open refuses it.
			file, real := filepath.Join(s, sandboxops.HelperName), filepath.Join(filepath.Dir(s), "real-helper")
			mustChmod(t, s, 0o755)
			if err := os.Rename(file, real); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(real, file); err != nil {
				t.Fatal(err)
			}
			mustChmod(t, s, 0o555)
			return p
		}, "open ops helper"},
		// MCR-04: the same files on a writable mount.
		{"directory on a writable mount", func(_ *testing.T, p OpsHelper, s string) OpsHelper {
			return OpsHelper{Dir: s, SHA256: p.SHA256}
		}, "writable mount"},
		{"directory on a writable mount around a read-only helper", func(t *testing.T, p OpsHelper, s string) OpsHelper {
			helper := filepath.Join(s, sandboxops.HelperName)
			if err := unix.Mount(helper, helper, "", unix.MS_BIND, ""); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = unix.Unmount(helper, unix.MNT_DETACH) })
			if err := unix.Mount("", helper, "", unix.MS_REMOUNT|unix.MS_BIND|unix.MS_RDONLY, ""); err != nil {
				t.Fatal(err)
			}
			return OpsHelper{Dir: s, SHA256: p.SHA256}
		}, "writable mount"},
		{"helper over-mounted from a writable mount", func(t *testing.T, p OpsHelper, _ string) OpsHelper {
			other := filepath.Join(t.TempDir(), sandboxops.HelperName)
			writeFile(t, other, "helper binary")
			mustChmod(t, other, 0o555)
			target := filepath.Join(p.Dir, sandboxops.HelperName)
			if err := unix.Mount(other, target, "", unix.MS_BIND, ""); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = unix.Unmount(target, unix.MNT_DETACH) })
			return p
		}, "writable mount"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pinned, source := pinnedHelperSource(t, "helper binary")
			broken := tc.change(t, pinned, source)
			if err := verifyHelper(broken); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("verifyHelper = %v, want a refusal containing %q", err, tc.want)
			}
			h := newHost(t)
			b := h.backend()
			b.opsHelper = &broken
			if err := b.Create(context.Background(), instanceOf(testLease(nil)), testLease(nil)); err == nil || len(h.engine.created) != 0 {
				t.Fatalf("create proceeded with a broken pin: %v", err)
			}
		})
	}
}

// RunHelper is docker exec of the fixed helper path as the image user with
// no added environment: the request is the only stdin, stdout comes back
// bounded, and failures are classified for attribution (OPS-U3 D1).
func TestRunHelperExecsTheFixedHelperAndClassifiesFailures(t *testing.T) {
	helper := pinnedHelper(t, "helper binary")
	h := newHost(t)
	h.engine.applied = mountAsAsked(nil)
	b := h.backend()
	opsMode(t, b, helper)
	lease := testLease(nil)
	instance := instanceOf(lease)
	if err := b.Create(context.Background(), instance, lease); err != nil {
		t.Fatal(err)
	}
	h.engine.ops = &fakeOpsEngine{helper: func(stdin []byte) ([]byte, []byte, int) {
		return append([]byte("answer:"), stdin...), []byte("guest noise"), 0
	}}
	out, err := b.RunHelper(context.Background(), instance, []byte("request"))
	if err != nil || string(out) != "answer:request" {
		t.Fatalf("RunHelper = %q, %v", out, err)
	}
	body := h.engine.ops.bodies[0]
	if fmt.Sprint(body["Cmd"]) != "[/.misscomputer/sandbox-ops-helper]" || body["User"] != "" || fmt.Sprint(body["Env"]) != "[]" ||
		body["Privileged"] != false || body["Tty"] != false || body["AttachStdin"] != true {
		t.Fatalf("exec create body = %v", body)
	}
	// dockerd may still report the exec running right after its stream
	// closed; the answer is kept once the exec is seen ended.
	h.engine.mu.Lock()
	h.engine.ops.runningInspects = 3
	h.engine.mu.Unlock()
	if out, err := b.RunHelper(context.Background(), instance, []byte("late")); err != nil || string(out) != "answer:late" {
		t.Fatalf("RunHelper with a late exec end = %q, %v", out, err)
	}

	for _, tc := range []struct {
		name  string
		setup func()
		check func(error) bool
	}{
		{"nonzero exit", func() {
			h.engine.ops.helper = func([]byte) ([]byte, []byte, int) { return []byte("{}"), nil, 137 }
		}, func(err error) bool { return err != nil && !errors.Is(err, miner.ErrSandboxNotRunning) }},
		{"stdout over bound", func() {
			h.engine.ops.helper = func([]byte) ([]byte, []byte, int) { return make([]byte, sandboxops.MaxResponseBytes+1), nil, 0 }
		}, func(err error) bool { return err != nil && strings.Contains(err.Error(), "bound") }},
		{"engine down", func() { h.engine.ops.dropCreate, h.engine.ops.pingDown = true, true }, func(err error) bool {
			var unavailable *miner.SandboxEngineUnavailable
			return errors.As(err, &unavailable)
		}},
		{"dropped but alive", func() { h.engine.ops.dropCreate, h.engine.ops.pingDown = true, false }, func(err error) bool {
			var unavailable *miner.SandboxEngineUnavailable
			return err != nil && !errors.As(err, &unavailable)
		}},
		{"stopped sandbox", func() {
			h.engine.ops.dropCreate = false
			h.engine.mu.Lock()
			h.engine.containers[instance].Status = "exited"
			h.engine.mu.Unlock()
		}, func(err error) bool { return errors.Is(err, miner.ErrSandboxNotRunning) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.setup()
			if _, err := b.RunHelper(context.Background(), instance, []byte("request")); !tc.check(err) {
				t.Fatalf("RunHelper error %v", err)
			}
		})
	}
}

// demux keeps stdout, drops stderr, and refuses a stream it cannot frame.
func TestDemuxBoundsAndFraming(t *testing.T) {
	frame := func(stream byte, data string) string {
		var header [8]byte
		header[0] = stream
		binary.BigEndian.PutUint32(header[4:], uint32(len(data)))
		return string(header[:]) + data
	}
	out, err := demux(bufio.NewReader(strings.NewReader(frame(2, "err")+frame(1, "out")+frame(1, "put"))), 16)
	if err != nil || string(out) != "output" {
		t.Fatalf("demux = %q, %v", out, err)
	}
	for name, stream := range map[string]string{
		"unknown stream": frame(3, "x"),
		"truncated":      frame(1, "abc")[:10],
		"stderr flood":   frame(2, strings.Repeat("x", maxHelperStderrBytes+1)),
	} {
		if _, err := demux(strings.NewReader(stream), 16); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
