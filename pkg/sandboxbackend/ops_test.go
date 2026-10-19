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
	"strings"
	"testing"

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
// 0555 directory and file under root-owned, non-writable ancestors. It is
// created in the test's temporary directory, never in the checkout, so only
// a root test run whose TMPDIR has such ancestors can create one (a
// world-writable /tmp cannot); every other run skips with the reason.
func pinnedHelper(t *testing.T, content string) OpsHelper {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("a root-owned helper pin needs a root test run")
	}
	dir, err := os.MkdirTemp(t.TempDir(), "ops-helper-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(dir, 0o755)
		_ = os.RemoveAll(dir)
	})
	writeFile(t, filepath.Join(dir, sandboxops.HelperName), content)
	if err := os.Chmod(filepath.Join(dir, sandboxops.HelperName), 0o555); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	helper := OpsHelper{Dir: dir, SHA256: digestOf(content)}
	if err := verifyHelper(helper); err != nil && strings.Contains(err.Error(), "ancestor") {
		t.Skipf("TMPDIR's ancestors cannot hold a pinned helper (use a root-owned, non-writable TMPDIR): %v", err)
	}
	return helper
}

// opsMode puts b in ops mode with a verified pin, as EnableOps will once the
// helper mount carries every property the contract requires; until then
// EnableOps refuses (XA-09), so these tests set the mode the same way the
// pin test below does.
func opsMode(t *testing.T, b *GVisor, helper OpsHelper) {
	t.Helper()
	if err := verifyHelper(helper); err != nil {
		t.Fatal(err)
	}
	b.opsHelper = &helper
}

// XA-09: the contract requires a nosuid, nodev helper mount, which the
// engine can neither request nor read back, so EnableOps fails closed, and
// does so before it reads the helper: the refusal names the missing
// properties, not the helper directory.
func TestEnableOpsFailsClosedWhileTheHelperMountIsUnproven(t *testing.T) {
	b := &GVisor{}
	err := b.EnableOps(OpsHelper{Dir: "/nonexistent/ops-helper", SHA256: digestOf("helper binary")})
	if err == nil || !strings.Contains(err.Error(), "nosuid, nodev") {
		t.Fatalf("EnableOps = %v, want the refusal naming nosuid and nodev", err)
	}
	if b.opsHelper != nil {
		t.Fatal("ops mode was enabled")
	}
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
// read-only binary alone in its directory, and is checked again before
// every create.
func TestOpsHelperPinRefusesAnythingButThePinnedBinary(t *testing.T) {
	helper := pinnedHelper(t, "helper binary")
	if err := verifyHelper(helper); err != nil {
		t.Fatalf("pinned helper refused: %v", err)
	}
	if err := verifyHelper(OpsHelper{Dir: helper.Dir, SHA256: digestOf("other")}); err == nil {
		t.Fatal("wrong digest accepted")
	}
	file := filepath.Join(helper.Dir, sandboxops.HelperName)
	for name, mutate := range map[string]func(){
		"writable helper": func() { _ = os.Chmod(file, 0o755) },
		"setuid helper":   func() { _ = os.Chmod(file, os.ModeSetuid|0o555) },
		"writable dir":    func() { _ = os.Chmod(helper.Dir, 0o755) },
		"extra file": func() {
			_ = os.Chmod(helper.Dir, 0o755)
			writeFile(t, filepath.Join(helper.Dir, "extra"), "x")
			_ = os.Chmod(helper.Dir, 0o555)
		},
		"symlinked helper": func() {
			_ = os.Chmod(helper.Dir, 0o755)
			_ = os.Rename(file, file+".real")
			_ = os.Symlink(file+".real", file)
			_ = os.Chmod(helper.Dir, 0o555)
		},
	} {
		t.Run(name, func(t *testing.T) {
			fresh := pinnedHelper(t, "helper binary")
			file = filepath.Join(fresh.Dir, sandboxops.HelperName)
			helper = fresh
			mutate()
			if err := verifyHelper(fresh); err == nil {
				t.Fatalf("%s accepted", name)
			}
			h := newHost(t)
			b := h.backend()
			b.opsHelper = &fresh
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
