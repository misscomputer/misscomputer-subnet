// SPDX-License-Identifier: AGPL-3.0-only

package sandboxbackend

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	"github.com/misscomputer/misscomputer-subnet/pkg/sandboxops"
)

// These tests cover the ops-mode defences that run before a sandbox is
// created: the helper pin's extended-attribute rule (G1) and the image
// probe for an entry at the helper's mount target (D1). The engine is an
// in-process http.RoundTripper, so no socket or listener exists. They prove
// what the backend asks the engine and how it decides on each answer; they
// do not prove how Docker answers. That, and whether a guest sees the host
// pin's attributes, is lab evidence.

// engineCall is one request the backend made to the scripted engine.
type engineCall struct {
	Method, Path string
	Query        url.Values
	Body         map[string]any
	// Cancelled is whether the request's context was already done.
	Cancelled bool
}

func (c engineCall) String() string {
	if len(c.Query) == 0 {
		return c.Method + " " + c.Path
	}
	return c.Method + " " + c.Path + "?" + c.Query.Encode()
}

// scriptedEngine is the backend's Engine API transport. answer returns the
// status, JSON body and headers of each call; a negative status drops the
// call without an answer.
type scriptedEngine struct {
	mu     sync.Mutex
	calls  []engineCall
	answer func(engineCall) (int, any, http.Header)
}

func (e *scriptedEngine) RoundTrip(r *http.Request) (*http.Response, error) {
	call := engineCall{Method: r.Method, Path: strings.TrimPrefix(r.URL.Path, "/"+engineAPIVersion), Query: r.URL.Query(), Cancelled: r.Context().Err() != nil}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&call.Body)
		_ = r.Body.Close()
	}
	e.mu.Lock()
	e.calls = append(e.calls, call)
	answer := e.answer
	e.mu.Unlock()
	status, body, header := answer(call)
	if status < 0 {
		return nil, errors.New("connection closed before the engine answered")
	}
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	if header == nil {
		header = http.Header{}
	}
	return &http.Response{StatusCode: status, Status: http.StatusText(status), Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: header, Body: io.NopCloser(bytes.NewReader(raw)), ContentLength: int64(len(raw)), Request: r}, nil
}

func (e *scriptedEngine) log() []engineCall {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.calls)
}

// scriptedBackend is a backend whose engine is e, with a public registry
// address and a data root with room for a pull.
func scriptedBackend(t *testing.T, e *scriptedEngine) *GVisor {
	client := &http.Client{Transport: e}
	return &GVisor{
		config: Config{Runtime: "runsc", DataRoot: t.TempDir(), Slice: testSlice, DiskMiB: 1024, Sandboxes: 2, ImageMaxMiB: 64, LogMiB: 4, PIDsMax: 4096},
		engine: &engine{client: client, pullClient: client, base: "http://docker/" + engineAPIVersion}, sliceCgroup: "/mc.slice/" + testSlice,
		lookup: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("151.101.0.1")}, nil
		},
		hostAddresses: func() ([]netip.Addr, error) { return nil, nil },
	}
}

// pathStat is the X-Docker-Container-Path-Stat header dockerd sends with an
// archive stat that found an entry; mode is a Go fs.FileMode.
func pathStat(mode uint32, target string) http.Header {
	raw, _ := json.Marshal(map[string]any{"name": ".misscomputer", "size": 0, "mode": mode, "mtime": "2026-10-19T00:00:00Z", "linkTarget": target})
	return http.Header{"X-Docker-Container-Path-Stat": {base64.StdEncoding.EncodeToString(raw)}}
}

// Entries an image can hold at /.misscomputer. Each is refused, the
// directory included: only an engine 404 shows that the path is absent.
var helperTargetEntries = map[string]http.Header{
	"symlink into the root": pathStat(1<<27|0o777, "/usr/bin"),
	"directory":             pathStat(1<<31|0o755, ""),
	"regular file":          pathStat(0o644, ""),
	"fifo":                  pathStat(1<<25|0o644, ""),
}

const testProbeID = "abababababababababababababababababababababababababababababababab"

// neverStartedProbe is an engine inspection of a created, never-started
// probe container.
func neverStartedProbe(id string) map[string]any {
	return map[string]any{"Id": id, "Name": "/probe", "Image": testImageID,
		"State": map[string]any{"Status": "created", "Running": false, "Pid": 0, "StartedAt": "0001-01-01T00:00:00Z", "FinishedAt": "0001-01-01T00:00:00Z"}}
}

// G1 (MSR-03): the helper pin refuses any extended attribute on the opened
// helper directory or helper file, such as a file capability set on the
// pinned binary, and accepts the same pin without it.
func TestOpsHelperPinRefusesExtendedAttributes(t *testing.T) {
	for _, target := range []string{"directory", "helper"} {
		t.Run(target, func(t *testing.T) {
			helper := pinnedHelper(t, "helper binary")
			if err := verifyHelper(helper); err != nil {
				t.Fatalf("pinned helper without attributes refused: %v", err)
			}
			path := helper.Dir
			if target == "helper" {
				path = filepath.Join(helper.Dir, sandboxops.HelperName)
			}
			if err := unix.Lsetxattr(path, "user.misscomputer-test", []byte("x"), 0); errors.Is(err, unix.ENOTSUP) {
				t.Skipf("TMPDIR's filesystem has no user extended attributes: %v", err)
			} else if err != nil {
				t.Fatal(err)
			}
			if err := verifyHelper(helper); err == nil || !strings.Contains(err.Error(), "extended attributes") {
				t.Fatalf("verifyHelper with an extended attribute on the %s = %v, want the extended-attribute refusal", target, err)
			}
		})
	}
}

// D1 (DEC-06, R23-H-01, DR-06, MSR-01): in ops mode, before the sandbox is
// created, a never-started container of the verified image without any
// mount is probed for /.misscomputer. Only an engine 404 for a probe that
// still exists lets the create proceed; any entry refuses the lease as
// image_unavailable, a refusal that is not the miner's fault. The probe is
// removed with its anonymous volumes either way. Without ops nothing is
// probed.
func TestOpsCreateProbesTheHelperTargetBeforeCreating(t *testing.T) {
	lease := testLease(nil)
	instance := instanceOf(lease)
	probeName := instance + "-image-probe"
	image := map[string]any{"Id": testImageID, "RepoDigests": []string{"busybox@" + testImageDigest}, "Os": "linux", "Architecture": "amd64",
		"Size": 4 << 20, "Config": map[string]any{"Cmd": []string{"sh"}}}
	// leaseEngine answers one Create: no container yet, a pull of the
	// image, its inspection, the probe, and a refused real create, the end
	// of what these cases need.
	leaseEngine := func(stat int, header http.Header) *scriptedEngine {
		probeExists := false
		return &scriptedEngine{answer: func(c engineCall) (int, any, http.Header) {
			switch {
			case c.Method == http.MethodPost && c.Path == "/images/create":
				return 200, map[string]string{"status": "Status: Downloaded newer image for busybox@" + testImageDigest}, nil
			case c.Method == http.MethodGet && (c.Path == "/images/docker.io/library/busybox@"+testImageDigest+"/json" || c.Path == "/images/"+testImageID+"/json"):
				return 200, image, nil
			case c.Method == http.MethodGet && c.Path == "/containers/"+instance+"/json":
				return 404, map[string]string{"message": "No such container"}, nil
			case c.Method == http.MethodPost && c.Path == "/containers/create" && c.Query.Get("name") == probeName:
				probeExists = true
				return 201, map[string]any{"Id": testProbeID, "Warnings": []string{}}, nil
			case c.Method == http.MethodHead && c.Path == "/containers/"+testProbeID+"/archive":
				return stat, nil, header
			case c.Method == http.MethodGet && c.Path == "/containers/"+testProbeID+"/json":
				if !probeExists {
					return 404, map[string]string{"message": "No such container"}, nil
				}
				return 200, neverStartedProbe(testProbeID), nil
			case c.Method == http.MethodDelete && c.Path == "/containers/"+testProbeID:
				probeExists = false
				return 204, nil, nil
			case c.Method == http.MethodPost && c.Path == "/containers/create" && c.Query.Get("name") == instance:
				return 500, map[string]string{"message": "scripted end of the create"}, nil
			}
			return 500, map[string]string{"message": "unscripted " + c.String()}, nil
		}}
	}
	containerCalls := func(e *scriptedEngine) (calls []string, creates []engineCall) {
		for _, c := range e.log() {
			if strings.HasPrefix(c.Path, "/containers/") {
				calls = append(calls, c.String())
			}
			if c.Path == "/containers/create" {
				creates = append(creates, c)
			}
		}
		return calls, creates
	}
	mounts := func(create engineCall) any {
		host, _ := create.Body["HostConfig"].(map[string]any)
		return host["Mounts"]
	}
	inspectInstance := "GET /containers/" + instance + "/json"
	createProbe := "POST /containers/create?name=" + url.QueryEscape(probeName) + "&platform=linux%2Famd64"
	statProbe := "HEAD /containers/" + testProbeID + "/archive?path=%2F.misscomputer"
	inspectProbe := "GET /containers/" + testProbeID + "/json"
	removeProbe := "DELETE /containers/" + testProbeID + "?force=1&v=1"
	createSandbox := "POST /containers/create?name=" + url.QueryEscape(instance) + "&platform=linux%2Famd64"

	t.Run("ops off", func(t *testing.T) {
		e := leaseEngine(404, nil)
		err := scriptedBackend(t, e).Create(context.Background(), instance, lease)
		calls, creates := containerCalls(e)
		if want := []string{inspectInstance, createSandbox}; !slices.Equal(calls, want) || refusalCode(err) != "" {
			t.Fatalf("calls %q (err %v), want %q", calls, err, want)
		}
		if _, has := creates[0].Body["HostConfig"].(map[string]any)["Mounts"]; has {
			t.Fatal("a create without ops carries a Mounts member")
		}
	})

	helper := pinnedHelper(t, "helper binary")
	t.Run("absent", func(t *testing.T) {
		e := leaseEngine(404, nil)
		b := scriptedBackend(t, e)
		opsMode(t, b, helper)
		err := b.Create(context.Background(), instance, lease)
		calls, creates := containerCalls(e)
		want := []string{inspectInstance, createProbe, statProbe, inspectProbe, removeProbe, inspectProbe, createSandbox}
		if !slices.Equal(calls, want) || err == nil || refusalCode(err) != "" {
			t.Fatalf("calls %q (err %v), want %q and the scripted create failure", calls, err, want)
		}
		if probe := creates[0]; probe.Body["Image"] != testImageID || mounts(probe) != nil {
			t.Fatalf("probe create body %v, want the verified image and no mount", probe.Body)
		}
		// The miner recognises a probe by its lease label and its name (pkg/miner orphan sweep).
		if labels, _ := creates[0].Body["Labels"].(map[string]any); labels[LabelLeaseID] != protocol.SandboxLeaseIDV1(lease) || labels[LabelSandbox] != sandboxLabelV1 {
			t.Fatalf("probe labels %v, want the lease label and the sandbox label", labels)
		}
		if mounts(creates[1]) == nil {
			t.Fatal("the sandbox create after the probe lost the helper mount")
		}
	})
	for name, header := range helperTargetEntries {
		t.Run(name, func(t *testing.T) {
			e := leaseEngine(200, header)
			b := scriptedBackend(t, e)
			opsMode(t, b, helper)
			err := b.Create(context.Background(), instance, lease)
			calls, _ := containerCalls(e)
			if want := []string{inspectInstance, createProbe, statProbe, removeProbe, inspectProbe}; !slices.Equal(calls, want) || refusalCode(err) != "image_unavailable" {
				t.Fatalf("calls %q, err %v; want %q and image_unavailable", calls, err, want)
			}
		})
	}
}

// probeEngine scripts the engine's side of one image probe: the probe
// container exists from an answered create (or an unanswered one that still
// made it) until a removal the engine carries out.
type probeEngine struct {
	exists bool
	// creates answers successive probe creates; 201 makes the container.
	creates []int
	// noID answers a create without the container's ID; lostCreate makes
	// the container though the create goes unanswered.
	noID, lostCreate bool
	// stat answers the archive stat; it may change exists first.
	stat func(p *probeEngine) int
	// inspect answers an inspection of an existing probe: 0 a created,
	// never-started container, 1 a started one, or that status.
	inspect int
	// remove answers the removal of an existing probe; 0 removes it.
	remove int
}

func (p *probeEngine) answer(c engineCall) (int, any, http.Header) {
	switch {
	case c.Method == http.MethodPost && c.Path == "/containers/create":
		status := 201
		if len(p.creates) > 0 {
			status, p.creates = p.creates[0], p.creates[1:]
		}
		switch {
		case status == 409 && p.exists, status == 404:
			return status, map[string]string{"message": "scripted refusal"}, nil
		case status == 201:
			p.exists = true
			if p.noID {
				return 201, map[string]any{"Warnings": []string{}}, nil
			}
			return 201, map[string]any{"Id": testProbeID, "Warnings": []string{}}, nil
		case status < 0:
			p.exists = p.lostCreate
			return status, nil, nil
		}
		return status, map[string]string{"message": "scripted refusal"}, nil
	case c.Method == http.MethodHead && c.Path == "/containers/"+testProbeID+"/archive":
		return p.stat(p), nil, nil
	case c.Method == http.MethodGet && strings.HasPrefix(c.Path, "/containers/") && strings.HasSuffix(c.Path, "/json"):
		switch {
		case !p.exists:
			return 404, map[string]string{"message": "No such container"}, nil
		case p.inspect == 0:
			return 200, neverStartedProbe(testProbeID), nil
		case p.inspect == 1:
			started := neverStartedProbe(testProbeID)
			started["State"] = map[string]any{"Status": "running", "Running": true, "Pid": 77, "StartedAt": "2026-10-19T00:00:01Z"}
			return 200, started, nil
		}
		return p.inspect, nil, nil
	case c.Method == http.MethodDelete && strings.HasPrefix(c.Path, "/containers/"):
		switch {
		case !p.exists:
			return 404, map[string]string{"message": "No such container"}, nil
		case p.remove != 0:
			return p.remove, map[string]string{"message": "driver failed to remove root filesystem"}, nil
		}
		p.exists = false
		return 204, nil, nil
	}
	return 500, map[string]string{"message": "unscripted " + c.String()}, nil
}

func statAnswer(status int) func(*probeEngine) int { return func(*probeEngine) int { return status } }

// Every answer the image probe can get from the engine ends in one decision:
// the image holds nothing at the target, a non-fault image_unavailable, the
// miner's fault, or a missing image the caller pulls again. Whatever it
// decides, a probe the engine created is removed with its volumes, also
// after the caller's context was cancelled, and a probe that cannot be
// removed is the miner's fault even when a conflict was found.
func TestImageProbeDecidesOnEveryEngineAnswerAndRemovesTheProbe(t *testing.T) {
	const instance = "miss-sbx-probe-test"
	probeName := instance + imageProbeSuffix
	create := "POST /containers/create?name=" + probeName + "&platform=linux%2Famd64"
	stat := "HEAD /containers/" + testProbeID + "/archive?path=%2F.misscomputer"
	inspect := "GET /containers/" + testProbeID + "/json"
	remove := "DELETE /containers/" + testProbeID + "?force=1&v=1"
	inspectName := "GET /containers/" + probeName + "/json"
	removeName := "DELETE /containers/" + probeName + "?force=1&v=1"
	removed := []string{remove, inspect}

	for _, tc := range []struct {
		name     string
		engine   probeEngine
		cancel   bool // the caller's context is cancelled during the stat
		decision string
		calls    []string
	}{
		{"absent", probeEngine{stat: statAnswer(404)}, false, "absent", append([]string{create, stat, inspect}, removed...)},
		{"entry", probeEngine{stat: statAnswer(200)}, false, "image_unavailable", append([]string{create, stat}, removed...)},
		{"stat refused for a never-started probe", probeEngine{stat: statAnswer(500)}, false, "image_unavailable", append([]string{create, stat, inspect}, removed...)},
		{"stat refused and the probe not inspected", probeEngine{stat: statAnswer(500), inspect: -1}, false, "fault", append([]string{create, stat, inspect}, removed...)},
		{"stat unanswered", probeEngine{stat: statAnswer(-1)}, false, "fault", append([]string{create, stat}, removed...)},
		{"caller cancelled during the stat", probeEngine{stat: statAnswer(-1)}, true, "fault", append([]string{create, stat}, removed...)},
		{"probe vanished during the stat", probeEngine{stat: func(p *probeEngine) int { p.exists = false; return 404 }}, false, "fault",
			[]string{create, stat, inspect, remove, inspect}},
		{"probe started", probeEngine{stat: statAnswer(404), inspect: 1}, false, "fault", append([]string{create, stat, inspect}, removed...)},
		{"entry but the probe is not removed", probeEngine{stat: statAnswer(200), remove: 500}, false, "fault", []string{create, stat, remove}},
		{"absent but the probe is not removed", probeEngine{stat: statAnswer(404), remove: 500}, false, "fault", []string{create, stat, inspect, remove}},
		{"image gone", probeEngine{creates: []int{404}}, false, "missing", []string{create}},
		{"probe create refused", probeEngine{creates: []int{500}}, false, "fault", []string{create, removeName, inspectName}},
		{"probe create unanswered", probeEngine{creates: []int{-1}, lostCreate: true}, false, "fault", []string{create, removeName, inspectName}},
		{"probe created without an ID", probeEngine{noID: true}, false, "fault", []string{create, removeName, inspectName}},
		{"probe left behind", probeEngine{exists: true, creates: []int{409, 201}, stat: statAnswer(404)}, false, "absent",
			append([]string{create, removeName, inspectName, create, stat, inspect}, removed...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p := tc.engine
			if tc.cancel {
				inner := p.stat
				p.stat = func(p *probeEngine) int { cancel(); return inner(p) }
			}
			e := &scriptedEngine{answer: p.answer}
			b := scriptedBackend(t, e)
			// The sandbox spec carries the helper mount; the probe must not.
			b.opsHelper = &OpsHelper{Dir: "/srv/mc-ops-helper", SHA256: digestOf("helper binary")}
			missing, err := b.imageConflict(ctx, instance, testImageID, b.spec(testLease(nil), digestOf("lease"), testImageID))
			decision := "fault"
			switch {
			case missing && err == nil:
				decision = "missing"
			case err == nil:
				decision = "absent"
			case refusalCode(err) != "":
				decision = refusalCode(err)
			}
			calls := e.log()
			rendered := make([]string, len(calls))
			for i, c := range calls {
				rendered[i] = c.String()
				if c.Method == http.MethodDelete && c.Cancelled {
					t.Errorf("probe removal %s ran on a cancelled context", c)
				}
				if c.Method == http.MethodPost {
					if host, _ := c.Body["HostConfig"].(map[string]any); host["Mounts"] != nil || c.Body["Image"] != testImageID {
						t.Errorf("probe create body %v, want the verified image and no mount", c.Body)
					}
				}
			}
			if decision != tc.decision || !slices.Equal(rendered, tc.calls) {
				t.Fatalf("decision %s (missing %v, err %v), calls %q; want %s, calls %q", decision, missing, err, rendered, tc.decision, tc.calls)
			}
			if p.exists && p.remove == 0 {
				t.Errorf("the probe container remains")
			}
			if p.remove != 0 && !strings.Contains(err.Error(), testProbeID) {
				t.Errorf("a probe left in place is not named by its ID: %v", err)
			}
		})
	}
}
