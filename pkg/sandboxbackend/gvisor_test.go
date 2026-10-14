// SPDX-License-Identifier: AGPL-3.0-only

package sandboxbackend

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/misscomputer/misscomputer-subnet/pkg/miner"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	"github.com/misscomputer/misscomputer-subnet/pkg/sandbox"
)

// These tests drive the backend against a scripted Docker Engine API on a
// unix socket and a scripted procfs/cgroupfs. They prove the backend's own
// decisions: what it asks the engine for, what it refuses, and which engine
// or kernel answers it rejects. They do not prove that Docker or gVisor
// enforce anything; gvisor_integration_test.go does that on a disposable host.

const (
	testImageDigest = "sha256:b7f3d86d6e84fc17718c48bcde1450807faa2d56704205c697b4bd5df7b9e29f"
	testImageID     = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	testSlice       = "mc-sandbox.slice"
	testPID         = 4242
)

type engineImage struct {
	ID           string
	RepoDigests  []string
	Os, Arch     string
	Size         int64
	Volumes      map[string]any
	PullStatus   int
	PullMessages []string
}

type engineContainer struct {
	Name, Image string
	Labels      map[string]string
	Host        map[string]any
	Status      string
	Mounts      []map[string]any
	// Error is the engine's start error and StartedAt its start time.
	Error, StartedAt string
}

// fakeEngine is a scripted Docker Engine API: images a pull may produce,
// containers, and hooks that make the engine misreport what it applied.
type fakeEngine struct {
	mu         sync.Mutex
	version    string
	info       map[string]any
	catalog    map[string]engineImage // pull reference -> image it yields
	images     map[string]engineImage // engine ID -> image
	containers map[string]*engineContainer
	created    []map[string]any
	pulls      int
	prunes     int
	// applied rewrites a container after creation, standing in for an
	// engine that did not apply what it was asked.
	applied func(*engineContainer)
	// started rewrites a container after start and inspected after each
	// inspection, standing in for a workload that exits.
	started, inspected func(*engineContainer)
}

func newFakeEngine(t *testing.T, dataRoot, runsc string) (*fakeEngine, string) {
	t.Helper()
	e := &fakeEngine{
		version: PinnedDockerVersion,
		info: map[string]any{
			"DockerRootDir": dataRoot, "Driver": "overlay2", "CgroupDriver": "systemd", "CgroupVersion": "2",
			"Runtimes":   map[string]any{"runsc": map[string]any{"path": runsc, "runtimeArgs": []string{"--systemd-cgroup", "--overlay2=none"}}},
			"Containerd": map[string]any{"Namespaces": map[string]any{"Containers": "mc-sandbox", "Plugins": "mc-sandbox-plugins"}},
			"RegistryConfig": map[string]any{
				"InsecureRegistryCIDRs": []string{"::1/128", "127.0.0.0/8"}, "Mirrors": []string{},
				"IndexConfigs": map[string]any{"docker.io": map[string]any{"Name": "docker.io", "Secure": true, "Mirrors": []string{}}},
			},
		},
		catalog: map[string]engineImage{
			"docker.io/library/busybox@" + testImageDigest: {
				ID: testImageID, RepoDigests: []string{"busybox@" + testImageDigest}, Os: "linux", Arch: "amd64", Size: 4 << 20,
				PullMessages: []string{`{"id":"layer1","status":"Downloading","progressDetail":{"current":1,"total":2097152}}`, `{"status":"Status: Downloaded"}`},
			},
		},
		images:     map[string]engineImage{},
		containers: map[string]*engineContainer{},
	}
	dir, err := os.MkdirTemp("", "sbx-engine")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "docker.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.StripPrefix("/"+engineAPIVersion, http.HandlerFunc(e.serve))}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	return e, socket
}

func reply(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if value != nil {
		_ = json.NewEncoder(w).Encode(value)
	}
}

func (e *fakeEngine) serve(w http.ResponseWriter, r *http.Request) {
	e.mu.Lock()
	defer e.mu.Unlock()
	p := r.URL.Path
	switch {
	case r.Method == http.MethodGet && p == "/version":
		reply(w, 200, map[string]string{"Version": e.version})
	case r.Method == http.MethodGet && p == "/info":
		reply(w, 200, e.info)
	case r.Method == http.MethodPost && p == "/images/create":
		e.pulls++
		reference := r.URL.Query().Get("fromImage") + "@" + r.URL.Query().Get("tag")
		image, ok := e.catalog[reference]
		if !ok {
			reply(w, 404, map[string]string{"message": "manifest unknown"})
			return
		}
		if image.PullStatus != 0 {
			reply(w, image.PullStatus, map[string]string{"message": "pull failed"})
			return
		}
		// The image is stored before the stream is answered, as when a pull
		// completes before the client reads its progress, unless the stream
		// reports an error.
		failed := false
		for _, line := range image.PullMessages {
			failed = failed || strings.Contains(line, `"error"`)
		}
		if !failed {
			e.images[image.ID] = image
		}
		w.WriteHeader(200)
		for _, line := range image.PullMessages {
			fmt.Fprintln(w, line)
		}
	case r.Method == http.MethodGet && strings.HasPrefix(p, "/images/") && strings.HasSuffix(p, "/json"):
		name := strings.TrimSuffix(strings.TrimPrefix(p, "/images/"), "/json")
		if id, ok := e.catalog[name]; ok {
			name = id.ID
		}
		image, ok := e.images[name]
		if !ok {
			reply(w, 404, map[string]string{"message": "No such image: " + name})
			return
		}
		reply(w, 200, map[string]any{"Id": image.ID, "RepoDigests": image.RepoDigests, "Os": image.Os, "Architecture": image.Arch,
			"Size": image.Size, "Config": map[string]any{"Volumes": image.Volumes}})
	case r.Method == http.MethodDelete && strings.HasPrefix(p, "/images/"):
		id := strings.TrimPrefix(p, "/images/")
		if _, ok := e.images[id]; !ok {
			reply(w, 404, map[string]string{"message": "No such image"})
			return
		}
		delete(e.images, id)
		reply(w, 200, []any{})
	case r.Method == http.MethodPost && p == "/images/prune":
		e.prunes++
		for id := range e.images {
			if !e.used(id) {
				delete(e.images, id)
			}
		}
		reply(w, 200, map[string]any{})
	case r.Method == http.MethodGet && p == "/containers/json":
		var filters map[string][]string
		_ = json.Unmarshal([]byte(r.URL.Query().Get("filters")), &filters)
		list := []map[string]any{}
		for name, c := range e.containers {
			if len(filters["label"]) > 0 && c.Labels[filters["label"][0]] == "" {
				continue
			}
			if len(filters["ancestor"]) > 0 && c.Image != filters["ancestor"][0] {
				continue
			}
			list = append(list, map[string]any{"Id": "id-" + name, "Names": []string{"/" + name}, "Labels": c.Labels})
		}
		reply(w, 200, list)
	case r.Method == http.MethodPost && p == "/containers/create":
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			reply(w, 400, map[string]string{"message": err.Error()})
			return
		}
		name := r.URL.Query().Get("name")
		if _, exists := e.containers[name]; exists {
			reply(w, 409, map[string]string{"message": "Conflict. The container name is already in use"})
			return
		}
		image, _ := body["Image"].(string)
		if _, ok := e.images[image]; !ok {
			reply(w, 404, map[string]string{"message": "No such image: " + image})
			return
		}
		e.created = append(e.created, body)
		labels := map[string]string{}
		for key, value := range body["Labels"].(map[string]any) {
			labels[key] = value.(string)
		}
		c := &engineContainer{Name: name, Image: image, Labels: labels, Host: body["HostConfig"].(map[string]any), Status: "created"}
		if e.applied != nil {
			e.applied(c)
		}
		e.containers[name] = c
		reply(w, 201, map[string]any{"Id": "id-" + name, "Warnings": []string{}})
	case r.Method == http.MethodPost && strings.HasPrefix(p, "/containers/") && strings.HasSuffix(p, "/start"):
		c, ok := e.containers[strings.TrimSuffix(strings.TrimPrefix(p, "/containers/"), "/start")]
		if !ok {
			reply(w, 404, map[string]string{"message": "No such container"})
			return
		}
		c.Status, c.StartedAt = "running", "2026-10-14T12:00:01Z"
		if e.started != nil {
			e.started(c)
		}
		w.WriteHeader(204)
	case r.Method == http.MethodGet && strings.HasPrefix(p, "/containers/") && strings.HasSuffix(p, "/json"):
		c, ok := e.containers[strings.TrimSuffix(strings.TrimPrefix(p, "/containers/"), "/json")]
		if !ok {
			reply(w, 404, map[string]string{"message": "No such container"})
			return
		}
		pid := 0
		if c.Status == "running" {
			pid = testPID
		}
		startedAt := c.StartedAt
		if startedAt == "" {
			startedAt = "0001-01-01T00:00:00Z"
		}
		reply(w, 200, map[string]any{
			"Id": "id-" + c.Name, "Name": "/" + c.Name, "Image": c.Image,
			"State":  map[string]any{"Status": c.Status, "Running": c.Status == "running", "Pid": pid, "Error": c.Error, "StartedAt": startedAt},
			"Config": map[string]any{"Labels": c.Labels}, "HostConfig": c.Host, "Mounts": c.Mounts,
		})
		if e.inspected != nil {
			e.inspected(c)
		}
	case r.Method == http.MethodDelete && strings.HasPrefix(p, "/containers/"):
		name := strings.TrimPrefix(p, "/containers/")
		if _, ok := e.containers[name]; !ok {
			reply(w, 404, map[string]string{"message": "No such container"})
			return
		}
		delete(e.containers, name)
		w.WriteHeader(204)
	default:
		reply(w, 500, map[string]string{"message": "unscripted " + r.Method + " " + p})
	}
}

func (e *fakeEngine) used(imageID string) bool {
	for _, c := range e.containers {
		if c.Image == imageID {
			return true
		}
	}
	return false
}

// host is one scripted miner host: pinned binaries, the engine, and the
// procfs and cgroupfs views of the sandbox process.
type host struct {
	t      *testing.T
	engine *fakeEngine
	socket string
	config Config
	sentry string
	// sentryFile is the sentry binary as Open would have hashed it.
	sentryFile os.FileInfo
	// dns answers registry host lookups; a host it lacks does not resolve.
	dns map[string][]netip.Addr
}

func writeFile(t *testing.T, file, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

func digestOf(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

func newHost(t *testing.T) *host {
	t.Helper()
	root := t.TempDir()
	runsc, sentry := filepath.Join(root, "bin", "runsc"), filepath.Join(root, "bin", "gvisor-bin", "gvisor_sentry")
	writeFile(t, runsc, "runsc binary")
	writeFile(t, sentry, "sentry binary")
	dataRoot := filepath.Join(root, "data")
	if err := os.MkdirAll(dataRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	engine, socket := newFakeEngine(t, dataRoot, runsc)
	public := []netip.Addr{netip.MustParseAddr("151.101.0.1")}
	h := &host{t: t, engine: engine, socket: socket, sentry: sentry, dns: map[string][]netip.Addr{
		"registry-1.docker.io": public, "ghcr.io": public,
	}, config: Config{
		DockerHost: "unix://" + socket, Runtime: "runsc", RunscPath: runsc, RunscSHA256: digestOf("runsc binary"),
		SentryPath: sentry, SentrySHA256: digestOf("sentry binary"), DataRoot: dataRoot, Slice: testSlice,
		CgroupRoot: filepath.Join(root, "cgroup"), ProcRoot: filepath.Join(root, "proc"),
		DiskMiB: 1024, Sandboxes: 2, ImageMaxMiB: 64, LogMiB: 4,
	}}
	var err error
	if h.sentryFile, err = os.Stat(sentry); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(h.config.CgroupRoot, "mc.slice", testSlice, "pids.max"), "4096\n")
	h.process(sentry, "/mc.slice/"+testSlice+"/docker-1.scope", testLease(nil).Resources)
	return h
}

// process scripts the kernel's view of the sandbox process: its executable,
// its cgroup, and that cgroup's limits.
func (h *host) process(exe, cgroup string, r sandbox.Resources) {
	h.t.Helper()
	proc := filepath.Join(h.config.ProcRoot, strconv.Itoa(testPID))
	_ = os.RemoveAll(proc)
	if err := os.MkdirAll(proc, 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.Symlink(exe, filepath.Join(proc, "exe")); err != nil {
		h.t.Fatal(err)
	}
	writeFile(h.t, filepath.Join(proc, "cgroup"), "0::"+cgroup+"\n")
	dir := filepath.Join(h.config.CgroupRoot, cgroup)
	writeFile(h.t, filepath.Join(dir, "memory.max"), strconv.Itoa(r.MemoryMiB<<20)+"\n")
	writeFile(h.t, filepath.Join(dir, "memory.swap.max"), "0\n")
	writeFile(h.t, filepath.Join(dir, "pids.max"), strconv.Itoa(r.PIDs)+"\n")
	writeFile(h.t, filepath.Join(dir, "cpu.max"), strconv.Itoa(r.CPUMillis*100)+" 100000\n")
}

// backend is the backend Open would build on this host. Open itself needs a
// real cgroup v2 mount for the slice, so tests of Create and Destroy build
// it directly; TestOpenRefusesUnverifiableHosts covers Open.
func (h *host) backend() *GVisor {
	return &GVisor{
		config: h.config, engine: newEngine(h.socket), sliceCgroup: "/mc.slice/" + testSlice, slicePIDs: 4096, sandboxExe: h.sentry, sandboxFile: h.sentryFile,
		lookup: func(_ context.Context, name string) ([]netip.Addr, error) {
			if addresses, ok := h.dns[name]; ok {
				return addresses, nil
			}
			return nil, fmt.Errorf("lookup %s: no such host", name)
		},
	}
}

func testLease(mutate func(*protocol.SandboxLeaseV1)) protocol.SandboxLeaseV1 {
	l := protocol.SandboxLeaseV1{
		AssignmentNonce: strings.Repeat("ab", 16), Env: map[string]string{}, Generation: 1, ImageDigest: testImageDigest,
		ImageReference: "busybox@" + testImageDigest, Isolation: sandbox.IsolationGVisor, IssuedAt: "2026-10-14T12:00:00Z",
		LeaseExpiresAt: "2026-10-14T12:10:00Z", MinerID: "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty",
		Network:   sandbox.NetworkPolicy{Mode: sandbox.NetworkNone, Allow: []string{}},
		Resources: sandbox.Resources{CPUMillis: 1000, MemoryMiB: 1024, DiskMiB: 5120, PIDs: 256},
		SandboxID: "sbx-" + strings.Repeat("0", 31) + "1", Schema: protocol.SandboxLeaseSchema, SchemaVersion: 1,
		SecretEnv: sandbox.SecretEnv{Delivery: sandbox.SecretDeliveryNone, Names: []string{}}, WorkloadKind: sandbox.WorkloadKind,
	}
	if mutate != nil {
		mutate(&l)
	}
	return l
}

func instanceOf(l protocol.SandboxLeaseV1) string {
	return miner.SandboxInstanceName(protocol.SandboxLeaseIDV1(l))
}

func refusalCode(err error) string {
	var refusal *miner.SandboxRefusal
	if errors.As(err, &refusal) {
		return refusal.Code
	}
	return ""
}

// A lease runs as one container under the pinned runtime, with no network,
// in the sandbox slice, with the lease's limits and a writable-layer quota.
// Create and Destroy are idempotent, and Instances ties the container to its
// lease for orphan reconciliation.
func TestCreateRunsTheLeaseUnderGVisorAndDestroyRemovesEverything(t *testing.T) {
	h := newHost(t)
	b := h.backend()
	ctx := context.Background()
	lease := testLease(nil)
	instance := instanceOf(lease)
	if err := b.Create(ctx, instance, lease); err != nil {
		t.Fatal(err)
	}
	if len(h.engine.created) != 1 {
		t.Fatalf("engine created %d containers, want 1", len(h.engine.created))
	}
	request := h.engine.created[0]
	hostConfig := request["HostConfig"].(map[string]any)
	for key, want := range map[string]any{
		"Runtime": "runsc", "NetworkMode": "none", "CgroupParent": testSlice, "Privileged": false,
		"NanoCpus": float64(1_000_000_000), "Memory": float64(1 << 30), "MemorySwap": float64(1 << 30), "PidsLimit": float64(256),
		"Init": false,
	} {
		if hostConfig[key] != want {
			t.Errorf("HostConfig.%s = %v, want %v", key, hostConfig[key], want)
		}
	}
	if request["Image"] != testImageID {
		t.Errorf("container image %v, want the verified engine ID %s", request["Image"], testImageID)
	}
	if size := hostConfig["StorageOpt"].(map[string]any)["size"]; size != "5120m" {
		t.Errorf("writable-layer quota %v, want 5120m", size)
	}
	if drop, add := fmt.Sprint(hostConfig["CapDrop"]), fmt.Sprint(hostConfig["CapAdd"]); drop != "[ALL]" || (add != "[]" && add != "<nil>") {
		t.Errorf("CapDrop %s CapAdd %s, want [ALL] and none", drop, add)
	}
	if _, binds := hostConfig["Binds"]; binds {
		t.Error("sandbox container requests bind mounts")
	}

	if err := b.Create(ctx, instance, lease); err != nil {
		t.Fatalf("replayed create: %v", err)
	}
	if len(h.engine.created) != 1 {
		t.Fatalf("replayed create made another container")
	}
	instances, err := b.Instances(ctx)
	if err != nil || len(instances) != 1 || instances[0] != (miner.SandboxInstance{Name: instance, LeaseID: protocol.SandboxLeaseIDV1(lease)}) {
		t.Fatalf("instances = %+v, %v", instances, err)
	}

	for range 2 {
		if err := b.Destroy(ctx, instance); err != nil {
			t.Fatal(err)
		}
	}
	if len(h.engine.containers) != 0 || len(h.engine.images) != 0 {
		t.Fatalf("after destroy: %d containers, %d images remain", len(h.engine.containers), len(h.engine.images))
	}
}

// A container that exists but was never started (a crash between create and
// start) is started and verified by a replayed Create; a container of the
// same name made for another lease is never adopted.
func TestCreateReplayStartsCreatedContainerAndRejectsAnotherLeases(t *testing.T) {
	h := newHost(t)
	b := h.backend()
	ctx := context.Background()
	lease := testLease(nil)
	instance := instanceOf(lease)
	h.engine.applied = func(c *engineContainer) { c.Status = "created" }
	if err := b.createContainer(ctx, instance, lease, mustDigest(t, lease)); err != nil {
		t.Fatal(err)
	}
	h.engine.applied = nil
	if err := b.Create(ctx, instance, lease); err != nil {
		t.Fatalf("replay did not resume the created container: %v", err)
	}
	if status := h.engine.containers[instance].Status; status != "running" {
		t.Fatalf("container is %s, want running", status)
	}

	other := testLease(func(l *protocol.SandboxLeaseV1) { l.LeaseExpiresAt = "2026-10-14T12:05:00Z" })
	if err := b.Create(ctx, instance, other); err == nil || refusalCode(err) != "" {
		t.Fatalf("create adopted a container made for another lease document: %v", err)
	}
}

// A workload that exits by itself after the engine started it under the
// verified configuration is served, not a miner fault (contract D11), even
// when it exits between the inspection and the kernel readback. The
// engine's configuration is still verified, and a start the engine or
// runtime reports as failed stays a miner fault.
func TestCreateServesAWorkloadThatExitedByItself(t *testing.T) {
	exit := func(c *engineContainer) { c.Status = "exited" }
	for _, test := range []struct {
		name                        string
		applied, started, inspected func(*engineContainer)
		noProcess                   bool
		want                        string // "" for success, else the miner fault
	}{
		{name: "exits at once", started: exit},
		{name: "exits during the readback", inspected: func(c *engineContainer) {
			if c.Status == "running" {
				c.Status = "exited"
			}
		}, noProcess: true},
		{name: "exits under an unverified runtime", applied: func(c *engineContainer) { c.Host["Runtime"] = "runc" }, started: exit, want: "runtime is"},
		{name: "runtime failed the start", started: func(c *engineContainer) {
			c.Status, c.Error = "exited", "OCI runtime create failed: runsc: exit status 1"
		}, want: "is exited, not running"},
		{name: "never started", started: func(c *engineContainer) { c.Status, c.StartedAt = "exited", "" }, want: "is exited, not running"},
		{name: "process vanished while running", noProcess: true, want: "process executable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newHost(t)
			h.engine.applied, h.engine.started, h.engine.inspected = test.applied, test.started, test.inspected
			if test.noProcess {
				if err := os.RemoveAll(filepath.Join(h.config.ProcRoot, strconv.Itoa(testPID))); err != nil {
					t.Fatal(err)
				}
			}
			lease := testLease(nil)
			err := h.backend().Create(context.Background(), instanceOf(lease), lease)
			switch {
			case test.want == "" && err != nil:
				t.Fatalf("create = %v, want the exited workload served", err)
			case test.want != "" && (err == nil || refusalCode(err) != "" || !strings.Contains(err.Error(), test.want)):
				t.Fatalf("create = %v, want a miner fault containing %q", err, test.want)
			case test.want == "":
				if err := h.backend().Create(context.Background(), instanceOf(lease), lease); err != nil || len(h.engine.created) != 1 {
					t.Fatalf("replayed create = %v with %d containers, want the exited sandbox adopted", err, len(h.engine.created))
				}
			}
		})
	}
}

func mustDigest(t *testing.T, lease protocol.SandboxLeaseV1) string {
	t.Helper()
	digest, err := protocol.SandboxDigestV1(lease)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

// What the backend cannot run exactly is refused with a non-fault code
// before a container exists; what goes wrong on the miner's side is a fault
// (no refusal code). Refused images are not kept.
func TestCreateRefusesWhatItCannotEnforce(t *testing.T) {
	key := "docker.io/library/busybox@" + testImageDigest
	for _, test := range []struct {
		name  string
		lease func(*protocol.SandboxLeaseV1)
		image func(*engineImage)
		// config changes the backend's configuration; such a case must
		// not reach the engine either.
		config func(*Config)
		dns    map[string][]netip.Addr
		code   string
		// policy marks a refusal the backend must reach before any pull.
		policy bool
		fault  string // the miner fault a case without a refusal code must report
	}{
		{name: "kata isolation", lease: func(l *protocol.SandboxLeaseV1) { l.Isolation = sandbox.IsolationKata }, code: "isolation_unsupported", policy: true},
		{name: "public network", lease: func(l *protocol.SandboxLeaseV1) { l.Network.Mode = sandbox.NetworkPublic }, code: "network_policy_unsupported", policy: true},
		{name: "more pids than the slice", lease: func(l *protocol.SandboxLeaseV1) { l.Resources.PIDs = 8192 }, code: "resources_unsupported", policy: true},
		{name: "registry has no such manifest", lease: func(l *protocol.SandboxLeaseV1) {
			l.ImageReference = "ghcr.io/nobody/missing@" + testImageDigest
		}, code: "image_unavailable"},
		{name: "registry refuses access", image: func(i *engineImage) { i.PullStatus = http.StatusUnauthorized }, code: "image_unavailable"},
		{name: "registry fails", image: func(i *engineImage) { i.PullStatus = http.StatusInternalServerError }, code: "image_unavailable"},
		{name: "registry gateway fails", image: func(i *engineImage) { i.PullStatus = http.StatusBadGateway }, code: "image_unavailable"},
		{name: "registry rate-limits mid-pull", image: func(i *engineImage) {
			i.PullMessages = []string{`{"error":"toomanyrequests: You have reached your pull rate limit"}`}
		}, code: "image_unavailable"},
		{name: "registry unreachable", image: func(i *engineImage) {
			i.PullMessages = []string{`{"error":"Get \"https://registry-1.docker.io/v2/\": net/http: TLS handshake timeout"}`}
		}, code: "image_unavailable"},
		// The engine relays registry text, so a disk-full message is not
		// evidence of the miner's disk; the headroom check before the pull is.
		{name: "pull runs out of reserved space", image: func(i *engineImage) {
			i.PullMessages = []string{`{"error":"write /data/tmp: no space left on device"}`}
		}, code: "image_unavailable"},
		{name: "download exceeds the image limit", image: func(i *engineImage) {
			i.PullMessages = []string{
				`{"id":"a","status":"Downloading","progressDetail":{"total":40000000}}`,
				`{"id":"b","status":"Downloading","progressDetail":{"total":40000000}}`,
			}
		}, code: "image_unavailable"},
		{name: "unpacked image exceeds the limit", image: func(i *engineImage) { i.Size = 65<<20 + 1 }, code: "image_unavailable"},
		{name: "image declares a volume", image: func(i *engineImage) { i.Volumes = map[string]any{"/data": map[string]any{}} }, code: "resources_unsupported"},
		{name: "image is not linux/amd64", image: func(i *engineImage) { i.Arch = "arm64" }, code: "image_unavailable"},
		{name: "localhost registry", lease: func(l *protocol.SandboxLeaseV1) {
			l.ImageReference = "localhost:5000/busybox@" + testImageDigest
		}, code: "image_unavailable", policy: true},
		{name: "IP literal registry", lease: func(l *protocol.SandboxLeaseV1) {
			l.ImageReference = "151.101.0.1/busybox@" + testImageDigest
		}, code: "image_unavailable", policy: true},
		{name: "registry resolving to a private address", lease: func(l *protocol.SandboxLeaseV1) {
			l.ImageReference = "registry.internal.example/busybox@" + testImageDigest
		}, dns: map[string][]netip.Addr{"registry.internal.example": {netip.MustParseAddr("10.1.2.3")}}, code: "image_unavailable", policy: true},
		{name: "registry with one metadata address", lease: func(l *protocol.SandboxLeaseV1) {
			l.ImageReference = "ghcr.io/someone/busybox@" + testImageDigest
		}, dns: map[string][]netip.Addr{"ghcr.io": {netip.MustParseAddr("151.101.0.1"), netip.MustParseAddr("169.254.169.254")}}, code: "image_unavailable", policy: true},
		{name: "registry that does not resolve", lease: func(l *protocol.SandboxLeaseV1) {
			l.ImageReference = "registry.invalid/busybox@" + testImageDigest
		}, code: "image_unavailable", policy: true},
		{name: "single-label registry", lease: func(l *protocol.SandboxLeaseV1) {
			l.ImageReference = "registry:5000/busybox@" + testImageDigest
		}, dns: map[string][]netip.Addr{"registry": {netip.MustParseAddr("151.101.0.1")}}, code: "image_unavailable", policy: true},
		{name: "internal registry name", lease: func(l *protocol.SandboxLeaseV1) {
			l.ImageReference = "metadata.google.internal/busybox@" + testImageDigest
		}, dns: map[string][]netip.Addr{"metadata.google.internal": {netip.MustParseAddr("151.101.0.1")}}, code: "image_unavailable", policy: true},
		{name: "mDNS registry name", lease: func(l *protocol.SandboxLeaseV1) {
			l.ImageReference = "nas.local/busybox@" + testImageDigest
		}, dns: map[string][]netip.Addr{"nas.local": {netip.MustParseAddr("151.101.0.1")}}, code: "image_unavailable", policy: true},
		{name: "engine records another digest", image: func(i *engineImage) {
			i.RepoDigests = []string{"busybox@sha256:" + strings.Repeat("9", 64)}
		}, fault: "is not recorded as"},
		{name: "engine records another repository", image: func(i *engineImage) {
			i.RepoDigests = []string{"evil/busybox@" + testImageDigest}
		}, fault: "is not recorded as"},
		{name: "data root lacks the pull reserve", config: func(c *Config) { c.ImageMaxMiB = 1 << 40 }, fault: "a pull reserves"},
		{name: "daemon breaks off the progress stream", image: func(i *engineImage) { i.PullMessages = []string{`{"error":`} }, fault: "decode docker pull progress"},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newHost(t)
			if test.image != nil {
				image := h.engine.catalog[key]
				test.image(&image)
				h.engine.catalog[key] = image
			}
			for name, addresses := range test.dns {
				h.dns[name] = addresses
			}
			b := h.backend()
			if test.config != nil {
				test.config(&b.config)
			}
			lease := testLease(test.lease)
			err := b.Create(context.Background(), instanceOf(lease), lease)
			if err == nil {
				t.Fatal("create succeeded")
			}
			if got := refusalCode(err); got != test.code || !strings.Contains(err.Error(), test.fault) {
				t.Fatalf("create = %v (refusal %q), want refusal %q / fault %q", err, got, test.code, test.fault)
			}
			if len(h.engine.containers) != 0 || len(h.engine.images) != 0 {
				t.Fatalf("refused create left %d containers and %d images", len(h.engine.containers), len(h.engine.images))
			}
			if (test.policy || test.config != nil) && h.engine.pulls != 0 {
				t.Fatalf("engine pulled %d times before a policy refusal", h.engine.pulls)
			}
		})
	}
}

// Create succeeds only once the engine's recorded container and the
// kernel's view of its process both match the lease. Each case is an engine
// or host that did not apply something the backend asked for.
func TestCreateRejectsSandboxesThatDoNotEnforceTheLease(t *testing.T) {
	resources := testLease(nil).Resources
	scope := "/mc.slice/" + testSlice + "/docker-1.scope"
	for _, test := range []struct {
		name    string
		applied func(*engineContainer)
		process func(*host)
		want    string
	}{
		{name: "engine ran runc", applied: func(c *engineContainer) { c.Host["Runtime"] = "runc" }, want: "runtime is"},
		{name: "engine attached a network", applied: func(c *engineContainer) { c.Host["NetworkMode"] = "bridge" }, want: "namespaces, ports"},
		{name: "engine dropped the disk quota", applied: func(c *engineContainer) { delete(c.Host, "StorageOpt") }, want: "resource limits"},
		{name: "engine dropped the memory limit", applied: func(c *engineContainer) { c.Host["Memory"] = 0 }, want: "resource limits"},
		{name: "engine mounted a volume", applied: func(c *engineContainer) { c.Mounts = []map[string]any{{"Type": "volume"}} }, want: "privileges, mounts"},
		{name: "engine granted privileges", applied: func(c *engineContainer) { c.Host["Privileged"] = true }, want: "privileges, mounts"},
		{name: "engine shared the host UTS namespace", applied: func(c *engineContainer) { c.Host["UTSMode"] = "host" }, want: "namespaces, ports"},
		{name: "engine published a port", applied: func(c *engineContainer) {
			c.Host["PortBindings"] = map[string]any{"80/tcp": []any{map[string]any{"HostPort": "8080"}}}
		}, want: "namespaces, ports"},
		{name: "engine added a capability", applied: func(c *engineContainer) { c.Host["CapAdd"] = []any{"CAP_NET_ADMIN"} }, want: "capabilities"},
		{name: "engine added an init process", applied: func(c *engineContainer) { c.Host["Init"] = true }, want: "host settings"},
		{name: "engine left init to the daemon default", applied: func(c *engineContainer) { delete(c.Host, "Init") }, want: "host settings"},
		{name: "engine passed runtime annotations", applied: func(c *engineContainer) {
			c.Host["Annotations"] = map[string]any{"dev.gvisor.flag.network": "host"}
		}, want: "host settings"},
		{name: "engine mounted a tmpfs", applied: func(c *engineContainer) { c.Host["Tmpfs"] = map[string]any{"/run": ""} }, want: "host settings"},
		{name: "engine set a sysctl", applied: func(c *engineContainer) { c.Host["Sysctls"] = map[string]any{"net.ipv4.ip_forward": "1"} }, want: "host settings"},
		{name: "engine allowed device nodes", applied: func(c *engineContainer) { c.Host["DeviceCgroupRules"] = []any{"c 1:3 rwm"} }, want: "host settings"},
		{name: "engine unbounded the log", applied: func(c *engineContainer) {
			c.Host["LogConfig"] = map[string]any{"Type": "json-file", "Config": map[string]any{}}
		}, want: "log bounds"},
		{name: "process is not the pinned sentry", process: func(h *host) { h.process(h.config.RunscPath+"-other", scope, resources) }, want: "not the pinned gVisor binary"},
		{name: "sentry replaced since open", process: func(h *host) {
			replacement := h.sentry + ".new"
			writeFile(h.t, replacement, "sentry binary")
			if err := os.Rename(replacement, h.sentry); err != nil {
				h.t.Fatal(err)
			}
		}, want: "replaced or rewritten"},
		{name: "process escaped the slice", process: func(h *host) { h.process(h.sentry, "/system.slice/docker-1.scope", resources) }, want: "outside slice"},
		{name: "kernel memory is unlimited", process: func(h *host) {
			h.process(h.sentry, scope, resources)
			writeFile(h.t, filepath.Join(h.config.CgroupRoot, scope, "memory.max"), "max\n")
		}, want: "kernel limits"},
		{name: "kernel swap is unlimited", process: func(h *host) {
			h.process(h.sentry, scope, resources)
			writeFile(h.t, filepath.Join(h.config.CgroupRoot, scope, "memory.swap.max"), "max\n")
		}, want: "kernel limits"},
		{name: "kernel cpu exceeds the lease", process: func(h *host) {
			h.process(h.sentry, scope, resources)
			writeFile(h.t, filepath.Join(h.config.CgroupRoot, scope, "cpu.max"), "200000 100000\n")
		}, want: "kernel limits"},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newHost(t)
			h.engine.applied = test.applied
			if test.process != nil {
				test.process(h)
			}
			lease := testLease(nil)
			err := h.backend().Create(context.Background(), instanceOf(lease), lease)
			if err == nil || refusalCode(err) != "" || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("create = %v, want a miner fault containing %q", err, test.want)
			}
		})
	}
}

// Open refuses every host property it cannot verify. Each case breaks one
// property of an otherwise valid host and must fail for that reason; the
// valid host itself fails only because a test directory is not a cgroup v2
// mount, which proves every earlier check passed.
func TestOpenRefusesUnverifiableHosts(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*host, *Config)
		want   string
	}{
		{name: "valid host up to the cgroup mount", want: "not on a cgroup v2 filesystem"},
		{name: "tcp daemon", mutate: func(_ *host, c *Config) { c.DockerHost = "tcp://127.0.0.1:2375" }, want: "unix://"},
		{name: "runc runtime", mutate: func(_ *host, c *Config) { c.Runtime = "runc" }, want: "runsc runtime"},
		{name: "runsc digest mismatch", mutate: func(_ *host, c *Config) { c.RunscSHA256 = strings.Repeat("0", 64) }, want: "pinned"},
		{name: "sentry digest mismatch", mutate: func(_ *host, c *Config) { c.SentrySHA256 = strings.Repeat("0", 64) }, want: "pinned"},
		{name: "runsc is a symlink", mutate: func(h *host, c *Config) {
			link := filepath.Join(filepath.Dir(c.RunscPath), "runsc-link")
			if err := os.Symlink(c.RunscPath, link); err != nil {
				h.t.Fatal(err)
			}
			c.RunscPath = link
		}, want: "open pinned binary"},
		{name: "unreviewed docker version", mutate: func(h *host, _ *Config) { h.engine.version = "28.1.0" }, want: "only " + PinnedDockerVersion},
		{name: "another data root", mutate: func(h *host, _ *Config) { h.engine.info["DockerRootDir"] = "/var/lib/docker" }, want: "want root="},
		{name: "cgroup v1", mutate: func(h *host, _ *Config) { h.engine.info["CgroupVersion"] = "1" }, want: "want root="},
		{name: "default containerd namespace", mutate: func(h *host, _ *Config) {
			h.engine.info["Containerd"] = map[string]any{"Namespaces": map[string]any{"Containers": "moby", "Plugins": "plugins.moby"}}
		}, want: "containerd namespaces"},
		{name: "insecure registry", mutate: func(h *host, _ *Config) {
			h.engine.info["RegistryConfig"].(map[string]any)["InsecureRegistryCIDRs"] = []string{"127.0.0.0/8", "10.0.0.0/8"}
		}, want: "insecure registry"},
		{name: "registry mirror", mutate: func(h *host, _ *Config) {
			h.engine.info["RegistryConfig"].(map[string]any)["Mirrors"] = []string{"https://mirror.internal.example/"}
		}, want: "mirrors"},
		{name: "insecure index", mutate: func(h *host, _ *Config) {
			h.engine.info["RegistryConfig"].(map[string]any)["IndexConfigs"] = map[string]any{"registry.internal.example": map[string]any{"Secure": false}}
		}, want: "registry index"},
		{name: "runtime registered elsewhere", mutate: func(h *host, _ *Config) {
			h.engine.info["Runtimes"] = map[string]any{"runsc": map[string]any{"path": "/usr/bin/runsc", "runtimeArgs": []string{"--systemd-cgroup", "--overlay2=none"}}}
		}, want: "does not register"},
		{name: "runtime with host networking", mutate: func(h *host, c *Config) {
			h.engine.info["Runtimes"] = map[string]any{"runsc": map[string]any{"path": c.RunscPath, "runtimeArgs": []string{"--systemd-cgroup", "--overlay2=none", "--network=host"}}}
		}, want: "unreviewed argument"},
		{name: "runtime without the quota overlay setting", mutate: func(h *host, c *Config) {
			h.engine.info["Runtimes"] = map[string]any{"runsc": map[string]any{"path": c.RunscPath, "runtimeArgs": []string{"--systemd-cgroup"}}}
		}, want: "--overlay2=none"},
		{name: "daemon runs another workload", mutate: func(h *host, _ *Config) {
			h.engine.containers["web"] = &engineContainer{Name: "web", Labels: map[string]string{}}
		}, want: "must be dedicated"},
		{name: "data root too small", mutate: func(_ *host, c *Config) { c.DiskMiB = 1 << 40 }, want: "need"},
		{name: "invalid slice", mutate: func(_ *host, c *Config) { c.Slice = "../escape.slice" }, want: "systemd slice"},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newHost(t)
			config := h.config
			if test.mutate != nil {
				test.mutate(h, &config)
			}
			_, err := Open(context.Background(), config)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Open = %v, want an error containing %q", err, test.want)
			}
		})
	}
}

func TestSliceCgroupFollowsSystemdNesting(t *testing.T) {
	for slice, want := range map[string]string{
		"mc.slice":            "/mc.slice",
		"mc-sandbox.slice":    "/mc.slice/mc-sandbox.slice",
		"mc-sandbox-v1.slice": "/mc.slice/mc-sandbox.slice/mc-sandbox-v1.slice",
		"-.slice":             "",
		"mc--x.slice":         "",
		"mc/x.slice":          "",
		"mc.service":          "",
	} {
		got, err := SliceCgroup(slice)
		if (err != nil) != (want == "") || got != want {
			t.Errorf("SliceCgroup(%q) = %q, %v; want %q", slice, got, err, want)
		}
	}
}

// The engine's recorded repository must be the lease's after Docker's own
// normalization; a different registry or namespace is a different image.
func TestNormalizedRepositoryMatchesDockerNormalization(t *testing.T) {
	digest := "@" + testImageDigest
	for reference, want := range map[string]string{
		"busybox" + digest:                         "docker.io/library/busybox",
		"docker.io/busybox" + digest:               "docker.io/library/busybox",
		"index.docker.io/library/busybox" + digest: "docker.io/library/busybox",
		"someone/busybox" + digest:                 "docker.io/someone/busybox",
		"ghcr.io/someone/busybox" + digest:         "ghcr.io/someone/busybox",
		"localhost:5000/busybox" + digest:          "localhost:5000/busybox",
		"localhost/busybox" + digest:               "localhost/busybox",
	} {
		if got, err := normalizedRepository(reference); err != nil || got != want {
			t.Errorf("normalizedRepository(%q) = %q, %v; want %q", reference, got, err, want)
		}
	}
	if _, err := normalizedRepository("busybox:latest"); err == nil {
		t.Error("a tag reference was normalized")
	}
}
