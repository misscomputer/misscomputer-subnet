// SPDX-License-Identifier: AGPL-3.0-only

package runtime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
	"github.com/misscomputer/misscomputer-subnet/pkg/artifact/ocitest"
)

// TestDockerOCIRuntimeRunsVerifiedImageUnderSmallV1 is the real-engine proof
// of contract §7.1 and §16 criterion 10: a Go-built OCI image is verified,
// loaded, identity-checked and run with the small-v1 isolation, and the app
// observes that isolation from inside. It needs root, Docker and iptables,
// creates its own network and host rule, and removes both.
func TestDockerOCIRuntimeRunsVerifiedImageUnderSmallV1(t *testing.T) {
	if os.Getenv("MISSCOMPUTER_DOCKER_OCI_TEST") != "1" {
		t.Skip("MISSCOMPUTER_DOCKER_OCI_TEST=1 is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	image := buildOrganicAppImage(t)
	store := artifact.FileStore{Root: t.TempDir()}
	if err := image.Publish(ctx, store); err != nil {
		t.Fatal(err)
	}
	suffix := randomHex(t, 3)
	runtime := NewDockerOCIRuntime("docker", t.TempDir(), "miss-oci-test-"+suffix, "missoci"+suffix)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Minute)
		defer cleanupCancel()
		rule := append([]string{"-D"}, runtime.HostIsolationRule()...)
		_ = exec.CommandContext(cleanupCtx, findIPTables(), rule...).Run()
		_ = exec.CommandContext(cleanupCtx, "docker", "network", "rm", runtime.Network).Run()
	})
	if err := runtime.EnsureNetwork(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runtime.EnsureHostIsolation(ctx, true); err != nil {
		t.Fatal(err)
	}
	if err := runtime.EnsureHostIsolation(ctx, false); err != nil {
		t.Fatalf("installed host isolation rule does not verify: %v", err)
	}
	gateway := strings.TrimSpace(dockerOutput(t, ctx, "network", "inspect", "--format", "{{range .IPAM.Config}}{{.Gateway}}{{end}}", runtime.Network))
	hostListener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer hostListener.Close()
	go func() {
		for {
			conn, err := hostListener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	hostPort := hostListener.Addr().(*net.TCPAddr).Port

	workload, health := testWorkload(), testHealth()
	launch := func(instanceID string) Started {
		t.Helper()
		started, err := runtime.Launch(ctx, Launch{
			InstanceID: instanceID, ArtifactDigest: image.ArtifactDigest, Manifest: image.Manifest,
			Blobs: store, Workload: workload, Profile: SmallV1,
		})
		if err != nil {
			t.Fatalf("launch %s: %v", instanceID, err)
		}
		t.Cleanup(func() { _ = runtime.Stop(context.Background(), instanceID) })
		return started
	}
	first := launch("miss-oci-test-a-" + suffix)
	second := launch("miss-oci-test-b-" + suffix)
	if first.LoadedImageConfigDigest != image.Manifest.Config.Digest {
		t.Fatalf("loaded config digest = %s, want %s", first.LoadedImageConfigDigest, image.Manifest.Config.Digest)
	}
	running := func(ctx context.Context) (bool, error) { return runtime.Running(ctx, first.Instance.ID) }
	if err := StartupHealth(ctx, nil, first.Instance.URL, "app.on.miss.computer", health, running); err != nil {
		t.Fatalf("startup health: %v", err)
	}
	if err := StartupHealth(ctx, nil, second.Instance.URL, "", health, nil); err != nil {
		t.Fatalf("second replica health: %v", err)
	}

	secondHost := strings.TrimPrefix(second.Instance.URL, "http://")
	targets := []string{
		net.JoinHostPort(gateway, strconv.Itoa(hostPort)), // host service via the bridge gateway
		secondHost,           // another organic container
		"169.254.169.254:80", // link-local metadata
		"10.0.0.1:80",        // RFC 1918
		"1.1.1.1:443",        // public egress (D9 deny-all)
	}
	var report struct {
		UID         int               `json:"uid"`
		GID         int               `json:"gid"`
		Env         []string          `json:"env"`
		RootFSWrite string            `json:"rootfs_write"`
		TmpWrite    string            `json:"tmp_write"`
		TmpBytes    uint64            `json:"tmp_bytes"`
		Status      map[string]string `json:"status"`
		PIDsMax     string            `json:"pids_max"`
		MemoryMax   string            `json:"memory_max"`
		Dials       map[string]string `json:"dials"`
	}
	resp, err := http.Get(first.Instance.URL + "/probe?dial=" + strings.Join(targets, ","))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err := json.Unmarshal(body, &report); err != nil {
		t.Fatalf("probe report %s: %v", body, err)
	}
	t.Logf("probe report: %s", body)
	if report.UID != 65532 || report.GID != 65532 {
		t.Errorf("container runs as %d:%d, want 65532:65532", report.UID, report.GID)
	}
	if report.RootFSWrite == "" || report.TmpWrite != "" || report.TmpBytes == 0 || report.TmpBytes > 64<<20 {
		t.Errorf("filesystem rootfs_write=%q tmp_write=%q tmp_bytes=%d", report.RootFSWrite, report.TmpWrite, report.TmpBytes)
	}
	if report.PIDsMax != "256" || report.MemoryMax != "1073741824" {
		t.Errorf("cgroup pids.max=%q memory.max=%q", report.PIDsMax, report.MemoryMax)
	}
	if report.Status["CapEff"] != "0000000000000000" || report.Status["NoNewPrivs"] != "1" {
		t.Errorf("privileges = %v", report.Status)
	}
	for _, target := range targets {
		if !strings.HasPrefix(report.Dials[target], "blocked") {
			t.Errorf("container reached %s: %q", target, report.Dials[target])
		}
	}
	// Engine-injected HOSTNAME/HOME are the only additions to image ENV plus
	// the runtime's PORT and HOST.
	allowed := []string{"PATH=/", "IMAGE_ENV=kept", "PORT=8080", "HOST=0.0.0.0"}
	for _, entry := range report.Env {
		name, _, _ := strings.Cut(entry, "=")
		if !slices.Contains(allowed, entry) && name != "HOSTNAME" && name != "HOME" {
			t.Errorf("unexpected container environment entry %q", entry)
		}
	}
	for _, want := range allowed {
		if !slices.Contains(report.Env, want) {
			t.Errorf("container environment lacks %q: %v", want, report.Env)
		}
	}

	ref := artifact.LayoutRefName(image.ArtifactDigest)
	if err := runtime.Stop(ctx, first.Instance.ID); err != nil {
		t.Fatal(err)
	}
	if err := exec.CommandContext(ctx, "docker", "image", "inspect", ref).Run(); err != nil {
		t.Fatalf("image removed while another endpoint still uses it: %v", err)
	}
	if alive, err := runtime.Running(ctx, second.Instance.ID); err != nil || !alive {
		t.Fatalf("stopping one replica affected the other: alive=%t err=%v", alive, err)
	}
	if err := runtime.Stop(ctx, second.Instance.ID); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Stop(ctx, second.Instance.ID); err != nil {
		t.Fatalf("repeated stop is not idempotent: %v", err)
	}
	if err := exec.CommandContext(ctx, "docker", "image", "inspect", ref).Run(); err == nil {
		t.Fatal("image retained after its last endpoint stopped")
	}
	entries, err := os.ReadDir(runtime.StateDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("instance state retained after cleanup: %v err=%v", entries, err)
	}
}

func buildOrganicAppImage(t *testing.T) ocitest.Image {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "app")
	build := exec.Command(filepath.Join(goruntime.GOROOT(), "bin", "go"), "build", "-trimpath", "-o", binary, "./testdata/organicapp")
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build test app: %v: %s", err, out)
	}
	body, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	image, err := ocitest.Build(ocitest.Spec{
		Layers:     []map[string]ocitest.File{{"app": {Mode: 0o755, Body: body}}},
		Entrypoint: []string{"/app"}, Env: []string{"PATH=/", "IMAGE_ENV=kept"}, Gzip: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return image
}

func dockerOutput(t *testing.T, ctx context.Context, args ...string) string {
	t.Helper()
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %v: %v: %s", args, err, out)
	}
	return string(out)
}

func randomHex(t *testing.T, size int) string {
	t.Helper()
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(buffer)
}
