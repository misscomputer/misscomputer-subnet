// SPDX-License-Identifier: AGPL-3.0-only

package runtime

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	"github.com/misscomputer/misscomputer-subnet/pkg/workload"
)

func TestDockerRuntimeRejectsUnpinnedImage(t *testing.T) {
	spec, layer, err := workload.Generate("static", 1024)
	if err != nil {
		t.Fatal(err)
	}
	manifest := artifact.Manifest{
		Annotations: map[string]string{"docker.image": "misscomputer-workload:latest"},
		Layers:      []artifact.Layer{{Digest: artifact.Digest(layer)}},
	}
	ticket := protocol.Ticket{ChallengePath: spec.ChallengePath, ChallengeSHA256: protocol.ChallengeDigest(spec.ChallengeValue)}
	_, err = NewDockerRuntime("docker", t.TempDir()).Deploy(context.Background(), ticket, manifest, [][]byte{layer})
	if err == nil || !strings.Contains(err.Error(), "pinned") {
		t.Fatalf("unpinned image error = %v", err)
	}
}

func TestRuntimeNamesAndCleanupAreEndpointIncarnationSafe(t *testing.T) {
	spec, layer, err := workload.Generate("static", 1024)
	if err != nil {
		t.Fatal(err)
	}
	manifest := artifact.Manifest{Layers: []artifact.Layer{{Digest: artifact.Digest(layer)}}}
	first := protocol.Ticket{
		DeploymentID: "same", MinerID: "m1", Generation: 1, AssignmentNonce: "nonce-a",
		ChallengePath: spec.ChallengePath, ChallengeSHA256: protocol.ChallengeDigest(spec.ChallengeValue),
	}
	second := first
	second.Generation = 2
	second.AssignmentNonce = "nonce-b"
	runtime := NewLocalRuntime()
	firstInstance, err := runtime.Deploy(context.Background(), first, manifest, [][]byte{layer})
	if err != nil {
		t.Fatal(err)
	}
	secondInstance, err := runtime.Deploy(context.Background(), second, manifest, [][]byte{layer})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Stop(context.Background(), secondInstance.ID)
	if firstInstance.ID == secondInstance.ID {
		t.Fatalf("incarnations collided at %q", firstInstance.ID)
	}
	if firstInstance.ID != InstanceName(protocol.EndpointID(first)) || secondInstance.ID != InstanceName(protocol.EndpointID(second)) {
		t.Fatalf("runtime IDs are not derived from endpoint IDs: %q %q", firstInstance.ID, secondInstance.ID)
	}
	if err := runtime.Stop(context.Background(), firstInstance.ID); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get(secondInstance.URL + "/healthz")
	if err != nil {
		t.Fatalf("stopping old generation stopped the new one: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("new generation health status = %d", resp.StatusCode)
	}
}

func TestInstanceNameNormalizationRetainsCollisionResistance(t *testing.T) {
	first := InstanceName("deployment/miner")
	second := InstanceName("deployment?miner")
	if first == second {
		t.Fatalf("normalized endpoint IDs collided at %q", first)
	}
	valid := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]+$`)
	for _, name := range []string{first, second, InstanceName(strings.Repeat("long/", 100))} {
		if !valid.MatchString(name) || len(name) > 70 {
			t.Fatalf("invalid runtime name %q", name)
		}
	}
}

func TestDockerStopRetainsLayerOnFailureAndHandlesMissingContainer(t *testing.T) {
	directory := t.TempDir()
	failureMarker := filepath.Join(directory, "fail")
	binary := filepath.Join(directory, "fake-docker")
	script := "#!/bin/sh\nif [ -f '" + failureMarker + "' ]; then echo 'daemon unavailable' >&2; exit 1; fi\necho 'Error response from daemon: No such container' >&2\nexit 1\n"
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(failureMarker, []byte("fail"), 0o600); err != nil {
		t.Fatal(err)
	}
	layerPath := filepath.Join(directory, "verified-test.layer")
	if err := os.WriteFile(layerPath, []byte("layer"), 0o400); err != nil {
		t.Fatal(err)
	}
	runtime := NewDockerRuntime(binary, directory)
	runtime.layers["instance"] = layerPath
	if err := runtime.Stop(context.Background(), "instance"); err == nil {
		t.Fatal("Docker stop failure was hidden")
	}
	if _, err := os.Stat(layerPath); err != nil {
		t.Fatalf("layer removed after failed stop: %v", err)
	}
	if runtime.layers["instance"] != layerPath {
		t.Fatal("layer bookkeeping removed after failed stop")
	}
	if err := os.Remove(failureMarker); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Cleanup(context.Background()); err != nil {
		t.Fatalf("cleanup should retry an already-gone container idempotently: %v", err)
	}
	if _, err := os.Stat(layerPath); !os.IsNotExist(err) {
		t.Fatalf("layer remains after idempotent stop: %v", err)
	}
	if _, exists := runtime.layers["instance"]; exists {
		t.Fatal("successful idempotent stop retained bookkeeping")
	}
}

func TestDockerStopAfterRestartDerivesExactLayerPath(t *testing.T) {
	controlDir := t.TempDir()
	stateDir := t.TempDir()
	binary := filepath.Join(controlDir, "fake-docker")
	script := "#!/bin/sh\necho 'Error response from daemon: No such container' >&2\nexit 1\n"
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	ticket := protocol.Ticket{
		DeploymentID: "restart", MinerID: "m1", Generation: 1, AssignmentNonce: "cleanup-plan",
	}
	beforeRestart := NewDockerRuntime(binary, stateDir)
	plan, err := beforeRestart.PlanCleanup(ticket)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plan.LayerPath, []byte("verified"), 0o400); err != nil {
		t.Fatal(err)
	}

	// A fresh backend has no in-memory layer map. Cleanup must nevertheless
	// use the exact persisted path even if the configured state directory was
	// changed before restart.
	restarted := NewDockerRuntime(binary, t.TempDir())
	if err := restarted.StopCleanup(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(plan.LayerPath); !os.IsNotExist(err) {
		t.Fatalf("restart cleanup left deterministic layer: %v", err)
	}
}

func TestDockerRecoveryInspectsExactLegacyBindBeforeStopping(t *testing.T) {
	controlDir := t.TempDir()
	stateDir := t.TempDir()
	legacyPath := filepath.Join(stateDir, "verified-381902.layer")
	if err := os.WriteFile(legacyPath, []byte("legacy-verified-layer"), 0o400); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(controlDir, "stopped")
	logPath := filepath.Join(controlDir, "calls.log")
	binary := filepath.Join(controlDir, "fake-docker")
	script := "#!/bin/sh\nprintf '%s\\n' \"$1\" >> '" + logPath + "'\ncase \"$1\" in\ninspect)\n  if [ -f '" + marker + "' ]; then echo 'Error response from daemon: No such container' >&2; exit 1; fi\n  printf '%s\\n' '[{\"Type\":\"bind\",\"Source\":\"" + legacyPath + "\",\"Destination\":\"/app/workload.layer\",\"RW\":false}]'\n  ;;\nstop) : > '" + marker + "' ;;\n*) exit 1 ;;\nesac\n"
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	ticket := protocol.Ticket{DeploymentID: "legacy", MinerID: "m1", Generation: 4, AssignmentNonce: "random-parent-layer"}
	runtime := NewDockerRuntime(binary, stateDir)
	plan, err := runtime.RecoverCleanup(context.Background(), ticket)
	if err != nil {
		t.Fatal(err)
	}
	if plan.InstanceID != InstanceName(protocol.EndpointID(ticket)) || plan.LayerPath != legacyPath || plan.LayerRoot != stateDir {
		t.Fatalf("legacy inspection plan = %+v", plan)
	}
	if err := runtime.StopCleanup(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(legacyPath); !os.IsNotExist(err) {
		t.Fatalf("exact legacy layer remains after confirmed container removal: %v", err)
	}
	calls, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(calls), "inspect\nstop\ninspect\n") {
		t.Fatalf("legacy cleanup did not inspect before stop and confirm removal: %q", calls)
	}
}

func TestDockerRecoveryDoesNotCompleteWhenAbsentContainerLeavesUnattributableLegacyLayer(t *testing.T) {
	controlDir := t.TempDir()
	stateDir := t.TempDir()
	legacyPath := filepath.Join(stateDir, "verified-918273.layer")
	if err := os.WriteFile(legacyPath, []byte("unattributable"), 0o400); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(controlDir, "fake-docker")
	script := "#!/bin/sh\necho 'Error response from daemon: No such container' >&2\nexit 1\n"
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	ticket := protocol.Ticket{DeploymentID: "legacy-absent", MinerID: "m1", Generation: 2, AssignmentNonce: "unknown-random-file"}
	_, err := NewDockerRuntime(binary, stateDir).RecoverCleanup(context.Background(), ticket)
	if err == nil || !strings.Contains(err.Error(), "unattributable") {
		t.Fatalf("absent-container legacy recovery error = %v", err)
	}
	if _, statErr := os.Stat(legacyPath); statErr != nil {
		t.Fatalf("unattributable legacy file was mutated: %v", statErr)
	}
}

func TestDockerRecoveryRejectsUnsafeLegacyMountsBeforeStop(t *testing.T) {
	ticket := protocol.Ticket{DeploymentID: "unsafe", MinerID: "m1", Generation: 1, AssignmentNonce: "mount-validation"}
	instanceID := InstanceName(protocol.EndpointID(ticket))
	for _, testCase := range []struct {
		name        string
		source      func(root, outside string) string
		destination string
		readWrite   bool
		duplicate   bool
	}{
		{name: "outside-root", source: func(_, outside string) string { return filepath.Join(outside, "verified-123.layer") }, destination: "/app/workload.layer"},
		{name: "mismatched-name", source: func(root, _ string) string { return filepath.Join(root, "another-runtime.layer") }, destination: "/app/workload.layer"},
		{name: "wrong-destination", source: func(root, _ string) string { return filepath.Join(root, "verified-123.layer") }, destination: "/app/not-workload.layer"},
		{name: "writable", source: func(root, _ string) string { return filepath.Join(root, "verified-123.layer") }, destination: "/app/workload.layer", readWrite: true},
		{name: "duplicate", source: func(root, _ string) string { return filepath.Join(root, "verified-123.layer") }, destination: "/app/workload.layer", duplicate: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			controlDir := t.TempDir()
			root := t.TempDir()
			outside := t.TempDir()
			source := testCase.source(root, outside)
			if err := os.WriteFile(source, []byte("candidate"), 0o400); err != nil {
				t.Fatal(err)
			}
			mount := `{"Type":"bind","Source":"` + source + `","Destination":"` + testCase.destination + `","RW":`
			if testCase.readWrite {
				mount += "true}"
			} else {
				mount += "false}"
			}
			payload := "[" + mount
			if testCase.duplicate {
				payload += "," + mount
			}
			payload += "]"
			stopLog := filepath.Join(controlDir, "stops.log")
			binary := filepath.Join(controlDir, "fake-docker")
			script := "#!/bin/sh\ncase \"$1\" in\ninspect) printf '%s\\n' '" + payload + "' ;;\nstop) printf '%s\\n' \"$2\" >> '" + stopLog + "' ;;\nesac\n"
			if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
				t.Fatal(err)
			}
			_, err := NewDockerRuntime(binary, root).RecoverCleanup(context.Background(), ticket)
			if err == nil {
				t.Fatalf("unsafe mount was accepted for %q", instanceID)
			}
			if _, statErr := os.Stat(stopLog); !os.IsNotExist(statErr) {
				t.Fatalf("unsafe mount stopped a container before validation: %v", statErr)
			}
			if _, statErr := os.Stat(source); statErr != nil {
				t.Fatalf("unsafe source was mutated: %v", statErr)
			}
		})
	}
}

func TestDockerStopCleanupRejectsPersistedPathOutsideOwnershipRoot(t *testing.T) {
	controlDir := t.TempDir()
	root := t.TempDir()
	outside := t.TempDir()
	path := filepath.Join(outside, "verified-123.layer")
	if err := os.WriteFile(path, []byte("do-not-delete"), 0o400); err != nil {
		t.Fatal(err)
	}
	stopLog := filepath.Join(controlDir, "stops.log")
	binary := filepath.Join(controlDir, "fake-docker")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '" + stopLog + "'\n"
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	err := NewDockerRuntime(binary, root).StopCleanup(context.Background(), CleanupPlan{
		InstanceID: "miss-safe", LayerPath: path, LayerRoot: root,
	})
	if err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("out-of-root persisted cleanup error = %v", err)
	}
	if _, statErr := os.Stat(stopLog); !os.IsNotExist(statErr) {
		t.Fatalf("invalid persisted path reached docker: %v", statErr)
	}
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("invalid persisted source was deleted: %v", statErr)
	}
}

func TestDockerRecoveryRejectsSymlinkedLegacySource(t *testing.T) {
	controlDir := t.TempDir()
	root := t.TempDir()
	outbound := filepath.Join(t.TempDir(), "outside.layer")
	if err := os.WriteFile(outbound, []byte("outside"), 0o400); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "verified-123.layer")
	if err := os.Symlink(outbound, link); err != nil {
		t.Fatal(err)
	}
	stopLog := filepath.Join(controlDir, "stops.log")
	binary := filepath.Join(controlDir, "fake-docker")
	payload := `[{"Type":"bind","Source":"` + link + `","Destination":"/app/workload.layer","RW":false}]`
	script := "#!/bin/sh\ncase \"$1\" in\ninspect) printf '%s\\n' '" + payload + "' ;;\nstop) printf '%s\\n' \"$2\" >> '" + stopLog + "' ;;\nesac\n"
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	ticket := protocol.Ticket{DeploymentID: "symlink", MinerID: "m1", Generation: 1, AssignmentNonce: "unsafe-link"}
	_, err := NewDockerRuntime(binary, root).RecoverCleanup(context.Background(), ticket)
	if err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("symlinked legacy source error = %v", err)
	}
	if _, statErr := os.Stat(stopLog); !os.IsNotExist(statErr) {
		t.Fatalf("symlinked source reached docker stop: %v", statErr)
	}
	if content, readErr := os.ReadFile(outbound); readErr != nil || string(content) != "outside" {
		t.Fatalf("symlink target was mutated: content=%q err=%v", content, readErr)
	}
}

func TestDockerLegacyOrphanCleanupIntegration(t *testing.T) {
	if os.Getenv("MISS_RUN_DOCKER_INTEGRATION") != "1" {
		t.Skip("set MISS_RUN_DOCKER_INTEGRATION=1 for the local Docker integration")
	}
	if err := exec.Command("docker", "image", "inspect", "alpine:3.21").Run(); err != nil {
		t.Skipf("local alpine:3.21 image unavailable: %v", err)
	}
	stateDir := t.TempDir()
	legacyPath := filepath.Join(stateDir, "verified-381902.layer")
	if err := os.WriteFile(legacyPath, []byte("legacy-integration-layer"), 0o400); err != nil {
		t.Fatal(err)
	}
	ticket := protocol.Ticket{
		DeploymentID: "legacy-integration", MinerID: "m1", Generation: 1,
		AssignmentNonce: fmt.Sprintf("docker-%d-%d", os.Getpid(), time.Now().UnixNano()),
	}
	instanceID := InstanceName(protocol.EndpointID(ticket))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	created := false
	t.Cleanup(func() {
		if created {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cleanupCancel()
			_ = exec.CommandContext(cleanupCtx, "docker", "rm", "-f", instanceID).Run()
		}
	})
	out, err := exec.CommandContext(
		ctx, "docker", "run", "-d", "--rm", "--name", instanceID,
		"--label", "misscomputer.test=legacy-cleanup",
		"--mount", "type=bind,src="+legacyPath+",dst=/app/workload.layer,readonly",
		"alpine:3.21", "sh", "-c", "while :; do sleep 1; done",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("start local legacy container: %v: %s", err, out)
	}
	created = true
	runtime := NewDockerRuntime("docker", stateDir)
	plan, err := runtime.RecoverCleanup(ctx, ticket)
	if err != nil {
		t.Fatal(err)
	}
	if plan.LayerPath != legacyPath || plan.LayerRoot != stateDir {
		t.Fatalf("real Docker legacy plan = %+v", plan)
	}
	if err := runtime.StopCleanup(ctx, plan); err != nil {
		t.Fatal(err)
	}
	created = false
	if inspectErr := exec.CommandContext(ctx, "docker", "inspect", instanceID).Run(); inspectErr == nil {
		t.Fatal("legacy Docker container still exists after confirmed cleanup")
	}
	if _, statErr := os.Stat(legacyPath); !os.IsNotExist(statErr) {
		t.Fatalf("legacy Docker layer still exists: %v", statErr)
	}
}

func dockerDeployFixture(t *testing.T) (protocol.Ticket, artifact.Manifest, [][]byte, string) {
	t.Helper()
	spec, layer, err := workload.Generate("static", 1024)
	if err != nil {
		t.Fatal(err)
	}
	manifest := artifact.Manifest{
		Annotations: map[string]string{"docker.image": "sha256:pinned-test-image"},
		Layers:      []artifact.Layer{{Digest: artifact.Digest(layer)}},
	}
	ticket := protocol.Ticket{
		DeploymentID: "orphan", MinerID: "m1", Generation: 3, AssignmentNonce: "nonce-run-failure",
		ChallengePath: spec.ChallengePath, ChallengeSHA256: protocol.ChallengeDigest(spec.ChallengeValue),
	}
	return ticket, manifest, [][]byte{layer}, InstanceName(protocol.EndpointID(ticket))
}

// TestDockerRunFailureStopsDeterministicallyNamedContainer covers the orphan
// window where the docker CLI fails or is killed by cancellation after the
// daemon may already have created the container: Deploy must invoke Stop with
// the deterministic endpoint-derived name and leave no layer or bookkeeping.
func TestDockerRunFailureStopsDeterministicallyNamedContainer(t *testing.T) {
	cases := []struct {
		name        string
		runBehavior string
		timeout     time.Duration
	}{
		{name: "run-error", runBehavior: "echo 'daemon rejected run' >&2; exit 125", timeout: 0},
		{name: "run-killed-by-cancellation", runBehavior: "exec sleep 10", timeout: 300 * time.Millisecond},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			controlDir := t.TempDir()
			stateDir := t.TempDir()
			stopLog := filepath.Join(controlDir, "stops.log")
			binary := filepath.Join(controlDir, "fake-docker")
			script := "#!/bin/sh\ncase \"$1\" in\nrun) " + testCase.runBehavior + " ;;\nstop) printf '%s\\n' \"$2\" >> '" + stopLog + "'; exit 0 ;;\ninspect) echo 'Error response from daemon: No such container' >&2; exit 1 ;;\n*) exit 1 ;;\nesac\n"
			if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
				t.Fatal(err)
			}
			ticket, manifest, layers, expectedName := dockerDeployFixture(t)
			runtime := NewDockerRuntime(binary, stateDir)
			ctx := context.Background()
			if testCase.timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, testCase.timeout)
				defer cancel()
			}
			_, err := runtime.Deploy(ctx, ticket, manifest, layers)
			if err == nil || !strings.Contains(err.Error(), "docker run") {
				t.Fatalf("docker run failure error = %v", err)
			}
			stops, readErr := os.ReadFile(stopLog)
			if readErr != nil || !strings.Contains(string(stops), expectedName) {
				t.Fatalf("failed run did not stop deterministic container name %q: log=%q err=%v", expectedName, stops, readErr)
			}
			entries, readDirErr := os.ReadDir(stateDir)
			if readDirErr != nil || len(entries) != 0 {
				t.Fatalf("failed run left materialized layers: entries=%d err=%v", len(entries), readDirErr)
			}
			runtime.mu.Lock()
			retained := len(runtime.layers)
			runtime.mu.Unlock()
			if retained != 0 {
				t.Fatalf("failed run retained %d bookkeeping entries", retained)
			}
		})
	}
}

// TestDockerRunFailureRetainsBookkeepingWhenStopFails proves a failed
// run-cleanup keeps the layer and name registered so Cleanup can retry, and
// that the retry then releases both.
func TestDockerRunFailureRetainsBookkeepingWhenStopFails(t *testing.T) {
	controlDir := t.TempDir()
	stateDir := t.TempDir()
	stopFailureMarker := filepath.Join(controlDir, "stop-fails")
	binary := filepath.Join(controlDir, "fake-docker")
	script := "#!/bin/sh\ncase \"$1\" in\nrun) echo 'daemon rejected run' >&2; exit 125 ;;\nstop) if [ -f '" + stopFailureMarker + "' ]; then echo 'daemon unavailable' >&2; exit 1; fi; echo 'Error response from daemon: No such container' >&2; exit 1 ;;\n*) exit 1 ;;\nesac\n"
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stopFailureMarker, []byte("fail"), 0o600); err != nil {
		t.Fatal(err)
	}
	ticket, manifest, layers, expectedName := dockerDeployFixture(t)
	runtime := NewDockerRuntime(binary, stateDir)
	_, err := runtime.Deploy(context.Background(), ticket, manifest, layers)
	if err == nil || !strings.Contains(err.Error(), "docker run") || !strings.Contains(err.Error(), "cleanup") {
		t.Fatalf("run+stop failure error = %v", err)
	}
	runtime.mu.Lock()
	layerPath := runtime.layers[expectedName]
	runtime.mu.Unlock()
	if layerPath == "" {
		t.Fatal("failed cleanup discarded bookkeeping needed for retry")
	}
	if _, statErr := os.Stat(layerPath); statErr != nil {
		t.Fatalf("failed cleanup removed layer before container stop succeeded: %v", statErr)
	}
	if removeErr := os.Remove(stopFailureMarker); removeErr != nil {
		t.Fatal(removeErr)
	}
	if cleanupErr := runtime.Cleanup(context.Background()); cleanupErr != nil {
		t.Fatalf("cleanup retry: %v", cleanupErr)
	}
	if _, statErr := os.Stat(layerPath); !os.IsNotExist(statErr) {
		t.Fatalf("cleanup retry left layer: %v", statErr)
	}
	runtime.mu.Lock()
	retained := len(runtime.layers)
	runtime.mu.Unlock()
	if retained != 0 {
		t.Fatalf("cleanup retry retained %d bookkeeping entries", retained)
	}
}
