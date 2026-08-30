// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
	"github.com/misscomputer/misscomputer-subnet/pkg/ledger"
	"github.com/misscomputer/misscomputer-subnet/pkg/miner"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	deployruntime "github.com/misscomputer/misscomputer-subnet/pkg/runtime"
	"github.com/misscomputer/misscomputer-subnet/pkg/tunnel"
	"github.com/misscomputer/misscomputer-subnet/pkg/validator"
	"github.com/misscomputer/misscomputer-subnet/pkg/workload"
)

// TestDockerFailedAcceptanceCleansResources is opt-in because it needs a
// pinned workload image, Docker socket access, host networking, and a state
// directory mounted at the same path for the test and Docker daemon.
func TestDockerFailedAcceptanceCleansResources(t *testing.T) {
	image := os.Getenv("MISSCOMPUTER_DOCKER_TEST_IMAGE")
	if image == "" {
		t.Skip("MISSCOMPUTER_DOCKER_TEST_IMAGE is not set")
	}
	stateDir := os.Getenv("MISSCOMPUTER_DOCKER_TEST_STATE_DIR")
	if stateDir == "" {
		t.Fatal("MISSCOMPUTER_DOCKER_TEST_STATE_DIR is required")
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(stateDir); err != nil || len(entries) != 0 {
		t.Fatalf("Docker test state directory must start empty: entries=%d err=%v", len(entries), err)
	}

	ctx := context.Background()
	ownerPublic, ownerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, minerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store := artifact.FileStore{Root: t.TempDir()}
	spec, layer, err := workload.Generate("static", 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := artifact.Publish(ctx, store, spec.Kind, [][]byte{layer}, map[string]string{"docker.image": image})
	if err != nil {
		t.Fatal(err)
	}
	tunnels := tunnel.NewLocalRegistry()
	router := newAuthorizedTestRouter(t, tunnels, "docker-failure-probe", ownerPublic, "on.miss.computer")
	runtimeBackend := deployruntime.NewDockerRuntime("docker", stateDir)
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := runtimeBackend.Cleanup(cleanupCtx); err != nil {
			t.Errorf("final runtime cleanup: %v", err)
		}
	}()
	agent := miner.NewAgent("docker-m1", ownerPublic, minerPrivate, store, runtimeBackend, tunnels)
	tracked := &countingAssigner{inner: agent}
	assignmentLedger := ledger.New()
	scheduler := &Scheduler{
		SigningKey: ownerPrivate, Miners: []miner.Assigner{tracked}, Router: router, Ledger: assignmentLedger, Replicas: 1,
		Validator: validator.Validator{Vantage: "unreachable-edge", EdgeURL: "http://127.0.0.1:1", InternalProbeToken: "docker-failure-probe", Client: &http.Client{Timeout: 100 * time.Millisecond}},
	}
	request := DeployRequest{
		DeploymentID: "docker-failed-acceptance", Manifest: manifest, ManifestKey: artifact.ManifestKey(manifest.ImageDigest), Workload: spec, Timeout: 15 * time.Second,
	}
	_, err = scheduler.Deploy(ctx, request)
	var capacity *CapacityError
	if !errors.As(err, &capacity) {
		t.Fatalf("failed acceptance error = %v", err)
	}
	if got := assignmentLedger.Trust(agent.ID()); got != 0 {
		t.Fatalf("failed acceptance trust = %v", got)
	}
	tracked.mu.Lock()
	assignmentCount := len(tracked.seen)
	if assignmentCount != 1 {
		tracked.mu.Unlock()
		t.Fatalf("assignment count = %d", assignmentCount)
	}
	ticket := tracked.seen[0]
	tracked.mu.Unlock()
	endpointID := protocol.EndpointID(ticket)
	if _, err := tunnels.Resolve(endpointID); err == nil {
		t.Fatal("failed acceptance left endpoint tunnel registered")
	}
	containerName := deployruntime.InstanceName(endpointID)
	inspectCtx, cancelInspect := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelInspect()
	if output, inspectErr := exec.CommandContext(inspectCtx, "docker", "inspect", containerName).CombinedOutput(); inspectErr == nil {
		t.Fatalf("failed acceptance left container %q: %s", containerName, output)
	}
	if entries, err := os.ReadDir(stateDir); err != nil || len(entries) != 0 {
		t.Fatalf("failed acceptance left verified layers: entries=%d err=%v", len(entries), err)
	}
}
