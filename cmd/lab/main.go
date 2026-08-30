// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
	"github.com/misscomputer/misscomputer-subnet/pkg/control"
	"github.com/misscomputer/misscomputer-subnet/pkg/edge"
	"github.com/misscomputer/misscomputer-subnet/pkg/ledger"
	"github.com/misscomputer/misscomputer-subnet/pkg/miner"
	"github.com/misscomputer/misscomputer-subnet/pkg/policy"
	deployruntime "github.com/misscomputer/misscomputer-subnet/pkg/runtime"
	"github.com/misscomputer/misscomputer-subnet/pkg/tunnel"
	"github.com/misscomputer/misscomputer-subnet/pkg/validator"
	"github.com/misscomputer/misscomputer-subnet/pkg/workload"
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, output io.Writer) (runErr error) {
	return runWithArtifactStore(ctx, args, output, artifactStore)
}

func runWithArtifactStore(ctx context.Context, args []string, output io.Writer, openStore func() (artifact.Store, func(), error)) (runErr error) {
	flags := flag.NewFlagSet("lab", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var (
		deploymentID = flags.String("deployment", "abc", "deployment subdomain label")
		domain       = flags.String("domain", "on.miss.computer", "application wildcard domain")
		kind         = flags.String("kind", "static", "synthetic workload kind")
		size         = flags.Int("size-mib", 10, "never-before-seen unique layer size in MiB")
		jsonOutput   = flags.Bool("json", false, "print machine-readable benchmark result")
		runtimeKind  = flags.String("runtime", "local", "miner runtime: local or docker")
		dockerImage  = flags.String("docker-image", "", "pinned warm runtime image ID or repository digest")
		dockerState  = flags.String("docker-state-dir", "", "host-visible directory for verified cold layers")
	)
	if err := flags.Parse(args); err != nil {
		return err
	}
	store, cleanup, err := openStore()
	if err != nil {
		return err
	}
	defer cleanup()
	spec, uniqueLayer, err := workload.Generate(*kind, *size<<20)
	if err != nil {
		return err
	}
	annotations := map[string]string{"build_id": spec.BuildID}
	if *runtimeKind == "docker" {
		if *dockerImage == "" {
			return fmt.Errorf("-docker-image is required for Docker runtime")
		}
		annotations["docker.image"] = *dockerImage
	} else if *runtimeKind != "local" {
		return fmt.Errorf("unsupported runtime %q", *runtimeKind)
	}
	manifest, err := artifact.Publish(ctx, store, spec.Kind, [][]byte{[]byte("misscomputer-runtime-base-v1"), uniqueLayer}, annotations)
	if err != nil {
		return err
	}
	ownerPublic, ownerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	tunnels := tunnel.NewLocalRegistry()
	probeToken, err := edge.GenerateProbeToken()
	if err != nil {
		return fmt.Errorf("generate internal probe token: %w", err)
	}
	router, err := edge.NewAuthorizedRouter(tunnels, probeToken, edge.RouterConfig{
		AuthorityKey: ownerPublic, Domain: *domain, AllowPrivateUpstreams: true,
	})
	if err != nil {
		return err
	}
	edgeServer := httptest.NewServer(router)
	defer edgeServer.Close()
	agents := make([]miner.Assigner, 0, 3)
	dockerRuntimes := make([]*deployruntime.DockerRuntime, 0, 3)
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		for _, runtime := range dockerRuntimes {
			if err := runtime.Cleanup(cleanupCtx); err != nil && runErr == nil {
				runErr = fmt.Errorf("final Docker runtime cleanup: %w", err)
			}
		}
	}()
	for i := 1; i <= 3; i++ {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		minerID := fmt.Sprintf("miner-%d", i)
		var runtime deployruntime.Runtime = deployruntime.NewLocalRuntime()
		if *runtimeKind == "docker" {
			dockerRuntime := deployruntime.NewDockerRuntime("docker", *dockerState)
			dockerRuntimes = append(dockerRuntimes, dockerRuntime)
			runtime = dockerRuntime
		}
		agents = append(agents, miner.NewAgent(minerID, ownerPublic, privateKey, store, runtime, tunnels))
	}
	assignmentLedger := ledger.New()
	scheduler := control.Scheduler{
		SigningKey: ownerPrivate, Miners: agents, Router: router, Ledger: assignmentLedger,
		Validator: validator.Validator{Vantage: "independent-local", EdgeURL: edgeServer.URL, InternalProbeToken: probeToken},
		Health:    policy.NewMonitor(), Replicas: 3, Domain: *domain,
	}
	deployed := false
	defer func() {
		if !deployed {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := scheduler.DeactivateDeployment(cleanupCtx, *deploymentID); err != nil && runErr == nil {
			runErr = err
		}
	}()
	result, err := scheduler.Deploy(ctx, control.DeployRequest{DeploymentID: *deploymentID, Manifest: manifest, ManifestKey: artifact.ManifestKey(manifest.ImageDigest), Workload: spec, Timeout: 2 * time.Minute})
	if err != nil {
		return err
	}
	deployed = true
	if *jsonOutput {
		snapshot, _ := assignmentLedger.Snapshot(result.DeploymentID)
		payload := struct {
			Result     control.DeployResult `json:"result"`
			Deployment ledger.Deployment    `json:"deployment"`
			Events     []ledger.Event       `json:"events"`
		}{result, snapshot, assignmentLedger.Events()}
		if err := json.NewEncoder(output).Encode(payload); err != nil {
			return err
		}
		return nil
	}
	fmt.Fprintf(output, "deployment:       %s\n", result.DeploymentID)
	fmt.Fprintf(output, "public URL:       https://%s\n", result.RouteHost)
	fmt.Fprintf(output, "image digest:     %s\n", manifest.ImageDigest)
	fmt.Fprintf(output, "unique layer:     %.1f MiB\n", float64(len(uniqueLayer))/(1<<20))
	fmt.Fprintf(output, "first replica:    %s\n", result.FirstReplicaTime.Round(time.Microsecond))
	fmt.Fprintf(output, "full redundancy:  %s\n", result.FullRedundancyTime.Round(time.Microsecond))
	fmt.Fprintf(output, "public probe:     %s (%s)\n", map[bool]string{true: "correct", false: "failed"}[result.PublicProbe.Correct], result.PublicProbe.Latency.Round(time.Microsecond))
	fmt.Fprintf(output, "ready miners:     %v\n", result.ReadyMiners)
	return nil
}

func artifactStore() (artifact.Store, func(), error) {
	if os.Getenv("ARTIFACT_BACKEND") == "s3" {
		endpoint := os.Getenv("S3_ENDPOINT")
		bucket := os.Getenv("S3_BUCKET")
		access := os.Getenv("S3_ACCESS_KEY_ID")
		secret := os.Getenv("S3_SECRET_ACCESS_KEY")
		if endpoint == "" || bucket == "" || access == "" || secret == "" {
			return nil, func() {}, fmt.Errorf("S3_ENDPOINT, S3_BUCKET, S3_ACCESS_KEY_ID, and S3_SECRET_ACCESS_KEY are required")
		}
		return artifact.S3Store{Endpoint: endpoint, Bucket: bucket, Region: os.Getenv("S3_REGION"), AccessKey: access, SecretKey: secret}, func() {}, nil
	}
	root, err := os.MkdirTemp("", "misscomputer-artifacts-*")
	if err != nil {
		return nil, func() {}, err
	}
	return artifact.FileStore{Root: filepath.Clean(root)}, func() { _ = os.RemoveAll(root) }, nil
}
