// SPDX-License-Identifier: AGPL-3.0-only

package integration_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
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

const liveS3Acknowledgement = "I_ACKNOWLEDGE_LIVE_S3_WRITES_AND_EXACT_CLEANUP"

type liveS3Stores struct {
	control artifact.S3Store
	reader  readOnlyS3Store
}

// TestLiveS3CompatibleArtifactThreeReplicaFlow is compiled by ordinary CI but
// skipped unless the caller supplies both exact live gates. It publishes
// never-before-seen content only after proving every target key absent, then
// exercises the real validator -> three miners -> verified fetch -> local
// runtime -> public probe flow and performs exact idempotent cleanup.
func TestLiveS3CompatibleArtifactThreeReplicaFlow(t *testing.T) {
	gate := os.Getenv("MISSCOMPUTER_LIVE_S3_CAPABILITY")
	if gate == "" {
		t.Skip("MISSCOMPUTER_LIVE_S3_CAPABILITY is not set")
	}
	if gate != "1" || os.Getenv("MISSCOMPUTER_LIVE_S3_ACK") != liveS3Acknowledgement {
		t.Fatal("live S3 capability gates are invalid")
	}
	stores, err := liveS3StoresFromEnvironment(os.Getenv)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	base := make([]byte, 256)
	if _, err := rand.Read(base); err != nil {
		t.Fatal("generate unique capability content")
	}
	spec, uniqueLayer, err := workload.Generate("static", 1<<16)
	if err != nil {
		t.Fatal("generate live S3 workload")
	}
	manifest, err := artifact.PrepareManifest(
		spec.Kind,
		[][]byte{base, uniqueLayer},
		map[string]string{"build_id": spec.BuildID, "test_scope": "live-s3-capability"},
		time.Now().UTC(),
	)
	if err != nil {
		t.Fatal("prepare live S3 artifact")
	}
	keys, err := artifact.ArtifactKeys(manifest)
	if err != nil {
		t.Fatal("prepare exact live S3 keys")
	}
	if err := proveExactKeysAbsent(ctx, stores.control, keys); err != nil {
		t.Fatal(err)
	}
	// Cleanup is armed only after every exact key is absent, and before the
	// first write, so a partial publish cannot strand a task-created object.
	defer cleanupExactS3Keys(t, stores.control, keys)

	publishStarted := time.Now()
	if _, err := artifact.PublishPrepared(
		ctx, stores.control, manifest, [][]byte{base, uniqueLayer},
	); err != nil {
		t.Fatal("publish live S3 artifact")
	}
	publishElapsed := time.Since(publishStarted)

	fetchStarted := time.Now()
	fetched, layers, err := artifact.Fetch(
		ctx,
		stores.reader,
		artifact.ManifestKey(manifest.ImageDigest),
		manifest.ImageDigest,
	)
	if err != nil {
		t.Fatal("fetch live S3 artifact with reader identity")
	}
	if fetched.ImageDigest != manifest.ImageDigest || len(layers) != 2 ||
		artifact.Digest(layers[0]) != manifest.Layers[0].Digest ||
		artifact.Digest(layers[1]) != manifest.Layers[1].Digest {
		t.Fatal("live S3 reader returned an unverifiable artifact")
	}
	directFetchElapsed := time.Since(fetchStarted)

	ownerPublic, ownerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate capability owner identity")
	}
	tunnels := tunnel.NewLocalRegistry()
	probeToken, err := edge.GenerateProbeToken()
	if err != nil {
		t.Fatal("generate public probe token")
	}
	router, err := edge.NewAuthorizedRouter(tunnels, probeToken, edge.RouterConfig{
		AuthorityKey: ownerPublic, Domain: "live-s3.local", AllowPrivateUpstreams: true,
	})
	if err != nil {
		t.Fatal("construct public capability router")
	}
	edgeServer := httptest.NewServer(router)
	defer edgeServer.Close()
	miners := make([]miner.Assigner, 0, 3)
	for index := 1; index <= 3; index++ {
		_, signingKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal("generate miner capability identity")
		}
		miners = append(miners, miner.NewAgent(
			fmt.Sprintf("s3-miner-%d", index),
			ownerPublic,
			signingKey,
			stores.reader,
			deployruntime.NewLocalRuntime(),
			tunnels,
		))
	}
	scheduler := control.Scheduler{
		SigningKey: ownerPrivate,
		Miners:     miners,
		Router:     router,
		Ledger:     ledger.New(),
		Validator: validator.Validator{
			Vantage: "live-s3-local-consumer", EdgeURL: edgeServer.URL,
			InternalProbeToken: probeToken,
		},
		Health: policy.NewMonitor(), Replicas: 3, Domain: "live-s3.local",
	}
	deploymentID := "s3-live-" + spec.BuildID[:12]
	flowStarted := time.Now()
	result, err := scheduler.Deploy(ctx, control.DeployRequest{
		DeploymentID: deploymentID,
		Manifest:     manifest,
		ManifestKey:  artifact.ManifestKey(manifest.ImageDigest),
		Workload:     spec,
		Timeout:      3 * time.Minute,
	})
	flowElapsed := time.Since(flowStarted)
	if err != nil {
		t.Fatal("validator/miner/runtime/public-probe live S3 flow failed")
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if err := scheduler.DeactivateDeployment(cleanupCtx, deploymentID); err != nil {
			t.Errorf("deactivate live S3 consumer flow: %v", err)
		}
	}()
	if len(result.ReadyMiners) != 3 || !result.PublicProbe.Correct {
		t.Fatal("live S3 flow did not reach three correct replicas")
	}
	t.Logf(
		"live S3 capability passed: exact_objects=%d publish=%s verified_fetch=%s first_replica=%s full_redundancy=%s total=%s",
		len(keys),
		publishElapsed.Round(time.Millisecond),
		directFetchElapsed.Round(time.Millisecond),
		result.FirstReplicaTime.Round(time.Millisecond),
		result.FullRedundancyTime.Round(time.Millisecond),
		flowElapsed.Round(time.Millisecond),
	)
}

type readOnlyS3Store struct{ inner artifact.S3Store }

func (s readOnlyS3Store) Put(context.Context, string, []byte, string) error {
	return errors.New("live S3 reader identity has no publication authority")
}

func (s readOnlyS3Store) Get(ctx context.Context, key string) ([]byte, error) {
	return s.inner.Get(ctx, key)
}

func (s readOnlyS3Store) GetBounded(ctx context.Context, key string, maximum int64) ([]byte, error) {
	return s.inner.GetBounded(ctx, key, maximum)
}

func liveS3StoresFromEnvironment(getenv func(string) string) (liveS3Stores, error) {
	endpoint := getenv("S3_ENDPOINT")
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Opaque != "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return liveS3Stores{}, errors.New("live S3 endpoint must be a credential-free HTTPS endpoint")
	}
	bucket := getenv("S3_BUCKET")
	if bucket == "" || bucket != strings.TrimSpace(bucket) ||
		getenv("MISSCOMPUTER_LIVE_S3_BUCKET_CONFIRM") != bucket {
		return liveS3Stores{}, errors.New("live S3 bucket requires an exact confirmation")
	}
	controlAccess, controlSecret := getenv("S3_ACCESS_KEY_ID"), getenv("S3_SECRET_ACCESS_KEY")
	readAccess, readSecret := getenv("S3_READ_ACCESS_KEY_ID"), getenv("S3_READ_SECRET_ACCESS_KEY")
	if controlAccess == "" || controlSecret == "" || readAccess == "" || readSecret == "" {
		return liveS3Stores{}, errors.New("live S3 controller and reader credentials are required")
	}
	if controlAccess == readAccess {
		return liveS3Stores{}, errors.New("live S3 controller and reader identities must be distinct")
	}
	common := artifact.S3Store{
		Endpoint: endpoint, Bucket: bucket, Region: getenv("S3_REGION"),
		RequestTimeout: 45 * time.Second, MaxAttempts: 4,
	}
	control := common
	control.AccessKey, control.SecretKey = controlAccess, controlSecret
	reader := common
	reader.AccessKey, reader.SecretKey = readAccess, readSecret
	if err := control.Validate(); err != nil {
		return liveS3Stores{}, errors.New("live S3 controller configuration is invalid")
	}
	if err := reader.Validate(); err != nil {
		return liveS3Stores{}, errors.New("live S3 reader configuration is invalid")
	}
	return liveS3Stores{control: control, reader: readOnlyS3Store{inner: reader}}, nil
}

func proveExactKeysAbsent(ctx context.Context, store artifact.S3Store, keys []string) error {
	for _, key := range keys {
		err := store.Head(ctx, key)
		if err == nil {
			return errors.New("live S3 capability refused a pre-existing object")
		}
		if !artifact.IsNotFound(err) {
			return errors.New("live S3 object absence could not be proven")
		}
	}
	return nil
}

func cleanupExactS3Keys(t *testing.T, store artifact.S3Store, keys []string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := artifact.DeleteExact(ctx, store, keys); err != nil {
		t.Errorf("delete exact live S3 capability objects: %v", err)
		return
	}
	if err := artifact.DeleteExact(ctx, store, keys); err != nil {
		t.Errorf("repeat exact live S3 capability cleanup: %v", err)
		return
	}
	for _, key := range keys {
		if err := store.Head(ctx, key); !artifact.IsNotFound(err) {
			t.Error("live S3 cleanup could not prove an exact key absent")
		}
	}
}

func TestLiveS3ConfigurationRejectsUnsafeEndpointBucketAndCredentialCollapse(t *testing.T) {
	values := map[string]string{
		"S3_ENDPOINT":                         "https://objects.example.invalid",
		"S3_BUCKET":                           "dedicated-capability",
		"MISSCOMPUTER_LIVE_S3_BUCKET_CONFIRM": "dedicated-capability",
		"S3_ACCESS_KEY_ID":                    "controller",
		"S3_SECRET_ACCESS_KEY":                "controller-secret",
		"S3_READ_ACCESS_KEY_ID":               "reader",
		"S3_READ_SECRET_ACCESS_KEY":           "reader-secret",
	}
	getenv := func(name string) string { return values[name] }
	if _, err := liveS3StoresFromEnvironment(getenv); err != nil {
		t.Fatal(err)
	}
	values["S3_ENDPOINT"] = "http://objects.example.invalid"
	if _, err := liveS3StoresFromEnvironment(getenv); err == nil {
		t.Fatal("plaintext S3 endpoint was accepted")
	}
	values["S3_ENDPOINT"] = "https://objects.example.invalid"
	values["MISSCOMPUTER_LIVE_S3_BUCKET_CONFIRM"] = "different"
	if _, err := liveS3StoresFromEnvironment(getenv); err == nil {
		t.Fatal("mismatched S3 bucket confirmation was accepted")
	}
	values["MISSCOMPUTER_LIVE_S3_BUCKET_CONFIRM"] = values["S3_BUCKET"]
	values["S3_READ_ACCESS_KEY_ID"] = values["S3_ACCESS_KEY_ID"]
	if _, err := liveS3StoresFromEnvironment(getenv); err == nil {
		t.Fatal("collapsed S3 controller and reader identities were accepted")
	}
}
