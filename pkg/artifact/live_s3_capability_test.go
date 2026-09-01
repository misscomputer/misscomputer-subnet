// SPDX-License-Identifier: AGPL-3.0-only

package artifact

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

type liveS3ControlStore interface {
	Store
	ExactDeleter
	Head(context.Context, string) error
}

type liveS3Replica struct {
	name  string
	store Store
}

type liveS3Configuration struct {
	control  S3Store
	replicas []liveS3Replica
}

func liveS3ConfigurationFromEnvironment(getenv func(string) string) (liveS3Configuration, error) {
	if getenv == nil {
		return liveS3Configuration{}, errors.New("live S3 environment reader is required")
	}
	endpoint := getenv("S3_ENDPOINT")
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Opaque != "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return liveS3Configuration{}, errors.New("live S3 endpoint must be a credential-free HTTPS endpoint")
	}
	bucket := getenv("S3_BUCKET")
	if bucket == "" || bucket != strings.TrimSpace(bucket) || getenv("MISSCOMPUTER_LIVE_S3_BUCKET_CONFIRM") != bucket {
		return liveS3Configuration{}, errors.New("live S3 bucket requires an exact non-empty confirmation")
	}
	controlAccess := getenv("S3_ACCESS_KEY_ID")
	controlSecret := getenv("S3_SECRET_ACCESS_KEY")
	readAccess := getenv("S3_READ_ACCESS_KEY_ID")
	readSecret := getenv("S3_READ_SECRET_ACCESS_KEY")
	if controlAccess == "" || controlSecret == "" || readAccess == "" || readSecret == "" {
		return liveS3Configuration{}, errors.New("live S3 controller and reader credentials are required")
	}
	if controlAccess == readAccess {
		return liveS3Configuration{}, errors.New("live S3 controller and reader identities must be distinct")
	}
	region := getenv("S3_REGION")
	control := S3Store{
		Endpoint: endpoint, Bucket: bucket, Region: region,
		AccessKey: controlAccess, SecretKey: controlSecret,
	}
	if err := control.Validate(); err != nil {
		return liveS3Configuration{}, errors.New("live S3 controller configuration is invalid")
	}
	reader := S3Store{
		Endpoint: endpoint, Bucket: bucket, Region: region,
		AccessKey: readAccess, SecretKey: readSecret,
	}
	if err := reader.Validate(); err != nil {
		return liveS3Configuration{}, errors.New("live S3 reader configuration is invalid")
	}
	return liveS3Configuration{
		control: control,
		replicas: []liveS3Replica{
			{name: "miner", store: reader},
			{name: "local-runtime", store: reader},
			{name: "public-probe", store: reader},
		},
	}, nil
}

func runLiveS3Capability(
	ctx context.Context,
	control liveS3ControlStore,
	replicas []liveS3Replica,
	random io.Reader,
	createdAt time.Time,
) (resultErr error) {
	if ctx == nil || control == nil || random == nil {
		return errors.New("live S3 capability dependencies are required")
	}
	if createdAt.IsZero() || createdAt.Location() != time.UTC {
		return errors.New("live S3 capability timestamp must be canonical UTC")
	}
	if len(replicas) != 3 {
		return errors.New("live S3 capability requires exactly three replicas")
	}
	wantedNames := []string{"local-runtime", "miner", "public-probe"}
	actualNames := make([]string, 0, len(replicas))
	for _, replica := range replicas {
		if replica.store == nil || replica.name == "" {
			return errors.New("live S3 replica configuration is invalid")
		}
		actualNames = append(actualNames, replica.name)
	}
	slices.Sort(actualNames)
	if !slices.Equal(actualNames, wantedNames) {
		return errors.New("live S3 replica roles are invalid")
	}

	layers, nonceDigest, err := newLiveS3Layers(random)
	if err != nil {
		return errors.New("live S3 unique content generation failed")
	}
	manifest, err := PrepareManifest(
		"misscomputer-live-s3-capability-v1",
		layers,
		map[string]string{"capability_nonce_digest": nonceDigest},
		createdAt,
	)
	if err != nil {
		return errors.New("live S3 manifest preparation failed")
	}
	keys, err := ArtifactKeys(manifest)
	if err != nil {
		return errors.New("live S3 exact key preparation failed")
	}
	for _, key := range keys {
		headErr := control.Head(ctx, key)
		if headErr == nil {
			return errors.New("live S3 capability refused a pre-existing object")
		}
		if !IsNotFound(headErr) {
			return errors.New("live S3 object absence could not be proven")
		}
	}

	// No write occurs before every exact content-addressed key has been proven
	// absent. From this point onward, cleanup owns only this explicit key set.
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		first := DeleteExact(cleanupCtx, control, keys)
		second := DeleteExact(cleanupCtx, control, keys)
		var absenceFailures []error
		for _, key := range keys {
			if headErr := control.Head(cleanupCtx, key); !IsNotFound(headErr) {
				absenceFailures = append(absenceFailures, errors.New("live S3 cleanup absence proof failed"))
			}
		}
		resultErr = errors.Join(resultErr, first, second, errors.Join(absenceFailures...))
	}()

	if _, err := PublishPrepared(ctx, control, manifest, layers); err != nil {
		return errors.New("live S3 artifact publish failed")
	}
	for _, replica := range replicas {
		fetched, fetchedLayers, err := Fetch(
			ctx,
			replica.store,
			ManifestKey(manifest.ImageDigest),
			manifest.ImageDigest,
		)
		if err != nil {
			return fmt.Errorf("live S3 %s replica fetch failed", replica.name)
		}
		if fetched.ImageDigest != manifest.ImageDigest || len(fetchedLayers) != len(layers) {
			return fmt.Errorf("live S3 %s replica verification failed", replica.name)
		}
		for index := range layers {
			if !bytes.Equal(fetchedLayers[index], layers[index]) || Digest(fetchedLayers[index]) != manifest.Layers[index].Digest {
				return fmt.Errorf("live S3 %s replica digest verification failed", replica.name)
			}
		}
	}
	return nil
}

func newLiveS3Layers(random io.Reader) ([][]byte, string, error) {
	nonce := make([]byte, 32)
	if _, err := io.ReadFull(random, nonce); err != nil {
		return nil, "", err
	}
	layers := make([][]byte, 3)
	for index, role := range []string{"validator", "runtime", "probe"} {
		layers[index] = append([]byte("misscomputer-live-s3-capability-v1:"+role+":"), nonce...)
	}
	return layers, Digest(nonce), nil
}

type liveS3FakeBackend struct {
	objects  map[string][]byte
	log      []string
	putCount int
	failPut  int
}

type liveS3FakeStore struct {
	backend  *liveS3FakeBackend
	role     string
	readOnly bool
}

func (s liveS3FakeStore) Put(_ context.Context, key string, body []byte, _ string) error {
	s.backend.log = append(s.backend.log, s.role+":put:"+key)
	if s.readOnly {
		return errors.New("read-only replica attempted a write")
	}
	s.backend.putCount++
	if s.backend.failPut != 0 && s.backend.putCount == s.backend.failPut {
		return errors.New("injected put failure")
	}
	if _, exists := s.backend.objects[key]; exists {
		return errors.New("fake store refused overwrite")
	}
	s.backend.objects[key] = bytes.Clone(body)
	return nil
}

func (s liveS3FakeStore) Get(_ context.Context, key string) ([]byte, error) {
	s.backend.log = append(s.backend.log, s.role+":get:"+key)
	body, exists := s.backend.objects[key]
	if !exists {
		return nil, &S3Error{Operation: "get", Key: key, Kind: S3ErrorNotFound, StatusCode: 404}
	}
	return bytes.Clone(body), nil
}

func (s liveS3FakeStore) Head(_ context.Context, key string) error {
	s.backend.log = append(s.backend.log, s.role+":head:"+key)
	if _, exists := s.backend.objects[key]; !exists {
		return &S3Error{Operation: "head", Key: key, Kind: S3ErrorNotFound, StatusCode: 404}
	}
	return nil
}

func (s liveS3FakeStore) Delete(_ context.Context, key string) error {
	s.backend.log = append(s.backend.log, s.role+":delete:"+key)
	if s.readOnly {
		return errors.New("read-only replica attempted cleanup")
	}
	delete(s.backend.objects, key)
	return nil
}

func TestLiveS3CapabilityOfflineThreeReplicaFlowAndExactCleanup(t *testing.T) {
	backend := &liveS3FakeBackend{objects: make(map[string][]byte)}
	control := liveS3FakeStore{backend: backend, role: "control"}
	replicas := []liveS3Replica{
		{name: "miner", store: liveS3FakeStore{backend: backend, role: "miner", readOnly: true}},
		{name: "local-runtime", store: liveS3FakeStore{backend: backend, role: "runtime", readOnly: true}},
		{name: "public-probe", store: liveS3FakeStore{backend: backend, role: "probe", readOnly: true}},
	}
	random := bytes.NewReader(bytes.Repeat([]byte{0x5a}, 32))
	if err := runLiveS3Capability(
		context.Background(), control, replicas, random, time.Unix(1_800_000_000, 0).UTC(),
	); err != nil {
		t.Fatal(err)
	}
	if len(backend.objects) != 0 {
		t.Fatalf("exact cleanup left %d objects", len(backend.objects))
	}
	firstPut := slices.IndexFunc(backend.log, func(value string) bool {
		return strings.HasPrefix(value, "control:put:")
	})
	if firstPut < 1 {
		t.Fatal("capability did not publish after absence checks")
	}
	for _, value := range backend.log[:firstPut] {
		if !strings.HasPrefix(value, "control:head:") {
			t.Fatalf("operation before first write = %q", value)
		}
	}
	for _, role := range []string{"miner", "runtime", "probe"} {
		if !slices.ContainsFunc(backend.log, func(value string) bool {
			return strings.HasPrefix(value, role+":get:")
		}) {
			t.Fatalf("%s replica did not fetch", role)
		}
		if slices.ContainsFunc(backend.log, func(value string) bool {
			return strings.HasPrefix(value, role+":put:") || strings.HasPrefix(value, role+":delete:")
		}) {
			t.Fatalf("%s replica received mutation authority", role)
		}
	}
}

func TestLiveS3CapabilityRefusesPreexistingKeyWithoutMutation(t *testing.T) {
	seed := bytes.Repeat([]byte{0x21}, 32)
	createdAt := time.Unix(1_800_000_001, 0).UTC()
	layers, nonceDigest, err := newLiveS3Layers(bytes.NewReader(seed))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := PrepareManifest(
		"misscomputer-live-s3-capability-v1",
		layers,
		map[string]string{"capability_nonce_digest": nonceDigest},
		createdAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := ArtifactKeys(manifest)
	if err != nil {
		t.Fatal(err)
	}
	backend := &liveS3FakeBackend{objects: map[string][]byte{keys[0]: []byte("owned elsewhere")}}
	control := liveS3FakeStore{backend: backend, role: "control"}
	replicas := []liveS3Replica{
		{name: "miner", store: control},
		{name: "local-runtime", store: control},
		{name: "public-probe", store: control},
	}
	err = runLiveS3Capability(
		context.Background(), control, replicas, bytes.NewReader(seed), createdAt,
	)
	if err == nil || !strings.Contains(err.Error(), "pre-existing") {
		t.Fatalf("pre-existing key error = %v", err)
	}
	if len(backend.objects) != 1 {
		t.Fatal("pre-existing object was changed")
	}
	if slices.ContainsFunc(backend.log, func(value string) bool {
		return strings.Contains(value, ":put:") || strings.Contains(value, ":delete:")
	}) {
		t.Fatalf("pre-existing refusal mutated store: %v", backend.log)
	}
}

func TestLiveS3CapabilityCleansPartialPublishTwice(t *testing.T) {
	backend := &liveS3FakeBackend{objects: make(map[string][]byte), failPut: 2}
	control := liveS3FakeStore{backend: backend, role: "control"}
	replicas := []liveS3Replica{
		{name: "miner", store: control},
		{name: "local-runtime", store: control},
		{name: "public-probe", store: control},
	}
	err := runLiveS3Capability(
		context.Background(),
		control,
		replicas,
		bytes.NewReader(bytes.Repeat([]byte{0x33}, 32)),
		time.Unix(1_800_000_002, 0).UTC(),
	)
	if err == nil || !strings.Contains(err.Error(), "publish failed") {
		t.Fatalf("partial publish error = %v", err)
	}
	if len(backend.objects) != 0 {
		t.Fatalf("partial publish cleanup left %d objects", len(backend.objects))
	}
	deleteCount := 0
	for _, value := range backend.log {
		if strings.HasPrefix(value, "control:delete:") {
			deleteCount++
		}
	}
	// Three layers plus one manifest, each deleted in both cleanup passes.
	if deleteCount != 8 {
		t.Fatalf("delete count = %d want 8", deleteCount)
	}
}

func TestLiveS3CapabilityConfigurationFailsClosed(t *testing.T) {
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
	if _, err := liveS3ConfigurationFromEnvironment(getenv); err != nil {
		t.Fatal(err)
	}
	values["S3_ENDPOINT"] = "http://objects.example.invalid"
	if _, err := liveS3ConfigurationFromEnvironment(getenv); err == nil {
		t.Fatal("plaintext endpoint was accepted")
	}
	values["S3_ENDPOINT"] = "https://objects.example.invalid"
	values["MISSCOMPUTER_LIVE_S3_BUCKET_CONFIRM"] = "another-bucket"
	if _, err := liveS3ConfigurationFromEnvironment(getenv); err == nil {
		t.Fatal("mismatched bucket confirmation was accepted")
	}
	values["MISSCOMPUTER_LIVE_S3_BUCKET_CONFIRM"] = values["S3_BUCKET"]
	values["S3_READ_ACCESS_KEY_ID"] = values["S3_ACCESS_KEY_ID"]
	if _, err := liveS3ConfigurationFromEnvironment(getenv); err == nil {
		t.Fatal("collapsed controller and reader identities were accepted")
	}
}
