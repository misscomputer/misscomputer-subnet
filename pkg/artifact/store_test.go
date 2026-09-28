// SPDX-License-Identifier: AGPL-3.0-only

package artifact

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// publishManifestV2 stores one valid artifact-manifest v2 document and
// returns its artifact digest.
func publishManifestV2(t *testing.T, store Store) string {
	t.Helper()
	digest := func(label string) string { return Digest([]byte(label)) }
	payload, artifactDigest, err := MarshalManifestV2(ManifestV2{
		Config:            Descriptor{Digest: digest("config"), MediaType: OCIConfigMediaType, Size: 512},
		Layers:            []LayerV2{{DiffID: digest("diff"), Digest: digest("layer"), MediaType: OCILayerGzipType, Size: 64, UncompressedSize: 128}},
		OCIManifest:       Descriptor{Digest: digest("oci-manifest"), MediaType: OCIManifestMediaType, Size: 256},
		Platform:          Platform{Architecture: "amd64", OS: "linux"},
		Schema:            ManifestV2Schema,
		SchemaVersion:     ManifestV2SchemaVersion,
		UncompressedBytes: 128,
		WorkloadType:      WorkloadTypeOCIImageV1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(context.Background(), ManifestKey(artifactDigest), payload, ManifestV2MediaType); err != nil {
		t.Fatal(err)
	}
	return artifactDigest
}

func TestFetchManifestV2UsesBoundedManifestGetterOnly(t *testing.T) {
	inner := FileStore{Root: t.TempDir()}
	artifactDigest := publishManifestV2(t, inner)
	store := &recordingBoundedStore{inner: inner}
	if _, err := FetchManifestV2(context.Background(), store, ManifestKey(artifactDigest), artifactDigest); err != nil {
		t.Fatal(err)
	}
	if len(store.bounded) != 1 || store.bounded[0].key != ManifestKey(artifactDigest) || store.bounded[0].maximum != maxManifestBytes {
		t.Fatalf("bounded reads = %+v", store.bounded)
	}
	if len(store.gets) != 0 {
		t.Fatalf("unbounded reads = %v", store.gets)
	}
}

func TestFetchManifestV2SupportsStoreWithoutBoundedCapability(t *testing.T) {
	store := legacyStore{inner: FileStore{Root: t.TempDir()}}
	artifactDigest := publishManifestV2(t, store)
	if _, err := FetchManifestV2(context.Background(), store, ManifestKey(artifactDigest), artifactDigest); err != nil {
		t.Fatalf("store without bounded reads: %v", err)
	}
}

func TestDeleteExactIsIdempotentAndScoped(t *testing.T) {
	ctx := context.Background()
	store := FileStore{Root: t.TempDir()}
	keys := []string{ManifestKey(Digest([]byte("manifest"))), BlobKey(Digest([]byte("base"))), BlobKey(Digest([]byte("unique")))}
	for _, key := range keys {
		if err := store.Put(ctx, key, []byte(key), "application/octet-stream"); err != nil {
			t.Fatal(err)
		}
	}
	unrelatedKey := "unrelated/keep me+safe%25"
	if err := store.Put(ctx, unrelatedKey, []byte("retained"), "application/octet-stream"); err != nil {
		t.Fatal(err)
	}
	if err := DeleteExact(ctx, store, append(keys, keys...)); err != nil {
		t.Fatal(err)
	}
	if err := DeleteExact(ctx, store, keys); err != nil {
		t.Fatalf("idempotent cleanup: %v", err)
	}
	if _, err := store.Get(ctx, unrelatedKey); err != nil {
		t.Fatalf("exact cleanup removed unrelated object: %v", err)
	}
	for _, key := range keys {
		if _, err := store.Get(ctx, key); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("cleaned key %q still exists or returned unexpected error: %v", key, err)
		}
	}
}

func TestS3CompatibleRoundTrip(t *testing.T) {
	var mu sync.Mutex
	objects := make(map[string][]byte)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			http.Error(w, readErr.Error(), http.StatusBadRequest)
			return
		}
		if err := verifyTestSigV4(r, body, "test-access", "test-secret"); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		const expectedPrefix = "/proxy/base prefix/test-bucket/"
		if !strings.HasPrefix(r.URL.Path, expectedPrefix) || !strings.HasPrefix(r.RequestURI, "/") {
			http.NotFound(w, r)
			return
		}
		const expectedEscaped = "/proxy/base%20prefix/test-bucket/v1/blobs/special%20folder/a%2Bb%25%3F%23snow-%E9%9B%AA"
		if r.URL.EscapedPath() != expectedEscaped {
			http.Error(w, "unexpected escaped object path", http.StatusBadRequest)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case http.MethodPut:
			objects[r.URL.Path] = body
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			body, ok := objects[r.URL.Path]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(body)
		case http.MethodHead:
			if _, ok := objects[r.URL.Path]; !ok {
				http.NotFound(w, r)
				return
			}
			w.WriteHeader(http.StatusOK)
		case http.MethodDelete:
			delete(objects, r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method", http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()
	store := S3Store{
		Endpoint: server.URL + "/proxy/base%20prefix", Bucket: "test-bucket", Region: "auto",
		AccessKey: "test-access", SecretKey: "test-secret", Client: server.Client(),
		Now: func() time.Time { return time.Date(2026, 8, 22, 0, 0, 0, 0, time.UTC) },
	}
	ctx := context.Background()
	key := "v1/blobs/special folder/a+b%?#snow-雪"
	if err := store.Put(ctx, key, []byte("payload"), "application/octet-stream"); err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "payload" {
		t.Fatalf("got %q", got)
	}
	if err := store.Head(ctx, key); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(ctx, key); err != nil {
		t.Fatalf("idempotent delete: %v", err)
	}
	if err := store.Head(ctx, key); !IsNotFound(err) {
		t.Fatalf("deleted object head error = %v", err)
	}
}

// verifyTestSigV4 is an independent server-side verifier for the exact S3
// subset under test. It reconstructs the request received on the wire rather
// than trusting an Authorization prefix, so URI/signature divergence fails.
func verifyTestSigV4(r *http.Request, body []byte, accessKey, secretKey string) error {
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		return fmt.Errorf("query-bearing S3 request is outside the exact-object signing subset")
	}
	authorization := r.Header.Get("Authorization")
	const algorithm = "AWS4-HMAC-SHA256"
	if !strings.HasPrefix(authorization, algorithm+" ") {
		return fmt.Errorf("missing SigV4 authorization")
	}
	fields := make(map[string]string)
	for _, field := range strings.Split(strings.TrimPrefix(authorization, algorithm+" "), ",") {
		parts := strings.SplitN(strings.TrimSpace(field), "=", 2)
		if len(parts) != 2 {
			return fmt.Errorf("malformed authorization field %q", field)
		}
		fields[parts[0]] = parts[1]
	}
	credential := strings.Split(fields["Credential"], "/")
	if len(credential) != 5 || credential[0] != accessKey || credential[3] != "s3" || credential[4] != "aws4_request" {
		return fmt.Errorf("invalid credential scope")
	}
	payloadSum := sha256.Sum256(body)
	payloadHash := hex.EncodeToString(payloadSum[:])
	if r.Header.Get("X-Amz-Content-Sha256") != payloadHash {
		return fmt.Errorf("payload hash mismatch")
	}
	signedHeaders := strings.Split(fields["SignedHeaders"], ";")
	var canonicalHeaders strings.Builder
	for _, name := range signedHeaders {
		value := r.Header.Get(name)
		if name == "host" {
			value = r.Host
		}
		canonicalHeaders.WriteString(name)
		canonicalHeaders.WriteByte(':')
		canonicalHeaders.WriteString(strings.Join(strings.Fields(value), " "))
		canonicalHeaders.WriteByte('\n')
	}
	canonicalURI := r.URL.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	canonical := r.Method + "\n" + canonicalURI + "\n\n" + canonicalHeaders.String() + "\n" + fields["SignedHeaders"] + "\n" + payloadHash
	canonicalSum := sha256.Sum256([]byte(canonical))
	scope := strings.Join(credential[1:], "/")
	toSign := algorithm + "\n" + r.Header.Get("X-Amz-Date") + "\n" + scope + "\n" + hex.EncodeToString(canonicalSum[:])
	signingKey := testHMAC([]byte("AWS4"+secretKey), credential[1])
	signingKey = testHMAC(signingKey, credential[2])
	signingKey = testHMAC(signingKey, credential[3])
	signingKey = testHMAC(signingKey, credential[4])
	want := hex.EncodeToString(testHMAC(signingKey, toSign))
	if !hmac.Equal([]byte(want), []byte(fields["Signature"])) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

func testHMAC(key []byte, value string) []byte {
	digest := hmac.New(sha256.New, key)
	_, _ = digest.Write([]byte(value))
	return digest.Sum(nil)
}

type boundedRead struct {
	key     string
	maximum int64
}

type recordingBoundedStore struct {
	inner   FileStore
	bounded []boundedRead
	gets    []string
}

func (store *recordingBoundedStore) Put(ctx context.Context, key string, body []byte, contentType string) error {
	return store.inner.Put(ctx, key, body, contentType)
}

func (store *recordingBoundedStore) Get(ctx context.Context, key string) ([]byte, error) {
	store.gets = append(store.gets, key)
	return store.inner.Get(ctx, key)
}

func (store *recordingBoundedStore) GetBounded(ctx context.Context, key string, maximum int64) ([]byte, error) {
	store.bounded = append(store.bounded, boundedRead{key: key, maximum: maximum})
	return store.inner.GetBounded(ctx, key, maximum)
}

type legacyStore struct{ inner FileStore }

func (store legacyStore) Put(ctx context.Context, key string, body []byte, contentType string) error {
	return store.inner.Put(ctx, key, body, contentType)
}

func (store legacyStore) Get(ctx context.Context, key string) ([]byte, error) {
	return store.inner.Get(ctx, key)
}
