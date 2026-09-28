// SPDX-License-Identifier: AGPL-3.0-only

package artifact

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

// TestMinIOSigV4RoundTrip is opt-in because the ordinary unit suite must not
// require Docker or a live object store. The verification workflow starts a
// real MinIO instance, creates MINIO_BUCKET, and supplies these local-only
// variables; MinIO then performs the authoritative SigV4 verification.
func TestMinIOSigV4RoundTrip(t *testing.T) {
	endpoint := os.Getenv("MINIO_ENDPOINT")
	if endpoint == "" {
		t.Skip("MINIO_ENDPOINT is not set")
	}
	bucket := os.Getenv("MINIO_BUCKET")
	accessKey := os.Getenv("MINIO_ACCESS_KEY")
	secretKey := os.Getenv("MINIO_SECRET_KEY")
	if bucket == "" || accessKey == "" || secretKey == "" {
		t.Fatal("MINIO_BUCKET, MINIO_ACCESS_KEY, and MINIO_SECRET_KEY are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	credentials := S3Store{Endpoint: endpoint, Region: "us-east-1", AccessKey: accessKey, SecretKey: secretKey}
	if err := credentials.Put(ctx, bucket, nil, ""); err != nil {
		var s3Err *S3Error
		if !errors.As(err, &s3Err) || s3Err.StatusCode != 409 {
			t.Fatalf("create MinIO test bucket: %v", err)
		}
	}
	store := credentials
	store.Bucket = bucket
	key := "sigv4 integration/round trip+%-雪-" + time.Now().UTC().Format("20060102T150405.000000000")
	defer func() {
		cleanup, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		if err := DeleteExact(cleanup, store, []string{key}); err != nil {
			t.Errorf("clean MinIO test object: %v", err)
		}
	}()
	want := []byte("real MinIO verified this SigV4 request")
	if err := store.Put(ctx, key, want, "application/octet-stream"); err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("MinIO round trip got %q want %q", got, want)
	}
	if err := store.Head(ctx, key); err != nil {
		t.Fatalf("head MinIO test object: %v", err)
	}
	if err := DeleteExact(ctx, store, []string{key, key}); err != nil {
		t.Fatalf("delete MinIO test object: %v", err)
	}
	if err := DeleteExact(ctx, store, []string{key}); err != nil {
		t.Fatalf("repeat MinIO test cleanup: %v", err)
	}
	if err := store.Head(ctx, key); !IsNotFound(err) {
		t.Fatalf("MinIO cleanup head error = %v", err)
	}
}
