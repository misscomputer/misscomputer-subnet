// SPDX-License-Identifier: AGPL-3.0-only

package service

import (
	"strings"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
)

func TestArtifactStoreRequiresExternalS3Credentials(t *testing.T) {
	t.Setenv("TEST_S3_ACCESS", "")
	t.Setenv("TEST_S3_SECRET", "")
	if _, err := ArtifactStore("s3", "", "https://s3.example", "bucket", "auto", "TEST_S3_ACCESS", "TEST_S3_SECRET"); err == nil {
		t.Fatal("S3 backend accepted missing external credentials")
	}
	t.Setenv("TEST_S3_ACCESS", "access")
	t.Setenv("TEST_S3_SECRET", "secret")
	store, err := ArtifactStore("s3", "", "https://s3.example", "bucket", "auto", "TEST_S3_ACCESS", "TEST_S3_SECRET")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.(artifact.S3Store); !ok {
		t.Fatalf("artifact store type = %T", store)
	}
}

func TestArtifactStoreAppliesBoundedS3Options(t *testing.T) {
	t.Setenv("TEST_S3_ACCESS", "access")
	t.Setenv("TEST_S3_SECRET", "secret")
	store, err := ArtifactStoreWithOptions(
		"s3", "", "https://s3.example/prefix", "bucket", "auto", "TEST_S3_ACCESS", "TEST_S3_SECRET",
		ArtifactStoreOptions{RequestTimeout: 17 * time.Second, MaxAttempts: 4},
	)
	if err != nil {
		t.Fatal(err)
	}
	s3Store, ok := store.(artifact.S3Store)
	if !ok {
		t.Fatalf("artifact store type = %T", store)
	}
	if s3Store.RequestTimeout != 17*time.Second || s3Store.MaxAttempts != 4 {
		t.Fatalf("S3 bounds were not applied: %+v", s3Store)
	}
	_, err = ArtifactStoreWithOptions(
		"s3", "", "https://s3.example", "bucket", "auto", "TEST_S3_ACCESS", "TEST_S3_SECRET",
		ArtifactStoreOptions{RequestTimeout: -time.Second, MaxAttempts: 4},
	)
	if err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "access") {
		t.Fatalf("unsafe invalid S3 configuration error: %v", err)
	}
}
