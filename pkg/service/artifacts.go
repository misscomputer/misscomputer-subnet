// SPDX-License-Identifier: AGPL-3.0-only

package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
)

type ArtifactStoreOptions struct {
	RequestTimeout time.Duration
	MaxAttempts    int
}

// ArtifactStore selects the existing filesystem or S3-compatible implementation for
// a long-running service. Credential values are read only from explicitly
// named environment variables and are never included in returned errors.
func ArtifactStore(backend, directory, endpoint, bucket, region, accessKeyEnv, secretKeyEnv string) (artifact.Store, error) {
	return ArtifactStoreWithOptions(backend, directory, endpoint, bucket, region, accessKeyEnv, secretKeyEnv, ArtifactStoreOptions{})
}

// ArtifactStoreWithOptions configures bounded S3-compatible behavior for a
// long-running service while preserving the simple filesystem backend.
func ArtifactStoreWithOptions(backend, directory, endpoint, bucket, region, accessKeyEnv, secretKeyEnv string, options ArtifactStoreOptions) (artifact.Store, error) {
	backend = strings.ToLower(strings.TrimSpace(backend))
	switch backend {
	case "", "file", "filesystem":
		if directory == "" {
			return nil, errors.New("artifact directory is required for filesystem backend")
		}
		return artifact.FileStore{Root: filepath.Clean(directory)}, nil
	case "s3":
		if endpoint == "" || bucket == "" {
			return nil, errors.New("S3 endpoint and bucket are required")
		}
		if accessKeyEnv == "" {
			accessKeyEnv = "S3_ACCESS_KEY_ID"
		}
		if secretKeyEnv == "" {
			secretKeyEnv = "S3_SECRET_ACCESS_KEY"
		}
		accessKey, secretKey := os.Getenv(accessKeyEnv), os.Getenv(secretKeyEnv)
		if accessKey == "" || secretKey == "" {
			return nil, fmt.Errorf("S3 credential environment variables %q and %q must be set", accessKeyEnv, secretKeyEnv)
		}
		store := artifact.S3Store{
			Endpoint: endpoint, Bucket: bucket, Region: region,
			AccessKey: accessKey, SecretKey: secretKey, RequestTimeout: options.RequestTimeout, MaxAttempts: options.MaxAttempts,
		}
		if err := store.Validate(); err != nil {
			return nil, fmt.Errorf("invalid S3 configuration: %w", err)
		}
		return store, nil
	default:
		return nil, fmt.Errorf("unsupported artifact backend %q", backend)
	}
}
