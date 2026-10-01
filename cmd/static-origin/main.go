// SPDX-License-Identifier: AGPL-3.0-only

// Command static-origin is the platform's temporary static origin for one
// static-site-v1 site version (see pkg/staticorigin). It verifies the signed
// release and every site byte from a read-only artifact store before it
// listens, serves only that site on only its route host, and exits instead
// of serving bytes that stop verifying.
//
// Process contract (stdout carries exactly one status line):
//
//	READY <json>        verified and listening; <json> also written to --ready-file
//	REJECTED <code>     refused before listening                     exit 2
//	FAILED <code>       stopped after a pinned body stopped verifying exit 3
//	STOPPED             SIGTERM/SIGINT drained and stopped           exit 0
//
// Usage errors exit 64, internal errors (including listen failures) 70.
// Secrets never travel in flags: S3 credentials come from an owner-only
// --s3-credentials-file or from the environment variables it names.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
	"github.com/misscomputer/misscomputer-subnet/pkg/organic"
	"github.com/misscomputer/misscomputer-subnet/pkg/static"
	"github.com/misscomputer/misscomputer-subnet/pkg/staticorigin"
)

const (
	exitStopped  = 0
	exitRejected = 2
	exitFailed   = 3
	exitUsage    = 64
	exitInternal = 70

	readySchema         = organic.SchemaPrefix + "static-origin-ready"
	maxCredentialsBytes = 4 << 10
)

func main() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	os.Exit(run(os.Args[1:], os.Getenv, signals, os.Stdout, os.Stderr))
}

type options struct {
	listen, routeHost, siteDigest, releaseDigest, releaseFile, trustPolicyFile, trustPolicyDigest     string
	implementation, cacheDir, readyFile                                                               string
	backend, artifactDir, s3Endpoint, s3Bucket, s3Region, s3CredentialsFile, s3AccessEnv, s3SecretEnv string
	cacheMaxBytes                                                                                     int64
	prepareTimeout, shutdownTimeout                                                                   time.Duration
	fetchConcurrency, requestConcurrency                                                              int
	printImplementation                                                                               bool
}

func run(args []string, getenv func(string) string, signals <-chan os.Signal, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("static-origin", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var o options
	flags.StringVar(&o.listen, "listen", "", "host:port to listen on after verification (port 0 picks one; reported in READY)")
	flags.StringVar(&o.routeHost, "route-host", "", "the one route host served; other Host values get 421")
	flags.StringVar(&o.siteDigest, "site-digest", "", "sha256:<hex> site_digest to serve")
	flags.StringVar(&o.releaseDigest, "release-digest", "", "sha256:<hex> release_digest bound to the site")
	flags.StringVar(&o.releaseFile, "release-file", "", "stored static-site-release bytes")
	flags.StringVar(&o.trustPolicyFile, "trust-policy-file", "", "stored static-site-release-trust-policy bytes")
	flags.StringVar(&o.trustPolicyDigest, "trust-policy-digest", "", "out-of-band pin: the policy's digest_sha256")
	flags.StringVar(&o.implementation, "server-implementation-digest", "", "handler digest the release must authorize; must equal this build's")
	flags.StringVar(&o.cacheDir, "cache-dir", "", "private directory for the verified copy (swept on start)")
	flags.Int64Var(&o.cacheMaxBytes, "cache-max-bytes", static.MaxTotalBytes, "verified-copy byte quota")
	flags.StringVar(&o.readyFile, "ready-file", "", "optional path receiving the READY json (written atomically, mode 0600)")
	flags.StringVar(&o.backend, "artifact-backend", "file", "read-only artifact store: file or s3")
	flags.StringVar(&o.artifactDir, "artifact-dir", "", "filesystem artifact store root")
	flags.StringVar(&o.s3Endpoint, "s3-endpoint", "", "S3-compatible endpoint URL")
	flags.StringVar(&o.s3Bucket, "s3-bucket", "", "S3 bucket")
	flags.StringVar(&o.s3Region, "s3-region", "auto", "S3 region")
	flags.StringVar(&o.s3CredentialsFile, "s3-credentials-file", "", `owner-only JSON {"access_key_id":…,"secret_access_key":…}; overrides the env variables`)
	flags.StringVar(&o.s3AccessEnv, "s3-access-key-env", "S3_ACCESS_KEY_ID", "environment variable holding the read-only access key id")
	flags.StringVar(&o.s3SecretEnv, "s3-secret-key-env", "S3_SECRET_ACCESS_KEY", "environment variable holding the read-only secret key")
	flags.DurationVar(&o.prepareTimeout, "prepare-timeout", staticorigin.DefaultPrepareTimeout, "bound on fetching and verifying the whole site")
	flags.DurationVar(&o.shutdownTimeout, "shutdown-timeout", 30*time.Second, "drain bound after SIGTERM")
	flags.IntVar(&o.fetchConcurrency, "fetch-concurrency", static.DefaultFetchConcurrency, "concurrent blob downloads")
	flags.IntVar(&o.requestConcurrency, "request-concurrency", staticorigin.DefaultRequestConcurrency, "in-flight request bound; excess gets the fixed 503")
	flags.BoolVar(&o.printImplementation, "print-server-implementation-digest", false, "print this build's handler digest and exit")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if o.printImplementation {
		fmt.Fprintln(stdout, static.ServerImplementationDigest)
		return exitStopped
	}
	if flags.NArg() != 0 || o.listen == "" || o.releaseFile == "" || o.trustPolicyFile == "" {
		fmt.Fprintln(stderr, "static-origin: --listen, --release-file and --trust-policy-file are required; no positional arguments")
		return exitUsage
	}
	store, err := openStore(o, getenv)
	if err != nil {
		fmt.Fprintln(stderr, "static-origin:", err)
		return exitUsage
	}
	release, err := readSmallFile(o.releaseFile, static.MaxReleaseBytes)
	if err != nil {
		fmt.Fprintln(stderr, "static-origin: release file:", err)
		return exitUsage
	}
	policy, err := readSmallFile(o.trustPolicyFile, static.MaxTrustPolicyBytes)
	if err != nil {
		fmt.Fprintln(stderr, "static-origin: trust policy file:", err)
		return exitUsage
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	prepared := make(chan struct{})
	go func() {
		select {
		case <-signals:
			cancel()
		case <-prepared:
		}
	}()
	origin, err := staticorigin.Prepare(ctx, staticorigin.Config{
		RouteHost: o.routeHost, SiteDigest: o.siteDigest, ReleaseDigest: o.releaseDigest,
		Release: release, TrustPolicy: policy, TrustPolicyDigestSHA256: o.trustPolicyDigest,
		ServerImplementationDigest: o.implementation, CacheDir: o.cacheDir, CacheMaxBytes: o.cacheMaxBytes,
		PrepareTimeout: o.prepareTimeout, FetchConcurrency: o.fetchConcurrency, RequestConcurrency: o.requestConcurrency,
	}, store)
	close(prepared)
	if err != nil {
		if ctx.Err() != nil {
			fmt.Fprintln(stdout, "STOPPED")
			return exitStopped
		}
		fmt.Fprintln(stderr, "static-origin:", err)
		fmt.Fprintln(stdout, "REJECTED", staticorigin.Code(err))
		return exitRejected
	}

	listener, err := net.Listen("tcp", o.listen)
	if err != nil {
		fmt.Fprintln(stderr, "static-origin: listen:", err)
		_ = origin.Shutdown(context.Background())
		return exitInternal
	}
	ready, err := json.Marshal(struct {
		Schema        string `json:"schema"`
		SchemaVersion int    `json:"schema_version"`
		ListenAddress string `json:"listen_address"`
		PID           int    `json:"pid"`
		staticorigin.Identity
	}{readySchema, 1, listener.Addr().String(), os.Getpid(), origin.Identity()})
	if err == nil && o.readyFile != "" {
		err = writeFileAtomic(o.readyFile, append(ready, '\n'))
	}
	if err != nil {
		fmt.Fprintln(stderr, "static-origin: ready report:", err)
		listener.Close()
		_ = origin.Shutdown(context.Background())
		return exitInternal
	}

	served := make(chan error, 1)
	go func() { served <- origin.Serve(listener) }()
	fmt.Fprintln(stdout, "READY", string(ready))
	select {
	case err := <-served:
		var fault *staticorigin.FaultError
		if errors.As(err, &fault) {
			fmt.Fprintln(stderr, "static-origin:", err)
			fmt.Fprintln(stdout, "FAILED", fault.Code)
			return exitFailed
		}
		fmt.Fprintln(stderr, "static-origin: serve:", err)
		return exitInternal
	case <-signals:
		shutdownCtx, stop := context.WithTimeout(context.Background(), o.shutdownTimeout)
		defer stop()
		if err := origin.Shutdown(shutdownCtx); err != nil {
			fmt.Fprintln(stderr, "static-origin: drain incomplete:", err)
		}
		if err := <-served; err != nil && !errors.Is(err, http.ErrServerClosed) {
			var fault *staticorigin.FaultError
			if errors.As(err, &fault) {
				fmt.Fprintln(stdout, "FAILED", fault.Code)
				return exitFailed
			}
		}
		fmt.Fprintln(stdout, "STOPPED")
		return exitStopped
	}
}

// openStore selects the read-only artifact store. Credential values never
// appear in errors, output or arguments.
func openStore(o options, getenv func(string) string) (staticorigin.Store, error) {
	switch o.backend {
	case "file":
		if o.artifactDir == "" {
			return nil, errors.New("--artifact-dir is required for the file backend")
		}
		return artifact.FileStore{Root: filepath.Clean(o.artifactDir)}, nil
	case "s3":
		if o.s3Endpoint == "" || o.s3Bucket == "" {
			return nil, errors.New("--s3-endpoint and --s3-bucket are required for the s3 backend")
		}
		accessKey, secretKey, err := s3Credentials(o, getenv)
		if err != nil {
			return nil, err
		}
		store := artifact.S3Store{Endpoint: o.s3Endpoint, Bucket: o.s3Bucket, Region: o.s3Region, AccessKey: accessKey, SecretKey: secretKey}
		if err := store.Validate(); err != nil {
			return nil, fmt.Errorf("invalid S3 configuration: %w", err)
		}
		return store, nil
	}
	return nil, fmt.Errorf("unsupported --artifact-backend %q", o.backend)
}

func s3Credentials(o options, getenv func(string) string) (string, string, error) {
	if o.s3CredentialsFile == "" {
		accessKey, secretKey := getenv(o.s3AccessEnv), getenv(o.s3SecretEnv)
		if accessKey == "" || secretKey == "" {
			return "", "", fmt.Errorf("S3 credentials: set %s and %s, or --s3-credentials-file", o.s3AccessEnv, o.s3SecretEnv)
		}
		return accessKey, secretKey, nil
	}
	info, err := os.Lstat(o.s3CredentialsFile)
	if err != nil {
		return "", "", errors.New("S3 credentials file is unreadable")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return "", "", errors.New("S3 credentials file must be a regular, owner-only (0600 or 0400) file")
	}
	raw, err := readSmallFile(o.s3CredentialsFile, maxCredentialsBytes)
	if err != nil {
		return "", "", errors.New("S3 credentials file is unreadable")
	}
	var credentials struct {
		AccessKeyID     string `json:"access_key_id"`
		SecretAccessKey string `json:"secret_access_key"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&credentials); err != nil || decoder.More() || credentials.AccessKeyID == "" || credentials.SecretAccessKey == "" {
		// The decoder error can quote file content; never return it.
		return "", "", errors.New(`S3 credentials file must be exactly {"access_key_id":…,"secret_access_key":…}`)
	}
	return credentials.AccessKeyID, credentials.SecretAccessKey, nil
}

func readSmallFile(path string, maximum int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, fmt.Errorf("file exceeds %d bytes", maximum)
	}
	return data, nil
}

func writeFileAtomic(path string, data []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".static-origin-ready-*")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporary.Name(), path)
}
