// SPDX-License-Identifier: AGPL-3.0-only

// Package staticorigin is the platform's temporary static origin: it serves
// exactly one static-site-v1 site version on one route host with the pinned
// pkg/static handler, and nothing else. No customer code runs.
//
// The lifecycle is two-phase and fails closed:
//
//	origin, err := staticorigin.Prepare(ctx, config, store) // verify everything, no socket
//	err = origin.Serve(listener)                            // blocks; Shutdown or a fault ends it
//	err = origin.Shutdown(ctx)                              // drain, then drop the pinned copy
//
// Prepare authenticates the release under the pinned trust policy, binds
// site, release and handler digests, fetches the manifest and every blob
// from a read-only artifact store and verifies each against the manifest. A
// caller must not open its listener until Prepare succeeded. While serving,
// every body is rehashed; the first pinned byte that no longer verifies
// stops the origin (FaultError) instead of serving on.
package staticorigin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
	"github.com/misscomputer/misscomputer-subnet/pkg/organic"
	"github.com/misscomputer/misscomputer-subnet/pkg/static"
)

const (
	DefaultPrepareTimeout     = 10 * time.Minute
	DefaultRequestConcurrency = 64
	// CodeConfigInvalid rejects a configuration before anything is fetched.
	CodeConfigInvalid = "config_invalid"
)

// Store is the only artifact capability the origin needs: bounded reads of
// exact keys. artifact.FileStore and artifact.S3Store implement it; the
// origin never writes, lists or deletes.
type Store = artifact.BlobOpener

// Config binds one origin to one route host and one site version. Release
// and TrustPolicy are the stored document bytes; the trust policy is pinned
// by its out-of-band self-digest, never by its content alone.
type Config struct {
	RouteHost                  string
	SiteDigest                 string
	ReleaseDigest              string
	Release                    []byte
	TrustPolicy                []byte
	TrustPolicyDigestSHA256    string
	ServerImplementationDigest string
	// CacheDir holds the verified copy under <CacheDir>/misscomputer-static-v1,
	// which is swept on start; give each origin process its own directory.
	CacheDir           string
	CacheMaxBytes      int64
	PrepareTimeout     time.Duration
	FetchConcurrency   int
	RequestConcurrency int
}

// Identity is what one prepared origin serves; the runner reports it.
type Identity struct {
	RouteHost                  string `json:"route_host"`
	SiteDigest                 string `json:"site_digest"`
	ReleaseDigest              string `json:"release_digest"`
	ServerImplementationDigest string `json:"server_implementation_digest"`
	TrustPolicyDigestSHA256    string `json:"trust_policy_digest_sha256"`
	FileCount                  int    `json:"file_count"`
	TotalBytes                 int64  `json:"total_bytes"`
}

// Code is the stable failure code of a Prepare error: a static receipt code
// (static_fetch_failed, static_verify_failed, …), a release code
// (signature_invalid, release_binding_mismatch, …) or config_invalid.
func Code(err error) string {
	var config *configError
	switch {
	case err == nil:
		return ""
	case errors.As(err, &config):
		return CodeConfigInvalid
	case static.ReleaseCodeOf(err) != "":
		return string(static.ReleaseCodeOf(err))
	}
	return string(static.CodeOf(err))
}

type configError struct{ msg string }

func (e *configError) Error() string { return e.msg }

// FaultError ends Serve when a pinned body stopped verifying.
type FaultError struct{ Code string }

func (e *FaultError) Error() string { return "static origin failed closed: " + e.Code }

// Origin is one prepared, verified site version.
type Origin struct {
	identity Identity
	site     *static.Site
	server   *http.Server

	fault     chan struct{}
	faultOnce sync.Once
	failed    atomic.Bool
	shutdown  atomic.Bool
	closeOnce sync.Once
}

// Prepare verifies the configuration, release and every site byte and
// returns an origin that has not yet opened any socket.
func Prepare(ctx context.Context, config Config, store Store) (*Origin, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	policy, err := static.ParseTrustPolicy(config.TrustPolicy, config.TrustPolicyDigestSHA256)
	if err != nil {
		return nil, err
	}
	release, err := static.ParseRelease(config.Release, config.ReleaseDigest)
	if err != nil {
		return nil, err
	}
	if err := static.VerifyRelease(release, policy, config.SiteDigest); err != nil {
		return nil, err
	}
	timeout := config.PrepareTimeout
	if timeout <= 0 {
		timeout = DefaultPrepareTimeout
	}
	fetchCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	manifest, err := fetchManifest(fetchCtx, store, config.SiteDigest)
	if err != nil {
		return nil, err
	}
	maxBytes := config.CacheMaxBytes
	if maxBytes <= 0 {
		maxBytes = static.MaxTotalBytes
	}
	cache, err := static.OpenCache(config.CacheDir, maxBytes)
	if err != nil {
		return nil, static.Fail(static.CodeInternal, err)
	}
	site, err := cache.Pin(fetchCtx, store, config.SiteDigest, manifest, static.PinOptions{Concurrency: config.FetchConcurrency})
	if err != nil {
		return nil, err
	}
	origin := &Origin{
		identity: Identity{
			RouteHost: config.RouteHost, SiteDigest: config.SiteDigest, ReleaseDigest: config.ReleaseDigest,
			ServerImplementationDigest: static.ServerImplementationDigest, TrustPolicyDigestSHA256: policy.DigestSHA256,
			FileCount: len(manifest.Files), TotalBytes: manifest.TotalBytes(),
		},
		site:  site,
		fault: make(chan struct{}),
	}
	concurrency := config.RequestConcurrency
	if concurrency <= 0 {
		concurrency = DefaultRequestConcurrency
	}
	handler := static.NewHandler(site.Index(), faultingSource{site: site, fail: origin.fail}, config.RouteHost, concurrency)
	origin.server = &http.Server{
		Handler:           origin.guard(handler),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	return origin, nil
}

func (c Config) validate() error {
	switch {
	case !organic.ValidHostname(c.RouteHost):
		return &configError{"route host must be a lowercase hostname"}
	case !organic.ValidDigest(c.SiteDigest) || !organic.ValidDigest(c.ReleaseDigest):
		return &configError{"site and release digests must be sha256:<64 lowercase hex>"}
	case !organic.ValidHex64(c.TrustPolicyDigestSHA256):
		return &configError{"trust policy pin must be 64 lowercase hex"}
	case c.ServerImplementationDigest != static.ServerImplementationDigest:
		return &configError{fmt.Sprintf("this build implements handler %s, not %s", static.ServerImplementationDigest, c.ServerImplementationDigest)}
	case c.CacheDir == "":
		return &configError{"cache directory is required"}
	}
	return nil
}

func fetchManifest(ctx context.Context, store Store, siteDigest string) (static.Manifest, error) {
	reader, err := store.OpenBounded(ctx, static.ManifestKey(siteDigest), static.MaxManifestBytes)
	if err != nil {
		if artifact.IsOversize(err) {
			return static.Manifest{}, static.Fail(static.CodeVerifyFailed, err)
		}
		return static.Manifest{}, static.Fail(static.CodeFetchFailed, err)
	}
	stored, err := io.ReadAll(reader)
	reader.Close()
	if err != nil {
		if artifact.IsOversize(err) {
			return static.Manifest{}, static.Fail(static.CodeVerifyFailed, err)
		}
		return static.Manifest{}, static.Fail(static.CodeFetchFailed, err)
	}
	return static.Parse(stored, siteDigest)
}

// Identity reports the verified site this origin serves.
func (o *Origin) Identity() Identity { return o.identity }

// Serve answers requests on listener until Shutdown (http.ErrServerClosed)
// or a pinned-body fault (*FaultError), after which it stops accepting.
func (o *Origin) Serve(listener net.Listener) error {
	served := make(chan error, 1)
	go func() { served <- o.server.Serve(listener) }()
	select {
	case err := <-served:
		if o.failed.Load() {
			return &FaultError{Code: string(static.CodeVerifyFailed)}
		}
		return err
	case <-o.fault:
		_ = o.server.Close()
		<-served
		o.release()
		return &FaultError{Code: string(static.CodeVerifyFailed)}
	}
}

// Shutdown stops accepting, drains in-flight requests within ctx, closes
// what remains and drops the pinned copy.
func (o *Origin) Shutdown(ctx context.Context) error {
	o.shutdown.Store(true)
	err := o.server.Shutdown(ctx)
	if err != nil {
		_ = o.server.Close()
	}
	o.release()
	return err
}

func (o *Origin) release() { o.closeOnce.Do(o.site.Release) }

func (o *Origin) fail() {
	o.faultOnce.Do(func() {
		o.failed.Store(true)
		close(o.fault)
	})
}

// guard answers the fixed 503 once the origin failed closed, so no request
// after a fault reaches a body.
func (o *Origin) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if o.failed.Load() {
			_, _ = static.WriteResponse(w, static.Unavailable(req.Method), nil, nil)
			return
		}
		next.ServeHTTP(w, req)
	})
}

// faultingSource serves the pinned copy and reports a fault when a body is
// observed not to match its manifest entry: unopenable, longer than its
// length, or ending at the wrong length or digest. A client that stops
// reading is not a fault.
type faultingSource struct {
	site *static.Site
	fail func()
}

func (s faultingSource) Open(file static.File) (io.ReadCloser, error) {
	body, err := s.site.Open(file)
	if err != nil {
		s.fail()
		return nil, err
	}
	return &faultingBody{body: body, file: file, hash: sha256.New(), fail: s.fail}, nil
}

type faultingBody struct {
	body io.ReadCloser
	file static.File
	hash hash.Hash
	read int64
	fail func()
}

func (b *faultingBody) Read(p []byte) (int, error) {
	n, err := b.body.Read(p)
	b.read += int64(n)
	b.hash.Write(p[:n])
	switch {
	case b.read > b.file.ContentLength:
		b.fail()
	case errors.Is(err, io.EOF) && (b.read != b.file.ContentLength || hex.EncodeToString(b.hash.Sum(nil)) != b.file.BodySHA256):
		b.fail()
	case err != nil && !errors.Is(err, io.EOF):
		b.fail()
	}
	return n, err
}

func (b *faultingBody) Close() error { return b.body.Close() }
