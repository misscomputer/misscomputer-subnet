// SPDX-License-Identifier: AGPL-3.0-only

package artifact

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestS3RetriesTransientStatusAndResigns(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		if err := verifyTestSigV4(r, body, "retry-access", "retry-secret"); err != nil {
			t.Errorf("verify retry signature: %v", err)
			return
		}
		if attempts.Add(1) < 3 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, `<Error><Code>SlowDown</Code><Message>temporary</Message></Error>`)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	store := S3Store{
		Endpoint: server.URL, Bucket: "retry-bucket", Region: "auto", AccessKey: "retry-access", SecretKey: "retry-secret",
		Client: server.Client(), MaxAttempts: 3, RetryBaseDelay: time.Millisecond,
	}
	if err := store.Put(context.Background(), "v1/retry/object", []byte("retry-safe"), "application/octet-stream"); err != nil {
		t.Fatal(err)
	}
	if got := attempts.Load(); got != 3 {
		t.Fatalf("attempts = %d, want 3", got)
	}
}

func TestS3RetryBackoffHonorsContextCancellation(t *testing.T) {
	called := make(chan struct{}, 1)
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		called <- struct{}{}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	store := S3Store{
		Endpoint: server.URL, Bucket: "cancel-bucket", Region: "auto", AccessKey: "cancel-access", SecretKey: "cancel-secret",
		Client: server.Client(), MaxAttempts: 3, RetryBaseDelay: 2 * time.Second,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- store.Put(ctx, "v1/cancel/object", nil, "application/octet-stream") }()
	<-called
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation error = %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("S3 retry ignored context cancellation")
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("attempts after cancellation = %d, want 1", got)
	}
}

func TestS3GetRetriesTransientResponseReadFailure(t *testing.T) {
	var attempts atomic.Int32
	var jitterCalls atomic.Int32
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body := io.ReadCloser(io.NopCloser(strings.NewReader("verified")))
		if attempts.Add(1) == 1 {
			body = failingReadCloser{}
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: body, Request: req}, nil
	})
	store := S3Store{
		Endpoint: "https://s3.example.invalid", Bucket: "retry-bucket", Region: "auto", AccessKey: "retry-access", SecretKey: "retry-secret",
		Client: &http.Client{Transport: transport}, MaxAttempts: 2, RetryBaseDelay: time.Nanosecond,
		RetryJitter: func(minimum, _ time.Duration) time.Duration {
			jitterCalls.Add(1)
			return minimum
		},
	}
	body, err := store.Get(context.Background(), "v1/retry/read")
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "verified" || attempts.Load() != 2 || jitterCalls.Load() != 1 {
		t.Fatalf("retried body = %q attempts=%d jitter_calls=%d", body, attempts.Load(), jitterCalls.Load())
	}
}

func TestS3RequestAttemptHasBoundedTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()
	store := S3Store{
		Endpoint: server.URL, Bucket: "timeout-bucket", Region: "auto", AccessKey: "timeout-access", SecretKey: "timeout-secret",
		Client: server.Client(), RequestTimeout: 20 * time.Millisecond, MaxAttempts: 1,
	}
	started := time.Now()
	err := store.Head(context.Background(), "v1/timeout/object")
	if time.Since(started) > time.Second {
		t.Fatal("bounded S3 request exceeded one second")
	}
	var s3Err *S3Error
	if !errors.As(err, &s3Err) || s3Err.Kind != S3ErrorTimeout || !s3Err.Retryable {
		t.Fatalf("timeout classification = %#v err=%v", s3Err, err)
	}
}

func TestS3ErrorsBoundProviderBodyAndHideAuthorization(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `<Error><Code>AccessDenied</Code><Message>`+r.Header.Get("Authorization")+strings.Repeat("x", 32<<10)+`</Message></Error>`)
	}))
	defer server.Close()
	store := S3Store{
		Endpoint: server.URL, Bucket: "private-bucket", Region: "auto", AccessKey: "sensitive-access-id", SecretKey: "sensitive-secret-value",
		Client: server.Client(), MaxAttempts: 1,
	}
	err := store.Put(context.Background(), "v1/private/object", []byte("body"), "application/octet-stream")
	var s3Err *S3Error
	if !errors.As(err, &s3Err) {
		t.Fatalf("error type = %T: %v", err, err)
	}
	if s3Err.Kind != S3ErrorPermission || s3Err.ServiceCode != "AccessDenied" || !s3Err.BodyTruncated {
		t.Fatalf("status classification = %#v", s3Err)
	}
	message := err.Error()
	for _, forbidden := range []string{"sensitive-access-id", "sensitive-secret-value", "AWS4-HMAC-SHA256", "Credential="} {
		if strings.Contains(message, forbidden) {
			t.Fatalf("safe error leaked %q: %s", forbidden, message)
		}
	}
	if len(message) > 512 {
		t.Fatalf("error message is unexpectedly large: %d", len(message))
	}
}

func TestS3TransportErrorTextCannotLeakSignedRequest(t *testing.T) {
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("provider reflected secret-value and %s", req.Header.Get("Authorization"))
	})
	store := S3Store{
		Endpoint: "https://s3.example.invalid/prefix", Bucket: "private-bucket", Region: "auto",
		AccessKey: "access-value", SecretKey: "secret-value", Client: &http.Client{Transport: transport}, MaxAttempts: 1,
	}
	err := store.Head(context.Background(), "v1/private/object")
	var s3Err *S3Error
	if !errors.As(err, &s3Err) || s3Err.Kind != S3ErrorTransport {
		t.Fatalf("transport error classification = %#v err=%v", s3Err, err)
	}
	for _, forbidden := range []string{"access-value", "secret-value", "AWS4-HMAC-SHA256", "Credential="} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("transport error leaked %q: %s", forbidden, err)
		}
	}
}

func TestS3GetBoundsSuccessfulObjectBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("x", 32))
	}))
	defer server.Close()
	store := S3Store{
		Endpoint: server.URL, Bucket: "bounded-bucket", Region: "auto", AccessKey: "bounded-access", SecretKey: "bounded-secret",
		Client: server.Client(), MaxAttempts: 1, MaxObjectBytes: 8,
	}
	_, err := store.Get(context.Background(), "v1/bounded/object")
	var s3Err *S3Error
	if !errors.As(err, &s3Err) || s3Err.Kind != S3ErrorResponseTooBig {
		t.Fatalf("large response classification = %#v err=%v", s3Err, err)
	}
}

func TestS3GetBoundedRejectsDeclaredOversizeWithoutReading(t *testing.T) {
	body := &observedReadCloser{reader: strings.NewReader(strings.Repeat("x", 32))}
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode:    http.StatusOK,
			Header:        make(http.Header),
			Body:          body,
			Request:       req,
			ContentLength: 9,
		}, nil
	})
	store := S3Store{
		Endpoint: "https://s3.example.invalid", Bucket: "bounded-bucket", Region: "auto",
		AccessKey: "bounded-access", SecretKey: "bounded-secret",
		Client: &http.Client{Transport: transport}, MaxAttempts: 1, MaxObjectBytes: 64,
	}
	_, err := store.GetBounded(context.Background(), "v1/bounded/manifest", 8)
	var s3Err *S3Error
	if !errors.As(err, &s3Err) || s3Err.Kind != S3ErrorResponseTooBig || s3Err.Retryable {
		t.Fatalf("declared oversize classification = %#v err=%v", s3Err, err)
	}
	if body.read != 0 || !body.closed {
		t.Fatalf("declared oversize body read=%d closed=%t", body.read, body.closed)
	}
}

func TestS3GetBoundedStopsUndeclaredOversizeAtLimit(t *testing.T) {
	source := &countingByteReader{remaining: 1 << 20}
	body := &observedReadCloser{reader: source}
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode:    http.StatusOK,
			Header:        make(http.Header),
			Body:          body,
			Request:       req,
			ContentLength: -1,
		}, nil
	})
	store := S3Store{
		Endpoint: "https://s3.example.invalid", Bucket: "bounded-bucket", Region: "auto",
		AccessKey: "bounded-access", SecretKey: "bounded-secret",
		Client: &http.Client{Transport: transport}, MaxAttempts: 1, MaxObjectBytes: 64,
	}
	_, err := store.GetBounded(context.Background(), "v1/bounded/manifest", 8)
	var s3Err *S3Error
	if !errors.As(err, &s3Err) || s3Err.Kind != S3ErrorResponseTooBig || s3Err.Retryable {
		t.Fatalf("actual oversize classification = %#v err=%v", s3Err, err)
	}
	if body.read != 9 || source.remaining != (1<<20)-9 || !body.closed {
		t.Fatalf("actual oversize body read=%d remaining=%d closed=%t", body.read, source.remaining, body.closed)
	}
}

func TestS3GetBoundedDoesNotWeakenStricterStoreLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("x", 32))
	}))
	defer server.Close()
	store := S3Store{
		Endpoint: server.URL, Bucket: "bounded-bucket", Region: "auto",
		AccessKey: "bounded-access", SecretKey: "bounded-secret",
		Client: server.Client(), MaxAttempts: 1, MaxObjectBytes: 8,
	}
	_, err := store.GetBounded(context.Background(), "v1/bounded/manifest", 64)
	var s3Err *S3Error
	if !errors.As(err, &s3Err) || s3Err.Kind != S3ErrorResponseTooBig {
		t.Fatalf("store-wide bound classification = %#v err=%v", s3Err, err)
	}
}

func TestS3SignedRequestRejectsQueries(t *testing.T) {
	store := S3Store{AccessKey: "query-access", SecretKey: "query-secret"}
	for _, raw := range []string{
		"https://s3.example.invalid/bucket/key?name=a+b",
		"https://s3.example.invalid/bucket/key?",
	} {
		target, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.signedRequest(context.Background(), http.MethodGet, target, nil, ""); err == nil || !strings.Contains(err.Error(), "query") {
			t.Fatalf("query-bearing target %q error = %v", raw, err)
		}
	}
	opaque := &url.URL{Scheme: "https", Opaque: "//s3.example.invalid/bucket/key?name=value"}
	if _, err := store.signedRequest(context.Background(), http.MethodGet, opaque, nil, ""); err == nil || !strings.Contains(err.Error(), "query") {
		t.Fatalf("opaque query-bearing target error = %v", err)
	}
}

func TestS3ValidateRejectsEndpointQueries(t *testing.T) {
	for _, endpoint := range []string{
		"https://s3.example.invalid/prefix?name=value",
		"https://s3.example.invalid/prefix?",
	} {
		store := S3Store{Endpoint: endpoint, Bucket: "bucket", AccessKey: "query-access", SecretKey: "query-secret"}
		if err := store.Validate(); err == nil || !strings.Contains(err.Error(), "query") {
			t.Fatalf("query-bearing endpoint %q error = %v", endpoint, err)
		}
	}
}

func TestS3RetryDelayUsesBoundedEqualJitter(t *testing.T) {
	lower := func(minimum, _ time.Duration) time.Duration { return minimum }
	upper := func(_, maximum time.Duration) time.Duration { return maximum }
	below := func(minimum, _ time.Duration) time.Duration { return minimum - time.Second }
	above := func(_, maximum time.Duration) time.Duration { return maximum + time.Second }

	if got := retryDelay(100*time.Millisecond, 3, "", lower); got != 200*time.Millisecond {
		t.Fatalf("lower equal-jitter delay = %s", got)
	}
	if got := retryDelay(100*time.Millisecond, 3, "", upper); got != 400*time.Millisecond {
		t.Fatalf("upper equal-jitter delay = %s", got)
	}
	if got := retryDelay(100*time.Millisecond, 3, "", below); got != 200*time.Millisecond {
		t.Fatalf("below-bound injected delay = %s", got)
	}
	if got := retryDelay(100*time.Millisecond, 3, "", above); got != 400*time.Millisecond {
		t.Fatalf("above-bound injected delay = %s", got)
	}
	if got := retryDelay(10*time.Second, 1, "", upper); got != maxS3RetryDelay {
		t.Fatalf("oversize base delay = %s", got)
	}

	jitterCalled := false
	jitter := func(_, _ time.Duration) time.Duration {
		jitterCalled = true
		return 0
	}
	if got := retryDelay(time.Millisecond, 1, "2", jitter); got != 2*time.Second || jitterCalled {
		t.Fatalf("Retry-After delay=%s jitterCalled=%t", got, jitterCalled)
	}
	if got := retryDelay(time.Millisecond, 1, "999", jitter); got != maxS3RetryDelay || jitterCalled {
		t.Fatalf("capped Retry-After delay=%s jitterCalled=%t", got, jitterCalled)
	}
	if got := retryDelay(time.Millisecond, 1, "9223372036854775807", jitter); got != maxS3RetryDelay || jitterCalled {
		t.Fatalf("overflow-safe Retry-After delay=%s jitterCalled=%t", got, jitterCalled)
	}
}

func TestS3DoesNotFollowRedirectsWithSignedAuthorization(t *testing.T) {
	var redirected atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		redirected.Add(1)
	}))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", destination.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	store := S3Store{
		Endpoint: source.URL, Bucket: "redirect-bucket", Region: "auto", AccessKey: "redirect-access", SecretKey: "redirect-secret",
		Client: source.Client(), MaxAttempts: 1,
	}
	err := store.Head(context.Background(), "v1/redirect/object")
	var s3Err *S3Error
	if !errors.As(err, &s3Err) || s3Err.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("redirect response = %#v err=%v", s3Err, err)
	}
	if got := redirected.Load(); got != 0 {
		t.Fatalf("signed request followed %d redirects", got)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type failingReadCloser struct{}

func (failingReadCloser) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (failingReadCloser) Close() error             { return nil }

type observedReadCloser struct {
	reader io.Reader
	read   int64
	closed bool
}

func (body *observedReadCloser) Read(buffer []byte) (int, error) {
	n, err := body.reader.Read(buffer)
	body.read += int64(n)
	return n, err
}

func (body *observedReadCloser) Close() error {
	body.closed = true
	return nil
}

type countingByteReader struct{ remaining int64 }

func (reader *countingByteReader) Read(buffer []byte) (int, error) {
	if reader.remaining == 0 {
		return 0, io.EOF
	}
	n := int64(len(buffer))
	if n > reader.remaining {
		n = reader.remaining
	}
	for index := int64(0); index < n; index++ {
		buffer[index] = 'x'
	}
	reader.remaining -= n
	return int(n), nil
}
