// SPDX-License-Identifier: AGPL-3.0-only

package runtime

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/organic"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
)

func testWorkload() protocol.WorkloadV4 {
	return protocol.WorkloadV4{
		Kind: organic.WorkloadKind, ContainerPort: 8080, RuntimeProfile: organic.RuntimeProfile,
		Env: protocol.WorkloadEnvV4{Host: "0.0.0.0", Port: "8080"},
	}
}

func testHealth() organic.HealthPredicate {
	return organic.HealthPredicate{
		Method: "GET", Path: "/", ExpectedStatuses: []int{200}, SuccessesRequired: 2,
		IntervalMillis: 500, ProbeTimeoutMillis: 1000, StartupTimeoutMillis: 5000,
	}
}

// The runtime's codes are the receipt v4 error_code vocabulary; a drifted or
// missing code would sign receipts the scheduler rejects.
func TestFailureCodesAreTheReceiptV4Vocabulary(t *testing.T) {
	codes := []FailureCode{
		CodeArtifactFetchFailed, CodeArtifactVerifyFailed, CodeImageLoadFailed, CodeImageIdentityMismatch,
		CodeContainerCreateFailed, CodeContainerExited, CodeHealthTimeout, CodeHealthUnexpectedStatus,
		CodeHealthMarkerMissing, CodeResourceExhausted, CodeDeactivated, CodeInternal,
	}
	if len(codes) != len(organic.ReceiptErrorAttribution) {
		t.Fatalf("runtime defines %d codes, contract has %d", len(codes), len(organic.ReceiptErrorAttribution))
	}
	for _, code := range codes {
		if _, known := organic.ReceiptErrorAttribution[string(code)]; !known {
			t.Errorf("runtime code %q is not a receipt v4 error_code", code)
		}
	}
}

func TestStartupHealthAppliesTicketPredicate(t *testing.T) {
	marker := "organic-ready"
	for _, test := range []struct {
		name    string
		handler func(calls int32, w http.ResponseWriter, r *http.Request)
		change  func(*organic.HealthPredicate)
		running bool
		want    FailureCode
	}{
		{name: "consecutive successes after warm-up", running: true, handler: func(calls int32, w http.ResponseWriter, r *http.Request) {
			if calls < 3 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write([]byte("ok " + marker))
		}, change: func(h *organic.HealthPredicate) { h.ResponseMarker = &marker }},
		{name: "redirect is not followed", running: true, want: CodeHealthUnexpectedStatus, handler: func(_ int32, w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" {
				http.Redirect(w, r, "/ok", http.StatusFound)
				return
			}
			w.WriteHeader(http.StatusOK)
		}},
		{name: "marker beyond 64 KiB prefix", running: true, want: CodeHealthMarkerMissing, handler: func(_ int32, w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(strings.Repeat("x", MaxHealthBodyBytes) + marker))
		}, change: func(h *organic.HealthPredicate) { h.ResponseMarker = &marker }},
		{name: "per-probe timeout, not total deadline", running: true, want: CodeHealthTimeout, handler: func(_ int32, w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-time.After(3 * time.Second):
			}
		}},
		{name: "exited container", running: false, want: CodeContainerExited, handler: func(_ int32, w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var calls atomic.Int32
			var sawHost atomic.Bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sawHost.Store(r.Host == "app-k3j9x0q2ab.on.miss.computer")
				test.handler(calls.Add(1), w, r)
			}))
			defer server.Close()
			check := testHealth()
			if test.change != nil {
				test.change(&check)
			}
			started := time.Now()
			running := func(context.Context) (bool, error) { return test.running, nil }
			err := StartupHealth(context.Background(), server.Client(), server.URL, "app-k3j9x0q2ab.on.miss.computer", check, running)
			if test.want == "" {
				if err != nil {
					t.Fatalf("health failed: %v", err)
				}
				if calls.Load() != 4 || !sawHost.Load() {
					t.Fatalf("calls=%d host forwarded=%t, want two warm-up failures then two consecutive successes", calls.Load(), sawHost.Load())
				}
				return
			}
			var failure *Failure
			if !errors.As(err, &failure) || failure.Code != test.want {
				t.Fatalf("health error = %v, want %s", err, test.want)
			}
			if test.want == CodeContainerExited && time.Since(started) > 2*time.Second {
				t.Fatalf("exited container waited %s for the startup deadline", time.Since(started))
			}
			if test.want == CodeHealthTimeout && calls.Load() < 2 {
				t.Fatalf("a single hung probe consumed the whole startup budget (%d attempts)", calls.Load())
			}
		})
	}
}
