// SPDX-License-Identifier: AGPL-3.0-only

package runtime

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/organic"
)

// StartupHealth runs the ticket's startup check directly against a started
// container: startup_timeout_millis is the overall deadline,
// probe_timeout_millis bounds each attempt, and successes_required
// consecutive matches are needed. Redirects are never followed. running is
// polled between attempts so a crashed process fails as container_exited
// instead of waiting for the deadline. host, when non-empty, is sent as the
// Host header so the app sees its public route host.
func StartupHealth(ctx context.Context, client *http.Client, baseURL, host string, check organic.HealthPredicate, running func(context.Context) (bool, error)) error {
	if err := check.Validate(); err != nil {
		return Fail(CodeInternal, err)
	}
	// Probes go straight to the container address: never through an
	// environment-configured proxy, and never reusing connections.
	probeClient := &http.Client{Transport: &http.Transport{
		Proxy: nil, DisableKeepAlives: true, MaxResponseHeaderBytes: 64 << 10,
		DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
	}}
	if client != nil {
		copied := *client
		probeClient = &copied
	}
	probeClient.Timeout = 0
	probeClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	deadline := time.Now().Add(time.Duration(check.StartupTimeoutMillis) * time.Millisecond)
	startupCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	interval := time.Duration(check.IntervalMillis) * time.Millisecond
	probeTimeout := time.Duration(check.ProbeTimeoutMillis) * time.Millisecond
	target := baseURL + check.Path

	consecutive := 0
	lastCode := CodeHealthTimeout
	var lastErr error = fmt.Errorf("no health attempt completed")
	for {
		code, err := probeOnce(startupCtx, probeClient, target, host, check, probeTimeout)
		if err == nil {
			consecutive++
			if consecutive >= check.SuccessesRequired {
				return nil
			}
		} else {
			consecutive = 0
			lastCode, lastErr = code, err
		}
		if running != nil {
			alive, runErr := running(context.WithoutCancel(ctx))
			if runErr == nil && !alive {
				return &Failure{Code: CodeContainerExited, Err: fmt.Errorf("container exited before startup health passed")}
			}
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !time.Now().Add(interval).Before(deadline) {
			return &Failure{Code: lastCode, Err: fmt.Errorf("startup health did not pass within %s: %w", time.Duration(check.StartupTimeoutMillis)*time.Millisecond, lastErr)}
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func probeOnce(ctx context.Context, client *http.Client, target, host string, check organic.HealthPredicate, timeout time.Duration) (FailureCode, error) {
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(probeCtx, check.Method, target, nil)
	if err != nil {
		return CodeInternal, err
	}
	if host != "" {
		req.Host = host
	}
	resp, err := client.Do(req)
	if err != nil {
		return CodeHealthTimeout, fmt.Errorf("health request failed")
	}
	defer resp.Body.Close()
	if !slices.Contains(check.ExpectedStatuses, resp.StatusCode) {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, MaxHealthBodyBytes))
		return CodeHealthUnexpectedStatus, fmt.Errorf("health returned status %d", resp.StatusCode)
	}
	if check.ResponseMarker == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, MaxHealthBodyBytes))
		return "", nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxHealthBodyBytes))
	if err != nil {
		return CodeHealthTimeout, fmt.Errorf("health body read failed")
	}
	if !bytes.Contains(body, []byte(*check.ResponseMarker)) {
		return CodeHealthMarkerMissing, fmt.Errorf("health response lacks the marker")
	}
	return "", nil
}
