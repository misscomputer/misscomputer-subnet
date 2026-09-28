// SPDX-License-Identifier: AGPL-3.0-only

package organic

import "errors"

// This file is the miner-facing health vocabulary. The miner agent, the
// runtime supervisor, and the deployment.v4 protocol all consume these
// types, so they live apart from the Deploy API resources in api.go: the
// customer-facing API surface can be retired without touching the health
// contract the miner side keeps.

// HealthPredicate is the customer health predicate (submission, runtime request).
type HealthPredicate struct {
	Method               string  `json:"method"`
	Path                 string  `json:"path"`
	ExpectedStatuses     []int   `json:"expected_statuses"`
	ResponseMarker       *string `json:"response_marker"`
	SuccessesRequired    int     `json:"successes_required"`
	IntervalMillis       int     `json:"interval_millis"`
	ProbeTimeoutMillis   int     `json:"probe_timeout_millis"`
	StartupTimeoutMillis int     `json:"startup_timeout_millis"`
}

func (h HealthPredicate) Validate() error {
	if err := validateProbe(h.Method, h.Path, h.ExpectedStatuses, h.ResponseMarker); err != nil {
		return err
	}
	switch {
	case !between(int64(h.SuccessesRequired), 1, 5):
		return errors.New("successes_required must be 1-5")
	case !between(int64(h.IntervalMillis), 500, 10000):
		return errors.New("interval_millis must be 500-10000")
	case !between(int64(h.ProbeTimeoutMillis), 1000, 10000):
		return errors.New("probe_timeout_millis must be 1000-10000")
	case !between(int64(h.StartupTimeoutMillis), 5000, 120000):
		return errors.New("startup_timeout_millis must be 5000-120000")
	}
	return nil
}

func validateProbe(method, path string, statuses []int, marker *string) error {
	if method != "GET" && method != "HEAD" {
		return errors.New("health method must be GET or HEAD")
	}
	if len(path) > 1024 || !healthPathPattern.MatchString(path) {
		return errors.New("health path must be absolute without //, ?, # or control bytes")
	}
	if len(statuses) < 1 || len(statuses) > 8 {
		return errors.New("expected_statuses must hold 1-8 values")
	}
	for _, status := range statuses {
		if status < 100 || status > 599 {
			return errors.New("expected status must be 100-599")
		}
	}
	if marker != nil && !markerPattern.MatchString(*marker) {
		return errors.New("response_marker must be 1-256 printable ASCII characters")
	}
	return nil
}

// TicketHealth is the deployment.v4 health: the predicate plus the fixed
// failure threshold (2), which customers never set.
type TicketHealth struct {
	HealthPredicate
	FailureThreshold int `json:"failure_threshold"`
}

func (h TicketHealth) Validate() error {
	if h.FailureThreshold != HealthFailureThreshold {
		return errors.New("health failure_threshold must be 2")
	}
	return h.HealthPredicate.Validate()
}
