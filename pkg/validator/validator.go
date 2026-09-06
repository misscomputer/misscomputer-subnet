// SPDX-License-Identifier: AGPL-3.0-only

package validator

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/edge"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
)

type ProbeResult struct {
	Vantage string        `json:"vantage"`
	At      time.Time     `json:"at"`
	Latency time.Duration `json:"latency"`
	Status  int           `json:"status"`
	Correct bool          `json:"correct"`
	// ServedByReplica is true only when the edge attested that this exact
	// response came back from a replica. A probe travels through the edge, and
	// the edge answers with a status of its own whenever the miner is the thing
	// that is down or unroutable — 502 for a dead backend or a nil tunnel
	// target, 404 for a replica that is no longer routed, 403 for a probe-token
	// mismatch. Status alone therefore cannot distinguish "the miner replied
	// with the wrong bytes" from "the miner never replied at all", and callers
	// that act differently on those two facts must read this field, not Status.
	ServedByReplica bool `json:"served_by_replica"`
	// EdgeGenerated is true when a response arrived without the edge's upstream
	// marker: the edge, an intermediary, or a fronting CDN produced it on the
	// miner's behalf. It is the exact complement of ServedByReplica for a
	// completed HTTP exchange, and false when no response arrived at all.
	EdgeGenerated bool   `json:"edge_generated"`
	Error         string `json:"error,omitempty"`
}

type Validator struct {
	Vantage            string
	EdgeURL            string
	InternalProbeToken string
	Client             *http.Client
}

func (v Validator) Probe(ctx context.Context, routeHost, challengePath, expectedValue string) ProbeResult {
	return v.probe(ctx, routeHost, challengePath, expectedValue, "")
}

// ProbeReplica traverses the same edge proxy but authenticates to an internal
// targeting mechanism so an existing healthy replica cannot mask a candidate.
func (v Validator) ProbeReplica(ctx context.Context, routeHost, replicaID, challengePath, expectedValue string) ProbeResult {
	return v.probe(ctx, routeHost, challengePath, expectedValue, replicaID)
}

func (v Validator) probe(ctx context.Context, routeHost, challengePath, expectedValue, replicaID string) ProbeResult {
	start := time.Now().UTC()
	result := ProbeResult{Vantage: v.Vantage, At: start}
	base := strings.TrimRight(v.EdgeURL, "/")
	if strings.Contains(base, "{host}") {
		if strings.Count(base, "{host}") != 1 {
			result.Error = "edge URL contains an invalid host template"
			return result
		}
		base = strings.Replace(base, "{host}", routeHost, 1)
	}
	parsed, err := url.Parse(base)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		result.Error = "edge URL must be an explicit http(s) origin or https://{host} template"
		return result
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+challengePath, nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	req.Host = routeHost
	req.Header.Set("Cache-Control", "no-cache")
	if replicaID != "" {
		req.Header.Set(edge.TargetReplicaHeader, replicaID)
		req.Header.Set(edge.ProbeAuthorizationHeader, v.InternalProbeToken)
	}
	client := v.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	// A redirect could move the hidden challenge away from the exact public
	// deployment Host and let an unrelated origin satisfy acceptance. Clone the
	// caller's client so its transport/timeouts remain intact, but fail closed on
	// every redirect without mutating shared client state.
	probeClient := *client
	probeClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := probeClient.Do(req)
	result.Latency = time.Since(start)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()
	result.Status = resp.StatusCode
	result.ServedByReplica = resp.Header.Get(edge.UpstreamResponseHeader) == edge.UpstreamResponseMarker
	result.EdgeGenerated = !result.ServedByReplica
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		result.Error = err.Error()
		return result
	}
	result.Correct = resp.StatusCode == http.StatusOK && protocol.ChallengeDigest(string(body)) == protocol.ChallengeDigest(expectedValue)
	if !result.Correct {
		if result.EdgeGenerated {
			result.Error = fmt.Sprintf("edge-generated response status=%d", resp.StatusCode)
			return result
		}
		result.Error = fmt.Sprintf("incorrect response status=%d", resp.StatusCode)
	}
	return result
}

func Score(success bool, latency, target time.Duration, availability float64) float64 {
	if !success || availability <= 0 {
		return 0
	}
	latencyFactor := 1.0
	if latency > target && latency > 0 {
		latencyFactor = float64(target) / float64(latency)
	}
	if availability > 1 {
		availability = 1
	}
	return latencyFactor * availability
}
