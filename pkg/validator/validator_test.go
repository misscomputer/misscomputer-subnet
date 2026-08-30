// SPDX-License-Identifier: AGPL-3.0-only

package validator

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/edge"
)

func TestProbeHostTemplateUsesPublicHostnameAndExactTargetHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Host != "edge-dev-app.miss.computer" || req.Header.Get(edge.TargetReplicaHeader) != "app-miner" ||
			req.Header.Get(edge.ProbeAuthorizationHeader) != "probe-token" {
			http.Error(w, "wrong public probe identity", http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte("correct"))
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	dialer := &net.Dialer{Timeout: time.Second}
	client := &http.Client{
		Timeout: time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", parsed.Host)
		}},
	}
	value := Validator{
		Vantage: "test", EdgeURL: "http://{host}:" + parsed.Port(), InternalProbeToken: "probe-token", Client: client,
	}.ProbeReplica(context.Background(), "edge-dev-app.miss.computer", "app-miner", "/challenge", "correct")
	if !value.Correct || value.Status != http.StatusOK {
		t.Fatalf("templated public probe failed: %+v", value)
	}
}

func TestProbeRejectsMalformedHostTemplate(t *testing.T) {
	value := Validator{EdgeURL: "https://{host}.{host}"}.Probe(context.Background(), "app.test", "/challenge", "correct")
	if value.Correct || value.Error == "" {
		t.Fatalf("malformed template was accepted: %+v", value)
	}
}

func TestProbeDoesNotFollowRedirectAwayFromDeploymentHost(t *testing.T) {
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("correct"))
	}))
	defer destination.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, destination.URL+"/challenge", http.StatusFound)
	}))
	defer origin.Close()

	result := Validator{EdgeURL: origin.URL}.Probe(context.Background(), "app.test", "/challenge", "correct")
	if result.Correct || result.Status != http.StatusFound {
		t.Fatalf("redirect satisfied public acceptance: %+v", result)
	}
}
