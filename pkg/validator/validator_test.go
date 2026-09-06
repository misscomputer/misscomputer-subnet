// SPDX-License-Identifier: AGPL-3.0-only

package validator

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/edge"
)

type probeRoundTripper func(*http.Request) (*http.Response, error)

func (f probeRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type interruptedProbeBody struct {
	read bool
}

func (b *interruptedProbeBody) Read(destination []byte) (int, error) {
	if !b.read {
		b.read = true
		return copy(destination, "partial"), nil
	}
	return 0, io.ErrUnexpectedEOF
}

func (*interruptedProbeBody) Close() error { return nil }

type oversizedInterruptedProbeBody struct {
	remaining int
}

func (b *oversizedInterruptedProbeBody) Read(destination []byte) (int, error) {
	if b.remaining == 0 {
		return 0, io.ErrUnexpectedEOF
	}
	count := min(len(destination), b.remaining)
	for index := 0; index < count; index++ {
		destination[index] = 'x'
	}
	b.remaining -= count
	return count, nil
}

func (*oversizedInterruptedProbeBody) Close() error { return nil }

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

func TestProbeDistinguishesReplicaResponsesFromEdgeGeneratedErrors(t *testing.T) {
	for name, testCase := range map[string]struct {
		handler         http.HandlerFunc
		wantStatus      int
		wantServed      bool
		wantEdge        bool
		wantCorrect     bool
		wantErrorSubstr string
	}{
		"replica served the challenge": {
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set(edge.UpstreamResponseHeader, edge.UpstreamResponseMarker)
				_, _ = w.Write([]byte("correct"))
			},
			wantStatus: http.StatusOK, wantServed: true, wantCorrect: true,
		},
		"replica served the wrong bytes": {
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set(edge.UpstreamResponseHeader, edge.UpstreamResponseMarker)
				_, _ = w.Write([]byte("something else"))
			},
			wantStatus: http.StatusOK, wantServed: true, wantErrorSubstr: "incorrect response",
		},
		// The edge answers 502 on the miner's behalf when the miner is dead. It
		// must not be readable as the miner having answered anything.
		"edge answered for a dead replica": {
			handler: func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "replica unavailable", http.StatusBadGateway)
			},
			wantStatus: http.StatusBadGateway, wantEdge: true, wantErrorSubstr: "edge-generated response",
		},
		"edge refused the probe token": {
			handler: func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "targeted probe forbidden", http.StatusForbidden)
			},
			wantStatus: http.StatusForbidden, wantEdge: true, wantErrorSubstr: "edge-generated response",
		},
		// A response body a miner fully controls cannot be used to forge the
		// marker: the marker is a response header the edge alone writes.
		"replica cannot forge the marker in its body": {
			handler: func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, edge.UpstreamResponseHeader+": "+edge.UpstreamResponseMarker, http.StatusBadGateway)
			},
			wantStatus: http.StatusBadGateway, wantEdge: true, wantErrorSubstr: "edge-generated response",
		},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(testCase.handler)
			defer server.Close()
			value := Validator{Vantage: "test", EdgeURL: server.URL, InternalProbeToken: "probe-token"}.
				ProbeReplica(context.Background(), "app.test", "app-miner", "/challenge", "correct")
			if value.Status != testCase.wantStatus {
				t.Fatalf("status = %d, want %d", value.Status, testCase.wantStatus)
			}
			if value.ServedByReplica != testCase.wantServed || value.EdgeGenerated != testCase.wantEdge {
				t.Fatalf("served_by_replica=%v edge_generated=%v, want %v/%v",
					value.ServedByReplica, value.EdgeGenerated, testCase.wantServed, testCase.wantEdge)
			}
			if value.Correct != testCase.wantCorrect {
				t.Fatalf("correct = %v, want %v", value.Correct, testCase.wantCorrect)
			}
			if !value.ResponseComplete {
				t.Fatalf("completed HTTP response was marked incomplete: %+v", value)
			}
			if testCase.wantErrorSubstr != "" && !strings.Contains(value.Error, testCase.wantErrorSubstr) {
				t.Fatalf("error %q does not report %q", value.Error, testCase.wantErrorSubstr)
			}
		})
	}
}

func TestProbeClassifiesMidBodyTransportErrorAsIncomplete(t *testing.T) {
	client := &http.Client{Transport: probeRoundTripper(func(*http.Request) (*http.Response, error) {
		header := make(http.Header)
		header.Set(edge.UpstreamResponseHeader, edge.UpstreamResponseMarker)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     header,
			Body:       &interruptedProbeBody{},
		}, nil
	})}
	result := Validator{EdgeURL: "https://edge.test", Client: client}.
		ProbeReplica(context.Background(), "app.test", "app-miner", "/challenge", "partial")
	if result.Correct || result.ResponseComplete {
		t.Fatalf("truncated body became complete content: %+v", result)
	}
	if !result.ServedByReplica || result.EdgeGenerated {
		t.Fatalf("header provenance was lost or rewritten: %+v", result)
	}
	if !strings.Contains(result.Error, io.ErrUnexpectedEOF.Error()) {
		t.Fatalf("body transport error was not reported: %+v", result)
	}
}

func TestProbeDrainsOversizedBodyBeforeDeclaringTransportComplete(t *testing.T) {
	client := &http.Client{Transport: probeRoundTripper(func(*http.Request) (*http.Response, error) {
		header := make(http.Header)
		header.Set(edge.UpstreamResponseHeader, edge.UpstreamResponseMarker)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     header,
			Body:       &oversizedInterruptedProbeBody{remaining: 5000},
		}, nil
	})}
	result := Validator{EdgeURL: "https://edge.test", Client: client}.
		ProbeReplica(context.Background(), "app.test", "app-miner", "/challenge", "correct")
	if result.Correct || result.ResponseComplete || result.EdgeGenerated {
		t.Fatalf("oversized truncated body became complete content: %+v", result)
	}
	if !result.ServedByReplica || !strings.Contains(result.Error, io.ErrUnexpectedEOF.Error()) {
		t.Fatalf("oversized transport failure lost provenance/error: %+v", result)
	}
}
