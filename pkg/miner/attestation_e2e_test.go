// SPDX-License-Identifier: AGPL-3.0-only

package miner

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
	"github.com/misscomputer/misscomputer-subnet/pkg/durable"
	"github.com/misscomputer/misscomputer-subnet/pkg/edge"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	deployruntime "github.com/misscomputer/misscomputer-subnet/pkg/runtime"
	"github.com/misscomputer/misscomputer-subnet/pkg/tunnel"
	"github.com/misscomputer/misscomputer-subnet/pkg/workload"
)

// axonHost mimics the public miner axon surface in front of the Go agent: the
// edge reaches /runtime/{endpoint}/... and the runtime proxy sees the
// rewritten workload path, exactly as cmd/miner-agent serves it behind the
// Python neuron passthrough.
type axonHost struct {
	agent *Agent
}

func (h *axonHost) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /runtime/{endpoint}/{path...}", func(w http.ResponseWriter, req *http.Request) {
		endpointID := req.PathValue("endpoint")
		req.URL.Path = "/" + req.PathValue("path")
		req.URL.RawPath = ""
		h.agent.ProxyRuntime(w, req, endpointID)
	})
	return mux
}

// TestEdgeRoundRobinProbeAttributesActualResponder drives the real public
// path — edge router round-robin over three healthy bound replicas, each
// served through its own miner runtime proxy — and requires every probe
// response to carry exactly one verifiable attestation naming the replica
// that actually answered, while the edge's no-cache and internal
// targeted-probe boundaries stay intact.
func TestEdgeRoundRobinProbeAttributesActualResponder(t *testing.T) {
	ctx := context.Background()
	validatorPublic, validatorPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spec, layer, err := workload.Generate("static", 1024)
	if err != nil {
		t.Fatal(err)
	}
	probeToken := "internal-probe-token"
	edgeTunnels := tunnel.NewLocalRegistry()
	router, err := edge.NewAuthorizedRouter(edgeTunnels, probeToken, edge.RouterConfig{
		AuthorityKey: validatorPublic, Domain: "mock.local", AllowPrivateUpstreams: true,
		AllowInsecureMockHTTP: true, RequireBoundTickets: true, RequireEndpointPath: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	edgeServer := httptest.NewServer(router)
	defer edgeServer.Close()

	routeHost := "probe-deploy.mock.local"
	endpointKeys := make(map[string]ed25519.PublicKey, 3)
	endpointReplicas := make(map[string]string, 3)
	assigned := make([]string, 0, 3)
	for index, hotkey := range []string{"MinerRoundA", "MinerRoundB", "MinerRoundC"} {
		minerPublic, minerPrivate, keyErr := ed25519.GenerateKey(rand.Reader)
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		host := &axonHost{}
		axonServer := httptest.NewServer(host.handler())
		defer axonServer.Close()
		store := artifact.FileStore{Root: t.TempDir()}
		manifest, publishErr := artifact.Publish(ctx, store, spec.Kind, [][]byte{layer}, nil)
		if publishErr != nil {
			t.Fatal(publishErr)
		}
		uid := uint16(30 + index)
		ticket := protocol.Ticket{
			Version: protocol.BoundVersion, DeploymentID: "probe-deploy", Generation: 1,
			ImageDigest: manifest.ImageDigest, ManifestKey: artifact.ManifestKey(manifest.ImageDigest),
			MinerID: hotkey, RouteHost: routeHost,
			AssignmentNonce: fmt.Sprintf("%032x", 0x1000+index),
			ChallengePath:   spec.ChallengePath, ChallengeSHA256: protocol.ChallengeDigest(spec.ChallengeValue),
			Health:   protocol.HealthSpec{Path: "/healthz", ExpectedStatus: http.StatusOK, IntervalMillis: 1, TimeoutMillis: 30_000},
			IssuedAt: time.Now().Add(-time.Second).UTC(), ExpiresAt: time.Now().Add(time.Minute).UTC(),
			Subnet: &protocol.SubnetBinding{
				Network: "mock", NetUID: 24, ValidatorHotkey: "ValidatorHot", MinerHotkey: hotkey, MinerUID: &uid,
				MinerAxonURL: axonServer.URL, MinerTransport: "http",
				ChainBlock: 100, Epoch: 1, ExpiresAtBlock: 200,
				ValidatorServicePublicKey: hex.EncodeToString(validatorPublic),
				MinerServicePublicKey:     hex.EncodeToString(minerPublic),
			},
		}
		if signErr := protocol.SignTicket(&ticket, validatorPrivate); signErr != nil {
			t.Fatal(signErr)
		}
		state, openErr := durable.Open(filepath.Join(t.TempDir(), "state.db"))
		if openErr != nil {
			t.Fatal(openErr)
		}
		defer state.Close()
		agent := NewAgent(hotkey, validatorPublic, minerPrivate, store, deployruntime.NewLocalRuntime(), tunnel.NewLocalRegistry())
		agent.State = state
		agent.MinerTransport = "http"
		result, assignErr := agent.AssignBound(ctx, ticket, validatorPublic, 100, "mock", 24, "ValidatorHot", hotkey, &uid)
		if assignErr != nil {
			t.Fatal(assignErr)
		}
		host.agent = agent
		if registerErr := edgeTunnels.Register(result.EndpointID, axonServer.URL+"/runtime/"+result.EndpointID); registerErr != nil {
			t.Fatal(registerErr)
		}
		if routeErr := router.RegisterPending(ctx, ticket, result.Receipt, minerPublic, validatorPrivate); routeErr != nil {
			t.Fatal(routeErr)
		}
		if routeErr := router.Activate(ctx, ticket, result.Receipt, minerPublic, validatorPrivate); routeErr != nil {
			t.Fatal(routeErr)
		}
		endpointKeys[result.EndpointID] = minerPublic
		endpointReplicas[result.EndpointID] = protocol.ReplicaID(ticket)
		assigned = append(assigned, result.EndpointID)
	}

	client := edgeServer.Client()
	responders := make(map[string]bool, 3)
	for round := range 3 {
		nonce := fmt.Sprintf("%064x", 0xf00d+round)
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, edgeServer.URL+spec.ChallengePath, nil)
		if reqErr != nil {
			t.Fatal(reqErr)
		}
		req.Host = routeHost
		req.Header.Set(protocol.ProbeNonceHeader, nonce)
		req.Header.Set("Cache-Control", "no-cache")
		response, doErr := client.Do(req)
		if doErr != nil {
			t.Fatal(doErr)
		}
		body, readErr := io.ReadAll(response.Body)
		response.Body.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		if response.StatusCode != http.StatusOK || string(body) != spec.ChallengeValue {
			t.Fatalf("round %d probe failed: status %d body %q", round, response.StatusCode, body)
		}
		if got := response.Header.Get("Cache-Control"); got != "private, no-store" {
			t.Fatalf("edge no-cache boundary broke: %q", got)
		}
		if got := response.Header.Get("X-Build-ID"); got != spec.BuildID {
			t.Fatalf("build header broke: %q", got)
		}
		values := response.Header.Values(protocol.ProbeAttestationHeader)
		if len(values) != 1 {
			t.Fatalf("round %d carried %d attestation headers", round, len(values))
		}
		attestation, decodeErr := protocol.DecodeProbeAttestationHeader(values[0])
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		key, known := endpointKeys[attestation.EndpointID]
		if !known {
			t.Fatalf("round %d attested unknown endpoint %q", round, attestation.EndpointID)
		}
		if verifyErr := protocol.VerifyProbeAttestation(attestation, key); verifyErr != nil {
			t.Fatal(verifyErr)
		}
		if attestation.ProbeNonce != nonce || attestation.RouteHost != routeHost {
			t.Fatalf("round %d attestation binding mismatch: %+v", round, attestation)
		}
		responders[attestation.EndpointID] = true
	}
	if len(responders) != 3 {
		t.Fatalf("round-robin probes attributed %d distinct replicas, want 3: %v", len(responders), responders)
	}
	for _, endpointID := range assigned {
		if !responders[endpointID] {
			t.Fatalf("replica %s was never attributed", endpointID)
		}
	}

	// The credentialed internal targeted probe stays authorized, exact, and
	// attestation-free, and its token boundary still fails closed.
	targeted, err := http.NewRequestWithContext(ctx, http.MethodGet, edgeServer.URL+spec.ChallengePath, nil)
	if err != nil {
		t.Fatal(err)
	}
	targeted.Host = routeHost
	targeted.Header.Set(edge.TargetReplicaHeader, endpointReplicas[assigned[0]])
	targeted.Header.Set(edge.ProbeAuthorizationHeader, probeToken)
	targetedResponse, err := client.Do(targeted)
	if err != nil {
		t.Fatal(err)
	}
	targetedBody, err := io.ReadAll(targetedResponse.Body)
	targetedResponse.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if targetedResponse.StatusCode != http.StatusOK || string(targetedBody) != spec.ChallengeValue {
		t.Fatalf("targeted internal probe broke: %d %q", targetedResponse.StatusCode, targetedBody)
	}
	if targetedResponse.Header.Get(protocol.ProbeAttestationHeader) != "" {
		t.Fatal("nonce-free targeted probe unexpectedly carried an attestation")
	}
	forbidden, err := http.NewRequestWithContext(ctx, http.MethodGet, edgeServer.URL+spec.ChallengePath, nil)
	if err != nil {
		t.Fatal(err)
	}
	forbidden.Host = routeHost
	forbidden.Header.Set(edge.TargetReplicaHeader, endpointReplicas[assigned[0]])
	forbidden.Header.Set(edge.ProbeAuthorizationHeader, "wrong-token")
	forbiddenResponse, err := client.Do(forbidden)
	if err != nil {
		t.Fatal(err)
	}
	forbiddenResponse.Body.Close()
	if forbiddenResponse.StatusCode != http.StatusForbidden {
		t.Fatalf("targeted probe without the credential returned %d, want 403", forbiddenResponse.StatusCode)
	}
}
