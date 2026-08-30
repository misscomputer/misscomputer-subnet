// SPDX-License-Identifier: AGPL-3.0-only

package edge

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	"github.com/misscomputer/misscomputer-subnet/pkg/tunnel"
)

type routeFixture struct {
	validatorPrivate ed25519.PrivateKey
	validatorPublic  ed25519.PublicKey
	minerPrivate     ed25519.PrivateKey
	minerPublic      ed25519.PublicKey
	ticket           protocol.Ticket
	receipt          protocol.Receipt
	registry         *tunnel.LocalRegistry
	backend          *httptest.Server
}

func newPinnedTLSServer(t *testing.T, handler http.Handler) (*httptest.Server, []byte) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "127.0.0.1"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	keyPair, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{keyPair}}
	server.StartTLS()
	return server, der
}

func newRouteFixture(t *testing.T, deploymentID string, generation uint64, nonce string) routeFixture {
	t.Helper()
	validatorPublic, validatorPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	minerPublic, minerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	ticket := protocol.Ticket{
		Version: protocol.Version, DeploymentID: deploymentID, Generation: generation, MinerID: "miner-a",
		ImageDigest: "sha256:image", ManifestKey: "v1/manifests/image.json", RouteHost: "edge-dev-" + deploymentID + ".miss.computer",
		AssignmentNonce: nonce, ChallengePath: "/challenge", ChallengeSHA256: protocol.ChallengeDigest("correct"),
		IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute),
	}
	if err := protocol.SignTicket(&ticket, validatorPrivate); err != nil {
		t.Fatal(err)
	}
	receipt := protocol.Receipt{
		Version: ticket.Version, DeploymentID: ticket.DeploymentID, Generation: ticket.Generation,
		AssignmentNonce: ticket.AssignmentNonce, MinerID: ticket.MinerID, ReplicaID: protocol.ReplicaID(ticket),
		EndpointID: protocol.EndpointID(ticket), ImageDigest: ticket.ImageDigest, ManifestKey: ticket.ManifestKey,
		RouteHost: ticket.RouteHost, Stage: protocol.StageReady,
	}
	if err := protocol.SignReceipt(&receipt, minerPrivate); err != nil {
		t.Fatal(err)
	}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get(TargetReplicaHeader) != "" || req.Header.Get(ProbeAuthorizationHeader) != "" {
			http.Error(w, "internal header leak", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("correct"))
	}))
	registry := tunnel.NewLocalRegistry()
	if err := registry.Register(protocol.EndpointID(ticket), backend.URL); err != nil {
		backend.Close()
		t.Fatal(err)
	}
	return routeFixture{
		validatorPrivate: validatorPrivate, validatorPublic: validatorPublic,
		minerPrivate: minerPrivate, minerPublic: minerPublic, ticket: ticket, receipt: receipt,
		registry: registry, backend: backend,
	}
}

func (f routeFixture) router(t *testing.T, config RouterConfig) *Router {
	t.Helper()
	config.AuthorityKey = f.validatorPublic
	config.Domain = "miss.computer"
	config.HostLabelPrefix = "edge-dev-"
	router, err := NewAuthorizedRouter(f.registry, "probe-token", config)
	if err != nil {
		t.Fatal(err)
	}
	return router
}

func TestSignedRouteLifecycleKeepsPendingReplicaOffPublicRotation(t *testing.T) {
	fixture := newRouteFixture(t, "app", 1, "nonce-a")
	defer fixture.backend.Close()
	router := fixture.router(t, RouterConfig{AllowPrivateUpstreams: true})
	if err := router.RegisterPending(context.Background(), fixture.ticket, fixture.receipt, fixture.minerPublic, fixture.validatorPrivate); err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "http://edge-dev-app.miss.computer/challenge", nil)
	public := httptest.NewRecorder()
	router.ServeHTTP(public, request)
	if public.Code != http.StatusServiceUnavailable {
		t.Fatalf("pending route was publicly eligible: %d", public.Code)
	}
	targetedRequest := httptest.NewRequest(http.MethodGet, "http://edge-dev-app.miss.computer/challenge", nil)
	targetedRequest.Header.Set(TargetReplicaHeader, fixture.receipt.ReplicaID)
	targetedRequest.Header.Set(ProbeAuthorizationHeader, "probe-token")
	targeted := httptest.NewRecorder()
	router.ServeHTTP(targeted, targetedRequest)
	if targeted.Code != http.StatusOK || targeted.Body.String() != "correct" {
		t.Fatalf("targeted pending probe status=%d body=%q", targeted.Code, targeted.Body.String())
	}
	if err := router.Activate(context.Background(), fixture.ticket, fixture.receipt, fixture.minerPublic, fixture.validatorPrivate); err != nil {
		t.Fatal(err)
	}
	public = httptest.NewRecorder()
	router.ServeHTTP(public, request)
	if public.Code != http.StatusOK || public.Body.String() != "correct" {
		t.Fatalf("active route status=%d body=%q", public.Code, public.Body.String())
	}
	if err := router.Deactivate(context.Background(), fixture.ticket, fixture.validatorPrivate); err != nil {
		t.Fatal(err)
	}
	if got := router.Replicas(fixture.ticket.RouteHost); len(got) != 0 {
		t.Fatalf("deactivated route remained published: %+v", got)
	}
}

func TestLiveRouterRejectsLegacyUnboundTicket(t *testing.T) {
	fixture := newRouteFixture(t, "legacy", 1, "legacy-nonce")
	defer fixture.backend.Close()
	router := fixture.router(t, RouterConfig{AllowPrivateUpstreams: true, RequireBoundTickets: true})
	if err := router.RegisterPending(context.Background(), fixture.ticket, fixture.receipt, fixture.minerPublic, fixture.validatorPrivate); err == nil {
		t.Fatal("live edge router accepted a legacy ticket without an authenticated transport pin")
	}
}

func TestBoundHTTPSRouteUsesExactPinnedLoopbackLeaf(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("NO_PROXY", "")
	fixture := newRouteFixture(t, "tlsapp", 1, "tls-nonce")
	fixture.backend.Close()
	fixture.registry.Unregister(fixture.receipt.EndpointID)
	tlsBackend, leafDER := newPinnedTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("pinned"))
	}))
	defer tlsBackend.Close()
	digest := sha256.Sum256(leafDER)
	pin := hex.EncodeToString(digest[:])
	fixture.ticket.Version = protocol.BoundVersion
	fixture.ticket.Subnet = &protocol.SubnetBinding{
		Network: "test", NetUID: 24, ValidatorHotkey: "validator", MinerHotkey: fixture.ticket.MinerID,
		MinerAxonURL: tlsBackend.URL, MinerTransport: "https", MinerTLSCertificateSHA256: &pin,
		ChainBlock: 100, ExpiresAtBlock: 112, ValidatorServicePublicKey: hex.EncodeToString(fixture.validatorPublic),
		MinerServicePublicKey: hex.EncodeToString(fixture.minerPublic),
	}
	if err := protocol.SignTicket(&fixture.ticket, fixture.validatorPrivate); err != nil {
		t.Fatal(err)
	}
	fixture.receipt.Version = fixture.ticket.Version
	fixture.receipt.Subnet = fixture.ticket.Subnet
	if err := protocol.SignReceipt(&fixture.receipt, fixture.minerPrivate); err != nil {
		t.Fatal(err)
	}
	target := tlsBackend.URL + "/runtime/" + protocol.EndpointID(fixture.ticket)
	if err := fixture.registry.RegisterPinned(protocol.EndpointID(fixture.ticket), target, leafDER, pin); err != nil {
		t.Fatal(err)
	}
	router := fixture.router(t, RouterConfig{AllowPrivateUpstreams: true, RequireEndpointPath: true})
	defer router.closeIdleConnections()
	if err := router.RegisterPending(context.Background(), fixture.ticket, fixture.receipt, fixture.minerPublic, fixture.validatorPrivate); err != nil {
		t.Fatalf("register pinned HTTPS route: %v", err)
	}
	if err := router.Activate(context.Background(), fixture.ticket, fixture.receipt, fixture.minerPublic, fixture.validatorPrivate); err != nil {
		t.Fatalf("activate pinned HTTPS route: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://"+fixture.ticket.RouteHost+"/", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "pinned" {
		t.Fatalf("pinned TLS proxy status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestBoundHTTPSRouteRejectsActiveRelayLeafBeforeRequestBody(t *testing.T) {
	fixture := newRouteFixture(t, "relay", 1, "relay-nonce")
	fixture.backend.Close()
	fixture.registry.Unregister(fixture.receipt.EndpointID)
	trusted, trustedDER := newPinnedTLSServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	trusted.Close()
	relay, _ := newPinnedTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("relay received workload request")
		w.WriteHeader(http.StatusOK)
	}))
	defer relay.Close()
	trustedDigest := sha256.Sum256(trustedDER)
	signedPin := hex.EncodeToString(trustedDigest[:])
	fixture.ticket.Version = protocol.BoundVersion
	fixture.ticket.Subnet = &protocol.SubnetBinding{
		Network: "test", NetUID: 24, ValidatorHotkey: "validator", MinerHotkey: fixture.ticket.MinerID,
		MinerAxonURL: relay.URL, MinerTransport: "https", MinerTLSCertificateSHA256: &signedPin,
		ChainBlock: 100, ExpiresAtBlock: 112, ValidatorServicePublicKey: hex.EncodeToString(fixture.validatorPublic),
		MinerServicePublicKey: hex.EncodeToString(fixture.minerPublic),
	}
	if err := protocol.SignTicket(&fixture.ticket, fixture.validatorPrivate); err != nil {
		t.Fatal(err)
	}
	fixture.receipt.Version = fixture.ticket.Version
	fixture.receipt.Subnet = fixture.ticket.Subnet
	if err := protocol.SignReceipt(&fixture.receipt, fixture.minerPrivate); err != nil {
		t.Fatal(err)
	}
	if err := fixture.registry.RegisterPinned(protocol.EndpointID(fixture.ticket), relay.URL+"/runtime/"+protocol.EndpointID(fixture.ticket), trustedDER, signedPin); err != nil {
		t.Fatal(err)
	}
	router := fixture.router(t, RouterConfig{AllowPrivateUpstreams: true, RequireEndpointPath: true})
	defer router.closeIdleConnections()
	if err := router.RegisterPending(context.Background(), fixture.ticket, fixture.receipt, fixture.minerPublic, fixture.validatorPrivate); err != nil {
		t.Fatalf("register route from accepted bootstrap metadata: %v", err)
	}
	if err := router.Activate(context.Background(), fixture.ticket, fixture.receipt, fixture.minerPublic, fixture.validatorPrivate); err != nil {
		t.Fatalf("activate route from accepted bootstrap metadata: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "http://"+fixture.ticket.RouteHost+"/workload", strings.NewReader("secret workload"))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusBadGateway {
		t.Fatalf("active relay certificate returned %d, want fail-closed 502", response.Code)
	}
}

func TestRouteUpdateRejectsReplayCrossIdentityAndStaleGeneration(t *testing.T) {
	fixture := newRouteFixture(t, "bound", 2, "nonce-new")
	defer fixture.backend.Close()
	router := fixture.router(t, RouterConfig{AllowPrivateUpstreams: true})
	update, err := NewRouteUpdate(RouteRegisterPending, fixture.ticket, &fixture.receipt, fixture.validatorPrivate, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := router.ApplyRouteUpdate(context.Background(), update, fixture.minerPublic); err != nil {
		t.Fatal(err)
	}
	if err := router.ApplyRouteUpdate(context.Background(), update, fixture.minerPublic); !errors.Is(err, ErrRouteReplay) {
		t.Fatalf("replay error = %v", err)
	}

	crossHost := fixture.ticket
	crossHost.RouteHost = "edge-dev-sibling.miss.computer"
	crossHost.AssignmentNonce = "cross-host"
	if err := protocol.SignTicket(&crossHost, fixture.validatorPrivate); err != nil {
		t.Fatal(err)
	}
	crossHostReceipt := fixture.receipt
	crossHostReceipt.RouteHost = crossHost.RouteHost
	crossHostReceipt.AssignmentNonce = crossHost.AssignmentNonce
	crossHostReceipt.EndpointID = protocol.EndpointID(crossHost)
	if err := protocol.SignReceipt(&crossHostReceipt, fixture.minerPrivate); err != nil {
		t.Fatal(err)
	}
	if err := fixture.registry.Register(crossHostReceipt.EndpointID, fixture.backend.URL); err != nil {
		t.Fatal(err)
	}
	if err := router.RegisterPending(context.Background(), crossHost, crossHostReceipt, fixture.minerPublic, fixture.validatorPrivate); err == nil {
		t.Fatal("cross-host route claim was accepted")
	}

	crossMinerReceipt := fixture.receipt
	crossMinerReceipt.MinerID = "miner-b"
	if err := protocol.SignReceipt(&crossMinerReceipt, fixture.minerPrivate); err != nil {
		t.Fatal(err)
	}
	if err := router.Activate(context.Background(), fixture.ticket, crossMinerReceipt, fixture.minerPublic, fixture.validatorPrivate); err == nil {
		t.Fatal("cross-miner route activation was accepted")
	}

	stale := fixture.ticket
	stale.Generation = 1
	stale.AssignmentNonce = "nonce-stale"
	if err := protocol.SignTicket(&stale, fixture.validatorPrivate); err != nil {
		t.Fatal(err)
	}
	staleReceipt := fixture.receipt
	staleReceipt.Generation = stale.Generation
	staleReceipt.AssignmentNonce = stale.AssignmentNonce
	staleReceipt.EndpointID = protocol.EndpointID(stale)
	if err := protocol.SignReceipt(&staleReceipt, fixture.minerPrivate); err != nil {
		t.Fatal(err)
	}
	if err := fixture.registry.Register(staleReceipt.EndpointID, fixture.backend.URL); err != nil {
		t.Fatal(err)
	}
	if err := router.RegisterPending(context.Background(), stale, staleReceipt, fixture.minerPublic, fixture.validatorPrivate); !errors.Is(err, ErrStaleRoute) {
		t.Fatalf("stale generation error = %v", err)
	}
}

func TestFailedRouteTransitionDoesNotConsumeSignedUpdate(t *testing.T) {
	fixture := newRouteFixture(t, "retry", 1, "nonce-retry")
	defer fixture.backend.Close()
	router := fixture.router(t, RouterConfig{AllowPrivateUpstreams: true})
	activation, err := NewRouteUpdate(RouteActivate, fixture.ticket, &fixture.receipt, fixture.validatorPrivate, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := router.ApplyRouteUpdate(context.Background(), activation, fixture.minerPublic); err == nil || errors.Is(err, ErrRouteReplay) {
		t.Fatalf("activation without pending route error = %v", err)
	}
	if err := router.RegisterPending(context.Background(), fixture.ticket, fixture.receipt, fixture.minerPublic, fixture.validatorPrivate); err != nil {
		t.Fatal(err)
	}
	if err := router.ApplyRouteUpdate(context.Background(), activation, fixture.minerPublic); err != nil {
		t.Fatalf("valid retry of previously failed transition = %v", err)
	}
	if err := router.ApplyRouteUpdate(context.Background(), activation, fixture.minerPublic); !errors.Is(err, ErrRouteReplay) {
		t.Fatalf("successful update replay error = %v", err)
	}
}

func TestConcurrentIdenticalRouteUpdateHasOneWinner(t *testing.T) {
	fixture := newRouteFixture(t, "concurrent", 1, "nonce-concurrent")
	defer fixture.backend.Close()
	router := fixture.router(t, RouterConfig{AllowPrivateUpstreams: true})
	update, err := NewRouteUpdate(RouteRegisterPending, fixture.ticket, &fixture.receipt, fixture.validatorPrivate, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	const contenders = 32
	start := make(chan struct{})
	results := make(chan error, contenders)
	var workers sync.WaitGroup
	for range contenders {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			results <- router.ApplyRouteUpdate(context.Background(), update, fixture.minerPublic)
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	succeeded, replayed := 0, 0
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrRouteReplay):
			replayed++
		default:
			t.Fatalf("concurrent update failed with non-replay error: %v", err)
		}
	}
	if succeeded != 1 || replayed != contenders-1 {
		t.Fatalf("concurrent outcomes: succeeded=%d replayed=%d", succeeded, replayed)
	}
}

func TestRouteRegistrationRejectsSSRFAndUnboundEndpointPath(t *testing.T) {
	fixture := newRouteFixture(t, "ssrf", 1, "nonce-ssrf")
	defer fixture.backend.Close()
	publicOnly := fixture.router(t, RouterConfig{})
	if err := publicOnly.RegisterPending(context.Background(), fixture.ticket, fixture.receipt, fixture.minerPublic, fixture.validatorPrivate); err == nil {
		t.Fatal("loopback upstream was accepted by production policy")
	}

	pathBound := fixture.router(t, RouterConfig{AllowPrivateUpstreams: true, RequireEndpointPath: true})
	if err := pathBound.RegisterPending(context.Background(), fixture.ticket, fixture.receipt, fixture.minerPublic, fixture.validatorPrivate); err == nil {
		t.Fatal("upstream URL not bound to endpoint path was accepted")
	}
}

func TestExplicitLocalPolicyAllowsMockDNSUpstream(t *testing.T) {
	fixture := newRouteFixture(t, "mockdns", 1, "nonce-mockdns")
	defer fixture.backend.Close()
	fixture.registry.Unregister(fixture.receipt.EndpointID)
	if err := fixture.registry.Register(fixture.receipt.EndpointID, "http://miner-1:8091"); err != nil {
		t.Fatal(err)
	}
	router := fixture.router(t, RouterConfig{AllowPrivateUpstreams: true})
	if err := router.RegisterPending(context.Background(), fixture.ticket, fixture.receipt, fixture.minerPublic, fixture.validatorPrivate); err != nil {
		t.Fatalf("explicit mock DNS policy was rejected: %v", err)
	}
}

func TestAuthoritativeDeactivationWorksAfterTicketExpiry(t *testing.T) {
	fixture := newRouteFixture(t, "expiry", 1, "nonce-expiry")
	defer fixture.backend.Close()
	fixture.ticket.ExpiresAt = time.Now().UTC().Add(150 * time.Millisecond)
	if err := protocol.SignTicket(&fixture.ticket, fixture.validatorPrivate); err != nil {
		t.Fatal(err)
	}
	fixture.receipt.EndpointID = protocol.EndpointID(fixture.ticket)
	if err := protocol.SignReceipt(&fixture.receipt, fixture.minerPrivate); err != nil {
		t.Fatal(err)
	}
	router := fixture.router(t, RouterConfig{AllowPrivateUpstreams: true})
	if err := router.RegisterPending(context.Background(), fixture.ticket, fixture.receipt, fixture.minerPublic, fixture.validatorPrivate); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if err := router.Deactivate(context.Background(), fixture.ticket, fixture.validatorPrivate); err != nil {
		t.Fatalf("expired exact ticket could not deactivate route: %v", err)
	}
}
