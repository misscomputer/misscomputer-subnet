// SPDX-License-Identifier: AGPL-3.0-only

package edge

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	"github.com/misscomputer/misscomputer-subnet/pkg/tunnel"
)

const (
	TargetReplicaHeader      = "X-Miss-Target-Replica"
	ProbeAuthorizationHeader = "X-Miss-Internal-Probe-Token"
)

var errResponseTooLarge = errors.New("edge upstream response exceeds configured limit")

// GenerateProbeToken returns an unpredictable control-plane credential. It is
// intentionally unrelated to deployment manifests, build IDs, and workload
// configuration, all of which are visible to miners.
func GenerateProbeToken() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

type Replica struct {
	ID         string `json:"id"`
	MinerID    string `json:"miner_id"`
	EndpointID string `json:"endpoint_id"`
	Healthy    bool   `json:"healthy"`
}

type routeClaim struct {
	replica   Replica
	record    RouteRecord
	ticket    protocol.Ticket
	receipt   protocol.Receipt
	target    *url.URL
	transport http.RoundTripper
}

type Router struct {
	tunnels     tunnel.Registry
	probeToken  string
	config      RouterConfig
	authority   ed25519.PublicKey
	store       RouteStateStore
	transport   http.RoundTripper
	mu          sync.RWMutex
	routes      map[string][]routeClaim
	claims      map[string]routeClaim
	history     map[string]RouteRecord
	maxGen      map[string]uint64
	hostOwners  map[string]string
	seenUpdates map[string]time.Time
	next        atomic.Uint64
}

// NewRouter is retained only for isolated adapter tests that do not exercise
// the scheduler. Production and scheduler code must use NewAuthorizedRouter;
// this constructor exposes no exported route mutation methods.
func NewRouter(tunnels tunnel.Registry, probeToken string) *Router {
	config := defaultRouterConfig(RouterConfig{AllowPrivateUpstreams: true})
	return newRouter(tunnels, probeToken, config)
}

// NewAuthorizedRouter creates a fail-closed route authority. Persisted active
// or pending routes are quarantined before the returned handler can serve, so
// a restart never silently republishes an unprobed incarnation.
func NewAuthorizedRouter(tunnels tunnel.Registry, probeToken string, config RouterConfig) (*Router, error) {
	if tunnels == nil {
		return nil, errors.New("edge tunnel registry is required")
	}
	if len(config.AuthorityKey) != ed25519.PublicKeySize {
		return nil, errors.New("edge route authority public key is required")
	}
	domain, err := validateDomain(config.Domain)
	if err != nil {
		return nil, err
	}
	config.Domain = domain
	if config.HostLabelPrefix != "" {
		if strings.ToLower(config.HostLabelPrefix) != config.HostLabelPrefix || strings.HasPrefix(config.HostLabelPrefix, "-") {
			return nil, errors.New("edge route label prefix must be lowercase and cannot begin with a hyphen")
		}
		for _, character := range config.HostLabelPrefix {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return nil, errors.New("edge route label prefix contains invalid characters")
			}
		}
	}
	config = defaultRouterConfig(config)
	if config.Store != nil {
		if err := config.Store.QuarantineEdgeRoutes(context.Background()); err != nil {
			return nil, fmt.Errorf("quarantine persisted edge routes: %w", err)
		}
	}
	return newRouter(tunnels, probeToken, config), nil
}

func defaultRouterConfig(config RouterConfig) RouterConfig {
	if config.ResponseHeaderTimeout <= 0 {
		config.ResponseHeaderTimeout = 15 * time.Second
	}
	if config.DialTimeout <= 0 {
		config.DialTimeout = 5 * time.Second
	}
	if config.TLSHandshakeTimeout <= 0 {
		config.TLSHandshakeTimeout = 5 * time.Second
	}
	if config.MaxResponseBytes <= 0 {
		config.MaxResponseBytes = 64 << 20
	}
	return config
}

func newRouter(tunnels tunnel.Registry, probeToken string, config RouterConfig) *Router {
	dialer := &net.Dialer{Timeout: config.DialTimeout, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy: nil, DialContext: dialer.DialContext, ForceAttemptHTTP2: true,
		MaxIdleConns: 128, MaxIdleConnsPerHost: 16, IdleConnTimeout: 60 * time.Second,
		TLSHandshakeTimeout: config.TLSHandshakeTimeout, ResponseHeaderTimeout: config.ResponseHeaderTimeout,
		ExpectContinueTimeout: time.Second,
	}
	return &Router{
		tunnels: tunnels, probeToken: probeToken, config: config,
		authority: append(ed25519.PublicKey(nil), config.AuthorityKey...), store: config.Store, transport: transport,
		routes: make(map[string][]routeClaim), claims: make(map[string]routeClaim), history: make(map[string]RouteRecord),
		maxGen: make(map[string]uint64), hostOwners: make(map[string]string), seenUpdates: make(map[string]time.Time),
	}
}

func (r *Router) IsAuthorizedFor(key ed25519.PublicKey) bool {
	return len(r.authority) == ed25519.PublicKeySize && len(key) == ed25519.PublicKeySize && subtle.ConstantTimeCompare(r.authority, key) == 1
}

// HighestGeneration reports the highest route generation this authority has
// observed for one deployment across every miner, consulting both in-memory
// monotonic state and the durable store. A new incarnation of a previously
// deactivated deployment ID must issue strictly higher generations, because
// reusing a consumed generation is indistinguishable from a stale replay and
// fails closed at registration.
func (r *Router) HighestGeneration(ctx context.Context, deploymentID string) (uint64, error) {
	var maximum uint64
	if r.store != nil {
		persisted, err := r.store.HighestEdgeGeneration(ctx, deploymentID)
		if err != nil {
			return 0, fmt.Errorf("load persisted edge route generation: %w", err)
		}
		maximum = persisted
	}
	prefix := deploymentID + "\x00"
	r.mu.RLock()
	defer r.mu.RUnlock()
	for key, generation := range r.maxGen {
		if strings.HasPrefix(key, prefix) && generation > maximum {
			maximum = generation
		}
	}
	return maximum, nil
}

func (r *Router) RegisterPending(ctx context.Context, ticket protocol.Ticket, receipt protocol.Receipt, minerKey ed25519.PublicKey, key ed25519.PrivateKey) error {
	update, err := NewRouteUpdate(RouteRegisterPending, ticket, &receipt, key, time.Now().UTC())
	if err != nil {
		return err
	}
	return r.ApplyRouteUpdate(ctx, update, minerKey)
}

func (r *Router) Activate(ctx context.Context, ticket protocol.Ticket, receipt protocol.Receipt, minerKey ed25519.PublicKey, key ed25519.PrivateKey) error {
	update, err := NewRouteUpdate(RouteActivate, ticket, &receipt, key, time.Now().UTC())
	if err != nil {
		return err
	}
	return r.ApplyRouteUpdate(ctx, update, minerKey)
}

func (r *Router) Deactivate(ctx context.Context, ticket protocol.Ticket, key ed25519.PrivateKey) error {
	update, err := NewRouteUpdate(RouteDeactivate, ticket, nil, key, time.Now().UTC())
	if err != nil {
		return err
	}
	return r.ApplyRouteUpdate(ctx, update, nil)
}

// ApplyRouteUpdate verifies both service signatures, exact ticket/receipt
// identity, route namespace, monotonic generation, replay state, and the
// control-derived upstream before changing the serving table.
func (r *Router) ApplyRouteUpdate(ctx context.Context, update RouteUpdate, minerKey ed25519.PublicKey) error {
	if len(r.authority) != ed25519.PublicKeySize {
		return errors.New("edge router has no route authority")
	}
	if r.config.RequireBoundTickets && (update.Ticket.Version != protocol.BoundVersion || update.Ticket.Subnet == nil) {
		return errors.New("edge router requires a current transport-bound ticket")
	}
	now := time.Now().UTC()
	if err := verifyRouteUpdate(update, r.authority, now); err != nil {
		return err
	}
	expectedHost, err := expectedRouteHost(update.DeploymentID, r.config.Domain, r.config.HostLabelPrefix)
	if err != nil || update.RouteHost != expectedHost {
		return errors.New("edge route host is outside the configured exact deployment namespace")
	}
	var target *url.URL
	var routeTransport http.RoundTripper
	if update.Action != RouteDeactivate {
		if err := verifyReadyReceipt(update.Ticket, update.Receipt, minerKey); err != nil {
			return err
		}
		target, routeTransport, err = r.resolveBoundTarget(update)
		if err != nil {
			return err
		}
		if err := validateUpstream(target, update.EndpointID, r.config); err != nil {
			return fmt.Errorf("reject unsafe edge upstream: %w", err)
		}
	}
	recordState := "pending"
	if update.Action == RouteActivate {
		recordState = "active"
	} else if update.Action == RouteDeactivate {
		recordState = "deactivated"
	}
	record, err := routeRecord(update, recordState)
	if err != nil {
		return err
	}
	replayKey := routeUpdateReplayKey(update)

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.store == nil {
		for key, expires := range r.seenUpdates {
			if !expires.After(now) {
				delete(r.seenUpdates, key)
			}
		}
		if _, exists := r.seenUpdates[replayKey]; exists {
			return ErrRouteReplay
		}
	}
	if err := r.validateTransitionLocked(update, record); err != nil {
		return err
	}
	if r.store != nil {
		var committed bool
		committed, err = r.store.ApplyEdgeRouteTransition(ctx, "edge-route-update", replayKey, update.ExpiresAt, record)
		if err != nil {
			return fmt.Errorf("persist edge route transition: %w", err)
		}
		if !committed {
			return ErrRouteReplay
		}
	} else {
		// Reserve only after transition validation has succeeded. The lock keeps
		// validation, reservation, and the in-memory mutation one atomic step.
		r.seenUpdates[replayKey] = update.ExpiresAt
	}
	r.applyTransitionLocked(update, record, target, routeTransport)
	return nil
}

func (r *Router) validateTransitionLocked(update RouteUpdate, record RouteRecord) error {
	generationKey := update.DeploymentID + "\x00" + update.MinerID
	if maximum := r.maxGen[generationKey]; update.Generation < maximum {
		return ErrStaleRoute
	}
	if owner := r.hostOwners[update.RouteHost]; owner != "" && owner != update.DeploymentID {
		return errors.New("edge route host is already owned by another deployment")
	}
	existing, exists := r.history[update.EndpointID]
	if exists && !sameRouteIdentity(existing, record) {
		return errors.New("edge endpoint identity conflicts with another exact signed ticket")
	}
	switch update.Action {
	case RouteRegisterPending:
		if exists && existing.State == "deactivated" {
			return errors.New("deactivated edge incarnation cannot be republished")
		}
		if exists && len(existing.ReceiptJSON) > 0 && !bytes.Equal(existing.ReceiptJSON, record.ReceiptJSON) {
			return errors.New("edge route receipt conflicts with the exact registered receipt")
		}
		if maximum := r.maxGen[generationKey]; update.Generation == maximum && (!exists || existing.EndpointID != update.EndpointID) {
			return ErrStaleRoute
		}
	case RouteActivate:
		claim, found := r.claims[update.EndpointID]
		if !found || !sameRouteIdentity(claim.record, record) || !bytes.Equal(claim.record.ReceiptJSON, record.ReceiptJSON) || claim.record.State != "pending" {
			return errors.New("only the exact pending edge incarnation can be activated")
		}
	case RouteDeactivate:
		// An authoritative tombstone is valid even before registration. This
		// closes the late-success window after scheduler cancellation.
	}
	return nil
}

func (r *Router) applyTransitionLocked(update RouteUpdate, record RouteRecord, target *url.URL, routeTransport http.RoundTripper) {
	generationKey := update.DeploymentID + "\x00" + update.MinerID
	if update.Generation > r.maxGen[generationKey] {
		r.maxGen[generationKey] = update.Generation
	}
	r.hostOwners[update.RouteHost] = update.DeploymentID
	switch update.Action {
	case RouteRegisterPending:
		copyTarget := *target
		claim := routeClaim{
			replica: Replica{ID: update.ReplicaID, MinerID: update.MinerID, EndpointID: update.EndpointID}, record: record,
			ticket: cloneTicket(update.Ticket), receipt: cloneReceipt(*update.Receipt), target: &copyTarget, transport: routeTransport,
		}
		r.claims[update.EndpointID] = claim
		r.history[update.EndpointID] = record
		r.upsertRouteLocked(update.RouteHost, claim)
	case RouteActivate:
		claim := r.claims[update.EndpointID]
		if target != nil {
			copyTarget := *target
			claim.target = &copyTarget
		}
		if routeTransport != nil {
			closeTransport(claim.transport)
			claim.transport = routeTransport
		}
		claim.replica.Healthy = true
		claim.record.State = "active"
		r.claims[update.EndpointID] = claim
		r.history[update.EndpointID] = claim.record
		r.upsertRouteLocked(update.RouteHost, claim)
	case RouteDeactivate:
		if claim, exists := r.claims[update.EndpointID]; exists {
			closeTransport(claim.transport)
		}
		delete(r.claims, update.EndpointID)
		r.removeRouteLocked(update.RouteHost, update.EndpointID)
		if existing, exists := r.history[update.EndpointID]; exists {
			existing.State = "deactivated"
			r.history[update.EndpointID] = existing
		} else {
			r.history[update.EndpointID] = record
		}
	}
}

func cloneTicket(ticket protocol.Ticket) protocol.Ticket {
	copyTicket := ticket
	copyTicket.Subnet = cloneSubnetBinding(ticket.Subnet)
	return copyTicket
}

func cloneReceipt(receipt protocol.Receipt) protocol.Receipt {
	copyReceipt := receipt
	copyReceipt.Subnet = cloneSubnetBinding(receipt.Subnet)
	return copyReceipt
}

func cloneSubnetBinding(binding *protocol.SubnetBinding) *protocol.SubnetBinding {
	if binding == nil {
		return nil
	}
	copyBinding := *binding
	if binding.MinerUID != nil {
		uid := *binding.MinerUID
		copyBinding.MinerUID = &uid
	}
	if binding.MinerTLSCertificateSHA256 != nil {
		pin := *binding.MinerTLSCertificateSHA256
		copyBinding.MinerTLSCertificateSHA256 = &pin
	}
	return &copyBinding
}

func (r *Router) resolveBoundTarget(update RouteUpdate) (*url.URL, http.RoundTripper, error) {
	binding := update.Ticket.Subnet
	if binding == nil {
		target, err := r.tunnels.Resolve(update.EndpointID)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve controlled edge upstream: %w", err)
		}
		return target, r.transport, nil
	}
	expected := binding.MinerAxonURL + "/runtime/" + url.PathEscape(update.EndpointID)
	switch binding.MinerTransport {
	case "https":
		if binding.MinerTLSCertificateSHA256 == nil {
			return nil, nil, errors.New("HTTPS edge route lacks a signed certificate pin")
		}
		registry, ok := r.tunnels.(tunnel.PinnedRegistry)
		if !ok {
			return nil, nil, errors.New("edge tunnel registry cannot resolve pinned TLS metadata")
		}
		pinned, err := registry.ResolvePinned(update.EndpointID)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve controlled pinned edge upstream: %w", err)
		}
		if pinned.URL != nil {
			urlCopy := *pinned.URL
			pinned.URL = &urlCopy
		}
		pinned.CertificateDER = append([]byte(nil), pinned.CertificateDER...)
		if pinned.URL == nil || pinned.URL.String() != expected || pinned.URL.Scheme != "https" ||
			pinned.CertificateSHA256 != *binding.MinerTLSCertificateSHA256 {
			return nil, nil, errors.New("edge upstream does not match the exact signed HTTPS transport identity")
		}
		transport, err := r.pinnedTransport(pinned)
		if err != nil {
			return nil, nil, err
		}
		return pinned.URL, transport, nil
	case "http":
		if !r.config.AllowInsecureMockHTTP || binding.MinerTLSCertificateSHA256 != nil {
			return nil, nil, errors.New("pinless HTTP edge upstream is disabled outside explicit mock mode")
		}
		target, err := r.tunnels.Resolve(update.EndpointID)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve controlled edge upstream: %w", err)
		}
		if target.Scheme != "http" || target.String() != expected {
			return nil, nil, errors.New("mock HTTP upstream does not match the exact signed transport identity")
		}
		return target, r.transport, nil
	default:
		return nil, nil, errors.New("edge route has an unsupported miner transport")
	}
}

func (r *Router) pinnedTransport(target tunnel.PinnedTarget) (*http.Transport, error) {
	if target.URL == nil || target.URL.Scheme != "https" || target.CertificateSHA256 == "" {
		return nil, errors.New("pinned HTTPS edge target is incomplete")
	}
	certificate, err := tunnel.ValidatePinnedCertificate(target.CertificateDER, target.CertificateSHA256, time.Now().UTC())
	if err != nil {
		return nil, fmt.Errorf("validate pinned edge certificate: %w", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	pin := target.CertificateSHA256
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    roots,
		ServerName: target.URL.Hostname(),
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("TLS peer did not present a leaf certificate")
			}
			peerDigest := sha256.Sum256(state.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(peerDigest[:])), []byte(pin)) != 1 {
				return errors.New("TLS peer leaf certificate does not match the signed pin")
			}
			return nil
		},
	}
	dialer := &net.Dialer{Timeout: r.config.DialTimeout, KeepAlive: 30 * time.Second}
	return &http.Transport{
		Proxy: nil, DialContext: dialer.DialContext, ForceAttemptHTTP2: true, TLSClientConfig: tlsConfig,
		MaxIdleConns: 16, MaxIdleConnsPerHost: 8, IdleConnTimeout: 60 * time.Second,
		TLSHandshakeTimeout: r.config.TLSHandshakeTimeout, ResponseHeaderTimeout: r.config.ResponseHeaderTimeout,
		ExpectContinueTimeout: time.Second,
	}, nil
}

func closeTransport(roundTripper http.RoundTripper) {
	if transport, ok := roundTripper.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
}

func (r *Router) upsertRouteLocked(host string, claim routeClaim) {
	current := r.routes[host]
	for index := range current {
		if current[index].replica.EndpointID == claim.replica.EndpointID {
			current[index] = claim
			r.routes[host] = current
			return
		}
	}
	r.routes[host] = append(current, claim)
}

func (r *Router) removeRouteLocked(host, endpointID string) {
	current := r.routes[host]
	filtered := current[:0]
	for _, claim := range current {
		if claim.replica.EndpointID != endpointID {
			filtered = append(filtered, claim)
		}
	}
	if len(filtered) == 0 {
		delete(r.routes, host)
		return
	}
	r.routes[host] = filtered
}

func (r *Router) Replicas(host string) []Replica {
	r.mu.RLock()
	defer r.mu.RUnlock()
	claims := r.routes[strings.ToLower(host)]
	values := make([]Replica, 0, len(claims))
	for _, claim := range claims {
		values = append(values, claim.replica)
	}
	return values
}

// TicketFor returns the already-verified signed ticket only when every caller
// identity names the same current or exactly tombstoned incarnation. Retaining
// an exact tombstone makes legacy repeated health removal safely idempotent;
// another incarnation, route, replica, or miner still fails closed.
func (r *Router) TicketFor(routeHost, replicaID, endpointID, minerID string) (protocol.Ticket, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	claim, exists := r.claims[endpointID]
	if exists {
		if claim.record.RouteHost != routeHost || claim.record.ReplicaID != replicaID || claim.record.MinerID != minerID {
			return protocol.Ticket{}, false
		}
		return claim.ticket, true
	}
	record, exists := r.history[endpointID]
	if !exists || record.State != "deactivated" || record.RouteHost != routeHost || record.ReplicaID != replicaID || record.MinerID != minerID {
		return protocol.Ticket{}, false
	}
	var ticket protocol.Ticket
	if err := json.Unmarshal(record.TicketJSON, &ticket); err != nil {
		return protocol.Ticket{}, false
	}
	return ticket, true
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	host := stripPort(req.Host)
	if len(r.authority) == ed25519.PublicKeySize {
		canonical, err := canonicalDeploymentHost(req.Host, r.config.Domain, r.config.HostLabelPrefix)
		if err != nil {
			http.Error(w, "invalid deployment host", http.StatusMisdirectedRequest)
			return
		}
		host = canonical
	}
	r.mu.RLock()
	replicas := append([]routeClaim(nil), r.routes[host]...)
	r.mu.RUnlock()
	if targetID := req.Header.Get(TargetReplicaHeader); targetID != "" {
		provided := req.Header.Get(ProbeAuthorizationHeader)
		if r.probeToken == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(r.probeToken)) != 1 {
			http.Error(w, "targeted probe forbidden", http.StatusForbidden)
			return
		}
		for _, replica := range replicas {
			if replica.replica.ID == targetID {
				r.proxy(w, req, replica)
				return
			}
		}
		http.Error(w, "target replica not found", http.StatusNotFound)
		return
	}
	healthy := replicas[:0]
	for _, replica := range replicas {
		if replica.replica.Healthy {
			healthy = append(healthy, replica)
		}
	}
	if len(healthy) == 0 {
		http.Error(w, "no healthy replicas", http.StatusServiceUnavailable)
		return
	}
	replica := healthy[(r.next.Add(1)-1)%uint64(len(healthy))]
	r.proxy(w, req, replica)
}

func (r *Router) proxy(w http.ResponseWriter, req *http.Request, claim routeClaim) {
	if claim.target == nil {
		http.Error(w, "replica unavailable", http.StatusBadGateway)
		return
	}
	target := *claim.target
	proxy := &httputil.ReverseProxy{
		Transport: claim.transport,
		Rewrite: func(request *httputil.ProxyRequest) {
			request.SetURL(&target)
			request.Out.Host = request.In.Host
			request.Out.Header.Del(TargetReplicaHeader)
			request.Out.Header.Del(ProbeAuthorizationHeader)
			request.Out.Header.Del("X-Trusted-Client-IP")
			request.Out.Header.Del("X-Trusted-Request-ID")
			request.Out.Header.Del("Forwarded")
			request.Out.Header.Del("X-Forwarded-For")
			request.Out.Header.Del("X-Forwarded-Host")
			request.Out.Header.Del("X-Forwarded-Proto")
			forwarded := forwardingFromContext(request.In.Context(), request.In)
			if forwarded.clientIP != "" {
				request.Out.Header.Set("X-Forwarded-For", forwarded.clientIP)
			}
			request.Out.Header.Set("X-Forwarded-Host", stripPort(request.In.Host))
			request.Out.Header.Set("X-Forwarded-Proto", forwarded.proto)
		},
		ModifyResponse: func(response *http.Response) error {
			if response.ContentLength > r.config.MaxResponseBytes {
				return errResponseTooLarge
			}
			// Dynamic deployment traffic, especially exact targeted challenges,
			// must never be satisfied from an intermediary cache entry belonging to
			// another replica or incarnation.
			response.Header.Set("Cache-Control", "private, no-store")
			response.Body = &boundedResponseBody{body: response.Body, remaining: r.config.MaxResponseBytes}
			return nil
		},
		ErrorHandler: func(writer http.ResponseWriter, _ *http.Request, err error) {
			if errors.Is(err, errResponseTooLarge) {
				http.Error(writer, "upstream response exceeds edge limit", http.StatusBadGateway)
				return
			}
			http.Error(writer, "replica unavailable", http.StatusBadGateway)
		},
		FlushInterval: -1,
	}
	if proxy.Transport == nil {
		proxy.Transport = r.transport
	}
	proxy.ServeHTTP(w, req)
}

type boundedResponseBody struct {
	body      io.ReadCloser
	remaining int64
	checked   bool
}

func (b *boundedResponseBody) Read(payload []byte) (int, error) {
	if b.remaining > 0 {
		if int64(len(payload)) > b.remaining {
			payload = payload[:b.remaining]
		}
		n, err := b.body.Read(payload)
		b.remaining -= int64(n)
		return n, err
	}
	if b.checked {
		return 0, errResponseTooLarge
	}
	b.checked = true
	var extra [1]byte
	n, err := b.body.Read(extra[:])
	if n > 0 {
		return 0, errResponseTooLarge
	}
	return 0, err
}

func (b *boundedResponseBody) Close() error { return b.body.Close() }

// Local-only mutation helpers are intentionally unexported. They keep the
// small reverse-proxy unit tests independent from protocol setup while making
// it impossible for another package to bypass signed production lifecycle.
func (r *Router) addLocal(host string, replica Replica, target *url.URL) {
	host = strings.ToLower(host)
	r.mu.Lock()
	defer r.mu.Unlock()
	claim := routeClaim{replica: replica, target: target}
	r.upsertRouteLocked(host, claim)
}

func stripPort(host string) string {
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		return strings.ToLower(parsed)
	}
	return strings.ToLower(host)
}

func canonicalDeploymentHost(rawHost, domain, prefix string) (string, error) {
	if rawHost == "" || strings.TrimSpace(rawHost) != rawHost || strings.HasSuffix(rawHost, ".") {
		return "", errors.New("host is empty or non-canonical")
	}
	host := rawHost
	if strings.Contains(rawHost, ":") {
		var port string
		var err error
		host, port, err = net.SplitHostPort(rawHost)
		if err != nil {
			return "", errors.New("host port is invalid")
		}
		if parsed, parseErr := strconv.Atoi(port); parseErr != nil || parsed < 1 || parsed > 65535 {
			return "", errors.New("host port is invalid")
		}
	}
	host = strings.ToLower(host)
	suffix := "." + domain
	if !strings.HasSuffix(host, suffix) {
		return "", errors.New("host is outside edge domain")
	}
	label := strings.TrimSuffix(host, suffix)
	if strings.Contains(label, ".") || !validDNSLabel(label) || !strings.HasPrefix(label, prefix) || !validDNSLabel(strings.TrimPrefix(label, prefix)) {
		return "", errors.New("host is outside deployment namespace")
	}
	return host, nil
}

type forwardingDetails struct {
	clientIP string
	proto    string
}

type forwardingContextKey struct{}

func forwardingFromContext(ctx context.Context, req *http.Request) forwardingDetails {
	if value, ok := ctx.Value(forwardingContextKey{}).(forwardingDetails); ok {
		return value
	}
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		host = ""
	}
	proto := "http"
	if req.TLS != nil {
		proto = "https"
	}
	return forwardingDetails{clientIP: host, proto: proto}
}

func contextWithForwarding(ctx context.Context, details forwardingDetails) context.Context {
	return context.WithValue(ctx, forwardingContextKey{}, details)
}

func (r *Router) closeIdleConnections() {
	if transport, ok := r.transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, claim := range r.claims {
		if claim.transport != r.transport {
			closeTransport(claim.transport)
		}
	}
}

func (r *Router) String() string {
	return fmt.Sprintf("edge.Router(domain=%s,prefix=%s)", r.config.Domain, r.config.HostLabelPrefix)
}
