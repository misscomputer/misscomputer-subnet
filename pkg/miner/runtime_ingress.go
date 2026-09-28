// SPDX-License-Identifier: AGPL-3.0-only

package miner

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/organic"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
)

// EdgeAuthorizationHeader carries the edge-runtime-request v1 signature.
const EdgeAuthorizationHeader = "X-Miss-Edge-Authorization"

// edgeReplayCapacity bounds live edge nonces; at capacity new requests fail
// closed (401) rather than letting the cache grow without limit.
const edgeReplayCapacity = 1 << 18

// edgeReplayCache rejects a second use of one edge nonce while its signed
// timestamp could still verify (freshness window plus future skew).
type edgeReplayCache struct {
	mu      sync.Mutex
	entries map[string]time.Time
}

func (c *edgeReplayCache) claim(authorization organic.EdgeAuthorization, now time.Time) error {
	expires := time.Unix(0, authorization.Timestamp).Add(organic.EdgeRequestFreshness + organic.EdgeRequestFutureSkew)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[string]time.Time)
	}
	if len(c.entries) >= edgeReplayCapacity {
		for nonce, until := range c.entries {
			if !until.After(now) {
				delete(c.entries, nonce)
			}
		}
	}
	if until, exists := c.entries[authorization.Nonce]; exists && until.After(now) {
		return errors.New("edge authorization nonce replayed")
	}
	if len(c.entries) >= edgeReplayCapacity {
		return errors.New("edge replay cache is full")
	}
	c.entries[authorization.Nonce] = expires
	return nil
}

// forwardedRuntimeMethods is the exact public method set (§8).
var forwardedRuntimeMethods = map[string]bool{
	http.MethodGet: true, http.MethodHead: true, http.MethodPost: true, http.MethodPut: true,
	http.MethodPatch: true, http.MethodDelete: true, http.MethodOptions: true,
}

const (
	// maxRuntimeRequestBytes equals the public edge and bridge request bound.
	maxRuntimeRequestBytes = 1 << 20
	// MaxRuntimeResponseBytes is the miner-hop response bound (§8): at least
	// the 16 MiB public edge limit, measured in encoded bytes.
	MaxRuntimeResponseBytes = 16 << 20
	maxEndpointIDBytes      = 256
)

var errRuntimeResponseTooLarge = errors.New("runtime response exceeds the miner limit")

// runtimeTransport reaches loopback-published containers only. It never
// consults proxy environment variables and never adds or decodes
// Content-Encoding, so compression stays end to end.
var runtimeTransport = &http.Transport{
	Proxy:                 nil,
	DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
	DisableCompression:    true,
	MaxIdleConns:          64,
	MaxIdleConnsPerHost:   8,
	IdleConnTimeout:       30 * time.Second,
	ResponseHeaderTimeout: 15 * time.Second,
	ExpectContinueTimeout: time.Second,
}

// RuntimeIngressHandler serves <prefix><endpoint_id>/<path>?<query> for the
// runtime proxy. It parses the escaped request target itself instead of using
// ServeMux patterns, because ServeMux cleans and redirects paths such as
// "//" or "/./" and would break byte-exact forwarding and the signed path.
func (a *Agent) RuntimeIngressHandler(prefix string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		escaped := req.URL.EscapedPath()
		if !strings.HasPrefix(escaped, prefix) {
			http.NotFound(w, req)
			return
		}
		rest := escaped[len(prefix):]
		separator := strings.IndexByte(rest, '/')
		if separator <= 0 || !validEndpointID(rest[:separator]) {
			http.NotFound(w, req)
			return
		}
		endpointID, appPath := rest[:separator], rest[separator:]
		unescaped, err := url.PathUnescape(appPath)
		if err != nil {
			http.Error(w, "runtime path is not validly escaped", http.StatusBadRequest)
			return
		}
		req.URL.Path, req.URL.RawPath = unescaped, appPath
		a.ProxyRuntime(w, req, endpointID)
	})
}

func validEndpointID(value string) bool {
	if value == "" || len(value) > maxEndpointIDBytes {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

// authorizeEdgeRuntimeRequest enforces the §6.9 edge-runtime-request
// signature before any application contact. The verifying key is the
// validator service key of the addressed endpoint's retained signed ticket,
// never a caller-supplied value. Every authentication failure is 401.
func (a *Agent) authorizeEdgeRuntimeRequest(req *http.Request, endpointID string) (protocol.Ticket, int, error) {
	if !forwardedRuntimeMethods[req.Method] {
		return protocol.Ticket{}, http.StatusMethodNotAllowed, errors.New("method not allowed")
	}
	unauthorized := func(message string) (protocol.Ticket, int, error) {
		return protocol.Ticket{}, http.StatusUnauthorized, errors.New(message)
	}
	if !validEndpointID(endpointID) {
		return unauthorized("runtime endpoint identity is invalid")
	}
	headers := req.Header.Values(EdgeAuthorizationHeader)
	if len(headers) != 1 {
		return unauthorized("exactly one edge runtime authorization is required")
	}
	if a.State == nil {
		return unauthorized("edge runtime authorization requires durable assignment state")
	}
	ticket, _, exists, err := a.State.AssignmentTicket(req.Context(), endpointID)
	if err != nil {
		return protocol.Ticket{}, http.StatusServiceUnavailable, errors.New("runtime assignment state is unavailable")
	}
	if !exists || protocol.EndpointID(ticket) != endpointID {
		return unauthorized("runtime endpoint has no assignment")
	}
	if err := a.ValidateSubnetTransport(ticket); err != nil || ticket.MinerID != a.MinerID || ticket.Subnet.MinerHotkey != a.MinerID {
		return unauthorized("runtime assignment is not bound to this miner")
	}
	validatorKey, err := hex.DecodeString(ticket.Subnet.ValidatorServicePublicKey)
	if err != nil || len(validatorKey) != ed25519.PublicKeySize {
		return unauthorized("runtime assignment validator key is invalid")
	}
	if err := protocol.VerifyTicketSignature(ticket, ed25519.PublicKey(validatorKey)); err != nil {
		return unauthorized("runtime assignment ticket signature is invalid")
	}
	body, err := readRuntimeRequestBody(req)
	if err != nil {
		return unauthorized("runtime request body is unreadable or exceeds the limit")
	}
	now := time.Now()
	digest := sha256.Sum256(body)
	authorization, err := organic.VerifyEdgeRuntimeRequest(organic.EdgeRuntimeRequest{
		BodySHA256: hex.EncodeToString(digest[:]), EndpointID: endpointID, Method: req.Method,
		Path: req.URL.EscapedPath(), Query: req.URL.RawQuery,
	}, headers[0], ed25519.PublicKey(validatorKey), now)
	if err != nil {
		return unauthorized(err.Error())
	}
	if err := a.edgeReplay.claim(authorization, now); err != nil {
		return unauthorized(err.Error())
	}
	return ticket, 0, nil
}

func readRuntimeRequestBody(req *http.Request) ([]byte, error) {
	if req.Body == nil || req.Body == http.NoBody {
		req.Body = http.NoBody
		req.ContentLength = 0
		return nil, nil
	}
	payload, err := io.ReadAll(io.LimitReader(req.Body, maxRuntimeRequestBytes+1))
	_ = req.Body.Close()
	if err != nil || len(payload) > maxRuntimeRequestBytes {
		return nil, errors.New("runtime request body exceeds limit")
	}
	req.ContentLength = int64(len(payload))
	req.Body = io.NopCloser(bytes.NewReader(payload))
	if len(payload) == 0 {
		req.Body = http.NoBody
	}
	return payload, nil
}

// rewriteRuntimeRequest forwards the application request byte-exact and
// rebuilds the forwarding metadata from authenticated sources: Host is the
// signed ticket's route host, and X-Forwarded-For is the single client address
// the authenticated edge supplied.
func rewriteRuntimeRequest(request *httputil.ProxyRequest, target *url.URL, routeHost string) {
	request.SetURL(target)
	request.Out.URL.RawQuery = request.In.URL.RawQuery
	request.Out.Host = routeHost
	for name := range request.Out.Header {
		canonical := http.CanonicalHeaderKey(name)
		if strings.HasPrefix(canonical, "X-Miss-") || strings.HasPrefix(canonical, "Cf-") ||
			strings.HasPrefix(canonical, "X-Trusted-") || canonical == "X-Real-Ip" {
			request.Out.Header.Del(name)
		}
	}
	if values := request.In.Header.Values("X-Forwarded-For"); len(values) == 1 {
		if address := net.ParseIP(strings.TrimSpace(values[0])); address != nil {
			request.Out.Header.Set("X-Forwarded-For", address.String())
		}
	}
	request.Out.Header.Set("X-Forwarded-Host", routeHost)
	proto := request.In.Header.Get("X-Forwarded-Proto")
	if proto != "http" {
		proto = "https"
	}
	request.Out.Header.Set("X-Forwarded-Proto", proto)
}

// sanitizeRuntimeResponse removes every workload-supplied X-Miss-* header,
// including any spoofed attestation, and bounds the encoded body.
func sanitizeRuntimeResponse(response *http.Response) error {
	for name := range response.Header {
		if strings.HasPrefix(http.CanonicalHeaderKey(name), "X-Miss-") {
			response.Header.Del(name)
		}
	}
	if response.ContentLength > MaxRuntimeResponseBytes {
		return errRuntimeResponseTooLarge
	}
	response.Body = &boundedRuntimeBody{body: response.Body, remaining: MaxRuntimeResponseBytes}
	return nil
}

type boundedRuntimeBody struct {
	body      io.ReadCloser
	remaining int64
}

func (b *boundedRuntimeBody) Read(payload []byte) (int, error) {
	if b.remaining <= 0 {
		var extra [1]byte
		n, err := b.body.Read(extra[:])
		if n > 0 {
			return 0, errRuntimeResponseTooLarge
		}
		return 0, err
	}
	if int64(len(payload)) > b.remaining {
		payload = payload[:b.remaining]
	}
	n, err := b.body.Read(payload)
	b.remaining -= int64(n)
	return n, err
}

func (b *boundedRuntimeBody) Close() error { return b.body.Close() }
