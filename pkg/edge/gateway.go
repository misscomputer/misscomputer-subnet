// SPDX-License-Identifier: AGPL-3.0-only

package edge

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

type GatewayConfig struct {
	Domain                        string
	HostLabelPrefix               string
	TrustedProxyCIDRs             []string
	RequireTrustedIngressIdentity bool
	MaxRequestBytes               int64
	Logger                        *slog.Logger
}

type Gateway struct {
	router                        *Router
	domain                        string
	prefix                        string
	trustedProxies                []*net.IPNet
	requireTrustedIngressIdentity bool
	maxRequestBytes               int64
	logger                        *slog.Logger
}

func NewGateway(router *Router, config GatewayConfig) (*Gateway, error) {
	if router == nil || len(router.authority) != 32 {
		return nil, errors.New("gateway requires an authorized edge router")
	}
	domain, err := validateDomain(config.Domain)
	if err != nil {
		return nil, err
	}
	if domain != router.config.Domain || config.HostLabelPrefix != router.config.HostLabelPrefix {
		return nil, errors.New("gateway host policy must exactly match the route authority")
	}
	if len(config.TrustedProxyCIDRs) == 0 {
		config.TrustedProxyCIDRs = []string{"127.0.0.0/8", "::1/128"}
	}
	trusted := make([]*net.IPNet, 0, len(config.TrustedProxyCIDRs))
	for _, raw := range config.TrustedProxyCIDRs {
		_, network, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, errors.New("gateway trusted proxy CIDR is invalid")
		}
		trusted = append(trusted, network)
	}
	if config.MaxRequestBytes <= 0 {
		config.MaxRequestBytes = 1 << 20
	}
	return &Gateway{
		router: router, domain: domain, prefix: config.HostLabelPrefix, trustedProxies: trusted,
		requireTrustedIngressIdentity: config.RequireTrustedIngressIdentity, maxRequestBytes: config.MaxRequestBytes, logger: config.Logger,
	}, nil
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	started := time.Now()
	requestID := randomRequestID()
	if requestID != "" {
		w.Header().Set("X-Miss-Request-ID", requestID)
	}
	recorder := &statusRecorder{ResponseWriter: w}
	host, hostErr := canonicalDeploymentHost(req.Host, g.domain, g.prefix)
	peerIP := remoteIP(req.RemoteAddr)
	if hostErr != nil {
		http.Error(recorder, "invalid deployment host", http.StatusMisdirectedRequest)
		g.logRequest(recorder.statusCode(), req.Method, "", requestID, started)
		return
	}
	if peerIP == nil || !containsIP(g.trustedProxies, peerIP) {
		http.Error(recorder, "edge ingress peer is not trusted", http.StatusForbidden)
		g.logRequest(recorder.statusCode(), req.Method, host, requestID, started)
		return
	}
	clientIP := peerIP.String()
	proto := "http"
	if req.TLS != nil {
		proto = "https"
	}
	if g.requireTrustedIngressIdentity {
		connectingIP := net.ParseIP(req.Header.Get("X-Trusted-Client-IP"))
		if connectingIP == nil || !connectingIP.IsGlobalUnicast() || connectingIP.IsPrivate() || connectingIP.IsLoopback() || connectingIP.IsLinkLocalUnicast() ||
			!validIngressRequestID(req.Header.Get("X-Trusted-Request-ID")) {
			http.Error(recorder, "missing trusted ingress identity", http.StatusForbidden)
			g.logRequest(recorder.statusCode(), req.Method, host, requestID, started)
			return
		}
		clientIP = connectingIP.String()
		proto = "https"
	}
	if req.Method == http.MethodConnect || req.Method == http.MethodTrace {
		http.Error(recorder, "method not allowed", http.StatusMethodNotAllowed)
		g.logRequest(recorder.statusCode(), req.Method, host, requestID, started)
		return
	}
	if req.Header.Get("Upgrade") != "" || headerHasToken(req.Header.Get("Connection"), "upgrade") {
		http.Error(recorder, "protocol upgrade is not supported", http.StatusUpgradeRequired)
		g.logRequest(recorder.statusCode(), req.Method, host, requestID, started)
		return
	}
	if req.ContentLength > g.maxRequestBytes {
		http.Error(recorder, "request body exceeds edge limit", http.StatusRequestEntityTooLarge)
		g.logRequest(recorder.statusCode(), req.Method, host, requestID, started)
		return
	}
	if req.Body != nil {
		payload, err := io.ReadAll(io.LimitReader(req.Body, g.maxRequestBytes+1))
		_ = req.Body.Close()
		if err != nil {
			http.Error(recorder, "read request body", http.StatusBadRequest)
			g.logRequest(recorder.statusCode(), req.Method, host, requestID, started)
			return
		}
		if int64(len(payload)) > g.maxRequestBytes {
			http.Error(recorder, "request body exceeds edge limit", http.StatusRequestEntityTooLarge)
			g.logRequest(recorder.statusCode(), req.Method, host, requestID, started)
			return
		}
		req.Body = io.NopCloser(bytes.NewReader(payload))
		req.ContentLength = int64(len(payload))
	}
	// Client-controlled forwarding metadata is never propagated. The trusted proxy's
	// two configured identity headers are consumed only from an explicitly trusted direct
	// peer, then removed by the reverse proxy before miner ingress.
	for _, header := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"} {
		req.Header.Del(header)
	}
	req.Host = host
	req = req.WithContext(contextWithForwarding(req.Context(), forwardingDetails{clientIP: clientIP, proto: proto}))
	g.router.ServeHTTP(recorder, req)
	g.logRequest(recorder.statusCode(), req.Method, host, requestID, started)
}

func (g *Gateway) Close() { g.router.closeIdleConnections() }

func (g *Gateway) logRequest(status int, method, host, requestID string, started time.Time) {
	if g.logger == nil {
		return
	}
	g.logger.Info("edge request", "request_id", requestID, "host", host, "method", method, "status", status, "duration_ms", time.Since(started).Milliseconds())
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	if r.status != 0 {
		return
	}
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(payload []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(payload)
}

func (r *statusRecorder) Flush() {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	controller := http.NewResponseController(r.ResponseWriter)
	_ = controller.Flush()
}

func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

func (r *statusRecorder) statusCode() int {
	if r.status == 0 {
		return http.StatusOK
	}
	return r.status
}

func remoteIP(address string) net.IP {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

func containsIP(networks []*net.IPNet, ip net.IP) bool {
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func validIngressRequestID(value string) bool {
	if len(value) < 8 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func headerHasToken(value, wanted string) bool {
	for _, token := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(token), wanted) {
			return true
		}
	}
	return false
}

func randomRequestID() string {
	value := make([]byte, 12)
	if _, err := rand.Read(value); err != nil {
		return ""
	}
	return hex.EncodeToString(value)
}
