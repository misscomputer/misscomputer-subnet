// SPDX-License-Identifier: AGPL-3.0-only

package miner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/organic"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
)

const (
	// maxAttestedResponseBytes bounds the one response the agent buffers: an
	// authorized validator probe, which it must hash whole. It equals the
	// public response limit, so no valid app response is refused.
	maxAttestedResponseBytes = 16 << 20
	// probeAuthorizationFreshness and probeAuthorizationSkew bound the
	// validator-signed issued_at of a targeted organic probe (§17.2).
	probeAuthorizationFreshness = 30 * time.Second
	probeAuthorizationSkew      = 2 * time.Second
	maxProbeAuthorizationHeader = 8 << 10
)

var errAttestationRejected = errors.New("probe attestation rejected")

// organicProbe is one admitted validator probe awaiting its attestation.
type organicProbe struct {
	authorization organic.ProbeAuthorization
	ticket        protocol.TicketV4
}

// proxyOrganic forwards one edge-authorized request (ProxyRuntime already
// verified the edge-runtime-request signature, body and nonce) byte-exact to
// the container. A request that also carries an organic probe authorization
// for this exact endpoint incarnation leaves with one miner-signed
// miner-probe-attestation v2.
func (a *Agent) proxyOrganic(w http.ResponseWriter, req *http.Request, endpointID, rawURL string, ticket protocol.TicketV4) {
	var probe *organicProbe
	if values := req.Header.Values(organic.OrganicProbeAuthorizationHeader); len(values) > 0 {
		authorization, err := a.admitOrganicProbe(req.Context(), values, req.Method, req.URL.EscapedPath(), req.URL.RawQuery, endpointID, ticket)
		if err != nil {
			http.Error(w, "probe authorization rejected", http.StatusUnauthorized)
			return
		}
		probe = &organicProbe{authorization: authorization, ticket: ticket}
	}
	target, err := url.Parse(rawURL)
	if err != nil {
		http.Error(w, "endpoint target invalid", http.StatusBadGateway)
		return
	}
	proxy := &httputil.ReverseProxy{
		Transport: runtimeTransport,
		// Every X-Miss-* request header, including the edge and probe
		// authorizations, is edge/agent protocol and never reaches the app.
		Rewrite: func(request *httputil.ProxyRequest) { rewriteRuntimeRequest(request, target, ticket.RouteHost) },
		ModifyResponse: func(response *http.Response) error {
			// An app-supplied X-Miss-* header, such as an attestation, is
			// always a spoof.
			if err := sanitizeRuntimeResponse(response); err != nil {
				return err
			}
			if probe == nil {
				return nil
			}
			return a.attestOrganicProbe(response, probe)
		},
		ErrorHandler: func(writer http.ResponseWriter, _ *http.Request, proxyErr error) {
			switch {
			case errors.Is(proxyErr, errAttestationRejected):
				http.Error(writer, "probe attestation unavailable", http.StatusBadGateway)
			case errors.Is(proxyErr, errRuntimeResponseTooLarge):
				http.Error(writer, "runtime response exceeds the miner limit", http.StatusBadGateway)
			default:
				http.Error(writer, "runtime unavailable", http.StatusBadGateway)
			}
		},
		FlushInterval: -1,
	}
	proxy.ServeHTTP(w, req)
}

// admitOrganicProbe accepts one canonical organic probe authorization for
// exactly this endpoint incarnation and request. The edge verifies the
// validator hotkey signature and validator membership before forwarding; the
// miner binds the authorization it attests to the edge-signed request, the
// endpoint, freshness and a one-time nonce.
func (a *Agent) admitOrganicProbe(ctx context.Context, values []string, method, appPath, query, endpointID string, ticket protocol.TicketV4) (organic.ProbeAuthorization, error) {
	if len(values) != 1 || len(values[0]) > maxProbeAuthorizationHeader {
		return organic.ProbeAuthorization{}, errors.New("probe authorization must appear exactly once")
	}
	document, err := base64.StdEncoding.Strict().DecodeString(values[0])
	if err != nil || base64.StdEncoding.EncodeToString(document) != values[0] {
		return organic.ProbeAuthorization{}, errors.New("probe authorization is not canonical base64")
	}
	// The header carries canonical JSON without the stored-form newline,
	// like every base64 attestation header.
	var authorization organic.ProbeAuthorization
	if err := organic.DecodeCanonical(append(document, '\n'), &authorization); err != nil {
		return organic.ProbeAuthorization{}, err
	}
	if authorization.EndpointID != endpointID || uint64(authorization.Generation) != ticket.Generation ||
		authorization.Method != method || authorization.Path != appPath || query != "" {
		return organic.ProbeAuthorization{}, errors.New("probe authorization does not name this request")
	}
	issued, err := time.Parse(time.RFC3339, authorization.IssuedAt)
	now := time.Now()
	if err != nil || now.Sub(issued) > probeAuthorizationFreshness || issued.Sub(now) > probeAuthorizationSkew {
		return organic.ProbeAuthorization{}, errors.New("probe authorization is not fresh")
	}
	if err := a.reserveOnce(ctx, "organic-probe", authorization.Nonce, issued.Add(probeAuthorizationFreshness+probeAuthorizationSkew)); err != nil {
		return organic.ProbeAuthorization{}, err
	}
	return authorization, nil
}

// attestOrganicProbe buffers the probed response within the public response
// limit and sets exactly one miner-probe-attestation v2 header over the
// response status, body and end-to-end headers. The app's status is attested
// as observed; judging it is the validator's job.
func (a *Agent) attestOrganicProbe(response *http.Response, probe *organicProbe) error {
	body, err := io.ReadAll(io.LimitReader(response.Body, maxAttestedResponseBytes+1))
	closeErr := response.Body.Close()
	if err != nil || closeErr != nil || len(body) > maxAttestedResponseBytes {
		return errAttestationRejected
	}
	var headers [][2]string
	for name, values := range response.Header {
		for _, value := range values {
			headers = append(headers, [2]string{name, value})
		}
	}
	headerDigest, err := organic.ResponseHeaderSHA256(headers)
	if err != nil {
		return errAttestationRejected
	}
	ticketDigest, err := protocol.TicketDigestV4(probe.ticket)
	if err != nil {
		return errAttestationRejected
	}
	bodySum := sha256.Sum256(body)
	attestation := organic.ProbeAttestationV2{
		Schema: organic.SchemaPrefix + "miner-probe-attestation", SchemaVersion: 2,
		EndpointID: probe.authorization.EndpointID, Generation: probe.authorization.Generation,
		TicketDigest: ticketDigest, ArtifactDigest: probe.ticket.ImageDigest,
		ValidatorHotkey: probe.authorization.ValidatorHotkey, ProbeNonce: probe.authorization.Nonce,
		RequestMethod: probe.authorization.Method, RequestPath: probe.authorization.Path,
		ResponseStatus: response.StatusCode, ResponseBodySHA256: hex.EncodeToString(bodySum[:]),
		ResponseHeaderSHA256: headerDigest, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := organic.SignProbeAttestationV2(&attestation, a.SigningKey); err != nil {
		return errAttestationRejected
	}
	header, err := EncodeProbeAttestationV2Header(attestation)
	if err != nil {
		return errAttestationRejected
	}
	response.Header.Set(organic.ProbeAttestationHeader, header)
	response.Header.Set("Content-Length", strconv.Itoa(len(body)))
	response.ContentLength = int64(len(body))
	response.TransferEncoding = nil
	response.Body = io.NopCloser(bytes.NewReader(body))
	return nil
}

// EncodeProbeAttestationV2Header renders a signed attestation as the
// canonical base64 of its canonical JSON document.
func EncodeProbeAttestationV2Header(attestation organic.ProbeAttestationV2) (string, error) {
	if err := attestation.Validate(); err != nil {
		return "", err
	}
	document, err := organic.Canonical(attestation)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(document), nil
}

// reserveOnce consumes one nonce within its validity window, durably when a
// State store is configured.
func (a *Agent) reserveOnce(ctx context.Context, scope, nonce string, expires time.Time) error {
	if a.State != nil {
		reserved, err := a.State.ReserveReplay(ctx, scope, nonce, expires)
		if err != nil {
			return err
		}
		if !reserved {
			return errors.New("replayed nonce")
		}
		return nil
	}
	now := time.Now()
	key := scope + "\x00" + nonce
	a.mu.Lock()
	defer a.mu.Unlock()
	for stored, expiry := range a.edgeNonces {
		if now.After(expiry) {
			delete(a.edgeNonces, stored)
		}
	}
	if _, seen := a.edgeNonces[key]; seen {
		return errors.New("replayed nonce")
	}
	a.edgeNonces[key] = expires
	return nil
}
