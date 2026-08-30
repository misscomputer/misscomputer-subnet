// SPDX-License-Identifier: AGPL-3.0-only

// Package remote adapts the Go scheduler's Assigner interface to the local
// validator-neuron dendrite bridge. Scheduler/replacement semantics remain in
// Go; Python performs only metagraph discovery and btauth HTTP transport.
package remote

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/bridge"
	"github.com/misscomputer/misscomputer-subnet/pkg/miner"
	"github.com/misscomputer/misscomputer-subnet/pkg/netpolicy"
	"github.com/misscomputer/misscomputer-subnet/pkg/neuron"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	"github.com/misscomputer/misscomputer-subnet/pkg/tunnel"
)

type Assigner struct {
	MinerHotkey          string
	MinerUID             *uint16
	ServiceKey           ed25519.PublicKey
	BridgeURL            string
	AxonURL              string
	Transport            string
	TLSCertificateSHA256 string
	TLSCertificateDER    []byte
	Secret               []byte
	Client               *http.Client
	Tunnels              tunnel.Registry
	Retries              int
	mu                   sync.Mutex
	deployments          map[string]string
}

func New(registration neuron.MinerRegistration, secret []byte, tunnels tunnel.Registry) (*Assigner, error) {
	return NewWithTransportPolicy(registration, secret, tunnels, false, false)
}

func NewWithPolicy(registration neuron.MinerRegistration, secret []byte, tunnels tunnel.Registry, allowPrivateAxon bool) (*Assigner, error) {
	return NewWithTransportPolicy(registration, secret, tunnels, allowPrivateAxon, false)
}

func NewWithTransportPolicy(registration neuron.MinerRegistration, secret []byte, tunnels tunnel.Registry, allowPrivateAxon, allowInsecureMockHTTP bool) (*Assigner, error) {
	if len(secret) < 32 {
		return nil, fmt.Errorf("validator bridge secret must contain at least 32 bytes")
	}
	binding := registration.ServiceBinding
	if registration.Protocol != neuron.SynapseVersion || binding.Protocol != neuron.ServiceBindingVersion || binding.Role != "miner" ||
		registration.Network == "" || registration.Hotkey == "" || registration.Network != binding.Network || registration.NetUID != binding.NetUID ||
		registration.Hotkey != binding.Hotkey || !equalUID(registration.UID, binding.UID) {
		return nil, fmt.Errorf("miner registration identity does not match its current service binding")
	}
	if allowInsecureMockHTTP && (!allowPrivateAxon || !localMockNetwork(registration.Network)) {
		return nil, fmt.Errorf("insecure mock HTTP requires private axons on an explicit local/mock network")
	}
	key, err := hex.DecodeString(registration.ServiceBinding.ServicePublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize || registration.ServiceBinding.ServicePublicKey != hex.EncodeToString(key) {
		return nil, fmt.Errorf("miner service key must be 32-byte lowercase hex")
	}
	if err := neuron.ValidateServiceBindingTransport(registration.ServiceBinding, allowInsecureMockHTTP); err != nil {
		return nil, err
	}
	bridgeURL, err := canonicalURL(registration.BridgeURL, "http")
	if err != nil || !loopbackHost(bridgeURL.Hostname()) {
		return nil, fmt.Errorf("validator bridge URL must be explicit loopback HTTP with an exact port")
	}
	axonURL, err := canonicalURL(registration.AxonURL, registration.ServiceBinding.Transport)
	if err != nil {
		return nil, fmt.Errorf("miner axon URL must be an explicit %s numeric-IP URL with an exact port", registration.ServiceBinding.Transport)
	}
	publicAddress, publicErr := netpolicy.CanonicalPublicAddress(axonURL.Hostname())
	_, privateAddress, privateErr := netpolicy.CanonicalNumericAddress(axonURL.Hostname())
	permittedIP := (!allowPrivateAxon && publicErr == nil && publicAddress == axonURL.Hostname()) ||
		(allowPrivateAxon && privateErr == nil && (privateAddress.IsGlobalUnicast() || privateAddress.IsLoopback()))
	permittedMockHost := privateErr != nil && allowPrivateAxon && allowInsecureMockHTTP &&
		registration.ServiceBinding.Transport == neuron.TransportHTTP && validMockHostname(axonURL.Hostname())
	if !permittedIP && !permittedMockHost {
		return nil, fmt.Errorf("miner axon URL must use a permitted numeric IP or explicit local-mock hostname")
	}
	var certificateDER []byte
	var certificateSHA256 string
	if registration.ServiceBinding.Transport == neuron.TransportHTTPS {
		if registration.ServiceBinding.TransportCertificateSHA256 == nil {
			return nil, fmt.Errorf("HTTPS miner registration lacks a certificate pin")
		}
		certificateSHA256 = *registration.ServiceBinding.TransportCertificateSHA256
		if len(registration.TransportCertificateDERBase64) > base64.StdEncoding.EncodedLen(tunnel.MaxCertificateDERBytes) {
			return nil, fmt.Errorf("miner transport certificate DER exceeds the size limit")
		}
		certificateDER, err = base64.StdEncoding.DecodeString(registration.TransportCertificateDERBase64)
		if err != nil || base64.StdEncoding.EncodeToString(certificateDER) != registration.TransportCertificateDERBase64 {
			return nil, fmt.Errorf("miner transport certificate DER must use canonical base64")
		}
		certificate, err := tunnel.ValidatePinnedCertificate(certificateDER, certificateSHA256, time.Now().UTC())
		if err != nil {
			return nil, fmt.Errorf("validate miner transport certificate: %w", err)
		}
		if err := certificate.VerifyHostname(axonURL.Hostname()); err != nil {
			return nil, fmt.Errorf("miner transport certificate must contain the exact numeric axon IP SAN: %w", err)
		}
	} else if registration.TransportCertificateDERBase64 != "" {
		return nil, fmt.Errorf("HTTP mock registration cannot carry a transport certificate")
	}
	return &Assigner{
		MinerHotkey: registration.Hotkey, MinerUID: cloneUID(registration.UID), ServiceKey: ed25519.PublicKey(key),
		BridgeURL: bridgeURL.String(), AxonURL: axonURL.String(), Transport: registration.ServiceBinding.Transport,
		TLSCertificateSHA256: certificateSHA256, TLSCertificateDER: append([]byte(nil), certificateDER...),
		Secret: append([]byte(nil), secret...), Client: newBridgeClient(), Tunnels: tunnels, Retries: 1, deployments: make(map[string]string),
	}, nil
}

func newBridgeClient() *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy: nil, DialContext: dialer.DialContext, MaxIdleConns: 32, MaxIdleConnsPerHost: 8,
		IdleConnTimeout: 60 * time.Second, ResponseHeaderTimeout: 2 * time.Minute, ExpectContinueTimeout: time.Second,
	}
	return &http.Client{
		Timeout:   2 * time.Minute,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func localMockNetwork(network string) bool {
	normalized := strings.ToLower(strings.TrimSpace(network))
	return normalized == "local" || normalized == "mock" || strings.HasPrefix(normalized, "mock-")
}

func validMockHostname(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func equalUID(left, right *uint16) bool {
	return (left == nil && right == nil) || (left != nil && right != nil && *left == *right)
}

func cloneUID(value *uint16) *uint16 {
	if value == nil {
		return nil
	}
	copyValue := *value
	return &copyValue
}

func canonicalURL(raw, scheme string) (*url.URL, error) {
	if strings.ContainsAny(raw, "?#") {
		return nil, fmt.Errorf("invalid URL")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed == nil || parsed.Scheme != scheme || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.ForceQuery || parsed.RawFragment != "" || parsed.Opaque != "" || parsed.RawPath != "" || parsed.Path != "" {
		return nil, fmt.Errorf("invalid URL")
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 || port > 65535 || parsed.Port() != strconv.Itoa(port) || parsed.Hostname() == "" {
		return nil, fmt.Errorf("invalid URL port")
	}
	host := parsed.Hostname()
	if address, parseErr := netip.ParseAddr(host); parseErr == nil {
		if address.Is4In6() || address.Zone() != "" {
			return nil, fmt.Errorf("invalid mapped or zoned IP identity")
		}
		host = address.String()
	} else {
		if strings.Contains(host, ":") {
			return nil, fmt.Errorf("invalid numeric IP identity")
		}
		host = strings.ToLower(host)
	}
	parsed.Path = ""
	parsed.RawPath = ""
	parsed.Host = net.JoinHostPort(host, strconv.Itoa(port))
	return parsed, nil
}

func loopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (a *Assigner) ID() string { return a.MinerHotkey }

func (a *Assigner) PublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), a.ServiceKey...)
}

func (a *Assigner) SubnetIdentity() miner.SubnetIdentity {
	return miner.SubnetIdentity{
		Hotkey: a.MinerHotkey, UID: cloneUID(a.MinerUID), AxonURL: a.AxonURL, Transport: a.Transport,
		TransportCertificateSHA256: a.TLSCertificateSHA256,
	}
}

func (a *Assigner) Assign(ctx context.Context, ticket protocol.Ticket) (miner.Result, error) {
	request := neuron.BridgeAssignRequest{Protocol: neuron.SynapseVersion, RequestID: ticket.AssignmentNonce, Ticket: ticket}
	var response neuron.DeployResponse
	path := "/v1/miners/" + url.PathEscape(a.MinerHotkey) + "/deploy"
	if err := a.post(ctx, path, request, &response); err != nil {
		return miner.Result{}, err
	}
	if response.Protocol != neuron.SynapseVersion || response.RequestID != request.RequestID {
		return miner.Result{}, fmt.Errorf("validator bridge returned a mismatched response envelope")
	}
	expectedEndpoint := protocol.EndpointID(ticket)
	if response.Result.EndpointID != expectedEndpoint {
		return miner.Result{}, fmt.Errorf("validator bridge returned an unexpected endpoint identity")
	}
	if a.Tunnels != nil {
		target := a.AxonURL + "/runtime/" + url.PathEscape(expectedEndpoint)
		var err error
		if a.Transport == neuron.TransportHTTPS {
			pinned, ok := a.Tunnels.(tunnel.PinnedRegistry)
			if !ok {
				return miner.Result{}, fmt.Errorf("remote tunnel registry cannot retain an exact TLS pin")
			}
			err = pinned.RegisterPinned(expectedEndpoint, target, a.TLSCertificateDER, a.TLSCertificateSHA256)
		} else {
			err = a.Tunnels.Register(expectedEndpoint, target)
		}
		if err != nil {
			return miner.Result{}, fmt.Errorf("register remote tunnel endpoint: %w", err)
		}
	}
	a.mu.Lock()
	a.deployments[expectedEndpoint] = ticket.DeploymentID
	a.mu.Unlock()
	return response.Result, nil
}

func (a *Assigner) Deactivate(ctx context.Context, endpointID string) error {
	a.mu.Lock()
	deploymentID := a.deployments[endpointID]
	a.mu.Unlock()
	return a.DeactivateKnown(ctx, endpointID, deploymentID)
}

// DeactivateKnown supports restart recovery, where the durable control store
// supplies the deployment ID rather than ephemeral adapter memory.
func (a *Assigner) DeactivateKnown(ctx context.Context, endpointID, deploymentID string) error {
	if a.Tunnels != nil {
		a.Tunnels.Unregister(endpointID)
	}
	// Carry this handle's exact bound identity so the validator bridge can
	// fail closed instead of delivering the cleanup to a same-hotkey miner
	// that has since rebound to a different UID, axon, or service key.
	request := neuron.BridgeDeactivateRequest{
		Protocol: neuron.SynapseVersion, RequestID: endpointID, EndpointID: endpointID, DeploymentID: deploymentID,
		MinerHotkey: a.MinerHotkey, MinerUID: cloneUID(a.MinerUID), AxonURL: a.AxonURL,
		MinerServicePublicKey: hex.EncodeToString(a.ServiceKey), MinerTransport: a.Transport,
	}
	if a.TLSCertificateSHA256 != "" {
		request.MinerTLSCertificateSHA256 = &a.TLSCertificateSHA256
	}
	var response neuron.DeactivateResponse
	path := "/v1/miners/" + url.PathEscape(a.MinerHotkey) + "/deactivate"
	if err := a.post(ctx, path, request, &response); err != nil {
		return err
	}
	if response.Status != "deactivated" && response.Status != "absent" {
		return fmt.Errorf("unexpected deactivation status %q", response.Status)
	}
	a.mu.Lock()
	delete(a.deployments, endpointID)
	a.mu.Unlock()
	return nil
}

func (a *Assigner) post(ctx context.Context, path string, value, output any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	attempts := a.Retries + 1
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.BridgeURL+path, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		if err := bridge.SignRequest(req, payload, a.Secret, time.Now().UTC()); err != nil {
			return err
		}
		client := a.Client
		if client == nil {
			client = newBridgeClient()
		}
		resp, requestErr := client.Do(req)
		if requestErr == nil {
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, bridge.MaxBodyBytes+1))
			resp.Body.Close()
			if readErr != nil {
				lastErr = readErr
			} else if len(body) > bridge.MaxBodyBytes {
				lastErr = fmt.Errorf("validator bridge response exceeds limit")
			} else if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				decoder := json.NewDecoder(bytes.NewReader(body))
				decoder.DisallowUnknownFields()
				if err := decoder.Decode(output); err != nil {
					return fmt.Errorf("decode validator bridge response: %w", err)
				}
				if err := decoder.Decode(&struct{}{}); err != io.EOF {
					return fmt.Errorf("decode validator bridge response: expected one JSON value")
				}
				return nil
			} else {
				var envelope bridge.ErrorEnvelope
				if json.Unmarshal(body, &envelope) == nil && envelope.Error.Code != "" {
					lastErr = fmt.Errorf("validator bridge %s: %s", envelope.Error.Code, envelope.Error.Message)
					if !envelope.Error.Retryable {
						return lastErr
					}
				} else {
					lastErr = fmt.Errorf("validator bridge returned HTTP %d", resp.StatusCode)
				}
			}
		} else {
			lastErr = requestErr
		}
		if attempt+1 < attempts {
			timer := time.NewTimer(time.Duration(attempt+1) * 100 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
	return fmt.Errorf("validator bridge request failed: %w", lastErr)
}
