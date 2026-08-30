// SPDX-License-Identifier: AGPL-3.0-only

package tunnel

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const MaxCertificateDERBytes = 64 << 10

// Registry is the edge-facing abstraction for persistent outbound miner
// tunnels. LocalRegistry is in-process for the lab; a production adapter can
// map the same endpoint IDs to QUIC or WireGuard sessions.
type Registry interface {
	Register(endpointID, rawURL string) error
	Unregister(endpointID string)
	Resolve(endpointID string) (*url.URL, error)
}

// PinnedRegistry is the production extension used for self-signed miner TLS.
// The legacy Registry surface remains available for isolated local adapters,
// while bound HTTPS routes fail closed unless this exact metadata is present.
type PinnedRegistry interface {
	Registry
	RegisterPinned(endpointID, rawURL string, certificateDER []byte, certificateSHA256 string) error
	ResolvePinned(endpointID string) (PinnedTarget, error)
}

type PinnedTarget struct {
	URL               *url.URL
	CertificateDER    []byte
	CertificateSHA256 string
}

type endpoint struct {
	url               *url.URL
	certificateDER    []byte
	certificateSHA256 string
}

type LocalRegistry struct {
	mu        sync.RWMutex
	endpoints map[string]endpoint
}

func NewLocalRegistry() *LocalRegistry {
	return &LocalRegistry{endpoints: make(map[string]endpoint)}
}

func (r *LocalRegistry) Register(endpointID, rawURL string) error {
	return r.register(endpointID, rawURL, nil, "")
}

func (r *LocalRegistry) RegisterPinned(endpointID, rawURL string, certificateDER []byte, certificateSHA256 string) error {
	return r.register(endpointID, rawURL, certificateDER, certificateSHA256)
}

func (r *LocalRegistry) register(endpointID, rawURL string, certificateDER []byte, certificateSHA256 string) error {
	if strings.ContainsAny(rawURL, "?#") {
		return fmt.Errorf("invalid tunnel target %q", rawURL)
	}
	u, err := url.Parse(rawURL)
	if err != nil || u == nil {
		return fmt.Errorf("invalid tunnel target %q", rawURL)
	}
	portValid := true
	if u.Port() != "" {
		port, portErr := strconv.Atoi(u.Port())
		portValid = portErr == nil && port >= 1 && port <= 65535
	}
	if endpointID == "" || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || u.RawFragment != "" || u.Opaque != "" || !portValid {
		return fmt.Errorf("invalid tunnel target %q", rawURL)
	}
	if len(certificateDER) > 0 || certificateSHA256 != "" {
		if u.Scheme != "https" {
			return fmt.Errorf("pinned tunnel target must use HTTPS")
		}
		if !canonicalSHA256(certificateSHA256) {
			return fmt.Errorf("pinned tunnel target has an invalid certificate SHA-256")
		}
		if _, validateErr := ValidatePinnedCertificate(certificateDER, certificateSHA256, time.Now().UTC()); validateErr != nil {
			return validateErr
		}
	} else if u.Scheme == "https" {
		// A bare HTTPS target can still be used by old local-only tests, but a
		// bound network route will reject it through ResolvePinned.
		certificateDER = nil
	}
	r.mu.Lock()
	if existing, exists := r.endpoints[endpointID]; exists &&
		(existing.url.String() != u.String() || existing.certificateSHA256 != certificateSHA256 || !equalBytes(existing.certificateDER, certificateDER)) {
		r.mu.Unlock()
		return fmt.Errorf("tunnel endpoint %q is already bound to another target", endpointID)
	}
	r.endpoints[endpointID] = endpoint{url: u, certificateDER: append([]byte(nil), certificateDER...), certificateSHA256: certificateSHA256}
	r.mu.Unlock()
	return nil
}

// ValidatePinnedCertificate applies the public-leaf constraints shared by
// registration and runtime routing. It never handles private key material.
func ValidatePinnedCertificate(certificateDER []byte, certificateSHA256 string, now time.Time) (*x509.Certificate, error) {
	if len(certificateDER) == 0 || len(certificateDER) > MaxCertificateDERBytes {
		return nil, fmt.Errorf("pinned certificate DER is empty or exceeds the size limit")
	}
	if !canonicalSHA256(certificateSHA256) {
		return nil, fmt.Errorf("pinned certificate has an invalid SHA-256")
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return nil, fmt.Errorf("parse pinned certificate: %w", err)
	}
	if now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
		return nil, fmt.Errorf("pinned certificate is not currently valid")
	}
	if !certificate.BasicConstraintsValid || certificate.IsCA {
		return nil, fmt.Errorf("pinned certificate must declare CA=false")
	}
	if len(certificate.ExtKeyUsage) > 0 {
		serverAuth := false
		for _, usage := range certificate.ExtKeyUsage {
			serverAuth = serverAuth || usage == x509.ExtKeyUsageServerAuth
		}
		if !serverAuth {
			return nil, fmt.Errorf("pinned certificate is not valid for server authentication")
		}
	}
	digest := sha256.Sum256(certificate.Raw)
	if hex.EncodeToString(digest[:]) != certificateSHA256 {
		return nil, fmt.Errorf("pinned certificate does not match its SHA-256")
	}
	return certificate, nil
}

func (r *LocalRegistry) Unregister(endpointID string) {
	r.mu.Lock()
	delete(r.endpoints, endpointID)
	r.mu.Unlock()
}

func (r *LocalRegistry) Resolve(endpointID string) (*url.URL, error) {
	r.mu.RLock()
	value, exists := r.endpoints[endpointID]
	r.mu.RUnlock()
	if !exists {
		return nil, fmt.Errorf("tunnel endpoint %q is unavailable", endpointID)
	}
	copy := *value.url
	return &copy, nil
}

func (r *LocalRegistry) ResolvePinned(endpointID string) (PinnedTarget, error) {
	r.mu.RLock()
	value, exists := r.endpoints[endpointID]
	r.mu.RUnlock()
	if !exists {
		return PinnedTarget{}, fmt.Errorf("tunnel endpoint %q is unavailable", endpointID)
	}
	copyURL := *value.url
	return PinnedTarget{
		URL: &copyURL, CertificateDER: append([]byte(nil), value.certificateDER...), CertificateSHA256: value.certificateSHA256,
	}, nil
}

func canonicalSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(value) == sha256.Size*2 && len(decoded) == sha256.Size && value == hex.EncodeToString(decoded)
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
