// SPDX-License-Identifier: AGPL-3.0-only

package remote

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/neuron"
	"github.com/misscomputer/misscomputer-subnet/pkg/tunnel"
)

func registration(t *testing.T, bridgeURL string) neuron.MinerRegistration {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uid := uint16(1)
	der := certificateDER(t, time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
	digest := sha256.Sum256(der)
	pin := hex.EncodeToString(digest[:])
	return neuron.MinerRegistration{
		Protocol: neuron.SynapseVersion, Network: "test", NetUID: 42, Hotkey: "miner", UID: &uid,
		AxonURL: "https://8.8.8.8:8091", BridgeURL: bridgeURL, TransportCertificateDERBase64: base64.StdEncoding.EncodeToString(der),
		ServiceBinding: neuron.ServiceKeyBinding{
			Protocol: neuron.ServiceBindingVersion, Role: "miner", Network: "test", NetUID: 42, Hotkey: "miner", UID: &uid,
			ServicePublicKey: hex.EncodeToString(public), Transport: neuron.TransportHTTPS, TransportCertificateSHA256: &pin,
		},
	}
}

func certificateDER(t *testing.T, notBefore, notAfter time.Time) []byte {
	t.Helper()
	_, certificateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test miner"}, NotBefore: notBefore, NotAfter: notAfter,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("127.0.0.1"), net.ParseIP("2606:4700:4700::1111")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, certificateKey.Public(), certificateKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestNewRejectsPrivateAxonWithoutExplicitLocalPolicy(t *testing.T) {
	value := registration(t, "http://127.0.0.1:9200")
	value.AxonURL = "https://127.0.0.1:8091"
	if _, err := New(value, make([]byte, 32), tunnel.NewLocalRegistry()); err == nil {
		t.Fatal("private axon target was accepted by the live policy")
	}
	if _, err := NewWithPolicy(value, make([]byte, 32), tunnel.NewLocalRegistry(), true); err != nil {
		t.Fatalf("explicit local policy rejected private axon: %v", err)
	}
}

func TestNewRejectsSharedAndSpecialPurposeAxons(t *testing.T) {
	for _, host := range []string{"100.64.1.2", "192.0.2.1", "198.18.0.1"} {
		value := registration(t, "http://127.0.0.1:9200")
		value.AxonURL = "https://" + host + ":8091"
		if _, err := New(value, make([]byte, 32), tunnel.NewLocalRegistry()); err == nil {
			t.Fatalf("special-purpose axon target %s was accepted", host)
		}
	}
}

func TestPrivatePolicyStillRejectsNonUnicastAxons(t *testing.T) {
	for _, host := range []string{"0.0.0.0", "255.255.255.255", "224.0.0.1", "[::]", "[ff02::1]", "[fe80::1]"} {
		value := registration(t, "http://127.0.0.1:9200")
		value.AxonURL = "https://" + host + ":8091"
		if _, err := NewWithPolicy(value, make([]byte, 32), tunnel.NewLocalRegistry(), true); err == nil {
			t.Fatalf("non-unicast axon target %s was accepted by private policy", host)
		}
	}
}

func TestNewRequiresLoopbackValidatorBridge(t *testing.T) {
	if _, err := New(registration(t, "http://validator.example:9200"), make([]byte, 32), tunnel.NewLocalRegistry()); err == nil {
		t.Fatal("non-loopback validator bridge URL was accepted")
	}
	if _, err := New(registration(t, "http://127.0.0.1:9200"), make([]byte, 32), tunnel.NewLocalRegistry()); err != nil {
		t.Fatalf("loopback validator bridge rejected: %v", err)
	}
}

func TestNewRejectsAmbiguousOrCredentialedURLs(t *testing.T) {
	for _, value := range []struct {
		field string
		url   string
	}{
		{"bridge", "http://127.0.0.1"},
		{"bridge", "http://user@127.0.0.1:9200"},
		{"bridge", "http://127.0.0.1:9200/path"},
		{"bridge", "http://127.0.0.1:9200?proxy=1"},
		{"axon", "https://user@8.8.8.8:8091"},
		{"axon", "https://8.8.8.8:8091/path"},
		{"axon", "https://8.8.8.8:8091/"},
		{"axon", "https://8.8.8.8:08091"},
		{"axon", "https://8.8.8.8:8091?target=other"},
		{"axon", "https://8.8.8.8:8091?"},
		{"axon", "https://8.8.8.8:8091#fragment"},
		{"axon", "https://8.8.8.8:8091#"},
		{"axon", "https://miner.example:8091"},
	} {
		registration := registration(t, "http://127.0.0.1:9200")
		if value.field == "bridge" {
			registration.BridgeURL = value.url
		} else {
			registration.AxonURL = value.url
		}
		if _, err := New(registration, make([]byte, 32), tunnel.NewLocalRegistry()); err == nil {
			t.Fatalf("ambiguous %s URL %q was accepted", value.field, value.url)
		}
	}
}

func TestNewPreservesNormalizedPublicIPv6Axon(t *testing.T) {
	value := registration(t, "http://127.0.0.1:9200")
	value.AxonURL = "https://[2606:4700:4700:0:0:0:0:1111]:8091"
	assigner, err := New(value, make([]byte, 32), tunnel.NewLocalRegistry())
	if err != nil {
		t.Fatalf("normalized public IPv6 axon rejected: %v", err)
	}
	if assigner.AxonURL != "https://[2606:4700:4700::1111]:8091" {
		t.Fatalf("IPv6 axon was not canonicalized: got %q", assigner.AxonURL)
	}
}

func TestNewAllowsHTTPOnlyWithExplicitMockPolicy(t *testing.T) {
	value := registration(t, "http://127.0.0.1:9200")
	value.Network = "local"
	value.ServiceBinding.Network = "local"
	value.AxonURL = "http://127.0.0.1:8091"
	value.TransportCertificateDERBase64 = ""
	value.ServiceBinding.Transport = neuron.TransportHTTP
	value.ServiceBinding.TransportCertificateSHA256 = nil
	if _, err := NewWithPolicy(value, make([]byte, 32), tunnel.NewLocalRegistry(), true); err == nil {
		t.Fatal("pinless HTTP was accepted without the separate mock policy")
	}
	if _, err := NewWithTransportPolicy(value, make([]byte, 32), tunnel.NewLocalRegistry(), true, true); err != nil {
		t.Fatalf("explicit mock HTTP policy rejected local registration: %v", err)
	}
	value.AxonURL = "http://miner-1:8091"
	if _, err := NewWithTransportPolicy(value, make([]byte, 32), tunnel.NewLocalRegistry(), true, true); err != nil {
		t.Fatalf("explicit mock HTTP policy rejected a scoped Compose hostname: %v", err)
	}
	for _, hostname := range []string{"-miner", "miner-", "miner_name", "miner..one"} {
		value.AxonURL = "http://" + hostname + ":8091"
		if _, err := NewWithTransportPolicy(value, make([]byte, 32), tunnel.NewLocalRegistry(), true, true); err == nil {
			t.Fatalf("explicit mock HTTP policy accepted malformed hostname %q", hostname)
		}
	}
}

func TestNewRejectsCertificatePinMismatch(t *testing.T) {
	value := registration(t, "http://127.0.0.1:9200")
	wrong := hex.EncodeToString(make([]byte, sha256.Size))
	value.ServiceBinding.TransportCertificateSHA256 = &wrong
	if _, err := New(value, make([]byte, 32), tunnel.NewLocalRegistry()); err == nil {
		t.Fatal("registration whose public certificate mismatched the signed pin was accepted")
	}
}

func TestNewRejectsCertificateWithoutExactAxonIPSAN(t *testing.T) {
	value := registration(t, "http://127.0.0.1:9200")
	value.AxonURL = "https://1.1.1.1:8091"
	if _, err := New(value, make([]byte, 32), tunnel.NewLocalRegistry()); err == nil {
		t.Fatal("registration whose certificate omitted the numeric axon IP SAN was accepted")
	}
}

func TestNewRejectsExpiredAndNotYetValidCertificates(t *testing.T) {
	now := time.Now().UTC()
	for _, validity := range []struct {
		name      string
		notBefore time.Time
		notAfter  time.Time
	}{
		{name: "expired", notBefore: now.Add(-2 * time.Hour), notAfter: now.Add(-time.Hour)},
		{name: "not yet valid", notBefore: now.Add(time.Hour), notAfter: now.Add(2 * time.Hour)},
	} {
		t.Run(validity.name, func(t *testing.T) {
			value := registration(t, "http://127.0.0.1:9200")
			der := certificateDER(t, validity.notBefore, validity.notAfter)
			digest := sha256.Sum256(der)
			pin := hex.EncodeToString(digest[:])
			value.TransportCertificateDERBase64 = base64.StdEncoding.EncodeToString(der)
			value.ServiceBinding.TransportCertificateSHA256 = &pin
			if _, err := New(value, make([]byte, 32), tunnel.NewLocalRegistry()); err == nil {
				t.Fatal("certificate outside its validity window was accepted")
			}
		})
	}
}

func TestPostHonorsTimeoutAndBoundsRetries(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
		time.Sleep(100 * time.Millisecond)
	}))
	defer server.Close()
	assigner, err := New(registration(t, server.URL), make([]byte, 32), tunnel.NewLocalRegistry())
	if err != nil {
		t.Fatal(err)
	}
	assigner.Client = &http.Client{Timeout: 10 * time.Millisecond}
	assigner.Retries = 1
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	err = assigner.post(ctx, "/timeout", map[string]string{"value": "test"}, &map[string]string{})
	if err == nil {
		t.Fatal("timed-out validator bridge request succeeded")
	}
	// The HTTP client wraps its own timeout rather than the parent deadline;
	// the important boundary is that retries are finite.
	if got := requests.Load(); got != 2 {
		t.Fatalf("bounded retries made %d requests, err=%v", got, err)
	}
}

func TestBridgeClientDisablesProxyInheritanceAndRedirects(t *testing.T) {
	var redirected atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected.Add(1)
	}))
	defer target.Close()
	bridgeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer bridgeServer.Close()
	assigner, err := New(registration(t, bridgeServer.URL), make([]byte, 32), tunnel.NewLocalRegistry())
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := assigner.Client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || assigner.Client.CheckRedirect == nil {
		t.Fatal("validator bridge client did not explicitly disable proxies and redirects")
	}
	assigner.Retries = 0
	if err := assigner.post(context.Background(), "/redirect", map[string]string{"secret": "payload"}, &map[string]string{}); err == nil {
		t.Fatal("redirecting bridge response was accepted")
	}
	if redirected.Load() != 0 {
		t.Fatal("workload-bearing bridge request followed a redirect")
	}
}
