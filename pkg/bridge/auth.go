// SPDX-License-Identifier: AGPL-3.0-only

// Package bridge implements the authenticated loopback contract between the
// Python neurons and Go services. It is independent of Bittensor btauth/1,
// which authenticates remote hotkeys on the neuron-facing HTTP boundary.
package bridge

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/durable"
)

const (
	HeaderVersion   = "X-Miss-Bridge-Version"
	HeaderTimestamp = "X-Miss-Bridge-Timestamp"
	HeaderNonce     = "X-Miss-Bridge-Nonce"
	HeaderSignature = "X-Miss-Bridge-Signature"
	Version         = "1"
	MaxBodyBytes    = 1 << 20
)

type Authenticator struct {
	Secret []byte
	Store  *durable.Store
	MaxAge time.Duration
	Now    func() time.Time
}

type replayStore interface {
	ReserveReplay(context.Context, string, string, time.Time) (bool, error)
}

func LoadSecret(filePath, envName string) ([]byte, error) {
	var value []byte
	var err error
	if filePath != "" {
		value, err = os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("read bridge secret file: %w", err)
		}
	} else if envName != "" {
		value = []byte(os.Getenv(envName))
	}
	value = bytes.TrimSpace(value)
	if len(value) < 32 {
		return nil, errors.New("bridge secret must contain at least 32 bytes")
	}
	return append([]byte(nil), value...), nil
}

func SignRequest(req *http.Request, body, secret []byte, now time.Time) error {
	if len(secret) < 32 {
		return errors.New("bridge secret is too short")
	}
	nonceBytes := make([]byte, 18)
	if _, err := rand.Read(nonceBytes); err != nil {
		return err
	}
	timestamp := strconv.FormatInt(now.UTC().UnixNano(), 10)
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	target := req.URL.EscapedPath()
	if req.URL.RawQuery != "" {
		target += "?" + req.URL.RawQuery
	}
	signature := signatureFor(secret, timestamp, nonce, req.Method, target, body)
	req.Header.Set(HeaderVersion, Version)
	req.Header.Set(HeaderTimestamp, timestamp)
	req.Header.Set(HeaderNonce, nonce)
	req.Header.Set(HeaderSignature, signature)
	return nil
}

func (a Authenticator) Verify(ctx context.Context, req *http.Request, body []byte) error {
	if len(a.Secret) < 32 {
		return errors.New("bridge authentication is not configured")
	}
	if req.Header.Get(HeaderVersion) != Version {
		return errors.New("unsupported bridge authentication version")
	}
	timestamp := req.Header.Get(HeaderTimestamp)
	nonce := req.Header.Get(HeaderNonce)
	provided := req.Header.Get(HeaderSignature)
	if timestamp == "" || nonce == "" || provided == "" {
		return errors.New("missing bridge authentication headers")
	}
	timestampNS, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return errors.New("invalid bridge timestamp")
	}
	now := time.Now().UTC()
	if a.Now != nil {
		now = a.Now().UTC()
	}
	maxAge := a.MaxAge
	if maxAge <= 0 {
		maxAge = 10 * time.Second
	}
	requestTime := time.Unix(0, timestampNS).UTC()
	if requestTime.Before(now.Add(-maxAge)) || requestTime.After(now.Add(2*time.Second)) {
		return errors.New("stale bridge request")
	}
	target := req.URL.EscapedPath()
	if req.URL.RawQuery != "" {
		target += "?" + req.URL.RawQuery
	}
	expected := signatureFor(a.Secret, timestamp, nonce, req.Method, target, body)
	if !hmac.Equal([]byte(provided), []byte(expected)) {
		return errors.New("invalid bridge signature")
	}
	if a.Store != nil {
		accepted, err := a.Store.ReserveReplay(ctx, "bridge", nonce, now.Add(maxAge+2*time.Second))
		if err != nil {
			return fmt.Errorf("persist bridge replay key: %w", err)
		}
		if !accepted {
			return errors.New("replayed bridge request")
		}
	}
	return nil
}

func (a Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, req.Body, MaxBodyBytes))
		if err != nil {
			WriteError(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body exceeds the bridge limit", false)
			return
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
		if err := a.Verify(req.Context(), req, body); err != nil {
			WriteError(w, http.StatusUnauthorized, "unauthorized", err.Error(), false)
			return
		}
		next.ServeHTTP(w, req)
	})
}

func signatureFor(secret []byte, timestamp, nonce, method, target string, body []byte) string {
	digest := sha256.Sum256(body)
	payload := strings.Join([]string{"miss-bridge/1", timestamp, nonce, strings.ToUpper(method), target, hex.EncodeToString(digest[:])}, "\n")
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

type ErrorEnvelope struct {
	Error ErrorDetail `json:"error"`
}

type ErrorDetail struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

func WriteError(w http.ResponseWriter, status int, code, message string, retryable bool) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ErrorEnvelope{Error: ErrorDetail{
		Code: code, Message: message, Retryable: retryable,
	}})
}

type RoundTripper struct {
	Secret []byte
	Base   http.RoundTripper
	Now    func() time.Time
}

func (r RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		var err error
		body, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
	}
	now := time.Now().UTC()
	if r.Now != nil {
		now = r.Now().UTC()
	}
	if err := SignRequest(req, body, r.Secret, now); err != nil {
		return nil, err
	}
	base := r.Base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}
