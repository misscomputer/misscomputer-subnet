// SPDX-License-Identifier: AGPL-3.0-only

package organic

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"time"
)

const (
	// EdgeRequestFreshness and EdgeRequestFutureSkew bound the signed
	// timestamp of an edge -> miner runtime request (same as miss-bridge/1).
	EdgeRequestFreshness  = 10 * time.Second
	EdgeRequestFutureSkew = 2 * time.Second
)

var edgeRuntimeRequestDomain = []byte("miss.computer/misscomputer-subnet/edge-runtime-request/v1/ed25519")

var (
	edgeMethods        = setOf("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
	edgePathPattern    = regexp.MustCompile(`^/[\x21-\x7e]*$`)
	edgeQueryPattern   = regexp.MustCompile(`^[\x21-\x7e]*$`)
	edgeHeaderPattern  = regexp.MustCompile(`^v1 ts=([1-9][0-9]{0,18}),nonce=([0-9a-f]{32}),sig=([0-9a-f]{128})$`)
	endpointIDMaxBytes = 320
)

func setOf(values ...string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		set[value] = true
	}
	return set
}

// EdgeRuntimeRequest is the exact object the validator Go service key signs
// for one edge -> miner /runtime/<endpoint_id>/... request. Path is the raw
// (escaped) application path after /runtime/<endpoint_id>; Query is the raw
// query without "?", empty when absent; BodySHA256 hashes the exact body
// bytes (the empty body included); Timestamp is Unix nanoseconds.
type EdgeRuntimeRequest struct {
	BodySHA256 string `json:"body_sha256"`
	EndpointID string `json:"endpoint_id"`
	Method     string `json:"method"`
	Nonce      string `json:"nonce"`
	Path       string `json:"path"`
	Query      string `json:"query"`
	Timestamp  int64  `json:"timestamp"`
}

func (r EdgeRuntimeRequest) Validate() error {
	if !ValidHex64(r.BodySHA256) || len(r.EndpointID) < 3 || len(r.EndpointID) > endpointIDMaxBytes ||
		!edgeMethods[r.Method] || !hex32Pattern.MatchString(r.Nonce) ||
		len(r.Path) > 8192 || !edgePathPattern.MatchString(r.Path) ||
		len(r.Query) > 8192 || !edgeQueryPattern.MatchString(r.Query) || r.Timestamp < 1 {
		return errors.New("edge runtime request fields are invalid")
	}
	return nil
}

// EdgeRuntimeRequestMessage is domain || 0x00 || canonical(request).
func EdgeRuntimeRequestMessage(request EdgeRuntimeRequest) ([]byte, error) {
	if err := request.Validate(); err != nil {
		return nil, err
	}
	encoded, err := Canonical(request)
	if err != nil {
		return nil, err
	}
	message := append(append([]byte{}, edgeRuntimeRequestDomain...), 0)
	return append(message, encoded...), nil
}

// SignEdgeRuntimeRequest returns the X-Miss-Edge-Authorization header value.
func SignEdgeRuntimeRequest(request EdgeRuntimeRequest, key ed25519.PrivateKey) (string, error) {
	if len(key) != ed25519.PrivateKeySize {
		return "", errors.New("invalid edge signing key")
	}
	message, err := EdgeRuntimeRequestMessage(request)
	if err != nil {
		return "", err
	}
	signature := hex.EncodeToString(ed25519.Sign(key, message))
	return fmt.Sprintf("v1 ts=%d,nonce=%s,sig=%s", request.Timestamp, request.Nonce, signature), nil
}

// EdgeAuthorization is a parsed X-Miss-Edge-Authorization header value.
type EdgeAuthorization struct {
	Timestamp int64
	Nonce     string
	Signature []byte
}

// ParseEdgeAuthorization parses one header value; anything non-canonical fails.
func ParseEdgeAuthorization(value string) (EdgeAuthorization, error) {
	match := edgeHeaderPattern.FindStringSubmatch(value)
	if match == nil {
		return EdgeAuthorization{}, errors.New("edge_authorization_malformed")
	}
	timestamp, err := strconv.ParseInt(match[1], 10, 64)
	if err != nil || timestamp > math.MaxInt64 {
		return EdgeAuthorization{}, errors.New("edge_authorization_malformed")
	}
	signature, _ := hex.DecodeString(match[3])
	return EdgeAuthorization{Timestamp: timestamp, Nonce: match[2], Signature: signature}, nil
}

// VerifyEdgeRuntimeRequest checks the header against the request the miner
// actually received, the freshness window and the addressed endpoint's
// ticket.subnet.validator_service_public_key. The caller supplies the
// received method, path, query, endpoint and body digest; the timestamp and
// nonce come from the header. Nonce uniqueness within the window is the
// caller's replay cache. Any failure must be answered 401 without contacting
// the container.
func VerifyEdgeRuntimeRequest(received EdgeRuntimeRequest, header string, key ed25519.PublicKey, now time.Time) (EdgeAuthorization, error) {
	authorization, err := ParseEdgeAuthorization(header)
	if err != nil {
		return EdgeAuthorization{}, err
	}
	received.Timestamp = authorization.Timestamp
	received.Nonce = authorization.Nonce
	age := now.UnixNano() - authorization.Timestamp
	if age > int64(EdgeRequestFreshness) || -age > int64(EdgeRequestFutureSkew) {
		return EdgeAuthorization{}, errors.New("edge_authorization_stale")
	}
	if len(key) != ed25519.PublicKeySize {
		return EdgeAuthorization{}, errors.New("edge_authorization_invalid")
	}
	message, err := EdgeRuntimeRequestMessage(received)
	if err != nil {
		return EdgeAuthorization{}, err
	}
	if !ed25519.Verify(key, message, authorization.Signature) {
		return EdgeAuthorization{}, errors.New("edge_authorization_invalid")
	}
	return authorization, nil
}
