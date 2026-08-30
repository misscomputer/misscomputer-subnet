// SPDX-License-Identifier: AGPL-3.0-only

// Package runtimeapi defines the versioned, provider-neutral process boundary
// owned by the public runtime. Private controllers exchange these DTOs over a
// Unix socket; they never link this package.
package runtimeapi

import "encoding/json"

const (
	ProtocolVersion = "misscomputer.runtime.v1"
	MaxMessageBytes = 4 << 20
)

type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      string          `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      string          `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type StateKey struct {
	Key string `json:"key"`
}

type StatePut struct {
	Key   string          `json:"key"`
	Value json.RawMessage `json:"value"`
}

type StateValue struct {
	Found bool            `json:"found"`
	Value json.RawMessage `json:"value,omitempty"`
}

type StateList struct {
	Keys []string `json:"keys"`
}

type Ping struct {
	Protocol string `json:"protocol"`
}

// ControlRequest is the provider-neutral DTO used by the private authenticated
// gateway. Method, Path, and Query describe one control operation exactly as
// the validator neuron issued it; Body is an exact canonical JSON document.
// Provider credentials and policy configuration are deliberately absent from
// this public boundary.
type ControlRequest struct {
	Method string          `json:"method"`
	Path   string          `json:"path"`
	Query  string          `json:"query,omitempty"`
	Body   json.RawMessage `json:"body"`
}

type ControlResponse struct {
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body"`
}

type NonceClaim struct {
	Nonce          string `json:"nonce"`
	ExpiresAtEpoch int64  `json:"expires_at_epoch"`
}

type NonceClaimResult struct {
	Accepted bool `json:"accepted"`
}
