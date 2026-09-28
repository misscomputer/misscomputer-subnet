// SPDX-License-Identifier: AGPL-3.0-only

package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/durable"
)

func TestBridgeAuthBindsMethodPathBodyFreshnessAndReplay(t *testing.T) {
	store, err := durable.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	secret := bytes.Repeat([]byte("s"), 32)
	now := time.Now().UTC()
	body := []byte(`{"hello":"world"}`)
	req, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1/v1/test?q=1", bytes.NewReader(body))
	if err := SignRequest(req, body, secret, now); err != nil {
		t.Fatal(err)
	}
	auth := Authenticator{Secret: secret, Store: store, Now: func() time.Time { return now }}
	if err := auth.Verify(context.Background(), req, body); err != nil {
		t.Fatalf("valid bridge request rejected: %v", err)
	}
	if err := auth.Verify(context.Background(), req, body); err == nil {
		t.Fatal("replayed bridge request accepted")
	}
	changed, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1/v1/other?q=1", bytes.NewReader(body))
	changed.Header = req.Header.Clone()
	auth.Store = nil
	if err := auth.Verify(context.Background(), changed, body); err == nil {
		t.Fatal("signature replayed against another path")
	}
	stale, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1/v1/test?q=1", bytes.NewReader(body))
	if err := SignRequest(stale, body, secret, now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := auth.Verify(context.Background(), stale, body); err == nil {
		t.Fatal("stale bridge request accepted")
	}
}

func TestErrorEnvelopeAlwaysUsesValidJSONEscaping(t *testing.T) {
	recorder := httptest.NewRecorder()
	WriteError(recorder, http.StatusBadRequest, "bad_input", "control\x01 café", false)
	var envelope ErrorEnvelope
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("invalid JSON error envelope: %v: %q", err, recorder.Body.String())
	}
	if envelope.Error.Message != "control\x01 café" {
		t.Fatalf("error message changed: %q", envelope.Error.Message)
	}
}
