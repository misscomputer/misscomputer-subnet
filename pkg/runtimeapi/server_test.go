// SPDX-License-Identifier: AGPL-3.0-only

package runtimeapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestStateSurvivesRuntimeRecovery(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	server, err := Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	response := server.Handle([]byte(`{"jsonrpc":"2.0","id":"1","method":"runtime.v1.state.put","params":{"key":"deployment/example","value":{"generation":7}}}`))
	if response.Error != nil {
		t.Fatalf("put error: %+v", response.Error)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	recovered, err := Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	response = recovered.Handle([]byte(`{"jsonrpc":"2.0","id":"2","method":"runtime.v1.state.get","params":{"key":"deployment/example"}}`))
	if response.Error != nil {
		t.Fatalf("get error: %+v", response.Error)
	}
	var result StateValue
	if err := json.Unmarshal(response.Result, &result); err != nil {
		t.Fatal(err)
	}
	if !result.Found || string(result.Value) != `{"generation":7}` {
		t.Fatalf("recovered value = %s", response.Result)
	}
}

func TestRuntimeRejectsTrailingAndNonCanonicalJSON(t *testing.T) {
	server := openServer(t)
	requests := []string{
		`{"jsonrpc":"2.0","id":"1","method":"runtime.v1.ping","params":{}} {}`,
		`{"jsonrpc":"2.0","id":"2","method":"runtime.v1.state.put","params":{"key":"x","value":{"b":2, "a":1}}}`,
		`{"jsonrpc":"2.0","id":"3","method":"runtime.v1.state.put","params":{"key":"x","value":{"b":2,"a":1}}}`,
	}
	for _, request := range requests {
		if response := server.Handle([]byte(request)); response.Error == nil {
			t.Fatalf("request unexpectedly accepted: %s", request)
		}
	}
	accepted := `{"jsonrpc":"2.0","id":"4","method":"runtime.v1.state.put","params":{"key":"x","value":{"a":1,"b":2}}}`
	if response := server.Handle([]byte(accepted)); response.Error != nil {
		t.Fatalf("canonical request rejected: %+v", response.Error)
	}
}

func TestPersistenceFailureRollsBackMemory(t *testing.T) {
	server := openServer(t)
	put := func(id, value string) Response {
		return server.Handle([]byte(`{"jsonrpc":"2.0","id":"` + id + `","method":"runtime.v1.state.put","params":{"key":"x","value":` + value + `}}`))
	}
	if response := put("1", `{"generation":1}`); response.Error != nil {
		t.Fatalf("initial put: %+v", response.Error)
	}
	statePath := server.statePath()
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(statePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if response := put("2", `{"generation":2}`); response.Error == nil {
		t.Fatal("persistence failure unexpectedly succeeded")
	}
	response := server.Handle([]byte(`{"jsonrpc":"2.0","id":"3","method":"runtime.v1.state.get","params":{"key":"x"}}`))
	if response.Error != nil {
		t.Fatal(response.Error)
	}
	var value StateValue
	if err := json.Unmarshal(response.Result, &value); err != nil {
		t.Fatal(err)
	}
	if string(value.Value) != `{"generation":1}` {
		t.Fatalf("in-memory mutation was not rolled back: %s", value.Value)
	}
}

func TestRuntimeStateHasAggregateLimits(t *testing.T) {
	server := openServer(t)
	put := func(key, value string) Response {
		return server.Handle([]byte(`{"jsonrpc":"2.0","id":"put","method":"runtime.v1.state.put","params":{"key":"` + key + `","value":` + value + `}}`))
	}
	server.maxStateKeys = 2
	for _, key := range []string{"one", "two"} {
		if response := put(key, `{"ok":true}`); response.Error != nil {
			t.Fatalf("bounded put %s: %+v", key, response.Error)
		}
	}
	if response := put("three", `{"ok":true}`); response.Error == nil || response.Error.Code != -32001 {
		t.Fatalf("state key cap response = %+v", response.Error)
	}
	list := server.Handle([]byte(`{"jsonrpc":"2.0","id":"list","method":"runtime.v1.state.list","params":{}}`))
	if list.Error != nil {
		t.Fatal(list.Error)
	}
	var keys StateList
	if err := json.Unmarshal(list.Result, &keys); err != nil {
		t.Fatal(err)
	}
	if len(keys.Keys) != 2 {
		t.Fatalf("state key cap was not rolled back: %+v", keys.Keys)
	}

	singleValue := json.RawMessage(`{"ok":true}`)
	payload, err := json.Marshal(map[string]json.RawMessage{"x": singleValue})
	if err != nil {
		t.Fatal(err)
	}
	server = openServer(t)
	server.maxStateKeys = 4
	server.maxStateBytes = len(payload)
	if response := put("x", string(singleValue)); response.Error != nil {
		t.Fatalf("bounded byte put: %+v", response.Error)
	}
	if response := put("y", string(singleValue)); response.Error == nil || response.Error.Code != -32001 {
		t.Fatalf("state byte cap response = %+v", response.Error)
	}
}

func TestConcurrentStateOperationsRemainConsistent(t *testing.T) {
	server := openServer(t)
	var wait sync.WaitGroup
	for index := 0; index < 16; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			request := []byte(`{"jsonrpc":"2.0","id":"put","method":"runtime.v1.state.put","params":{"key":"worker/` + string(rune('a'+index)) + `","value":{"ok":true}}}`)
			if response := server.Handle(request); response.Error != nil {
				t.Errorf("put %d: %+v", index, response.Error)
			}
		}(index)
	}
	wait.Wait()
	response := server.Handle([]byte(`{"jsonrpc":"2.0","id":"list","method":"runtime.v1.state.list","params":{}}`))
	if response.Error != nil {
		t.Fatal(response.Error)
	}
	var list StateList
	if err := json.Unmarshal(response.Result, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Keys) != 16 {
		t.Fatalf("keys = %d, want 16", len(list.Keys))
	}
}

func TestRuntimeRejectsUnknownFieldsAndMethods(t *testing.T) {
	server := openServer(t)
	for _, request := range []string{
		`{"jsonrpc":"2.0","id":"1","method":"runtime.v1.state.get","params":{"key":"x","extra":true}}`,
		`{"jsonrpc":"2.0","id":"2","method":"runtime.v2.ping","params":{}}`,
		`{"jsonrpc":"2.0","id":"3","method":"runtime.v1.edge.request","params":{"method":"POST","path":"/v1/edge/request","body":{}}}`,
	} {
		if response := server.Handle([]byte(request)); response.Error == nil {
			t.Fatalf("request unexpectedly accepted: %s", request)
		}
	}
}

func claim(t *testing.T, server *Server, nonce string, expiresAt int64) bool {
	t.Helper()
	params := json.RawMessage(fmt.Sprintf(`{"expires_at_epoch":%d,"nonce":%q}`, expiresAt, nonce))
	response := server.Handle(mustRequest(t, "runtime.v1.auth.nonce.claim", params))
	if response.Error != nil {
		t.Fatalf("claim %s: %+v", nonce, response.Error)
	}
	var result NonceClaimResult
	if err := json.Unmarshal(response.Result, &result); err != nil {
		t.Fatal(err)
	}
	return result.Accepted
}

func journalLines(t *testing.T, server *Server) int {
	t.Helper()
	payload, err := os.ReadFile(server.noncePath())
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Count(payload, []byte{'\n'})
}

func TestNonceClaimIsAtomicAndDurableAcrossRestart(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	server, err := Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	expiresAt := time.Now().UTC().Add(time.Minute).Unix()
	for index, want := range []bool{true, false} {
		if got := claim(t, server, "abcdefghijklmnopqrstuvwx", expiresAt); got != want {
			t.Fatalf("claim %d accepted=%v want=%v", index, got, want)
		}
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	recovered, err := Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	if claim(t, recovered, "abcdefghijklmnopqrstuvwx", expiresAt) {
		t.Fatal("replayed nonce was accepted after restart")
	}
	if !claim(t, recovered, "fresh-after-restart", expiresAt) {
		t.Fatal("fresh nonce rejected after restart")
	}
}

func TestExpiredNoncesArePrunedAndNeverAccumulate(t *testing.T) {
	server := openServer(t)
	clock := time.Unix(1_700_000_000, 0).UTC()
	server.Now = func() time.Time { return clock }
	server.minimumWatermark, server.pruneWatermark = 8, 8
	if claim(t, server, "already-expired", clock.Unix()) {
		t.Fatal("nonce that already expired was accepted")
	}
	for index := 0; index < 64; index++ {
		if !claim(t, server, fmt.Sprintf("nonce-%02d", index), clock.Unix()+12) {
			t.Fatalf("fresh nonce %d rejected", index)
		}
		clock = clock.Add(time.Second)
	}
	server.mu.Lock()
	live := len(server.nonces)
	server.mu.Unlock()
	if live >= 32 {
		t.Fatalf("replay set holds %d nonces after 64 claims over 64 seconds with a 12 second lifetime", live)
	}
	if !claim(t, server, "nonce-00", clock.Unix()+12) {
		t.Fatal("a nonce whose lifetime has fully elapsed must be claimable again")
	}
	if claim(t, server, "nonce-63", clock.Unix()+12) {
		t.Fatal("a live nonce was accepted twice")
	}
}

func TestReplayJournalIsCompactedInsteadOfGrowingWithoutBound(t *testing.T) {
	server := openServer(t)
	clock := time.Unix(1_700_000_000, 0).UTC()
	server.Now = func() time.Time { return clock }
	server.minimumWatermark, server.pruneWatermark = 8, 8
	total := 2*journalSlack + 512
	for index := 0; index < total; index++ {
		if !claim(t, server, fmt.Sprintf("nonce-%05d", index), clock.Unix()+2) {
			t.Fatalf("fresh nonce %d rejected", index)
		}
		clock = clock.Add(time.Second)
	}
	server.mu.Lock()
	live := len(server.nonces)
	server.mu.Unlock()
	if lines := journalLines(t, server); lines > 2*live+journalSlack {
		t.Fatalf("journal holds %d records for %d live nonces", lines, live)
	}
	if lines := journalLines(t, server); lines >= total {
		t.Fatalf("journal was never compacted: %d records after %d claims", lines, total)
	}
}

func TestNonceClaimRejectsDistantExpiryAndLiveSetCap(t *testing.T) {
	server := openServer(t)
	clock := time.Unix(1_700_000_000, 0).UTC()
	server.Now = func() time.Time { return clock }
	server.maxLiveNonces = 2
	server.maxNonceLifetime = 20 * time.Second
	if claim(t, server, "far-future", clock.Unix()+21) {
		t.Fatal("nonce with excessive lifetime was accepted")
	}
	if !claim(t, server, "nonce-a", clock.Unix()+20) {
		t.Fatal("first bounded nonce was rejected")
	}
	if !claim(t, server, "nonce-b", clock.Unix()+20) {
		t.Fatal("second bounded nonce was rejected")
	}
	if claim(t, server, "nonce-c", clock.Unix()+20) {
		t.Fatal("nonce accepted past the live replay set cap")
	}
	clock = clock.Add(21 * time.Second)
	if !claim(t, server, "nonce-c", clock.Unix()+20) {
		t.Fatal("expired replay keys were not pruned before enforcing the live cap")
	}
}

func TestNonceRecoveryRejectsExcessiveLifetimeAndLiveSetCap(t *testing.T) {
	writeJournal := func(t *testing.T, directory string, records []nonceRecord) {
		t.Helper()
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		var buffer bytes.Buffer
		for _, record := range records {
			payload, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			buffer.Write(payload)
			buffer.WriteByte('\n')
		}
		if err := os.WriteFile(filepath.Join(directory, "nonces.v1.log"), buffer.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	distant := filepath.Join(t.TempDir(), "distant")
	writeJournal(t, distant, []nonceRecord{{Nonce: "too-long", ExpiresAtEpoch: time.Now().UTC().Add(maxNonceLifetime + time.Second).Unix()}})
	if _, err := Open(distant); err == nil {
		t.Fatal("replay journal with excessive nonce lifetime was accepted")
	}

	overCap := filepath.Join(t.TempDir(), "over-cap")
	records := make([]nonceRecord, 0, maxLiveNonces+1)
	expiry := time.Now().UTC().Add(time.Minute).Unix()
	for index := 0; index < maxLiveNonces+1; index++ {
		records = append(records, nonceRecord{
			Nonce:          fmt.Sprintf("nonce-%05d", index),
			ExpiresAtEpoch: expiry,
		})
	}
	writeJournal(t, overCap, records)
	if _, err := Open(overCap); err == nil {
		t.Fatal("replay journal above the live nonce cap was accepted")
	}
}

func TestTornTrailingReplayRecordIsDroppedAtRecovery(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	server, err := Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	expiresAt := time.Now().UTC().Add(time.Minute).Unix()
	if !claim(t, server, "committed", expiresAt) {
		t.Fatal("initial claim rejected")
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	journal, err := os.OpenFile(filepath.Join(directory, "nonces.v1.log"), os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Write([]byte(`{"nonce":"torn","expires_at_ep`)); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	recovered, err := Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	if claim(t, recovered, "committed", expiresAt) {
		t.Fatal("committed nonce was lost by recovery")
	}
	if !claim(t, recovered, "torn", expiresAt) {
		t.Fatal("torn, never-acknowledged nonce was treated as claimed")
	}
	corrupted := filepath.Join(directory, "nonces.v1.log")
	if err := recovered.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(corrupted, []byte(fmt.Sprintf("{\"nonce\":\"a\",\"expires_at_epoch\":%d}\nnot json\n{\"nonce\":\"b\",\"expires_at_epoch\":%d}\n", expiresAt, expiresAt)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(directory); err == nil {
		t.Fatal("corrupt interior replay record was accepted")
	}
}
