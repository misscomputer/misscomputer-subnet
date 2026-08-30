// SPDX-License-Identifier: AGPL-3.0-only

package runtimeapi

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	maxStateKeys     = 4096
	maxStateBytes    = 8 << 20
	maxLiveNonces    = 8192
	maxNonceLifetime = 10 * time.Minute
	// minimumPruneWatermark bounds how often the replay set is swept: expired
	// nonces are dropped whenever the live set reaches the watermark, which is
	// then reset to twice the surviving size. Sweeps therefore cost O(1)
	// amortized per claim and the set never grows past twice its live size.
	minimumPruneWatermark = 1024
	// journalSlack is the number of appended records tolerated beyond the live
	// replay set before the append-only journal is compacted.
	journalSlack = 1024
)

// Server owns the runtime state directory: generic operator state, the
// durable bridge replay set, and the control plane installed by the runtime
// command. Every mutation is durable before it is acknowledged.
type Server struct {
	mu               sync.Mutex
	state            map[string]json.RawMessage
	nonces           map[string]int64
	journal          *os.File
	journalRecords   int
	maxStateKeys     int
	maxStateBytes    int
	maxLiveNonces    int
	maxNonceLifetime time.Duration
	// minimumWatermark and pruneWatermark implement the amortized sweep; the
	// minimum is a field only so regression tests can exercise the bound.
	minimumWatermark int
	pruneWatermark   int
	stateDir         string
	lockFile         *os.File

	// Control receives every typed control operation as an in-process HTTP
	// request. The runtime command installs the control plane before serving;
	// until then control operations fail closed.
	Control http.Handler
	// Now is the clock used for replay expiry. It is overridable for tests.
	Now func() time.Time
}

type nonceRecord struct {
	Nonce          string `json:"nonce"`
	ExpiresAtEpoch int64  `json:"expires_at_epoch"`
}

func Open(stateDir string) (*Server, error) {
	if !filepath.IsAbs(stateDir) || filepath.Clean(stateDir) != stateDir {
		return nil, errors.New("runtime state directory must be a normalized absolute path")
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("create runtime state directory: %w", err)
	}
	if err := os.Chmod(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("secure runtime state directory: %w", err)
	}
	lockFile, err := os.OpenFile(filepath.Join(stateDir, "runtime.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open runtime lock: %w", err)
	}
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lockFile.Close()
		return nil, errors.New("another public runtime owns this state directory")
	}
	server := &Server{
		state: make(map[string]json.RawMessage), nonces: make(map[string]int64),
		maxStateKeys: maxStateKeys, maxStateBytes: maxStateBytes, maxLiveNonces: maxLiveNonces, maxNonceLifetime: maxNonceLifetime,
		minimumWatermark: minimumPruneWatermark, pruneWatermark: minimumPruneWatermark, stateDir: stateDir, lockFile: lockFile,
	}
	if payload, err := os.ReadFile(server.statePath()); err == nil {
		if err := json.Unmarshal(payload, &server.state); err != nil {
			_ = server.Close()
			return nil, fmt.Errorf("recover runtime state: %w", err)
		}
		if _, err := server.marshalBoundedStateLocked(); err != nil {
			_ = server.Close()
			return nil, fmt.Errorf("recover runtime state: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		_ = server.Close()
		return nil, fmt.Errorf("read runtime state: %w", err)
	}
	if err := server.recoverNonces(); err != nil {
		_ = server.Close()
		return nil, fmt.Errorf("recover runtime replay journal: %w", err)
	}
	return server, nil
}

func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var first error
	if s.journal != nil {
		first = s.journal.Close()
		s.journal = nil
	}
	if s.lockFile == nil {
		return first
	}
	err := syscall.Flock(int(s.lockFile.Fd()), syscall.LOCK_UN)
	closeErr := s.lockFile.Close()
	s.lockFile = nil
	if first != nil {
		return first
	}
	if err != nil {
		return err
	}
	return closeErr
}

func (s *Server) Serve(listener net.Listener) error {
	for {
		connection, err := listener.Accept()
		if err != nil {
			return err
		}
		go s.serveConnection(connection)
	}
}

func (s *Server) serveConnection(connection net.Conn) {
	defer connection.Close()
	reader := bufio.NewReader(io.LimitReader(connection, MaxMessageBytes+1))
	payload, err := reader.ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return
	}
	if len(payload) > MaxMessageBytes {
		return
	}
	response := s.Handle(bytes.TrimSpace(payload))
	encoded, _ := json.Marshal(response)
	encoded = append(encoded, '\n')
	_, _ = connection.Write(encoded)
}

func (s *Server) Handle(payload []byte) Response {
	response := Response{JSONRPC: "2.0"}
	var request Request
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || request.JSONRPC != "2.0" || request.ID == "" {
		response.Error = &Error{Code: -32600, Message: "invalid request"}
		return response
	}
	if err := requireJSONEOF(decoder); err != nil {
		response.Error = &Error{Code: -32600, Message: "invalid request"}
		return response
	}
	response.ID = request.ID
	result, rpcError := s.dispatch(request.Method, request.Params)
	response.Result, response.Error = result, rpcError
	return response
}

func (s *Server) dispatch(method string, params json.RawMessage) (json.RawMessage, *Error) {
	switch method {
	case "runtime.v1.ping":
		return marshalResult(Ping{Protocol: ProtocolVersion})
	case "runtime.v1.state.get":
		var input StateKey
		if err := decodeParams(params, &input); err != nil || !validKey(input.Key) {
			return nil, invalidParams()
		}
		s.mu.Lock()
		value, found := s.state[input.Key]
		result := StateValue{Found: found, Value: cloneRaw(value)}
		s.mu.Unlock()
		return marshalResult(result)
	case "runtime.v1.state.list":
		s.mu.Lock()
		keys := make([]string, 0, len(s.state))
		for key := range s.state {
			keys = append(keys, key)
		}
		s.mu.Unlock()
		sort.Strings(keys)
		return marshalResult(StateList{Keys: keys})
	case "runtime.v1.state.put":
		var input StatePut
		if err := decodeParams(params, &input); err != nil || !validKey(input.Key) {
			return nil, invalidParams()
		}
		canonicalValue, err := canonicalJSON(input.Value)
		if err != nil || !bytes.Equal(input.Value, canonicalValue) {
			return nil, invalidParams()
		}
		s.mu.Lock()
		old, existed := s.state[input.Key]
		s.state[input.Key] = cloneRaw(canonicalValue)
		err = s.persistStateLocked()
		if err != nil {
			if existed {
				s.state[input.Key] = old
			} else {
				delete(s.state, input.Key)
			}
		}
		s.mu.Unlock()
		if err != nil {
			if errors.Is(err, errStateLimitExceeded) {
				return nil, &Error{Code: -32001, Message: "runtime state limit exceeded"}
			}
			return nil, &Error{Code: -32000, Message: "state persistence failed"}
		}
		return marshalResult(StateValue{Found: true, Value: input.Value})
	case "runtime.v1.state.delete":
		var input StateKey
		if err := decodeParams(params, &input); err != nil || !validKey(input.Key) {
			return nil, invalidParams()
		}
		s.mu.Lock()
		old, found := s.state[input.Key]
		delete(s.state, input.Key)
		err := s.persistStateLocked()
		if err != nil && found {
			s.state[input.Key] = old
		}
		s.mu.Unlock()
		if err != nil {
			return nil, &Error{Code: -32000, Message: "state persistence failed"}
		}
		return marshalResult(StateValue{Found: found})
	case "runtime.v1.auth.nonce.claim":
		var input NonceClaim
		if err := decodeParams(params, &input); err != nil || !validKey(input.Nonce) || input.ExpiresAtEpoch <= 0 {
			return nil, invalidParams()
		}
		accepted, err := s.claimNonce(input.Nonce, input.ExpiresAtEpoch)
		if err != nil {
			return nil, &Error{Code: -32000, Message: "state persistence failed"}
		}
		return marshalResult(NonceClaimResult{Accepted: accepted})
	default:
		var input ControlRequest
		if err := decodeParams(params, &input); err != nil {
			return nil, invalidParams()
		}
		if expected := controlRPCMethod(input.Method, input.Path); expected == "" || expected != method {
			return nil, &Error{Code: -32601, Message: "method not found"}
		}
		result, err := s.handleControl(input)
		if err != nil {
			return nil, err
		}
		return marshalResult(result)
	}
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// claimNonce durably reserves one bridge nonce until its expiry. Expired
// nonces are swept in amortized constant time and the append-only journal is
// compacted when it exceeds twice the live set, so neither memory nor disk
// grows with request volume.
func (s *Server) claimNonce(nonce string, expiresAt int64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().Unix()
	if expiresAt <= now {
		return false, nil
	}
	if expiresAt > now+int64(s.maxNonceLifetime.Seconds()) {
		return false, nil
	}
	if _, exists := s.nonces[nonce]; exists {
		return false, nil
	}
	s.pruneExpiredLocked(now)
	if len(s.nonces) >= s.maxLiveNonces {
		return false, nil
	}
	if err := s.appendNonceLocked(nonceRecord{Nonce: nonce, ExpiresAtEpoch: expiresAt}); err != nil {
		return false, err
	}
	s.nonces[nonce] = expiresAt
	return true, nil
}

func (s *Server) pruneExpiredLocked(now int64) {
	if len(s.nonces) < s.pruneWatermark && len(s.nonces) < s.maxLiveNonces {
		return
	}
	for nonce, expiry := range s.nonces {
		if expiry <= now {
			delete(s.nonces, nonce)
		}
	}
	s.pruneWatermark = max(s.minimumWatermark, 2*len(s.nonces))
}

func (s *Server) appendNonceLocked(record nonceRecord) error {
	if s.journal == nil {
		return errors.New("replay journal is closed")
	}
	if s.journalRecords >= 2*len(s.nonces)+journalSlack {
		if err := s.compactNoncesLocked(); err != nil {
			return err
		}
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	if _, err := s.journal.Write(payload); err != nil {
		// A partial record may now terminate the journal; rewrite it from the
		// in-memory set so the next append never follows a torn line.
		_ = s.compactNoncesLocked()
		return err
	}
	if err := s.journal.Sync(); err != nil {
		return err
	}
	s.journalRecords++
	return nil
}

func (s *Server) recoverNonces() error {
	now := s.now().Unix()
	payload, err := os.ReadFile(s.noncePath())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	lines := bytes.Split(payload, []byte{'\n'})
	for index, line := range lines {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var record nonceRecord
		if decodeErr := json.Unmarshal(line, &record); decodeErr != nil || !validKey(record.Nonce) || record.ExpiresAtEpoch <= 0 {
			if index == len(lines)-1 {
				// Only the final record may be torn by a crash mid-append; the
				// claim it described was never acknowledged.
				break
			}
			return errors.New("corrupt replay record")
		}
		if record.ExpiresAtEpoch <= now {
			continue
		}
		if record.ExpiresAtEpoch > now+int64(s.maxNonceLifetime.Seconds()) {
			return errors.New("replay record exceeds maximum lifetime")
		}
		if _, exists := s.nonces[record.Nonce]; !exists {
			if len(s.nonces) >= s.maxLiveNonces {
				return errors.New("replay journal exceeds live nonce limit")
			}
		}
		s.nonces[record.Nonce] = record.ExpiresAtEpoch
	}
	return s.compactNoncesLocked()
}

// compactNoncesLocked atomically rewrites the journal from the live replay set
// and reopens it for appends.
func (s *Server) compactNoncesLocked() error {
	if s.journal != nil {
		_ = s.journal.Close()
		s.journal = nil
	}
	nonces := make([]string, 0, len(s.nonces))
	for nonce := range s.nonces {
		nonces = append(nonces, nonce)
	}
	sort.Strings(nonces)
	var buffer bytes.Buffer
	for _, nonce := range nonces {
		payload, err := json.Marshal(nonceRecord{Nonce: nonce, ExpiresAtEpoch: s.nonces[nonce]})
		if err != nil {
			return err
		}
		buffer.Write(payload)
		buffer.WriteByte('\n')
	}
	if err := s.writeAtomically(s.noncePath(), ".nonces-v1-", buffer.Bytes()); err != nil {
		return err
	}
	journal, err := os.OpenFile(s.noncePath(), os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	s.journal = journal
	s.journalRecords = len(s.nonces)
	return nil
}

func (s *Server) statePath() string { return filepath.Join(s.stateDir, "state.v1.json") }

func (s *Server) noncePath() string { return filepath.Join(s.stateDir, "nonces.v1.log") }

// persistStateLocked rewrites the generic operator state document. It runs
// only for explicit state mutations, never on the per-request control or
// replay paths.
func (s *Server) persistStateLocked() error {
	payload, err := s.marshalBoundedStateLocked()
	if err != nil {
		return err
	}
	return s.writeAtomically(s.statePath(), ".state-v1-", append(payload, '\n'))
}

var errStateLimitExceeded = errors.New("runtime state limit exceeded")

func (s *Server) marshalBoundedStateLocked() ([]byte, error) {
	if len(s.state) > s.maxStateKeys {
		return nil, errStateLimitExceeded
	}
	payload, err := json.Marshal(s.state)
	if err != nil {
		return nil, err
	}
	if len(payload) > s.maxStateBytes {
		return nil, errStateLimitExceeded
	}
	return payload, nil
}

func (s *Server) writeAtomically(path, prefix string, payload []byte) error {
	temporary, err := os.CreateTemp(s.stateDir, prefix)
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	directory, err := os.Open(s.stateDir)
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func validKey(value string) bool {
	if value == "" || len(value) > 256 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func decodeParams(payload json.RawMessage, output any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

func canonicalJSON(payload json.RawMessage) (json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return encoded, nil
}

func cloneRaw(value json.RawMessage) json.RawMessage {
	if value == nil {
		return nil
	}
	return append(json.RawMessage(nil), value...)
}

func marshalResult(value any) (json.RawMessage, *Error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, &Error{Code: -32603, Message: "internal error"}
	}
	return payload, nil
}

func invalidParams() *Error { return &Error{Code: -32602, Message: "invalid params"} }
