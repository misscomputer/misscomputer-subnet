// SPDX-License-Identifier: AGPL-3.0-only

package workload

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type Spec struct {
	Kind           string `json:"kind"`
	BuildID        string `json:"build_id"`
	ChallengePath  string `json:"challenge_path"`
	ChallengeValue string `json:"challenge_value"`
	PayloadBytes   int    `json:"payload_bytes"`
}

func Generate(kind string, payloadBytes int) (Spec, []byte, error) {
	return GenerateWithReader(kind, payloadBytes, rand.Reader)
}

// GenerateWithReader is the testable form of Generate. Production callers
// must pass a cryptographically secure reader; Generate does so by default.
func GenerateWithReader(kind string, payloadBytes int, entropy io.Reader) (Spec, []byte, error) {
	s, err := GenerateSpecWithReader(kind, payloadBytes, entropy)
	if err != nil {
		return Spec{}, nil, err
	}
	b, err := EncodeWithReader(s, entropy)
	if err != nil {
		return Spec{}, nil, err
	}
	return s, b, nil
}

// GenerateSpec creates the unpredictable build and hidden-challenge identity
// without materializing the potentially large unique workload layer.
func GenerateSpec(kind string, payloadBytes int) (Spec, error) {
	return GenerateSpecWithReader(kind, payloadBytes, rand.Reader)
}

// GenerateSpecWithReader is intended for deterministic tests and for callers
// that need to persist a workload contract before allocating its layer.
// Production callers must supply a cryptographically secure reader.
func GenerateSpecWithReader(kind string, payloadBytes int, entropy io.Reader) (Spec, error) {
	buildID, err := randomHex(entropy, 12)
	if err != nil {
		return Spec{}, err
	}
	challenge, err := randomHex(entropy, 32)
	if err != nil {
		return Spec{}, err
	}
	return Spec{
		Kind: kind, BuildID: buildID, ChallengePath: "/__challenge/" + buildID,
		ChallengeValue: challenge, PayloadBytes: payloadBytes,
	}, nil
}

// Encode materializes a previously generated Spec with cryptographically
// random padding.
func Encode(s Spec) ([]byte, error) {
	return EncodeWithReader(s, rand.Reader)
}

// EncodeWithReader materializes a previously generated Spec into the existing
// unique-layer wire format. Production callers must supply a cryptographically
// secure reader so padding remains a never-before-seen layer.
func EncodeWithReader(s Spec, entropy io.Reader) ([]byte, error) {
	encoded, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	if uint64(len(encoded)) > uint64(^uint32(0)) {
		return nil, fmt.Errorf("workload spec is too large")
	}
	b := make([]byte, 4+len(encoded))
	binary.BigEndian.PutUint32(b[:4], uint32(len(encoded)))
	copy(b[4:], encoded)
	if s.PayloadBytes > len(b) {
		if entropy == nil {
			return nil, fmt.Errorf("workload entropy source is required")
		}
		padding := make([]byte, s.PayloadBytes-len(b))
		if _, err := io.ReadFull(entropy, padding); err != nil {
			return nil, err
		}
		b = append(b, padding...)
	}
	return b, nil
}

func Decode(layer []byte) (Spec, error) {
	var s Spec
	if len(layer) < 4 {
		return Spec{}, fmt.Errorf("workload layer is truncated")
	}
	size := int(binary.BigEndian.Uint32(layer[:4]))
	if size <= 0 || size > len(layer)-4 {
		return Spec{}, fmt.Errorf("workload spec length is invalid")
	}
	if err := json.Unmarshal(layer[4:4+size], &s); err != nil {
		return Spec{}, fmt.Errorf("decode workload spec: %w", err)
	}
	return s, nil
}

func Handler(s Spec) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Build-ID", s.BuildID)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc(s.ChallengePath, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Build-ID", s.BuildID)
		_, _ = w.Write([]byte(s.ChallengeValue))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintf(w, "<!doctype html><title>%s</title><h1>%s</h1><p>build %s</p>", s.Kind, s.Kind, s.BuildID)
	})
	return mux
}

func Suite() []struct {
	Kind string
	Size int
} {
	return []struct {
		Kind string
		Size int
	}{{"static", 10 << 20}, {"node", 100 << 20}, {"python", 300 << 20}, {"heavy", 1 << 30}}
}

func randomHex(entropy io.Reader, n int) (string, error) {
	if entropy == nil {
		return "", fmt.Errorf("workload entropy source is required")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(entropy, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
