// SPDX-License-Identifier: AGPL-3.0-only

package sandbox_test

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/misscomputer/misscomputer-subnet/pkg/sandbox"
)

func TestValidOpPath(t *testing.T) {
	for path, allowRoot := range map[string]bool{
		"/":                            true,
		"/workspace/main.py":           false,
		"/a b/c-d_e.f~":                false,
		"/" + strings.Repeat("x", 255): false,
		"/.hidden/..dots/...":          false,
	} {
		if err := sandbox.ValidOpPath(path, allowRoot); err != nil {
			t.Errorf("%q refused: %v", path, err)
		}
	}
	for name, path := range map[string]string{
		"empty":              "",
		"relative":           "workspace",
		"root where barred":  "/",
		"dot-dot":            "/workspace/../etc",
		"leading dot-dot":    "/..",
		"dot":                "/workspace/./x",
		"empty component":    "/workspace//x",
		"trailing slash":     "/workspace/",
		"NUL":                "/work\x00space",
		"newline":            "/work\nspace",
		"DEL":                "/work\x7fspace",
		"non-ASCII":          "/caf\xc3\xa9",
		"component over 255": "/" + strings.Repeat("x", 256),
		"path over 4096":     strings.Repeat("/abcdefg", 513),
	} {
		if sandbox.ValidOpPath(path, false) == nil {
			t.Errorf("%s path %q accepted", name, path)
		}
	}
}

// The exec payload is digest-bound bytes that every reader must decode to
// the same members. The vectors are the cross-language contract: case-variant
// or duplicate member names, invalid UTF-8 or lone surrogates, non-canonical
// base64 and per-exec env must all be refused (lane 7 SR-28-01, SR-28-02).
func TestExecPayloadVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "sandbox-ops-v1-exec-payload-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Accept []struct {
			Name       string   `json:"name"`
			PayloadB64 string   `json:"payload_b64"`
			Argv       []string `json:"argv"`
			Cwd        string   `json:"cwd"`
			Stdin      *string  `json:"stdin_b64"`
		} `json:"accept"`
		Reject []struct {
			Name       string `json:"name"`
			PayloadB64 string `json:"payload_b64"`
		} `json:"reject"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Accept) == 0 || len(vectors.Reject) == 0 {
		t.Fatal("payload vectors are empty")
	}
	decode := func(name, encoded string) []byte {
		payload, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatalf("%s: vector payload_b64: %v", name, err)
		}
		return payload
	}
	for _, vector := range vectors.Accept {
		command, err := sandbox.DecodeExecCommand(decode(vector.Name, vector.PayloadB64))
		if err != nil {
			t.Errorf("accept %q refused: %v", vector.Name, err)
			continue
		}
		if !slices.Equal(command.Argv, vector.Argv) || command.Cwd != vector.Cwd || len(command.Env) != 0 ||
			(command.Stdin == nil) != (vector.Stdin == nil) || (command.Stdin != nil && *command.Stdin != *vector.Stdin) {
			t.Errorf("accept %q decoded %+v", vector.Name, command)
		}
	}
	for _, vector := range vectors.Reject {
		if command, err := sandbox.DecodeExecCommand(decode(vector.Name, vector.PayloadB64)); err == nil {
			t.Errorf("reject %q accepted as argv=%q cwd=%q", vector.Name, command.Argv, command.Cwd)
		}
	}
}

// Truncated or garbage input never panics the payload decoder.
func FuzzDecodeExecCommand(f *testing.F) {
	f.Add([]byte(`{"argv":["a"],"cwd":"/","env":{},"stdin_b64":null}`))
	f.Add([]byte(`{"argv":["\ud83d\ude00"],"cwd":"/","env":{},"stdin_b64":null} "\`))
	f.Add([]byte(`{"argv":["\ud83d\`))
	f.Fuzz(func(t *testing.T, payload []byte) {
		command, err := sandbox.DecodeExecCommand(payload)
		if err == nil && command.Validate() != nil {
			t.Fatal("decoded an invalid command")
		}
	})
}
