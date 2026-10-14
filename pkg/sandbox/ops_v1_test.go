// SPDX-License-Identifier: AGPL-3.0-only

package sandbox_test

import (
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

// The exec payload is digest-bound bytes that two parsers must read the same
// way: strict members, no duplicates, no trailing data, and env {} (OPS-D1).
func TestDecodeExecCommand(t *testing.T) {
	good := `{"argv":["sh","-c","echo hi"],"cwd":"/","env":{},"stdin_b64":"aGk="}`
	command, err := sandbox.DecodeExecCommand([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if string(command.StdinBytes()) != "hi" || command.Argv[2] != "echo hi" {
		t.Fatalf("decoded %+v", command)
	}
	for name, payload := range map[string]string{
		"env value":          `{"argv":["sh"],"cwd":"/","env":{"API_KEY":"secret"},"stdin_b64":null}`,
		"env null":           `{"argv":["sh"],"cwd":"/","env":null,"stdin_b64":null}`,
		"missing stdin":      `{"argv":["sh"],"cwd":"/","env":{}}`,
		"unknown member":     `{"argv":["sh"],"cwd":"/","env":{},"stdin_b64":null,"tty":true}`,
		"duplicate member":   `{"argv":["sh"],"argv":["rm","-rf","/"],"cwd":"/","env":{},"stdin_b64":null}`,
		"nested duplicate":   `{"argv":["sh"],"cwd":"/","env":{"A":"1","A":"2"},"stdin_b64":null}`,
		"trailing data":      `{"argv":["sh"],"cwd":"/","env":{},"stdin_b64":null} {}`,
		"empty argv":         `{"argv":[],"cwd":"/","env":{},"stdin_b64":null}`,
		"empty program":      `{"argv":[""],"cwd":"/","env":{},"stdin_b64":null}`,
		"NUL in argument":    `{"argv":["sh","a\u0000b"],"cwd":"/","env":{},"stdin_b64":null}`,
		"relative cwd":       `{"argv":["sh"],"cwd":"tmp","env":{},"stdin_b64":null}`,
		"non-canonical b64":  `{"argv":["sh"],"cwd":"/","env":{},"stdin_b64":"aGk"}`,
		"array not object":   `[]`,
		"oversized argument": `{"argv":["` + strings.Repeat("a", sandbox.MaxExecArgBytes+1) + `"],"cwd":"/","env":{},"stdin_b64":null}`,
	} {
		if _, err := sandbox.DecodeExecCommand([]byte(payload)); err == nil {
			t.Errorf("%s payload accepted", name)
		}
	}
}
