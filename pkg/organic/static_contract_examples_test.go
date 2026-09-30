// SPDX-License-Identifier: AGPL-3.0-only

package organic_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/misscomputer/misscomputer-subnet/pkg/organic"
)

// The static-site contract's worked examples (§3.5 manifest and site_digest,
// §5.5 normative header digest, §7.1 release signature and release_digest),
// reproduced with the shared Go canonical helpers. The Python validator
// asserts the same literals in tests/python/test_static_index.py, so both
// languages and the contract text agree byte for byte.
const (
	staticContractManifest         = `{"fallback":{"kind":"spa-html-v1","target":"/index.html"},"files":[{"body_sha256":"f9444510dc7403e41049deb133f6892aa6a63c05591b2b59e4ee5b234d7bbd99","content_length":22,"content_type":"text/javascript; charset=utf-8","path":"/assets/app.js"},{"body_sha256":"4ada0f02c1764cbf47214c80ddc1f17d4eafc571f4c82fe71774b70fb65f87d9","content_length":35,"content_type":"text/html; charset=utf-8","path":"/docs/index.html"},{"body_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","content_length":0,"content_type":"text/plain; charset=utf-8","path":"/empty.txt"},{"body_sha256":"d628d86f44c331c490330a6c091d656e960ce76f429eaa739196e598a75796c5","content_length":74,"content_type":"text/html; charset=utf-8","path":"/index.html"}],"handler":"static-handler.v1","schema":"miss.computer/misscomputer-subnet/static-site-manifest","schema_version":1}` + "\n"
	staticContractSite             = "sha256:9db3b2a4b3f18c1d31fd7d3348f83e1dfde21163d5aca540fd2f63d6b88ab77f"
	staticContractReleasePublicKey = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"
	staticContractReleaseSignature = "863218e208d2059d71bcfca2105c946b1755c8209f1a53f00343be4fabdcdebf002349fa0b331f4147c424fb2916d1d403eff7216b984db678b858bbd164b208"
	staticContractReleaseDigest    = "sha256:9b96232b299069fe8b2dc546f9db0943c43dfefb48f79d15d28ee7b28a031830"
	staticContractGetRootHeaders   = "b830308c459ff241874e1e9b218a44b7161985c4005cdd824573f3a4677eed05"
)

func staticStoredDigest(stored []byte) string {
	sum := sha256.Sum256(stored)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func TestStaticContractWorkedExamplesMatchGoCanonicalBytes(t *testing.T) {
	files := []struct {
		path, contentType string
		body              []byte
	}{
		{"/assets/app.js", "text/javascript; charset=utf-8", []byte("console.log(\"hello\");\n")},
		{"/docs/index.html", "text/html; charset=utf-8", []byte("<!doctype html><title>docs</title>\n")},
		{"/empty.txt", "text/plain; charset=utf-8", []byte{}},
		{"/index.html", "text/html; charset=utf-8", []byte("<!doctype html><title>hello</title><script src=\"/assets/app.js\"></script>\n")},
	}
	entries := make([]map[string]any, len(files))
	for index, file := range files {
		sum := sha256.Sum256(file.body)
		entries[index] = map[string]any{
			"body_sha256":    hex.EncodeToString(sum[:]),
			"content_length": len(file.body),
			"content_type":   file.contentType,
			"path":           file.path,
		}
	}
	manifest, err := organic.CanonicalBytes(map[string]any{
		"fallback":       map[string]any{"kind": "spa-html-v1", "target": "/index.html"},
		"files":          entries,
		"handler":        "static-handler.v1",
		"schema":         "miss.computer/misscomputer-subnet/static-site-manifest",
		"schema_version": 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(manifest) != staticContractManifest || len(manifest) != 861 {
		t.Fatalf("manifest bytes differ from the contract:\n%s", manifest)
	}
	if got := staticStoredDigest(manifest); got != staticContractSite {
		t.Fatalf("site_digest = %s", got)
	}

	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x07}, ed25519.SeedSize))
	if got := hex.EncodeToString(key.Public().(ed25519.PublicKey)); got != staticContractReleasePublicKey {
		t.Fatalf("release public key = %s", got)
	}
	release := map[string]any{
		"issued_at":                    "2026-09-30T00:00:00Z",
		"producer_policy_version":      "static-producer-policy.v1",
		"schema":                       "miss.computer/misscomputer-subnet/static-site-release",
		"schema_version":               1,
		"server_implementation_digest": "sha256:" + string(bytes.Repeat([]byte("ab"), 32)),
		"signer_key_id":                "static-release-example",
		"site_digest":                  staticContractSite,
	}
	unsigned, err := organic.Canonical(release)
	if err != nil {
		t.Fatal(err)
	}
	message := append([]byte("miss.computer/misscomputer-subnet/static-site-release/v1/ed25519\x00"), unsigned...)
	signature := hex.EncodeToString(ed25519.Sign(key, message))
	if signature != staticContractReleaseSignature {
		t.Fatalf("release signature = %s", signature)
	}
	release["signature"] = signature
	signed, err := organic.CanonicalBytes(release)
	if err != nil {
		t.Fatal(err)
	}
	if got := staticStoredDigest(signed); got != staticContractReleaseDigest {
		t.Fatalf("release_digest = %s", got)
	}

	headers, err := organic.ResponseHeaderSHA256([][2]string{
		{"Content-Type", "text/html; charset=utf-8"},
		{"X-Content-Type-Options", "nosniff"},
		{"Cache-Control", "private, no-store"},
		{"Content-Length", "74"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if headers != staticContractGetRootHeaders {
		t.Fatalf("GET / normative header digest = %s", headers)
	}
}
