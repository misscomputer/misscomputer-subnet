// SPDX-License-Identifier: AGPL-3.0-only

package static_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
	"github.com/misscomputer/misscomputer-subnet/pkg/organic"
	"github.com/misscomputer/misscomputer-subnet/pkg/static"
)

func sha(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// The static-site contract §3.5 worked example.
var exampleBodies = map[string][]byte{
	"/index.html":      []byte("<!doctype html><title>hello</title><script src=\"/assets/app.js\"></script>\n"),
	"/assets/app.js":   []byte("console.log(\"hello\");\n"),
	"/docs/index.html": []byte("<!doctype html><title>docs</title>\n"),
	"/empty.txt":       {},
}

func exampleManifest(fallback bool) static.Manifest {
	m := static.Manifest{Handler: static.HandlerVersion, Schema: static.ManifestSchema, SchemaVersion: 1}
	for _, path := range []string{"/assets/app.js", "/docs/index.html", "/empty.txt", "/index.html"} {
		body := exampleBodies[path]
		m.Files = append(m.Files, static.File{
			BodySHA256: sha(body), ContentLength: int64(len(body)), ContentType: static.ContentTypeFor(path), Path: path,
		})
	}
	if fallback {
		m.Fallback = &static.Fallback{Kind: static.FallbackKind, Target: "/index.html"}
	}
	return m
}

type memoryBodies map[string][]byte

func (b memoryBodies) Open(file static.File) (io.ReadCloser, error) {
	body, ok := b[file.BodySHA256]
	if !ok {
		return nil, os.ErrNotExist
	}
	return io.NopCloser(bytes.NewReader(body)), nil
}

func exampleBodySource() memoryBodies {
	bodies := memoryBodies{}
	for _, body := range exampleBodies {
		bodies[sha(body)] = body
	}
	return bodies
}

// The stored manifest bytes and site digest are the cross-implementation
// identity; the contract fixes them for §3.5.
func TestContractWorkedExampleIdentity(t *testing.T) {
	stored, digest, err := static.Encode(exampleManifest(true))
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 861 || digest != "sha256:9db3b2a4b3f18c1d31fd7d3348f83e1dfde21163d5aca540fd2f63d6b88ab77f" {
		t.Fatalf("stored %d bytes, digest %s", len(stored), digest)
	}
	if _, err := static.Parse(stored, digest); err != nil {
		t.Fatal(err)
	}
	response := static.NewIndex(exampleManifest(true)).Resolve(http.MethodGet, "/", false)
	if got, _ := response.HeaderSHA256(); got != "b830308c459ff241874e1e9b218a44b7161985c4005cdd824573f3a4677eed05" {
		t.Fatalf("GET / response_header_sha256 = %s", got)
	}
}

type rawResponse struct {
	status int
	header http.Header
	body   []byte
}

// rawRequest writes target byte-exact, bypassing client URL normalization.
func rawRequest(t *testing.T, address, method, target, host, headers, payload string) rawResponse {
	t.Helper()
	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, method+" "+target+" HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n"+headers+"\r\n"+payload); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: method})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return rawResponse{status: response.StatusCode, header: response.Header, body: body}
}

// The §6 vectors, executed over a real socket against the reusable origin
// adapter. Every row also checks the exact §5.2 header set.
func TestHandlerServesContractVectors(t *testing.T) {
	const host = "hello-k3j9x0q2ab.on.miss.computer"
	idx := exampleBodies["/index.html"]
	doc := exampleBodies["/docs/index.html"]
	js := exampleBodies["/assets/app.js"]
	notFound, badRequest := []byte("Not Found\n"), []byte("Bad Request\n")
	const html, text = "text/html; charset=utf-8", "text/plain; charset=utf-8"
	long := "/" + strings.TrimSuffix(strings.Repeat(strings.Repeat("a", 204)+"/", 5), "/")
	type vector struct {
		name, method, target, host, extra, payload string
		fallback                                   bool
		status                                     int
		contentType                                string
		body                                       []byte
		length                                     int
	}
	bad := func(name, target string) vector {
		return vector{name: name, method: "GET", target: target, fallback: true, status: 400, contentType: text, body: badRequest, length: 12}
	}
	vectors := []vector{
		{name: "V01", method: "GET", target: "/", fallback: true, status: 200, contentType: html, body: idx, length: 74},
		{name: "V02", method: "HEAD", target: "/", fallback: true, status: 200, contentType: html, body: nil, length: 74},
		{name: "V03", method: "GET", target: "/index.html", fallback: true, status: 200, contentType: html, body: idx, length: 74},
		{name: "V04", method: "GET", target: "/assets/app.js", fallback: true, status: 200, contentType: "text/javascript; charset=utf-8", body: js, length: 22},
		{name: "V05", method: "GET", target: "/docs/", fallback: true, status: 200, contentType: html, body: doc, length: 35},
		{name: "V06", method: "GET", target: "/docs/index.html", fallback: true, status: 200, contentType: html, body: doc, length: 35},
		{name: "V07", method: "GET", target: "/empty.txt", fallback: true, status: 200, contentType: text, body: nil, length: 0},
		{name: "V08", method: "GET", target: "/docs", fallback: true, status: 200, contentType: html, body: idx, length: 74},
		{name: "V08-nofb", method: "GET", target: "/docs", status: 404, contentType: text, body: notFound, length: 10},
		{name: "V09", method: "GET", target: "/about/team", fallback: true, status: 200, contentType: html, body: idx, length: 74},
		{name: "V09-nofb", method: "GET", target: "/about/team", status: 404, contentType: text, body: notFound, length: 10},
		{name: "V10", method: "GET", target: "/assets/", fallback: true, status: 200, contentType: html, body: idx, length: 74},
		{name: "V10-nofb", method: "GET", target: "/assets/", status: 404, contentType: text, body: notFound, length: 10},
		{name: "V11", method: "GET", target: "/missing.js", fallback: true, status: 404, contentType: text, body: notFound, length: 10},
		{name: "V12", method: "GET", target: "/Index.html", fallback: true, status: 404, contentType: text, body: notFound, length: 10},
		{name: "V13", method: "GET", target: "/caf%C3%A9", fallback: true, status: 200, contentType: html, body: idx, length: 74},
		{name: "V13-nofb", method: "GET", target: "/caf%C3%A9", status: 404, contentType: text, body: notFound, length: 10},
		{name: "V14", method: "GET", target: "/?q=1", fallback: true, status: 200, contentType: html, body: idx, length: 74},
		{name: "V15", method: "GET", target: "/index.html?v=2", fallback: true, status: 200, contentType: html, body: idx, length: 74},
		{name: "V16", method: "HEAD", target: "/missing.js", fallback: true, status: 404, contentType: text, body: nil, length: 10},
		{name: "V17", method: "POST", target: "/", fallback: true, status: 405, contentType: text, body: []byte("Method Not Allowed\n"), length: 19},
		{name: "V17-OPTIONS", method: "OPTIONS", target: "/", fallback: true, status: 405, contentType: text, body: []byte("Method Not Allowed\n"), length: 19},
		bad("V18", "/%69ndex.html"), bad("V19", "/a%2Fb"), bad("V20", "/a%2fb"), bad("V21", "/../index.html"),
		bad("V22", "/./index.html"), bad("V23", "/%2E%2E/"), bad("V24", "//index.html"), bad("V25", "/a%5Cb"),
		bad("V26-00", "/%00"), bad("V26-7F", "/%7F"), bad("V27", "/a|b"), bad("V28", "/caf%c3%a9"),
		bad("V30", long), bad("V31", strings.Repeat("/a", 33)),
		{name: "V30-at-limit", method: "GET", target: long[:len(long)-1], fallback: true, status: 200, contentType: html, body: idx, length: 74},
		{name: "V32", method: "GET", target: "/", extra: "Content-Length: 1\r\n", payload: "x", fallback: true, status: 400, contentType: text, body: badRequest, length: 12},
		{name: "V33", method: "GET", target: "/", host: "other.on.miss.computer", fallback: true, status: 421, contentType: text, body: []byte("Misdirected Request\n"), length: 20},
		{name: "V33-port", method: "GET", target: "/", host: "HELLO-k3j9x0q2ab.on.miss.computer:443", fallback: true, status: 200, contentType: html, body: idx, length: 74},
		{name: "V34", method: "GET", target: "/", extra: "Range: bytes=0-0\r\n", fallback: true, status: 200, contentType: html, body: idx, length: 74},
		{name: "V35", method: "GET", target: "/", extra: "Accept-Encoding: gzip\r\n", fallback: true, status: 200, contentType: html, body: idx, length: 74},
		{name: "V36", method: "GET", target: "/", extra: "If-None-Match: *\r\n", fallback: true, status: 200, contentType: html, body: idx, length: 74},
		{name: "V37", method: "GET", target: "/index.html/", fallback: true, status: 200, contentType: html, body: idx, length: 74},
		{name: "V37-nofb", method: "GET", target: "/index.html/", status: 404, contentType: text, body: notFound, length: 10},
	}
	servers := map[bool]*httptest.Server{}
	for _, fallback := range []bool{false, true} {
		handler := static.NewHandler(static.NewIndex(exampleManifest(fallback)), exampleBodySource(), host, 0)
		servers[fallback] = httptest.NewServer(handler)
		defer servers[fallback].Close()
	}
	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			requestHost := v.host
			if requestHost == "" {
				requestHost = host
			}
			got := rawRequest(t, servers[v.fallback].Listener.Addr().String(), v.method, v.target, requestHost, v.extra, v.payload)
			if got.status != v.status || !bytes.Equal(got.body, v.body) {
				t.Fatalf("status %d body %q, want %d %q", got.status, got.body, v.status, v.body)
			}
			want := http.Header{
				"Cache-Control": {"private, no-store"}, "Content-Type": {v.contentType},
				"Content-Length": {strconv.Itoa(v.length)}, "X-Content-Type-Options": {"nosniff"},
			}
			if v.status == 405 {
				want["Allow"] = []string{"GET, HEAD"}
			}
			got.header.Del("Connection")
			if len(got.header) != len(want) {
				t.Fatalf("headers %v, want exactly %v", got.header, want)
			}
			for name, values := range want {
				if strings.Join(got.header.Values(name), ",") != strings.Join(values, ",") {
					t.Fatalf("header %s = %q, want %q", name, got.header.Values(name), values)
				}
			}
		})
	}
	// V29: net/http refuses a bare "%" before any handler runs, so the
	// rule is enforced by the shared table itself (the edge answers it).
	if response := static.NewIndex(exampleManifest(true)).Resolve(http.MethodGet, "/100%", false); response.Status != 400 {
		t.Fatalf("V29 status %d", response.Status)
	}
}

// Every rule and limit is enforced on the verified bytes with the contract's
// attribution: a digest mismatch is the miner's, a verified invalid document
// is the platform's.
func TestParseRejectsManifestsWithAttributedCodes(t *testing.T) {
	encode := func(m static.Manifest) ([]byte, string) {
		stored, err := organic.CanonicalBytes(m)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(stored)
		return stored, "sha256:" + hex.EncodeToString(sum[:])
	}
	file := func(path string, size int64) static.File {
		return static.File{BodySHA256: strings.Repeat("a", 64), ContentLength: size, ContentType: static.ContentTypeFor(path), Path: path}
	}
	withFiles := func(files ...static.File) static.Manifest {
		m := exampleManifest(false)
		m.Files = files
		return m
	}
	index := file("/index.html", 1)
	many := make([]static.File, 0, static.MaxFiles+1)
	for i := 0; i < static.MaxFiles; i++ {
		many = append(many, file("/f"+fmt.Sprintf("%04d", i)+".txt", 0))
	}
	many = append(many, index)
	big := make([]static.File, 0, 17)
	for i := 0; i < 16; i++ {
		big = append(big, file("/b"+fmt.Sprintf("%02d", i)+".bin", static.MaxFileBytes))
	}
	big = append(big, file("/c.bin", 1), index)
	cases := []struct {
		name     string
		manifest static.Manifest
		mutate   func([]byte) []byte
		code     static.Code
	}{
		{"digest mismatch", exampleManifest(false), func(b []byte) []byte { return append(b[:len(b)-1], ' ', '\n') }, static.CodeVerifyFailed},
		{"handler", func() static.Manifest { m := exampleManifest(false); m.Handler = "static-handler.v2"; return m }(), nil, static.CodeManifestInvalid},
		{"unsorted", withFiles(index, file("/a.txt", 0)), nil, static.CodeManifestInvalid},
		{"missing index", withFiles(file("/a.txt", 0)), nil, static.CodeManifestInvalid},
		{"case fold collision", withFiles(file("/A.txt", 0), index, file("/a.txt", 0)), nil, static.CodeManifestInvalid},
		{"file directory collision", withFiles(file("/a", 0), file("/a/b.txt", 0), index), nil, static.CodeManifestInvalid},
		{"content type not policy", withFiles(static.File{BodySHA256: strings.Repeat("a", 64), ContentType: "text/html; charset=utf-8", Path: "/a.txt"}, index), nil, static.CodeManifestInvalid},
		{"escape other than space", withFiles(file("/a%21.txt", 0), index), nil, static.CodeManifestInvalid},
		{"non-ascii escape", withFiles(file("/caf%C3%A9.txt", 0), index), nil, static.CodeManifestInvalid},
		{"dot segment", withFiles(file("/../x.txt", 0), index), nil, static.CodeManifestInvalid},
		{"fallback not html", func() static.Manifest {
			m := exampleManifest(false)
			m.Fallback = &static.Fallback{Kind: static.FallbackKind, Target: "/assets/app.js"}
			return m
		}(), nil, static.CodeManifestInvalid},
		{"fallback kind", func() static.Manifest {
			m := exampleManifest(false)
			m.Fallback = &static.Fallback{Kind: "spa-any", Target: "/index.html"}
			return m
		}(), nil, static.CodeManifestInvalid},
		{"too many files", withFiles(many...), nil, static.CodeLimitsExceeded},
		{"file too large", withFiles(file("/a.bin", static.MaxFileBytes+1), index), nil, static.CodeLimitsExceeded},
		{"total too large", withFiles(big...), nil, static.CodeLimitsExceeded},
		{"path too long", withFiles(file("/"+strings.Repeat("a", 1020)+".txt", 0), index), nil, static.CodeLimitsExceeded},
		{"segment too long", withFiles(file("/"+strings.Repeat("a", 252)+".txt", 0), index), nil, static.CodeLimitsExceeded},
		{"too deep", withFiles(file(strings.Repeat("/a", 32)+"/b.txt", 0), index), nil, static.CodeLimitsExceeded},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			stored, digest := encode(test.manifest)
			if test.mutate != nil {
				stored = test.mutate(stored)
			}
			_, err := static.Parse(stored, digest)
			if static.CodeOf(err) != test.code {
				t.Fatalf("code %q (%v), want %q", static.CodeOf(err), err, test.code)
			}
		})
	}
	// Non-canonical bytes of an otherwise valid manifest never parse.
	stored, _ := encode(exampleManifest(false))
	spaced := bytes.Replace(stored, []byte(`"files":`), []byte(`"files": `), 1)
	sum := sha256.Sum256(spaced)
	if _, err := static.Parse(spaced, "sha256:"+hex.EncodeToString(sum[:])); static.CodeOf(err) != static.CodeManifestInvalid {
		t.Fatalf("non-canonical manifest: %v", err)
	}
}

type siteStore struct {
	store artifact.FileStore
	root  string
}

func newSiteStore(t *testing.T) *siteStore {
	root := t.TempDir()
	return &siteStore{store: artifact.FileStore{Root: root}, root: root}
}

func (s *siteStore) put(t *testing.T, body []byte) {
	t.Helper()
	if err := s.store.Put(context.Background(), static.BlobKey(sha(body)), body, "application/octet-stream"); err != nil {
		t.Fatal(err)
	}
}

func (s *siteStore) publish(t *testing.T, m static.Manifest, bodies ...[]byte) string {
	t.Helper()
	for _, body := range bodies {
		s.put(t, body)
	}
	_, digest, err := static.Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func blobCount(t *testing.T, cacheRoot string) int {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(cacheRoot, "misscomputer-static-v1", "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

func exampleBodyList() [][]byte {
	var list [][]byte
	for _, body := range exampleBodies {
		list = append(list, body)
	}
	return list
}

// Nothing is pinned unless every listed body matched its length and digest,
// and a failed pin leaves no referenced bytes behind.
func TestPinVerifiesEveryFileBeforeTheSiteExists(t *testing.T) {
	good := exampleManifest(true)
	cases := []struct {
		name  string
		store func(*siteStore)
		quota int64
		code  static.Code
	}{
		{name: "all verified", store: func(s *siteStore) {
			for _, body := range exampleBodyList() {
				s.put(t, body)
			}
		}, quota: 1 << 20},
		{name: "one body is longer", store: func(s *siteStore) {
			for path, body := range exampleBodies {
				if path == "/assets/app.js" {
					_ = s.store.Put(context.Background(), static.BlobKey(sha(body)), append(append([]byte{}, body...), '!'), "")
					continue
				}
				s.put(t, body)
			}
		}, quota: 1 << 20, code: static.CodeVerifyFailed},
		{name: "quota", store: func(s *siteStore) {
			for _, body := range exampleBodyList() {
				s.put(t, body)
			}
		}, quota: 100, code: static.CodeStorageExhausted},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			store := newSiteStore(t)
			test.store(store)
			cacheRoot := t.TempDir()
			cache, err := static.OpenCache(cacheRoot, test.quota)
			if err != nil {
				t.Fatal(err)
			}
			_, digest, _ := static.Encode(good)
			site, err := cache.Pin(context.Background(), store.store, digest, good, static.PinOptions{})
			if test.code == "" {
				if err != nil {
					t.Fatal(err)
				}
				if cache.Occupancy() != 131 || blobCount(t, cacheRoot) != 4 {
					t.Fatalf("occupancy %d blobs %d", cache.Occupancy(), blobCount(t, cacheRoot))
				}
				site.Release()
				if cache.Occupancy() != 0 || blobCount(t, cacheRoot) != 0 {
					t.Fatalf("release left occupancy %d blobs %d", cache.Occupancy(), blobCount(t, cacheRoot))
				}
				return
			}
			if site != nil || static.CodeOf(err) != test.code {
				t.Fatalf("site %v code %q (%v), want %q", site, static.CodeOf(err), err, test.code)
			}
			if cache.Occupancy() != 0 || blobCount(t, cacheRoot) != 0 {
				t.Fatalf("failed pin left occupancy %d blobs %d", cache.Occupancy(), blobCount(t, cacheRoot))
			}
		})
	}
}

// A blob shared by two pinned sites survives the release of one of them.
func TestReleaseKeepsBlobsReferencedByAnotherSite(t *testing.T) {
	store := newSiteStore(t)
	for _, body := range exampleBodyList() {
		store.put(t, body)
	}
	cacheRoot := t.TempDir()
	cache, err := static.OpenCache(cacheRoot, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	first := exampleManifest(true)
	second := exampleManifest(false)
	second.Files = []static.File{first.Files[3]} // only /index.html
	_, firstDigest, _ := static.Encode(first)
	_, secondDigest, _ := static.Encode(second)
	one, err := cache.Pin(context.Background(), store.store, firstDigest, first, static.PinOptions{})
	if err != nil {
		t.Fatal(err)
	}
	two, err := cache.Pin(context.Background(), store.store, secondDigest, second, static.PinOptions{})
	if err != nil {
		t.Fatal(err)
	}
	one.Release()
	if blobCount(t, cacheRoot) != 1 {
		t.Fatalf("blobs after first release: %d", blobCount(t, cacheRoot))
	}
	server := httptest.NewServer(static.NewHandler(two.Index(), two, "", 0))
	defer server.Close()
	got := rawRequest(t, server.Listener.Addr().String(), "GET", "/", "x", "", "")
	if got.status != 200 || !bytes.Equal(got.body, exampleBodies["/index.html"]) {
		t.Fatalf("second site after first release: %d %q", got.status, got.body)
	}
	two.Release()
	if blobCount(t, cacheRoot) != 0 || cache.Occupancy() != 0 {
		t.Fatalf("blobs %d occupancy %d after both releases", blobCount(t, cacheRoot), cache.Occupancy())
	}
}

// Cached bytes that change after verification never produce a complete
// response with the announced length.
func TestCorruptedPinnedBodyAbortsTheResponse(t *testing.T) {
	store := newSiteStore(t)
	for _, body := range exampleBodyList() {
		store.put(t, body)
	}
	cacheRoot := t.TempDir()
	cache, err := static.OpenCache(cacheRoot, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	m := exampleManifest(true)
	_, digest, _ := static.Encode(m)
	site, err := cache.Pin(context.Background(), store.store, digest, m, static.PinOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer site.Release()
	index := exampleBodies["/index.html"]
	path := filepath.Join(cacheRoot, "misscomputer-static-v1", "blobs", sha(index))
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, bytes.ToUpper(index), 0o600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(static.NewHandler(site.Index(), site, "", 0))
	defer server.Close()
	response, err := http.Get(server.URL + "/")
	if err != nil {
		return // the connection was aborted before a response
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(response.Body)
	if readErr == nil || int64(len(body)) == response.ContentLength {
		t.Fatalf("corrupted body delivered completely: %d bytes, err %v", len(body), readErr)
	}
}
