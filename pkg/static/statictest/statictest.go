// SPDX-License-Identifier: AGPL-3.0-only

// Package statictest holds the static-site contract §3.5 worked example and
// the §6 normative HTTP vectors, shared by every static-handler.v1 server's
// socket-level tests (the pkg/static adapter and the static origin) so the
// vector table exists once.
package statictest

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/misscomputer/misscomputer-subnet/pkg/static"
)

// RouteHost is the route host the vectors address.
const RouteHost = "hello-k3j9x0q2ab.on.miss.computer"

// ExampleBodies are the §3.5 file bodies by path.
var ExampleBodies = map[string][]byte{
	"/index.html":      []byte("<!doctype html><title>hello</title><script src=\"/assets/app.js\"></script>\n"),
	"/assets/app.js":   []byte("console.log(\"hello\");\n"),
	"/docs/index.html": []byte("<!doctype html><title>docs</title>\n"),
	"/empty.txt":       {},
}

// SHA256 is the bare hex SHA-256 of body.
func SHA256(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// ExampleManifest is the §3.5 manifest, with or without its SPA fallback.
func ExampleManifest(fallback bool) static.Manifest {
	m := static.Manifest{Handler: static.HandlerVersion, Schema: static.ManifestSchema, SchemaVersion: 1}
	for _, path := range []string{"/assets/app.js", "/docs/index.html", "/empty.txt", "/index.html"} {
		body := ExampleBodies[path]
		m.Files = append(m.Files, static.File{
			BodySHA256: SHA256(body), ContentLength: int64(len(body)), ContentType: static.ContentTypeFor(path), Path: path,
		})
	}
	if fallback {
		m.Fallback = &static.Fallback{Kind: static.FallbackKind, Target: "/index.html"}
	}
	return m
}

// Vector is one §6 row. Fallback selects the site with the SPA fallback;
// Host empty means RouteHost.
type Vector struct {
	Name, Method, Target, Host, Extra, Payload string
	Fallback                                   bool
	Status                                     int
	ContentType                                string
	Body                                       []byte
	Length                                     int
}

// Vectors returns the §6 table that a socket can carry. V29 ("/100%") is
// absent: net/http refuses an invalid escape with its own 400 before any
// handler runs, so the edge answers it (§10.3).
func Vectors() []Vector {
	idx := ExampleBodies["/index.html"]
	doc := ExampleBodies["/docs/index.html"]
	js := ExampleBodies["/assets/app.js"]
	notFound, badRequest := []byte("Not Found\n"), []byte("Bad Request\n")
	const html, text = "text/html; charset=utf-8", "text/plain; charset=utf-8"
	long := "/" + strings.TrimSuffix(strings.Repeat(strings.Repeat("a", 204)+"/", 5), "/")
	bad := func(name, target string) Vector {
		return Vector{Name: name, Method: "GET", Target: target, Fallback: true, Status: 400, ContentType: text, Body: badRequest, Length: 12}
	}
	return []Vector{
		{Name: "V01", Method: "GET", Target: "/", Fallback: true, Status: 200, ContentType: html, Body: idx, Length: 74},
		{Name: "V02", Method: "HEAD", Target: "/", Fallback: true, Status: 200, ContentType: html, Body: nil, Length: 74},
		{Name: "V03", Method: "GET", Target: "/index.html", Fallback: true, Status: 200, ContentType: html, Body: idx, Length: 74},
		{Name: "V04", Method: "GET", Target: "/assets/app.js", Fallback: true, Status: 200, ContentType: "text/javascript; charset=utf-8", Body: js, Length: 22},
		{Name: "V05", Method: "GET", Target: "/docs/", Fallback: true, Status: 200, ContentType: html, Body: doc, Length: 35},
		{Name: "V06", Method: "GET", Target: "/docs/index.html", Fallback: true, Status: 200, ContentType: html, Body: doc, Length: 35},
		{Name: "V07", Method: "GET", Target: "/empty.txt", Fallback: true, Status: 200, ContentType: text, Body: nil, Length: 0},
		{Name: "V08", Method: "GET", Target: "/docs", Fallback: true, Status: 200, ContentType: html, Body: idx, Length: 74},
		{Name: "V08-nofb", Method: "GET", Target: "/docs", Status: 404, ContentType: text, Body: notFound, Length: 10},
		{Name: "V09", Method: "GET", Target: "/about/team", Fallback: true, Status: 200, ContentType: html, Body: idx, Length: 74},
		{Name: "V09-nofb", Method: "GET", Target: "/about/team", Status: 404, ContentType: text, Body: notFound, Length: 10},
		{Name: "V10", Method: "GET", Target: "/assets/", Fallback: true, Status: 200, ContentType: html, Body: idx, Length: 74},
		{Name: "V10-nofb", Method: "GET", Target: "/assets/", Status: 404, ContentType: text, Body: notFound, Length: 10},
		{Name: "V11", Method: "GET", Target: "/missing.js", Fallback: true, Status: 404, ContentType: text, Body: notFound, Length: 10},
		{Name: "V12", Method: "GET", Target: "/Index.html", Fallback: true, Status: 404, ContentType: text, Body: notFound, Length: 10},
		{Name: "V13", Method: "GET", Target: "/caf%C3%A9", Fallback: true, Status: 200, ContentType: html, Body: idx, Length: 74},
		{Name: "V13-nofb", Method: "GET", Target: "/caf%C3%A9", Status: 404, ContentType: text, Body: notFound, Length: 10},
		{Name: "V14", Method: "GET", Target: "/?q=1", Fallback: true, Status: 200, ContentType: html, Body: idx, Length: 74},
		{Name: "V15", Method: "GET", Target: "/index.html?v=2", Fallback: true, Status: 200, ContentType: html, Body: idx, Length: 74},
		{Name: "V16", Method: "HEAD", Target: "/missing.js", Fallback: true, Status: 404, ContentType: text, Body: nil, Length: 10},
		{Name: "V17", Method: "POST", Target: "/", Fallback: true, Status: 405, ContentType: text, Body: []byte("Method Not Allowed\n"), Length: 19},
		{Name: "V17-OPTIONS", Method: "OPTIONS", Target: "/", Fallback: true, Status: 405, ContentType: text, Body: []byte("Method Not Allowed\n"), Length: 19},
		bad("V18", "/%69ndex.html"), bad("V19", "/a%2Fb"), bad("V20", "/a%2fb"), bad("V21", "/../index.html"),
		bad("V22", "/./index.html"), bad("V23", "/%2E%2E/"), bad("V24", "//index.html"), bad("V25", "/a%5Cb"),
		bad("V26-00", "/%00"), bad("V26-7F", "/%7F"), bad("V27", "/a|b"), bad("V28", "/caf%c3%a9"),
		bad("V30", long), bad("V31", strings.Repeat("/a", 33)),
		{Name: "V30-at-limit", Method: "GET", Target: long[:len(long)-1], Fallback: true, Status: 200, ContentType: html, Body: idx, Length: 74},
		{Name: "V32", Method: "GET", Target: "/", Extra: "Content-Length: 1\r\n", Payload: "x", Fallback: true, Status: 400, ContentType: text, Body: badRequest, Length: 12},
		{Name: "V33", Method: "GET", Target: "/", Host: "other.on.miss.computer", Fallback: true, Status: 421, ContentType: text, Body: []byte("Misdirected Request\n"), Length: 20},
		{Name: "V33-port", Method: "GET", Target: "/", Host: "HELLO-k3j9x0q2ab.on.miss.computer:443", Fallback: true, Status: 200, ContentType: html, Body: idx, Length: 74},
		{Name: "V34", Method: "GET", Target: "/", Extra: "Range: bytes=0-0\r\n", Fallback: true, Status: 200, ContentType: html, Body: idx, Length: 74},
		{Name: "V35", Method: "GET", Target: "/", Extra: "Accept-Encoding: gzip\r\n", Fallback: true, Status: 200, ContentType: html, Body: idx, Length: 74},
		{Name: "V36", Method: "GET", Target: "/", Extra: "If-None-Match: *\r\n", Fallback: true, Status: 200, ContentType: html, Body: idx, Length: 74},
		{Name: "V37", Method: "GET", Target: "/index.html/", Fallback: true, Status: 200, ContentType: html, Body: idx, Length: 74},
		{Name: "V37-nofb", Method: "GET", Target: "/index.html/", Status: 404, ContentType: text, Body: notFound, Length: 10},
	}
}

// Response is one raw HTTP/1.1 response.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

// RawRequest writes target byte-exact over a fresh connection, bypassing
// client URL normalization, and reads one response.
func RawRequest(t testing.TB, address, method, target, host, headers, payload string) Response {
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
	return Response{Status: response.StatusCode, Header: response.Header, Body: body}
}

// Check sends v to address and requires its status, body and exactly the
// §5.2 header set (the Connection header of the test client aside).
func Check(t testing.TB, address string, v Vector) {
	t.Helper()
	host := v.Host
	if host == "" {
		host = RouteHost
	}
	got := RawRequest(t, address, v.Method, v.Target, host, v.Extra, v.Payload)
	if got.Status != v.Status || !bytes.Equal(got.Body, v.Body) {
		t.Fatalf("%s: status %d body %q, want %d %q", v.Name, got.Status, got.Body, v.Status, v.Body)
	}
	want := http.Header{
		"Cache-Control": {"private, no-store"}, "Content-Type": {v.ContentType},
		"Content-Length": {strconv.Itoa(v.Length)}, "X-Content-Type-Options": {"nosniff"},
	}
	if v.Status == http.StatusMethodNotAllowed {
		want["Allow"] = []string{"GET, HEAD"}
	}
	got.Header.Del("Connection")
	if len(got.Header) != len(want) {
		t.Fatalf("%s: headers %v, want exactly %v", v.Name, got.Header, want)
	}
	for name, values := range want {
		if strings.Join(got.Header.Values(name), ",") != strings.Join(values, ",") {
			t.Fatalf("%s: header %s = %q, want %q", v.Name, name, got.Header.Values(name), values)
		}
	}
}
