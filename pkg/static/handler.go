// SPDX-License-Identifier: AGPL-3.0-only

package static

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/misscomputer/misscomputer-subnet/pkg/organic"
)

// CacheControl is sent on every static response in v1.
const CacheControl = "private, no-store"

const (
	fixedContentType = "text/plain; charset=utf-8"
	allowedMethods   = "GET, HEAD"
)

// Fixed platform bodies (§5.3). Unavailable answers a miner-local capacity
// refusal before lookup; it is a transport-class response, never a content
// response.
var (
	badRequestBody       = []byte("Bad Request\n")
	notFoundBody         = []byte("Not Found\n")
	methodNotAllowedBody = []byte("Method Not Allowed\n")
	misdirectedBody      = []byte("Misdirected Request\n")
	unavailableBody      = []byte("Service Unavailable\n")
)

// Response is the complete answer of the pinned handler: one verified
// manifest file or one fixed platform body. It depends only on the manifest
// and the request method, path, Host (where checked) and body presence.
type Response struct {
	Status int
	// File is the manifest entry served; nil for a fixed platform response.
	File *File
	// Fixed is the body of a fixed platform response.
	Fixed []byte
	// Head suppresses the body (HEAD) while keeping the GET headers.
	Head bool
}

// ContentLength is the GET representation length, also announced for HEAD.
func (r Response) ContentLength() int64 {
	if r.File != nil {
		return r.File.ContentLength
	}
	return int64(len(r.Fixed))
}

// BodySHA256 is the bare hex SHA-256 of the bytes actually sent.
func (r Response) BodySHA256() string {
	if r.Head {
		sum := sha256.Sum256(nil)
		return hex.EncodeToString(sum[:])
	}
	if r.File != nil {
		return r.File.BodySHA256
	}
	sum := sha256.Sum256(r.Fixed)
	return hex.EncodeToString(sum[:])
}

// Header returns exactly the normative header set (§5.2).
func (r Response) Header() http.Header {
	contentType := fixedContentType
	if r.File != nil {
		contentType = r.File.ContentType
	}
	header := http.Header{
		"Cache-Control":          {CacheControl},
		"Content-Length":         {strconv.FormatInt(r.ContentLength(), 10)},
		"Content-Type":           {contentType},
		"X-Content-Type-Options": {"nosniff"},
	}
	if r.Status == http.StatusMethodNotAllowed {
		header["Allow"] = []string{allowedMethods}
	}
	return header
}

// HeaderSHA256 is the attestation v2 response_header_sha256 of the
// normative header set (§5.5).
func (r Response) HeaderSHA256() (string, error) {
	var pairs [][2]string
	for name, values := range r.Header() {
		for _, value := range values {
			pairs = append(pairs, [2]string{strings.ToLower(name), value})
		}
	}
	return organic.ResponseHeaderSHA256(pairs)
}

// Index is the immutable response table (§4.4) of one validated manifest.
type Index struct {
	routes   map[string]File
	fallback *File
}

// NewIndex compiles a manifest that already satisfies Validate.
func NewIndex(m Manifest) *Index {
	index := &Index{routes: make(map[string]File, len(m.Files)+8)}
	for _, file := range m.Files {
		index.routes[file.Path] = file
	}
	for _, file := range m.Files {
		if lastSegment(file.Path) == indexName {
			index.routes[strings.TrimSuffix(file.Path, indexName)] = file
		}
	}
	if m.Fallback != nil {
		target := index.routes[m.Fallback.Target]
		index.fallback = &target
	}
	return index
}

// Routes lists every routable path in byte order (the admission crawl set).
func (x *Index) Routes() []string {
	paths := make([]string, 0, len(x.routes))
	for path := range x.routes {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

// Unavailable is the fixed capacity refusal.
func Unavailable(method string) Response {
	return Response{Status: http.StatusServiceUnavailable, Fixed: unavailableBody, Head: method == http.MethodHead}
}

// Misdirected is the fixed §5.1 step-1 response for a Host mismatch, used
// where a Host is meaningful (edge, origin); the endpoint-addressed miner
// ingress skips that step.
func Misdirected(method string) Response {
	return Response{Status: http.StatusMisdirectedRequest, Fixed: misdirectedBody, Head: method == http.MethodHead}
}

// Resolve applies §5.1 steps 2-7 to a method, the raw request path (bytes
// before the first "?"; the query never matters) and whether the request
// carries a body.
func (x *Index) Resolve(method, rawPath string, hasBody bool) Response {
	head := method == http.MethodHead
	switch {
	case method != http.MethodGet && !head:
		return Response{Status: http.StatusMethodNotAllowed, Fixed: methodNotAllowedBody}
	case hasBody, !ValidRequestPath(rawPath):
		return Response{Status: http.StatusBadRequest, Fixed: badRequestBody, Head: head}
	}
	if file, found := x.routes[rawPath]; found {
		return Response{Status: http.StatusOK, File: &file, Head: head}
	}
	if x.fallback != nil && !strings.Contains(lastSegment(rawPath), ".") {
		target := *x.fallback
		return Response{Status: http.StatusOK, File: &target, Head: head}
	}
	return Response{Status: http.StatusNotFound, Fixed: notFoundBody, Head: head}
}

// implementationSources are the handler-package files that define the
// static-handler.v1 semantics. Origin and miner compile the same files, so
// they derive the same ServerImplementationDigest.
//
//go:embed handler.go manifest.go path.go serve.go
var implementationSources embed.FS

var implementationFiles = []string{"handler.go", "manifest.go", "path.go", "serve.go"}

// ServerImplementationDigest is "sha256:" + hex(SHA-256(canonical JSON of the
// implementation descriptor)): the handler version plus the path and SHA-256
// of every semantics source file. A static ticket and release name the digest
// they authorize; a miner answers any other digest with
// static_server_implementation_mismatch.
var ServerImplementationDigest = implementationDigest()

type implementationFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type implementationDescriptor struct {
	Files         []implementationFile `json:"files"`
	Handler       string               `json:"handler"`
	Schema        string               `json:"schema"`
	SchemaVersion int                  `json:"schema_version"`
}

func implementationDigest() string {
	descriptor := implementationDescriptor{
		Handler: HandlerVersion, Schema: organic.SchemaPrefix + "static-handler-implementation", SchemaVersion: 1,
	}
	for _, name := range implementationFiles {
		source, err := implementationSources.ReadFile(name)
		if err != nil {
			panic(err)
		}
		sum := sha256.Sum256(source)
		descriptor.Files = append(descriptor.Files, implementationFile{Path: "pkg/static/" + name, SHA256: hex.EncodeToString(sum[:])})
	}
	encoded, err := organic.Canonical(descriptor)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}
