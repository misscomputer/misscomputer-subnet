// SPDX-License-Identifier: AGPL-3.0-only

package static

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"
)

// This file is the adapter surface shared by every static-handler.v1
// server: the miner's endpoint-addressed ingress and the platform's
// temporary static origin. Both resolve with the same Index and write with
// WriteResponse, so their bytes are identical by construction.
//
//	index := static.NewIndex(manifest)            // manifest from static.Parse
//	handler := static.Handler{Index: index, Bodies: source, RouteHost: host}
//	http.Handle("/", handler)                     // origin: Host checked (§5.1 step 1)
//
// The miner omits RouteHost (its ingress already fixes the site), derives the
// raw path after its /runtime/<endpoint_id> prefix itself, and calls
// ResolveRequest/WriteResponse directly so it can add an attestation.

// BodySource supplies the bytes of a manifest file. Implementations need not
// be trusted: WriteResponse rehashes every body and withholds the final chunk
// unless length and SHA-256 match the manifest.
type BodySource interface {
	Open(file File) (io.ReadCloser, error)
}

// ErrBodyCorrupted reports body bytes that do not match the manifest.
var ErrBodyCorrupted = errors.New("static body bytes do not match the manifest")

// RawRequestPath returns the raw request path: the request-target bytes
// before the first "?", taken from the unparsed RequestURI so no decoding or
// re-escaping can change them. ok is false for a non-origin-form target.
func RawRequestPath(req *http.Request) (string, bool) {
	target := req.RequestURI
	if target == "" {
		target = req.URL.EscapedPath()
	}
	if cut := strings.IndexByte(target, '?'); cut >= 0 {
		target = target[:cut]
	}
	return target, strings.HasPrefix(target, "/")
}

// HasBody reports whether a request carries a body (§5.1 step 3).
func HasBody(req *http.Request) bool {
	return req.ContentLength > 0 || len(req.TransferEncoding) > 0 || req.Header.Get("Transfer-Encoding") != ""
}

// NormalizeHost applies the §5.1 step-1 comparison form: ASCII lowercase
// and one trailing ":443" removed.
func NormalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(host), ":443")
}

// ResolveRequest applies §5.1 to req. routeHost enables step 1; pass "" where
// the site is fixed by an authenticated endpoint address (the miner).
func ResolveRequest(index *Index, req *http.Request, rawPath string, routeHost string) Response {
	if routeHost != "" && NormalizeHost(req.Host) != routeHost {
		return Misdirected(req.Method)
	}
	return index.Resolve(req.Method, rawPath, HasBody(req))
}

// WriteResponse sends response with exactly the normative headers plus
// extra. A file body is streamed from bodies, rehashed, and its final chunk
// is withheld until length and digest match; on mismatch it returns
// ErrBodyCorrupted after the header was sent, and the caller must abort the
// connection (panic(http.ErrAbortHandler)) so no complete wrong response is
// ever delivered. headerSent reports whether a status line was written.
func WriteResponse(w http.ResponseWriter, response Response, bodies BodySource, extra http.Header) (headerSent bool, err error) {
	header := w.Header()
	for name := range header {
		delete(header, name)
	}
	for name, values := range response.Header() {
		header[name] = values
	}
	for name, values := range extra {
		header[name] = values
	}
	// Suppress the server-generated Date: the header set stays exactly the
	// normative one (§5.2 excludes Date from every comparison anyway).
	header["Date"] = nil
	if response.File == nil {
		w.WriteHeader(response.Status)
		if !response.Head {
			_, err = w.Write(response.Fixed)
		}
		return true, err
	}
	body, err := bodies.Open(*response.File)
	if err != nil {
		return false, errors.Join(ErrBodyCorrupted, err)
	}
	defer body.Close()
	w.WriteHeader(response.Status)
	if response.Head {
		return true, nil
	}
	return true, streamVerified(w, body, response.File.BodySHA256, response.File.ContentLength)
}

func streamVerified(w io.Writer, reader io.Reader, sha string, size int64) error {
	hash := sha256.New()
	limited := io.LimitReader(reader, size+1)
	var held []byte
	var total int64
	buffer := make([]byte, chunkSize)
	for {
		n, readErr := limited.Read(buffer)
		if n > 0 {
			if held != nil {
				if _, err := w.Write(held); err != nil {
					return err
				}
			}
			held = append(held[:0], buffer[:n]...)
			hash.Write(buffer[:n])
			total += int64(n)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return errors.Join(ErrBodyCorrupted, readErr)
		}
	}
	if total != size || hex.EncodeToString(hash.Sum(nil)) != sha {
		return ErrBodyCorrupted
	}
	if held != nil {
		_, err := w.Write(held)
		return err
	}
	return nil
}

// Handler is the reusable net/http static-handler.v1 server for one site.
// Concurrency, when positive, bounds in-flight requests; excess requests
// receive the fixed 503.
type Handler struct {
	Index     *Index
	Bodies    BodySource
	RouteHost string
	slots     chan struct{}
}

// NewHandler builds a Handler with an in-flight bound (0 = unbounded).
func NewHandler(index *Index, bodies BodySource, routeHost string, concurrency int) *Handler {
	handler := &Handler{Index: index, Bodies: bodies, RouteHost: routeHost}
	if concurrency > 0 {
		handler.slots = make(chan struct{}, concurrency)
	}
	return handler
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if h.slots != nil {
		select {
		case h.slots <- struct{}{}:
			defer func() { <-h.slots }()
		default:
			_, _ = WriteResponse(w, Unavailable(req.Method), h.Bodies, nil)
			return
		}
	}
	rawPath, ok := RawRequestPath(req)
	response := Response{Status: http.StatusBadRequest, Fixed: badRequestBody, Head: req.Method == http.MethodHead}
	if ok {
		response = ResolveRequest(h.Index, req, rawPath, h.RouteHost)
	} else if req.Method != http.MethodGet && req.Method != http.MethodHead {
		response = h.Index.Resolve(req.Method, "", false)
	}
	if headerSent, err := WriteResponse(w, response, h.Bodies, nil); err != nil {
		if headerSent {
			panic(http.ErrAbortHandler)
		}
		// Nothing was sent: the body source is unusable, never serve bytes.
		_, _ = WriteResponse(w, Unavailable(req.Method), h.Bodies, nil)
	}
}
