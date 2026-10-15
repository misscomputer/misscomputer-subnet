// SPDX-License-Identifier: AGPL-3.0-only

package sandboxbackend

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// engineAPIVersion is the Docker Engine API version every request is pinned
// to. PinnedDockerVersion serves it.
const engineAPIVersion = "v1.47"

const (
	maxEngineResponseBytes = 8 << 20
	maxEngineErrorBytes    = 64 << 10
	maxPullMessageBytes    = 1 << 20
)

// engine is a minimal Docker Engine API client bound to one unix socket. It
// carries no credentials and never falls back to another daemon.
type engine struct {
	client *http.Client
	base   string
}

func newEngine(socket string) *engine {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", socket)
		},
		DisableCompression:    true,
		MaxIdleConns:          4,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: 2 * time.Minute,
	}
	return &engine{client: &http.Client{Transport: transport}, base: "http://docker/" + engineAPIVersion}
}

// engineError is a non-2xx Engine API answer.
type engineError struct {
	Status  int
	Message string
}

func (e *engineError) Error() string {
	return fmt.Sprintf("docker engine %d: %s", e.Status, e.Message)
}

func engineStatus(err error) int {
	var failure *engineError
	if errors.As(err, &failure) {
		return failure.Status
	}
	return 0
}

func (e *engine) request(ctx context.Context, method, path string, query url.Values, body any) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(payload)
	}
	target := e.base + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("docker engine %s %s: %w", method, path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxEngineErrorBytes))
		var message struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(raw, &message) != nil || message.Message == "" {
			message.Message = strings.TrimSpace(string(raw))
		}
		return nil, &engineError{Status: resp.StatusCode, Message: bounded(message.Message)}
	}
	return resp, nil
}

// call performs one request and decodes a JSON answer into out, if out is
// not nil.
func (e *engine) call(ctx context.Context, method, path string, query url.Values, body, out any) error {
	resp, err := e.request(ctx, method, path, query, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	limited := io.LimitReader(resp.Body, maxEngineResponseBytes+1)
	if out == nil {
		_, err = io.Copy(io.Discard, limited)
		return err
	}
	raw, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if len(raw) > maxEngineResponseBytes {
		return fmt.Errorf("docker engine %s %s answer is too large", method, path)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("decode docker engine %s %s: %w", method, path, err)
	}
	return nil
}

// pullMessage is one line of the pull progress stream.
type pullMessage struct {
	ID             string `json:"id"`
	Status         string `json:"status"`
	Error          string `json:"error"`
	ProgressDetail struct {
		Total int64 `json:"total"`
	} `json:"progressDetail"`
}

// errPullTooLarge stops a pull whose distinct layer downloads exceed the
// per-image limit.
var errPullTooLarge = errors.New("image download exceeds the per-image limit")

// pull pulls reference for linux/amd64 and stops, by closing the request,
// once the compressed sizes the engine reports for distinct layers sum to
// more than maxBytes. Compressed sizes are a lower bound on the stored
// image, so the caller still checks the unpacked size after the pull.
//
// Once the engine has answered the request, every failure of its progress
// stream is an *engineError carrying that answer's status: an error line,
// a line that does not decode or exceeds the reader bound, a stream that
// breaks off, and one that ends before the engine reports completion. The
// registry chooses the text, and so the length, of what the engine relays,
// so none of these is evidence about the miner (contract D15(c)). Only a
// request the daemon gives no answer to is not an *engineError.
func (e *engine) pull(ctx context.Context, name, digest string, maxBytes int64) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	resp, err := e.request(ctx, http.MethodPost, "/images/create", url.Values{
		"fromImage": {name}, "tag": {digest}, "platform": {"linux/amd64"},
	}, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	answered := func(message string) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return &engineError{Status: resp.StatusCode, Message: bounded(message)}
	}
	layers := map[string]int64{}
	var total int64
	completed := false
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64<<10), maxPullMessageBytes)
	for scanner.Scan() {
		var message pullMessage
		if err := json.Unmarshal(scanner.Bytes(), &message); err != nil {
			return answered("decode docker pull progress: " + err.Error())
		}
		if message.Error != "" {
			return answered(message.Error)
		}
		// The engine's last line of a pull that succeeded ("Status:
		// Downloaded newer image for ..." or "Status: Image is up to date
		// for ...").
		completed = completed || strings.HasPrefix(message.Status, "Status: ")
		if size := message.ProgressDetail.Total; message.ID != "" && size > layers[message.ID] {
			total += size - layers[message.ID]
			layers[message.ID] = size
			if total > maxBytes {
				return errPullTooLarge
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return answered("read docker pull progress: " + err.Error())
	}
	if !completed {
		return answered("docker pull progress ended before the pull completed")
	}
	return nil
}

func bounded(text string) string {
	text = strings.TrimSpace(text)
	if len(text) > 512 {
		text = text[:512] + "..."
	}
	return text
}
