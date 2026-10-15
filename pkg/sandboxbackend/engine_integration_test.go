// SPDX-License-Identifier: AGPL-3.0-only

package sandboxbackend

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestEnginePullOversizedRegistryErrorOnDisposableHost asks the real
// dedicated daemon to pull from a loopback registry that serves a valid
// manifest and then answers every blob request with a 600 KiB text/plain
// error body. dockerd relays that body as the pull error, longer than the
// reader bound, after it may already have answered the pull with HTTP 200.
// Whichever way the daemon reports it, the backend must classify it as an
// engine answer, never as a daemon that gave no answer (contract D15(c)).
// It runs only when MC_SANDBOX_BACKEND_IT=1 on a disposable provisioned
// host, with MC_SANDBOX_DOCKER_HOST naming the dedicated daemon.
func TestEnginePullOversizedRegistryErrorOnDisposableHost(t *testing.T) {
	if os.Getenv("MC_SANDBOX_BACKEND_IT") != "1" {
		t.Skip("set MC_SANDBOX_BACKEND_IT=1 on a disposable provisioned host")
	}
	socket, err := dedicatedSocket(os.Getenv("MC_SANDBOX_DOCKER_HOST"))
	if err != nil {
		t.Fatal(err)
	}
	digestOf := func(raw []byte) string {
		sum := sha256.Sum256(raw)
		return "sha256:" + hex.EncodeToString(sum[:])
	}
	config, layer := []byte(`{"architecture":"amd64","os":"linux"}`), []byte("layer that is never served")
	manifest, _ := json.Marshal(map[string]any{
		"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
		"config": map[string]any{"mediaType": "application/vnd.docker.container.image.v1+json", "size": len(config), "digest": digestOf(config)},
		"layers": []any{map[string]any{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "size": len(layer), "digest": digestOf(layer)}},
	})
	manifestDigest := digestOf(manifest)
	body := "unknown: " + strings.Repeat("A", 600<<10)
	var blobRequests atomic.Int64
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
		switch {
		case r.URL.Path == "/v2/":
			w.WriteHeader(http.StatusOK)
		case strings.HasPrefix(r.URL.Path, "/v2/lane1/oversized/manifests/"):
			w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
			w.Header().Set("Docker-Content-Digest", manifestDigest)
			if r.Method != http.MethodHead {
				_, _ = w.Write(manifest)
			}
		case strings.HasPrefix(r.URL.Path, "/v2/lane1/oversized/blobs/"):
			blobRequests.Add(1)
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusTeapot)
			_, _ = w.Write([]byte(body))
		default:
			http.NotFound(w, r)
		}
	}))
	defer registry.Close()
	name := strings.TrimPrefix(registry.URL, "http://") + "/lane1/oversized"

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	err = newEngine(socket).pull(ctx, name, manifestDigest, 64<<20)
	if err == nil {
		t.Fatal("pull of an image whose blobs the registry refuses succeeded")
	}
	if blobRequests.Load() == 0 {
		t.Fatalf("the daemon never requested a blob, so the oversized error was not exercised: %v", err)
	}
	status := engineStatus(err)
	t.Logf("daemon answer status %d after %d blob requests: %s", status, blobRequests.Load(), bounded(err.Error()))
	if status == 0 {
		t.Fatalf("a registry-chosen pull error was classified as a daemon that gave no answer (a miner fault): %v", err)
	}
}
