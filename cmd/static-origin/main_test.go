// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
	"github.com/misscomputer/misscomputer-subnet/pkg/organic"
	"github.com/misscomputer/misscomputer-subnet/pkg/static"
	"github.com/misscomputer/misscomputer-subnet/pkg/static/statictest"
)

// These tests drive the built binary over loopback sockets and signals, the
// same way the private temporary-origin runner launches it.

var binary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "static-origin-bin-")
	if err != nil {
		panic(err)
	}
	binary = filepath.Join(dir, "static-origin")
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Stdout, build.Stderr = os.Stderr, os.Stderr
	if err := build.Run(); err != nil {
		panic("build static-origin: " + err.Error())
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

var releaseSigner = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))

// site is one published site version in a filesystem artifact store with
// its signed release and pinned trust policy.
type site struct {
	dir, store                string
	siteDigest, releaseDigest string
	releaseFile, policyFile   string
	policyDigest              string
}

func publish(t *testing.T, fallback bool) *site {
	t.Helper()
	dir := t.TempDir()
	s := &site{dir: dir, store: filepath.Join(dir, "store")}
	store := artifact.FileStore{Root: s.store}
	stored, digest, err := static.Encode(statictest.ExampleManifest(fallback))
	if err != nil {
		t.Fatal(err)
	}
	s.siteDigest = digest
	if err := store.Put(context.Background(), static.ManifestKey(digest), stored, ""); err != nil {
		t.Fatal(err)
	}
	for _, body := range statictest.ExampleBodies {
		if err := store.Put(context.Background(), static.BlobKey(statictest.SHA256(body)), body, ""); err != nil {
			t.Fatal(err)
		}
	}
	policy := static.TrustPolicy{
		Schema: static.TrustPolicySchema, SchemaVersion: 1, PolicyID: "static-release-test",
		TrustedKeys: []static.ReleaseKey{{
			Algorithm: "ed25519", KeyID: "static-release-a", PublicKeyHex: hex.EncodeToString(releaseSigner.Public().(ed25519.PublicKey)),
			ValidFromEpoch: 1790000000, ValidUntilEpoch: 1800000000,
		}},
	}
	policy.DigestSHA256, _ = organic.DigestWithout(policy, "digest_sha256")
	s.policyDigest = policy.DigestSHA256
	s.policyFile = s.write(t, "policy.json", mustCanonical(t, policy))
	s.sign(t, static.Release{SiteDigest: digest, SignerKeyID: "static-release-a"}, releaseSigner)
	return s
}

// sign writes a release of r's site and signer id, signed by key.
func (s *site) sign(t *testing.T, r static.Release, key ed25519.PrivateKey) {
	t.Helper()
	r.IssuedAt, r.ProducerPolicyVersion, r.Schema, r.SchemaVersion = "2026-09-30T00:00:00Z", static.ProducerPolicyVersion, static.ReleaseSchema, 1
	r.ServerImplementationDigest = static.ServerImplementationDigest
	message, err := static.ReleaseMessage(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Signature = hex.EncodeToString(ed25519.Sign(key, message))
	stored := mustCanonical(t, r)
	s.releaseDigest = static.Digest(stored)
	s.releaseFile = s.write(t, "release.json", stored)
}

func (s *site) write(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(s.dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func (s *site) blobPath(path string) string {
	return filepath.Join(s.store, static.BlobKey(statictest.SHA256(statictest.ExampleBodies[path])))
}

func (s *site) args(extra ...string) []string {
	return append([]string{
		"--listen", "127.0.0.1:0", "--route-host", statictest.RouteHost,
		"--site-digest", s.siteDigest, "--release-digest", s.releaseDigest, "--release-file", s.releaseFile,
		"--trust-policy-file", s.policyFile, "--trust-policy-digest", s.policyDigest,
		"--server-implementation-digest", static.ServerImplementationDigest,
		"--cache-dir", filepath.Join(s.dir, "cache"), "--ready-file", filepath.Join(s.dir, "ready.json"),
		"--artifact-backend", "file", "--artifact-dir", s.store,
	}, extra...)
}

func mustCanonical(t *testing.T, value any) []byte {
	t.Helper()
	stored, err := organic.CanonicalBytes(value)
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

// process is one running binary with its combined status and diagnostics.
type process struct {
	cmd    *exec.Cmd
	lines  chan string
	output *lockedBuffer
	done   chan error
}

// lockedBuffer collects stdout and stderr; the buffer is a field, not
// embedded, so os/exec cannot reach an unlocked ReadFrom.
type lockedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

func start(t *testing.T, env []string, args ...string) *process {
	t.Helper()
	cmd := exec.Command(binary, args...)
	cmd.Env = env
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	p := &process{cmd: cmd, lines: make(chan string, 8), output: &lockedBuffer{}, done: make(chan error, 1)}
	cmd.Stderr = p.output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 64<<10), 64<<10)
		for scanner.Scan() {
			p.output.Write([]byte(scanner.Text() + "\n"))
			p.lines <- scanner.Text()
		}
		close(p.lines)
		p.done <- cmd.Wait()
	}()
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	return p
}

func (p *process) line(t *testing.T) string {
	t.Helper()
	select {
	case line, ok := <-p.lines:
		if !ok {
			t.Fatalf("no status line; output:\n%s", p.output.String())
		}
		return line
	case <-time.After(30 * time.Second):
		t.Fatalf("no status line within 30s; output:\n%s", p.output.String())
	}
	return ""
}

// exit waits for the process and returns its exit code.
func (p *process) exit(t *testing.T) int {
	t.Helper()
	select {
	case err := <-p.done:
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode()
		}
		if err != nil {
			t.Fatal(err)
		}
		return 0
	case <-time.After(30 * time.Second):
		t.Fatalf("process did not exit; output:\n%s", p.output.String())
	}
	return -1
}

type readyReport struct {
	Schema        string `json:"schema"`
	ListenAddress string `json:"listen_address"`
	SiteDigest    string `json:"site_digest"`
	ReleaseDigest string `json:"release_digest"`
	FileCount     int    `json:"file_count"`
}

func (p *process) ready(t *testing.T, s *site) readyReport {
	t.Helper()
	line := p.line(t)
	payload, ok := strings.CutPrefix(line, "READY ")
	if !ok {
		t.Fatalf("status %q; output:\n%s", line, p.output.String())
	}
	var report readyReport
	if err := json.Unmarshal([]byte(payload), &report); err != nil {
		t.Fatal(err)
	}
	file, err := os.ReadFile(filepath.Join(s.dir, "ready.json"))
	if err != nil || strings.TrimSpace(string(file)) != payload {
		t.Fatalf("ready file %q differs from READY %q (%v)", file, payload, err)
	}
	if report.Schema != "miss.computer/misscomputer-subnet/static-origin-ready" || report.SiteDigest != s.siteDigest ||
		report.ReleaseDigest != s.releaseDigest || report.FileCount != 4 {
		t.Fatalf("ready report %+v", report)
	}
	return report
}

func (p *process) stop(t *testing.T) {
	t.Helper()
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if line := p.line(t); line != "STOPPED" {
		t.Fatalf("after SIGTERM: %q", line)
	}
	if code := p.exit(t); code != 0 {
		t.Fatalf("exit %d after SIGTERM", code)
	}
}

// The origin answers every socket-carried §6 vector byte-exactly for the
// bound route host, then drains and exits 0 on SIGTERM.
func TestOriginServesTheNormativeVectorsThenStops(t *testing.T) {
	addresses := map[bool]string{}
	for _, fallback := range []bool{false, true} {
		s := publish(t, fallback)
		p := start(t, nil, s.args()...)
		addresses[fallback] = p.ready(t, s).ListenAddress
		defer p.stop(t)
	}
	for _, v := range statictest.Vectors() {
		t.Run(v.Name, func(t *testing.T) { statictest.Check(t, addresses[v.Fallback], v) })
	}
	// V29: net/http itself refuses the bare "%" with its own 400 body
	// before the handler; the status is still 400 (the edge answers V29).
	if got := statictest.RawRequest(t, addresses[true], "GET", "/100%", statictest.RouteHost, "", ""); got.Status != 400 {
		t.Fatalf("V29 status %d", got.Status)
	}
}

// Nothing listens unless the release, digests and every byte verified.
func TestOriginRefusesToListenOnAnyMismatch(t *testing.T) {
	stranger := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	cases := []struct {
		name   string
		break_ func(t *testing.T, s *site) []string
		code   string
	}{
		{"corrupt blob", func(t *testing.T, s *site) []string {
			if err := os.WriteFile(s.blobPath("/assets/app.js"), []byte("console.log(\"evil!\");\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			return nil
		}, "static_verify_failed"},
		{"missing blob", func(t *testing.T, s *site) []string {
			if err := os.Remove(s.blobPath("/docs/index.html")); err != nil {
				t.Fatal(err)
			}
			return nil
		}, "static_fetch_failed"},
		{"release signed by an untrusted key id", func(t *testing.T, s *site) []string {
			s.sign(t, static.Release{SiteDigest: s.siteDigest, SignerKeyID: "static-release-b"}, stranger)
			return nil
		}, "signer_untrusted"},
		{"release forged under the trusted key id", func(t *testing.T, s *site) []string {
			s.sign(t, static.Release{SiteDigest: s.siteDigest, SignerKeyID: "static-release-a"}, stranger)
			return nil
		}, "signature_invalid"},
		{"release of another site", func(t *testing.T, s *site) []string {
			s.sign(t, static.Release{SiteDigest: "sha256:" + strings.Repeat("0", 64), SignerKeyID: "static-release-a"}, releaseSigner)
			return nil
		}, "release_binding_mismatch"},
		{"release digest not the bound one", func(t *testing.T, s *site) []string {
			return []string{"--release-digest", "sha256:" + strings.Repeat("1", 64)}
		}, "release_digest_mismatch"},
		{"trust policy not the pinned one", func(t *testing.T, s *site) []string {
			return []string{"--trust-policy-digest", strings.Repeat("2", 64)}
		}, "trust_policy_digest_mismatch"},
		{"another handler implementation", func(t *testing.T, s *site) []string {
			return []string{"--server-implementation-digest", "sha256:" + strings.Repeat("3", 64)}
		}, "config_invalid"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := publish(t, true)
			p := start(t, nil, s.args(c.break_(t, s)...)...)
			if line := p.line(t); line != "REJECTED "+c.code {
				t.Fatalf("status %q, want REJECTED %s; output:\n%s", line, c.code, p.output.String())
			}
			if code := p.exit(t); code != 2 {
				t.Fatalf("exit %d, want 2", code)
			}
			if _, err := os.Stat(filepath.Join(s.dir, "ready.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("ready file exists after rejection: %v", err)
			}
		})
	}
}

// A pinned byte that changes after start is never delivered as a complete
// response, and the origin stops (exit 3) rather than serving on.
func TestOriginFailsClosedWhenThePinnedCopyChanges(t *testing.T) {
	s := publish(t, true)
	p := start(t, nil, s.args()...)
	address := p.ready(t, s).ListenAddress
	body := statictest.ExampleBodies["/assets/app.js"]
	pinned := filepath.Join(s.dir, "cache", "misscomputer-static-v1", "blobs", statictest.SHA256(body))
	if err := os.Chmod(pinned, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pinned, []byte("console.log(\"evil!\");\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	io.WriteString(conn, "GET /assets/app.js HTTP/1.1\r\nHost: "+statictest.RouteHost+"\r\nConnection: close\r\n\r\n")
	if response, err := http.ReadResponse(bufio.NewReader(conn), nil); err == nil {
		received, readErr := io.ReadAll(response.Body)
		if response.StatusCode == 200 && readErr == nil {
			t.Fatalf("a complete 200 was delivered from a changed pinned copy: %q", received)
		}
	}
	if line := p.line(t); line != "FAILED static_verify_failed" {
		t.Fatalf("status %q; output:\n%s", line, p.output.String())
	}
	if code := p.exit(t); code != 3 {
		t.Fatalf("exit %d, want 3", code)
	}
}

// The S3 backend reads with credentials from an owner-only file (never a
// flag), signs with them, and never prints the secret; a group-readable
// credentials file is refused before anything is fetched.
func TestOriginReadsS3WithAnOwnerOnlyCredentialsFile(t *testing.T) {
	const accessKey, secret = "AKIDORIGINTEST", "secret-do-not-print-4b1f9c"
	s := publish(t, true)
	var mu sync.Mutex
	var authorizations []string
	objects := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		authorizations = append(authorizations, r.Header.Get("Authorization"))
		mu.Unlock()
		key, ok := strings.CutPrefix(r.URL.Path, "/site-artifacts/")
		if r.Method != http.MethodGet || !ok {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		http.ServeFile(w, r, filepath.Join(s.store, filepath.FromSlash(key)))
	}))
	defer objects.Close()
	requests := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), authorizations...)
	}
	credentials := s.write(t, "s3.json", []byte(`{"access_key_id":"`+accessKey+`","secret_access_key":"`+secret+`"}`))
	s3 := func(credentialsFile string) []string {
		return s.args("--artifact-backend", "s3", "--s3-endpoint", objects.URL, "--s3-bucket", "site-artifacts",
			"--s3-region", "auto", "--s3-credentials-file", credentialsFile)
	}

	loose := s.write(t, "s3-loose.json", []byte(`{"access_key_id":"`+accessKey+`","secret_access_key":"`+secret+`"}`))
	if err := os.Chmod(loose, 0o640); err != nil {
		t.Fatal(err)
	}
	refused := start(t, nil, s3(loose)...)
	if code := refused.exit(t); code != 64 || len(requests()) != 0 {
		t.Fatalf("group-readable credentials: exit %d after %d store requests", code, len(requests()))
	}

	p := start(t, nil, s3(credentials)...)
	address := p.ready(t, s).ListenAddress
	statictest.Check(t, address, statictest.Vectors()[0])
	p.stop(t)
	signed := requests()
	// The manifest and three blobs; the empty file is fully determined by
	// its digest and never fetched.
	if len(signed) != 4 {
		t.Fatalf("%d store requests, want 4", len(signed))
	}
	for _, header := range signed {
		if !strings.Contains(header, "Credential="+accessKey+"/") {
			t.Fatalf("store request not signed with the file's access key: %q", header)
		}
	}
	for _, output := range []string{refused.output.String(), p.output.String()} {
		if strings.Contains(output, secret) {
			t.Fatal("the secret key appeared in the origin's output")
		}
	}
}
