// SPDX-License-Identifier: AGPL-3.0-only

package sandboxbackend

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"

	"github.com/misscomputer/misscomputer-subnet/pkg/miner"
	"github.com/misscomputer/misscomputer-subnet/pkg/sandboxops"
)

// The sandbox-ops-v1 mode of the backend (docs/sandbox-ops-v1-lane.md,
// helper_B_conditions B-1..B-4): every sandbox created while it is enabled
// carries one read-only directory mount of the pinned helper at
// /.misscomputer, and RunHelper runs that helper with docker exec. With ops
// disabled (the default) the create body and its readback are byte-identical
// to a backend without this file.

// OpsHelper pins the helper delivery directory: a root-owned 0555 directory
// holding exactly sandboxops.HelperName, a root-owned 0555 regular file whose
// SHA-256 is SHA256.
type OpsHelper struct {
	Dir    string
	SHA256 string
}

// maxHelperStderrBytes bounds what the backend reads of the helper's stderr;
// the helper writes none, and anything a guest writes there is dropped.
const maxHelperStderrBytes = 64 << 10

// livenessTimeout bounds the independent daemon liveness check of OPS-U3 D1.
const livenessTimeout = 5 * time.Second

var _ miner.SandboxOpsBackend = (*GVisor)(nil)

// EnableOps turns on the ops mode with the pinned helper. It verifies the pin
// now and again before every create. It must run before any Create.
func (b *GVisor) EnableOps(helper OpsHelper) error {
	if !filepath.IsAbs(helper.Dir) || filepath.Clean(helper.Dir) != helper.Dir || helper.Dir == "/" || !sha256Pattern.MatchString(helper.SHA256) {
		return errors.New("ops helper directory must be a clean absolute path pinned by a lowercase SHA-256")
	}
	if err := verifyHelper(helper); err != nil {
		return err
	}
	b.opsHelper = &helper
	return nil
}

// verifyHelper is the B-2 host-side pin: the directory and every ancestor
// are root-owned and not group- or other-writable, the directory holds only
// the helper, and the helper, opened without following a symlink, is a
// root-owned regular file of mode exactly 0555 with the pinned digest.
func verifyHelper(helper OpsHelper) error {
	for dir := helper.Dir; ; dir = filepath.Dir(dir) {
		var st unix.Stat_t
		if err := unix.Lstat(dir, &st); err != nil {
			return fmt.Errorf("ops helper directory %s: %w", dir, err)
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&0o022 != 0 {
			return fmt.Errorf("ops helper ancestor %s must be a root-owned directory that is not group- or other-writable", dir)
		}
		if dir == helper.Dir && st.Mode&0o7777 != 0o555 {
			return fmt.Errorf("ops helper directory %s must have mode 0555", dir)
		}
		if dir == "/" {
			break
		}
	}
	entries, err := os.ReadDir(helper.Dir)
	if err != nil {
		return fmt.Errorf("ops helper directory: %w", err)
	}
	if len(entries) != 1 || entries[0].Name() != sandboxops.HelperName {
		return fmt.Errorf("ops helper directory %s must hold only %s", helper.Dir, sandboxops.HelperName)
	}
	path := filepath.Join(helper.Dir, sandboxops.HelperName)
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open ops helper: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Mode&0o7777 != 0o555 {
		return errors.New("ops helper must be a root-owned regular file with mode exactly 0555")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}
	if hex.EncodeToString(hash.Sum(nil)) != helper.SHA256 {
		return errors.New("ops helper does not match its pinned SHA-256")
	}
	return nil
}

// helperMount is the one mount an ops-mode sandbox has (B-1).
func helperMount(helper *OpsHelper) map[string]any {
	return map[string]any{
		"Type": "bind", "Source": helper.Dir, "Target": sandboxops.MountTarget, "ReadOnly": true,
		"BindOptions": map[string]any{"Propagation": "rprivate"},
	}
}

// verifyHelperMount is the ops-mode readback: exactly the requested mount in
// the host configuration and exactly one read-only rprivate bind of the
// pinned directory at /.misscomputer among the container's mounts.
func verifyHelperMount(c inspectedContainer, helper *OpsHelper) error {
	h := c.HostConfig
	if len(h.Mounts) != 1 || len(c.Mounts) != 1 {
		return fmt.Errorf("sandbox %s does not carry exactly the ops helper mount", c.Name)
	}
	requested, mounted := h.Mounts[0], c.Mounts[0]
	if requested.Type != "bind" || requested.Source != helper.Dir || requested.Target != sandboxops.MountTarget || !requested.ReadOnly ||
		requested.BindOptions == nil || requested.BindOptions.Propagation != "rprivate" {
		return fmt.Errorf("sandbox %s ops helper mount request differs from the pinned mount", c.Name)
	}
	if mounted.Type != "bind" || mounted.Source != helper.Dir || mounted.Destination != sandboxops.MountTarget || mounted.RW ||
		mounted.Propagation != "rprivate" {
		return fmt.Errorf("sandbox %s ops helper mount is not the pinned read-only directory", c.Name)
	}
	return nil
}

// RunHelper runs the helper once in instanceID (B-4): docker exec of the fixed
// helper path as the image's default user, not privileged, with no added
// environment and no TTY, with request as its only stdin. Its stdout is read
// bounded by sandboxops.MaxResponseBytes; stderr is drained and dropped.
func (b *GVisor) RunHelper(ctx context.Context, instanceID string, request []byte) ([]byte, error) {
	if b.opsHelper == nil {
		return nil, errors.New("sandbox ops are not enabled on this backend")
	}
	if len(request) > sandboxops.MaxRequestBytes {
		return nil, errors.New("ops helper request exceeds its bound")
	}
	var created struct {
		ID string `json:"Id"`
	}
	err := b.engine.call(ctx, http.MethodPost, "/containers/"+url.PathEscape(instanceID)+"/exec", nil, map[string]any{
		"AttachStdin": true, "AttachStdout": true, "AttachStderr": true, "Tty": false, "Privileged": false,
		"User": "", "Env": []string{}, "Cmd": []string{sandboxops.HelperPath},
	}, &created)
	switch status := engineStatus(err); {
	case status == http.StatusNotFound || status == http.StatusConflict:
		// No such container, or it is not running.
		return nil, miner.ErrSandboxNotRunning
	case err != nil:
		return nil, b.unanswered(ctx, err)
	case created.ID == "":
		return nil, errors.New("docker engine created an exec without an ID")
	}
	stdout, err := b.engine.hijackExec(ctx, created.ID, request)
	if err != nil {
		return nil, b.unanswered(ctx, err)
	}
	var inspected struct {
		Running  bool `json:"Running"`
		ExitCode int  `json:"ExitCode"`
	}
	if err := b.engine.call(ctx, http.MethodGet, "/exec/"+url.PathEscape(created.ID)+"/json", nil, nil, &inspected); err != nil {
		return nil, b.unanswered(ctx, err)
	}
	if inspected.Running || inspected.ExitCode != 0 {
		// The helper ended abnormally or was replaced: sandbox_op_failed.
		return nil, fmt.Errorf("ops helper exited with status %d", inspected.ExitCode)
	}
	return stdout, nil
}

// unanswered classifies a failed engine call (OPS-U3 D1). An engine-answered
// error is never a miner fault (the allowlist is empty until lab evidence).
// A call without an answer is a miner fault only when an independent
// liveness check of the same daemon fails as well.
func (b *GVisor) unanswered(ctx context.Context, err error) error {
	if engineStatus(err) != 0 || ctx.Err() != nil {
		return err
	}
	ping, cancel := context.WithTimeout(context.WithoutCancel(ctx), livenessTimeout)
	defer cancel()
	if pingErr := b.engine.call(ping, http.MethodGet, "/_ping", nil, nil, nil); pingErr != nil {
		return &miner.SandboxEngineUnavailable{Err: errors.Join(err, pingErr)}
	}
	return err
}

// hijackExec starts exec id attached, writes stdin, half-closes it, and
// demultiplexes the raw stream until the helper exits.
func (e *engine) hijackExec(ctx context.Context, id string, stdin []byte) ([]byte, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", e.socket)
	if err != nil {
		return nil, fmt.Errorf("docker engine exec start: %w", err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	body, _ := json.Marshal(map[string]any{"Detach": false, "Tty": false})
	var request bytes.Buffer
	fmt.Fprintf(&request, "POST /%s/exec/%s/start HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Length: %d\r\n\r\n",
		engineAPIVersion, url.PathEscape(id), len(body))
	request.Write(body)
	if _, err := conn.Write(request.Bytes()); err != nil {
		return nil, fmt.Errorf("docker engine exec start: %w", err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		return nil, fmt.Errorf("docker engine exec start: %w", err)
	}
	if response.StatusCode != http.StatusSwitchingProtocols && response.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(response.Body, maxEngineErrorBytes))
		response.Body.Close()
		return nil, &engineError{Status: response.StatusCode, Message: bounded(string(raw))}
	}
	if _, err := conn.Write(stdin); err != nil {
		return nil, fmt.Errorf("write ops helper request: %w", err)
	}
	if closer, ok := conn.(interface{ CloseWrite() error }); ok {
		if err := closer.CloseWrite(); err != nil {
			return nil, err
		}
	}
	return demux(reader, sandboxops.MaxResponseBytes)
}

// demux reads Docker's multiplexed raw stream: an 8-byte header (stream,
// three zero bytes, big-endian length) per frame. It keeps at most limit
// bytes of stdout and fails beyond them, and drops stderr after counting it
// against its own bound.
func demux(reader io.Reader, limit int) ([]byte, error) {
	var stdout bytes.Buffer
	stderr := 0
	var header [8]byte
	for {
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return stdout.Bytes(), nil
			}
			return nil, fmt.Errorf("ops helper stream: %w", err)
		}
		size := int64(binary.BigEndian.Uint32(header[4:]))
		switch header[0] {
		case 1:
			if int64(stdout.Len())+size > int64(limit) {
				return nil, errors.New("ops helper stdout exceeds its bound")
			}
			if _, err := io.CopyN(&stdout, reader, size); err != nil {
				return nil, fmt.Errorf("ops helper stream: %w", err)
			}
		case 2:
			if stderr += int(size); stderr > maxHelperStderrBytes {
				return nil, errors.New("ops helper stderr exceeds its bound")
			}
			if _, err := io.CopyN(io.Discard, reader, size); err != nil {
				return nil, fmt.Errorf("ops helper stream: %w", err)
			}
		default:
			return nil, errors.New("ops helper stream has an unknown frame")
		}
	}
}
