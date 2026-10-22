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
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
// to a backend without this file. EnableOps refuses while the helper mount
// cannot carry every property the contract requires (XA-09, amendment A1,
// docs/sandbox-ops-backend-hardening.md).

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

// dockerd records an attached exec's end shortly after its stream closes, so
// an inspect right after EOF can still report it running; it is re-read at
// most exitSettleTries times, exitSettlePoll apart.
const (
	exitSettleTries = 20
	exitSettlePoll  = 25 * time.Millisecond
)

var _ miner.SandboxOpsBackend = (*GVisor)(nil)

// helperMountRequired are the mount properties the contract's delivery
// requires of the helper mount inside the sandbox (docs/sandbox-ops-v1.md,
// In-sandbox helper). helperMountProven are the ones this backend both
// requests of the engine and reads back (helperMount, verifyHelperMount):
// an Engine API v1.47 bind mount carries ReadOnly and BindOptions.Propagation,
// and its readback shows RW and Propagation. A readback that does not name a
// property proves nothing about it.
//
// The required set is read-only and rprivate under amendment A1 (XA-09),
// adopted conditionally: the pinned engine can neither request nor report
// nosuid or nodev on a bind, dockerd hands runsc only rbind, ro and the
// propagation, and the pinned runsc ignores nodev. A1 replaces the two flags
// with properties this backend enforces or reads back, none of which this
// file may weaken. On every create: the pinned directory holds only a
// root-owned 0555 regular helper, neither carries an extended attribute,
// both are on a read-only host mount, and every ancestor is root-owned and
// not group- or other-writable (verifyHelper, also at enable); the readback
// shows exactly this one bind, read-only and rprivate (verifyHelperMount),
// every capability dropped with none added and no-new-privileges
// (verifyEngine). When the backend is opened and when ops are enabled: the
// runtime is registered with only reviewed arguments, none of which enables
// set-ID execution, flag overrides or device or host-file passthrough
// (verifyRuntime). When ops are enabled: the runtime's cached OCI features
// are shown and list no rro mount option (verifyOpsRuntime). A guest
// observation (D5-P9) on the pinned Docker and runsc must pass and be
// reviewed independently before this change merges, and again on every
// re-pin.
var (
	helperMountRequired = []string{"ro", "rprivate"}
	helperMountProven   = map[string]bool{"ro": true, "rprivate": true}
)

// opsInfoTimeout bounds EnableOps's read of the daemon's runtime
// registration.
const opsInfoTimeout = 10 * time.Second

// ociRuntimeFeaturesKey is the runtime status member in which dockerd
// reports the OCI features it cached for a runtime (daemon/info_unix.go of
// moby v28.0.4, read as source at the tag).
const ociRuntimeFeaturesKey = "org.opencontainers.runtime-spec.features"

// EnableOps turns on the ops mode with the pinned helper. It must run before
// any Create. It fails closed while a property the contract requires of the
// helper mount is not requested and read back (XA-09, amendment A1), before
// it asks the daemon anything. It then checks the daemon's runtime
// registration (verifyOpsRuntime) and verifies the helper pin, which is
// verified again before every create. No flag, configuration member or lab
// profile bypasses any of these checks.
func (b *GVisor) EnableOps(helper OpsHelper) error {
	if !filepath.IsAbs(helper.Dir) || filepath.Clean(helper.Dir) != helper.Dir || helper.Dir == "/" || !sha256Pattern.MatchString(helper.SHA256) {
		return errors.New("ops helper directory must be a clean absolute path pinned by a lowercase SHA-256")
	}
	var unproven []string
	for _, property := range helperMountRequired {
		if !helperMountProven[property] {
			unproven = append(unproven, property)
		}
	}
	if len(unproven) != 0 {
		return fmt.Errorf("sandbox ops stay off: the contract requires a %s helper mount, which the engine can neither request nor read back (XA-09)",
			strings.Join(unproven, ", "))
	}
	if err := b.verifyOpsRuntime(); err != nil {
		return fmt.Errorf("sandbox ops stay off: %w", err)
	}
	if err := verifyHelper(helper); err != nil {
		return err
	}
	b.opsHelper = &helper
	return nil
}

// verifyOpsRuntime checks one fresh /info answer of the daemon. The runtime
// must still be registered as verifyRuntime requires, with only the
// reviewed arguments, so none that enables set-ID execution, flag
// overrides, or device or host-file passthrough. The OCI features dockerd
// cached for it must be shown, decode, and list no rro mount option
// (MCR-03, R23-H-03).
//
// dockerd turns a read-only bind into rro, not ro, only when those cached
// features list rro (daemon/oci_linux.go and supportsRecursivelyReadOnly in
// daemon/daemon_linux.go of moby v28.0.4, the pinned daemon's tag; source
// at the tag, the binary is assumed to correspond, P6). The reviewed runsc
// parser applies ro and ignores options it does not know, so a runtime that
// listed rro could be handed a helper bind it does not make read-only. A
// runtime whose features dockerd does not report refuses as well: the
// options it would be handed are then not shown here. That is deliberately
// stricter than dockerd 28.0.4, which hands such a runtime ro. The features
// are what the runtime claims to parse; they are never proof of what a
// guest sees (D5-P9). The check holds when ops are enabled; a daemon
// reloaded with another runtime afterwards is not seen until the next
// start.
func (b *GVisor) verifyOpsRuntime() error {
	ctx, cancel := context.WithTimeout(context.Background(), opsInfoTimeout)
	defer cancel()
	var info daemonInfo
	if err := b.engine.call(ctx, http.MethodGet, "/info", nil, nil, &info); err != nil {
		return fmt.Errorf("sandbox docker daemon info: %w", err)
	}
	if err := b.verifyRuntime(info); err != nil {
		return err
	}
	raw, ok := info.Runtimes[b.config.Runtime].Status[ociRuntimeFeaturesKey]
	if !ok {
		return fmt.Errorf("the daemon reports no OCI features for runtime %q, so the helper bind's read-only option is not shown (MCR-03)", b.config.Runtime)
	}
	var features struct {
		MountOptions []string `json:"mountOptions"`
	}
	if err := json.Unmarshal([]byte(raw), &features); err != nil {
		return fmt.Errorf("cannot decode the OCI features of runtime %q (MCR-03): %w", b.config.Runtime, err)
	}
	if slices.Contains(features.MountOptions, "rro") {
		return fmt.Errorf("runtime %q lists the rro mount option, which dockerd would request for the helper bind and the reviewed runsc does not apply (MCR-03)", b.config.Runtime)
	}
	return nil
}

// verifyHelper is the B-2 host-side pin: the directory and every ancestor
// are root-owned and not group- or other-writable, the directory holds only
// the helper, and the helper, opened without following a symlink, is a
// root-owned regular file of mode exactly 0555 with the pinned digest.
// The directory is opened first, without following a symlink, and the
// checks of the directory, its entries and the helper are made on that
// descriptor and on the helper opened from it. Neither the opened directory
// nor the opened helper may carry an extended attribute, such as a file
// capability or an access ACL, and a descriptor whose attributes cannot be
// listed fails the pin (G1, MSR-03). Both must be on a read-only host mount
// (MCR-04): the helper is checked as well as the directory, since a file
// mounted over the helper can come from another mount. The pin holds at the
// moment it is checked; it does not stop a privileged host process from
// changing the files or the mounts afterwards, and it says nothing about
// what a guest observes.
func verifyHelper(helper OpsHelper) error {
	dirFD, err := unix.Open(helper.Dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("ops helper directory %s: %w", helper.Dir, err)
	}
	dir := os.NewFile(uintptr(dirFD), helper.Dir)
	defer dir.Close()
	var opened unix.Stat_t
	if err := unix.Fstat(dirFD, &opened); err != nil {
		return fmt.Errorf("ops helper directory %s: %w", helper.Dir, err)
	}
	for path := helper.Dir; ; path = filepath.Dir(path) {
		var st unix.Stat_t
		if err := unix.Lstat(path, &st); err != nil {
			return fmt.Errorf("ops helper directory %s: %w", path, err)
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&0o022 != 0 {
			return fmt.Errorf("ops helper ancestor %s must be a root-owned directory that is not group- or other-writable", path)
		}
		if path == helper.Dir && (st.Dev != opened.Dev || st.Ino != opened.Ino) {
			return fmt.Errorf("ops helper directory %s changed while it was checked", path)
		}
		if path == "/" {
			break
		}
	}
	if opened.Mode&unix.S_IFMT != unix.S_IFDIR || opened.Uid != 0 || opened.Mode&0o7777 != 0o555 {
		return fmt.Errorf("ops helper directory %s must have mode 0555", helper.Dir)
	}
	if err := noExtendedAttributes(dirFD); err != nil {
		return fmt.Errorf("ops helper directory %s: %w", helper.Dir, err)
	}
	if err := readOnlyMount(dirFD); err != nil {
		return fmt.Errorf("ops helper directory %s: %w", helper.Dir, err)
	}
	names, err := dir.Readdirnames(-1)
	if err != nil {
		return fmt.Errorf("ops helper directory: %w", err)
	}
	if len(names) != 1 || names[0] != sandboxops.HelperName {
		return fmt.Errorf("ops helper directory %s must hold only %s", helper.Dir, sandboxops.HelperName)
	}
	path := filepath.Join(helper.Dir, sandboxops.HelperName)
	fd, err := unix.Openat(dirFD, sandboxops.HelperName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
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
	if err := noExtendedAttributes(fd); err != nil {
		return fmt.Errorf("ops helper %s: %w", path, err)
	}
	if err := readOnlyMount(fd); err != nil {
		return fmt.Errorf("ops helper %s: %w", path, err)
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

// noExtendedAttributes requires the extended-attribute list of the open file
// fd to be empty: one listxattr call that answers a size of zero. Any other
// answer fails, including a filesystem that cannot list attributes, since
// then their absence is not shown. The list holds every namespace the
// caller may see (security, system and user; trusted only with
// CAP_SYS_ADMIN), so a host whose security module labels files through
// extended attributes cannot hold a pinned helper.
func noExtendedAttributes(fd int) error {
	size, err := unix.Flistxattr(fd, nil)
	if err != nil {
		return fmt.Errorf("cannot show it has no extended attributes: %w", err)
	}
	if size != 0 {
		return errors.New("has extended attributes; the pin allows none")
	}
	return nil
}

// readOnlyMount requires the open file fd to be on a read-only mount: one
// fstatfs call on the descriptor, so no path is resolved again, whose mount
// flags include ST_RDONLY. The flag is set for a read-only mount and for a
// read-only filesystem alike (MCR-04).
func readOnlyMount(fd int) error {
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return fmt.Errorf("cannot show it is on a read-only mount: %w", err)
	}
	if fs.Flags&unix.ST_RDONLY == 0 {
		return errors.New("is on a writable mount; the pin requires a read-only host mount (statfs ST_RDONLY)")
	}
	return nil
}

// imageProbeSuffix names the image probe container after the sandbox it is
// made for, so a probe whose create went unanswered can still be removed by
// name, and one left behind is found by the next probe's create. The probe
// carries the sandbox labels and the lease label. The lane's orphan sweep
// recognises it by that name and label, and destroys it only while no Create
// of its lease holds the lease lock (miner.SandboxProbeSuffix).
const imageProbeSuffix = miner.SandboxProbeSuffix

// imageConflict is the ops-mode check, before the sandbox is created, that
// the verified image holds nothing at the helper's mount target (D1; DEC-06,
// R23-H-01, DR-06, MSR-01). The engine follows a symlink there when it
// mounts the helper, and an image entry can be re-pointed by the guest once
// it is not a mount point, so the mount is made only over a path the image
// does not hold. It creates, and never starts, a container of imageID from
// the create body of s without the helper mount, and asks the engine's
// archive stat for sandboxops.MountTarget. The archive stat does not follow
// a final symlink, and with no mount in the probe it sees the image's own
// layers. The probe is then removed with its anonymous volumes, under
// removalTimeout even if ctx was cancelled.
//
// It returns nil only when the stat answered 404 and a fresh inspection
// shows the same probe still exists and never started: a 404 also answers a
// container that is gone. Any entry, whatever its type, is a
// *miner.SandboxRefusal image_unavailable: the customer chose the image,
// and it is refused on every honest miner alike. So is a stat the engine
// answered with another error, once the probe is shown never started; the
// engine may fail to stat an image whose layers it cannot mount, which
// would also have failed the start (contract D23). Everything else is
// returned as the miner's fault, as the sandbox create's own failures are:
// a call the engine did not answer, a probe that vanished or started, a
// probe create the engine refused, and any probe that could not be
// removed, even after a conflict was found. missing reports that the engine
// no longer has imageID; the caller pulls it again.
func (b *GVisor) imageConflict(ctx context.Context, instanceID, imageID string, s spec) (missing bool, err error) {
	s.helper = nil
	name := instanceID + imageProbeSuffix
	create := func() (string, error) {
		var created struct {
			ID string `json:"Id"`
		}
		err := b.engine.call(ctx, http.MethodPost, "/containers/create", url.Values{"name": {name}, "platform": {"linux/amd64"}}, b.createBody(s, imageID), &created)
		return created.ID, err
	}
	id, err := create()
	if engineStatus(err) == http.StatusConflict {
		// An earlier probe of this sandbox was left behind.
		if err := b.removeProbe(ctx, name); err != nil {
			return false, fmt.Errorf("sandbox %s image probe %s left behind: %w", instanceID, name, err)
		}
		id, err = create()
	}
	switch {
	case engineStatus(err) == http.StatusNotFound:
		return true, nil
	case err != nil:
		return false, errors.Join(fmt.Errorf("sandbox %s image probe: %w", instanceID, err), b.removeProbe(ctx, name))
	case id == "":
		return false, errors.Join(fmt.Errorf("sandbox %s image probe was created without an ID", instanceID), b.removeProbe(ctx, name))
	}
	verdict := b.probeVerdict(ctx, id)
	if err := b.removeProbe(ctx, id); err != nil {
		return false, fmt.Errorf("sandbox %s image probe %s (%s) not removed after %v: %w", instanceID, name, id, verdictText(verdict), err)
	}
	slog.Info("sandbox image probe", "sandbox", instanceID, "probe_id", id, "target", sandboxops.MountTarget, "decision", verdictText(verdict))
	return false, verdict
}

// probeVerdict asks the engine's archive stat for the helper target in the
// probe container id and decides as imageConflict describes, before the
// probe is removed.
func (b *GVisor) probeVerdict(ctx context.Context, id string) error {
	statErr := b.engine.call(ctx, http.MethodHead, "/containers/"+url.PathEscape(id)+"/archive", url.Values{"path": {sandboxops.MountTarget}}, nil, nil)
	status := engineStatus(statErr)
	switch {
	case statErr == nil:
		return &miner.SandboxRefusal{Code: "image_unavailable"}
	case status == 0:
		return fmt.Errorf("image probe %s archive stat: %w", id, statErr)
	}
	again, found, err := b.inspect(ctx, id)
	switch {
	case err != nil:
		return fmt.Errorf("image probe %s after its archive stat: %w", id, err)
	case !found || again.ID != id:
		return fmt.Errorf("image probe %s vanished during its archive stat", id)
	case !neverStarted(again):
		return fmt.Errorf("image probe %s was started", id)
	case status == http.StatusNotFound:
		return nil
	}
	return &miner.SandboxRefusal{Code: "image_unavailable"}
}

// verdictText is how a probe verdict is logged.
func verdictText(verdict error) string {
	var refusal *miner.SandboxRefusal
	switch {
	case verdict == nil:
		return "absent"
	case errors.As(verdict, &refusal):
		return "refused: " + refusal.Code
	}
	return "fault: " + verdict.Error()
}

// removeProbe removes the probe container (an ID or the probe's name) and its
// anonymous volumes, and waits until the engine no longer reports it. It
// runs even when ctx was cancelled, bounded by removalTimeout.
func (b *GVisor) removeProbe(ctx context.Context, probe string) error {
	return b.removeContainer(context.WithoutCancel(ctx), probe)
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
	for try := 0; ; try++ {
		if err := b.engine.call(ctx, http.MethodGet, "/exec/"+url.PathEscape(created.ID)+"/json", nil, nil, &inspected); err != nil {
			return nil, b.unanswered(ctx, err)
		}
		if !inspected.Running || try == exitSettleTries {
			break
		}
		timer := time.NewTimer(exitSettlePoll)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, b.unanswered(ctx, ctx.Err())
		case <-timer.C:
		}
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
