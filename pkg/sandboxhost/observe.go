// SPDX-License-Identifier: AGPL-3.0-only

package sandboxhost

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Host reads the kernel's view of this machine. Proc is the procfs mount of
// the host PID namespace ("/proc" when empty; an agent in a container with
// the host's procfs mounted elsewhere names that mount). Every read is
// read-only; nothing is written or signalled. The only connection made is
// one to the dedicated engine socket, closed without sending a byte, to read
// its listener's peer credentials.
type Host struct {
	Proc string
	// ListNFTable returns `nft -j list table inet <name>` when asJSON is
	// set and `nft list table inet <name>` otherwise; nil runs the nft binary
	// read-only. An agent that reads the ruleset another way (for example
	// through a privileged helper) supplies it here.
	ListNFTable func(name string, asJSON bool) (string, error)
}

func (h Host) proc(parts ...string) string {
	root := h.Proc
	if root == "" {
		root = "/proc"
	}
	return filepath.Join(append([]string{root}, parts...)...)
}

type recorder struct{ checks []Check }

func (r *recorder) add(id string, err error, evidence string) {
	entry, _ := catalogEntry(id)
	status := StatusPass
	if err != nil {
		status, evidence = StatusFail, err.Error()
	}
	r.checks = append(r.checks, Check{ID: id, Class: entry.Class, Status: status, Evidence: clean(evidence)})
}

func (r *recorder) gap(id, evidence string) {
	r.checks = append(r.checks, Check{ID: id, Class: Unenforced, Status: StatusGap, Evidence: clean(evidence)})
}

func clean(text string) string {
	out := make([]byte, 0, len(text))
	for i := 0; i < len(text) && len(out) < 500; i++ {
		switch c := text[i]; {
		case c >= 0x20 && c <= 0x7e:
			out = append(out, c)
		case c == '\n' || c == '\t':
			out = append(out, ' ')
		}
	}
	return string(out)
}

// slicePath is the cgroup v2 path of a top-level slice. Profiles allow only
// top-level names without '-', which systemd maps to /<name>.
func slicePath(name string) string { return "/" + name }

func within(child, parent string) bool {
	return child == parent || strings.HasPrefix(child, parent+"/")
}

// Preflight observes every preflight check this package owns, plus every
// declared gap, for the host profile describes. exclusive names cgroups
// sandboxes must never share (the agent's own and the deployment.v4
// replicas'); the caller's own cgroup is always included. Engine checks
// come from the backend's engine client and are merged with BuildReport.
func (h Host) Preflight(profile Profile, exclusive []string) []Check {
	var r recorder
	lease, engine := slicePath(profile.LeaseSlice), slicePath(profile.EngineSlice)
	cg := cgroupReader{root: profile.CgroupRoot}

	r.add("host.cgroup2_mount_authentic", h.cgroup2Authentic(profile.CgroupRoot), profile.CgroupRoot+": cgroup2 superblock magic, single mount of the hierarchy root")

	leaseLimits, leaseErr := cg.limits(lease)
	if leaseErr == nil && (leaseLimits.cpuQuota <= 0 || leaseLimits.memory <= 0 || leaseLimits.pids <= 0) {
		leaseErr = fmt.Errorf("%s limits are not all finite: %s", lease, leaseLimits)
	}
	r.add("cgroup.lease_slice_finite", leaseErr, lease+" "+leaseLimits.String())
	swapErr := leaseErr
	if swapErr == nil && leaseLimits.swap != 0 {
		swapErr = fmt.Errorf("%s memory.swap.max=%d", lease, leaseLimits.swap)
	}
	r.add("cgroup.lease_slice_swap_zero", swapErr, lease+" memory.swap.max=0")

	engineLimits, engineErr := cg.limits(engine)
	if engineErr == nil && (engineLimits.memory <= 0 || engineLimits.pids <= 0 || engineLimits.swap != 0) {
		engineErr = fmt.Errorf("%s limits are not finite with swap 0: %s", engine, engineLimits)
	}
	r.add("cgroup.engine_slice_finite", engineErr, engine+" "+engineLimits.String())

	need := int64(profile.Aggregate.Sandboxes) * int64(profile.PerLease.PIDsMax)
	pidsErr := leaseErr
	if pidsErr == nil && leaseLimits.pids < need {
		pidsErr = fmt.Errorf("%s pids.max=%d < sandboxes x pids_max = %d", lease, leaseLimits.pids, need)
	}
	r.add("cgroup.pids_finite_covers_sum", pidsErr, fmt.Sprintf("%s pids.max=%d >= %d", lease, leaseLimits.pids, need))

	members, memberErr := h.socketOwnersIn(engine, profile.DockerSocket(), profile.Containerd.Address)
	r.add("cgroup.engine_processes_member", memberErr, members)

	self, disjointErr := h.processCgroup("self")
	if disjointErr == nil {
		disjointErr = disjoint(lease, engine, append([]string{self}, exclusive...))
	}
	r.add("cgroup.disjoint_from_caller", disjointErr, fmt.Sprintf("%s and %s disjoint from caller %s and %v", lease, engine, self, exclusive))

	shared, sharedErr := h.sharesEngineNamespaces(profile.DockerSocket())
	r.add("host.agent_shares_engine_namespaces", sharedErr, shared)

	mounts, mountErr := h.mounts()
	quotaErr := mountErr
	if quotaErr == nil {
		quotaErr = xfsProjectQuota(mounts, profile.DataRoot)
	}
	r.add("storage.data_fs_xfs_prjquota", quotaErr, profile.DataRoot+": xfs, prjquota accounting and enforcement")
	var dataBytes int64
	sizeErr := mountErr
	if sizeErr == nil {
		dataBytes, sizeErr = dedicatedSize(mounts, profile.DataRoot, int64(profile.Aggregate.DataFSMiB)<<20)
	}
	r.add("storage.data_fs_dedicated_finite", sizeErr, fmt.Sprintf("%s: one whole xfs mount of %d bytes", profile.DataRoot, dataBytes))
	runErr := mountErr
	if runErr == nil {
		runErr = sizedTmpfs(mounts, profile.RunRoot, profile.DockerSocket(), profile.Containerd.Address)
	}
	r.add("storage.run_root_tmpfs_finite", runErr, profile.RunRoot+": sized tmpfs holding both engine sockets")

	a := profile.Aggregate
	budgetErr := errors.Join(leaseErr, sizeErr)
	if budgetErr == nil {
		switch {
		case int64(a.CPUMillis) > leaseLimits.cpuMillis():
			budgetErr = fmt.Errorf("profile cpu %d millis > slice %d", a.CPUMillis, leaseLimits.cpuMillis())
		case int64(a.MemoryMiB) > leaseLimits.memory>>20:
			budgetErr = fmt.Errorf("profile memory %d MiB > slice %d MiB", a.MemoryMiB, leaseLimits.memory>>20)
		case int64(a.PIDs) > leaseLimits.pids:
			budgetErr = fmt.Errorf("profile pids %d > slice %d", a.PIDs, leaseLimits.pids)
		case int64(a.DiskRequiredMiB()) > dataBytes>>20:
			budgetErr = fmt.Errorf("disk with overhead %d MiB > data filesystem %d MiB", a.DiskRequiredMiB(), dataBytes>>20)
		}
	}
	r.add("budget.within_observed", budgetErr, fmt.Sprintf("profile within observed slice; disk %d MiB + overhead = %d MiB <= %d MiB", a.DiskMiB, a.DiskRequiredMiB(), dataBytes>>20))

	jsonListing, egressErr := h.listEgress(profile.Engine.EgressTable, true)
	var textListing string
	if egressErr == nil {
		textListing, egressErr = h.listEgress(profile.Engine.EgressTable, false)
	}
	if egressErr == nil {
		egressErr = egressRestricted(jsonListing, textListing, profile.Engine.EgressTable, profile.EngineSlice)
	}
	r.add("network.engine_egress_restricted", egressErr, fmt.Sprintf("nft table inet %s is exactly the provisioned engine egress chain for %s (host-local, private and reserved destinations rejected)", profile.Engine.EgressTable, profile.EngineSlice))

	r.gap("storage.images_cache_unreserved", "image and pull bytes share the data filesystem; the image reserve is arithmetic, not a quota")
	r.gap("storage.shim_socket_dir_shared", "containerd shim sockets live in the host-wide /run/containerd/s directory")
	r.gap("network.engine_pull_egress_public_unrestricted", "the engine may reach any public unicast address; no registry hostname allowlist")
	r.gap("network.public_allowlist_unsupported", "only network=none is provisioned; public and allowlist must be refused")
	r.gap("lease.guest_pids_host_task_semantics", "the lease pids limit bounds sentry host tasks, not guest processes; exceeding it may terminate the sandbox")
	r.gap("lease.image_volumes_refused", "the engine gives image VOLUMEs no per-lease quota; the backend must refuse such images")
	return r.checks
}

// ObserveInstance observes the instance checks this package owns for the
// sandbox whose sentry (the engine's container PID) is pid. The sentry's
// executable, cgroup and limits are observed by the backend (catalog owner).
func (h Host) ObserveInstance(profile Profile, pid int) []Check {
	var r recorder
	procs, err := h.runtimeProcesses(profile, slicePath(profile.LeaseSlice), slicePath(profile.EngineSlice))
	r.add("lease.runtime_processes_in_finite_cgroups", err, procs)
	netErr := fmt.Errorf("PID %d is not a process", pid)
	if pid > 0 {
		netErr = h.loOnlyNoRoutes(strconv.Itoa(pid))
	}
	r.add("lease.host_netns_lo_only_no_routes", netErr, fmt.Sprintf("network namespace of PID %d: only lo, no route off lo", pid))
	return r.checks
}

// ---- cgroups ---------------------------------------------------------------

// sliceLimits holds cgroup v2 limits; -1 is "max".
type sliceLimits struct {
	cpuQuota, cpuPeriod, memory, swap, pids int64
}

func (l sliceLimits) cpuMillis() int64 {
	if l.cpuQuota <= 0 || l.cpuPeriod <= 0 {
		return -1
	}
	return l.cpuQuota * 1000 / l.cpuPeriod
}

func (l sliceLimits) String() string {
	return fmt.Sprintf("cpu.max=%d/%d memory.max=%d memory.swap.max=%d pids.max=%d", l.cpuQuota, l.cpuPeriod, l.memory, l.swap, l.pids)
}

type cgroupReader struct{ root string }

func parseLimit(value string) (int64, error) {
	if value == "max" {
		return -1, nil
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("malformed cgroup limit %q", value)
	}
	return n, nil
}

func (c cgroupReader) limits(cgroup string) (sliceLimits, error) {
	dir, err := openNoFollow(c.root, cgroup)
	if err != nil {
		return sliceLimits{}, err
	}
	defer unix.Close(dir)
	var l sliceLimits
	cpu, err := readAt(dir, "cpu.max")
	if err != nil {
		return l, fmt.Errorf("%s: %w", cgroup, err)
	}
	fields := strings.Fields(cpu)
	if len(fields) != 2 {
		return l, fmt.Errorf("%s cpu.max %q is malformed", cgroup, cpu)
	}
	if l.cpuQuota, err = parseLimit(fields[0]); err != nil {
		return l, err
	}
	if l.cpuPeriod, err = strconv.ParseInt(fields[1], 10, 64); err != nil || l.cpuPeriod <= 0 {
		return l, fmt.Errorf("%s cpu.max period %q is malformed", cgroup, fields[1])
	}
	for _, item := range []struct {
		name   string
		target *int64
	}{{"memory.max", &l.memory}, {"memory.swap.max", &l.swap}, {"pids.max", &l.pids}} {
		value, err := readAt(dir, item.name)
		if err != nil {
			return l, fmt.Errorf("%s: %w", cgroup, err)
		}
		if *item.target, err = parseLimit(value); err != nil {
			return l, err
		}
	}
	return l, nil
}

// openNoFollow opens root/cgroup one component at a time without following
// symlinks, so a link cannot substitute another subtree's limits.
func openNoFollow(root, cgroup string) (int, error) {
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, fmt.Errorf("open cgroup root %s: %w", root, err)
	}
	for _, part := range strings.Split(strings.Trim(cgroup, "/"), "/") {
		if part == "" || part == "." || part == ".." {
			unix.Close(fd)
			return -1, fmt.Errorf("cgroup path %q is not clean", cgroup)
		}
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		unix.Close(fd)
		if err != nil {
			return -1, fmt.Errorf("open cgroup %s: %w", cgroup, err)
		}
		fd = next
	}
	return fd, nil
}

func readAt(dir int, name string) (string, error) {
	fd, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", name, err)
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 257))
	if err != nil {
		return "", err
	}
	if len(raw) > 256 {
		return "", fmt.Errorf("%s is too large", name)
	}
	return strings.TrimSpace(string(raw)), nil
}

func (h Host) processCgroup(pid string) (string, error) {
	raw, err := os.ReadFile(h.proc(pid, "cgroup"))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if rest, ok := strings.CutPrefix(line, "0::"); ok && strings.HasPrefix(rest, "/") {
			return rest, nil
		}
	}
	return "", fmt.Errorf("PID %s has no cgroup v2 membership", pid)
}

func disjoint(lease, engine string, others []string) error {
	if within(lease, engine) || within(engine, lease) {
		return fmt.Errorf("%s overlaps %s", lease, engine)
	}
	for _, other := range others {
		if other == "" || !path.IsAbs(other) || path.Clean(other) != other || other == "/" {
			return fmt.Errorf("exclusive cgroup %q must be a clean absolute path below the root", other)
		}
		for _, mine := range []string{lease, engine} {
			if within(mine, other) || within(other, mine) {
				return fmt.Errorf("%s overlaps %s", mine, other)
			}
		}
	}
	return nil
}

// ---- mounts ----------------------------------------------------------------

type mount struct{ root, target, fstype, superOptions string }

func unescapeMount(field string) string {
	var b strings.Builder
	for i := 0; i < len(field); i++ {
		if field[i] == '\\' && i+3 < len(field) {
			if n, err := strconv.ParseUint(field[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(field[i])
	}
	return b.String()
}

func (h Host) mounts() ([]mount, error) {
	file, err := os.Open(h.proc("self", "mountinfo"))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var out []mount
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		left, right, ok := strings.Cut(scanner.Text(), " - ")
		fields, tail := strings.Fields(left), strings.Fields(right)
		if !ok || len(fields) < 5 || len(tail) < 3 {
			return nil, errors.New("malformed mountinfo line")
		}
		out = append(out, mount{root: unescapeMount(fields[3]), target: unescapeMount(fields[4]), fstype: tail[0], superOptions: tail[2]})
	}
	return out, scanner.Err()
}

func mountsAt(mounts []mount, target string) []mount {
	var out []mount
	for _, m := range mounts {
		if m.target == target {
			out = append(out, m)
		}
	}
	return out
}

func hasOption(options, want string) bool {
	for _, option := range strings.Split(options, ",") {
		if option == want {
			return true
		}
	}
	return false
}

func statfsType(name string, magic int64) error {
	var stat unix.Statfs_t
	if err := unix.Statfs(name, &stat); err != nil {
		return fmt.Errorf("statfs %s: %w", name, err)
	}
	if stat.Type != magic {
		return fmt.Errorf("%s superblock magic %#x, want %#x", name, stat.Type, magic)
	}
	return nil
}

func (h Host) cgroup2Authentic(root string) error {
	if err := statfsType(root, unix.CGROUP2_SUPER_MAGIC); err != nil {
		return err
	}
	mounts, err := h.mounts()
	if err != nil {
		return err
	}
	at := mountsAt(mounts, root)
	if len(at) != 1 || at[0].fstype != "cgroup2" || at[0].root != "/" {
		return fmt.Errorf("%s must be exactly one cgroup2 mount of the hierarchy root, found %v", root, at)
	}
	return nil
}

// xfsProjectQuota relies on XFS reporting its live quota state as mount
// options: prjquota is accounting and enforcement, pqnoenforce accounting
// only.
func xfsProjectQuota(mounts []mount, dataRoot string) error {
	if err := statfsType(dataRoot, unix.XFS_SUPER_MAGIC); err != nil {
		return err
	}
	at := mountsAt(mounts, dataRoot)
	if len(at) != 1 || !hasOption(at[0].superOptions, "prjquota") || hasOption(at[0].superOptions, "pqnoenforce") {
		return fmt.Errorf("%s project quota is not enforced: %v", dataRoot, at)
	}
	return nil
}

func dedicatedSize(mounts []mount, dataRoot string, want int64) (int64, error) {
	at := mountsAt(mounts, dataRoot)
	if len(at) != 1 || at[0].fstype != "xfs" || at[0].root != "/" {
		return 0, fmt.Errorf("%s must be exactly one whole xfs filesystem, found %v", dataRoot, at)
	}
	var stat unix.Statfs_t
	if err := unix.Statfs(dataRoot, &stat); err != nil {
		return 0, err
	}
	size := int64(stat.Blocks) * stat.Bsize
	if size > want || size < want*9/10 {
		return size, fmt.Errorf("%s holds %d bytes, profile says %d", dataRoot, size, want)
	}
	return size, nil
}

func sizedTmpfs(mounts []mount, runRoot string, sockets ...string) error {
	at := mountsAt(mounts, runRoot)
	if len(at) != 1 || at[0].fstype != "tmpfs" {
		return fmt.Errorf("%s must be exactly one tmpfs, found %v", runRoot, at)
	}
	sized := false
	for _, option := range strings.Split(at[0].superOptions, ",") {
		if size, ok := strings.CutPrefix(option, "size="); ok && strings.TrimLeft(size, "0") != "" && !strings.HasPrefix(size, "0") {
			sized = true
		}
	}
	if !sized {
		return fmt.Errorf("%s tmpfs has no size limit", runRoot)
	}
	for _, socket := range sockets {
		if !strings.HasPrefix(socket, runRoot+"/") {
			return fmt.Errorf("socket %s is not on %s", socket, runRoot)
		}
	}
	return nil
}

// ---- processes -------------------------------------------------------------

// socketOwnersIn finds the processes holding each listening unix socket
// path and requires every one of them to be in cgroup.
func (h Host) socketOwnersIn(cgroup string, sockets ...string) (string, error) {
	owners, err := h.socketHolders(sockets...)
	if err != nil {
		return "", err
	}
	var evidence strings.Builder
	for _, socket := range sockets {
		if len(owners[socket]) == 0 {
			return evidence.String(), fmt.Errorf("no visible process holds listening socket %s", socket)
		}
		for _, pid := range owners[socket] {
			member, err := h.processCgroup(pid)
			if err != nil {
				return evidence.String(), err
			}
			if !within(member, cgroup) {
				return evidence.String(), fmt.Errorf("PID %s holding %s is in %s, not %s", pid, socket, member, cgroup)
			}
			fmt.Fprintf(&evidence, "%s pid=%s cgroup=%s; ", path.Base(socket), pid, member)
		}
	}
	return evidence.String(), nil
}

// socketHolders maps each unix socket path to the PIDs (in h.Proc) holding
// a descriptor of the socket bound to it, read from net/unix and every
// process's fd table. A process whose fd table is unreadable is skipped.
func (h Host) socketHolders(sockets ...string) (map[string][]string, error) {
	raw, err := os.ReadFile(h.proc("net", "unix"))
	if err != nil {
		return nil, err
	}
	inodes := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n")[1:] {
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		for _, socket := range sockets {
			if fields[7] == socket {
				inodes["socket:["+fields[6]+"]"] = socket
			}
		}
	}
	owners := map[string][]string{}
	if err := h.eachPID(func(pid string) error {
		fds, err := os.ReadDir(h.proc(pid, "fd"))
		if err != nil {
			return nil // exited, or not readable without privilege
		}
		for _, fd := range fds {
			if link, err := os.Readlink(h.proc(pid, "fd", fd.Name())); err == nil {
				if socket, ok := inodes[link]; ok {
					owners[socket] = append(owners[socket], pid)
				}
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return owners, nil
}

// engineDialTimeout bounds the connection made to read the engine socket's
// peer credentials.
const engineDialTimeout = 5 * time.Second

// sharesEngineNamespaces requires the caller to share the PID and network
// namespaces of the dedicated dockerd. The daemon is the listener of the
// engine socket, identified by SO_PEERCRED of a connection to it (the kernel
// reports PID 0 when the listener is not visible in the caller's PID
// namespace) and confirmed in h.Proc as a holder of that listening socket, so
// a PID number from another namespace cannot name a different process.
// Namespace identity is the (st_dev, st_ino) pair of the nsfs files. Every
// failure to connect, identify or read fails the check. The connection stays
// open while the namespaces are read, so the listener cannot have exited.
func (h Host) sharesEngineNamespaces(socket string) (string, error) {
	conn, err := net.DialTimeout("unix", socket, engineDialTimeout)
	if err != nil {
		return "", fmt.Errorf("connect to engine socket %s: %w", socket, err)
	}
	defer conn.Close()
	pid, err := peerPID(conn)
	if err != nil {
		return "", fmt.Errorf("peer credentials of %s: %w", socket, err)
	}
	if pid <= 0 {
		return "", fmt.Errorf("listener of %s is not visible in the caller's PID namespace (SO_PEERCRED PID %d)", socket, pid)
	}
	peer := strconv.Itoa(pid)
	holders, err := h.socketHolders(socket)
	if err != nil {
		return "", err
	}
	held := false
	for _, holder := range holders[socket] {
		held = held || holder == peer
	}
	if !held {
		return "", fmt.Errorf("SO_PEERCRED PID %d of %s does not hold that listening socket in %s (holders %v)", pid, socket, h.proc(), holders[socket])
	}
	evidence := fmt.Sprintf("dockerd PID %d (SO_PEERCRED of %s, holder of its listening socket):", pid, socket)
	for _, kind := range []string{"pid", "net"} {
		self, err := namespaceOf(h.proc("self", "ns", kind))
		if err != nil {
			return "", fmt.Errorf("caller %s namespace: %w", kind, err)
		}
		theirs, err := namespaceOf(h.proc(peer, "ns", kind))
		if err != nil {
			return "", fmt.Errorf("dockerd PID %d %s namespace: %w", pid, kind, err)
		}
		if self.dev != theirs.dev || self.ino != theirs.ino {
			return "", fmt.Errorf("caller %s namespace %s differs from dockerd PID %d %s", kind, self, pid, theirs)
		}
		evidence += fmt.Sprintf(" %s %s shared;", kind, self)
	}
	return evidence, nil
}

// peerPID is the SO_PEERCRED PID of a connected unix socket.
func peerPID(conn net.Conn) (int, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, errors.New("not a unix connection")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if credErr != nil {
		return 0, credErr
	}
	return int(cred.Pid), nil
}

// namespace is the identity of a namespace: its nsfs device and inode, with
// the kernel's "kind:[inode]" link text for evidence.
type namespace struct {
	dev, ino uint64
	label    string
}

func (n namespace) String() string { return fmt.Sprintf("%s(dev=%d,ino=%d)", n.label, n.dev, n.ino) }

func namespaceOf(file string) (namespace, error) {
	var st unix.Stat_t
	if err := unix.Stat(file, &st); err != nil {
		return namespace{}, fmt.Errorf("stat %s: %w", file, err)
	}
	label, err := os.Readlink(file)
	if err != nil {
		label = "?"
	}
	return namespace{dev: uint64(st.Dev), ino: st.Ino, label: label}, nil
}

func (h Host) eachPID(visit func(pid string) error) error {
	entries, err := os.ReadDir(h.proc())
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err == nil {
			if err := visit(entry.Name()); err != nil {
				return err
			}
		}
	}
	return nil
}

// runtimeProcesses requires every process executing from the runtime's
// directory (runsc, the sentry, gofers, the pinned containerd and shim) to
// be in the lease or engine slice.
func (h Host) runtimeProcesses(profile Profile, lease, engine string) (string, error) {
	binDir := path.Dir(profile.Runtime.Path) + "/"
	var evidence strings.Builder
	found := 0
	err := h.eachPID(func(pid string) error {
		exe, err := os.Readlink(h.proc(pid, "exe"))
		if err != nil || !strings.HasPrefix(exe, binDir) {
			return nil
		}
		member, err := h.processCgroup(pid)
		if err != nil {
			return nil // exited
		}
		if !within(member, lease) && !within(member, engine) {
			return fmt.Errorf("PID %s (%s) is in unbounded cgroup %s", pid, exe, member)
		}
		found++
		fmt.Fprintf(&evidence, "%s@%s ", path.Base(exe), member)
		return nil
	})
	if err == nil && found == 0 {
		err = fmt.Errorf("no process executes from %s", binDir)
	}
	return evidence.String(), err
}

// loOnlyNoRoutes reads pid's network namespace through procfs, which shows
// the namespace of the named process, not the reader's.
func (h Host) loOnlyNoRoutes(pid string) error {
	dev, err := os.ReadFile(h.proc(pid, "net", "dev"))
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimSpace(string(dev)), "\n")
	var names []string
	for _, line := range lines[min(2, len(lines)):] {
		name, _, _ := strings.Cut(strings.TrimSpace(line), ":")
		names = append(names, name)
	}
	if len(names) != 1 || names[0] != "lo" {
		return fmt.Errorf("interfaces %v, want only lo", names)
	}
	route, err := os.ReadFile(h.proc(pid, "net", "route"))
	if err != nil {
		return err
	}
	if lines := strings.Split(strings.TrimSpace(string(route)), "\n"); len(lines) > 1 {
		return fmt.Errorf("%d IPv4 routes present", len(lines)-1)
	}
	v6, err := os.ReadFile(h.proc(pid, "net", "ipv6_route"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(v6)), "\n") {
		if fields := strings.Fields(line); len(fields) == 10 && fields[9] != "lo" {
			return fmt.Errorf("IPv6 route via %s", fields[9])
		}
	}
	return nil
}
