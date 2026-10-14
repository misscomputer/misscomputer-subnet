// SPDX-License-Identifier: AGPL-3.0-only

package miner

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/misscomputer/misscomputer-subnet/pkg/sandbox"
	"golang.org/x/sys/unix"
)

// DefaultCgroupRoot is the usual cgroup v2 mount point.
const DefaultCgroupRoot = "/sys/fs/cgroup"

// VerifySandboxCgroup reads the CPU and memory limits of the dedicated
// sandbox cgroup v2 subtree at cgroup (a path below root, the cgroup2
// mount). Both limits must be finite: a sandbox budget the kernel does not
// enforce is not a budget. The subtree must be disjoint from every cgroup in
// forbidden (the miner agent's own, and the one deployment.v4 replicas run
// in), so sandboxes never share CPU or memory with web replicas.
func VerifySandboxCgroup(root, cgroup string, forbidden []string) (sandbox.Capacity, error) {
	clean := path.Clean("/" + strings.TrimPrefix(cgroup, "/"))
	if cgroup == "" || clean == "/" || clean != cgroup {
		return sandbox.Capacity{}, fmt.Errorf("sandbox cgroup %q must be a clean absolute path below the cgroup root", cgroup)
	}
	for _, other := range forbidden {
		if other == "" || !path.IsAbs(other) || path.Clean(other) != other || other == "/" {
			return sandbox.Capacity{}, fmt.Errorf("exclusive cgroup %q must be a clean absolute path below the cgroup root", other)
		}
		if within(clean, other) || within(other, clean) {
			return sandbox.Capacity{}, fmt.Errorf("sandbox cgroup %q overlaps cgroup %q, which sandboxes must not share", clean, other)
		}
	}
	dir, err := openSandboxCgroup(root, clean)
	if err != nil {
		return sandbox.Capacity{}, err
	}
	defer dir.Close()
	cpu, err := readCgroupFile(dir, "cpu.max")
	if err != nil {
		return sandbox.Capacity{}, err
	}
	// cpu.max is "<quota> <period>"; a quota of "max" is no limit.
	fields := strings.Fields(cpu)
	var quota, period int64
	var quotaErr, periodErr error
	if len(fields) == 2 {
		quota, quotaErr = strconv.ParseInt(fields[0], 10, 64)
		period, periodErr = strconv.ParseInt(fields[1], 10, 64)
	}
	if len(fields) != 2 || quotaErr != nil || periodErr != nil || period <= 0 {
		return sandbox.Capacity{}, fmt.Errorf("sandbox cgroup cpu.max %q is not a finite limit", cpu)
	}
	memory, err := readCgroupFile(dir, "memory.max")
	if err != nil {
		return sandbox.Capacity{}, err
	}
	bytes, err := strconv.ParseInt(memory, 10, 64)
	if err != nil || bytes <= 0 {
		return sandbox.Capacity{}, fmt.Errorf("sandbox cgroup memory.max %q is not a finite limit", memory)
	}
	return sandbox.Capacity{CPUMillis: int(quota * 1000 / period), MemoryMiB: int(bytes >> 20)}, nil
}

// Open each path component relative to its already-open parent. A symlink in
// the subtree or either limit file could otherwise make finite values from an
// unrelated location stand in for the sandbox's actual cgroup limits.
func openSandboxCgroup(root, cgroup string) (*os.File, error) {
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open cgroup root %q: %w", root, err)
	}
	for _, part := range strings.Split(strings.TrimPrefix(cgroup, "/"), "/") {
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		unix.Close(fd)
		if openErr != nil {
			return nil, fmt.Errorf("open sandbox cgroup %q: %w", cgroup, openErr)
		}
		fd = next
	}
	return os.NewFile(uintptr(fd), cgroup), nil
}

func readCgroupFile(dir *os.File, name string) (string, error) {
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return "", fmt.Errorf("sandbox cgroup %s has no %s; is it a cgroup v2 directory with the cpu and memory controllers?", dir.Name(), name)
		}
		return "", fmt.Errorf("open sandbox cgroup %s/%s: %w", dir.Name(), name, err)
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 257))
	if err != nil {
		return "", err
	}
	if len(raw) > 256 {
		return "", fmt.Errorf("sandbox cgroup %s/%s is too large", dir.Name(), name)
	}
	return strings.TrimSpace(string(raw)), nil
}

// within reports whether child is parent or below it.
func within(child, parent string) bool {
	return child == parent || strings.HasPrefix(child, parent+"/")
}
