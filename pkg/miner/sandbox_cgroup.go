// SPDX-License-Identifier: AGPL-3.0-only

package miner

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/misscomputer/misscomputer-subnet/pkg/sandbox"
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
		other = path.Clean("/" + strings.TrimPrefix(other, "/"))
		if other == "/" {
			// The unlimited root cgroup is no budget to share.
			continue
		}
		if within(clean, other) || within(other, clean) {
			return sandbox.Capacity{}, fmt.Errorf("sandbox cgroup %q overlaps cgroup %q, which sandboxes must not share", clean, other)
		}
	}
	dir := filepath.Join(root, filepath.FromSlash(clean))
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

func readCgroupFile(dir, name string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("sandbox cgroup %s has no %s; is it a cgroup v2 directory with the cpu and memory controllers?", dir, name)
		}
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

// within reports whether child is parent or below it.
func within(child, parent string) bool {
	return child == parent || strings.HasPrefix(child, parent+"/")
}
