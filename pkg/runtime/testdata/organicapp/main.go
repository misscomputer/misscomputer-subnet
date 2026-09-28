// SPDX-License-Identifier: AGPL-3.0-only

// Command organicapp is the static test application for the Docker OCI
// runtime integration test. It serves a health endpoint and reports the
// isolation it observes from inside the container.
package main

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("organic-ready host=" + r.Host))
	})
	http.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {
		report := map[string]any{
			"uid": os.Getuid(), "gid": os.Getgid(), "env": os.Environ(),
			"rootfs_write": writeError("/app-write-test"),
			"tmp_write":    writeError("/tmp/write-test"),
			"status":       statusFields(),
			"pids_max":     readTrim("/sys/fs/cgroup/pids.max"),
			"memory_max":   readTrim("/sys/fs/cgroup/memory.max"),
		}
		var tmp syscall.Statfs_t
		if syscall.Statfs("/tmp", &tmp) == nil {
			report["tmp_bytes"] = tmp.Blocks * uint64(tmp.Bsize)
		}
		dials := map[string]string{}
		for _, target := range strings.Split(r.URL.Query().Get("dial"), ",") {
			if target != "" {
				dials[target] = dial(target)
			}
		}
		report["dials"] = dials
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(report)
	})
	server := &http.Server{Addr: net.JoinHostPort(os.Getenv("HOST"), os.Getenv("PORT")), ReadHeaderTimeout: 5 * time.Second}
	if err := server.ListenAndServe(); err != nil {
		os.Exit(1)
	}
}

func writeError(path string) string {
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		return err.Error()
	}
	return ""
}

func readTrim(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return "error: " + err.Error()
	}
	return strings.TrimSpace(string(data))
}

func statusFields() map[string]string {
	fields := map[string]string{}
	data, _ := os.ReadFile("/proc/self/status")
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok && (key == "CapEff" || key == "CapPrm" || key == "NoNewPrivs") {
			fields[key] = strings.TrimSpace(value)
		}
	}
	return fields
}

func dial(target string) string {
	conn, err := net.DialTimeout("tcp", target, 2*time.Second)
	if err != nil {
		return "blocked: " + err.Error()
	}
	conn.Close()
	return "open"
}
