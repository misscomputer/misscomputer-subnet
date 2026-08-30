// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/runtimeapi"
)

func baseArguments(t *testing.T) []string {
	t.Helper()
	root := t.TempDir()
	secretPath := filepath.Join(root, "bridge.secret")
	if err := os.WriteFile(secretPath, bytes.Repeat([]byte{'s'}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	return []string{
		"--socket", filepath.Join(root, "runtime.sock"), "--state-dir", filepath.Join(root, "runtime-v1"),
		"--network", "local", "--netuid", "42", "--validator-hotkey", "validator",
		"--bridge-secret-file", secretPath, "--service-key-file", filepath.Join(root, "service.key"),
		"--state-db", filepath.Join(root, "control.db"), "--artifact-dir", filepath.Join(root, "artifacts"),
		"--edge-bind", "127.0.0.1:0", "--allow-private-axons", "--allow-insecure-mock-http",
	}
}

func TestConfigurationFailsClosed(t *testing.T) {
	for name, arguments := range map[string][]string{
		"relative socket":     append(baseArguments(t), "--socket", "runtime.sock"),
		"unclean state dir":   append(baseArguments(t), "--state-dir", "/var/lib//misscomputer"),
		"missing identity":    append(baseArguments(t), "--validator-hotkey", ""),
		"two replicas":        append(baseArguments(t), "--replicas", "2"),
		"non-loopback edge":   append(baseArguments(t), "--edge-bind", "0.0.0.0:8081"),
		"netuid out of range": append(baseArguments(t), "--netuid", "70000"),
		"positional":          append(baseArguments(t), "extra"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseConfiguration(arguments); err == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
	if _, err := parseConfiguration(baseArguments(t)); err != nil {
		t.Fatal(err)
	}
}

func rpc(t *testing.T, socket string, request runtimeapi.Request) runtimeapi.Response {
	t.Helper()
	connection, err := net.DialTimeout("unix", socket, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Write(append(payload, '\n')); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(connection).ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	var response runtimeapi.Response
	if err := json.Unmarshal(line, &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func TestRuntimeServesTheControlPlaneOverTheSocketAndBindsTheEdgeOrigin(t *testing.T) {
	config, err := parseConfiguration(baseArguments(t))
	if err != nil {
		t.Fatal(err)
	}
	instance, err := newRuntime(config, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- instance.serve(ctx) }()

	ping := rpc(t, config.socketPath, runtimeapi.Request{JSONRPC: "2.0", ID: "ping", Method: "runtime.v1.ping", Params: json.RawMessage(`{}`)})
	if ping.Error != nil || !strings.Contains(string(ping.Result), runtimeapi.ProtocolVersion) {
		t.Fatalf("ping = %+v", ping)
	}
	params, _ := json.Marshal(runtimeapi.ControlRequest{Method: http.MethodGet, Path: "/v1/capabilities", Body: json.RawMessage(`{}`)})
	capabilities := rpc(t, config.socketPath, runtimeapi.Request{JSONRPC: "2.0", ID: "caps", Method: "runtime.v1.capabilities.get", Params: params})
	var control runtimeapi.ControlResponse
	if capabilities.Error != nil || json.Unmarshal(capabilities.Result, &control) != nil || control.Status != http.StatusOK ||
		!strings.Contains(string(control.Body), `"service_public_key"`) || !strings.Contains(string(control.Body), `"scheduler"`) {
		t.Fatalf("capabilities over the socket = %+v %+v", capabilities, control)
	}
	params, _ = json.Marshal(runtimeapi.ControlRequest{Method: http.MethodGet, Path: "/v1/weights", Query: "hours=24", Body: json.RawMessage(`{}`)})
	weights := rpc(t, config.socketPath, runtimeapi.Request{JSONRPC: "2.0", ID: "weights", Method: "runtime.v1.weights.get", Params: params})
	if weights.Error != nil || json.Unmarshal(weights.Result, &control) != nil || control.Status != http.StatusOK || !strings.Contains(string(control.Body), `"dry_run":true`) {
		t.Fatalf("weights over the socket = %+v %+v", weights, control)
	}
	params, _ = json.Marshal(runtimeapi.ControlRequest{Method: http.MethodPost, Path: "/v1/deployments", Body: json.RawMessage(`{"deployment_id":"demo","protocol":"wrong"}`)})
	deploy := rpc(t, config.socketPath, runtimeapi.Request{JSONRPC: "2.0", ID: "deploy", Method: "runtime.v1.deployment.create", Params: params})
	if deploy.Error != nil || json.Unmarshal(deploy.Result, &control) != nil || control.Status != http.StatusBadRequest {
		t.Fatalf("deployment validation over the socket = %+v %+v", deploy, control)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	request, _ := http.NewRequest(http.MethodGet, "http://"+instance.edgeAddress()+"/index.html", nil)
	request.Host = "demo.mock.local"
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusMisdirectedRequest || response.StatusCode == http.StatusOK {
		t.Fatalf("edge origin answered %d for a trusted loopback peer without a route", response.StatusCode)
	}

	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("serve returned %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("runtime did not stop after cancellation")
	}
	if _, err := os.Stat(config.socketPath); !os.IsNotExist(err) {
		t.Fatal("runtime socket was not removed at shutdown")
	}
}
