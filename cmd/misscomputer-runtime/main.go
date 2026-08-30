// SPDX-License-Identifier: AGPL-3.0-only

// Command misscomputer-runtime is the public validator runtime. It owns the
// production control plane (chain/miner-set admission, three-replica
// scheduling, signed edge route authority, health actions, dry-run weights,
// restart recovery, optional synthetic campaign), serves it to the private
// authenticated gateway over the misscomputer.runtime.v1 Unix socket, and
// binds the provider-neutral edge origin.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
	"github.com/misscomputer/misscomputer-subnet/pkg/bridge"
	"github.com/misscomputer/misscomputer-subnet/pkg/controlplane"
	"github.com/misscomputer/misscomputer-subnet/pkg/runtimeapi"
	"github.com/misscomputer/misscomputer-subnet/pkg/service"
)

type configuration struct {
	socketPath string
	stateDir   string

	edgeBind                          string
	edgeAllowNonLoopback              bool
	edgeTrustedProxyCIDRs             string
	edgeRequireTrustedIngressIdentity bool
	edgeProbeURL                      string
	edgeMaxRequestBytes               int64
	edgeMaxResponseBytes              int64
	edgeResponseHeaderTimeout         time.Duration

	network          string
	netuid           uint
	validatorHotkey  string
	domain           string
	routeLabelPrefix string
	replicas         int

	bridgeSecretFile string
	bridgeSecretEnv  string
	serviceKeyFile   string
	stateDB          string

	artifactBackend  string
	artifactDir      string
	s3Endpoint       string
	s3Bucket         string
	s3Region         string
	s3AccessKeyEnv   string
	s3SecretKeyEnv   string
	s3RequestTimeout time.Duration
	s3MaxAttempts    int

	allowLocalWorkloads   bool
	allowPrivateAxons     bool
	allowInsecureMockHTTP bool

	campaignConfigFile    string
	campaignStateDir      string
	campaignReadinessFile string
}

func main() {
	config, err := parseConfiguration(os.Args[1:])
	if err != nil {
		fatal(err.Error())
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	instance, err := newRuntime(config, slog.Default())
	if err != nil {
		fatal(err.Error())
	}
	if err := instance.serve(ctx); err != nil {
		fatal(err.Error())
	}
}

func parseConfiguration(arguments []string) (configuration, error) {
	var config configuration
	flags := flag.NewFlagSet("misscomputer-runtime", flag.ContinueOnError)
	flags.StringVar(&config.socketPath, "socket", "/run/misscomputer/runtime-v1.sock", "normalized absolute Unix socket path")
	flags.StringVar(&config.stateDir, "state-dir", "/var/lib/misscomputer/runtime-v1", "normalized absolute runtime state directory")
	flags.StringVar(&config.edgeBind, "edge-bind", "127.0.0.1:8081", "edge origin address (loopback by default)")
	flags.BoolVar(&config.edgeAllowNonLoopback, "edge-allow-non-loopback", false, "allow edge origin binding beyond loopback")
	flags.StringVar(&config.edgeTrustedProxyCIDRs, "edge-trusted-proxy-cidrs", "127.0.0.0/8,::1/128", "comma-separated direct ingress peer CIDRs")
	flags.BoolVar(&config.edgeRequireTrustedIngressIdentity, "edge-require-trusted-ingress-identity", false, "require X-Trusted-Client-IP and X-Trusted-Request-ID from a trusted direct peer")
	flags.StringVar(&config.edgeProbeURL, "edge-probe-url", "http://127.0.0.1:8081", "acceptance probe base URL or https://{host} template")
	flags.Int64Var(&config.edgeMaxRequestBytes, "edge-max-request-bytes", 1<<20, "maximum buffered public request body")
	flags.Int64Var(&config.edgeMaxResponseBytes, "edge-max-response-bytes", 64<<20, "maximum public response body")
	flags.DurationVar(&config.edgeResponseHeaderTimeout, "edge-response-header-timeout", 15*time.Second, "upstream response-header timeout")
	flags.StringVar(&config.network, "network", "", "configured Bittensor network identity")
	flags.UintVar(&config.netuid, "netuid", 0, "configured Bittensor netuid")
	flags.StringVar(&config.validatorHotkey, "validator-hotkey", "", "configured validator hotkey SS58")
	flags.StringVar(&config.domain, "domain", "mock.local", "deployment route suffix")
	flags.StringVar(&config.routeLabelPrefix, "route-label-prefix", "", "single-label route prefix, for example edge-dev-")
	flags.IntVar(&config.replicas, "replicas", 3, "required replica count")
	flags.StringVar(&config.bridgeSecretFile, "bridge-secret-file", "", "file containing the validator bridge HMAC secret")
	flags.StringVar(&config.bridgeSecretEnv, "bridge-secret-env", "MISS_BRIDGE_SECRET", "environment variable fallback for the bridge secret")
	flags.StringVar(&config.serviceKeyFile, "service-key-file", "", "persistent validator Go service key")
	flags.StringVar(&config.stateDB, "state-db", "", "SQLite control state path")
	flags.StringVar(&config.artifactBackend, "artifact-backend", "file", "artifact backend: file or s3")
	flags.StringVar(&config.artifactDir, "artifact-dir", "", "filesystem artifact store root")
	flags.StringVar(&config.s3Endpoint, "s3-endpoint", "", "S3-compatible origin endpoint")
	flags.StringVar(&config.s3Bucket, "s3-bucket", "", "S3-compatible bucket")
	flags.StringVar(&config.s3Region, "s3-region", "auto", "S3 signing region")
	flags.StringVar(&config.s3AccessKeyEnv, "s3-access-key-env", "S3_ACCESS_KEY_ID", "environment variable containing the S3 access key")
	flags.StringVar(&config.s3SecretKeyEnv, "s3-secret-key-env", "S3_SECRET_ACCESS_KEY", "environment variable containing the S3 secret key")
	flags.DurationVar(&config.s3RequestTimeout, "s3-request-timeout", artifact.DefaultS3RequestTimeout, "timeout for each S3 request attempt")
	flags.IntVar(&config.s3MaxAttempts, "s3-max-attempts", artifact.DefaultS3MaxAttempts, "maximum attempts for transient S3 failures")
	flags.BoolVar(&config.allowLocalWorkloads, "allow-local-workloads", false, "enable deterministic local synthetic deployment endpoint")
	flags.BoolVar(&config.allowPrivateAxons, "allow-private-axons", false, "allow private numeric-IP miner axon targets (local mock only)")
	flags.BoolVar(&config.allowInsecureMockHTTP, "allow-insecure-mock-http", false, "allow pinless HTTP miner axons only on an explicit local mock subnet")
	flags.StringVar(&config.campaignConfigFile, "campaign-config-file", "", "canonical synthetic campaign runtime config (empty keeps campaign inert)")
	flags.StringVar(&config.campaignStateDir, "campaign-state-dir", "", "private atomic synthetic campaign state directory")
	flags.StringVar(&config.campaignReadinessFile, "campaign-readiness-file", "", "canonical pre-provisioned wildcard readiness proof")
	if err := flags.Parse(arguments); err != nil {
		return config, err
	}
	if flags.NArg() != 0 {
		return config, errors.New("positional arguments are not accepted")
	}
	for name, value := range map[string]string{"socket": config.socketPath, "state-dir": config.stateDir} {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return config, fmt.Errorf("%s must be a normalized absolute path", name)
		}
	}
	if err := service.ValidateBind(config.edgeBind, config.edgeAllowNonLoopback); err != nil {
		return config, fmt.Errorf("edge origin bind: %w", err)
	}
	if config.netuid > 65535 || strings.TrimSpace(config.network) == "" || config.validatorHotkey == "" || config.serviceKeyFile == "" || config.stateDB == "" {
		return config, errors.New("network, validator-hotkey, service-key-file, state-db, and valid netuid are required")
	}
	if config.replicas != 3 {
		return config, errors.New("this subnet architecture requires exactly three active replicas")
	}
	if config.edgeMaxRequestBytes < 1 || config.edgeMaxResponseBytes < 1 || config.edgeResponseHeaderTimeout <= 0 {
		return config, errors.New("edge request/response bounds and response-header timeout must be positive")
	}
	return config, nil
}

type runtime struct {
	server       *runtimeapi.Server
	plane        *controlplane.Plane
	listener     net.Listener
	edgeListener net.Listener
	edgeServer   *http.Server
	socketPath   string
	logger       *slog.Logger
}

func newRuntime(config configuration, logger *slog.Logger) (instance *runtime, err error) {
	secret, err := bridge.LoadSecret(config.bridgeSecretFile, config.bridgeSecretEnv)
	if err != nil {
		return nil, err
	}
	artifacts, err := service.ArtifactStoreWithOptions(
		config.artifactBackend, config.artifactDir, config.s3Endpoint, config.s3Bucket, config.s3Region, config.s3AccessKeyEnv, config.s3SecretKeyEnv,
		service.ArtifactStoreOptions{RequestTimeout: config.s3RequestTimeout, MaxAttempts: config.s3MaxAttempts},
	)
	if err != nil {
		return nil, err
	}
	// The state-directory ownership lock is taken before any durable state,
	// socket, or listener is touched so a losing second instance can never
	// disturb the live owner.
	server, err := runtimeapi.Open(config.stateDir)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = server.Close()
		}
	}()
	plane, err := controlplane.New(controlplane.Config{
		Network: config.network, NetUID: uint16(config.netuid), ValidatorHotkey: config.validatorHotkey,
		Domain: config.domain, RouteLabelPrefix: config.routeLabelPrefix, Replicas: config.replicas,
		BridgeSecret: secret, ServiceKeyFile: config.serviceKeyFile, StateDB: config.stateDB, Artifacts: artifacts,
		EdgeProbeURL: config.edgeProbeURL, EdgeTrustedProxyCIDRs: strings.Split(config.edgeTrustedProxyCIDRs, ","),
		EdgeRequireTrustedIngressIdentity: config.edgeRequireTrustedIngressIdentity,
		EdgeMaxRequestBytes:               config.edgeMaxRequestBytes, EdgeMaxResponseBytes: config.edgeMaxResponseBytes,
		EdgeResponseHeaderTimeout: config.edgeResponseHeaderTimeout,
		AllowLocalWorkloads:       config.allowLocalWorkloads, AllowPrivateAxons: config.allowPrivateAxons, AllowInsecureMockHTTP: config.allowInsecureMockHTTP,
		CampaignConfigFile: config.campaignConfigFile, CampaignStateDir: config.campaignStateDir, CampaignReadinessFile: config.campaignReadinessFile,
		Logger: logger,
	})
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = plane.Close(context.Background())
		}
	}()
	server.Control = plane.Control()
	if err = os.MkdirAll(filepath.Dir(config.socketPath), 0o700); err != nil {
		return nil, err
	}
	if err = os.Remove(config.socketPath); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	listener, err := net.Listen("unix", config.socketPath)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = listener.Close()
			_ = os.Remove(config.socketPath)
		}
	}()
	if err = os.Chmod(config.socketPath, 0o600); err != nil {
		return nil, err
	}
	edgeListener, err := net.Listen("tcp", config.edgeBind)
	if err != nil {
		return nil, fmt.Errorf("edge origin listen: %w", err)
	}
	edgeServer := &http.Server{
		Handler: plane.Edge(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 2 * time.Minute, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10,
	}
	return &runtime{
		server: server, plane: plane, listener: listener, edgeListener: edgeListener, edgeServer: edgeServer,
		socketPath: config.socketPath, logger: logger,
	}, nil
}

func (r *runtime) edgeAddress() string { return r.edgeListener.Addr().String() }

// serve runs the runtime socket, the edge origin, and the control plane until
// ctx is cancelled or any of them fails, then shuts everything down in order.
func (r *runtime) serve(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	failures := make(chan error, 3)
	go func() { failures <- normalizeListenerError(r.server.Serve(r.listener)) }()
	go func() { failures <- normalizeListenerError(r.edgeServer.Serve(r.edgeListener)) }()
	go func() { failures <- r.plane.Run(ctx) }()
	r.logger.Info("public runtime ready", "socket", r.socketPath, "edge_bind", r.edgeAddress(), "campaign", r.plane.CampaignEnabled())
	var first error
	select {
	case <-ctx.Done():
	case first = <-failures:
	}
	cancel()
	_ = r.listener.Close()
	shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer shutdownCancel()
	if err := r.edgeServer.Shutdown(shutdownContext); first == nil {
		first = err
	}
	if err := r.plane.Close(shutdownContext); first == nil {
		first = err
	}
	if err := r.server.Close(); first == nil {
		first = err
	}
	_ = os.Remove(r.socketPath)
	return first
}

func normalizeListenerError(err error) error {
	if err == nil || errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	if _, ok := err.(*net.OpError); ok && strings.Contains(err.Error(), "use of closed network connection") {
		return nil
	}
	return err
}

func fatal(message string) {
	_, _ = fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
