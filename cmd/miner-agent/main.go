// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
	"github.com/misscomputer/misscomputer-subnet/pkg/bridge"
	"github.com/misscomputer/misscomputer-subnet/pkg/durable"
	"github.com/misscomputer/misscomputer-subnet/pkg/miner"
	"github.com/misscomputer/misscomputer-subnet/pkg/neuron"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	deployruntime "github.com/misscomputer/misscomputer-subnet/pkg/runtime"
	"github.com/misscomputer/misscomputer-subnet/pkg/service"
	"github.com/misscomputer/misscomputer-subnet/pkg/tunnel"
)

type api struct {
	agent   *miner.Agent
	store   *durable.Store
	network string
	netuid  uint16
	hotkey  string
	uid     *uint16
	public  ed25519.PublicKey
}

func main() {
	if err := run(); err != nil {
		slog.Error("miner agent stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		bind                  = flag.String("bind", "127.0.0.1:9101", "authenticated Python-to-Go bridge address")
		allowNonLoopback      = flag.Bool("allow-non-loopback", false, "allow bridge binding beyond loopback (unsafe unless separately isolated)")
		network               = flag.String("network", "local", "Bittensor network name or endpoint identity")
		netuid                = flag.Uint("netuid", 0, "Bittensor subnet netuid")
		hotkey                = flag.String("hotkey", "", "registered miner hotkey SS58")
		uid                   = flag.Int("uid", -1, "current miner UID, or -1 when unknown")
		secretFile            = flag.String("bridge-secret-file", "", "file containing the loopback HMAC secret")
		secretEnv             = flag.String("bridge-secret-env", "MISS_BRIDGE_SECRET", "environment variable fallback for the HMAC secret")
		keyFile               = flag.String("service-key-file", "", "persistent Ed25519 Go service key file")
		stateDB               = flag.String("state-db", "", "SQLite state path")
		artifactBackend       = flag.String("artifact-backend", "file", "artifact backend: file or s3")
		artifactDir           = flag.String("artifact-dir", "", "local artifact store root")
		s3Endpoint            = flag.String("s3-endpoint", "", "S3-compatible origin endpoint")
		s3Bucket              = flag.String("s3-bucket", "", "S3-compatible bucket")
		s3Region              = flag.String("s3-region", "auto", "S3 signing region")
		s3AccessKeyEnv        = flag.String("s3-access-key-env", "S3_ACCESS_KEY_ID", "environment variable containing S3 access key")
		s3SecretKeyEnv        = flag.String("s3-secret-key-env", "S3_SECRET_ACCESS_KEY", "environment variable containing S3 secret key")
		s3RequestTimeout      = flag.Duration("s3-request-timeout", artifact.DefaultS3RequestTimeout, "timeout for each S3 request attempt")
		s3MaxAttempts         = flag.Int("s3-max-attempts", artifact.DefaultS3MaxAttempts, "maximum attempts for transient S3 failures")
		runtimeKind           = flag.String("runtime", "local", "runtime backend: local or docker")
		dockerState           = flag.String("docker-state-dir", "", "verified Docker layer state directory")
		minerTransport        = flag.String("miner-transport", "https", "advertised miner transport: https, or explicit mock http")
		tlsCertificateSHA256  = flag.String("tls-certificate-sha256", "", "SHA-256 fingerprint of the configured public TLS leaf certificate")
		allowInsecureMockHTTP = flag.Bool("allow-insecure-mock-http", false, "allow pinless HTTP tickets only on an explicit local/mock network")
	)
	flag.Parse()
	if err := service.ValidateBind(*bind, *allowNonLoopback); err != nil {
		return err
	}
	if strings.TrimSpace(*network) == "" || *hotkey == "" || *keyFile == "" || *stateDB == "" {
		return errors.New("network, hotkey, service-key-file, and state-db are required")
	}
	if *netuid > 65535 || *uid < -1 || *uid > 65535 {
		return errors.New("netuid or UID exceeds uint16")
	}
	if *minerTransport == neuron.TransportHTTPS {
		if !neuron.CanonicalSHA256(*tlsCertificateSHA256) {
			return errors.New("HTTPS miner transport requires a canonical lowercase TLS certificate SHA-256")
		}
	} else if *minerTransport != neuron.TransportHTTP || *tlsCertificateSHA256 != "" || !*allowInsecureMockHTTP || !localMockNetwork(*network) {
		return errors.New("pinless HTTP miner transport requires --allow-insecure-mock-http on an explicit local/mock network")
	}
	secret, err := bridge.LoadSecret(*secretFile, *secretEnv)
	if err != nil {
		return err
	}
	privateKey, err := service.LoadOrCreateSigningKey(*keyFile)
	if err != nil {
		return err
	}
	store, err := durable.Open(*stateDB)
	if err != nil {
		return err
	}
	defer store.Close()
	artifacts, err := service.ArtifactStoreWithOptions(
		*artifactBackend, *artifactDir, *s3Endpoint, *s3Bucket, *s3Region, *s3AccessKeyEnv, *s3SecretKeyEnv,
		service.ArtifactStoreOptions{RequestTimeout: *s3RequestTimeout, MaxAttempts: *s3MaxAttempts},
	)
	if err != nil {
		return err
	}
	var runtime deployruntime.Runtime
	switch *runtimeKind {
	case "local":
		runtime = deployruntime.NewLocalRuntime()
	case "docker":
		runtime = deployruntime.NewDockerRuntime("docker", *dockerState)
	default:
		return fmt.Errorf("unsupported runtime %q", *runtimeKind)
	}
	registry := tunnel.NewLocalRegistry()
	agent := miner.NewAgent(*hotkey, nil, privateKey, artifacts, runtime, registry)
	agent.State = store
	agent.MinerTransport = *minerTransport
	agent.MinerTLSCertificateSHA256 = *tlsCertificateSHA256
	recoveryCtx, recoveryCancel := context.WithTimeout(context.Background(), 30*time.Second)
	if err := agent.RecoverCleanup(recoveryCtx); err != nil {
		recoveryCancel()
		return fmt.Errorf("restart cleanup: %w", err)
	}
	recoveryCancel()
	var minerUID *uint16
	if *uid >= 0 {
		value := uint16(*uid)
		minerUID = &value
	}
	serviceAPI := &api{
		agent: agent, store: store, network: *network, netuid: uint16(*netuid), hotkey: *hotkey, uid: minerUID,
		public: privateKey.Public().(ed25519.PublicKey),
	}
	protected := http.NewServeMux()
	protected.HandleFunc("GET /v1/capabilities", serviceAPI.capabilities)
	protected.HandleFunc("POST /v1/assignments", serviceAPI.assign)
	protected.HandleFunc("POST /v1/status", serviceAPI.status)
	protected.HandleFunc("POST /v1/deactivate", serviceAPI.deactivate)
	protected.HandleFunc("GET /v1/runtime/{endpoint}/{path...}", serviceAPI.runtime)
	root := http.NewServeMux()
	root.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	root.Handle("/v1/", bridge.Authenticator{Secret: secret, Store: store}.Middleware(protected))
	server := &http.Server{
		Addr: *bind, Handler: root, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second,
		WriteTimeout: 2 * time.Minute, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32 << 10,
	}
	shutdownCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errorsChannel := make(chan error, 1)
	go func() {
		slog.Info("miner agent ready", "bind", *bind, "network", *network, "netuid", *netuid, "hotkey", *hotkey)
		errorsChannel <- server.ListenAndServe()
	}()
	var serveErr error
	select {
	case err := <-errorsChannel:
		if !errors.Is(err, http.ErrServerClosed) {
			serveErr = err
		}
	case <-shutdownCtx.Done():
	}
	shutdown, cancelShutdown := context.WithTimeout(context.Background(), 15*time.Second)
	if err := server.Shutdown(shutdown); serveErr == nil && err != nil {
		serveErr = err
	}
	cancelShutdown()
	cleanup, cancelCleanup := context.WithTimeout(context.Background(), 30*time.Second)
	if err := agent.RecoverCleanup(cleanup); serveErr == nil && err != nil {
		serveErr = fmt.Errorf("shutdown cleanup: %w", err)
	}
	cancelCleanup()
	return serveErr
}

func localMockNetwork(network string) bool {
	normalized := strings.ToLower(strings.TrimSpace(network))
	return normalized == "local" || normalized == "mock" || strings.HasPrefix(normalized, "mock-")
}

func (a *api) capabilities(w http.ResponseWriter, _ *http.Request) {
	var certificatePin *string
	if a.agent.MinerTLSCertificateSHA256 != "" {
		pin := a.agent.MinerTLSCertificateSHA256
		certificatePin = &pin
	}
	writeJSON(w, http.StatusOK, neuron.LocalCapabilities{
		Protocol: neuron.SynapseVersion, Network: a.network, NetUID: a.netuid, MinerHotkey: a.hotkey, MinerUID: a.uid,
		ServicePublicKey: hex.EncodeToString(a.public), Transport: a.agent.MinerTransport, TransportCertificateSHA256: certificatePin,
		Features: []string{"deploy", "status", "deactivate", "runtime-proxy", neuron.FeatureProbeAttestationV1}, MaxBodyBytes: bridge.MaxBodyBytes,
	})
}

func (a *api) assign(w http.ResponseWriter, req *http.Request) {
	var input neuron.LocalAssignRequest
	if err := decodeJSON(req.Body, &input); err != nil {
		bridge.WriteError(w, http.StatusBadRequest, "invalid_request", err.Error(), false)
		return
	}
	if input.Protocol != neuron.SynapseVersion || input.RequestID == "" || !input.BindingVerified {
		bridge.WriteError(w, http.StatusForbidden, "binding_unverified", "validator hotkey service binding was not verified", false)
		return
	}
	binding := input.ValidatorBinding
	if binding.Protocol != neuron.ServiceBindingVersion || binding.Role != "validator" || binding.Network != a.network || binding.NetUID != a.netuid || binding.Hotkey != input.CallerHotkey || binding.ServicePublicKey == "" {
		bridge.WriteError(w, http.StatusForbidden, "identity_mismatch", "validator binding does not match the authenticated caller", false)
		return
	}
	if err := neuron.ValidateServiceBindingTransport(binding, false); err != nil {
		bridge.WriteError(w, http.StatusForbidden, "identity_mismatch", err.Error(), false)
		return
	}
	keyBytes, err := hex.DecodeString(binding.ServicePublicKey)
	if err != nil || len(keyBytes) != ed25519.PublicKeySize {
		bridge.WriteError(w, http.StatusBadRequest, "invalid_service_key", "validator service key is invalid", false)
		return
	}
	if input.CurrentBlock < binding.ValidFromBlock || input.CurrentBlock >= binding.ExpiresAtBlock {
		bridge.WriteError(w, http.StatusGone, "expired_binding", "validator service binding is not current", false)
		return
	}
	if err := a.store.UpsertServiceBinding(req.Context(), durable.ServiceBinding{
		Role: binding.Role, Network: binding.Network, NetUID: binding.NetUID, Hotkey: binding.Hotkey, UID: binding.UID,
		ServicePublicKey: binding.ServicePublicKey, Generation: binding.Generation, ExpiresAtBlock: binding.ExpiresAtBlock,
		Transport: binding.Transport, TransportCertificateSHA256: optionalString(binding.TransportCertificateSHA256),
		BindingJSON: neuron.BindingJSON(binding),
	}); err != nil {
		bridge.WriteError(w, http.StatusConflict, "binding_rollback", err.Error(), false)
		return
	}
	result, err := a.agent.AssignBound(req.Context(), input.Ticket, ed25519.PublicKey(keyBytes), input.CurrentBlock, a.network, a.netuid, input.CallerHotkey, a.hotkey, a.uid)
	if err != nil {
		status, code, retryable := assignmentError(err)
		bridge.WriteError(w, status, code, err.Error(), retryable)
		return
	}
	writeJSON(w, http.StatusOK, deployResponse(input.RequestID, result))
}

func deployResponse(requestID string, result miner.Result) neuron.DeployResponse {
	return neuron.DeployResponse{
		Protocol: neuron.SynapseVersion, RequestID: requestID, Result: result, Idempotent: result.Idempotent,
	}
}

func (a *api) status(w http.ResponseWriter, req *http.Request) {
	var input neuron.StatusSynapse
	if err := decodeJSON(req.Body, &input); err != nil {
		bridge.WriteError(w, http.StatusBadRequest, "invalid_request", err.Error(), false)
		return
	}
	if input.Protocol != neuron.SynapseVersion || input.RequestID == "" {
		bridge.WriteError(w, http.StatusBadRequest, "version_mismatch", "unsupported status contract", false)
		return
	}
	ticket, status, exists, err := a.store.AssignmentTicket(req.Context(), input.EndpointID)
	if err != nil {
		bridge.WriteError(w, http.StatusInternalServerError, "state_error", err.Error(), true)
		return
	}
	if !exists {
		writeJSON(w, http.StatusOK, neuron.StatusResponse{Protocol: neuron.SynapseVersion, RequestID: input.RequestID, Status: "absent"})
		return
	}
	if ticket.Subnet == nil || ticket.Subnet.ValidatorHotkey != input.CallerHotkey {
		bridge.WriteError(w, http.StatusForbidden, "identity_mismatch", "assignment belongs to another validator", false)
		return
	}
	if err := a.agent.ValidateSubnetTransport(ticket); err != nil {
		bridge.WriteError(w, http.StatusForbidden, "identity_mismatch", err.Error(), false)
		return
	}
	receipt, found, err := a.store.CachedResult(req.Context(), input.EndpointID)
	if err != nil {
		bridge.WriteError(w, http.StatusInternalServerError, "state_error", err.Error(), true)
		return
	}
	var receiptPointer *protocol.Receipt
	if found {
		receiptPointer = &receipt
	}
	writeJSON(w, http.StatusOK, neuron.StatusResponse{Protocol: neuron.SynapseVersion, RequestID: input.RequestID, Status: status, Receipt: receiptPointer})
}

func (a *api) deactivate(w http.ResponseWriter, req *http.Request) {
	var input neuron.DeactivateSynapse
	if err := decodeJSON(req.Body, &input); err != nil {
		bridge.WriteError(w, http.StatusBadRequest, "invalid_request", err.Error(), false)
		return
	}
	if input.Protocol != neuron.SynapseVersion || input.RequestID == "" {
		bridge.WriteError(w, http.StatusBadRequest, "version_mismatch", "unsupported deactivation contract", false)
		return
	}
	ticket, _, exists, err := a.store.AssignmentTicket(req.Context(), input.EndpointID)
	if err != nil {
		bridge.WriteError(w, http.StatusInternalServerError, "state_error", err.Error(), true)
		return
	}
	if !exists {
		if err := a.agent.FenceDeactivation(req.Context(), input.EndpointID, input.DeploymentID, input.CallerHotkey); err != nil {
			bridge.WriteError(w, http.StatusConflict, "cleanup_failed", err.Error(), false)
			return
		}
		writeJSON(w, http.StatusOK, neuron.DeactivateResponse{Protocol: neuron.SynapseVersion, RequestID: input.RequestID, Status: "deactivated"})
		return
	}
	if ticket.DeploymentID != input.DeploymentID || ticket.Subnet == nil || ticket.Subnet.ValidatorHotkey != input.CallerHotkey {
		bridge.WriteError(w, http.StatusForbidden, "identity_mismatch", "deactivation does not own this endpoint", false)
		return
	}
	if err := a.agent.ValidateSubnetTransport(ticket); err != nil {
		bridge.WriteError(w, http.StatusForbidden, "identity_mismatch", err.Error(), false)
		return
	}
	if err := a.agent.Deactivate(req.Context(), input.EndpointID); err != nil {
		bridge.WriteError(w, http.StatusBadGateway, "cleanup_failed", err.Error(), true)
		return
	}
	writeJSON(w, http.StatusOK, neuron.DeactivateResponse{Protocol: neuron.SynapseVersion, RequestID: input.RequestID, Status: "deactivated"})
}

func optionalString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func (a *api) runtime(w http.ResponseWriter, req *http.Request) {
	endpointID := req.PathValue("endpoint")
	rest := req.PathValue("path")
	for _, header := range []string{
		bridge.HeaderVersion, bridge.HeaderTimestamp, bridge.HeaderNonce, bridge.HeaderSignature,
	} {
		req.Header.Del(header)
	}
	req.URL.Path = "/" + rest
	req.URL.RawPath = ""
	a.agent.ProxyRuntime(w, req, endpointID)
}

func assignmentError(err error) (int, string, bool) {
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "replayed") || strings.Contains(message, "already"):
		return http.StatusConflict, "replayed_assignment", false
	case strings.Contains(message, "expired") || strings.Contains(message, "not valid"):
		return http.StatusGone, "expired_assignment", false
	case strings.Contains(message, "hotkey") || strings.Contains(message, "signature") || strings.Contains(message, "subnet") || strings.Contains(message, "uid") ||
		strings.Contains(message, "service key") || strings.Contains(message, "transport") || strings.Contains(message, "certificate pin"):
		return http.StatusForbidden, "identity_mismatch", false
	default:
		return http.StatusUnprocessableEntity, "assignment_failed", false
	}
}

func decodeJSON(reader io.Reader, output any) error {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request must contain one JSON value")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
