// SPDX-License-Identifier: AGPL-3.0-only

// Package controlplane is the validator control plane owned by the public
// runtime: finalized chain and miner-set admission, three-replica scheduling,
// the signed edge route authority and provider-neutral edge origin, health
// actions, dry-run weight preparation, restart recovery, and the optional
// synthetic campaign. Private operators reach it only through the
// misscomputer.runtime.v1 socket served by cmd/misscomputer-runtime.
package controlplane

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
	campaignintegration "github.com/misscomputer/misscomputer-subnet/pkg/campaign/integration"
	"github.com/misscomputer/misscomputer-subnet/pkg/control"
	"github.com/misscomputer/misscomputer-subnet/pkg/durable"
	"github.com/misscomputer/misscomputer-subnet/pkg/edge"
	"github.com/misscomputer/misscomputer-subnet/pkg/ledger"
	"github.com/misscomputer/misscomputer-subnet/pkg/neuron"
	"github.com/misscomputer/misscomputer-subnet/pkg/policy"
	"github.com/misscomputer/misscomputer-subnet/pkg/remote"
	"github.com/misscomputer/misscomputer-subnet/pkg/service"
	"github.com/misscomputer/misscomputer-subnet/pkg/tunnel"
	validatorcore "github.com/misscomputer/misscomputer-subnet/pkg/validator"
)

// Config is the complete production configuration of the control plane. It
// carries no provider names or credentials: object storage arrives as an
// already-constructed provider-neutral store and edge identity is expressed
// through trusted proxy peers and neutral identity headers.
type Config struct {
	Network          string
	NetUID           uint16
	ValidatorHotkey  string
	Domain           string
	RouteLabelPrefix string
	Replicas         int

	// BridgeSecret authenticates assignment traffic to the validator neuron's
	// loopback bridge. It is the same root-provisioned secret the private
	// gateway uses to authenticate the neuron.
	BridgeSecret   []byte
	ServiceKeyFile string
	StateDB        string
	Artifacts      artifact.Store

	EdgeProbeURL                      string
	EdgeTrustedProxyCIDRs             []string
	EdgeRequireTrustedIngressIdentity bool
	EdgeMaxRequestBytes               int64
	EdgeMaxResponseBytes              int64
	EdgeResponseHeaderTimeout         time.Duration

	AllowLocalWorkloads   bool
	AllowPrivateAxons     bool
	AllowInsecureMockHTTP bool

	CampaignConfigFile    string
	CampaignStateDir      string
	CampaignReadinessFile string

	Logger *slog.Logger
}

// Plane is one running control plane. Control returns the authenticated
// route table the private gateway replays into; Edge returns the public edge
// origin handler.
type Plane struct {
	api      *api
	store    *durable.Store
	gateway  *edge.Gateway
	campaign *campaignintegration.Runner
	control  http.Handler
	logger   *slog.Logger
}

func New(config Config) (plane *Plane, err error) {
	if strings.TrimSpace(config.Network) == "" || config.ValidatorHotkey == "" || config.ServiceKeyFile == "" || config.StateDB == "" {
		return nil, errors.New("network, validator-hotkey, service-key-file, and state-db are required")
	}
	if config.Replicas != 3 {
		return nil, errors.New("this subnet architecture requires exactly three active replicas")
	}
	if config.EdgeMaxRequestBytes == 0 {
		config.EdgeMaxRequestBytes = 1 << 20
	}
	if config.EdgeMaxResponseBytes == 0 {
		config.EdgeMaxResponseBytes = 64 << 20
	}
	if config.EdgeResponseHeaderTimeout == 0 {
		config.EdgeResponseHeaderTimeout = 15 * time.Second
	}
	if config.EdgeMaxRequestBytes < 1 || config.EdgeMaxResponseBytes < 1 || config.EdgeResponseHeaderTimeout <= 0 {
		return nil, errors.New("edge request/response bounds and response-header timeout must be positive")
	}
	if config.EdgeProbeURL == "" {
		return nil, errors.New("edge acceptance probe URL is required")
	}
	if config.EdgeRequireTrustedIngressIdentity && strings.TrimRight(config.EdgeProbeURL, "/") != "https://{host}" {
		return nil, errors.New("trusted-ingress edge mode requires an https://{host} acceptance probe so acceptance traverses the public path")
	}
	if config.EdgeRequireTrustedIngressIdentity && config.AllowPrivateAxons {
		return nil, errors.New("trusted-ingress edge mode cannot enable private axon upstreams")
	}
	if config.AllowPrivateAxons && !localMockNetwork(config.Network) {
		return nil, errors.New("private axons are restricted to an explicit local/mock network")
	}
	if config.AllowInsecureMockHTTP && (!config.AllowPrivateAxons || !localMockNetwork(config.Network)) {
		return nil, errors.New("insecure mock HTTP requires private axons and an explicit local/mock network")
	}
	if len(config.BridgeSecret) < 32 {
		return nil, errors.New("bridge secret must contain at least 32 bytes")
	}
	if config.Artifacts == nil {
		return nil, errors.New("an artifact store is required")
	}
	trustedProxyCIDRs := make([]string, 0, len(config.EdgeTrustedProxyCIDRs))
	for _, cidr := range config.EdgeTrustedProxyCIDRs {
		if trimmed := strings.TrimSpace(cidr); trimmed != "" {
			trustedProxyCIDRs = append(trustedProxyCIDRs, trimmed)
		}
	}
	if len(trustedProxyCIDRs) == 0 {
		return nil, errors.New("at least one exact edge trusted-proxy CIDR is required")
	}
	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}
	privateKey, err := service.LoadOrCreateSigningKey(config.ServiceKeyFile)
	if err != nil {
		return nil, err
	}
	store, err := durable.Open(config.StateDB)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = store.Close()
		}
	}()
	registry := tunnel.NewLocalRegistry()
	probeToken, err := edge.GenerateProbeToken()
	if err != nil {
		return nil, err
	}
	assignmentLedger, err := ledger.NewDurable(store)
	if err != nil {
		return nil, fmt.Errorf("load durable ledger: %w", err)
	}
	startupRecovery, err := loadStartupRecovery(context.Background(), store)
	if err != nil {
		return nil, fmt.Errorf("load startup recovery snapshot: %w", err)
	}
	router, err := edge.NewAuthorizedRouter(registry, probeToken, edge.RouterConfig{
		AuthorityKey: privateKey.Public().(ed25519.PublicKey), Store: store, Domain: config.Domain, HostLabelPrefix: config.RouteLabelPrefix,
		AllowPrivateUpstreams: config.AllowPrivateAxons, RequireBoundTickets: true, RequireEndpointPath: !config.AllowPrivateAxons,
		AllowInsecureMockHTTP: config.AllowInsecureMockHTTP,
		ResponseHeaderTimeout: config.EdgeResponseHeaderTimeout, MaxResponseBytes: config.EdgeMaxResponseBytes,
	})
	if err != nil {
		return nil, err
	}
	gateway, err := edge.NewGateway(router, edge.GatewayConfig{
		Domain: config.Domain, HostLabelPrefix: config.RouteLabelPrefix, TrustedProxyCIDRs: trustedProxyCIDRs,
		RequireTrustedIngressIdentity: config.EdgeRequireTrustedIngressIdentity, MaxRequestBytes: config.EdgeMaxRequestBytes, Logger: logger,
	})
	if err != nil {
		return nil, err
	}
	scheduler := &control.Scheduler{
		SigningKey: privateKey, Router: router, Ledger: assignmentLedger, Health: policy.NewMonitor(), Replicas: config.Replicas, Domain: config.Domain, HostLabelPrefix: config.RouteLabelPrefix,
		Validator: validatorcore.Validator{Vantage: "validator-control", EdgeURL: strings.TrimRight(config.EdgeProbeURL, "/"), InternalProbeToken: probeToken},
	}
	serviceAPI := &api{
		scheduler: scheduler, ledger: assignmentLedger, store: store, artifacts: config.Artifacts,
		secret: append([]byte(nil), config.BridgeSecret...), publicKey: privateKey.Public().(ed25519.PublicKey), network: config.Network, netuid: config.NetUID,
		validatorHotkey: config.ValidatorHotkey, allowSynthetic: config.AllowLocalWorkloads, allowPrivateAxons: config.AllowPrivateAxons,
		allowInsecureMockHTTP: config.AllowInsecureMockHTTP,
		campaignReadinessFile: config.CampaignReadinessFile,
		miners:                make(map[string]*remote.Assigner), registrations: make(map[string]neuron.MinerRegistration),
		publishedRegistrations: make(map[string]neuron.MinerRegistration),
		startupRecovery:        startupRecovery,
		tunnels:                registry,
	}
	plane = &Plane{api: serviceAPI, store: store, gateway: gateway, control: routes(serviceAPI), logger: logger}
	if config.CampaignConfigFile != "" {
		campaignConfig, campaignDigest, loadErr := campaignintegration.LoadRuntimeConfig(config.CampaignConfigFile)
		if loadErr != nil {
			err = fmt.Errorf("load synthetic campaign config: %w", loadErr)
			gateway.Close()
			return nil, err
		}
		if campaignConfig.Campaign.Enabled {
			if config.CampaignStateDir == "" || config.CampaignReadinessFile == "" {
				err = errors.New("enabled synthetic campaign requires explicit state directory and readiness proof")
				gateway.Close()
				return nil, err
			}
			readiness, readinessErr := campaignintegration.LoadReadinessProof(config.CampaignReadinessFile, time.Now().UTC())
			if readinessErr != nil {
				err = fmt.Errorf("load synthetic campaign readiness: %w", readinessErr)
				gateway.Close()
				return nil, err
			}
			managedArtifacts, ok := config.Artifacts.(campaignintegration.ManagedArtifactStore)
			if !ok {
				err = errors.New("enabled synthetic campaign requires exact artifact deletion support")
				gateway.Close()
				return nil, err
			}
			runner, runnerErr := campaignintegration.NewRunner(campaignConfig, campaignDigest, campaignintegration.Dependencies{
				StateDirectory: config.CampaignStateDir,
				Environment: campaignintegration.ActivationEnvironment{
					Network: config.Network, NetUID: config.NetUID, Domain: config.Domain, HostLabelPrefix: config.RouteLabelPrefix,
					EdgeRequiresManagedWildcard: config.EdgeRequireTrustedIngressIdentity, EdgeProbeURL: config.EdgeProbeURL,
				},
				Readiness: readiness, Scheduler: scheduler, Artifacts: managedArtifacts,
				Miners: serviceAPI.campaignMinerIDs,
			})
			if runnerErr != nil {
				err = fmt.Errorf("activate synthetic campaign: %w", runnerErr)
				gateway.Close()
				return nil, err
			}
			serviceAPI.campaign = runner
			plane.campaign = runner
		}
	}
	return plane, nil
}

// routes is the exact production control route table. Authentication is the
// private gateway's responsibility; every route here is reachable only through
// the runtime socket.
func routes(serviceAPI *api) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/capabilities", serviceAPI.capabilities)
	mux.HandleFunc("POST /v1/chain-state", serviceAPI.updateChain)
	mux.HandleFunc("POST /v1/miners", serviceAPI.registerMiner)
	mux.HandleFunc("GET /v1/miners/{hotkey}", serviceAPI.minerRegistration)
	mux.HandleFunc("POST /v1/miners/snapshot", serviceAPI.replaceMinerSet)
	mux.HandleFunc("GET /v1/miners", serviceAPI.listMiners)
	mux.HandleFunc("POST /v1/deployments", serviceAPI.deploy)
	mux.HandleFunc("POST /v1/local/deployments", serviceAPI.deploySynthetic)
	mux.HandleFunc("GET /v1/deployments/{deployment}", serviceAPI.deployment)
	mux.HandleFunc("DELETE /v1/deployments/{deployment}", serviceAPI.deactivateDeployment)
	mux.HandleFunc("POST /v1/health", serviceAPI.health)
	mux.HandleFunc("GET /v1/weights", serviceAPI.weights)
	mux.HandleFunc("GET /v1/recovery", serviceAPI.recovery)
	mux.HandleFunc("GET /v1/campaign/status", serviceAPI.campaignStatus)
	mux.HandleFunc("GET /v1/campaign/evidence/{sequence}", serviceAPI.campaignEvidence)
	mux.HandleFunc("POST /v1/campaign/pause", serviceAPI.campaignPause)
	mux.HandleFunc("POST /v1/campaign/resume", serviceAPI.campaignResume)
	mux.HandleFunc("POST /v1/campaign/drain", serviceAPI.campaignDrain)
	mux.HandleFunc("POST /v1/campaign/shutdown", serviceAPI.campaignShutdown)
	return mux
}

func (p *Plane) Control() http.Handler { return p.control }

func (p *Plane) Edge() http.Handler { return p.gateway }

func (p *Plane) ServicePublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), p.api.publicKey...)
}

func (p *Plane) CampaignEnabled() bool { return p.campaign != nil }

// Run drives the synthetic campaign until ctx is cancelled. Without an enabled
// campaign it simply waits for cancellation so callers have one lifecycle.
func (p *Plane) Run(ctx context.Context) error {
	if p.campaign == nil {
		<-ctx.Done()
		return nil
	}
	p.logger.Info("synthetic campaign ready", "scoring_disposition", control.ScoringEvidenceOnly)
	err := p.campaign.Run(ctx)
	if errors.Is(err, context.Canceled) && ctx.Err() != nil {
		return nil
	}
	return err
}

// Close shuts the campaign down within ctx, releases edge upstream
// connections, and closes the durable store.
func (p *Plane) Close(ctx context.Context) error {
	var first error
	if p.campaign != nil {
		first = p.campaign.Shutdown(ctx)
		p.campaign.Close()
	}
	p.gateway.Close()
	if err := p.store.Close(); first == nil {
		first = err
	}
	return first
}
