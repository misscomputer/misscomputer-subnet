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
	"sync"
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

	// PeriodicProbeInterval enables the internal periodic serving prober. Zero
	// keeps it inert, preserving the historical behaviour in which health
	// actions run only when an external vantage posts an observation. A
	// negative value is rejected.
	//
	// The prober re-probes every active replica through the same internal
	// targeted path used at admission time and applies the result through the
	// existing health policy, so a miner that goes dark or starts serving the
	// wrong bytes after acceptance is evicted without an external caller.
	PeriodicProbeInterval time.Duration
	// PeriodicProbeTimeout bounds one replica probe. Zero uses
	// control.DefaultProbeTimeout.
	PeriodicProbeTimeout time.Duration

	Logger *slog.Logger
}

// Plane is one running control plane. Control returns the authenticated
// route table the private gateway replays into; Edge returns the public edge
// origin handler.
type Plane struct {
	api            *api
	scheduler      *control.Scheduler
	store          *durable.Store
	gateway        *edge.Gateway
	campaign       *campaignintegration.Runner
	prober         *control.Prober
	control        http.Handler
	logger         *slog.Logger
	runMu          sync.Mutex
	runActive      bool
	runDone        chan struct{}
	closing        bool
	requestMu      sync.Mutex
	requestActive  int
	requestDone    chan struct{}
	requestClosing bool
}

func New(config Config) (plane *Plane, err error) {
	if strings.TrimSpace(config.Network) == "" || config.ValidatorHotkey == "" || config.ServiceKeyFile == "" || config.StateDB == "" {
		return nil, errors.New("network, validator-hotkey, service-key-file, and state-db are required")
	}
	if config.Replicas != 3 {
		return nil, errors.New("this subnet architecture requires exactly three active replicas")
	}
	if config.PeriodicProbeInterval < 0 || config.PeriodicProbeTimeout < 0 {
		return nil, errors.New("periodic probe interval and timeout must not be negative")
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
	plane = &Plane{api: serviceAPI, scheduler: scheduler, store: store, gateway: gateway, control: routes(serviceAPI), logger: logger}
	if config.PeriodicProbeInterval > 0 {
		prober := &control.Prober{
			Scheduler: scheduler, Interval: config.PeriodicProbeInterval, Timeout: config.PeriodicProbeTimeout, Logger: logger,
		}
		// A prober whose cadence cannot produce two failures inside the health
		// rapid window evicts nothing at all, and a timeout at or beyond the
		// interval is the ordinary way to reach that state. The CLI rejects both,
		// but a library caller configuring the plane directly deserves the same
		// refusal instead of a silently inert prober.
		if cadenceErr := prober.Validate(); cadenceErr != nil {
			return nil, cadenceErr
		}
		plane.prober = prober
	}
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

func (p *Plane) Control() http.Handler { return p.admittedHandler(p.control) }

func (p *Plane) Edge() http.Handler { return p.admittedHandler(p.gateway) }

// admittedHandler keeps Plane resource ownership around the whole HTTP
// transaction, including API persistence that occurs after scheduler work has
// completed. Scheduler.Drain alone cannot see that tail, so Close first seals
// this admission gate and joins every admitted request.
func (p *Plane) admittedHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if !p.beginRequest() {
			http.Error(response, "control plane is closing", http.StatusServiceUnavailable)
			return
		}
		defer p.endRequest()
		next.ServeHTTP(response, request)
	})
}

func (p *Plane) beginRequest() bool {
	p.requestMu.Lock()
	defer p.requestMu.Unlock()
	if p.requestClosing {
		return false
	}
	if p.requestActive == 0 {
		p.requestDone = make(chan struct{})
	}
	p.requestActive++
	return true
}

func (p *Plane) endRequest() {
	p.requestMu.Lock()
	p.requestActive--
	if p.requestActive == 0 {
		close(p.requestDone)
	}
	p.requestMu.Unlock()
}

func (p *Plane) closeRequestAdmission(ctx context.Context) error {
	p.requestMu.Lock()
	p.requestClosing = true
	active := p.requestActive
	done := p.requestDone
	p.requestMu.Unlock()
	if active == 0 {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("join admitted control-plane requests: %w", ctx.Err())
	}
}

func (p *Plane) ServicePublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), p.api.publicKey...)
}

func (p *Plane) CampaignEnabled() bool { return p.campaign != nil }

// Run drives the synthetic campaign until ctx is cancelled. Without an enabled
// campaign it simply waits for cancellation so callers have one lifecycle.
func (p *Plane) Run(ctx context.Context) error {
	p.runMu.Lock()
	if p.closing {
		p.runMu.Unlock()
		return errors.New("control plane is closing")
	}
	if p.runActive {
		p.runMu.Unlock()
		return errors.New("control plane is already running")
	}
	p.runActive = true
	p.runDone = make(chan struct{})
	runDone := p.runDone
	p.runMu.Unlock()
	defer func() {
		p.runMu.Lock()
		p.runActive = false
		close(runDone)
		p.runMu.Unlock()
	}()
	// The prober owns no state the campaign needs and never returns before
	// cancellation, so it runs beside the campaign rather than in sequence.
	proberDone := make(chan struct{})
	if p.prober == nil {
		close(proberDone)
	} else {
		proberCtx, stopProber := context.WithCancel(ctx)
		defer stopProber()
		p.logger.Info("periodic serving prober ready", "interval", p.prober.Interval, "timeout", p.prober.Timeout)
		go func() {
			defer close(proberDone)
			if err := p.prober.Run(proberCtx); err != nil && !errors.Is(err, context.Canceled) {
				p.logger.Error("periodic serving prober stopped", "error", err)
			}
		}()
		defer func() {
			stopProber()
			<-proberDone
		}()
	}
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
	p.runMu.Lock()
	p.closing = true
	runActive := p.runActive
	runDone := p.runDone
	p.runMu.Unlock()
	if err := p.closeRequestAdmission(ctx); err != nil {
		return err
	}
	if p.campaign != nil {
		first = p.campaign.Shutdown(ctx)
		if ctx.Err() != nil {
			return errors.Join(first, ctx.Err())
		}
	}
	if runActive {
		select {
		case <-runDone:
		case <-ctx.Done():
			return errors.Join(first, fmt.Errorf("join control-plane runner: %w", ctx.Err()))
		}
	}
	if first != nil {
		// Shutdown may have committed terminal campaign state while a durable
		// evidence install or exact cleanup remains retryable. Keep every owned
		// resource open so a later Close call can finish that terminal work.
		return first
	}
	if p.campaign != nil {
		if err := p.campaign.Close(); err != nil {
			// Runner.Close leaves its store open when its workers have not joined,
			// so a later Close call can safely retry without closing resources
			// beneath a late campaign worker.
			return errors.Join(first, err)
		}
	}
	if p.scheduler != nil {
		if err := p.scheduler.Drain(ctx); err != nil {
			// Do not close the gateway/store beneath an assignment or exact
			// cleanup worker which still owns them. A caller can retry Close with
			// a fresh deadline after the late operation finishes.
			return errors.Join(first, err)
		}
	}
	p.gateway.Close()
	if err := p.store.Close(); first == nil {
		first = err
	}
	return first
}
