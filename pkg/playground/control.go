// SPDX-License-Identifier: AGPL-3.0-only

// Package playground composes the production campaign, scheduler, miner,
// artifact, edge, and validator components into one bounded local control run.
// It has no wallet, RPC, cloud, DNS, or live-service adapter.
package playground

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
	"github.com/misscomputer/misscomputer-subnet/pkg/campaign"
	"github.com/misscomputer/misscomputer-subnet/pkg/control"
	"github.com/misscomputer/misscomputer-subnet/pkg/edge"
	"github.com/misscomputer/misscomputer-subnet/pkg/ledger"
	"github.com/misscomputer/misscomputer-subnet/pkg/miner"
	"github.com/misscomputer/misscomputer-subnet/pkg/policy"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	deployruntime "github.com/misscomputer/misscomputer-subnet/pkg/runtime"
	"github.com/misscomputer/misscomputer-subnet/pkg/tunnel"
	"github.com/misscomputer/misscomputer-subnet/pkg/validator"
	"github.com/misscomputer/misscomputer-subnet/pkg/workload"
)

const (
	BundleSchema       = "miss.computer/misscomputer-subnet/supervised-playground-control-bundle"
	BundleVersion      = 1
	DefaultRunID       = "supervised-playground-v1"
	ValidatorUID       = uint16(7)
	ValidatorHotkey    = "ValidatorPlayground"
	FinalizedHeight    = uint64(12_345_678)
	FinalizedTempo     = uint64(360)
	controlRecordCount = 12
)

// MinerIdentity is the public finalized identity used by both the bound
// scheduler tickets and the later Python metagraph projection.
type MinerIdentity struct {
	UID      uint16 `json:"uid"`
	Hotkey   string `json:"hotkey"`
	Axon     string `json:"axon"`
	Active   bool   `json:"active"`
	Eligible bool   `json:"eligible"`
}

// ReplicaObservation is the credential-free projection of one scheduler-
// accepted bound ticket and validator-side acceptance observation.
type ReplicaObservation struct {
	TicketVersion      string    `json:"ticket_version"`
	DeploymentID       string    `json:"deployment_id"`
	BuildID            string    `json:"build_id"`
	ChallengePath      string    `json:"challenge_path"`
	ChallengeSHA256    string    `json:"challenge_sha256"`
	MinerUID           uint16    `json:"miner_uid"`
	MinerHotkey        string    `json:"miner_hotkey"`
	Generation         uint64    `json:"generation"`
	AssignmentNonce    string    `json:"assignment_nonce"`
	TicketDigestSHA256 string    `json:"ticket_digest_sha256"`
	ReplicaID          string    `json:"replica_id"`
	EndpointID         string    `json:"endpoint_id"`
	ImageDigest        string    `json:"image_digest"`
	ManifestKey        string    `json:"manifest_key"`
	AcceptedAt         time.Time `json:"accepted_at"`
	ObservedAt         time.Time `json:"observed_at"`
	Success            bool      `json:"success"`
	LatencyMS          int64     `json:"latency_ms"`
	TransferredBytes   int       `json:"transferred_bytes"`
}

// ControlRecord joins one production campaign evidence document to the
// independently projected scheduler observations used by central scoring.
type ControlRecord struct {
	FinalizedEpochIndex uint64               `json:"finalized_epoch_index"`
	CompletionDeadline  time.Time            `json:"completion_deadline_at"`
	CampaignEvidence    campaign.Evidence    `json:"campaign_evidence"`
	Replicas            []ReplicaObservation `json:"replicas"`
}

// ControlBundle is the sole Go-to-Python handoff. BundleDigestSHA256 covers
// the complete credential-free document with that field omitted.
type ControlBundle struct {
	Schema                     string          `json:"schema"`
	SchemaVersion              int             `json:"schema_version"`
	Purpose                    string          `json:"purpose"`
	RunID                      string          `json:"run_id"`
	Network                    string          `json:"network"`
	NetUID                     uint16          `json:"netuid"`
	Domain                     string          `json:"domain"`
	ValidatorUID               uint16          `json:"validator_uid"`
	ValidatorHotkey            string          `json:"validator_hotkey"`
	FinalizedHeight            uint64          `json:"finalized_height"`
	FinalizedBlockHash         string          `json:"finalized_block_hash"`
	FinalizedEpoch             uint64          `json:"finalized_epoch"`
	Tempo                      uint64          `json:"tempo"`
	WindowStartedAt            time.Time       `json:"window_started_at"`
	WindowEndedAt              time.Time       `json:"window_ended_at"`
	CampaignConfigDigestSHA256 string          `json:"campaign_config_digest_sha256"`
	SchedulerStateDigestSHA256 string          `json:"scheduler_state_digest_sha256"`
	Miners                     []MinerIdentity `json:"miners"`
	Records                    []ControlRecord `json:"records"`
	BundleDigestSHA256         string          `json:"bundle_digest_sha256,omitempty"`
}

type boundAgent struct {
	*miner.Agent
	identity     miner.SubnetIdentity
	edgeRegistry *tunnel.LocalRegistry
}

func (agent *boundAgent) SubnetIdentity() miner.SubnetIdentity { return agent.identity }

func (agent *boundAgent) Assign(ctx context.Context, ticket protocol.Ticket) (miner.Result, error) {
	result, err := agent.Agent.AssignBound(
		ctx,
		ticket,
		agent.Agent.OwnerKey,
		FinalizedHeight,
		campaign.MainnetNetwork,
		campaign.MainnetNetUID,
		ValidatorHotkey,
		agent.identity.Hotkey,
		agent.identity.UID,
	)
	if err != nil {
		return result, err
	}
	target := agent.identity.AxonURL + "/runtime/" + url.PathEscape(result.EndpointID)
	if err := agent.edgeRegistry.Register(result.EndpointID, target); err != nil {
		_ = agent.Agent.Deactivate(context.Background(), result.EndpointID)
		return miner.Result{}, err
	}
	return result, nil
}

func (agent *boundAgent) Deactivate(ctx context.Context, endpointID string) error {
	agent.edgeRegistry.Unregister(endpointID)
	return agent.Agent.Deactivate(ctx, endpointID)
}

func runtimeProxy(registry *tunnel.LocalRegistry) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		path := strings.TrimPrefix(request.URL.EscapedPath(), "/runtime/")
		parts := strings.SplitN(path, "/", 2)
		if len(parts) == 0 || parts[0] == "" {
			http.NotFound(response, request)
			return
		}
		endpointID, err := url.PathUnescape(parts[0])
		if err != nil || endpointID == "" {
			http.Error(response, "invalid endpoint", http.StatusBadRequest)
			return
		}
		target, err := registry.Resolve(endpointID)
		if err != nil {
			http.NotFound(response, request)
			return
		}
		remainder := "/"
		if len(parts) == 2 && parts[1] != "" {
			remainder += parts[1]
		}
		request.URL.Path = remainder
		request.URL.RawPath = ""
		request.Host = target.Host
		httputil.NewSingleHostReverseProxy(target).ServeHTTP(response, request)
	})
}

// deterministicReader is an unbounded SHA-256 counter stream. It is confined
// to this local playground; no production service or wallet uses it.
type deterministicReader struct {
	seed    []byte
	counter uint64
	buffer  []byte
}

func newDeterministicReader(label string) io.Reader {
	sum := sha256.Sum256([]byte("misscomputer-supervised-playground-v1\x00" + label))
	return &deterministicReader{seed: sum[:]}
}

func (reader *deterministicReader) Read(target []byte) (int, error) {
	written := 0
	for written < len(target) {
		if len(reader.buffer) == 0 {
			payload := append(append([]byte(nil), reader.seed...), byte(reader.counter>>56), byte(reader.counter>>48), byte(reader.counter>>40), byte(reader.counter>>32), byte(reader.counter>>24), byte(reader.counter>>16), byte(reader.counter>>8), byte(reader.counter))
			sum := sha256.Sum256(payload)
			reader.buffer = append(reader.buffer[:0], sum[:]...)
			reader.counter++
		}
		count := copy(target[written:], reader.buffer)
		reader.buffer = reader.buffer[count:]
		written += count
	}
	return written, nil
}

func privateKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("misscomputer-supervised-service-key-v1\x00" + label))
	return ed25519.NewKeyFromSeed(seed[:])
}

func playgroundConfig() campaign.Config {
	config := campaign.DefaultConfig()
	config.Enabled = true
	config.Cadence.MinimumDelayMillis = 1_000
	config.Cadence.MaximumDelayMillis = 1_000
	config.Limits.MaxConcurrent = 1
	config.Limits.MaxPending = 1
	config.Limits.RetainedTerminalChallenges = 16
	config.Workloads = []campaign.WorkloadPolicy{
		{Kind: "static", PayloadBytes: 1 << 10, Weight: 1},
		{Kind: "node", PayloadBytes: 1 << 10, Weight: 1},
		{Kind: "python", PayloadBytes: 1 << 10, Weight: 1},
	}
	return config
}

func minerIdentities() []MinerIdentity {
	return []MinerIdentity{
		{UID: 10, Hotkey: "MinerA", Axon: "http://miner-a.local:8091", Active: true, Eligible: true},
		{UID: 11, Hotkey: "MinerB", Axon: "http://miner-b.local:8091", Active: true, Eligible: true},
		{UID: 12, Hotkey: "MinerC", Axon: "http://miner-c.local:8091", Active: true, Eligible: true},
		{UID: 13, Hotkey: "MinerD", Axon: "http://miner-d.local:8091", Active: true, Eligible: true},
	}
}

func canonicalDigest(value any) (string, error) {
	rendered, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	var document map[string]any
	if err := json.Unmarshal(rendered, &document); err != nil {
		return "", err
	}
	delete(document, "bundle_digest_sha256")
	canonical, err := json.Marshal(document)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

func canonicalBytes(value any) ([]byte, error) {
	rendered, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var document map[string]any
	if err := json.Unmarshal(rendered, &document); err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(document)
	if err != nil {
		return nil, err
	}
	return append(canonical, '\n'), nil
}

func ticketDigest(ticket protocol.Ticket) (string, error) {
	rendered, err := json.Marshal(ticket)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(rendered)
	return hex.EncodeToString(digest[:]), nil
}

func selectedTriad(target string, ordinal uint64, identities []MinerIdentity) ([]string, error) {
	peers := make([]string, 0, 3)
	for _, identity := range identities {
		if identity.Hotkey != target {
			peers = append(peers, identity.Hotkey)
		}
	}
	if len(peers) != 3 || ordinal < 1 || ordinal > 3 {
		return nil, errors.New("playground target or ordinal is invalid")
	}
	pairs := [][2]int{{0, 1}, {0, 2}, {1, 2}}
	pair := pairs[ordinal-1]
	return []string{target, peers[pair[0]], peers[pair[1]]}, nil
}

func orderAgents(target string, ordinal uint64, identities []MinerIdentity, agents map[string]*boundAgent) ([]miner.Assigner, error) {
	triad, err := selectedTriad(target, ordinal, identities)
	if err != nil {
		return nil, err
	}
	selected := make(map[string]struct{}, len(triad))
	ordered := make([]miner.Assigner, 0, len(agents))
	for _, hotkey := range triad {
		agent := agents[hotkey]
		if agent == nil {
			return nil, errors.New("playground miner is unavailable")
		}
		ordered = append(ordered, agent)
		selected[hotkey] = struct{}{}
	}
	for _, identity := range identities {
		if _, exists := selected[identity.Hotkey]; !exists {
			ordered = append(ordered, agents[identity.Hotkey])
		}
	}
	return ordered, nil
}

func observationMap(values []control.AcceptanceObservation) map[string]control.AcceptanceObservation {
	result := make(map[string]control.AcceptanceObservation, len(values))
	for _, value := range values {
		result[value.MinerHotkey] = value
	}
	return result
}

func buildReplicas(challenge campaign.Challenge, result control.DeployResult) ([]ReplicaObservation, error) {
	observations := observationMap(result.Observations)
	replicas := make([]ReplicaObservation, 0, len(result.AcceptedTickets))
	for _, accepted := range result.AcceptedTickets {
		ticket := accepted.Ticket
		if ticket.Subnet == nil || ticket.Subnet.MinerUID == nil {
			return nil, errors.New("accepted playground ticket lacks a finalized miner identity")
		}
		observation, exists := observations[ticket.MinerID]
		if !exists || !observation.Success {
			return nil, errors.New("accepted playground ticket lacks a successful validator observation")
		}
		digest, err := ticketDigest(ticket)
		if err != nil {
			return nil, err
		}
		replicas = append(replicas, ReplicaObservation{
			TicketVersion: ticket.Version, DeploymentID: ticket.DeploymentID,
			BuildID: challenge.Workload.BuildID, ChallengePath: ticket.ChallengePath,
			ChallengeSHA256: ticket.ChallengeSHA256, MinerUID: *ticket.Subnet.MinerUID,
			MinerHotkey: ticket.MinerID, Generation: ticket.Generation,
			AssignmentNonce: ticket.AssignmentNonce, TicketDigestSHA256: digest,
			ReplicaID: protocol.ReplicaID(ticket), EndpointID: protocol.EndpointID(ticket),
			ImageDigest: ticket.ImageDigest, ManifestKey: ticket.ManifestKey,
			AcceptedAt: accepted.AcceptedAt.UTC().Round(0),
			ObservedAt: observation.ObservedAt.UTC().Round(0), Success: true,
			LatencyMS: observation.LatencyMS, TransferredBytes: challenge.Workload.PayloadBytes,
		})
	}
	sort.Slice(replicas, func(left, right int) bool {
		if replicas[left].MinerUID != replicas[right].MinerUID {
			return replicas[left].MinerUID < replicas[right].MinerUID
		}
		return replicas[left].MinerHotkey < replicas[right].MinerHotkey
	})
	if len(replicas) != 3 {
		return nil, errors.New("playground deployment did not produce exactly three replicas")
	}
	return replicas, nil
}

// RunControl executes exactly twelve evidence-only campaign deployments: three
// fairness targets per each of four eligible miners, always retaining one
// clean spare. The returned bundle contains public evidence only.
func RunControl(ctx context.Context, runID string) (_ ControlBundle, runErr error) {
	if ctx == nil {
		return ControlBundle{}, errors.New("playground context is required")
	}
	if runID == "" || len(runID) > 64 || runID[0] == '-' || runID[len(runID)-1] == '-' {
		return ControlBundle{}, errors.New("playground run ID is invalid")
	}
	for _, character := range runID {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return ControlBundle{}, errors.New("playground run ID is invalid")
		}
	}

	config := playgroundConfig()
	base := time.Now().UTC().Truncate(time.Second)
	engine, err := campaign.NewWithEntropy(config, base, newDeterministicReader(runID+"/campaign"))
	if err != nil {
		return ControlBundle{}, err
	}
	configDigest, err := campaign.ConfigDigest(config)
	if err != nil {
		return ControlBundle{}, err
	}
	artifactRoot, err := os.MkdirTemp("", "misscomputer-playground-artifacts-")
	if err != nil {
		return ControlBundle{}, err
	}
	defer os.RemoveAll(artifactRoot)
	store := artifact.FileStore{Root: filepath.Clean(artifactRoot)}

	ownerPrivate := privateKey(runID + "/validator-service")
	ownerPublic := ownerPrivate.Public().(ed25519.PublicKey)
	edgeRegistry := tunnel.NewLocalRegistry()
	probeDigest := sha256.Sum256([]byte(runID + "/probe-token"))
	probeToken := hex.EncodeToString(probeDigest[:])
	router, err := edge.NewAuthorizedRouter(edgeRegistry, probeToken, edge.RouterConfig{
		AuthorityKey: ownerPublic, Domain: campaign.MainnetDomain, AllowPrivateUpstreams: true,
		AllowInsecureMockHTTP: true,
	})
	if err != nil {
		return ControlBundle{}, err
	}
	edgeServer := httptest.NewServer(router)
	defer edgeServer.Close()

	identities := minerIdentities()
	agents := make(map[string]*boundAgent, len(identities))
	proxyServers := make([]*httptest.Server, 0, len(identities))
	defer func() {
		for _, server := range proxyServers {
			server.Close()
		}
	}()
	for index := range identities {
		identity := &identities[index]
		localRegistry := tunnel.NewLocalRegistry()
		proxy := httptest.NewServer(runtimeProxy(localRegistry))
		proxyServers = append(proxyServers, proxy)
		identity.Axon = proxy.URL
		agent := miner.NewAgent(
			identity.Hotkey,
			ownerPublic,
			privateKey(runID+"/"+identity.Hotkey),
			store,
			deployruntime.NewLocalRuntime(),
			localRegistry,
		)
		agent.MinerTransport = "http"
		agents[identity.Hotkey] = &boundAgent{
			Agent: agent,
			identity: miner.SubnetIdentity{
				Hotkey: identity.Hotkey, UID: &identity.UID, AxonURL: identity.Axon,
				Transport: "http",
			},
			edgeRegistry: edgeRegistry,
		}
	}

	assignmentLedger := ledger.New()
	scheduler := control.Scheduler{
		SigningKey: ownerPrivate, Router: router, Ledger: assignmentLedger,
		Validator: validator.Validator{Vantage: "supervised-local", EdgeURL: edgeServer.URL, InternalProbeToken: probeToken},
		Health:    policy.NewMonitor(), Replicas: 3, Domain: campaign.MainnetDomain,
		Entropy: newDeterministicReader(runID + "/assignment-nonces"),
		Subnet: &protocol.SubnetBinding{
			Network: campaign.MainnetNetwork, NetUID: campaign.MainnetNetUID,
			ValidatorHotkey: ValidatorHotkey, ChainBlock: FinalizedHeight,
			Epoch: FinalizedHeight / FinalizedTempo, ExpiresAtBlock: FinalizedHeight + FinalizedTempo,
		},
	}

	minerHotkeys := make([]string, len(identities))
	for index, identity := range identities {
		minerHotkeys[index] = identity.Hotkey
	}
	records := make([]ControlRecord, 0, controlRecordCount)
	for sequence := 1; sequence <= controlRecordCount; sequence++ {
		scheduledAt := base.Add(time.Duration(sequence-1) * time.Second)
		decision, err := engine.Schedule(scheduledAt, minerHotkeys)
		if err != nil || decision.Challenge == nil || decision.Reason != campaign.DecisionScheduled {
			return ControlBundle{}, fmt.Errorf("schedule playground challenge %d: %w", sequence, err)
		}
		startAt := scheduledAt.Add(50 * time.Millisecond)
		started, err := engine.StartNext(startAt)
		if err != nil || started.Challenge == nil || started.Reason != campaign.DecisionStarted {
			return ControlBundle{}, fmt.Errorf("start playground challenge %d: %w", sequence, err)
		}
		challenge := *started.Challenge
		ordered, err := orderAgents(challenge.CoverageTargetMiner, challenge.CoverageTargetOrdinal, identities, agents)
		if err != nil {
			return ControlBundle{}, err
		}
		scheduler.SetMiners(ordered)
		controlNow := scheduledAt.Add(100 * time.Millisecond)
		scheduler.Now = func() time.Time { return controlNow }
		layer, err := workload.EncodeWithReader(challenge.Workload, newDeterministicReader(fmt.Sprintf("%s/layer/%d", runID, sequence)))
		if err != nil {
			return ControlBundle{}, err
		}
		manifest, err := artifact.PrepareManifest(
			challenge.Workload.Kind,
			[][]byte{[]byte("misscomputer-runtime-base-v1"), layer},
			map[string]string{"build_id": challenge.Workload.BuildID},
			startAt,
		)
		if err != nil {
			return ControlBundle{}, err
		}
		manifest, err = artifact.PublishPrepared(
			ctx,
			store,
			manifest,
			[][]byte{[]byte("misscomputer-runtime-base-v1"), layer},
		)
		if err != nil {
			return ControlBundle{}, err
		}
		result, err := scheduler.Deploy(ctx, control.DeployRequest{
			DeploymentID: challenge.DeploymentID, Manifest: manifest,
			ManifestKey: artifact.ManifestKey(manifest.ImageDigest), Workload: challenge.Workload,
			Timeout: time.Minute, RequiredMiner: challenge.CoverageTargetMiner,
			ScoringDisposition: control.ScoringEvidenceOnly,
		})
		if err != nil {
			return ControlBundle{}, fmt.Errorf("deploy playground challenge %d: %w", sequence, err)
		}
		deployed := true
		deactivate := func() error {
			if !deployed {
				return nil
			}
			deployed = false
			return scheduler.DeactivateDeployment(context.Background(), challenge.DeploymentID)
		}
		for _, accepted := range result.AcceptedTickets {
			if err := engine.RecordAcceptedTicket(challenge.Sequence, accepted.Ticket, accepted.AcceptedAt.UTC().Round(0)); err != nil {
				_ = deactivate()
				return ControlBundle{}, err
			}
		}
		completedAt := scheduledAt.Add(300 * time.Millisecond)
		evidence, err := engine.Complete(challenge.Sequence, completedAt, campaign.OutcomeSucceeded, campaign.FailureNone)
		if err != nil {
			_ = deactivate()
			return ControlBundle{}, err
		}
		replicas, err := buildReplicas(challenge, result)
		if err != nil {
			_ = deactivate()
			return ControlBundle{}, err
		}
		if err := deactivate(); err != nil {
			return ControlBundle{}, err
		}
		if challenge.DeadlineAt == nil {
			return ControlBundle{}, errors.New("playground challenge deadline is missing")
		}
		records = append(records, ControlRecord{
			FinalizedEpochIndex: FinalizedHeight / FinalizedTempo,
			CompletionDeadline:  challenge.DeadlineAt.UTC().Round(0),
			CampaignEvidence:    evidence, Replicas: replicas,
		})
	}

	state := engine.Snapshot()
	blockHash := sha256.Sum256([]byte("misscomputer-playground-finalized-block-v1\x00" + runID))
	bundle := ControlBundle{
		Schema: BundleSchema, SchemaVersion: BundleVersion,
		Purpose: "wallet_free_supervised_local_integration_v1", RunID: runID,
		Network: campaign.MainnetNetwork, NetUID: campaign.MainnetNetUID,
		Domain: campaign.MainnetDomain, ValidatorUID: ValidatorUID, ValidatorHotkey: ValidatorHotkey,
		FinalizedHeight: FinalizedHeight, FinalizedBlockHash: hex.EncodeToString(blockHash[:]),
		FinalizedEpoch: FinalizedHeight / FinalizedTempo, Tempo: FinalizedTempo,
		WindowStartedAt: base, WindowEndedAt: base.Add(24 * time.Hour),
		CampaignConfigDigestSHA256: configDigest,
		SchedulerStateDigestSHA256: state.StateDigestSHA256,
		Miners:                     identities, Records: records,
	}
	digest, err := canonicalDigest(bundle)
	if err != nil {
		return ControlBundle{}, err
	}
	bundle.BundleDigestSHA256 = digest
	return bundle, nil
}

// MarshalControlBundle verifies the digest and emits one canonical compact
// JSON line. The Python supervisor repeats the digest and contract checks.
func MarshalControlBundle(bundle ControlBundle) ([]byte, error) {
	digest, err := canonicalDigest(bundle)
	if err != nil || digest != bundle.BundleDigestSHA256 {
		return nil, errors.New("playground bundle digest is invalid")
	}
	return canonicalBytes(bundle)
}

// ParseControlBundle provides a Go-side exact replay verifier for tests and
// any future local supervisor.
func ParseControlBundle(rendered []byte) (ControlBundle, error) {
	decoder := json.NewDecoder(bytes.NewReader(rendered))
	decoder.DisallowUnknownFields()
	var bundle ControlBundle
	if err := decoder.Decode(&bundle); err != nil {
		return ControlBundle{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return ControlBundle{}, errors.New("playground bundle has trailing content")
	}
	canonical, err := MarshalControlBundle(bundle)
	if err != nil || !bytes.Equal(rendered, canonical) {
		return ControlBundle{}, errors.New("playground bundle is not canonical")
	}
	return bundle, nil
}
