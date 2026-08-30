// SPDX-License-Identifier: AGPL-3.0-only

package edge

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/netpolicy"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
)

const RouteUpdateVersion = "edge-route.v1"

type RouteAction string

const (
	RouteRegisterPending RouteAction = "register_pending"
	RouteActivate        RouteAction = "activate"
	RouteDeactivate      RouteAction = "deactivate"
)

var (
	ErrRouteReplay = errors.New("edge route update replayed")
	ErrStaleRoute  = errors.New("edge route generation is stale")
)

// RouteUpdate is the only production route-mutation input. The authoritative
// Go control plane signs every short-lived update with the same service key
// that signed the exact assignment ticket. Miner receipts are required for
// registration/activation but never supply an upstream URL or runtime ID.
type RouteUpdate struct {
	Version      string            `json:"version"`
	Action       RouteAction       `json:"action"`
	DeploymentID string            `json:"deployment_id"`
	Generation   uint64            `json:"generation"`
	MinerID      string            `json:"miner_id"`
	ReplicaID    string            `json:"replica_id"`
	EndpointID   string            `json:"endpoint_id"`
	RouteHost    string            `json:"route_host"`
	Nonce        string            `json:"nonce"`
	IssuedAt     time.Time         `json:"issued_at"`
	ExpiresAt    time.Time         `json:"expires_at"`
	Ticket       protocol.Ticket   `json:"ticket"`
	Receipt      *protocol.Receipt `json:"receipt,omitempty"`
	Signature    string            `json:"signature"`
}

// RouteRecord is the persistence boundary implemented by durable.Store.
// State values are pending, active, quarantined, or deactivated.
type RouteRecord struct {
	EndpointID   string
	DeploymentID string
	Generation   uint64
	MinerID      string
	ReplicaID    string
	RouteHost    string
	State        string
	TicketJSON   []byte
	ReceiptJSON  []byte
}

// RouteStateStore makes route transitions durable without allowing restart to
// re-publish a previously active route. QuarantineRoutes is called before an
// authorized Router begins serving.
type RouteStateStore interface {
	// ApplyEdgeRouteTransition atomically reserves the replay key and commits
	// the route transition. A false result with no error means the replay key
	// was already live. Any transition error must leave the replay key unused.
	ApplyEdgeRouteTransition(context.Context, string, string, time.Time, RouteRecord) (bool, error)
	QuarantineEdgeRoutes(context.Context) error
	// HighestEdgeGeneration returns the highest persisted route generation for
	// one deployment across all miners and lifecycle states, or zero when the
	// deployment has never had a persisted route.
	HighestEdgeGeneration(context.Context, string) (uint64, error)
}

type RouterConfig struct {
	AuthorityKey          ed25519.PublicKey
	Store                 RouteStateStore
	Domain                string
	HostLabelPrefix       string
	AllowPrivateUpstreams bool
	AllowInsecureMockHTTP bool
	RequireBoundTickets   bool
	RequireEndpointPath   bool
	ResponseHeaderTimeout time.Duration
	DialTimeout           time.Duration
	TLSHandshakeTimeout   time.Duration
	MaxResponseBytes      int64
}

func NewRouteUpdate(action RouteAction, ticket protocol.Ticket, receipt *protocol.Receipt, key ed25519.PrivateKey, now time.Time) (RouteUpdate, error) {
	if len(key) != ed25519.PrivateKeySize {
		return RouteUpdate{}, errors.New("invalid edge route signing key")
	}
	if action != RouteRegisterPending && action != RouteActivate && action != RouteDeactivate {
		return RouteUpdate{}, fmt.Errorf("unsupported edge route action %q", action)
	}
	nonceBytes := make([]byte, 24)
	if _, err := rand.Read(nonceBytes); err != nil {
		return RouteUpdate{}, err
	}
	update := RouteUpdate{
		Version: RouteUpdateVersion, Action: action, DeploymentID: ticket.DeploymentID,
		Generation: ticket.Generation, MinerID: ticket.MinerID, ReplicaID: protocol.ReplicaID(ticket),
		EndpointID: protocol.EndpointID(ticket), RouteHost: ticket.RouteHost,
		Nonce: hex.EncodeToString(nonceBytes), IssuedAt: now.UTC(), ExpiresAt: now.Add(30 * time.Second).UTC(),
		Ticket: ticket, Receipt: receipt,
	}
	if err := SignRouteUpdate(&update, key); err != nil {
		return RouteUpdate{}, err
	}
	return update, nil
}

func SignRouteUpdate(update *RouteUpdate, key ed25519.PrivateKey) error {
	if update == nil || len(key) != ed25519.PrivateKeySize {
		return errors.New("edge route update and signing key are required")
	}
	payload, err := unsignedRouteUpdate(*update)
	if err != nil {
		return err
	}
	update.Signature = hex.EncodeToString(ed25519.Sign(key, payload))
	return nil
}

func verifyRouteUpdate(update RouteUpdate, key ed25519.PublicKey, now time.Time) error {
	if len(key) != ed25519.PublicKeySize {
		return errors.New("edge route authority key is invalid")
	}
	if update.Version != RouteUpdateVersion || update.Nonce == "" || update.IssuedAt.IsZero() ||
		!update.ExpiresAt.After(update.IssuedAt) || update.ExpiresAt.Sub(update.IssuedAt) > time.Minute ||
		now.Before(update.IssuedAt.Add(-30*time.Second)) || !now.Before(update.ExpiresAt) {
		return errors.New("edge route update is malformed, expired, or not yet valid")
	}
	if update.Action != RouteRegisterPending && update.Action != RouteActivate && update.Action != RouteDeactivate {
		return fmt.Errorf("unsupported edge route action %q", update.Action)
	}
	signature, err := hex.DecodeString(update.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("edge route update signature is invalid")
	}
	payload, err := unsignedRouteUpdate(update)
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, payload, signature) {
		return errors.New("edge route update signature is invalid")
	}
	if err := protocol.VerifyTicketSignature(update.Ticket, key); err != nil {
		return fmt.Errorf("edge route ticket authority: %w", err)
	}
	if update.Action != RouteDeactivate {
		if err := protocol.VerifyTicket(update.Ticket, key, now); err != nil {
			return fmt.Errorf("edge route ticket validity: %w", err)
		}
	}
	if update.DeploymentID != update.Ticket.DeploymentID || update.Generation != update.Ticket.Generation ||
		update.MinerID != update.Ticket.MinerID || update.ReplicaID != protocol.ReplicaID(update.Ticket) ||
		update.EndpointID != protocol.EndpointID(update.Ticket) || update.RouteHost != update.Ticket.RouteHost {
		return errors.New("edge route update does not match its exact signed ticket")
	}
	return nil
}

func verifyReadyReceipt(ticket protocol.Ticket, receipt *protocol.Receipt, minerKey ed25519.PublicKey) error {
	if receipt == nil {
		return errors.New("ready miner receipt is required")
	}
	if err := protocol.VerifyReceipt(*receipt, minerKey); err != nil {
		return fmt.Errorf("verify edge route receipt: %w", err)
	}
	if receipt.Version != ticket.Version || receipt.DeploymentID != ticket.DeploymentID || receipt.Generation != ticket.Generation ||
		receipt.AssignmentNonce != ticket.AssignmentNonce || receipt.MinerID != ticket.MinerID ||
		receipt.ReplicaID != protocol.ReplicaID(ticket) || receipt.EndpointID != protocol.EndpointID(ticket) ||
		receipt.ImageDigest != ticket.ImageDigest || receipt.ManifestKey != ticket.ManifestKey ||
		receipt.RouteHost != ticket.RouteHost || receipt.Stage != protocol.StageReady ||
		!protocol.EqualSubnetBinding(receipt.Subnet, ticket.Subnet) {
		return errors.New("edge route receipt does not match its exact signed ticket")
	}
	if ticket.Subnet != nil {
		encoded := hex.EncodeToString(minerKey)
		if encoded != ticket.Subnet.MinerServicePublicKey || ticket.Subnet.MinerHotkey != ticket.MinerID {
			return errors.New("edge route receipt key does not match the ticket miner binding")
		}
	}
	return nil
}

func routeRecord(update RouteUpdate, state string) (RouteRecord, error) {
	ticketJSON, err := json.Marshal(update.Ticket)
	if err != nil {
		return RouteRecord{}, err
	}
	var receiptJSON []byte
	if update.Receipt != nil {
		receiptJSON, err = json.Marshal(update.Receipt)
		if err != nil {
			return RouteRecord{}, err
		}
	}
	return RouteRecord{
		EndpointID: update.EndpointID, DeploymentID: update.DeploymentID, Generation: update.Generation,
		MinerID: update.MinerID, ReplicaID: update.ReplicaID, RouteHost: update.RouteHost, State: state,
		TicketJSON: ticketJSON, ReceiptJSON: receiptJSON,
	}, nil
}

func sameRouteIdentity(left, right RouteRecord) bool {
	return left.EndpointID == right.EndpointID && left.DeploymentID == right.DeploymentID && left.Generation == right.Generation &&
		left.MinerID == right.MinerID && left.ReplicaID == right.ReplicaID && left.RouteHost == right.RouteHost &&
		bytes.Equal(left.TicketJSON, right.TicketJSON)
}

func validateUpstream(target *url.URL, endpointID string, config RouterConfig) error {
	if target == nil || (target.Scheme != "http" && target.Scheme != "https") || target.Host == "" || target.User != nil ||
		target.RawQuery != "" || target.Fragment != "" || target.ForceQuery || target.RawFragment != "" || target.Opaque != "" {
		return errors.New("edge upstream must be an explicit http(s) URL without userinfo, query, or fragment")
	}
	port, err := strconv.Atoi(target.Port())
	if err != nil || port < 1 || port > 65535 {
		return errors.New("edge upstream must include an explicit valid port")
	}
	host := target.Hostname()
	if !config.AllowPrivateUpstreams {
		canonical, policyErr := netpolicy.CanonicalPublicAddress(host)
		if policyErr != nil || canonical != host {
			return errors.New("edge upstream must use a canonical publicly routable non-special-purpose IP")
		}
	}
	if config.RequireEndpointPath {
		expected := "/runtime/" + url.PathEscape(endpointID)
		if target.EscapedPath() != expected {
			return errors.New("edge upstream path is not bound to the scheduler-derived endpoint identity")
		}
	}
	return nil
}

func validateDomain(domain string) (string, error) {
	if domain == "" || domain != strings.ToLower(domain) || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") || net.ParseIP(domain) != nil {
		return "", errors.New("edge domain must be a lowercase absolute DNS suffix without dots at either edge")
	}
	for _, label := range strings.Split(domain, ".") {
		if !validDNSLabel(label) {
			return "", errors.New("edge domain contains an invalid DNS label")
		}
	}
	return domain, nil
}

func expectedRouteHost(deploymentID, domain, prefix string) (string, error) {
	if !validDNSLabel(deploymentID) {
		return "", errors.New("deployment ID must be a lowercase DNS label")
	}
	label := prefix + deploymentID
	if !validDNSLabel(label) {
		return "", errors.New("route label prefix plus deployment ID must form one DNS label")
	}
	return label + "." + domain, nil
}

func validDNSLabel(value string) bool {
	if len(value) < 1 || len(value) > 63 || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func unsignedRouteUpdate(update RouteUpdate) ([]byte, error) {
	update.Signature = ""
	return json.Marshal(update)
}

func routeUpdateReplayKey(update RouteUpdate) string {
	sum := sha256.Sum256([]byte(update.Nonce + "\x00" + update.Signature))
	return hex.EncodeToString(sum[:])
}
