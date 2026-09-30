// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
	"github.com/misscomputer/misscomputer-subnet/pkg/durable"
	"github.com/misscomputer/misscomputer-subnet/pkg/miner"
	"github.com/misscomputer/misscomputer-subnet/pkg/neuron"
	"github.com/misscomputer/misscomputer-subnet/pkg/organic"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	"github.com/misscomputer/misscomputer-subnet/pkg/static"
	"github.com/misscomputer/misscomputer-subnet/pkg/tunnel"
)

// A validator-signed static ticket in a subnet-static-synapse.v1 bridge
// request reaches a verified ready static receipt only when the operator
// enabled the workload; the capability is advertised exactly then. Static
// status has its own envelope, and the kind-neutral deactivation synapse
// retires the static endpoint under exact ownership.
func TestStaticAssignThroughTheBridgeIsOptInAndOwnerDeactivated(t *testing.T) {
	ctx := context.Background()
	const (
		validatorHotkey = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
		minerHotkey     = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
		routeLabel      = "hello-world-k3j9x0q2ab"
	)
	artifacts := artifact.FileStore{Root: t.TempDir()}
	index := []byte("<!doctype html><title>hello</title>\n")
	sum := sha256.Sum256(index)
	manifest := static.Manifest{
		Handler: static.HandlerVersion, Schema: static.ManifestSchema, SchemaVersion: 1,
		Files: []static.File{{BodySHA256: hex.EncodeToString(sum[:]), ContentLength: int64(len(index)), ContentType: static.ContentTypeFor("/index.html"), Path: "/index.html"}},
	}
	stored, siteDigest, err := static.Encode(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := artifacts.Put(ctx, static.BlobKey(hex.EncodeToString(sum[:])), index, ""); err != nil {
		t.Fatal(err)
	}
	if err := artifacts.Put(ctx, static.ManifestKey(siteDigest), stored, ""); err != nil {
		t.Fatal(err)
	}
	validatorPublic, validatorPrivate, _ := ed25519.GenerateKey(rand.Reader)
	minerPublic, minerPrivate, _ := ed25519.GenerateKey(rand.Reader)
	uid := uint16(17)
	now := time.Now().UTC()
	ticket := protocol.StaticTicketV1{
		AssignmentNonce: "c0634d1e9b2f4a7788d1e0f5a6b7c8d9", DeploymentID: routeLabel, Generation: 1,
		IssuedAt: *protocol.StaticTime(now.Add(-time.Second)), ExpiresAt: *protocol.StaticTime(now.Add(5 * time.Minute)),
		MinerID: minerHotkey, ReleaseDigest: "sha256:" + hex.EncodeToString(sum[:]), RouteHost: organic.RouteHost(routeLabel),
		Schema: protocol.StaticTicketSchema, SchemaVersion: 1, ServerImplementationDigest: static.ServerImplementationDigest,
		SiteDigest: siteDigest, SiteManifestKey: static.ManifestKey(siteDigest), WorkloadKind: static.WorkloadKind,
		Subnet: &protocol.StaticSubnetBindingV1{
			Network: "mock", NetUID: 24, ValidatorHotkey: validatorHotkey, MinerHotkey: minerHotkey, MinerUID: &uid,
			MinerAxonURL: "http://127.0.0.1:8091", MinerTransport: neuron.TransportHTTP, ChainBlock: 100, Epoch: 1, ExpiresAtBlock: 112,
			ValidatorServicePublicKey: hex.EncodeToString(validatorPublic), MinerServicePublicKey: hex.EncodeToString(minerPublic),
		},
	}
	if err := protocol.SignStaticTicketV1(&ticket, validatorPrivate); err != nil {
		t.Fatal(err)
	}
	assignBody, _ := json.Marshal(neuron.LocalStaticAssignRequestV1{
		Protocol: neuron.StaticSynapseVersion, RequestID: "assign-1", CurrentBlock: 101, CallerHotkey: validatorHotkey,
		BindingVerified: true, Ticket: ticket,
		ValidatorBinding: neuron.ServiceKeyBinding{
			Protocol: neuron.ServiceBindingVersion, Role: "validator", Network: "mock", NetUID: 24, Hotkey: validatorHotkey,
			ServicePublicKey: hex.EncodeToString(validatorPublic), Transport: neuron.TransportLocal, Generation: 1,
			ValidFromBlock: 100, ExpiresAtBlock: 200,
		},
	})
	state, err := durable.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	agent := miner.NewAgent(minerHotkey, nil, minerPrivate, artifacts, nil, tunnel.NewLocalRegistry())
	agent.State, agent.MinerTransport = state, neuron.TransportHTTP
	service := &api{agent: agent, store: state, network: "mock", netuid: 24, hotkey: minerHotkey, uid: &uid, public: minerPublic}
	call := func(handle http.HandlerFunc, body []byte) *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		handle(response, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
		return response
	}
	features := func() []string {
		var capabilities neuron.LocalCapabilities
		response := httptest.NewRecorder()
		service.capabilities(response, httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil))
		if err := json.Unmarshal(response.Body.Bytes(), &capabilities); err != nil {
			t.Fatal(err)
		}
		return capabilities.Features
	}

	if agent.Static, err = openStaticSites("off", "", 0, 0, 0); err != nil || agent.Static != nil {
		t.Fatalf("default static mode: %v %v", agent.Static, err)
	}
	if slices.Contains(features(), neuron.FeatureOrganicStaticV1) {
		t.Fatal("disabled miner advertises static capability")
	}
	if response := call(service.assignStatic, assignBody); response.Code != http.StatusNotImplemented {
		t.Fatalf("disabled static assignment: %d %s", response.Code, response.Body.String())
	}
	if agent.Static, err = openStaticSites("on", t.TempDir(), 1<<30, time.Minute, 4); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(features(), neuron.FeatureOrganicStaticV1) {
		t.Fatal("enabled miner does not advertise static capability")
	}
	response := call(service.assignStatic, assignBody)
	var deployed neuron.StaticDeployResponseV1
	if err := organic.DecodeStrict(response.Body.Bytes(), &deployed); err != nil {
		t.Fatalf("static deploy response %d is not strict: %v %s", response.Code, err, response.Body.String())
	}
	if err := protocol.VerifyStaticReceiptV1(deployed.Receipt, minerPublic); err != nil {
		t.Fatal(err)
	}
	if deployed.Receipt.Stage != protocol.StageReady || protocol.StaticReceiptMatchesTicketV1(ticket, deployed.Receipt) != nil {
		t.Fatalf("static receipt %+v", deployed.Receipt)
	}
	endpointID := deployed.EndpointID

	v3Status, _ := json.Marshal(neuron.StatusSynapse{Protocol: neuron.SynapseVersion, RequestID: "s", CurrentBlock: 101, CallerHotkey: validatorHotkey, EndpointID: endpointID})
	if response := call(service.status, v3Status); response.Code != http.StatusConflict {
		t.Fatalf("v3 status of a static endpoint: %d", response.Code)
	}
	staticStatus := func() neuron.StaticStatusResponseV1 {
		body, _ := json.Marshal(neuron.StaticStatusSynapseV1{Protocol: neuron.StaticSynapseVersion, RequestID: "s", CurrentBlock: 101, CallerHotkey: validatorHotkey, EndpointID: endpointID})
		var status neuron.StaticStatusResponseV1
		if err := organic.DecodeStrict(call(service.staticStatus, body).Body.Bytes(), &status); err != nil {
			t.Fatal(err)
		}
		return status
	}
	if status := staticStatus(); status.Status != "ready" || status.Receipt == nil || status.Receipt.Signature != deployed.Receipt.Signature {
		t.Fatalf("static status %+v", status)
	}
	deactivate := func(deploymentID string) int {
		body, _ := json.Marshal(neuron.DeactivateSynapse{Protocol: neuron.SynapseVersion, RequestID: "d", CurrentBlock: 101, CallerHotkey: validatorHotkey, EndpointID: endpointID, DeploymentID: deploymentID})
		return call(service.deactivate, body).Code
	}
	if code := deactivate("another-k3j9x0q2ab"); code != http.StatusForbidden {
		t.Fatalf("foreign deactivation: %d", code)
	}
	if code := deactivate(routeLabel); code != http.StatusOK {
		t.Fatalf("owner deactivation: %d", code)
	}
	if status := staticStatus(); status.Status != "deactivated" || agent.Static.Cache.Occupancy() != 0 {
		t.Fatalf("after deactivation: %+v occupancy %d", status, agent.Static.Cache.Occupancy())
	}
}
