// SPDX-License-Identifier: AGPL-3.0-only

package validator

import (
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/durable"
)

func TestPrepareWeightsDeterministicNormalizedBoundedAndTrustZero(t *testing.T) {
	observations := []durable.Observation{
		{MinerHotkey: "b", Success: true, LatencyMS: 1000, Availability: 1},
		{MinerHotkey: "a", Success: true, LatencyMS: 500, Availability: 1},
		{MinerHotkey: "c", Success: true, LatencyMS: 1, Availability: 1},
		{MinerHotkey: "a", Success: false, LatencyMS: 1, Availability: 1},
	}
	weights := PrepareWeights(observations, map[string]float64{"c": 0}, time.Second)
	if len(weights) != 3 || weights[0].MinerHotkey != "a" || weights[1].MinerHotkey != "b" || weights[2].MinerHotkey != "c" {
		t.Fatalf("weights are not stably sorted: %#v", weights)
	}
	if weights[2].Weight != 0 {
		t.Fatalf("trust-zero miner received positive weight: %#v", weights[2])
	}
	sum := 0.0
	for _, weight := range weights {
		if weight.Weight < 0 || weight.Weight > 1 {
			t.Fatalf("unbounded weight: %#v", weight)
		}
		sum += weight.Weight
	}
	if sum < 0.999999999 || sum > 1.000000001 {
		t.Fatalf("weights not normalized: %.12f", sum)
	}
}
