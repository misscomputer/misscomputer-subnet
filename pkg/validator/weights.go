// SPDX-License-Identifier: AGPL-3.0-only

package validator

import (
	"math"
	"sort"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/durable"
)

type Weight struct {
	MinerHotkey string  `json:"miner_hotkey"`
	Weight      float64 `json:"weight"`
	Samples     int     `json:"samples"`
}

// PrepareWeights deterministically aggregates bounded benchmark observations.
// Trust-zero miners are always assigned zero and omitted from the positive
// normalization denominator. Missing trust means the fresh-miner default 1.
func PrepareWeights(observations []durable.Observation, trust map[string]float64, target time.Duration) []Weight {
	if target <= 0 {
		target = time.Second
	}
	type aggregate struct {
		total float64
		count int
	}
	groups := make(map[string]aggregate)
	for _, observation := range observations {
		if observation.MinerHotkey == "" || observation.LatencyMS < 0 || !finite01(observation.Availability) {
			continue
		}
		value := Score(observation.Success, time.Duration(observation.LatencyMS)*time.Millisecond, target, observation.Availability)
		if !finite01(value) {
			value = 0
		}
		group := groups[observation.MinerHotkey]
		group.total += value
		group.count++
		groups[observation.MinerHotkey] = group
	}
	hotkeys := make([]string, 0, len(groups))
	for hotkey := range groups {
		hotkeys = append(hotkeys, hotkey)
	}
	sort.Strings(hotkeys)
	weights := make([]Weight, 0, len(hotkeys))
	denominator := 0.0
	for _, hotkey := range hotkeys {
		group := groups[hotkey]
		value := group.total / float64(group.count)
		if trustValue, exists := trust[hotkey]; exists {
			if !finite01(trustValue) {
				trustValue = 0
			}
			value *= trustValue
		}
		if value < 0 {
			value = 0
		}
		if value > 1 {
			value = 1
		}
		weights = append(weights, Weight{MinerHotkey: hotkey, Weight: value, Samples: group.count})
		denominator += value
	}
	if denominator <= 0 {
		for i := range weights {
			weights[i].Weight = 0
		}
		return weights
	}
	for i := range weights {
		weights[i].Weight /= denominator
	}
	return weights
}

func finite01(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0 && value <= 1
}
