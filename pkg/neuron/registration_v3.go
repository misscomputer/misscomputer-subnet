// SPDX-License-Identifier: AGPL-3.0-only

package neuron

import (
	"errors"
	"regexp"
	"slices"
)

const (
	// MinerRegistrationV3Version is the protocol of miner-registration.v3,
	// the registration that carries capability features.
	MinerRegistrationV3Version = "subnet-synapse.v3"
	// FeatureMinerRegistrationV3 is the control capability a runtime
	// advertises when it decodes miner-registration.v3. Validators send v3
	// only to such a runtime; every other runtime keeps receiving v2.
	FeatureMinerRegistrationV3 = "miner-registration-v3"
	// MaxRegistrationFeatures bounds the features of one registration.
	MaxRegistrationFeatures = 32
)

var registrationFeaturePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,63}$`)

// CapabilityFeatures returns the registration's validated features: nil for
// miner-registration.v2 (no capability is ever assumed), the exact sorted
// unique token list for v3. Any other shape is an error.
func (r MinerRegistration) CapabilityFeatures() ([]string, error) {
	switch r.Protocol {
	case SynapseVersion:
		if r.Features != nil {
			return nil, errors.New("miner-registration.v2 must not carry features")
		}
		return nil, nil
	case MinerRegistrationV3Version:
		if r.Features == nil {
			return nil, errors.New("miner-registration.v3 requires features")
		}
		features := *r.Features
		if len(features) > MaxRegistrationFeatures {
			return nil, errors.New("miner-registration.v3 carries too many features")
		}
		for index, feature := range features {
			if !registrationFeaturePattern.MatchString(feature) || (index > 0 && feature <= features[index-1]) {
				return nil, errors.New("miner-registration.v3 features must be sorted unique feature tokens")
			}
		}
		return slices.Clone(features), nil
	default:
		return nil, errors.New("unsupported miner registration protocol")
	}
}

// HasFeature reports whether a valid registration advertises feature.
func (r MinerRegistration) HasFeature(feature string) bool {
	features, err := r.CapabilityFeatures()
	return err == nil && slices.Contains(features, feature)
}
