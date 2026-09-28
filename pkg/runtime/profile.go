// SPDX-License-Identifier: AGPL-3.0-only

package runtime

import "github.com/misscomputer/misscomputer-subnet/pkg/organic"

// MaxHealthBodyBytes bounds the response prefix searched for a health marker.
const MaxHealthBodyBytes = 64 << 10

// Profile is the engine realisation of one frozen runtime profile. Resources
// are the contract values (organic.SmallV1); the remaining fields are the
// fixed execution settings of contract §7.1 shared with the CLI smoke test.
type Profile struct {
	Name      string
	Platform  string
	Resources organic.Resources
	// User overrides the image user.
	User string
	// LogMaxSize and LogMaxFile configure the engine's local json-file logs.
	LogMaxSize string
	LogMaxFile int
}

// SmallV1 is the only MVP profile.
var SmallV1 = Profile{
	Name: organic.RuntimeProfile, Platform: organic.Platform, Resources: organic.SmallV1,
	User: "65532:65532", LogMaxSize: "1m", LogMaxFile: 2,
}

// LookupProfile returns the profile a miner implements for a ticket's
// workload.runtime_profile.
func LookupProfile(name string) (Profile, bool) {
	if name == SmallV1.Name {
		return SmallV1, true
	}
	return Profile{}, false
}
