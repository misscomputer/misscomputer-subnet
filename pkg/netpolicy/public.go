// SPDX-License-Identifier: AGPL-3.0-only

// Package netpolicy contains the shared network-address policy used before a
// chain-published miner endpoint can become an HTTP client or edge upstream.
package netpolicy

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/netip"
)

const policyName = "iana-special-purpose-address-policy"
const policyVersion = 1

// policyJSON is also packaged into the Python wheel. Both runtimes therefore
// consume one versioned list instead of relying on language-version-specific
// interpretations of "global" address space.
//
//go:embed iana-special-purpose.v1.json
var policyJSON []byte

type addressPolicy struct {
	Policy       string   `json:"policy"`
	Version      int      `json:"version"`
	DenyPrefixes []string `json:"deny_prefixes"`
}

var deniedPrefixes = loadPolicy()

func loadPolicy() []netip.Prefix {
	var document addressPolicy
	if err := json.Unmarshal(policyJSON, &document); err != nil {
		panic("decode embedded network policy: " + err.Error())
	}
	if document.Policy != policyName || document.Version != policyVersion || len(document.DenyPrefixes) == 0 {
		panic("embedded network policy has an unexpected identity")
	}
	prefixes := make([]netip.Prefix, 0, len(document.DenyPrefixes))
	for _, value := range document.DenyPrefixes {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix != prefix.Masked() {
			panic("invalid canonical network policy prefix: " + value)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes
}

// CanonicalPublicAddress validates a textual numeric address without first
// collapsing IPv4-mapped IPv6 into IPv4. The returned identity is canonical
// RFC 5952/IPv4 text and is stable across the Go and Python callers.
func CanonicalPublicAddress(value string) (string, error) {
	address, err := netip.ParseAddr(value)
	if err != nil || address.Zone() != "" || address.Is4In6() {
		return "", fmt.Errorf("address is not a canonicalizable public numeric IP")
	}
	for _, prefix := range deniedPrefixes {
		if prefix.Contains(address) {
			return "", fmt.Errorf("address belongs to denied special-purpose prefix %s", prefix)
		}
	}
	return address.String(), nil
}

// CanonicalNumericAddress canonicalizes numeric mock addresses while retaining
// the mapped-address rejection used by the live identity policy.
func CanonicalNumericAddress(value string) (string, netip.Addr, error) {
	address, err := netip.ParseAddr(value)
	if err != nil || address.Zone() != "" || address.Is4In6() {
		return "", netip.Addr{}, fmt.Errorf("address is not an unmapped numeric IP")
	}
	return address.String(), address, nil
}
