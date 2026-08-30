// SPDX-License-Identifier: AGPL-3.0-only

package netpolicy

import (
	"encoding/json"
	"testing"
)

type regressionCorpus struct {
	Policy          string `json:"policy"`
	Version         int    `json:"version"`
	RegressionCases []struct {
		Address   string  `json:"address"`
		Allowed   bool    `json:"allowed"`
		Canonical *string `json:"canonical"`
	} `json:"regression_cases"`
}

func TestSharedAddressPolicyRegressionCorpus(t *testing.T) {
	var corpus regressionCorpus
	if err := json.Unmarshal(policyJSON, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Policy != policyName || corpus.Version != policyVersion || len(corpus.RegressionCases) == 0 {
		t.Fatalf("unexpected corpus identity: %+v", corpus)
	}
	for _, test := range corpus.RegressionCases {
		canonical, err := CanonicalPublicAddress(test.Address)
		if test.Allowed {
			if err != nil || test.Canonical == nil || canonical != *test.Canonical {
				t.Errorf("public address %q: canonical=%q err=%v expected=%v", test.Address, canonical, err, test.Canonical)
			}
			continue
		}
		if err == nil {
			t.Errorf("special-purpose address %q was accepted as %q", test.Address, canonical)
		}
	}
}

func TestPublicPolicyRejectsMappedBeforeCanonicalization(t *testing.T) {
	if canonical, err := CanonicalPublicAddress("::ffff:8.8.8.8"); err == nil {
		t.Fatalf("mapped address collapsed and accepted as %q", canonical)
	}
	if canonical, err := CanonicalPublicAddress("8.8.8.8"); err != nil || canonical != "8.8.8.8" {
		t.Fatalf("ordinary public IPv4 rejected: canonical=%q err=%v", canonical, err)
	}
}
