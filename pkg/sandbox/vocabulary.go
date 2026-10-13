// SPDX-License-Identifier: AGPL-3.0-only

// Package sandbox is the shared vocabulary of the sandbox-lease-v1 lane
// (docs/sandbox-lease-v1.md). The lane is off by default and independent of
// deployment.v4 and static-site-v1: it adds documents, tables and a
// capability feature, and changes none of theirs.
package sandbox

import (
	"errors"
	"net/netip"
	"regexp"
	"sort"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/organic"
)

const (
	// CapabilityFeature is reserved for a miner agent that runs the sandbox
	// lane. No released miner agent advertises it yet.
	CapabilityFeature = "sandbox-lease-v1"
	// WorkloadKind distinguishes sandbox documents from web workloads.
	WorkloadKind = "sandbox"

	// MaxHold bounds how long a reservation may pin capacity uncommitted.
	MaxHold = 2 * time.Minute
	// MaxLeaseWindow bounds one lease or renewal window. A validator that
	// stops renewing frees the miner within MaxLeaseWindow plus Grace.
	MaxLeaseWindow = 15 * time.Minute
	// Grace is the miner-side teardown slack after a lease expires.
	Grace = 30 * time.Second
	// IssueSkew is the tolerated clock skew before issued_at.
	IssueSkew = 30 * time.Second
)

// Resource bounds per sandbox. GPU is not part of v1.
const (
	MinCPUMillis = 1000
	MaxCPUMillis = 16000
	MinMemoryMiB = 1024
	MaxMemoryMiB = 65536
	MinDiskMiB   = 5120
	MaxDiskMiB   = 102400
	MinPIDs      = 64
	MaxPIDs      = 32768
)

// Resources is one sandbox's requested allocation. It is billed and held as
// requested; there is no fixed class.
type Resources struct {
	CPUMillis int `json:"cpu_millis"`
	DiskMiB   int `json:"disk_mib"`
	MemoryMiB int `json:"memory_mib"`
	PIDs      int `json:"pids"`
}

// Validate checks the per-sandbox bounds.
func (r Resources) Validate() error {
	if r.CPUMillis < MinCPUMillis || r.CPUMillis > MaxCPUMillis || r.MemoryMiB < MinMemoryMiB || r.MemoryMiB > MaxMemoryMiB ||
		r.DiskMiB < MinDiskMiB || r.DiskMiB > MaxDiskMiB || r.PIDs < MinPIDs || r.PIDs > MaxPIDs {
		return errors.New("sandbox resources are out of bounds")
	}
	return nil
}

// Capacity is an aggregate over sandboxes: a miner's budget, or the part of
// it that holds or live leases consume.
type Capacity struct {
	CPUMillis int `json:"cpu_millis"`
	DiskMiB   int `json:"disk_mib"`
	MemoryMiB int `json:"memory_mib"`
	Sandboxes int `json:"sandboxes"`
}

// Add returns c plus one sandbox of r.
func (c Capacity) Add(r Resources) Capacity {
	return Capacity{CPUMillis: c.CPUMillis + r.CPUMillis, DiskMiB: c.DiskMiB + r.DiskMiB, MemoryMiB: c.MemoryMiB + r.MemoryMiB, Sandboxes: c.Sandboxes + 1}
}

// Plus returns the component-wise sum.
func (c Capacity) Plus(other Capacity) Capacity {
	return Capacity{CPUMillis: c.CPUMillis + other.CPUMillis, DiskMiB: c.DiskMiB + other.DiskMiB,
		MemoryMiB: c.MemoryMiB + other.MemoryMiB, Sandboxes: c.Sandboxes + other.Sandboxes}
}

// Within reports whether every component of c is non-negative and at most
// the matching component of limit.
func (c Capacity) Within(limit Capacity) bool {
	return c.CPUMillis >= 0 && c.DiskMiB >= 0 && c.MemoryMiB >= 0 && c.Sandboxes >= 0 &&
		c.CPUMillis <= limit.CPUMillis && c.DiskMiB <= limit.DiskMiB && c.MemoryMiB <= limit.MemoryMiB && c.Sandboxes <= limit.Sandboxes
}

// Network modes. Every mode is part of the v1 contract; a miner that cannot
// enforce a mode refuses the reservation with network_policy_unsupported.
const (
	NetworkNone      = "none"
	NetworkPublic    = "public"
	NetworkAllowlist = "allowlist"

	MaxAllowEntries = 64
)

// NetworkPolicy is the egress policy of one sandbox. Inbound is never open
// in v1.
type NetworkPolicy struct {
	Allow []string `json:"allow"`
	Mode  string   `json:"mode"`
}

// Validate requires allow to be present (an empty array, never null), empty
// unless mode is allowlist, and otherwise 1..64 sorted unique hostnames or
// canonical CIDR prefixes.
func (p NetworkPolicy) Validate() error {
	if p.Allow == nil {
		return errors.New("network allow must be an array")
	}
	switch p.Mode {
	case NetworkNone, NetworkPublic:
		if len(p.Allow) != 0 {
			return errors.New("network allow is only valid in allowlist mode")
		}
		return nil
	case NetworkAllowlist:
	default:
		return errors.New("network mode is invalid")
	}
	if len(p.Allow) == 0 || len(p.Allow) > MaxAllowEntries || !sortedUnique(p.Allow) {
		return errors.New("network allowlist must hold 1..64 sorted unique entries")
	}
	for _, entry := range p.Allow {
		if !validAllowEntry(entry) {
			return errors.New("network allowlist entry is not a hostname or canonical CIDR")
		}
	}
	return nil
}

func validAllowEntry(entry string) bool {
	if organic.ValidHostname(entry) {
		return true
	}
	prefix, err := netip.ParsePrefix(entry)
	return err == nil && prefix.Masked() == prefix && prefix.String() == entry
}

// Isolation classes. Each is a kernel boundary stronger than plain runc
// namespaces; a lease names exactly one.
const (
	IsolationGVisor      = "gvisor"
	IsolationKata        = "kata"
	IsolationFirecracker = "firecracker"
)

// ValidIsolation reports whether value is a v1 isolation class.
func ValidIsolation(value string) bool {
	switch value {
	case IsolationGVisor, IsolationKata, IsolationFirecracker:
		return true
	}
	return false
}

// Environment bounds. env carries only non-secret values: every signed
// document is persisted and may be logged by validator and miner.
const (
	MaxEnvEntries    = 128
	MaxEnvValueBytes = 4096
	MaxEnvTotalBytes = 32768
	MaxSecretNames   = 64
)

var (
	envNamePattern  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	envValuePattern = regexp.MustCompile(`^[\x20-\x7e\t]*$`)
	imagePattern    = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]{1,5})?/)?[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*@(sha256:[0-9a-f]{64})$`)
)

// ValidEnvName reports whether value is a portable environment name.
func ValidEnvName(value string) bool { return envNamePattern.MatchString(value) }

// ValidateEnv checks a non-secret environment map. It must be present (an
// empty object, never null).
func ValidateEnv(env map[string]string) error {
	if env == nil {
		return errors.New("env must be an object")
	}
	if len(env) > MaxEnvEntries {
		return errors.New("env has too many entries")
	}
	total := 0
	for name, value := range env {
		if !ValidEnvName(name) || len(value) > MaxEnvValueBytes || !envValuePattern.MatchString(value) {
			return errors.New("env entry is invalid")
		}
		total += len(name) + len(value)
	}
	if total > MaxEnvTotalBytes {
		return errors.New("env is too large")
	}
	return nil
}

// Secret delivery schemes. A signed document never carries a secret value.
// sealed-bundle-v1 names the variables and binds the digest of a bundle
// that is delivered separately; its delivery path is not implemented yet,
// so a miner refuses it with secret_delivery_unsupported.
const (
	SecretDeliveryNone         = "none"
	SecretDeliverySealedBundle = "sealed-bundle-v1"
)

// SecretEnv declares secret environment variables without their values.
type SecretEnv struct {
	BundleDigest *string  `json:"bundle_digest"`
	Delivery     string   `json:"delivery"`
	Names        []string `json:"names"`
}

// Validate checks the declaration shape.
func (s SecretEnv) Validate() error {
	if s.Names == nil {
		return errors.New("secret_env names must be an array")
	}
	switch s.Delivery {
	case SecretDeliveryNone:
		if len(s.Names) != 0 || s.BundleDigest != nil {
			return errors.New("secret_env without delivery carries names or a bundle")
		}
		return nil
	case SecretDeliverySealedBundle:
	default:
		return errors.New("secret_env delivery is invalid")
	}
	if s.BundleDigest == nil || !organic.ValidDigest(*s.BundleDigest) {
		return errors.New("secret_env bundle_digest is invalid")
	}
	if len(s.Names) == 0 || len(s.Names) > MaxSecretNames || !sortedUnique(s.Names) {
		return errors.New("secret_env names must be 1..64 sorted unique names")
	}
	for _, name := range s.Names {
		if !ValidEnvName(name) {
			return errors.New("secret_env name is invalid")
		}
	}
	return nil
}

// ImageDigest returns the digest pinned by an OCI reference of the form
// [registry[:port]/]repository@sha256:<hex>. Tags are not admitted: the
// validator resolves a tag before signing.
func ImageDigest(reference string) (string, bool) {
	if len(reference) > 512 {
		return "", false
	}
	match := imagePattern.FindStringSubmatch(reference)
	if match == nil {
		return "", false
	}
	return match[1], true
}

// Release reasons.
const (
	ReleaseCustomerDelete   = "customer_delete"
	ReleaseTTLExpired       = "ttl_expired"
	ReleasePlacementAborted = "placement_aborted"
	ReleaseHoldUnused       = "hold_unused"
	ReleaseLivenessLost     = "liveness_lost"
	ReleaseOperator         = "operator_takedown"
)

// ValidReleaseReason reports whether value is a v1 release reason.
func ValidReleaseReason(value string) bool {
	switch value {
	case ReleaseCustomerDelete, ReleaseTTLExpired, ReleasePlacementAborted, ReleaseHoldUnused, ReleaseLivenessLost, ReleaseOperator:
		return true
	}
	return false
}

// Receipt stages: held and refused answer a reservation; the rest answer a
// lease, a renewal or a release.
const (
	StageHeld     = "held"
	StageRefused  = "refused"
	StageAccepted = "accepted"
	StageReady    = "ready"
	StageFailed   = "failed"
	StageReleased = "released"
	StageExpired  = "expired"
)

// ReceiptErrorAttribution maps every receipt error code to whether it is
// attributed to the miner. Unsupported features and customer or validator
// decisions are not miner faults.
var ReceiptErrorAttribution = map[string]bool{
	"capacity_exhausted":          false,
	"resources_unsupported":       false,
	"network_policy_unsupported":  false,
	"isolation_unsupported":       false,
	"secret_delivery_unsupported": false,
	"sandbox_disabled":            false,
	"released_before_use":         false,
	"hold_expired":                false,
	"lease_expired":               false,
	"image_unavailable":           false,
	"runtime_start_failed":        true,
	"miner_restart":               true,
}

func sortedUnique(values []string) bool {
	if !sort.StringsAreSorted(values) {
		return false
	}
	for index := 1; index < len(values); index++ {
		if values[index] == values[index-1] {
			return false
		}
	}
	return true
}
