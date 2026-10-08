// SPDX-License-Identifier: AGPL-3.0-only

// Package organic holds the Go mirror of the organic app deployment wire
// contracts (misscomputer_subnet.organic_contracts). Every exported document
// type has a Validate method carrying the same rules as the Pydantic model,
// and DecodeStrict refuses anything the Python parser refuses: duplicate or
// unknown keys, case-folded keys, missing fields, non-integral numbers,
// non-ASCII text and trailing data. The shared fixtures under contracts/ pin
// both implementations byte for byte.
//
// The deployment.v4 ticket and receipt live in pkg/protocol and the
// artifact-manifest v2 in pkg/artifact; both reuse this package's vocabulary.
package organic

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
	"github.com/misscomputer/misscomputer-subnet/pkg/assignment"
)

const (
	SchemaPrefix       = "miss.computer/misscomputer-subnet/"
	RouteDomain        = "on.miss.computer"
	Platform           = "linux/amd64"
	RuntimeProfile     = "small-v1"
	WorkloadKind       = "oci-image-v1"
	ScoringDisposition = "organic_v1"
	// CapabilityFeature is the miner capability a validator requires before
	// assigning organic work; miners without it are ineligible (fail closed).
	CapabilityFeature = "organic-oci-v1"
	// SynapseVersion is the envelope version of every validator<->miner
	// message that embeds a deployment.v4 ticket or receipt.
	SynapseVersion         = "subnet-synapse.v3"
	Replicas               = 3
	HealthFailureThreshold = 2

	OCIManifestMediaType = "application/vnd.oci.image.manifest.v1+json"
	OCIConfigMediaType   = "application/vnd.oci.image.config.v1+json"
	OCILayerTar          = "application/vnd.oci.image.layer.v1.tar"
	OCILayerTarGzip      = "application/vnd.oci.image.layer.v1.tar+gzip"
	MaxLayers            = 127

	EdgeAuthorizationHeader         = "X-Miss-Edge-Authorization"
	OrganicProbeAuthorizationHeader = "X-Miss-Organic-Probe-Authorization"
	ProbeAttestationHeader          = "X-Miss-Probe-Attestation"
	ApplicationSecretHeader         = "X-MissComputer-Application-Secret"

	// The edge wire vocabulary a third-party verifier speaks when probing
	// deployments through the edge. The canonical definitions live here so
	// the public validator carries no dependency on the private edge
	// implementation, which aliases these names for its own callers.
	TargetReplicaHeader      = "X-Miss-Target-Replica"
	ProbeAuthorizationHeader = "X-Miss-Internal-Probe-Token"
	// UpstreamResponseHeader marks a response the edge actually received
	// from a replica, as opposed to one the edge synthesized on the
	// replica's behalf; UpstreamResponseMarker is its only replica value.
	UpstreamResponseHeader = "X-Miss-Edge-Upstream"
	// AgentEndpointUnavailableHeader is emitted by an authenticated miner agent
	// only when its bound organic endpoint has no active runtime incarnation.
	// Workload responses cannot supply this reserved protocol header.
	AgentEndpointUnavailableHeader = "X-Miss-Agent-Endpoint-State"
	AgentEndpointUnavailableValue  = "unavailable-v1"
	UpstreamResponseMarker         = "replica"

	// MaxDocumentBytes bounds every organic wire document DecodeStrict accepts.
	MaxDocumentBytes = 16 << 20
)

// SmallV1 is the only runtime profile of the MVP. A miner rejects a ticket
// whose resources differ from it.
var SmallV1 = Resources{CPUMillis: 1000, MemoryMB: 1024, DiskMB: 2048, PIDs: 256, TmpfsMB: 64}

// Resources is the deployment.v4 resource vocabulary.
type Resources struct {
	CPUMillis int `json:"cpu_millis"`
	MemoryMB  int `json:"memory_mb"`
	DiskMB    int `json:"disk_mb"`
	PIDs      int `json:"pids"`
	TmpfsMB   int `json:"tmpfs_mb"`
}

var reservedRoutePrefixes = []string{"syn-", "readiness-probe", "xn--"}

const dnsLabel = `[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?`

var (
	digestPattern         = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	hex32Pattern          = regexp.MustCompile(`^[0-9a-f]{32}$`)
	hex64Pattern          = regexp.MustCompile(`^[0-9a-f]{64}$`)
	signaturePattern      = regexp.MustCompile(`^[0-9a-f]{128}$`)
	hotkeyPattern         = regexp.MustCompile(`^[A-Za-z0-9]{1,128}$`)
	applicationKeyPattern = regexp.MustCompile(`^app_[0-9a-f]{32}$`)
	applicationIDPattern  = regexp.MustCompile(`^apl_[0-9a-f]{32}$`)
	apiDeploymentPattern  = regexp.MustCompile(`^dep_[0-9a-f]{32}$`)
	uploadIDPattern       = regexp.MustCompile(`^upl_[0-9a-f]{32}$`)
	dnsLabelPattern       = regexp.MustCompile(`^` + dnsLabel + `$`)
	hostnamePattern       = regexp.MustCompile(`^` + dnsLabel + `(?:\.` + dnsLabel + `)+$`)
	printablePattern      = regexp.MustCompile(`^[\x20-\x7e]*$`)
	upperSnakePattern     = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	lowerSnakePattern     = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	healthPathPattern     = regexp.MustCompile(`^/(?:[\x21\x22\x24-\x2e\x30-\x3e\x40-\x7e][\x21\x22\x24-\x3e\x40-\x7e]*)?$`)
	markerPattern         = regexp.MustCompile(`^[\x20-\x7e]{1,256}$`)
	manifestKeyPattern    = regexp.MustCompile(`^v1/manifests/[0-9a-f]{64}\.json$`)
	timestampPattern      = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z$`)
	integerPattern        = regexp.MustCompile(`^(?:0|[1-9][0-9]*)$`)
)

// ValidDigest reports whether value is "sha256:" plus 64 lowercase hex.
func ValidDigest(value string) bool { return digestPattern.MatchString(value) }

// ValidHex64 reports whether value is 64 lowercase hex characters.
func ValidHex64(value string) bool { return hex64Pattern.MatchString(value) }

// ValidRouteLabel reports whether value is a DNS label usable as a
// route_label / subnet deployment_id (and therefore as requested_name).
func ValidRouteLabel(value string) bool {
	if !dnsLabelPattern.MatchString(value) {
		return false
	}
	for _, prefix := range reservedRoutePrefixes {
		if strings.HasPrefix(value, prefix) {
			return false
		}
	}
	return true
}

// ValidHostname reports whether value is a lowercase multi-label hostname.
func ValidHostname(value string) bool {
	return len(value) <= 253 && hostnamePattern.MatchString(value)
}

// ValidHotkey reports whether value has the public hotkey shape.
func ValidHotkey(value string) bool { return hotkeyPattern.MatchString(value) }

// RouteHost is the public hostname of a route label.
func RouteHost(routeLabel string) string { return routeLabel + "." + RouteDomain }

// ManifestKey is the artifact bucket key of an artifact digest.
func ManifestKey(artifactDigest string) string { return artifact.ManifestKey(artifactDigest) }

// ValidTimestamp reports whether value is a canonical Go RFC3339Nano UTC
// timestamp: "Z" suffix and no trailing fractional zeros.
func ValidTimestamp(value string) bool {
	if !timestampPattern.MatchString(value) {
		return false
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && parsed.UTC().Format(time.RFC3339Nano) == value
}

func validOptionalTimestamp(value *string) bool { return value == nil || ValidTimestamp(*value) }

func validPrintable(value string, maximum int) bool {
	return len(value) <= maximum && printablePattern.MatchString(value)
}

func validOptionalPrintable(value *string, maximum int) bool {
	return value == nil || validPrintable(*value, maximum)
}

// Canonical renders the canonical JSON bytes shared by every contract
// (sorted keys, compact separators, ASCII only).
func Canonical(value any) ([]byte, error) { return assignment.CanonicalJSON(value) }

// CanonicalBytes is the on-disk/on-wire form: canonical JSON plus one newline.
func CanonicalBytes(value any) ([]byte, error) {
	encoded, err := Canonical(value)
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

// DigestHex is the lowercase hex SHA-256 of value's canonical JSON.
func DigestHex(value any) (string, error) {
	encoded, err := Canonical(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

// DigestWithout is the self-digest of value's canonical document without the
// named top-level field, exactly as the Python contracts compute it.
func DigestWithout(value any, field string) (string, error) {
	document, err := genericDocument(value)
	if err != nil {
		return "", err
	}
	object, ok := document.(map[string]any)
	if !ok {
		return "", errors.New("self digest requires an object document")
	}
	delete(object, field)
	return DigestHex(object)
}

func genericDocument(value any) (any, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var document any
	if err := decoder.Decode(&document); err != nil {
		return nil, err
	}
	return document, nil
}

// Validator is implemented by every organic contract document.
type Validator interface {
	Validate() error
}

// DecodeStrict decodes exactly one JSON document into out and validates it.
// HTTP bodies need not be canonical bytes; DecodeCanonical additionally
// requires them. The decoded value must re-encode to the same document, so a
// missing, case-folded or non-integral member is refused rather than zeroed.
func DecodeStrict(payload []byte, out Validator) error {
	if len(payload) == 0 || len(payload) > MaxDocumentBytes {
		return errors.New("document_size_invalid")
	}
	if err := rejectDuplicateKeys(payload); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return fmt.Errorf("document_invalid: %w", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("document_invalid: trailing data")
	}
	original := json.NewDecoder(bytes.NewReader(payload))
	original.UseNumber()
	var generic any
	if err := original.Decode(&generic); err != nil {
		return fmt.Errorf("document_invalid: %w", err)
	}
	want, err := Canonical(generic)
	if err != nil {
		return fmt.Errorf("document_invalid: %w", err)
	}
	got, err := Canonical(out)
	if err != nil {
		return fmt.Errorf("document_invalid: %w", err)
	}
	if !bytes.Equal(want, got) {
		return errors.New("document_invalid: members do not round-trip exactly")
	}
	return out.Validate()
}

// DecodeCanonical is DecodeStrict plus an exact canonical-bytes requirement.
func DecodeCanonical(payload []byte, out Validator) error {
	if err := DecodeStrict(payload, out); err != nil {
		return err
	}
	rendered, err := CanonicalBytes(out)
	if err != nil {
		return err
	}
	if !bytes.Equal(rendered, payload) {
		return errors.New("document_not_canonical")
	}
	return nil
}

func rejectDuplicateKeys(payload []byte) error {
	type frame struct {
		object    bool
		expectKey bool
		keys      map[string]struct{}
	}
	var stack []frame
	valueDone := func() {
		if top := len(stack) - 1; top >= 0 && stack[top].object {
			stack[top].expectKey = true
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("document_invalid: %w", err)
		}
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{':
				stack = append(stack, frame{object: true, expectKey: true, keys: map[string]struct{}{}})
			case '[':
				stack = append(stack, frame{})
			default:
				stack = stack[:len(stack)-1]
				valueDone()
			}
			continue
		}
		if top := len(stack) - 1; top >= 0 && stack[top].object && stack[top].expectKey {
			key, _ := token.(string)
			if _, seen := stack[top].keys[key]; seen {
				return errors.New("duplicate_json_key")
			}
			stack[top].keys[key] = struct{}{}
			stack[top].expectKey = false
			continue
		}
		valueDone()
	}
}

// Scalar is one metadata value: a printable string, a boolean or a
// non-negative integer. It keeps its exact JSON so metadata round-trips.
type Scalar = json.RawMessage

func validScalar(value Scalar, maximumString int) bool {
	text := string(value)
	switch {
	case text == "true" || text == "false":
		return true
	case integerPattern.MatchString(text):
		parsed, err := strconv.ParseUint(text, 10, 64)
		return err == nil && parsed <= math.MaxInt64
	case strings.HasPrefix(text, `"`):
		var decoded string
		return json.Unmarshal(value, &decoded) == nil && validPrintable(decoded, maximumString)
	}
	return false
}

func validScalarMap(values map[string]Scalar, maximumString int) bool {
	if values == nil || len(values) > 32 {
		return false
	}
	for key, value := range values {
		if !lowerSnakePattern.MatchString(key) || !validScalar(value, maximumString) {
			return false
		}
	}
	return true
}

func between(value, minimum, maximum int64) bool { return value >= minimum && value <= maximum }

func validSchema(value, name string) error {
	if value != SchemaPrefix+name {
		return fmt.Errorf("schema must be %q", SchemaPrefix+name)
	}
	return nil
}
