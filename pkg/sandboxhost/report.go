// SPDX-License-Identifier: AGPL-3.0-only

// Package sandboxhost is the read-only host contract of the sandbox-lease-v1
// gVisor backend: the sandbox-host-profile.v1 document a provisioner writes,
// the sandbox-host-preflight.v1 report, and kernel, cgroup, filesystem and
// process observations of the checks this package owns
// (docs/sandbox-host-enforcement.md). It never changes the host. Engine
// facts (engine.* checks) are observed by the backend's Engine API client
// and merged into the same report with BuildReport.
package sandboxhost

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
)

// Evidence classes (see the catalog's "classes" member).
const (
	ObservedEffect = "observed_effect"
	ObservedState  = "observed_state"
	Configured     = "configured"
	Unenforced     = "unenforced"
)

// Check statuses. Only an unenforced check reports StatusGap.
const (
	StatusPass   = "pass"
	StatusFail   = "fail"
	StatusNotRun = "not_run"
	StatusGap    = "gap"
)

// Report modes.
const (
	ModeConformance = "conformance"
	ModePreflight   = "preflight"
	ModeInstance    = "instance"
)

const reportSchema = "miss.computer/misscomputer-subnet/sandbox-host-preflight"

//go:embed check-catalog.v1.json
var catalogJSON []byte

// CatalogEntry is one check of check-catalog.v1.json.
type CatalogEntry struct {
	ID    string   `json:"id"`
	Class string   `json:"class"`
	Owner string   `json:"owner"`
	Modes []string `json:"modes"`
	What  string   `json:"what"`
}

var catalog = mustLoadCatalog()

func mustLoadCatalog() []CatalogEntry {
	var doc struct {
		SchemaVersion int            `json:"schema_version"`
		Checks        []CatalogEntry `json:"checks"`
	}
	if err := json.Unmarshal(catalogJSON, &doc); err != nil || doc.SchemaVersion != 1 {
		panic(fmt.Sprintf("sandboxhost: invalid embedded catalog: %v", err))
	}
	return doc.Checks
}

// Catalog returns the checks in catalog order.
func Catalog() []CatalogEntry { return append([]CatalogEntry(nil), catalog...) }

func catalogEntry(id string) (CatalogEntry, bool) {
	for _, entry := range catalog {
		if entry.ID == id {
			return entry, true
		}
	}
	return CatalogEntry{}, false
}

func (e CatalogEntry) inMode(mode string) bool {
	for _, m := range e.Modes {
		if m == mode {
			return true
		}
	}
	return false
}

// Check is one recorded check.
type Check struct {
	ID       string `json:"id"`
	Class    string `json:"class"`
	Status   string `json:"status"`
	Evidence string `json:"evidence"`
}

// Environment identifies what produced a report.
type Environment struct {
	SourceSHA   *string `json:"source_sha"`
	GitHubRunID *string `json:"github_run_id"`
	RunnerImage *string `json:"runner_image"`
	Kernel      *string `json:"kernel"`
	Systemd     *string `json:"systemd"`
	Docker      *string `json:"docker"`
	Containerd  *string `json:"containerd"`
	Runsc       *string `json:"runsc"`
}

// Report is a sandbox-host-preflight.v1 document.
type Report struct {
	Schema        string      `json:"schema"`
	SchemaVersion int         `json:"schema_version"`
	Mode          string      `json:"mode"`
	Environment   Environment `json:"environment"`
	ProfileDigest string      `json:"profile_digest"`
	Checks        []Check     `json:"checks"`
	Unenforced    []string    `json:"unenforced"`
	Verdict       string      `json:"verdict"`
}

// Passed reports whether every non-gap check passed.
func (r Report) Passed() bool { return r.Verdict == StatusPass }

var printable = regexp.MustCompile(`^[\x20-\x7e]{0,512}$`)

func checkEntry(c Check, mode string) error {
	entry, ok := catalogEntry(c.ID)
	if !ok {
		return fmt.Errorf("unknown check %q", c.ID)
	}
	if !entry.inMode(mode) {
		return fmt.Errorf("check %q is not part of mode %s", c.ID, mode)
	}
	if c.Class != entry.Class {
		return fmt.Errorf("check %q is class %s, not %s", c.ID, entry.Class, c.Class)
	}
	allowed := map[string]bool{StatusPass: true, StatusFail: true, StatusNotRun: true}
	if entry.Class == Unenforced {
		allowed = map[string]bool{StatusGap: true, StatusNotRun: true}
	}
	if !allowed[c.Status] {
		return fmt.Errorf("check %q of class %s cannot report status %q", c.ID, entry.Class, c.Status)
	}
	if !printable.MatchString(c.Evidence) {
		return fmt.Errorf("check %q evidence must be printable ASCII of at most 512 bytes", c.ID)
	}
	return nil
}

func deriveVerdict(checks []Check) string {
	for _, c := range checks {
		want := StatusPass
		if c.Class == Unenforced {
			want = StatusGap
		}
		if c.Status != want {
			return StatusFail
		}
	}
	return StatusPass
}

// BuildReport merges the checks of every producer (this package and the
// backend's engine client) into one report. Every catalog check of mode
// appears once with its catalog class; one that nobody recorded is not_run.
// The verdict is derived, never supplied.
func BuildReport(mode string, profile Profile, checks []Check, env Environment) (Report, error) {
	if mode != ModeConformance && mode != ModePreflight && mode != ModeInstance {
		return Report{}, fmt.Errorf("unknown mode %q", mode)
	}
	digest, err := profile.Digest()
	if err != nil {
		return Report{}, err
	}
	byID := map[string]Check{}
	for _, c := range checks {
		if err := checkEntry(c, mode); err != nil {
			return Report{}, err
		}
		if _, dup := byID[c.ID]; dup {
			return Report{}, fmt.Errorf("check %q recorded twice", c.ID)
		}
		byID[c.ID] = c
	}
	report := Report{Schema: reportSchema, SchemaVersion: 1, Mode: mode, Environment: env, ProfileDigest: digest,
		Checks: []Check{}, Unenforced: []string{}}
	for _, entry := range catalog {
		if !entry.inMode(mode) {
			continue
		}
		c, ok := byID[entry.ID]
		if !ok {
			c = Check{ID: entry.ID, Class: entry.Class, Status: StatusNotRun, Evidence: "not reached"}
		}
		report.Checks = append(report.Checks, c)
		if entry.Class == Unenforced {
			report.Unenforced = append(report.Unenforced, entry.ID)
		}
	}
	sort.Strings(report.Unenforced)
	report.Verdict = deriveVerdict(report.Checks)
	return report, nil
}

// ErrNotPassed is returned by RequirePass for a report that did not pass.
var ErrNotPassed = errors.New("sandbox host report did not pass")

// RequirePass returns nil only for a passed report and otherwise names the
// first check that did not pass.
func RequirePass(r Report) error {
	if r.Passed() && deriveVerdict(r.Checks) == StatusPass {
		return nil
	}
	for _, c := range r.Checks {
		if (c.Class == Unenforced && c.Status != StatusGap) || (c.Class != Unenforced && c.Status != StatusPass) {
			return fmt.Errorf("%w: %s %s: %s", ErrNotPassed, c.ID, c.Status, c.Evidence)
		}
	}
	return ErrNotPassed
}
