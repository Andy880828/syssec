// Package core holds the domain model shared by every syssec module.
// It has no dependencies on infrastructure (filesystem, network, storage).
package core

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
)

// SchemaVersion identifies the shape of the JSON envelope emitted by the CLI.
const SchemaVersion = "syssec/v1"

// Severity ranks the impact of a failed check or a vulnerability.
type Severity int

const (
	SeverityUnknown Severity = iota - 1
	SeverityInfo
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = map[Severity]string{
	SeverityUnknown:  "unknown",
	SeverityInfo:     "info",
	SeverityLow:      "low",
	SeverityMedium:   "medium",
	SeverityHigh:     "high",
	SeverityCritical: "critical",
}

func (s Severity) String() string {
	if n, ok := severityNames[s]; ok {
		return n
	}
	return "unknown"
}

// ParseSeverity accepts canonical names plus common vendor aliases
// (GHSA "moderate", Red Hat "important", Ubuntu "negligible", Debian "unimportant").
func ParseSeverity(v string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "critical":
		return SeverityCritical, nil
	case "high", "important":
		return SeverityHigh, nil
	case "medium", "moderate":
		return SeverityMedium, nil
	case "low", "negligible":
		return SeverityLow, nil
	case "info", "informational", "none", "unimportant":
		return SeverityInfo, nil
	case "unknown", "":
		return SeverityUnknown, nil
	}
	return SeverityUnknown, fmt.Errorf("unknown severity %q (want info|low|medium|high|critical)", v)
}

// SeverityFromCVSS maps a CVSS base score onto the qualitative scale.
func SeverityFromCVSS(score float64) Severity {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score > 0:
		return SeverityLow
	}
	return SeverityInfo
}

// Weight is the scoring weight of a check of this severity.
func (s Severity) Weight() int {
	switch s {
	case SeverityCritical:
		return 10
	case SeverityHigh:
		return 6
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 1
	}
	return 0
}

func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

func (s *Severity) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	v, err := ParseSeverity(str)
	*s = v
	return err
}

// Status is the outcome of a single check.
type Status string

const (
	StatusPass  Status = "pass"
	StatusFail  Status = "fail"
	StatusWarn  Status = "warn"
	StatusSkip  Status = "skip"
	StatusError Status = "error"
	// StatusWaived is a fail/warn the operator accepted via a waiver.
	StatusWaived Status = "waived"
)

// IsProblem reports whether the status deserves attention.
func (s Status) IsProblem() bool { return s == StatusFail || s == StatusWarn || s == StatusError }

func (s Status) rank() int {
	switch s {
	case StatusFail:
		return 0
	case StatusWarn:
		return 1
	case StatusError:
		return 2
	case StatusWaived:
		return 3
	case StatusPass:
		return 4
	}
	return 5
}

// CheckMeta is the static description of a security check.
type CheckMeta struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Category    string   `json:"category"`
	Severity    Severity `json:"severity"`
	Platforms   []string `json:"platforms,omitempty"`
	Description string   `json:"description,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	References  []string `json:"references,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

// SupportsPlatform reports whether the check applies to GOOS p. An empty
// platform list means "all platforms".
func (m CheckMeta) SupportsPlatform(p string) bool {
	return len(m.Platforms) == 0 || slices.Contains(m.Platforms, p)
}

// Result is the outcome of running one check on one host.
type Result struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Category    string   `json:"category"`
	Severity    Severity `json:"severity"`
	Status      Status   `json:"status"`
	Evidence    string   `json:"evidence,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Waiver      *Waiver  `json:"waiver,omitempty"`
}

// Waiver records an accepted risk. Expires is a date (YYYY-MM-DD) or empty.
type Waiver struct {
	ID      string `json:"id"`                // check ID, advisory ID or CVE
	Package string `json:"package,omitempty"` // vulns only: limit to one package
	Reason  string `json:"reason"`
	Expires string `json:"expires,omitempty"`
	Created string `json:"created,omitempty"`
}

// HostOnly tags checks that judge the host kernel/boot chain; inside a
// container they are skipped because the container cannot change them.
const TagHostOnly = "host-only"

// SortResults orders results so the most actionable items come first.
func SortResults(rs []Result) {
	slices.SortStableFunc(rs, func(a, b Result) int {
		if a.Status.IsProblem() != b.Status.IsProblem() {
			if a.Status.IsProblem() {
				return -1
			}
			return 1
		}
		if a.Severity != b.Severity {
			return int(b.Severity - a.Severity)
		}
		if a.Status.rank() != b.Status.rank() {
			return a.Status.rank() - b.Status.rank()
		}
		return strings.Compare(a.ID, b.ID)
	})
}

// Package is one installed software package.
type Package struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	Manager       string `json:"manager"`
	Arch          string `json:"arch,omitempty"`
	Ecosystem     string `json:"ecosystem,omitempty"` // OSV ecosystem; empty = not matchable
	SourceName    string `json:"source_name,omitempty"`
	SourceVersion string `json:"source_version,omitempty"`
}

// Key identifies a package independently of its version.
func (p Package) Key() string { return p.Manager + "/" + p.Name + ":" + p.Arch }

// Query returns the name/version pair advisories are keyed on. Debian-style
// advisories are published against source packages.
func (p Package) Query() (name, version string) {
	name, version = p.Name, p.Version
	if p.SourceName != "" {
		name = p.SourceName
	}
	if p.SourceVersion != "" {
		version = p.SourceVersion
	}
	return name, version
}

// Vuln is a known vulnerability affecting an installed package.
type Vuln struct {
	ID        string   `json:"id"`
	Package   string   `json:"package"`
	Version   string   `json:"version"`
	Ecosystem string   `json:"ecosystem,omitempty"`
	Severity  Severity `json:"severity"`
	CVSS      float64  `json:"cvss,omitempty"`
	KEV       bool     `json:"kev,omitempty"`  // listed in CISA Known Exploited Vulnerabilities
	EPSS      float64  `json:"epss,omitempty"` // FIRST EPSS: probability of exploitation in 30 days
	Priority  string   `json:"priority"`       // P0..P3, see Prioritize
	FixedIn   string   `json:"fixed_in,omitempty"`
	Summary   string   `json:"summary,omitempty"`
	Aliases   []string `json:"aliases,omitempty"`
	Waiver    *Waiver  `json:"waiver,omitempty"`
}

// Prioritize assigns a transparent, explainable fix priority:
//
//	P0  exploited in the wild (CISA KEV)
//	P1  likely to be exploited (EPSS >= 0.1) or critical with a fix available
//	P2  high/critical severity, or EPSS >= 0.01
//	P3  everything else
func (v *Vuln) Prioritize() {
	switch {
	case v.KEV:
		v.Priority = "P0"
	case v.EPSS >= 0.1 || (v.Severity == SeverityCritical && v.FixedIn != ""):
		v.Priority = "P1"
	case v.Severity >= SeverityHigh || v.EPSS >= 0.01:
		v.Priority = "P2"
	default:
		v.Priority = "P3"
	}
}

// Key identifies a vulnerability instance on a package.
func (v Vuln) Key() string { return v.ID + "@" + v.Package }

// SortVulns orders vulns by priority, exploit probability, severity, score, then ID.
func SortVulns(vs []Vuln) {
	slices.SortStableFunc(vs, func(a, b Vuln) int {
		if a.Priority != b.Priority {
			return strings.Compare(a.Priority, b.Priority)
		}
		if a.EPSS != b.EPSS {
			if a.EPSS > b.EPSS {
				return -1
			}
			return 1
		}
		if a.Severity != b.Severity {
			return int(b.Severity - a.Severity)
		}
		if a.CVSS != b.CVSS {
			if a.CVSS > b.CVSS {
				return -1
			}
			return 1
		}
		if c := strings.Compare(a.ID, b.ID); c != 0 {
			return c
		}
		return strings.Compare(a.Package, b.Package)
	})
}

// KEVEntry is a record of the CISA Known Exploited Vulnerabilities catalog.
type KEVEntry struct {
	CVE        string `json:"cveID"`
	Vendor     string `json:"vendorProject"`
	Product    string `json:"product"`
	Name       string `json:"vulnerabilityName"`
	DateAdded  string `json:"dateAdded"`
	DueDate    string `json:"dueDate"`
	Ransomware string `json:"knownRansomwareCampaignUse"`
}

// EPSSScore is the probability (0-1) that a CVE is exploited in the next
// 30 days, and its percentile among all scored CVEs.
type EPSSScore struct {
	CVE        string  `json:"cve"`
	Score      float64 `json:"score"`
	Percentile float64 `json:"percentile"`
	Date       string  `json:"date"`
}

// Host describes the scanned machine.
type Host struct {
	Hostname   string `json:"hostname"`
	OS         string `json:"os"`
	Arch       string `json:"arch"`
	Distro     string `json:"distro,omitempty"`
	Version    string `json:"version,omitempty"`
	Pretty     string `json:"pretty,omitempty"`
	Kernel     string `json:"kernel,omitempty"`
	Container  string `json:"container,omitempty"` // docker|podman|kubernetes|lxc|container when inside one
	Privileged bool   `json:"privileged"`
}

// Summary condenses a report into numbers an agent can reason about quickly.
type Summary struct {
	Score           int            `json:"score"` // 0-100 hardening score
	Grade           string         `json:"grade"`
	Checks          int            `json:"checks"`
	Status          map[string]int `json:"status"`             // count per status
	Failed          map[string]int `json:"failed_by_severity"` // fail+warn per severity
	Packages        int            `json:"packages"`
	Vulns           int            `json:"vulns"` // excludes waived vulns
	VulnsByPriority map[string]int `json:"vulns_by_priority,omitempty"`
	VulnsBySeverity map[string]int `json:"vulns_by_severity,omitempty"`
	KEV             int            `json:"kev"`
	Fixable         int            `json:"fixable"` // vulns with a published fixed version
	Waived          int            `json:"waived"`  // checks + vulns covered by a waiver
}

// Report is the full outcome of one scan.
type Report struct {
	ID               int64     `json:"scan_id,omitempty"`
	StartedAt        time.Time `json:"started_at"`
	DurationMS       int64     `json:"duration_ms"`
	Host             Host      `json:"host"`
	Summary          Summary   `json:"summary"`
	Results          []Result  `json:"results"`
	Packages         []Package `json:"packages,omitempty"`
	Vulns            []Vuln    `json:"vulns,omitempty"`
	InventoryScanned bool      `json:"inventory_scanned"`
	VulnScanned      bool      `json:"vuln_scanned"`
	Partial          bool      `json:"partial,omitempty"` // only a subset of checks ran
	Errors           []string  `json:"errors,omitempty"`
}

// Summarize computes the score and counters. Passed checks earn their full
// weight, warnings half, failures none; skipped, errored and waived checks
// are excluded.
func Summarize(results []Result, packages int, vulns []Vuln) Summary {
	s := Summary{
		Checks:   len(results),
		Status:   map[string]int{},
		Failed:   map[string]int{},
		Packages: packages,
	}
	total, earned := 0, 0
	for _, r := range results {
		s.Status[string(r.Status)]++
		w := r.Severity.Weight()
		switch r.Status {
		case StatusPass:
			total += 2 * w
			earned += 2 * w
		case StatusWarn:
			total += 2 * w
			earned += w
			s.Failed[r.Severity.String()]++
		case StatusFail:
			total += 2 * w
			s.Failed[r.Severity.String()]++
		}
	}
	s.Score = 100
	if total > 0 {
		s.Score = (earned*100 + total/2) / total
	}
	s.Grade = Grade(s.Score)
	s.Waived = s.Status[string(StatusWaived)]
	for _, v := range vulns {
		if v.Waiver != nil {
			s.Waived++
			continue
		}
		if s.VulnsBySeverity == nil {
			s.VulnsBySeverity, s.VulnsByPriority = map[string]int{}, map[string]int{}
		}
		s.Vulns++
		s.VulnsBySeverity[v.Severity.String()]++
		s.VulnsByPriority[v.Priority]++
		if v.KEV {
			s.KEV++
		}
		if v.FixedIn != "" {
			s.Fixable++
		}
	}
	return s
}

// Grade converts a score into a letter grade.
func Grade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	}
	return "F"
}
