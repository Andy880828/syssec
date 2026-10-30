package cli

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Andy880828/syssec/internal/app"
	"github.com/Andy880828/syssec/internal/core"
	"github.com/Andy880828/syssec/internal/diff"
	"github.com/Andy880828/syssec/internal/intel"
)

// reportView is the token-efficient projection of a report: only problems
// are listed by default, at most topVulns vulns are inlined (the `vulns`
// command pages through the rest) and packages are omitted.
type reportView struct {
	ScanID      int64             `json:"scan_id,omitempty"`
	Profile     string            `json:"profile,omitempty"` // summary/findings restricted to this profile
	StartedAt   string            `json:"started_at"`
	Host        core.Host         `json:"host"`
	Summary     core.Summary      `json:"summary"`
	Partial     bool              `json:"partial,omitempty"`
	Findings    []core.Result     `json:"findings"`
	TopVulns    []core.Vuln       `json:"top_vulns,omitempty"`
	VulnScanned bool              `json:"vuln_scanned"`
	Match       *intel.MatchStats `json:"vuln_match,omitempty"`
	Diff        *diffView         `json:"diff,omitempty"`
	Errors      []string          `json:"errors,omitempty"`
	NextSteps   []string          `json:"next_steps,omitempty"`
}

const topVulns = 10

// withProfile restricts a report to one profile's checks and recomputes the
// summary, leaving inventory and vulns untouched. Profiles are views over a
// full scan, so this works for any stored scan too.
func withProfile(a *app.App, r *core.Report, profile string) (*core.Report, error) {
	if profile == "" {
		return r, nil
	}
	if err := a.Checks.ValidateProfile(profile); err != nil {
		return nil, usageError("list profiles with `syssec checks --json` (field profiles)", "%v", err)
	}
	cp := *r
	cp.Results = nil
	for _, res := range r.Results {
		if a.Checks.InProfile(res.ID, profile) {
			cp.Results = append(cp.Results, res)
		}
	}
	cp.Summary = core.Summarize(cp.Results, len(cp.Packages), cp.Vulns)
	return &cp, nil
}

func newReportView(r *core.Report, all bool, min core.Severity) *reportView {
	v := &reportView{
		ScanID: r.ID, StartedAt: r.StartedAt.Format(time.RFC3339), Host: r.Host, Summary: r.Summary,
		Partial: r.Partial, Findings: []core.Result{}, VulnScanned: r.VulnScanned, Errors: r.Errors,
	}
	for _, res := range r.Results {
		if (all || res.Status.IsProblem()) && res.Severity >= min {
			v.Findings = append(v.Findings, res)
		}
	}
	v.TopVulns = vulnFilter{Limit: topVulns}.apply(r.Vulns)
	v.NextSteps = nextSteps(r)
	return v
}

// vulnFilter is shared by `vulns`, `scan`/`report` (top vulns) and --fail-on.
type vulnFilter struct {
	MinSeverity core.Severity
	MaxPriority string // "P1" keeps P0+P1
	KEV         bool
	Fixable     bool
	Running     bool // only vulns in code loaded by a running process
	Package     string
	Waived      bool // include waived vulns
	Limit       int  // 0 = unlimited
}

func (f vulnFilter) match(v core.Vuln) bool {
	return (f.Waived || v.Waiver == nil) &&
		(v.Severity >= f.MinSeverity || v.KEV) &&
		(f.MaxPriority == "" || v.Priority <= f.MaxPriority) &&
		(!f.KEV || v.KEV) &&
		(!f.Fixable || v.FixedIn != "") &&
		(!f.Running || v.Running()) &&
		(f.Package == "" || strings.Contains(strings.ToLower(v.Package), strings.ToLower(f.Package)))
}

func (f vulnFilter) apply(vs []core.Vuln) []core.Vuln {
	out := []core.Vuln{}
	for _, v := range vs {
		if f.match(v) {
			if f.Limit > 0 && len(out) == f.Limit {
				break
			}
			out = append(out, v)
		}
	}
	return out
}

func nextSteps(r *core.Report) []string {
	var steps []string
	for _, v := range r.Vulns {
		if v.KEV && v.Waiver == nil {
			steps = append(steps, fmt.Sprintf("syssec vulns --priority P0 --json  # %d actively exploited (CISA KEV); e.g. %s in %s, fixed in %s", r.Summary.KEV, v.ID, v.Package, orUnknown(v.FixedIn)))
			break
		}
	}
	n := 0
	for _, res := range r.Results {
		if res.Status == core.StatusFail && res.Severity >= core.SeverityHigh && n < 3 {
			steps = append(steps, fmt.Sprintf("syssec explain %s --json  # %s", res.ID, res.Title))
			n++
		}
	}
	if r.Summary.VulnsByPriority["P1"] > 0 {
		steps = append(steps, fmt.Sprintf("syssec vulns --priority P1 --json  # %d likely-exploited or critical-with-fix vulns", r.Summary.VulnsByPriority["P1"]))
	}
	if !r.Host.Privileged && r.Summary.Status["skip"] > 0 {
		steps = append(steps, fmt.Sprintf("re-run as root/Administrator: %d checks were skipped or limited", r.Summary.Status["skip"]))
	}
	if !r.VulnScanned {
		steps = append(steps, "syssec scan --vulns --json  # match installed packages against OSV advisories")
	}
	return steps
}

func orUnknown(s string) string {
	if s == "" {
		return "(no fix published)"
	}
	return s
}

// diffView caps list sizes; --full lifts the cap.
type diffView struct {
	From            diff.Ref             `json:"from"`
	To              diff.Ref             `json:"to"`
	ScoreDelta      int                  `json:"score_delta"`
	Regression      bool                 `json:"regression"`
	Notes           []string             `json:"notes,omitempty"`
	Regressed       []diff.CheckChange   `json:"regressed"`
	Resolved        []diff.CheckChange   `json:"resolved"`
	Changed         []diff.CheckChange   `json:"changed,omitempty"`
	Drifted         []diff.CheckChange   `json:"drifted,omitempty"`
	NewVulns        []core.Vuln          `json:"new_vulns,omitempty"`
	FixedVulns      []core.Vuln          `json:"fixed_vulns,omitempty"`
	PackagesAdded   []core.Package       `json:"packages_added,omitempty"`
	PackagesRemoved []core.Package       `json:"packages_removed,omitempty"`
	PackagesChanged []diff.PackageChange `json:"packages_changed,omitempty"`
	Counts          map[string]int       `json:"counts"`
	Truncated       bool                 `json:"truncated,omitempty"`
}

func newDiffView(d *diff.Diff, limit int) *diffView {
	if d == nil {
		return nil
	}
	v := &diffView{From: d.From, To: d.To, ScoreDelta: d.ScoreDelta, Regression: d.HasRegression(), Notes: d.Notes,
		Regressed: d.Regressed, Resolved: d.Resolved, Changed: d.Changed, Drifted: d.Drifted, Counts: map[string]int{
			"regressed": len(d.Regressed), "resolved": len(d.Resolved), "drifted": len(d.Drifted),
		}}
	clip := func(n int) int {
		if limit > 0 && n > limit {
			v.Truncated = true
			return limit
		}
		return n
	}
	if d.Vulns != nil {
		v.Counts["new_vulns"], v.Counts["fixed_vulns"] = len(d.Vulns.New), len(d.Vulns.Fixed)
		v.NewVulns = d.Vulns.New[:clip(len(d.Vulns.New))]
		v.FixedVulns = d.Vulns.Fixed[:clip(len(d.Vulns.Fixed))]
	}
	if p := d.Packages; p != nil {
		v.Counts["packages_added"], v.Counts["packages_removed"], v.Counts["packages_changed"] = len(p.Added), len(p.Removed), len(p.Upgraded)
		v.PackagesAdded = p.Added[:clip(len(p.Added))]
		v.PackagesRemoved = p.Removed[:clip(len(p.Removed))]
		v.PackagesChanged = p.Upgraded[:clip(len(p.Upgraded))]
	}
	return v
}

// ---- human rendering ----

var statusIcon = map[core.Status]string{
	core.StatusFail: "✗", core.StatusWarn: "!", core.StatusError: "E", core.StatusPass: "✓", core.StatusSkip: "-", core.StatusWaived: "~",
}

func table(w io.Writer) *tabwriter.Writer { return tabwriter.NewWriter(w, 0, 0, 2, ' ', 0) }

func renderReport(w io.Writer, v *reportView) {
	s := v.Summary
	host := v.Host.Pretty
	if host == "" {
		host = v.Host.OS
	}
	id := "unsaved"
	if v.ScanID > 0 {
		id = fmt.Sprintf("#%d", v.ScanID)
	}
	fmt.Fprintf(w, "%s  %s  scan %s  %s\n", v.Host.Hostname, host, id, v.StartedAt)
	fmt.Fprintf(w, "Score %d/100 (%s)  checks %d: %d pass, %d fail, %d warn, %d skip",
		s.Score, s.Grade, s.Checks, s.Status["pass"], s.Status["fail"], s.Status["warn"], s.Status["skip"])
	if v.VulnScanned {
		fmt.Fprintf(w, "  vulns %d (P0 %d, P1 %d, fixable %d)", s.Vulns, s.VulnsByPriority["P0"], s.VulnsByPriority["P1"], s.Fixable)
	}
	if s.Waived > 0 {
		fmt.Fprintf(w, "  waived %d", s.Waived)
	}
	fmt.Fprintln(w)
	if !v.Host.Privileged {
		fmt.Fprintln(w, "note: not running as root — some checks are limited")
	}
	if v.Host.Container != "" {
		fmt.Fprintf(w, "note: inside a %s container — host-level checks are skipped\n", v.Host.Container)
	}
	if v.Profile != "" {
		fmt.Fprintf(w, "profile: %s (score and findings cover this profile only)\n", v.Profile)
	}
	if len(v.Findings) > 0 {
		fmt.Fprintln(w)
		t := table(w)
		for _, f := range v.Findings {
			fmt.Fprintf(t, "%s\t%s\t%s\t%s\t%s\n", statusIcon[f.Status], f.Severity, f.ID, f.Title, f.Evidence)
		}
		t.Flush()
	}
	if len(v.TopVulns) > 0 {
		fmt.Fprintln(w, "\nTop vulnerabilities:")
		renderVulns(w, v.TopVulns)
		if more := s.Vulns - len(v.TopVulns); more > 0 {
			fmt.Fprintf(w, "  … %d more: syssec vulns\n", more)
		}
	}
	if v.Diff != nil {
		fmt.Fprintln(w)
		renderDiff(w, v.Diff)
	}
	if len(v.Errors) > 0 {
		fmt.Fprintln(w, "\nErrors:")
		for _, e := range v.Errors {
			fmt.Fprintln(w, "  "+e)
		}
	}
	if len(v.NextSteps) > 0 {
		fmt.Fprintln(w, "\nNext:")
		for _, n := range v.NextSteps {
			fmt.Fprintln(w, "  "+n)
		}
	}
}

func renderVulns(w io.Writer, vs []core.Vuln) {
	t := table(w)
	for _, v := range vs {
		fix := v.FixedIn
		if fix == "" {
			fix = "-"
		}
		epss := ""
		if v.EPSS > 0 {
			epss = fmt.Sprintf("epss %.0f%%", v.EPSS*100)
		}
		if v.Running() {
			epss += " RUN"
		}
		fmt.Fprintf(t, "  %s\t%s\t%s\t%s\t%s %s\tfix: %s\t%s\n", v.Priority, v.Severity, epss, v.ID, v.Package, v.Version, fix, v.Summary)
	}
	t.Flush()
}

func renderDiff(w io.Writer, d *diffView) {
	fmt.Fprintf(w, "Since scan #%d (%s): score %d → %d (%+d)\n", d.From.ID, d.From.StartedAt.Format("2006-01-02 15:04"), d.From.Score, d.To.Score, d.ScoreDelta)
	section := func(title string, cs []diff.CheckChange) {
		if len(cs) == 0 {
			return
		}
		fmt.Fprintf(w, "%s:\n", title)
		for _, c := range cs {
			from := string(c.From)
			if from == "" {
				from = "new"
			}
			fmt.Fprintf(w, "  [%s] %s %s (%s → %s)\n", c.Severity, c.ID, c.Title, from, c.To)
		}
	}
	for _, n := range d.Notes {
		fmt.Fprintln(w, "note: "+n)
	}
	section("Regressed", d.Regressed)
	section("Resolved", d.Resolved)
	section("Changed", d.Changed)
	if len(d.Drifted) > 0 {
		fmt.Fprintln(w, "Evidence changed (still failing):")
		for _, c := range d.Drifted {
			fmt.Fprintf(w, "  [%s] %s %s\n    was: %s\n    now: %s\n", c.Severity, c.ID, c.Title, c.Previous, c.Evidence)
		}
	}
	if len(d.NewVulns) > 0 {
		fmt.Fprintf(w, "New vulns (%d):\n", d.Counts["new_vulns"])
		renderVulns(w, d.NewVulns)
	}
	if n := d.Counts["fixed_vulns"]; n > 0 {
		fmt.Fprintf(w, "Fixed vulns: %d\n", n)
	}
	if a, r, c := d.Counts["packages_added"], d.Counts["packages_removed"], d.Counts["packages_changed"]; a+r+c > 0 {
		fmt.Fprintf(w, "Packages: +%d -%d ~%d\n", a, r, c)
		for _, p := range d.PackagesChanged {
			fmt.Fprintf(w, "  ~ %s %s → %s\n", p.Name, p.From, p.To)
		}
		for _, p := range d.PackagesAdded {
			fmt.Fprintf(w, "  + %s %s\n", p.Name, p.Version)
		}
		for _, p := range d.PackagesRemoved {
			fmt.Fprintf(w, "  - %s %s\n", p.Name, p.Version)
		}
	}
	if len(d.Regressed)+len(d.Resolved)+len(d.Changed)+len(d.Drifted)+d.Counts["new_vulns"]+d.Counts["fixed_vulns"] == 0 {
		fmt.Fprintln(w, "No security-relevant changes.")
	}
	if d.Truncated {
		fmt.Fprintln(w, "(lists truncated; use --full)")
	}
}

func indent(s string) string { return "  " + strings.ReplaceAll(s, "\n", "\n  ") }
