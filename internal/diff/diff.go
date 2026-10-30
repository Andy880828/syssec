// Package diff compares two scan reports to explain how a host's security
// posture changed: regressions, fixes, package drift and vuln churn.
package diff

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Andy880828/syssec/internal/core"
)

// Ref identifies one side of a comparison.
type Ref struct {
	ID        int64     `json:"scan_id"`
	StartedAt time.Time `json:"started_at"`
	Score     int       `json:"score"`
	Grade     string    `json:"grade"`
}

// CheckChange is a status transition of one check.
type CheckChange struct {
	ID       string        `json:"id"`
	Title    string        `json:"title"`
	Severity core.Severity `json:"severity"`
	From     core.Status   `json:"from"` // "" when the check did not run before
	To       core.Status   `json:"to"`
	Evidence string        `json:"evidence,omitempty"`
	Previous string        `json:"previous_evidence,omitempty"` // drifted only
}

// PackageChange is a version change of one package.
type PackageChange struct {
	Name    string `json:"name"`
	Manager string `json:"manager"`
	From    string `json:"from"`
	To      string `json:"to"`
}

// Diff is the delta between two reports.
type Diff struct {
	From       Ref           `json:"from"`
	To         Ref           `json:"to"`
	ScoreDelta int           `json:"score_delta"`
	Regressed  []CheckChange `json:"regressed"`         // became fail/warn
	Resolved   []CheckChange `json:"resolved"`          // became pass
	Changed    []CheckChange `json:"changed,omitempty"` // other transitions (e.g. -> skip/error)
	Drifted    []CheckChange `json:"drifted,omitempty"` // still failing, but what is observed changed
	Notes      []string      `json:"notes,omitempty"`   // caveats about comparability
	Packages   *PackageDelta `json:"packages,omitempty"`
	Vulns      *VulnDelta    `json:"vulns,omitempty"`
}

// PackageDelta summarises inventory drift.
type PackageDelta struct {
	Added    []core.Package  `json:"added"`
	Removed  []core.Package  `json:"removed"`
	Upgraded []PackageChange `json:"changed"`
}

// VulnDelta summarises vulnerability churn.
type VulnDelta struct {
	New   []core.Vuln `json:"new"`
	Fixed []core.Vuln `json:"fixed"`
}

// HasRegression reports whether anything got worse.
func (d *Diff) HasRegression() bool {
	return len(d.Regressed) > 0 || (d.Vulns != nil && len(d.Vulns.New) > 0)
}

// Empty reports whether nothing security-relevant changed.
func (d *Diff) Empty() bool {
	return len(d.Regressed) == 0 && len(d.Resolved) == 0 && len(d.Changed) == 0 && len(d.Drifted) == 0 &&
		(d.Vulns == nil || len(d.Vulns.New)+len(d.Vulns.Fixed) == 0) &&
		(d.Packages == nil || len(d.Packages.Added)+len(d.Packages.Removed)+len(d.Packages.Upgraded) == 0)
}

func ref(r *core.Report) Ref {
	return Ref{ID: r.ID, StartedAt: r.StartedAt, Score: r.Summary.Score, Grade: r.Summary.Grade}
}

// Compute diffs `from` (older) against `to` (newer). Checks absent from the
// newer report are ignored, so a partial scan never reports false fixes.
func Compute(from, to *core.Report) *Diff {
	d := &Diff{From: ref(from), To: ref(to), ScoreDelta: to.Summary.Score - from.Summary.Score,
		Regressed: []CheckChange{}, Resolved: []CheckChange{}}
	before := map[string]core.Result{}
	for _, r := range from.Results {
		before[r.ID] = r
	}
	for _, r := range to.Results {
		prev, existed := before[r.ID]
		if existed && prev.Status == r.Status {
			// Same problem status, different observation: a new exposed port,
			// another SUID file, one more NOPASSWD rule. Pass evidence (counts,
			// "none found") is volatile and deliberately ignored.
			if isProblem(r.Status) && prev.Evidence != r.Evidence {
				d.Drifted = append(d.Drifted, CheckChange{ID: r.ID, Title: r.Title, Severity: r.Severity,
					From: prev.Status, To: r.Status, Evidence: r.Evidence, Previous: prev.Evidence})
			}
			continue
		}
		c := CheckChange{ID: r.ID, Title: r.Title, Severity: r.Severity, From: prev.Status, To: r.Status, Evidence: r.Evidence}
		switch {
		case r.Status == core.StatusFail || r.Status == core.StatusWarn:
			if existed && prev.Status == core.StatusFail && r.Status == core.StatusWarn {
				d.Resolved = append(d.Resolved, c) // partial improvement
			} else {
				d.Regressed = append(d.Regressed, c)
			}
		case r.Status == core.StatusPass && existed:
			d.Resolved = append(d.Resolved, c)
		case existed:
			d.Changed = append(d.Changed, c)
		}
	}
	for _, list := range [][]CheckChange{d.Regressed, d.Resolved, d.Changed, d.Drifted} {
		slices.SortFunc(list, func(a, b CheckChange) int {
			if a.Severity != b.Severity {
				return int(b.Severity - a.Severity)
			}
			return strings.Compare(a.ID, b.ID)
		})
	}
	if !slices.Equal(from.Paths, to.Paths) {
		d.Notes = append(d.Notes, fmt.Sprintf("scanned paths differ (%v vs %v): language package and vuln changes partly reflect that", from.Paths, to.Paths))
	}
	if from.InventoryScanned && to.InventoryScanned {
		d.Packages = packages(from.Packages, to.Packages)
	}
	if from.VulnScanned && to.VulnScanned {
		d.Vulns = vulns(from.Vulns, to.Vulns)
	}
	return d
}

func isProblem(s core.Status) bool { return s == core.StatusFail || s == core.StatusWarn }

func packages(a, b []core.Package) *PackageDelta {
	pd := &PackageDelta{Added: []core.Package{}, Removed: []core.Package{}, Upgraded: []PackageChange{}}
	old := map[string]core.Package{}
	for _, p := range a {
		old[p.Key()] = p
	}
	for _, p := range b {
		prev, ok := old[p.Key()]
		switch {
		case !ok:
			pd.Added = append(pd.Added, p)
		case prev.Version != p.Version:
			pd.Upgraded = append(pd.Upgraded, PackageChange{Name: p.Name, Manager: p.Manager, From: prev.Version, To: p.Version})
		}
		delete(old, p.Key())
	}
	for _, p := range a {
		if _, gone := old[p.Key()]; gone {
			pd.Removed = append(pd.Removed, p)
		}
	}
	return pd
}

// vulns matches findings by package plus any shared ID or alias, so a
// finding that is re-keyed upstream (USN-x → CVE-y, a new GHSA alias) is
// not reported as one fix plus one new vuln.
func vulns(a, b []core.Vuln) *VulnDelta {
	vd := &VulnDelta{New: []core.Vuln{}, Fixed: []core.Vuln{}}
	index := func(vs []core.Vuln) map[string]bool {
		m := map[string]bool{}
		for _, v := range vs {
			for _, id := range append([]string{v.ID}, v.Aliases...) {
				m[v.Package+"|"+id] = true
			}
		}
		return m
	}
	known := func(m map[string]bool, v core.Vuln) bool {
		for _, id := range append([]string{v.ID}, v.Aliases...) {
			if m[v.Package+"|"+id] {
				return true
			}
		}
		return false
	}
	old, cur := index(a), index(b)
	for _, v := range b {
		if !known(old, v) {
			vd.New = append(vd.New, v)
		}
	}
	for _, v := range a {
		if !known(cur, v) {
			vd.Fixed = append(vd.Fixed, v)
		}
	}
	return vd
}
