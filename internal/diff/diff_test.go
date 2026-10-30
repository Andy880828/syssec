package diff

import (
	"testing"

	"github.com/Andy880828/syssec/internal/core"
)

func TestCompute(t *testing.T) {
	a := &core.Report{ID: 1, InventoryScanned: true, VulnScanned: true,
		Results: []core.Result{
			{ID: "A", Status: core.StatusPass, Severity: core.SeverityHigh},
			{ID: "B", Status: core.StatusFail, Severity: core.SeverityMedium},
			{ID: "C", Status: core.StatusFail},
			{ID: "GONE", Status: core.StatusFail},
		},
		Packages: []core.Package{{Name: "openssl", Version: "1", Manager: "dpkg"}, {Name: "telnetd", Version: "1", Manager: "dpkg"}},
		Vulns:    []core.Vuln{{ID: "CVE-OLD", Package: "openssl"}},
		Summary:  core.Summary{Score: 70},
	}
	b := &core.Report{ID: 2, InventoryScanned: true, VulnScanned: true,
		Results: []core.Result{
			{ID: "A", Status: core.StatusFail, Severity: core.SeverityHigh},
			{ID: "B", Status: core.StatusPass, Severity: core.SeverityMedium},
			{ID: "C", Status: core.StatusSkip},
			{ID: "NEW", Status: core.StatusWarn},
		},
		Packages: []core.Package{{Name: "openssl", Version: "2", Manager: "dpkg"}, {Name: "nginx", Version: "1", Manager: "dpkg"}},
		Vulns:    []core.Vuln{{ID: "CVE-NEW", Package: "nginx"}},
		Summary:  core.Summary{Score: 65},
	}
	d := Compute(a, b)
	if d.ScoreDelta != -5 || !d.HasRegression() {
		t.Errorf("score/regression: %+v", d)
	}
	if len(d.Regressed) != 2 || d.Regressed[0].ID != "A" {
		t.Errorf("regressed: %+v", d.Regressed)
	}
	if len(d.Resolved) != 1 || d.Resolved[0].ID != "B" {
		t.Errorf("resolved: %+v (GONE must not count as resolved)", d.Resolved)
	}
	if len(d.Changed) != 1 || d.Changed[0].To != core.StatusSkip {
		t.Errorf("changed: %+v", d.Changed)
	}
	p := d.Packages
	if len(p.Added) != 1 || len(p.Removed) != 1 || len(p.Upgraded) != 1 || p.Upgraded[0].To != "2" {
		t.Errorf("packages: %+v", p)
	}
	if len(d.Vulns.New) != 1 || len(d.Vulns.Fixed) != 1 {
		t.Errorf("vulns: %+v", d.Vulns)
	}
	renamed := Compute(&core.Report{VulnScanned: true, Vulns: []core.Vuln{{ID: "USN-1", Package: "p", Aliases: []string{"CVE-9"}}}},
		&core.Report{VulnScanned: true, Vulns: []core.Vuln{{ID: "CVE-9", Package: "p", Aliases: []string{"USN-1"}}}})
	if len(renamed.Vulns.New)+len(renamed.Vulns.Fixed) != 0 {
		t.Errorf("re-keyed advisory must not count as churn: %+v", renamed.Vulns)
	}
	b.VulnScanned = false
	if Compute(a, b).Vulns != nil {
		t.Error("vuln diff requires both scans to have vuln data")
	}
}
