package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Andy880828/syssec/internal/core"
)

func TestRoundTrip(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "x", "syssec.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.LatestID(ctx, false); err != ErrNoScans {
		t.Errorf("empty db: %v", err)
	}
	mk := func(status core.Status, partial bool) *core.Report {
		r := &core.Report{
			StartedAt: time.Now(), Host: core.Host{Hostname: "h", OS: "linux"}, Partial: partial,
			InventoryScanned: true, VulnScanned: true,
			Results:  []core.Result{{ID: "SSH-001", Title: "t", Category: "ssh", Severity: core.SeverityHigh, Status: status, Evidence: "e"}},
			Packages: []core.Package{{Name: "bash", Version: "5", Manager: "dpkg", SourceName: "bash"}},
			Vulns:    []core.Vuln{{ID: "CVE-1", Package: "bash", Severity: core.SeverityCritical, KEV: true, Aliases: []string{"CVE-1", "DSA-1"}}},
		}
		r.Summary = core.Summarize(r.Results, 1, r.Vulns)
		return r
	}
	id1, _ := s.SaveReport(ctx, mk(core.StatusFail, false))
	id2, _ := s.SaveReport(ctx, mk(core.StatusPass, false))
	id3, _ := s.SaveReport(ctx, mk(core.StatusPass, true))

	if latest, _ := s.LatestID(ctx, true); latest != id2 {
		t.Errorf("latest complete = %d, want %d", latest, id2)
	}
	if prev, _ := s.PreviousID(ctx, id3); prev != id2 {
		t.Errorf("previous of partial = %d, want %d", prev, id2)
	}
	r, err := s.LoadReport(ctx, id1)
	if err != nil {
		t.Fatal(err)
	}
	if r.Results[0].Severity != core.SeverityHigh || !r.Vulns[0].KEV || len(r.Vulns[0].Aliases) != 2 || r.Packages[0].SourceName != "bash" || r.Summary.Score != 0 {
		t.Errorf("round trip lost data: %+v", r)
	}
	pts, _ := s.CheckHistory(ctx, "ssh-001", 10)
	if len(pts) != 3 || pts[2].Status != core.StatusFail {
		t.Errorf("history: %+v", pts)
	}
	if n, _ := s.Prune(ctx, 1, true); n != 2 {
		t.Errorf("dry-run prune would delete %d", n)
	}
	if n, _ := s.Prune(ctx, 1, false); n != 2 {
		t.Errorf("prune deleted %d", n)
	}
	if err := s.PutVuln(ctx, "X", "m", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if _, mod, ok, _ := s.GetVuln(ctx, "X"); !ok || mod != "m" {
		t.Error("vuln cache miss")
	}
}

func TestVulnIDsResolvesAlias(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "syssec.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r := &core.Report{StartedAt: time.Now(), Host: core.Host{Hostname: "h"}, VulnScanned: true,
		Vulns: []core.Vuln{{ID: "CVE-2026-111943", Package: "stdlib", Aliases: []string{"GO-2026-6809", "BIT-golang-2026-111943"}}}}
	if _, err := s.SaveReport(ctx, r); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"CVE-2026-111943", "GO-2026-6809"} {
		ids, err := s.VulnIDs(ctx, q)
		if err != nil || len(ids) != 3 || ids[0] != "CVE-2026-111943" || ids[1] != "GO-2026-6809" {
			t.Errorf("VulnIDs(%s) = %v, %v", q, ids, err)
		}
	}
	// 別名比對要整段相等，"GO-2026-680" 不能誤中 "GO-2026-6809"
	if ids, err := s.VulnIDs(ctx, "GO-2026-680"); err != nil || ids != nil {
		t.Errorf("partial ID matched: %v, %v", ids, err)
	}
}
