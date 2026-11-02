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

// 回歸：計分規則改過後，history 仍讀存檔當下的 scans.score，新舊公式混雜（舊 #3、#4 顯示 100）。
func TestScoreIsRecomputedOnRead(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "syssec.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r := &core.Report{StartedAt: time.Now(), Host: core.Host{Hostname: "h"},
		Results: []core.Result{
			{ID: "A", Title: "a", Severity: core.SeverityHigh, Status: core.StatusPass},
			{ID: "B", Title: "b", Severity: core.SeverityHigh, Status: core.StatusError},
		},
		Summary: core.Summary{Score: 100, Grade: "A", Vulns: 7}, // 模擬舊公式存下的快照
	}
	id, err := s.SaveReport(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.LoadReport(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Summary.Score != 50 || got.Summary.Grade != "F" || got.Summary.Status["error"] != 1 || got.Summary.Vulns != 7 {
		t.Errorf("LoadReport summary not rescored (or lost vuln counts): %+v", got.Summary)
	}
	scans, err := s.ListScans(ctx, 10)
	if err != nil || len(scans) != 1 {
		t.Fatalf("ListScans: %v, %v", scans, err)
	}
	if si := scans[0]; si.Score != 50 || si.Grade != "F" || si.Summary.Score != 50 || si.Summary.Vulns != 7 {
		t.Errorf("ListScans not rescored: %+v", si)
	}
}

// v6 migration：舊資料庫只有 evidence 後綴，升級時要回填 unverified 欄位。
func TestUnverifiedColumnAndBackfill(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "syssec.db")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	r := &core.Report{StartedAt: time.Now(), Results: []core.Result{
		{ID: "ACC-005", Severity: core.SeverityLow, Status: core.StatusError, Evidence: "sudoers not readable (run as root for full coverage)", Unverified: true},
		{ID: "SYS-099", Severity: core.SeverityLow, Status: core.StatusError, Evidence: "probe timed out"},
	}}
	id, err := s.SaveReport(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := s.LoadReport(ctx, id)
	flags := map[string]bool{}
	for _, x := range got.Results {
		flags[x.ID] = x.Unverified
	}
	if !flags["ACC-005"] || flags["SYS-099"] {
		t.Fatalf("round trip: %v", flags)
	}
	// 退回 v5 的樣子：拿掉欄位、把版本設回 5，重開後 migration 應依後綴回填。
	for _, q := range []string{`ALTER TABLE results DROP COLUMN unverified`, `PRAGMA user_version = 5`} {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()
	if s, err = Open(ctx, path); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, _ = s.LoadReport(ctx, id)
	for _, x := range got.Results {
		if x.Unverified != (x.ID == "ACC-005") {
			t.Errorf("backfill: %s unverified=%v", x.ID, x.Unverified)
		}
	}
}
