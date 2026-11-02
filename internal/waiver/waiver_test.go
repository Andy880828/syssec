package waiver

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/Andy880828/syssec/internal/core"
)

func TestApply(t *testing.T) {
	now := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	f := &File{Waivers: []core.Waiver{
		{ID: "net-101", Reason: "docker host"},
		{ID: "CVE-1", Package: "openssl", Reason: "not reachable", Expires: "2026-10-30"},
		{ID: "SSH-002", Reason: "old", Expires: "2026-10-29"},
	}}
	rs := []core.Result{{ID: "NET-101", Status: core.StatusFail, Remediation: "x"}, {ID: "SSH-002", Status: core.StatusFail}}
	vs := []core.Vuln{{ID: "DSA-1", Aliases: []string{"CVE-1"}, Package: "openssl"}, {ID: "CVE-1", Package: "curl"}}
	expired := f.Apply(rs, vs, now)
	if rs[0].Status != core.StatusWaived || rs[0].Waiver.Reason != "docker host" || rs[0].Remediation != "" {
		t.Errorf("check waiver: %+v", rs[0])
	}
	if rs[1].Status != core.StatusFail || len(expired) != 1 {
		t.Errorf("expired waiver must not apply: %+v %v", rs[1], expired)
	}
	if vs[0].Waiver == nil || vs[1].Waiver != nil {
		t.Errorf("package-scoped vuln waiver: %+v", vs)
	}
}

func TestFileRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "w.json")
	f, _ := Load(p)
	f.Put(core.Waiver{ID: "A", Reason: "r"})
	f.Put(core.Waiver{ID: "A", Reason: "r2"})
	if err := f.Save(p); err != nil {
		t.Fatal(err)
	}
	g, _ := Load(p)
	if len(g.Waivers) != 1 || g.Waivers[0].Reason != "r2" || g.Remove("a", "") != 1 {
		t.Errorf("round trip: %+v", g)
	}
	if d, _ := ParseExpiry("30d", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)); d != "2026-01-31" {
		t.Errorf("relative expiry: %s", d)
	}
}

// 同一份彙總公告拆出的兩列只共用公告 ID；豁免 CVE-A 不能連帶豁免 CVE-B。
func TestWaiverDoesNotSpreadAcrossRollupSiblings(t *testing.T) {
	f := &File{Waivers: []core.Waiver{{ID: "CVE-2099-1000", Reason: "not reachable"}}}
	vs := []core.Vuln{
		{ID: "CVE-2099-1000", Package: "linux-hwe-6.17", Aliases: []string{"USN-9"}},
		{ID: "CVE-2099-2000", Package: "linux-hwe-6.17", Aliases: []string{"USN-9"}, KEV: true},
	}
	f.Apply(nil, vs, time.Now())
	if vs[0].Waiver == nil || vs[1].Waiver != nil {
		t.Errorf("waiver leaked to the sibling CVE: %+v", vs)
	}
}
