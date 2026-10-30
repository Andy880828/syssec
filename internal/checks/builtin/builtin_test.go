package builtin

import (
	"context"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/Andy880828/syssec/internal/checks"
	"github.com/Andy880828/syssec/internal/core"
	"github.com/Andy880828/syssec/internal/sysenv"
)

func TestCatalogIsValid(t *testing.T) {
	r := checks.NewRegistry()
	Register(r) // panics on duplicate IDs
	for _, c := range r.Select(checks.Filter{}) {
		m := c.Meta()
		if m.Category == "" || len(m.Platforms) == 0 || m.Severity == core.SeverityUnknown {
			t.Errorf("%s: incomplete metadata %+v", m.ID, m)
		}
		if m.Severity >= core.SeverityMedium && m.Remediation == "" {
			t.Errorf("%s: medium+ checks need remediation", m.ID)
		}
	}
	for _, p := range []string{"linux", "darwin", "windows"} {
		if len(r.Select(checks.Filter{Platform: p})) < 10 {
			t.Errorf("%s has too few checks", p)
		}
	}
}

func TestParseProcNet(t *testing.T) {
	tcp := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:18EB 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 1111 1
   1: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2222 1
   2: 0100007F:0CEA 0100007F:D431 01 00000000:00000000 00:00000000 00000000     0        0 3333 1
`
	ls := parseProcNet([]byte(tcp), "tcp")
	if len(ls) != 2 {
		t.Fatalf("want 2 listeners, got %+v", ls)
	}
	if ls[0].Port != 6379 || !ls[0].Exposed() {
		t.Errorf("redis on 0.0.0.0 not decoded: %+v", ls[0])
	}
	if ls[1].Addr != "127.0.0.1" || ls[1].Exposed() {
		t.Errorf("loopback misdecoded: %+v", ls[1])
	}
	tcp6 := "hdr\n   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 0 0 0 0 0 4444 1\n"
	if l := parseProcNet([]byte(tcp6), "tcp6"); len(l) != 1 || l[0].Addr != "::" || l[0].Proto != "tcp" {
		t.Errorf("ipv6 any misdecoded: %+v", l)
	}
}

func run(t *testing.T, env *sysenv.Env, id string) checks.Outcome {
	t.Helper()
	r := checks.NewRegistry()
	Register(r)
	c, ok := r.Get(id)
	if !ok {
		t.Fatalf("no check %s", id)
	}
	return c.Run(context.Background(), env)
}

func TestRiskyServiceExposure(t *testing.T) {
	fs := sysenv.MemFS{"proc/net/tcp": &fstest.MapFile{Data: []byte("h\n 0: 00000000:18EB 00000000:0000 0A 0 0 0 0 0 1 1\n")}}
	o := run(t, &sysenv.Env{GOOS: "linux", FS: fs}, "NET-001")
	if o.Status != core.StatusFail || !strings.Contains(o.Evidence, "redis") {
		t.Errorf("want redis exposure failure, got %+v", o)
	}
}

func TestAccounts(t *testing.T) {
	fs := sysenv.MemFS{
		"etc/passwd": &fstest.MapFile{Data: []byte("root:x:0:0::/root:/bin/bash\ntoor:x:0:0::/root:/bin/sh\ndaemon:x:1:1::/:/usr/sbin/nologin\n")},
		"etc/shadow": &fstest.MapFile{Data: []byte("root:$6$abc:1::::::\ntoor::1::::::\n")},
	}
	env := &sysenv.Env{GOOS: "linux", FS: fs}
	if o := run(t, env, "ACC-001"); o.Status != core.StatusFail || !strings.Contains(o.Evidence, "toor") {
		t.Errorf("ACC-001: %+v", o)
	}
	if o := run(t, env, "ACC-002"); o.Status != core.StatusFail {
		t.Errorf("ACC-002: %+v", o)
	}
	if o := run(t, env, "ACC-003"); o.Status != core.StatusFail {
		t.Errorf("ACC-003 (duplicate uid 0): %+v", o)
	}
}

func TestWindowsRegistryRules(t *testing.T) {
	reg := sysenv.FakeRegistry{
		regPolicySystem + `\EnableLUA`:                    0,
		regFirewall + `PublicProfile\EnableFirewall`:      1,
		regTS + `\fDenyTSConnections`:                     0,
		regTS + `\WinStations\RDP-Tcp\UserAuthentication`: 0,
	}
	env := &sysenv.Env{GOOS: "windows", Reg: reg}
	for id, want := range map[string]core.Status{
		"WIN-001": core.StatusFail, "WIN-005": core.StatusPass, "WIN-003": core.StatusFail,
		"WIN-008": core.StatusPass, "WIN-016": core.StatusFail, "WIN-015": core.StatusPass,
	} {
		if o := run(t, env, id); o.Status != want {
			t.Errorf("%s: want %s got %+v", id, want, o)
		}
	}
}

func TestDarwinCommandRules(t *testing.T) {
	env := &sysenv.Env{GOOS: "darwin", Exec: sysenv.FakeRunner{
		"fdesetup status": "FileVault is Off.",
		"spctl --status":  "assessments enabled",
		"csrutil status":  "System Integrity Protection status: enabled.",
		"defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled": "1",
	}}
	for id, want := range map[string]core.Status{
		"MAC-001": core.StatusFail, "MAC-002": core.StatusPass, "MAC-003": core.StatusPass,
		"MAC-008": core.StatusFail, "MAC-004": core.StatusSkip,
	} {
		if o := run(t, env, id); o.Status != want {
			t.Errorf("%s: want %s got %+v", id, want, o)
		}
	}
}
