package checks

import (
	"context"
	"io/fs"
	"testing"
	"testing/fstest"
	"time"

	"github.com/Andy880828/syssec/internal/core"
	"github.com/Andy880828/syssec/internal/sysenv"
)

func memEnv(files map[string]string) *sysenv.Env {
	m := sysenv.MemFS{}
	for k, v := range files {
		m[k] = &fstest.MapFile{Data: []byte(v), Mode: 0o644}
	}
	return &sysenv.Env{GOOS: "linux", FS: m, Exec: sysenv.FakeRunner{}, Reg: sysenv.FakeRegistry{}}
}

func TestExpect(t *testing.T) {
	cases := []struct {
		e      Expect
		in     string
		expect bool
	}{
		{Eq("no"), "No", true},
		{Eq("0"), "1", false},
		{In("1", "2"), "2", true},
		{NotIn("0"), "5", true},
		{NotIn("0"), "0", false},
		{GE(1), "2", true},
		{GE(1), "0", false},
		{LE(4), "6", false},
		{LE(60), "30s", false}, // "30s" is non-numeric -> never satisfies
		{LE(60), "30", true},
		{Matches(`^ab`), "abc", true},
	}
	for _, c := range cases {
		got, err := c.e.Match(c.in)
		if err != nil || got != c.expect {
			t.Errorf("%v.Match(%q) = %v, %v; want %v", c.e, c.in, got, err, c.expect)
		}
	}
	if err := (Expect{Op: "bogus", Values: []string{"x"}}).Validate(); err == nil {
		t.Error("expected validation error for unknown op")
	}
}

func TestSSHDFirstMatchAndInclude(t *testing.T) {
	env := memEnv(map[string]string{
		"etc/ssh/sshd_config":                     "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\nPasswordAuthentication yes\nMatch User bob\n  PasswordAuthentication no\n",
		"etc/ssh/sshd_config.d/10-hardening.conf": "PermitRootLogin no\n",
	})
	cfg, err := LoadSSHD(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := cfg.Get("PermitRootLogin"); v != "no" {
		t.Errorf("drop-in should win (first match), got %q", v)
	}
	if v, _ := cfg.Get("passwordauthentication"); v != "yes" {
		t.Errorf("Match block must not leak into global config, got %q", v)
	}
	if v, def := cfg.Get("X11Forwarding"); v != "no" || !def {
		t.Errorf("expected default X11Forwarding=no, got %q default=%v", v, def)
	}
}

func TestSysctlPrimitive(t *testing.T) {
	env := memEnv(map[string]string{"proc/sys/kernel/randomize_va_space": "1\n"})
	c := Sysctl(core.CheckMeta{ID: "T-1", Title: "aslr"}, "kernel.randomize_va_space", Eq("2"))
	if o := c.Run(context.Background(), env); o.Status != core.StatusFail {
		t.Errorf("want fail, got %+v", o)
	}
	missing := Sysctl(core.CheckMeta{ID: "T-2", Title: "x"}, "kernel.nope", Eq("1"))
	if o := missing.Run(context.Background(), env); o.Status != core.StatusSkip {
		t.Errorf("want skip, got %+v", o)
	}
}

func TestFileModePrimitive(t *testing.T) {
	m := sysenv.MemFS{"etc/shadow": &fstest.MapFile{Data: []byte("x"), Mode: fs.FileMode(0o644)}}
	env := &sysenv.Env{FS: m}
	c := FileMode(core.CheckMeta{ID: "T", Title: "t"}, "/etc/shadow", 0o640)
	if o := c.Run(context.Background(), env); o.Status != core.StatusFail {
		t.Errorf("0644 > 0640 should fail, got %+v", o)
	}
}

func TestEngineIsolatesPanicsAndTimeouts(t *testing.T) {
	panicky := New(core.CheckMeta{ID: "P", Title: "p", Severity: core.SeverityHigh}, func(context.Context, *sysenv.Env) Outcome { panic("boom") })
	slow := New(core.CheckMeta{ID: "S", Title: "s"}, func(ctx context.Context, _ *sysenv.Env) Outcome {
		<-ctx.Done()
		time.Sleep(10 * time.Millisecond)
		return Pass("late")
	})
	ok := New(core.CheckMeta{ID: "F", Title: "f", Severity: core.SeverityCritical, Remediation: "fix it"}, func(context.Context, *sysenv.Env) Outcome { return Fail("bad") })
	res := Engine{Timeout: 50 * time.Millisecond}.Run(context.Background(), memEnv(nil), []Check{panicky, slow, ok})
	got := map[string]core.Result{}
	for _, r := range res {
		got[r.ID] = r
	}
	if got["P"].Status != core.StatusError || got["S"].Status != core.StatusError {
		t.Errorf("panic/timeout should be errors: %+v", res)
	}
	if res[0].ID != "F" || res[0].Remediation != "fix it" {
		t.Errorf("critical failure should sort first with remediation: %+v", res[0])
	}
}

func TestRegistryAndFilter(t *testing.T) {
	r := NewRegistry()
	mk := func(id, cat string, sev core.Severity, plats ...string) Check {
		return New(core.CheckMeta{ID: id, Title: id, Category: cat, Severity: sev, Platforms: plats}, nil)
	}
	r.MustRegister(mk("A-1", "ssh", core.SeverityHigh, "linux"), mk("B-1", "kernel", core.SeverityLow, "windows"))
	if err := r.Register(mk("a-1", "x", 0)); err == nil {
		t.Error("duplicate (case-insensitive) id should fail")
	}
	if n := len(r.Select(Filter{Platform: "linux"})); n != 1 {
		t.Errorf("platform filter: got %d", n)
	}
	if n := len(r.Select(Filter{MinSeverity: core.SeverityMedium})); n != 1 {
		t.Errorf("severity filter: got %d", n)
	}
	if _, ok := r.Get("b-1"); !ok {
		t.Error("Get should be case-insensitive")
	}
}

func TestRuleSpecBuild(t *testing.T) {
	yes := true
	specs := []RuleSpec{
		{CheckMeta: core.CheckMeta{ID: "C-1", Title: "t"}, Type: "sysctl", Key: "kernel.x", Expect: &Expect{Op: "eq", Values: []string{"1"}}},
		{CheckMeta: core.CheckMeta{ID: "C-2", Title: "t"}, Type: "file_mode", Path: "/etc/x", Mode: "0600"},
		{CheckMeta: core.CheckMeta{ID: "C-3", Title: "t"}, Type: "file_regex", Path: "/etc/x", Pattern: "^a", Present: &yes},
		{CheckMeta: core.CheckMeta{ID: "C-4", Title: "t"}, Type: "registry", Path: `HKLM\X`, Name: "Y", Expect: &Expect{Op: "eq", Values: []string{"1"}}},
		{CheckMeta: core.CheckMeta{ID: "C-5", Title: "t"}, Type: "command", Command: []string{"true"}, Pattern: "x"},
	}
	for _, s := range specs {
		c, err := s.Build()
		if err != nil {
			t.Fatalf("%s: %v", s.ID, err)
		}
		if c.Meta().Category != "custom" {
			t.Errorf("%s: defaults not applied: %+v", s.ID, c.Meta())
		}
	}
	bad := []RuleSpec{
		{CheckMeta: core.CheckMeta{ID: "X", Title: "t"}, Type: "sysctl", Key: "k"},
		{CheckMeta: core.CheckMeta{ID: "X", Title: "t"}, Type: "file_regex", Path: "/x", Pattern: "("},
		{CheckMeta: core.CheckMeta{ID: "X", Title: "t"}, Type: "nope"},
	}
	for _, s := range bad {
		if _, err := s.Build(); err == nil {
			t.Errorf("expected error for %+v", s)
		}
	}
}

func TestParseRulePackDefaults(t *testing.T) {
	cs, errs := ParseRulePack([]byte(`{"rules":[
		{"id":"ORG-1","title":"kexec off","type":"sysctl","key":"kernel.kexec_load_disabled","expect":{"op":"eq","values":["1"]}},
		{"id":"ORG-2","title":"bad","severity":"high","type":"sysctl"}]}`))
	if len(cs) != 1 || len(errs) != 1 {
		t.Fatalf("got %d checks, errs %v", len(cs), errs)
	}
	if m := cs[0].Meta(); m.Severity != core.SeverityMedium || m.Platforms[0] != "linux" {
		t.Errorf("defaults: %+v", m)
	}
}

func TestHostOnlyChecksSkipInContainers(t *testing.T) {
	c := New(core.CheckMeta{ID: "H", Title: "h", Tags: []string{core.TagHostOnly}}, func(context.Context, *sysenv.Env) Outcome { return Fail("x") })
	env := memEnv(nil)
	env.Host.Container = "docker"
	if r := (Engine{}).Run(context.Background(), env, []Check{c}); r[0].Status != core.StatusSkip {
		t.Errorf("host-only check should skip in a container: %+v", r[0])
	}
}
