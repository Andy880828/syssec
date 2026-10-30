package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
)

func run(t *testing.T, args ...string) (int, map[string]any) {
	t.Helper()
	t.Setenv("SYSSEC_HOME", t.TempDir())
	var out, errb bytes.Buffer
	code := Run(context.Background(), args, &out, &errb)
	var env map[string]any
	if err := json.Unmarshal(out.Bytes(), &env); err != nil {
		t.Fatalf("not JSON (%v): %s / %s", err, out.String(), errb.String())
	}
	return code, env
}

func TestDescribeManifest(t *testing.T) {
	code, env := run(t, "--json", "describe")
	if code != 0 || env["ok"] != true || env["schema"] != "syssec/v1" {
		t.Fatalf("bad envelope: %v", env)
	}
	cmds := env["data"].(map[string]any)["commands"].([]any)
	if len(cmds) < 10 {
		t.Errorf("manifest too small: %d", len(cmds))
	}
}

func TestUsageErrorEnvelope(t *testing.T) {
	code, env := run(t, "scan", "--json", "--fail-on", "extreme")
	if code != ExitUsage || env["ok"] != false {
		t.Fatalf("want usage error, got %d %v", code, env)
	}
	if env["error"].(map[string]any)["code"] != "usage" {
		t.Errorf("error code: %v", env["error"])
	}
}

func TestNoDataIsStructured(t *testing.T) {
	db := filepath.Join(t.TempDir(), "t.db")
	code, env := run(t, "report", "--json", "--db", db)
	if code != ExitError || env["error"].(map[string]any)["code"] != "no_data" {
		t.Errorf("want no_data error, got %d %v", code, env)
	}
	if _, env := run(t, "status", "--json", "--db", db); env["ok"] != true {
		t.Errorf("status must work without history: %v", env)
	}
}

func TestHelpJSON(t *testing.T) {
	code, env := run(t, "help", "vulns", "--json")
	if code != 0 || env["data"].(map[string]any)["command"] != "syssec vulns" {
		t.Errorf("help --json: %d %v", code, env)
	}
}

func TestWaiverFlow(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SYSSEC_HOME", home)
	var out, errb bytes.Buffer
	if code := Run(context.Background(), []string{"waive", "add", "SSH-001", "--reason", "test", "--expires", "30d", "--json"}, &out, &errb); code != 0 {
		t.Fatalf("waive add: %s %s", out.String(), errb.String())
	}
	out.Reset()
	Run(context.Background(), []string{"waive", "list", "--json"}, &out, &errb)
	if !bytes.Contains(out.Bytes(), []byte(`"SSH-001"`)) {
		t.Errorf("waive list: %s", out.String())
	}
	if code, _ := run(t, "waive", "add", "X", "--json"); code != ExitUsage {
		t.Error("missing --reason must be a usage error")
	}
}

func TestScanSaveDiffHistory(t *testing.T) {
	db := filepath.Join(t.TempDir(), "t.db")
	for range 2 {
		if code, env := run(t, "scan", "--json", "--db", db); code != 0 || env["ok"] != true {
			t.Fatalf("scan failed: %v", env)
		}
	}
	code, env := run(t, "history", "--json", "--db", db)
	if code != 0 {
		t.Fatal(env)
	}
	if scans := env["data"].(map[string]any)["scans"].([]any); len(scans) != 2 {
		t.Errorf("want 2 scans, got %d", len(scans))
	}
	if code, env := run(t, "diff", "--db", db, "--json"); code != 0 || env["data"].(map[string]any)["from"] == nil {
		t.Errorf("diff: %d %v", code, env)
	}
	if code, env := run(t, "explain", "SSH-001", "--json", "--db", db); code != 0 || env["data"].(map[string]any)["kind"] != "check" {
		t.Errorf("explain: %d %v", code, env)
	}
}

func TestSplitGlobals(t *testing.T) {
	g, rest := splitGlobals([]string{"--json", "--db", "x.db", "scan", "--all"})
	if len(g) != 3 || rest[0] != "scan" {
		t.Errorf("globals=%v rest=%v", g, rest)
	}
}
