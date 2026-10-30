package inventory

import (
	"testing"

	"github.com/Andy880828/syssec/internal/sysenv"
)

func TestParseDpkgStatus(t *testing.T) {
	status := `Package: libssl3t64
Status: install ok installed
Architecture: amd64
Source: openssl (3.0.13-0ubuntu3.4)
Version: 3.0.13-0ubuntu3.4
Description: Secure Sockets Layer toolkit
 continuation line: not a field

Package: removed-pkg
Status: deinstall ok config-files
Version: 1.0

Package: bash
Status: install ok installed
Architecture: amd64
Version: 5.2.21-2ubuntu4
`
	pkgs := ParseDpkgStatus([]byte(status), "Ubuntu:24.04:LTS")
	if len(pkgs) != 2 {
		t.Fatalf("want 2 installed packages, got %+v", pkgs)
	}
	ssl := pkgs[0]
	if n, v := ssl.Query(); n != "openssl" || v != "3.0.13-0ubuntu3.4" {
		t.Errorf("source mapping wrong: %s %s", n, v)
	}
	if n, _ := pkgs[1].Query(); n != "bash" {
		t.Errorf("binary name fallback wrong: %s", n)
	}
}

func TestParseAPK(t *testing.T) {
	db := "P:musl\nV:1.2.4-r2\nA:x86_64\no:musl\n\nP:busybox\nV:1.36.1-r5\no:busybox\n"
	pkgs := ParseAPKInstalled([]byte(db), "Alpine:v3.19")
	if len(pkgs) != 2 || pkgs[1].Version != "1.36.1-r5" || pkgs[0].Ecosystem != "Alpine:v3.19" {
		t.Errorf("unexpected: %+v", pkgs)
	}
}

func TestEcosystem(t *testing.T) {
	cases := map[string]map[string]string{
		"Debian:12":        {"ID": "debian", "VERSION_ID": "12"},
		"Ubuntu:24.04:LTS": {"ID": "ubuntu", "VERSION_ID": "24.04", "VERSION": "24.04.1 LTS (Noble Numbat)"},
		"Ubuntu:24.10":     {"ID": "ubuntu", "VERSION_ID": "24.10", "VERSION": "24.10 (Oracular Oriole)"},
		"Alpine:v3.19":     {"ID": "alpine", "VERSION_ID": "3.19.1"},
		"Rocky Linux:9":    {"ID": "rocky", "VERSION_ID": "9.3"},
		"":                 {"ID": "arch"},
	}
	for want, osr := range cases {
		if got := Ecosystem(&sysenv.Env{OSRelease: osr}); got != want {
			t.Errorf("%v: got %q want %q", osr, got, want)
		}
	}
}
