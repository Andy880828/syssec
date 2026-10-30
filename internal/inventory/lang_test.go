package inventory

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"testing/fstest"

	"github.com/Andy880828/syssec/internal/core"
	"github.com/Andy880828/syssec/internal/sysenv"
)

func find(ps []core.Package, name string) *core.Package {
	for i := range ps {
		if ps[i].Name == name {
			return &ps[i]
		}
	}
	return nil
}

func TestLockfileParsers(t *testing.T) {
	cases := []struct {
		file, content, name, version string
		count                        int
	}{
		{"go.mod", "module x\n\ngo 1.24\n\nrequire golang.org/x/net v0.20.0\nrequire (\n\tgithub.com/a/b v1.2.3 // indirect\n)\n", "github.com/a/b", "1.2.3", 2},
		{"package-lock.json", `{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/lodash":{"version":"4.17.20"},"node_modules/a/node_modules/@scope/b":{"version":"1.0.0"}}}`, "@scope/b", "1.0.0", 2},
		{"package-lock.json", `{"lockfileVersion":1,"dependencies":{"minimist":{"version":"0.0.8","dependencies":{"x":{"version":"1.0.0"}}}}}`, "x", "1.0.0", 2},
		{"yarn.lock", "# yarn lockfile v1\n\n\"@babel/core@^7.0.0\", \"@babel/core@^7.1.0\":\n  version \"7.1.2\"\n\nlodash@^4:\n  version \"4.17.21\"\n", "@babel/core", "7.1.2", 2},
		{"requirements.txt", "Django==3.2.0 ; python_version > '3'\nrequests[socks]==2.25.1  # pinned\nflask>=2\n", "requests", "2.25.1", 2},
		{"Cargo.lock", "version = 3\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.100\"\n\n[[package]]\nname = \"smallvec\"\nversion = \"1.6.0\"\n[metadata]\n", "smallvec", "1.6.0", 2},
		{"Pipfile.lock", `{"default":{"jinja2":{"version":"==2.10"}},"develop":{"pytest":{"version":"==6.0.0"}}}`, "jinja2", "2.10", 2},
		{"composer.lock", `{"packages":[{"name":"guzzlehttp/guzzle","version":"v7.0.0"}],"packages-dev":[]}`, "guzzlehttp/guzzle", "7.0.0", 1},
		{"Gemfile.lock", "GEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.10.0-x86_64-linux)\n      racc (~> 1.4)\n    rack (2.2.3)\n\nPLATFORMS\n  ruby\n", "nokogiri", "1.10.0", 2},
	}
	for _, c := range cases {
		lp, ok := parserFor(c.file)
		if !ok {
			t.Fatalf("no parser for %s", c.file)
		}
		pkgs, err := lp.parse([]byte(c.content))
		if err != nil {
			t.Fatalf("%s: %v", c.file, err)
		}
		p := find(pkgs, c.name)
		if len(pkgs) != c.count || p == nil || p.Version != c.version {
			t.Errorf("%s: got %+v", c.file, pkgs)
		}
	}
}

func TestCollectPathsSkipsVendoredDirs(t *testing.T) {
	m := sysenv.MemFS{
		"srv/app/go.mod": &fstest.MapFile{Data: []byte("require github.com/a/b v1.0.0\n")},
		"srv/app/node_modules/x/package-lock.json": &fstest.MapFile{Data: []byte(`{"packages":{"node_modules/y":{"version":"1"}}}`)},
		"srv/app/requirements-prod.txt":            &fstest.MapFile{Data: []byte("pyyaml==5.3\n")},
	}
	pkgs, errs := CollectPaths(context.Background(), &sysenv.Env{FS: m}, []string{"/srv"})
	if len(errs) != 0 || len(pkgs) != 2 {
		t.Fatalf("got %+v %v", pkgs, errs)
	}
	if p := find(pkgs, "github.com/a/b"); p.Ecosystem != "Go" || p.Path != "/srv/app/go.mod" || p.Manager != "gomod" {
		t.Errorf("metadata: %+v", p)
	}
}

func TestGoBinary(t *testing.T) {
	exe, err := os.Executable() // the test binary itself carries build info
	if err != nil {
		t.Skip(err)
	}
	pkgs := goBinary(exe)
	std := find(pkgs, "stdlib")
	if std == nil || std.Version != runtime.Version()[2:] || std.Path != exe {
		t.Errorf("stdlib from buildinfo: %+v", pkgs)
	}
	if goBinary(filepath.Join(t.TempDir(), "missing")) != nil {
		t.Error("non-Go file must yield nothing")
	}
}
