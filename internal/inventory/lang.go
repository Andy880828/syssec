package inventory

import (
	"bufio"
	"bytes"
	"context"
	"debug/buildinfo"
	"encoding/json"
	"fmt"
	"io/fs"
	"slices"
	"strings"

	"github.com/Andy880828/syssec/internal/core"
	"github.com/Andy880828/syssec/internal/sysenv"
)

// lockParser turns one lockfile into packages (Name, Version only).
type lockParser struct {
	manager, ecosystem string
	parse              func([]byte) ([]core.Package, error)
}

// lockfiles maps a file name to its parser. Add an entry to support a new
// ecosystem; OSV ecosystem names follow https://ossf.github.io/osv-schema/.
var lockfiles = map[string]lockParser{
	"go.mod":            {"gomod", "Go", parseGoMod},
	"package-lock.json": {"npm", "npm", parseNpmLock},
	"yarn.lock":         {"yarn", "npm", parseYarnLock},
	"requirements.txt":  {"pip", "PyPI", parseRequirements},
	"poetry.lock":       {"poetry", "PyPI", parseTOMLPackages},
	"uv.lock":           {"uv", "PyPI", parseTOMLPackages},
	"Pipfile.lock":      {"pipenv", "PyPI", parsePipfileLock},
	"Cargo.lock":        {"cargo", "crates.io", parseTOMLPackages},
	"composer.lock":     {"composer", "Packagist", parseComposerLock},
	"Gemfile.lock":      {"bundler", "RubyGems", parseGemfileLock},
}

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, ".venv": true, "venv": true,
	"__pycache__": true, "target": true, ".cache": true, ".tox": true, "dist": true,
}

const (
	maxDepth      = 8
	maxBinarySize = 256 << 20
)

// CollectPaths scans directories for lockfiles and Go binaries. Each
// package records the file it came from in Path.
func CollectPaths(ctx context.Context, env *sysenv.Env, roots []string) ([]core.Package, []error) {
	var out []core.Package
	var errs []error
	for _, root := range roots {
		// Keep the caller's separator style: env.FS may be the OS filesystem
		// (\ on Windows) or an abstract one (/), so never filepath.Clean here.
		if len(root) > 1 {
			root = strings.TrimRight(root, `/\`)
		}
		base := depth(root)
		err := env.FS.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if d.IsDir() {
				if p != root && (skipDirs[d.Name()] || depth(p)-base >= maxDepth) {
					return fs.SkipDir
				}
				return nil
			}
			if lp, ok := parserFor(d.Name()); ok {
				pkgs, err := parseLockfile(env, p, lp)
				if err != nil {
					errs = append(errs, fmt.Errorf("%s: %w", p, err))
				}
				out = append(out, pkgs...)
				return nil
			}
			if d.Type().IsRegular() {
				if fi, err := d.Info(); err == nil && fi.Mode().Perm()&0o111 != 0 && fi.Size() < maxBinarySize {
					out = append(out, goBinary(p)...)
				}
			}
			return nil
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("scan %s: %w", root, err))
		}
	}
	return out, errs
}

// depth counts path separators of either style.
func depth(p string) int { return strings.Count(p, "/") + strings.Count(p, `\`) }

func parserFor(name string) (lockParser, bool) {
	if lp, ok := lockfiles[name]; ok {
		return lp, true
	}
	if strings.HasPrefix(name, "requirements") && strings.HasSuffix(name, ".txt") { // requirements-prod.txt
		return lockfiles["requirements.txt"], true
	}
	return lockParser{}, false
}

func parseLockfile(env *sysenv.Env, p string, lp lockParser) ([]core.Package, error) {
	b, err := env.FS.ReadFile(p)
	if err != nil {
		return nil, err
	}
	pkgs, err := lp.parse(b)
	for i := range pkgs {
		pkgs[i].Manager, pkgs[i].Ecosystem, pkgs[i].Path = lp.manager, lp.ecosystem, p
	}
	return pkgs, err
}

// goBinary reads the module list Go embeds in every binary it builds,
// including the exact standard library version (reported as "stdlib").
// It reads the real filesystem: buildinfo needs random access.
func goBinary(p string) []core.Package {
	bi, err := buildinfo.ReadFile(p)
	if err != nil {
		return nil
	}
	mk := func(name, ver string) core.Package {
		return core.Package{Name: name, Version: strings.TrimPrefix(ver, "v"), Manager: "gobinary", Ecosystem: "Go", Path: p}
	}
	out := []core.Package{mk("stdlib", strings.TrimPrefix(bi.GoVersion, "go"))}
	for _, d := range bi.Deps {
		if d.Replace != nil {
			d = d.Replace
		}
		if d.Version != "" && d.Version != "(devel)" {
			out = append(out, mk(d.Path, d.Version))
		}
	}
	return out
}

func pkg(name, version string) core.Package { return core.Package{Name: name, Version: version} }

func parseGoMod(b []byte) ([]core.Package, error) {
	var out []core.Package
	inBlock := false
	for _, line := range strings.Split(string(b), "\n") {
		line, _, _ = strings.Cut(line, "//")
		f := strings.Fields(line)
		switch {
		case len(f) == 0:
		case f[0] == "require" && len(f) > 1 && f[1] == "(":
			inBlock = true
		case inBlock && f[0] == ")":
			inBlock = false
		case inBlock && len(f) >= 2:
			out = append(out, pkg(f[0], strings.TrimPrefix(f[1], "v")))
		case f[0] == "require" && len(f) >= 3:
			out = append(out, pkg(f[1], strings.TrimPrefix(f[2], "v")))
		}
	}
	return out, nil
}

func parseNpmLock(b []byte) ([]core.Package, error) {
	var lock struct {
		Packages map[string]struct {
			Version string `json:"version"`
			Link    bool   `json:"link"`
		} `json:"packages"`
		Dependencies map[string]json.RawMessage `json:"dependencies"`
	}
	if err := json.Unmarshal(b, &lock); err != nil {
		return nil, err
	}
	var out []core.Package
	if len(lock.Packages) > 0 { // lockfileVersion 2/3
		for key, p := range lock.Packages {
			i := strings.LastIndex(key, "node_modules/")
			if i < 0 || p.Link || p.Version == "" {
				continue // "" is the root project
			}
			out = append(out, pkg(key[i+len("node_modules/"):], p.Version))
		}
		return out, nil
	}
	var walk func(map[string]json.RawMessage) // lockfileVersion 1
	walk = func(deps map[string]json.RawMessage) {
		for name, raw := range deps {
			var d struct {
				Version      string                     `json:"version"`
				Dependencies map[string]json.RawMessage `json:"dependencies"`
			}
			if json.Unmarshal(raw, &d) == nil {
				out = append(out, pkg(name, d.Version))
				walk(d.Dependencies)
			}
		}
	}
	walk(lock.Dependencies)
	return out, nil
}

func parseYarnLock(b []byte) ([]core.Package, error) {
	var out []core.Package
	name := ""
	for _, line := range strings.Split(string(b), "\n") {
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
		case !strings.HasPrefix(line, " ") && strings.HasSuffix(line, ":"):
			spec := strings.Trim(strings.TrimSpace(strings.SplitN(strings.TrimSuffix(line, ":"), ",", 2)[0]), `"`)
			if at := strings.LastIndex(spec, "@"); at > 0 {
				name = spec[:at]
			}
		case name != "" && strings.HasPrefix(strings.TrimSpace(line), "version"):
			v := strings.Trim(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "version")), `:" `)
			out = append(out, pkg(name, v))
			name = ""
		}
	}
	return out, nil
}

func parseRequirements(b []byte) ([]core.Package, error) {
	var out []core.Package
	for _, line := range strings.Split(string(b), "\n") {
		line, _, _ = strings.Cut(line, "#")
		line, _, _ = strings.Cut(line, ";") // environment markers
		name, ver, ok := strings.Cut(line, "==")
		if !ok {
			continue // only pinned requirements identify an installed version
		}
		name, _, _ = strings.Cut(name, "[") // extras
		out = append(out, pkg(strings.ToLower(strings.TrimSpace(name)), strings.TrimSpace(strings.Fields(ver + " ")[0])))
	}
	return out, nil
}

// parseTOMLPackages reads the [[package]] name/version pairs shared by
// Cargo.lock, poetry.lock and uv.lock without a TOML dependency.
func parseTOMLPackages(b []byte) ([]core.Package, error) {
	var out []core.Package
	var cur *core.Package
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "[[package]]":
			if cur != nil && cur.Name != "" && cur.Version != "" {
				out = append(out, *cur)
			}
			cur = &core.Package{}
		case strings.HasPrefix(line, "["):
			if cur != nil && cur.Name != "" && cur.Version != "" {
				out = append(out, *cur)
			}
			cur = nil
		case cur != nil:
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			v = strings.Trim(strings.TrimSpace(v), `"`)
			switch strings.TrimSpace(k) {
			case "name":
				cur.Name = v
			case "version":
				cur.Version = v
			}
		}
	}
	if cur != nil && cur.Name != "" && cur.Version != "" {
		out = append(out, *cur)
	}
	return out, sc.Err()
}

func parsePipfileLock(b []byte) ([]core.Package, error) {
	var lock map[string]map[string]struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(b, &lock); err != nil {
		return nil, err
	}
	var out []core.Package
	for _, section := range []string{"default", "develop"} {
		for name, d := range lock[section] {
			if v := strings.TrimPrefix(d.Version, "=="); v != "" {
				out = append(out, pkg(strings.ToLower(name), v))
			}
		}
	}
	return out, nil
}

func parseComposerLock(b []byte) ([]core.Package, error) {
	var lock struct {
		Packages    []struct{ Name, Version string } `json:"packages"`
		PackagesDev []struct{ Name, Version string } `json:"packages-dev"`
	}
	if err := json.Unmarshal(b, &lock); err != nil {
		return nil, err
	}
	var out []core.Package
	for _, p := range slices.Concat(lock.Packages, lock.PackagesDev) {
		out = append(out, pkg(p.Name, strings.TrimPrefix(p.Version, "v")))
	}
	return out, nil
}

func parseGemfileLock(b []byte) ([]core.Package, error) {
	var out []core.Package
	inSpecs := false
	for _, line := range strings.Split(string(b), "\n") {
		switch {
		case strings.TrimSpace(line) == "specs:":
			inSpecs = true
		case !strings.HasPrefix(line, " "):
			inSpecs = false
		case inSpecs && strings.HasPrefix(line, "    ") && !strings.HasPrefix(line, "     "):
			name, ver, ok := strings.Cut(strings.TrimSpace(line), " (")
			if ok {
				ver, _, _ = strings.Cut(strings.TrimSuffix(ver, ")"), "-") // drop platform suffix
				out = append(out, pkg(name, ver))
			}
		}
	}
	return out, nil
}

// LockfileNames lists the supported lockfile names (for help text).
func LockfileNames() []string {
	names := make([]string, 0, len(lockfiles))
	for n := range lockfiles {
		names = append(names, n)
	}
	slices.Sort(names)
	return append(names, "Go binaries")
}
