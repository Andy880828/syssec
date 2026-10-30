package inventory

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io/fs"
	"path"
	"strings"

	"github.com/Andy880828/syssec/internal/core"
	"github.com/Andy880828/syssec/internal/sysenv"
)

const dpkgStatus = "/var/lib/dpkg/status"

type dpkg struct{}

func (dpkg) Name() string { return "dpkg" }
func (dpkg) Applicable(env *sysenv.Env) bool {
	_, err := env.FS.Stat(dpkgStatus)
	return env.GOOS == "linux" && err == nil
}

func (dpkg) Collect(_ context.Context, env *sysenv.Env) ([]core.Package, error) {
	b, err := env.FS.ReadFile(dpkgStatus)
	if err != nil {
		return nil, err
	}
	return ParseDpkgStatus(b, Ecosystem(env)), nil
}

// ParseDpkgStatus parses /var/lib/dpkg/status. Debian advisories key on
// source packages, so the Source field (and its optional version) is kept.
func ParseDpkgStatus(b []byte, ecosystem string) []core.Package {
	var out []core.Package
	for _, para := range paragraphs(b) {
		f := rfc822(para)
		if !strings.HasSuffix(f["Status"], " installed") || f["Package"] == "" {
			continue
		}
		p := core.Package{Name: f["Package"], Version: f["Version"], Arch: f["Architecture"], Manager: "dpkg", Ecosystem: ecosystem}
		if src := f["Source"]; src != "" {
			name, ver, hasVer := strings.Cut(src, " ")
			p.SourceName = name
			if hasVer {
				p.SourceVersion = strings.Trim(ver, "() ")
			}
		}
		out = append(out, p)
	}
	return out
}

func paragraphs(b []byte) [][]byte {
	b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
	return bytes.Split(b, []byte("\n\n"))
}

func rfc822(para []byte) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(para))
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == ' ' || line[0] == '\t' {
			continue // continuation lines (descriptions, conffiles)
		}
		if k, v, ok := strings.Cut(line, ":"); ok {
			out[k] = strings.TrimSpace(v)
		}
	}
	return out
}

const apkInstalled = "/lib/apk/db/installed"

type apk struct{}

func (apk) Name() string { return "apk" }
func (apk) Applicable(env *sysenv.Env) bool {
	_, err := env.FS.Stat(apkInstalled)
	return env.GOOS == "linux" && err == nil
}

func (apk) Collect(_ context.Context, env *sysenv.Env) ([]core.Package, error) {
	b, err := env.FS.ReadFile(apkInstalled)
	if err != nil {
		return nil, err
	}
	return ParseAPKInstalled(b, Ecosystem(env)), nil
}

// ParseAPKInstalled parses Alpine's installed database (single-letter keys).
func ParseAPKInstalled(b []byte, ecosystem string) []core.Package {
	var out []core.Package
	for _, para := range paragraphs(b) {
		var p core.Package
		for _, line := range strings.Split(string(para), "\n") {
			if len(line) < 2 || line[1] != ':' {
				continue
			}
			switch v := line[2:]; line[0] {
			case 'P':
				p.Name = v
			case 'V':
				p.Version = v
			case 'A':
				p.Arch = v
			case 'o':
				p.SourceName = v
			}
		}
		if p.Name != "" {
			p.Manager, p.Ecosystem = "apk", ecosystem
			out = append(out, p)
		}
	}
	return out
}

type rpm struct{}

func (rpm) Name() string { return "rpm" }
func (rpm) Applicable(env *sysenv.Env) bool {
	if env.GOOS != "linux" {
		return false
	}
	for _, p := range []string{"/var/lib/rpm", "/usr/lib/sysimage/rpm"} {
		if _, err := env.FS.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// Collect shells out to rpm: the rpmdb is a binary header format (BDB,
// NDB or SQLite blobs) and rpm itself is always present where it applies.
func (rpm) Collect(ctx context.Context, env *sysenv.Env) ([]core.Package, error) {
	out, err := env.Exec.Run(ctx, "rpm", "-qa", "--qf", `%{NAME}\t%{EPOCH}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n`)
	if err != nil {
		if errors.Is(err, sysenv.ErrCommandNotFound) {
			return nil, nil
		}
		return nil, err
	}
	eco := Ecosystem(env)
	var pkgs []core.Package
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 4 || f[0] == "gpg-pubkey" {
			continue
		}
		ver := f[2]
		if f[1] != "(none)" && f[1] != "0" {
			ver = f[1] + ":" + ver
		}
		pkgs = append(pkgs, core.Package{Name: f[0], Version: ver, Arch: f[3], Manager: "rpm", Ecosystem: eco})
	}
	return pkgs, nil
}

type pacman struct{}

func (pacman) Name() string { return "pacman" }
func (pacman) Applicable(env *sysenv.Env) bool {
	_, err := env.FS.Stat("/var/lib/pacman/local")
	return env.GOOS == "linux" && err == nil
}

func (pacman) Collect(_ context.Context, env *sysenv.Env) ([]core.Package, error) {
	descs, err := env.FS.Glob("/var/lib/pacman/local/*/desc")
	if err != nil {
		return nil, err
	}
	var out []core.Package
	for _, d := range descs {
		b, err := env.FS.ReadFile(d)
		if err != nil {
			continue
		}
		fields := map[string]string{}
		lines := strings.Split(string(b), "\n")
		for i := 0; i+1 < len(lines); i++ {
			if strings.HasPrefix(lines[i], "%") {
				fields[strings.Trim(lines[i], "%")] = lines[i+1]
			}
		}
		if fields["NAME"] != "" {
			out = append(out, core.Package{Name: fields["NAME"], Version: fields["VERSION"], Arch: fields["ARCH"], Manager: "pacman"})
		}
	}
	return out, nil
}

var cellars = []string{"/opt/homebrew/Cellar", "/usr/local/Cellar", "/home/linuxbrew/.linuxbrew/Cellar"}

type brew struct{}

func (brew) Name() string { return "homebrew" }
func (brew) Applicable(env *sysenv.Env) bool {
	return env.GOOS == "darwin" || env.GOOS == "linux"
}

// Collect reads the Cellar layout (<cellar>/<formula>/<version>) directly.
func (brew) Collect(_ context.Context, env *sysenv.Env) ([]core.Package, error) {
	var out []core.Package
	for _, cellar := range cellars {
		formulae, err := env.FS.ReadDir(cellar)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		} else if err != nil {
			return out, err
		}
		for _, f := range formulae {
			versions, _ := env.FS.ReadDir(path.Join(cellar, f.Name()))
			for _, v := range versions {
				if v.IsDir() {
					out = append(out, core.Package{Name: f.Name(), Version: v.Name(), Manager: "homebrew"})
				}
			}
		}
	}
	return out, nil
}
