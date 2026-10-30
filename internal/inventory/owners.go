package inventory

import (
	"bufio"
	"bytes"
	"context"
	"path"
	"strings"

	"github.com/Andy880828/syssec/internal/sysenv"
)

// Owners maps each wanted file to the package that installed it, reading
// the package managers' own file lists (dpkg .list, apk F:/R:, pacman
// files) and falling back to `rpm -qf`. canon normalises usrmerge paths.
func Owners(ctx context.Context, env *sysenv.Env, wanted []string, canon func(string) string) map[string]string {
	want := map[string]bool{}
	for _, w := range wanted {
		want[w] = true
	}
	out := map[string]string{}
	add := func(file, pkg string) {
		if f := canon(file); want[f] {
			out[f] = pkg
		}
	}
	// dpkg: /var/lib/dpkg/info/<pkg>[:arch].list, one absolute path per line.
	lists, _ := env.FS.Glob("/var/lib/dpkg/info/*.list")
	for _, l := range lists {
		pkg, _, _ := strings.Cut(strings.TrimSuffix(path.Base(l), ".list"), ":")
		b, err := env.FS.ReadFile(l)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			add(sc.Text(), pkg)
		}
	}
	// apk: P:<pkg>, then F:<dir> followed by R:<file> lines.
	if b, err := env.FS.ReadFile(apkInstalled); err == nil {
		var pkg, dir string
		for _, line := range strings.Split(string(b), "\n") {
			if len(line) < 2 || line[1] != ':' {
				continue
			}
			switch line[0] {
			case 'P':
				pkg = line[2:]
			case 'F':
				dir = line[2:]
			case 'R':
				add("/"+path.Join(dir, line[2:]), pkg)
			}
		}
	}
	// pacman: local/<pkg>-<ver>/files lists relative paths under %FILES%.
	descs, _ := env.FS.Glob("/var/lib/pacman/local/*/files")
	for _, f := range descs {
		desc, _ := env.FS.ReadFile(path.Join(path.Dir(f), "desc"))
		name := ""
		if i := bytes.Index(desc, []byte("%NAME%\n")); i >= 0 {
			name, _, _ = strings.Cut(string(desc[i+7:]), "\n")
		}
		b, _ := env.FS.ReadFile(f)
		for _, line := range strings.Split(string(b), "\n") {
			if line != "" && !strings.HasPrefix(line, "%") {
				add("/"+line, name)
			}
		}
	}
	// rpm: the database is binary, so ask rpm about the unresolved files only.
	if (rpm{}).Applicable(env) {
		var rest []string
		for _, w := range wanted {
			if _, ok := out[w]; !ok {
				rest = append(rest, w)
			}
		}
		for start := 0; start < len(rest); start += 200 {
			chunk := rest[start:min(start+200, len(rest))]
			b, _ := env.Exec.Run(ctx, "rpm", append([]string{"-qf", "--qf", `%{NAME}\n`}, chunk...)...)
			lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
			if len(lines) != len(chunk) {
				continue // unexpected output shape; skip rather than misattribute
			}
			for i, l := range lines {
				if !strings.Contains(l, " ") { // "file X is not owned by any package"
					out[chunk[i]] = l
				}
			}
		}
	}
	return out
}
