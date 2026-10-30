// Package reach answers "is this code actually running?" on Linux by
// walking /proc/<pid>/maps: which files are mapped by which processes, and
// which processes still map files that were deleted on disk (upgraded
// libraries that need a restart, as needrestart reports).
package reach

import (
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/Andy880828/syssec/internal/checks"
	"github.com/Andy880828/syssec/internal/core"
	"github.com/Andy880828/syssec/internal/sysenv"
)

// Usage is a snapshot of mapped files.
type Usage struct {
	ByFile    map[string][]string // canonical path -> process names
	Stale     []Stale             // processes mapping replaced system files
	Processes int                 // processes whose maps were read
	Complete  bool                // every process was readable (needs root)
}

// Stale is a process still running code that was deleted from disk.
type Stale struct {
	PID     int      `json:"pid"`
	Process string   `json:"process"`
	Files   []string `json:"files"`
}

// systemPrefixes are where package-managed code lives; deleted files
// elsewhere (/tmp, memfd, caches) are not upgrade leftovers.
var systemPrefixes = []string{"/usr/", "/lib", "/bin/", "/sbin/", "/opt/"}

// Scan walks /proc once per Env (memoized).
func Scan(env *sysenv.Env) (*Usage, error) {
	return checks.Cached(env, "reach", func() (*Usage, error) {
		u := &Usage{ByFile: map[string][]string{}, Complete: true}
		canon := Canonicalizer(env.FS)
		procs, err := env.FS.ReadDir("/proc")
		if err != nil {
			return nil, err
		}
		for _, p := range procs {
			pid, err := strconv.Atoi(p.Name())
			if err != nil {
				continue
			}
			dir := "/proc/" + p.Name()
			maps, err := env.FS.ReadFile(dir + "/maps")
			if err != nil {
				u.Complete = false // other users' processes need root
				continue
			}
			if len(maps) == 0 {
				continue // kernel thread
			}
			comm, _ := env.FS.ReadFile(dir + "/comm")
			name := strings.TrimSpace(string(comm))
			u.Processes++
			files, deleted := ParseMaps(maps)
			for _, f := range files {
				f = canon(f)
				if !slices.Contains(u.ByFile[f], name) {
					u.ByFile[f] = append(u.ByFile[f], name)
				}
			}
			var stale []string
			for _, f := range deleted {
				if isSystem(f) {
					stale = append(stale, f)
				}
			}
			if len(stale) > 0 {
				u.Stale = append(u.Stale, Stale{PID: pid, Process: name, Files: stale})
			}
		}
		return u, nil
	})
}

// Files lists every mapped path.
func (u *Usage) Files() []string {
	out := make([]string, 0, len(u.ByFile))
	for f := range u.ByFile {
		out = append(out, f)
	}
	slices.Sort(out)
	return out
}

// ParseMaps extracts file-backed mappings, separating deleted ones.
func ParseMaps(b []byte) (files, deleted []string) {
	seen := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		// address perms offset dev inode pathname — the path may contain spaces.
		f := strings.Fields(line)
		if len(f) < 6 {
			continue
		}
		p := strings.Join(f[5:], " ")
		if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "/dev/") || strings.HasPrefix(p, "/memfd:") {
			continue
		}
		gone := strings.HasSuffix(p, " (deleted)")
		p = strings.TrimSuffix(p, " (deleted)")
		if seen[p] {
			continue
		}
		seen[p] = true
		if gone {
			deleted = append(deleted, p)
		} else {
			files = append(files, p)
		}
	}
	return files, deleted
}

func isSystem(p string) bool {
	for _, pre := range systemPrefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

// Canonicalizer folds usrmerge symlinks (/lib -> usr/lib, ...) so package
// file lists and kernel-reported paths compare equal.
func Canonicalizer(fsys sysenv.FS) func(string) string {
	links := map[string]string{}
	for _, d := range []string{"/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32"} {
		if target, err := fsys.Readlink(d); err == nil {
			if !path.IsAbs(target) {
				target = path.Join("/", target)
			}
			links[d+"/"] = target + "/"
		}
	}
	return func(p string) string {
		for from, to := range links {
			if rest, ok := strings.CutPrefix(p, from); ok {
				return to + rest
			}
		}
		return p
	}
}

// Annotate marks vulns whose package code is mapped by a running process.
// owners maps file path -> owning (binary) package name. When the walk was
// incomplete, unmatched vulns stay unknown (InUse == nil) instead of false.
func (u *Usage) Annotate(vulns []core.Vuln, pkgs []core.Package, owners map[string]string) {
	procsByBinary := map[string][]string{}
	for file, pkg := range owners {
		for _, proc := range u.ByFile[file] {
			if !slices.Contains(procsByBinary[pkg], proc) {
				procsByBinary[pkg] = append(procsByBinary[pkg], proc)
			}
		}
	}
	// Advisories are keyed by the query (source) name; roll binaries up.
	procsByQuery := map[string][]string{}
	osPkg := map[string]bool{}
	for _, p := range pkgs {
		q, _ := p.Query()
		if p.Path == "" {
			osPkg[q] = true
		}
		for _, proc := range procsByBinary[p.Name] {
			if !slices.Contains(procsByQuery[q], proc) {
				procsByQuery[q] = append(procsByQuery[q], proc)
			}
		}
	}
	for i := range vulns {
		v := &vulns[i]
		if !osPkg[v.Package] {
			continue // language deps: not attributable through package file lists
		}
		procs := procsByQuery[v.Package]
		switch {
		case len(procs) > 0:
			slices.Sort(procs)
			v.InUse, v.Processes = ptr(true), procs[:min(len(procs), 5)]
		case u.Complete:
			v.InUse = ptr(false)
		}
	}
}

func ptr[T any](v T) *T { return &v }
