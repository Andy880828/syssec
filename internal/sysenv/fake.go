package sysenv

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"
	"testing/fstest"
)

// MemFS adapts fstest.MapFS (keys without a leading slash) to FS with
// absolute paths. Symlinks are files with fs.ModeSymlink whose Data is the target.
type MemFS fstest.MapFS

func rel(name string) string {
	n := strings.TrimPrefix(path.Clean(name), "/")
	if n == "" {
		return "."
	}
	return n
}

func (m MemFS) ReadFile(n string) ([]byte, error)       { return fs.ReadFile(fstest.MapFS(m), rel(n)) }
func (m MemFS) Stat(n string) (fs.FileInfo, error)      { return fs.Stat(fstest.MapFS(m), rel(n)) }
func (m MemFS) Lstat(n string) (fs.FileInfo, error)     { return m.Stat(n) }
func (m MemFS) ReadDir(n string) ([]fs.DirEntry, error) { return fs.ReadDir(fstest.MapFS(m), rel(n)) }

func (m MemFS) Readlink(n string) (string, error) {
	f, ok := m[rel(n)]
	if !ok || f.Mode&fs.ModeSymlink == 0 {
		return "", &fs.PathError{Op: "readlink", Path: n, Err: fs.ErrInvalid}
	}
	return string(f.Data), nil
}

func (m MemFS) Glob(p string) ([]string, error) {
	out, err := fs.Glob(fstest.MapFS(m), rel(p))
	for i := range out {
		out[i] = "/" + out[i]
	}
	return out, err
}

func (m MemFS) WalkDir(root string, fn fs.WalkDirFunc) error {
	return fs.WalkDir(fstest.MapFS(m), rel(root), func(p string, d fs.DirEntry, err error) error {
		return fn("/"+strings.TrimPrefix(p, "./"), d, err)
	})
}

// FakeRunner returns canned command output keyed by "name arg1 arg2".
type FakeRunner map[string]string

func (f FakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	key := strings.TrimSpace(name + " " + strings.Join(args, " "))
	out, ok := f[key]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrCommandNotFound, name)
	}
	return []byte(out), nil
}

// FakeRegistry maps `PATH\Name` to a uint64 or string value.
type FakeRegistry map[string]any

func (f FakeRegistry) Integer(p, name string) (uint64, error) {
	v, ok := f[p+`\`+name]
	if !ok {
		return 0, ErrNotExist
	}
	switch t := v.(type) {
	case int:
		return uint64(t), nil
	case uint64:
		return t, nil
	}
	return 0, errors.New("value is not an integer")
}

func (f FakeRegistry) String(p, name string) (string, error) {
	v, ok := f[p+`\`+name]
	if !ok {
		return "", ErrNotExist
	}
	if s, ok := v.(string); ok {
		return s, nil
	}
	return fmt.Sprint(v), nil
}

func (f FakeRegistry) SubKeys(p string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	prefix := p + `\`
	for k := range f {
		if rest, ok := strings.CutPrefix(k, prefix); ok {
			if sub, _, found := strings.Cut(rest, `\`); found && !seen[sub] {
				seen[sub] = true
				out = append(out, sub)
			}
		}
	}
	if len(out) == 0 {
		return nil, ErrNotExist
	}
	return out, nil
}
