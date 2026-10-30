// Package waiver implements accepted-risk exceptions (Lynis "skip-test",
// InSpec waivers, Trivy .trivyignore) as one reviewable JSON file. A waiver
// never hides a finding: the result keeps its evidence, gets status
// "waived" and the reason, and drops out of the score and default lists.
package waiver

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Andy880828/syssec/internal/core"
)

// File is the on-disk format of waivers.json.
type File struct {
	Waivers []core.Waiver `json:"waivers"`
}

// Load reads the waiver file; a missing file means no waivers.
func Load(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return &File{Waivers: []core.Waiver{}}, nil
	}
	if err != nil {
		return nil, err
	}
	f := &File{}
	if err := json.Unmarshal(b, f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return f, nil
}

// Save writes the file atomically.
func (f *File) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(f, "", "  ")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Put adds or replaces the waiver with the same ID and package.
func (f *File) Put(w core.Waiver) {
	f.Waivers = slices.DeleteFunc(f.Waivers, func(x core.Waiver) bool {
		return strings.EqualFold(x.ID, w.ID) && x.Package == w.Package
	})
	f.Waivers = append(f.Waivers, w)
}

// Remove deletes waivers for id (only those scoped to pkg, when given) and
// reports how many were removed.
func (f *File) Remove(id, pkg string) int {
	n := len(f.Waivers)
	f.Waivers = slices.DeleteFunc(f.Waivers, func(w core.Waiver) bool {
		return strings.EqualFold(w.ID, id) && (pkg == "" || w.Package == pkg)
	})
	return n - len(f.Waivers)
}

// Expired reports whether the waiver no longer applies at now.
func Expired(w core.Waiver, now time.Time) bool {
	if w.Expires == "" {
		return false
	}
	t, err := time.Parse(time.DateOnly, w.Expires)
	return err != nil || !now.Before(t.AddDate(0, 0, 1))
}

// Apply marks waived results and vulns in place and returns the IDs of
// expired waivers so callers can surface them.
func (f *File) Apply(results []core.Result, vulns []core.Vuln, now time.Time) (expired []string) {
	active := map[string][]core.Waiver{}
	for _, w := range f.Waivers {
		if Expired(w, now) {
			expired = append(expired, w.ID)
			continue
		}
		active[strings.ToUpper(w.ID)] = append(active[strings.ToUpper(w.ID)], w)
	}
	if len(active) == 0 {
		return expired
	}
	for i := range results {
		r := &results[i]
		if ws := active[strings.ToUpper(r.ID)]; len(ws) > 0 && (r.Status == core.StatusFail || r.Status == core.StatusWarn) {
			w := ws[0]
			r.Status, r.Waiver, r.Remediation = core.StatusWaived, &w, ""
		}
	}
	for i := range vulns {
		v := &vulns[i]
		for _, id := range append([]string{v.ID}, v.Aliases...) {
			for _, w := range active[strings.ToUpper(id)] {
				if w.Package == "" || w.Package == v.Package {
					w := w
					v.Waiver = &w
				}
			}
		}
	}
	return expired
}

// ParseExpiry accepts "", a date (2026-12-31) or a relative "90d".
func ParseExpiry(s string, now time.Time) (string, error) {
	switch {
	case s == "":
		return "", nil
	case strings.HasSuffix(s, "d"):
		var n int
		if _, err := fmt.Sscanf(s, "%dd", &n); err != nil || n <= 0 {
			return "", fmt.Errorf("invalid duration %q (use e.g. 90d)", s)
		}
		return now.AddDate(0, 0, n).Format(time.DateOnly), nil
	}
	if _, err := time.Parse(time.DateOnly, s); err != nil {
		return "", fmt.Errorf("invalid date %q (use YYYY-MM-DD or Nd)", s)
	}
	return s, nil
}
