package checks

import (
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/Andy880828/syssec/internal/core"
)

// Registry holds every known check, keyed by upper-case ID.
type Registry struct {
	mu    sync.RWMutex
	byID  map[string]Check
	order []string
}

func NewRegistry() *Registry { return &Registry{byID: map[string]Check{}} }

// Register adds checks, rejecting duplicates and incomplete metadata.
func (r *Registry) Register(cs ...Check) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range cs {
		m := c.Meta()
		id := strings.ToUpper(strings.TrimSpace(m.ID))
		switch {
		case id == "":
			return fmt.Errorf("check %q: empty id", m.Title)
		case m.Title == "":
			return fmt.Errorf("check %s: empty title", id)
		case r.byID[id] != nil:
			return fmt.Errorf("check %s: duplicate id", id)
		}
		r.byID[id] = c
		r.order = append(r.order, id)
	}
	return nil
}

// MustRegister panics on error; use for built-in rule sets.
func (r *Registry) MustRegister(cs ...Check) {
	if err := r.Register(cs...); err != nil {
		panic(err)
	}
}

// Get looks a check up by ID (case-insensitive).
func (r *Registry) Get(id string) (Check, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.byID[strings.ToUpper(id)]
	return c, ok
}

// Filter narrows a selection of checks. Zero values match everything.
type Filter struct {
	Platform    string // GOOS, or "" for all
	IDs         []string
	Categories  []string
	MinSeverity core.Severity
}

// Restrictive reports whether the filter selects a subset of the platform's checks.
func (f Filter) Restrictive() bool {
	return len(f.IDs) > 0 || len(f.Categories) > 0 || f.MinSeverity > core.SeverityInfo
}

// Select returns matching checks in registration order.
func (r *Registry) Select(f Filter) []Check {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := upper(f.IDs)
	cats := lower(f.Categories)
	var out []Check
	for _, id := range r.order {
		c := r.byID[id]
		m := c.Meta()
		if f.Platform != "" && !m.SupportsPlatform(f.Platform) {
			continue
		}
		if len(ids) > 0 && !slices.Contains(ids, id) {
			continue
		}
		if len(cats) > 0 && !slices.Contains(cats, strings.ToLower(m.Category)) {
			continue
		}
		if m.Severity < f.MinSeverity {
			continue
		}
		out = append(out, c)
	}
	return out
}

func upper(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, strings.ToUpper(strings.TrimSpace(s)))
	}
	return out
}

func lower(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, strings.ToLower(strings.TrimSpace(s)))
	}
	return out
}
