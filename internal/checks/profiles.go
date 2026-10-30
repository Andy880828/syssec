package checks

import (
	"fmt"
	"slices"
	"strings"
)

// ProfileDef describes a named control set. Profiles are views: a scan
// always runs every applicable check, and a profile selects which results
// count. That keeps history comparable and avoids partial scans.
type ProfileDef struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Includes    []string `json:"includes,omitempty"` // other profiles it extends
}

// KnownProfiles documents the built-in profiles. Rule packs may introduce
// further names simply by listing them in a rule's "profiles".
var KnownProfiles = map[string]ProfileDef{
	"cis-l1": {Name: "cis-l1", Description: "Aligned with CIS Benchmark Level 1 intent: essential, low-impact hardening. Approximate mapping, not a certified CIS assessment."},
	"cis-l2": {Name: "cis-l2", Description: "Aligned with CIS Benchmark Level 2 intent: defence in depth that may affect functionality. Includes cis-l1.", Includes: []string{"cis-l1"}},
}

// expand resolves a profile and everything it includes.
func expand(name string) []string {
	out := []string{name}
	for _, inc := range KnownProfiles[name].Includes {
		out = append(out, expand(inc)...)
	}
	return out
}

// InProfile reports whether check id belongs to profile (or one it includes).
func (r *Registry) InProfile(id, profile string) bool {
	c, ok := r.Get(id)
	if !ok {
		return false
	}
	for _, p := range expand(strings.ToLower(profile)) {
		if slices.Contains(c.Meta().Profiles, p) {
			return true
		}
	}
	return false
}

// Profiles lists every profile name used by a registered check.
func (r *Registry) Profiles() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []string
	for _, c := range r.byID {
		for _, p := range c.Meta().Profiles {
			if !slices.Contains(out, p) {
				out = append(out, p)
			}
		}
	}
	slices.Sort(out)
	return out
}

// ValidateProfile returns an error naming the valid profiles.
func (r *Registry) ValidateProfile(p string) error {
	if p == "" || slices.Contains(r.Profiles(), strings.ToLower(p)) {
		return nil
	}
	return fmt.Errorf("unknown profile %q (available: %s)", p, strings.Join(r.Profiles(), ", "))
}
