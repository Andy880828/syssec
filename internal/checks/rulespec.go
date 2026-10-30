package checks

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"

	"github.com/Andy880828/syssec/internal/core"
)

// RuleSpec is a declarative rule loaded from a JSON rule pack. It lets
// operators (or agents) add controls without recompiling syssec.
//
//	{"rules":[{"id":"ORG-001","title":"...","severity":"high","type":"sysctl",
//	           "key":"kernel.kexec_load_disabled","expect":{"op":"eq","values":["1"]}}]}
type RuleSpec struct {
	core.CheckMeta
	Type    string      `json:"type"`              // sysctl|sshd|file_mode|file_regex|registry|command
	Key     string      `json:"key,omitempty"`     // sysctl / sshd keyword
	Path    string      `json:"path,omitempty"`    // file or registry key path
	Name    string      `json:"name,omitempty"`    // registry value name
	Mode    string      `json:"mode,omitempty"`    // file_mode: max octal mode, e.g. "0640"
	Pattern string      `json:"pattern,omitempty"` // file_regex / command
	Present *bool       `json:"present,omitempty"` // file_regex / command: must match (default true)
	Command []string    `json:"command,omitempty"` // command argv
	Expect  *Expect     `json:"expect,omitempty"`  // sysctl / sshd / registry
	Missing core.Status `json:"missing,omitempty"` // file_regex / registry when absent (default fail)
}

// Build turns a spec into a Check.
func (s RuleSpec) Build() (Check, error) {
	m := s.CheckMeta
	if m.ID == "" || m.Title == "" {
		return nil, errors.New("rule needs id and title")
	}
	if m.Category == "" {
		m.Category = "custom"
	}
	if m.Severity == core.SeverityUnknown {
		m.Severity = core.SeverityMedium
	}
	m.Tags = append(m.Tags, "custom")
	present := s.Present == nil || *s.Present
	missing := s.Missing
	if missing == "" {
		missing = core.StatusFail
	}
	needExpect := func() (Expect, error) {
		if s.Expect == nil {
			return Expect{}, fmt.Errorf("rule %s: type %s requires expect", m.ID, s.Type)
		}
		return *s.Expect, s.Expect.Validate()
	}
	switch s.Type {
	case "sysctl", "sshd":
		e, err := needExpect()
		if err != nil || s.Key == "" {
			return nil, errors.Join(err, requireField(m.ID, "key", s.Key))
		}
		if s.Type == "sysctl" {
			return Sysctl(m, s.Key, e), nil
		}
		return SSHDOption(m, s.Key, e), nil
	case "file_mode":
		mode, err := strconv.ParseUint(s.Mode, 8, 32)
		if err != nil || s.Path == "" {
			return nil, fmt.Errorf("rule %s: file_mode needs path and octal mode", m.ID)
		}
		return FileMode(m, s.Path, fs.FileMode(mode)), nil
	case "file_regex":
		if s.Path == "" || s.Pattern == "" {
			return nil, fmt.Errorf("rule %s: file_regex needs path and pattern", m.ID)
		}
		return safeBuild(func() Check { return FileRegex(m, s.Path, s.Pattern, present, missing) })
	case "registry":
		e, err := needExpect()
		if err != nil || s.Path == "" || s.Name == "" {
			return nil, errors.Join(err, fmt.Errorf("rule %s: registry needs path, name and expect", m.ID))
		}
		return RegistryValue(m, s.Path, s.Name, e, missing), nil
	case "command":
		if len(s.Command) == 0 || s.Pattern == "" {
			return nil, fmt.Errorf("rule %s: command needs command and pattern", m.ID)
		}
		return safeBuild(func() Check { return CommandOutput(m, s.Command, s.Pattern, present) })
	}
	return nil, fmt.Errorf("rule %s: unknown type %q", m.ID, s.Type)
}

func requireField(id, name, v string) error {
	if v == "" {
		return fmt.Errorf("rule %s: missing %s", id, name)
	}
	return nil
}

// safeBuild converts a regexp.MustCompile panic into an error.
func safeBuild(fn func() Check) (c Check, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("invalid pattern: %v", r)
		}
	}()
	return fn(), nil
}

// LoadRules reads every *.json rule pack in the given files or directories.
// Missing directories are ignored; malformed rules are reported, not fatal.
func LoadRules(paths ...string) ([]Check, []error) {
	var out []Check
	var errs []error
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, err)
			}
			continue
		}
		files := []string{p}
		if fi.IsDir() {
			files, _ = filepath.Glob(filepath.Join(p, "*.json"))
		}
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			cs, perrs := ParseRulePack(b)
			out = append(out, cs...)
			for _, e := range perrs {
				errs = append(errs, fmt.Errorf("%s: %w", f, e))
			}
		}
	}
	return out, errs
}

// ParseRulePack decodes and builds a JSON rule pack. Rules without an
// explicit severity default to medium.
func ParseRulePack(b []byte) ([]Check, []error) {
	var pack struct {
		Rules []json.RawMessage `json:"rules"`
	}
	if err := json.Unmarshal(b, &pack); err != nil {
		return nil, []error{err}
	}
	var out []Check
	var errs []error
	for i, raw := range pack.Rules {
		spec := RuleSpec{CheckMeta: core.CheckMeta{Severity: core.SeverityUnknown}}
		if err := json.Unmarshal(raw, &spec); err != nil {
			errs = append(errs, fmt.Errorf("rule #%d: %w", i, err))
			continue
		}
		c, err := spec.Build()
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, c)
	}
	return out, errs
}
