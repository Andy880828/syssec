package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"runtime"

	"github.com/Andy880828/syssec/internal/core"
	"github.com/Andy880828/syssec/internal/version"
)

func versionCmd() *Command {
	return &Command{
		Name:    "version",
		Summary: "print version information",
		Setup: func(fs *flag.FlagSet) Handler {
			return func(context.Context, *Runtime, []string) (*Output, error) {
				data := map[string]string{"version": version.Version, "commit": version.Commit, "go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH}
				return &Output{Data: data, Human: func(w io.Writer) {
					fmt.Fprintf(w, "syssec %s (%s) %s %s/%s\n", version.Version, version.Commit, runtime.Version(), runtime.GOOS, runtime.GOARCH)
				}}, nil
			}
		},
	}
}

// CommandInfo is one entry in the machine-readable manifest.
type CommandInfo struct {
	Command  string     `json:"command"`
	Summary  string     `json:"summary"`
	Args     string     `json:"args,omitempty"`
	Flags    []FlagInfo `json:"flags"`
	Examples []string   `json:"examples,omitempty"`
}

func describeCmd() *Command {
	return &Command{
		Name:    "describe",
		Summary: "machine-readable manifest of commands, flags, exit codes and env vars",
		Setup: func(fs *flag.FlagSet) Handler {
			return func(context.Context, *Runtime, []string) (*Output, error) {
				var cmds []CommandInfo
				var walk func(c *Command, path []string)
				walk = func(c *Command, path []string) {
					if c.Setup != nil {
						cmds = append(cmds, info(c, path))
					}
					for _, s := range c.Sub {
						walk(s, append(append([]string{}, path...), s.Name))
					}
				}
				walk(Root(), nil)
				data := map[string]any{
					"name": "syssec", "version": version.Version, "schema": core.SchemaVersion,
					"envelope": map[string]string{
						"ok": "bool", "command": "string", "schema": "string", "data": "object (command specific)",
						"warnings": "[]string, non-fatal", "error": "{code, message, hint} when ok=false",
					},
					"exit_codes":  map[string]string{"0": "success", "1": "runtime error", "2": "usage error", "3": "--fail-on threshold reached"},
					"error_codes": map[string]string{"usage": "bad flags/args; see hint", "no_data": "nothing recorded yet; run the hinted command", "not_found": "unknown ID", "network": "intel source unreachable; offline commands still work", "runtime": "anything else"},
					"statuses":    map[string]string{"pass": "compliant", "fail": "non-compliant", "warn": "likely issue or unverifiable", "skip": "not applicable/not readable", "error": "probe failed", "waived": "accepted risk (see waiver)"},
					"priorities":  map[string]string{"P0": "CISA KEV: exploited in the wild", "P1": "EPSS >= 0.1, or critical with a fix, or high+ with a fix loaded by a running process", "P2": "high/critical, or EPSS >= 0.01", "P3": "the rest"},
					"env": map[string]string{
						"SYSSEC_OUTPUT":          "set to 'json' to force JSON output",
						"SYSSEC_DB":              "SQLite database path",
						"SYSSEC_HOME":            "data directory: syssec.db, rules/, waivers.json",
						"SYSSEC_RULES_DIR":       "extra JSON rule directories (path-list)",
						"SYSSEC_OSV_URL":         "OSV API base URL (mirror/proxy)",
						"SYSSEC_HTTP_TIMEOUT":    "HTTP timeout in seconds",
						"SYSSEC_INTEL_TTL_HOURS": "reuse OSV answers for unchanged package versions (default 6)",
						"SYSSEC_KEV_URL":         "CISA KEV feed URL (mirror)",
						"SYSSEC_EPSS_URL":        "FIRST EPSS API URL (mirror)",
					},
					"commands": cmds,
				}
				return &Output{Data: data, Human: func(w io.Writer) {
					for _, c := range cmds {
						fmt.Fprintf(w, "%-24s %s\n", c.Command, c.Summary)
					}
				}}, nil
			}
		},
	}
}
