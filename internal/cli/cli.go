// Package cli is the agent-native command-line surface: every command
// returns data that is rendered either as a stable JSON envelope (--json)
// or as compact human text, from the same value.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/Andy880828/syssec/internal/app"
	"github.com/Andy880828/syssec/internal/config"
	"github.com/Andy880828/syssec/internal/core"
	"github.com/Andy880828/syssec/internal/intel"
	"github.com/Andy880828/syssec/internal/store"
)

// Exit codes.
const (
	ExitOK       = 0
	ExitError    = 1
	ExitUsage    = 2
	ExitFindings = 3 // --fail-on threshold reached
)

// Command is a node in the command tree.
type Command struct {
	Name     string
	Summary  string
	Args     string // positional argument synopsis
	Examples []string
	Setup    func(fs *flag.FlagSet) Handler
	Sub      []*Command
}

// Handler executes a command after flags are parsed.
type Handler func(ctx context.Context, rt *Runtime, args []string) (*Output, error)

// Output is what a handler produced.
type Output struct {
	Data     any
	Human    func(w io.Writer)
	Exit     int
	Warnings []string
}

// Error is a structured, agent-readable failure. Code is one of:
// usage, no_data, not_found, network, runtime.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
	exit    int
}

func (e *Error) Error() string { return e.Message }

func usageError(hint, format string, a ...any) *Error {
	return &Error{Code: "usage", Message: fmt.Sprintf(format, a...), Hint: hint, exit: ExitUsage}
}

// Runtime carries global options and lazily-built dependencies.
type Runtime struct {
	JSON   bool
	DBPath string
	Stdout io.Writer
	Stderr io.Writer
	app    *app.App
}

// App builds the application on first use so cheap commands stay cheap.
func (rt *Runtime) App(ctx context.Context) *app.App {
	if rt.app != nil {
		return rt.app
	}
	cfg := config.Load()
	if rt.DBPath != "" {
		cfg.DBPath = rt.DBPath
	}
	rt.app = app.New(ctx, cfg)
	return rt.app
}

type envelope struct {
	OK       bool     `json:"ok"`
	Command  string   `json:"command"`
	Schema   string   `json:"schema"`
	Data     any      `json:"data,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
	Error    *Error   `json:"error,omitempty"`
}

// Run executes the CLI and returns the process exit code.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	root := Root()
	rt := &Runtime{Stdout: stdout, Stderr: stderr, JSON: os.Getenv("SYSSEC_OUTPUT") == "json"}

	globals, rest := splitGlobals(args)
	if len(rest) > 0 && rest[0] == "help" { // `syssec help scan` == `syssec scan --help`
		rest = append(rest[1:], "--help")
	}
	cmd, path, rest := resolve(root, rest)
	if cmd == root || cmd.Setup == nil {
		if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
			fmt.Fprintf(stderr, "unknown command %q\n\n", strings.Join(append(path, rest[0]), " "))
			printHelp(stderr, cmd, path)
			return ExitUsage
		}
		printHelp(stdout, cmd, path)
		return ExitOK
	}
	name := strings.Join(path, " ")

	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.BoolVar(&rt.JSON, "json", rt.JSON, "emit a JSON envelope (also: SYSSEC_OUTPUT=json)")
	fs.StringVar(&rt.DBPath, "db", "", "SQLite database path (default $SYSSEC_HOME/syssec.db, or SYSSEC_DB)")
	handler := cmd.Setup(fs)
	positional, err := parseInterleaved(fs, append(globals, rest...))
	if errors.Is(err, flag.ErrHelp) {
		if rt.JSON || slices.Contains(args, "--json") || slices.Contains(args, "-json") {
			writeJSON(stdout, envelope{OK: true, Command: name, Schema: core.SchemaVersion, Data: info(cmd, path)})
		} else {
			printHelp(stdout, cmd, path)
		}
		return ExitOK
	}
	if err != nil {
		return emitError(rt, name, usageError("run `syssec "+name+" --help`", "%v", err))
	}

	defer func() {
		if rt.app != nil {
			rt.app.Close()
		}
	}()
	out, err := handler(ctx, rt, positional)
	if err != nil {
		return emitError(rt, name, err)
	}
	if rt.JSON {
		writeJSON(stdout, envelope{OK: true, Command: name, Schema: core.SchemaVersion, Data: out.Data, Warnings: out.Warnings})
	} else {
		if out.Human != nil {
			out.Human(stdout)
		} else {
			writeJSON(stdout, out.Data)
		}
		for _, w := range out.Warnings {
			fmt.Fprintln(stderr, "warning:", w)
		}
	}
	return out.Exit
}

func emitError(rt *Runtime, name string, err error) int {
	e := classify(err)
	if e.exit == 0 {
		e.exit = ExitError
	}
	if rt.JSON {
		writeJSON(rt.Stdout, envelope{OK: false, Command: name, Schema: core.SchemaVersion, Error: e})
	} else {
		fmt.Fprintf(rt.Stderr, "error: %s\n", e.Message)
		if e.Hint != "" {
			fmt.Fprintf(rt.Stderr, "hint: %s\n", e.Hint)
		}
	}
	return e.exit
}

// classify maps errors onto stable codes with actionable hints.
func classify(err error) *Error {
	var e *Error
	var netErr net.Error
	var urlErr *url.Error
	switch {
	case errors.As(err, &e):
		return e
	case errors.Is(err, store.ErrNoScans):
		return &Error{Code: "no_data", Message: err.Error(), Hint: "run `syssec scan --vulns --json` to record a baseline"}
	case errors.Is(err, intel.ErrNotFound):
		return &Error{Code: "not_found", Message: err.Error(), Hint: "check the ID; list checks with `syssec checks --json`"}
	case errors.As(err, &urlErr), errors.As(err, &netErr):
		return &Error{Code: "network", Message: err.Error(), Hint: "check connectivity/proxy, or point SYSSEC_OSV_URL/SYSSEC_KEV_URL/SYSSEC_EPSS_URL at a mirror; offline commands (report, vulns, diff, history) still work"}
	}
	return &Error{Code: "runtime", Message: err.Error()}
}

func writeJSON(w io.Writer, v any) {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if f, ok := w.(*os.File); ok {
		if fi, err := f.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
			enc.SetIndent("", "  ") // pretty for terminals, compact for pipes/agents
		}
	}
	_ = enc.Encode(v)
}

// splitGlobals lets common flags appear before the command name.
func splitGlobals(args []string) (globals, rest []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") || a == "-h" || a == "--help" || a == "-help" {
			return globals, args[i:]
		}
		globals = append(globals, a)
		bare := strings.TrimLeft(a, "-")
		if bare == "db" && i+1 < len(args) {
			i++
			globals = append(globals, args[i])
		}
	}
	return globals, nil
}

func resolve(root *Command, args []string) (*Command, []string, []string) {
	cmd, path := root, []string{}
	for len(args) > 0 {
		next := find(cmd.Sub, args[0])
		if next == nil {
			break
		}
		cmd, path, args = next, append(path, next.Name), args[1:]
	}
	return cmd, path, args
}

func find(cs []*Command, name string) *Command {
	for _, c := range cs {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// parseInterleaved allows flags after positional arguments.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		if args[0] == "--" {
			return append(pos, args[1:]...), nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

func printHelp(w io.Writer, cmd *Command, path []string) {
	name := strings.TrimSpace("syssec " + strings.Join(path, " "))
	if cmd.Summary != "" {
		fmt.Fprintf(w, "%s — %s\n\n", name, cmd.Summary)
	}
	if len(cmd.Sub) > 0 {
		fmt.Fprintf(w, "Usage: %s <command> [flags]\n\nCommands:\n", name)
		for _, c := range cmd.Sub {
			fmt.Fprintf(w, "  %-12s %s\n", c.Name, c.Summary)
		}
		fmt.Fprintf(w, "\nEvery command accepts --json. `%s help <command>` for flags; `syssec describe --json` for the full machine-readable manifest.\n", name)
		return
	}
	fmt.Fprintf(w, "Usage: %s %s[flags]\n\nFlags:\n", name, strings.TrimSpace(cmd.Args+" "))
	for _, f := range flagsOf(cmd) {
		def := ""
		if f.Default != "" && f.Default != "false" {
			def = fmt.Sprintf(" (default %s)", f.Default)
		}
		fmt.Fprintf(w, "  --%-18s %s%s\n", f.Name, f.Usage, def)
	}
	if len(cmd.Examples) > 0 {
		fmt.Fprintln(w, "\nExamples:")
		for _, e := range cmd.Examples {
			fmt.Fprintln(w, "  "+e)
		}
	}
}

// FlagInfo describes a flag in the manifest.
type FlagInfo struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Default string `json:"default,omitempty"`
	Usage   string `json:"usage"`
}

func flagsOf(cmd *Command) []FlagInfo {
	fs := flag.NewFlagSet(cmd.Name, flag.ContinueOnError)
	fs.Bool("json", false, "emit a JSON envelope (also: SYSSEC_OUTPUT=json)")
	fs.String("db", "", "SQLite database path (or SYSSEC_DB)")
	cmd.Setup(fs)
	var out []FlagInfo
	fs.VisitAll(func(f *flag.Flag) {
		typ := strings.TrimSuffix(strings.TrimPrefix(fmt.Sprintf("%T", f.Value), "*flag."), "Value")
		out = append(out, FlagInfo{Name: f.Name, Type: typ, Default: f.DefValue, Usage: f.Usage})
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// csv splits a comma-separated flag value.
func csv(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// info describes one command for the manifest and for `--help --json`.
func info(c *Command, path []string) CommandInfo {
	return CommandInfo{Command: "syssec " + strings.Join(path, " "), Summary: c.Summary, Args: c.Args, Flags: flagsOf(c), Examples: c.Examples}
}

func parseSeverityFlag(name, v string) (core.Severity, error) {
	if v == "" {
		return core.SeverityUnknown, nil
	}
	s, err := core.ParseSeverity(v)
	if err != nil {
		return 0, usageError("valid: info, low, medium, high, critical", "--%s: %v", name, err)
	}
	return s, nil
}
