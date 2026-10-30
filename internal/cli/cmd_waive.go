package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Andy880828/syssec/internal/core"
	"github.com/Andy880828/syssec/internal/waiver"
)

func waiveCmd() *Command {
	return &Command{
		Name:    "waive",
		Summary: "accepted-risk exceptions (waivers.json): waived items keep evidence but leave score, gates and lists",
		Sub:     []*Command{waiveAddCmd(), waiveRmCmd(), waiveListCmd()},
	}
}

func waiveAddCmd() *Command {
	return &Command{
		Name:    "add",
		Summary: "accept a risk for a check ID, advisory ID or CVE (takes effect on the next scan)",
		Args:    "<ID>",
		Examples: []string{
			`syssec waive add NET-101 --reason "Docker host: forwarding required" --expires 180d`,
			`syssec waive add CVE-2024-1234 --package openssl --reason "not reachable: no TLS server" --expires 2026-12-31`,
		},
		Setup: func(fs *flag.FlagSet) Handler {
			reason := fs.String("reason", "", "why the risk is accepted (required)")
			expires := fs.String("expires", "", "YYYY-MM-DD or Nd (e.g. 90d); empty = never")
			pkg := fs.String("package", "", "vulns only: restrict to this package")
			return func(ctx context.Context, rt *Runtime, args []string) (*Output, error) {
				if len(args) != 1 || strings.TrimSpace(*reason) == "" {
					return nil, usageError(`e.g. syssec waive add NET-101 --reason "docker host" --expires 90d`, "waive add needs exactly one ID and --reason")
				}
				now := time.Now()
				exp, err := waiver.ParseExpiry(*expires, now)
				if err != nil {
					return nil, usageError("", "--expires: %v", err)
				}
				a := rt.App(ctx)
				f, err := a.Waivers()
				if err != nil {
					return nil, err
				}
				w := core.Waiver{ID: strings.ToUpper(args[0]), Package: *pkg, Reason: *reason, Expires: exp, Created: now.Format(time.DateOnly)}
				f.Put(w)
				if err := f.Save(a.Cfg.WaiversPath); err != nil {
					return nil, err
				}
				var warnings []string
				if _, isCheck := a.Checks.Get(w.ID); !isCheck && !strings.Contains(w.ID, "-") {
					warnings = append(warnings, w.ID+" does not look like a check or advisory ID")
				}
				return &Output{Data: map[string]any{"waiver": w, "path": a.Cfg.WaiversPath}, Warnings: warnings,
					Human: func(out io.Writer) { fmt.Fprintf(out, "waived %s until %s\n", w.ID, orNever(w.Expires)) }}, nil
			}
		},
	}
}

func waiveRmCmd() *Command {
	return &Command{
		Name:    "rm",
		Summary: "remove a waiver (takes effect on the next scan)",
		Args:    "<ID>",
		Setup: func(fs *flag.FlagSet) Handler {
			pkg := fs.String("package", "", "only remove the waiver scoped to this package (default: all for the ID)")
			return func(ctx context.Context, rt *Runtime, args []string) (*Output, error) {
				if len(args) != 1 {
					return nil, usageError("", "waive rm needs exactly one ID")
				}
				a := rt.App(ctx)
				f, err := a.Waivers()
				if err != nil {
					return nil, err
				}
				n := f.Remove(args[0], *pkg)
				if n == 0 {
					return nil, &Error{Code: "not_found", Message: "no waiver for " + args[0], Hint: "list them with `syssec waive list --json`"}
				}
				if err := f.Save(a.Cfg.WaiversPath); err != nil {
					return nil, err
				}
				return &Output{Data: map[string]any{"removed": n},
					Human: func(out io.Writer) { fmt.Fprintf(out, "removed %d waiver(s)\n", n) }}, nil
			}
		},
	}
}

func waiveListCmd() *Command {
	return &Command{
		Name:    "list",
		Summary: "list waivers with their expiry state",
		Setup: func(fs *flag.FlagSet) Handler {
			return func(ctx context.Context, rt *Runtime, _ []string) (*Output, error) {
				a := rt.App(ctx)
				f, err := a.Waivers()
				if err != nil {
					return nil, err
				}
				type row struct {
					core.Waiver
					Expired bool `json:"expired"`
				}
				rows := []row{}
				for _, w := range f.Waivers {
					rows = append(rows, row{w, waiver.Expired(w, time.Now())})
				}
				return &Output{Data: map[string]any{"waivers": rows, "path": a.Cfg.WaiversPath}, Human: func(out io.Writer) {
					t := table(out)
					for _, r := range rows {
						state := "active"
						if r.Expired {
							state = "EXPIRED"
						}
						fmt.Fprintf(t, "%s\t%s\t%s\t%s\t%s\n", r.ID, r.Package, orNever(r.Expires), state, r.Reason)
					}
					t.Flush()
				}}, nil
			}
		},
	}
}

func orNever(s string) string {
	if s == "" {
		return "never"
	}
	return s
}
