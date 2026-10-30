package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/Andy880828/syssec/internal/checks"
	"github.com/Andy880828/syssec/internal/core"
	"github.com/Andy880828/syssec/internal/intel"
	"github.com/Andy880828/syssec/internal/store"
)

func checksCmd() *Command {
	return &Command{
		Name:     "checks",
		Summary:  "list the check catalog (built-in + custom JSON rules)",
		Examples: []string{"syssec checks --json", "syssec checks --platform all --category ssh"},
		Setup: func(fs *flag.FlagSet) Handler {
			platform := fs.String("platform", "current", "current | all | linux | darwin | windows")
			category := fs.String("category", "", "comma-separated categories")
			minSev := fs.String("min-severity", "", "minimum severity")
			return func(ctx context.Context, rt *Runtime, _ []string) (*Output, error) {
				min, err := parseSeverityFlag("min-severity", *minSev)
				if err != nil {
					return nil, err
				}
				a := rt.App(ctx)
				f := checks.Filter{Categories: csv(*category), MinSeverity: min}
				switch *platform {
				case "current":
					f.Platform = a.Env.GOOS
				case "all":
				default:
					f.Platform = *platform
				}
				var metas []core.CheckMeta
				cats := map[string]int{}
				for _, c := range a.Checks.Select(f) {
					m := c.Meta()
					metas = append(metas, m)
					cats[m.Category]++
				}
				data := map[string]any{"count": len(metas), "categories": cats, "checks": metas}
				return &Output{Data: data, Warnings: a.Warnings, Human: func(w io.Writer) {
					t := table(w)
					for _, m := range metas {
						fmt.Fprintf(t, "%s\t%s\t%s\t%s\t%s\n", m.ID, m.Severity, m.Category, strings.Join(m.Platforms, ","), m.Title)
					}
					t.Flush()
					fmt.Fprintf(w, "\n%d checks\n", len(metas))
				}}, nil
			}
		},
	}
}

func explainCmd() *Command {
	return &Command{
		Name:    "explain",
		Summary: "explain a check (rationale, fix, status timeline) or an advisory (CVE/GHSA/DSA/...)",
		Args:    "<CHECK-ID | VULN-ID>",
		Examples: []string{
			"syssec explain SSH-002 --json",
			"syssec explain CVE-2024-3094 --json",
		},
		Setup: func(fs *flag.FlagSet) Handler {
			return func(ctx context.Context, rt *Runtime, args []string) (*Output, error) {
				if len(args) != 1 {
					return nil, usageError("e.g. `syssec explain SSH-001` or `syssec explain CVE-2024-3094`", "explain takes exactly one ID")
				}
				a := rt.App(ctx)
				id := args[0]
				if c, ok := a.Checks.Get(id); ok {
					return explainCheck(ctx, rt, c.Meta())
				}
				svc, err := a.Intel(ctx)
				if err != nil {
					return nil, err
				}
				d, err := svc.Lookup(ctx, strings.ToUpper(id))
				if err != nil {
					if err == intel.ErrNotFound {
						return nil, &Error{Code: "not_found", Message: fmt.Sprintf("%s is neither a check ID nor a known advisory", id), Hint: "list checks with `syssec checks`", exit: ExitError}
					}
					return nil, err
				}
				data := map[string]any{"kind": "advisory", "advisory": d}
				st, _ := a.Store(ctx)
				if sid, at, err := st.VulnFirstSeen(ctx, d.ID); err == nil && sid > 0 {
					data["first_seen"] = map[string]any{"scan_id": sid, "at": at}
				}
				return &Output{Data: data, Human: func(w io.Writer) {
					kev := ""
					if d.KEV != nil {
						kev = fmt.Sprintf("  ⚠ CISA KEV since %s (due %s, ransomware: %s)", d.KEV.DateAdded, d.KEV.DueDate, d.KEV.Ransomware)
					}
					score := ""
					if d.CVSS > 0 {
						score = fmt.Sprintf(", CVSS %.1f", d.CVSS)
					}
					fmt.Fprintf(w, "%s  [%s%s]%s\n%s\n", d.ID, d.Severity, score, kev, d.Summary)
					if len(d.Aliases) > 0 {
						fmt.Fprintf(w, "Aliases: %s\n", strings.Join(d.Aliases, ", "))
					}
					for _, af := range d.Affected {
						fmt.Fprintf(w, "Affected: %s (%s) fixed: %s\n", af.Package, af.Ecosystem, strings.Join(af.Fixed, ", "))
					}
					if d.Details != "" {
						fmt.Fprintf(w, "\n%s\n", indent(d.Details))
					}
					fmt.Fprintf(w, "\n%s\n", d.URL)
				}}, nil
			}
		},
	}
}

func explainCheck(ctx context.Context, rt *Runtime, m core.CheckMeta) (*Output, error) {
	data := map[string]any{"kind": "check", "check": m}
	var timeline []store.CheckPoint
	if st, err := rt.app.Store(ctx); err == nil {
		if pts, err := st.CheckHistory(ctx, m.ID, 10); err == nil && len(pts) > 0 {
			timeline = pts
			data["timeline"] = pts
			data["current_status"] = pts[0].Status
		}
	}
	return &Output{Data: data, Human: func(w io.Writer) {
		fmt.Fprintf(w, "%s  %s\nseverity: %s  category: %s  platforms: %s\n", m.ID, m.Title, m.Severity, m.Category, strings.Join(m.Platforms, ","))
		if m.Description != "" {
			fmt.Fprintf(w, "\n%s\n", m.Description)
		}
		if m.Remediation != "" {
			fmt.Fprintf(w, "\nFix: %s\n", m.Remediation)
		}
		for _, r := range m.References {
			fmt.Fprintf(w, "Ref: %s\n", r)
		}
		if len(timeline) > 0 {
			fmt.Fprintln(w, "\nHistory:")
			for _, p := range timeline {
				fmt.Fprintf(w, "  #%d %s %s %s\n", p.ScanID, p.StartedAt.Local().Format("2006-01-02 15:04"), p.Status, p.Evidence)
			}
		}
	}}, nil
}
