package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/Andy880828/syssec/internal/app"
	"github.com/Andy880828/syssec/internal/checks"
	"github.com/Andy880828/syssec/internal/core"
)

// gate is a parsed --fail-on value: a severity (checks and vulns) or a
// priority P0..P3 (vulns only).
type gate struct {
	severity core.Severity
	priority string
}

func parseGate(v string) (*gate, error) {
	if v == "" {
		return nil, nil
	}
	if p := strings.ToUpper(v); validPriority(p) {
		return &gate{priority: p}, nil
	}
	s, err := parseSeverityFlag("fail-on", v)
	return &gate{severity: s}, err
}

func validPriority(p string) bool { return len(p) == 2 && p[0] == 'P' && p[1] >= '0' && p[1] <= '3' }

// breached ignores waived items: accepting a risk is how a gate is unblocked.
func (g *gate) breached(r *core.Report) bool {
	for _, res := range r.Results {
		if g.priority == "" && res.Status == core.StatusFail && res.Severity >= g.severity {
			return true
		}
	}
	for _, v := range r.Vulns {
		switch {
		case v.Waiver != nil:
		case g.priority != "" && v.Priority <= g.priority, g.priority == "" && v.Severity >= g.severity:
			return true
		}
	}
	return false
}

func scanCmd() *Command {
	return &Command{
		Name:    "scan",
		Summary: "run checks + package inventory (+ vulns), apply waivers, save, diff vs. last scan",
		Examples: []string{
			"sudo syssec scan --vulns --json",
			"syssec scan --category ssh,network --json   # partial: not saved",
			"syssec scan --vulns --fail-on P0 --json     # exit 3 on actively exploited vulns",
			"syssec scan --fail-on high --json           # exit 3 on high+ failed checks or vulns",
		},
		Setup: func(fs *flag.FlagSet) Handler {
			category := fs.String("category", "", "comma-separated categories (partial scan, not saved)")
			ids := fs.String("check", "", "comma-separated check IDs (partial scan, not saved)")
			vulns := fs.Bool("vulns", false, "match packages against OSV, enrich with KEV + EPSS (network on cache miss)")
			refresh := fs.Bool("refresh", false, "with --vulns: bypass the intel cache TTL")
			noSave := fs.Bool("no-save", false, "do not write to history")
			all := fs.Bool("all", false, "list passed, skipped and waived checks too")
			failOn := fs.String("fail-on", "", "exit 3 if a non-waived item reaches: severity (low..critical) or vuln priority (P0..P3)")
			return func(ctx context.Context, rt *Runtime, _ []string) (*Output, error) {
				g, err := parseGate(*failOn)
				if err != nil {
					return nil, err
				}
				res, err := rt.App(ctx).Scan(ctx, app.ScanOptions{
					Filter:  checks.Filter{IDs: csv(*ids), Categories: csv(*category)},
					Vulns:   *vulns,
					Save:    !*noSave,
					Refresh: *refresh,
				})
				if err != nil {
					return nil, err
				}
				v := newReportView(res.Report, *all, core.SeverityUnknown)
				v.Match, v.Diff = res.Match, newDiffView(res.Diff, 20)
				out := &Output{Data: v, Human: func(w io.Writer) { renderReport(w, v) }, Warnings: res.Warnings}
				if g != nil && g.breached(res.Report) {
					out.Exit = ExitFindings
				}
				return out, nil
			}
		},
	}
}

func reportCmd() *Command {
	return &Command{
		Name:     "report",
		Summary:  "show a saved scan without re-scanning (default: latest)",
		Examples: []string{"syssec report --json", "syssec report --id 12 --all --json"},
		Setup: func(fs *flag.FlagSet) Handler {
			id := fs.Int64("id", 0, "scan ID (default latest)")
			all := fs.Bool("all", false, "list passed, skipped and waived checks too")
			minSev := fs.String("min-severity", "", "only findings at or above this severity")
			return func(ctx context.Context, rt *Runtime, _ []string) (*Output, error) {
				min, err := parseSeverityFlag("min-severity", *minSev)
				if err != nil {
					return nil, err
				}
				r, err := rt.App(ctx).LoadReport(ctx, *id)
				if err != nil {
					return nil, err
				}
				v := newReportView(r, *all, min)
				return &Output{Data: v, Human: func(w io.Writer) { renderReport(w, v) }}, nil
			}
		},
	}
}

func vulnsCmd() *Command {
	return &Command{
		Name:    "vulns",
		Summary: "list vulnerabilities from a saved scan, prioritised (P0 KEV > P1 likely exploited > P2 > P3)",
		Examples: []string{
			"syssec vulns --priority P1 --json         # what to patch first",
			"syssec vulns --fixable --limit 0 --json   # everything patchable now",
			"syssec vulns --package openssl --json     # am I affected via openssl?",
		},
		Setup: func(fs *flag.FlagSet) Handler {
			id := fs.Int64("id", 0, "scan ID (default latest)")
			prio := fs.String("priority", "", "keep this priority and above (P0..P3)")
			minSev := fs.String("min-severity", "", "keep this severity and above (KEV always kept)")
			kev := fs.Bool("kev", false, "only CISA KEV (actively exploited)")
			fixable := fs.Bool("fixable", false, "only vulns with a published fixed version")
			pkg := fs.String("package", "", "substring match on package name")
			waived := fs.Bool("waived", false, "include waived vulns")
			limit := fs.Int("limit", 50, "max vulns returned (0 = all)")
			return func(ctx context.Context, rt *Runtime, _ []string) (*Output, error) {
				min, err := parseSeverityFlag("min-severity", *minSev)
				if err != nil {
					return nil, err
				}
				p := strings.ToUpper(*prio)
				if p != "" && !validPriority(p) {
					return nil, usageError("use P0, P1, P2 or P3", "invalid --priority %q", *prio)
				}
				r, err := rt.App(ctx).LoadReport(ctx, *id)
				if err != nil {
					return nil, err
				}
				if !r.VulnScanned {
					return nil, &Error{Code: "no_data", Message: fmt.Sprintf("scan #%d has no vulnerability data", r.ID), Hint: "run `syssec scan --vulns --json`"}
				}
				f := vulnFilter{MinSeverity: min, MaxPriority: p, KEV: *kev, Fixable: *fixable, Package: *pkg, Waived: *waived}
				matched := f.apply(r.Vulns)
				shown := matched
				if *limit > 0 && len(shown) > *limit {
					shown = shown[:*limit]
				}
				data := map[string]any{"scan_id": r.ID, "total": len(matched), "returned": len(shown), "vulns": shown}
				return &Output{Data: data, Human: func(w io.Writer) {
					renderVulns(w, shown)
					fmt.Fprintf(w, "\n%d of %d shown (scan #%d)\n", len(shown), len(matched), r.ID)
				}}, nil
			}
		},
	}
}
