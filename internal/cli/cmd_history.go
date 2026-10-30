package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/Andy880828/syssec/internal/store"
)

type trend struct {
	Scans      int    `json:"scans"`
	FirstScore int    `json:"first_score"`
	LastScore  int    `json:"last_score"`
	Delta      int    `json:"delta"`
	Direction  string `json:"direction"` // improving | degrading | stable
	BestScore  int    `json:"best_score"`
	WorstScore int    `json:"worst_score"`
}

func computeTrend(scans []store.ScanInfo) *trend {
	var full []store.ScanInfo // newest first; trend only over complete scans
	for _, s := range scans {
		if !s.Partial {
			full = append(full, s)
		}
	}
	if len(full) == 0 {
		return nil
	}
	t := &trend{Scans: len(full), FirstScore: full[len(full)-1].Score, LastScore: full[0].Score, BestScore: -1, WorstScore: 101}
	for _, s := range full {
		t.BestScore, t.WorstScore = max(t.BestScore, s.Score), min(t.WorstScore, s.Score)
	}
	t.Delta = t.LastScore - t.FirstScore
	switch {
	case t.Delta > 0:
		t.Direction = "improving"
	case t.Delta < 0:
		t.Direction = "degrading"
	default:
		t.Direction = "stable"
	}
	return t
}

func historyCmd() *Command {
	return &Command{
		Name:     "history",
		Summary:  "list past scans with score trend, or one check's status timeline",
		Examples: []string{"syssec history --json", "syssec history --check SSH-001 --json"},
		Setup: func(fs *flag.FlagSet) Handler {
			limit := fs.Int("limit", 20, "number of scans")
			check := fs.String("check", "", "show the status timeline of this check ID")
			return func(ctx context.Context, rt *Runtime, _ []string) (*Output, error) {
				a := rt.App(ctx)
				st, err := a.Store(ctx)
				if err != nil {
					return nil, err
				}
				if *check != "" {
					pts, err := st.CheckHistory(ctx, *check, *limit)
					if err != nil {
						return nil, err
					}
					data := map[string]any{"check": strings.ToUpper(*check), "timeline": pts}
					return &Output{Data: data, Human: func(w io.Writer) {
						t := table(w)
						for _, p := range pts {
							fmt.Fprintf(t, "#%d\t%s\t%s %s\t%s\n", p.ScanID, p.StartedAt.Local().Format("2006-01-02 15:04"), statusIcon[p.Status], p.Status, p.Evidence)
						}
						t.Flush()
					}}, nil
				}
				scans, err := st.ListScans(ctx, *limit)
				if err != nil {
					return nil, err
				}
				if scans == nil {
					scans = []store.ScanInfo{}
				}
				tr := computeTrend(scans)
				data := map[string]any{"scans": scans, "trend": tr}
				return &Output{Data: data, Human: func(w io.Writer) {
					if len(scans) == 0 {
						fmt.Fprintln(w, "No scans yet. Run `syssec scan`.")
						return
					}
					t := table(w)
					fmt.Fprintln(t, "ID\tWHEN\tSCORE\tCRIT\tHIGH\tMED\tVULNS\tKEV\t")
					for _, s := range scans {
						vul := "-"
						if s.VulnScanned {
							vul = fmt.Sprint(s.Summary.Vulns)
						}
						p := ""
						if s.Partial {
							p = "(partial)"
						}
						fmt.Fprintf(t, "#%d\t%s\t%d %s\t%d\t%d\t%d\t%s\t%d\t%s\n", s.ID, s.StartedAt.Local().Format("2006-01-02 15:04"), s.Score, s.Grade,
							s.Summary.Failed["critical"], s.Summary.Failed["high"], s.Summary.Failed["medium"], vul, s.Summary.KEV, p)
					}
					t.Flush()
					if tr != nil {
						fmt.Fprintf(w, "\nTrend over %d scans: %d → %d (%+d, %s)\n", tr.Scans, tr.FirstScore, tr.LastScore, tr.Delta, tr.Direction)
					}
				}}, nil
			}
		},
	}
}

func diffCmd() *Command {
	return &Command{
		Name:     "diff",
		Summary:  "compare two saved scans (default: latest vs. previous)",
		Examples: []string{"syssec diff --json", "syssec diff --from 3 --to 9 --full --json"},
		Setup: func(fs *flag.FlagSet) Handler {
			from := fs.Int64("from", 0, "older scan ID (default: scan before --to)")
			to := fs.Int64("to", 0, "newer scan ID (default: latest complete scan)")
			full := fs.Bool("full", false, "do not truncate package/vuln lists")
			return func(ctx context.Context, rt *Runtime, _ []string) (*Output, error) {
				a := rt.App(ctx)
				d, err := a.Diff(ctx, *from, *to)
				if err != nil {
					return nil, err
				}
				limit := 30
				if *full {
					limit = 0
				}
				v := newDiffView(d, limit)
				return &Output{Data: v, Human: func(w io.Writer) { renderDiff(w, v) }}, nil
			}
		},
	}
}

func pruneCmd() *Command {
	return &Command{
		Name:     "prune",
		Summary:  "delete old scans, keeping the newest N",
		Examples: []string{"syssec prune --keep 50 --dry-run --json"},
		Setup: func(fs *flag.FlagSet) Handler {
			keep := fs.Int("keep", 100, "number of scans to keep")
			dry := fs.Bool("dry-run", false, "report what would be deleted without deleting")
			return func(ctx context.Context, rt *Runtime, _ []string) (*Output, error) {
				if *keep < 1 {
					return nil, usageError("", "--keep must be >= 1")
				}
				a := rt.App(ctx)
				st, err := a.Store(ctx)
				if err != nil {
					return nil, err
				}
				n, err := st.Prune(ctx, *keep, *dry)
				if err != nil {
					return nil, err
				}
				verb := "deleted"
				if *dry {
					verb = "would delete"
				}
				return &Output{Data: map[string]any{"deleted": n, "kept": *keep, "dry_run": *dry},
					Human: func(w io.Writer) { fmt.Fprintf(w, "%s %d scans\n", verb, n) }}, nil
			}
		},
	}
}
