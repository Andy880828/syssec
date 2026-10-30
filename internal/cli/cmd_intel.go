package cli

import (
	"context"
	"flag"
	"fmt"
	"io"

	"github.com/Andy880828/syssec/internal/intel"
	"github.com/Andy880828/syssec/internal/inventory"
)

func intelSyncCmd() *Command {
	return &Command{
		Name:     "sync",
		Summary:  "refresh CISA KEV and re-query OSV for every installed package (bypasses the query cache; EPSS refreshes daily)",
		Examples: []string{"syssec intel sync --json", "syssec intel sync --kev-only"},
		Setup: func(fs *flag.FlagSet) Handler {
			kevOnly := fs.Bool("kev-only", false, "only refresh the KEV catalog")
			return func(ctx context.Context, rt *Runtime, _ []string) (*Output, error) {
				a := rt.App(ctx)
				svc, err := a.Intel(ctx)
				if err != nil {
					return nil, err
				}
				svc.QueryTTL = 0 // sync always asks OSV for fresh answers
				data := map[string]any{}
				var warnings []string
				kev, err := svc.SyncKEV(ctx)
				if err != nil {
					warnings = append(warnings, err.Error())
				} else {
					data["kev"] = kev
				}
				var stats *intel.MatchStats
				vulnCount := 0
				if !*kevOnly {
					pkgs, errs := inventory.Collect(ctx, a.Env)
					for _, e := range errs {
						warnings = append(warnings, e.Error())
					}
					vulns, st, err := svc.Match(ctx, pkgs)
					if err != nil {
						return nil, err
					}
					stats, vulnCount = &st, len(vulns)
					data["osv"] = st
					data["vulns_found"] = vulnCount
				}
				if kev == nil && stats == nil {
					return nil, fmt.Errorf("sync failed: %v", warnings)
				}
				return &Output{Data: data, Warnings: warnings, Human: func(w io.Writer) {
					if kev != nil {
						state := "unchanged (304)"
						if kev.Updated {
							state = "updated"
						}
						fmt.Fprintf(w, "KEV: %d entries, catalog %s, %s\n", kev.Entries, kev.Version, state)
					}
					if stats != nil {
						fmt.Fprintf(w, "OSV: %d packages, %d queries, %d advisories (%d cached, %d fetched), %d affecting this host\n",
							stats.Packages, stats.Queries, stats.Advisories, stats.CacheHits, stats.Fetched, vulnCount)
						fmt.Fprintln(w, "Run `syssec scan --vulns` to record them in history.")
					}
				}}, nil
			}
		},
	}
}
