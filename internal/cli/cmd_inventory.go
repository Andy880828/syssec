package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/Andy880828/syssec/internal/core"
	"github.com/Andy880828/syssec/internal/inventory"
)

func inventoryCmd() *Command {
	return &Command{
		Name:     "inventory",
		Summary:  "list installed packages (dpkg, rpm, apk, pacman, Homebrew, Windows)",
		Examples: []string{"syssec inventory --json --limit 0", "syssec inventory --filter openssl --json"},
		Setup: func(fs *flag.FlagSet) Handler {
			filter := fs.String("filter", "", "case-insensitive substring match on name")
			manager := fs.String("manager", "", "only this package manager")
			limit := fs.Int("limit", 100, "max packages listed (0 = all)")
			return func(ctx context.Context, rt *Runtime, _ []string) (*Output, error) {
				a := rt.App(ctx)
				pkgs, errs := inventory.Collect(ctx, a.Env)
				byMgr := map[string]int{}
				matchable := 0
				var shown []core.Package
				omitted := 0
				for _, p := range pkgs {
					byMgr[p.Manager]++
					if p.Ecosystem != "" {
						matchable++
					}
					if *manager != "" && p.Manager != *manager {
						continue
					}
					if *filter != "" && !strings.Contains(strings.ToLower(p.Name), strings.ToLower(*filter)) {
						continue
					}
					if *limit > 0 && len(shown) >= *limit {
						omitted++
						continue
					}
					shown = append(shown, p)
				}
				if shown == nil {
					shown = []core.Package{}
				}
				var warnings []string
				for _, e := range errs {
					warnings = append(warnings, e.Error())
				}
				data := map[string]any{
					"total": len(pkgs), "by_manager": byMgr, "osv_ecosystem": inventory.Ecosystem(a.Env),
					"vuln_matchable": matchable, "packages": shown, "omitted": omitted,
				}
				return &Output{Data: data, Warnings: warnings, Human: func(w io.Writer) {
					t := table(w)
					for _, p := range shown {
						fmt.Fprintf(t, "%s\t%s\t%s\t%s\n", p.Manager, p.Name, p.Version, p.Arch)
					}
					t.Flush()
					fmt.Fprintf(w, "\n%d packages total (%d matchable against OSV)", len(pkgs), matchable)
					if omitted > 0 {
						fmt.Fprintf(w, ", %d not shown (use --limit 0)", omitted)
					}
					fmt.Fprintln(w)
				}}, nil
			}
		},
	}
}
