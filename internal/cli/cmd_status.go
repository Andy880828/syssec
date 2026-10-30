package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"strings"
	"time"

	"github.com/Andy880828/syssec/internal/core"
	"github.com/Andy880828/syssec/internal/inventory"
	"github.com/Andy880828/syssec/internal/store"
	"github.com/Andy880828/syssec/internal/waiver"
)

// statusView answers "where do things stand and what should I do?" in one
// offline call — the recommended first command for an agent.
type statusView struct {
	Host     core.Host   `json:"host"`
	LastScan *lastScan   `json:"last_scan"`
	Intel    intelState  `json:"intel"`
	Waivers  waiverState `json:"waivers"`
	Next     []string    `json:"next_steps"`
}

type lastScan struct {
	ID         int64          `json:"scan_id"`
	AgeHours   float64        `json:"age_hours"`
	Score      int            `json:"score"`
	Grade      string         `json:"grade"`
	Failed     map[string]int `json:"failed_by_severity"`
	Vulns      int            `json:"vulns"`
	ByPriority map[string]int `json:"vulns_by_priority,omitempty"`
	VulnData   bool           `json:"vuln_scanned"`
	Regression *bool          `json:"regression,omitempty"` // vs. the previous complete scan
}

type intelState struct {
	OSVEcosystem string `json:"osv_ecosystem"`
	KEVEntries   int    `json:"kev_entries"`
	KEVSyncedAt  string `json:"kev_synced_at,omitempty"`
	Advisories   int    `json:"cached_advisories"`
	EPSSScores   int    `json:"epss_scores"`
}

type waiverState struct {
	Active  int      `json:"active"`
	Expired []string `json:"expired,omitempty"`
}

func statusCmd() *Command {
	return &Command{
		Name:     "status",
		Summary:  "one-call overview: last scan, regression, intel freshness, waivers, next steps (offline)",
		Examples: []string{"syssec status --json"},
		Setup: func(fs *flag.FlagSet) Handler {
			return func(ctx context.Context, rt *Runtime, _ []string) (*Output, error) {
				a := rt.App(ctx)
				st, err := a.Store(ctx)
				if err != nil {
					return nil, err
				}
				v := &statusView{Host: a.Env.Host}
				stats, err := st.Stats(ctx)
				if err != nil {
					return nil, err
				}
				v.Intel = intelState{OSVEcosystem: inventory.Ecosystem(a.Env), KEVEntries: stats.KEVEntries,
					KEVSyncedAt: stats.KEVSyncedAt, Advisories: stats.CachedVulns, EPSSScores: stats.EPSSScores}
				if ws, err := a.Waivers(); err == nil {
					for _, w := range ws.Waivers {
						if waiver.Expired(w, time.Now()) {
							v.Waivers.Expired = append(v.Waivers.Expired, w.ID)
						} else {
							v.Waivers.Active++
						}
					}
				}
				r, err := a.LoadReport(ctx, 0)
				switch {
				case errors.Is(err, store.ErrNoScans):
					v.Next = append(v.Next, "syssec scan --vulns --json  # no baseline yet")
				case err != nil:
					return nil, err
				default:
					s := r.Summary
					v.LastScan = &lastScan{ID: r.ID, AgeHours: math.Round(time.Since(r.StartedAt).Hours()*10) / 10,
						Score: s.Score, Grade: s.Grade, Failed: s.Failed, Vulns: s.Vulns, ByPriority: s.VulnsByPriority, VulnData: r.VulnScanned}
					if d, err := a.Diff(ctx, 0, r.ID); err == nil {
						reg := d.HasRegression()
						v.LastScan.Regression = &reg
						if reg {
							v.Next = append(v.Next, "syssec diff --json  # the last scan regressed")
						} else if len(d.Drifted) > 0 {
							v.Next = append(v.Next, fmt.Sprintf("syssec diff --json  # %d failing checks changed evidence (e.g. %s)", len(d.Drifted), d.Drifted[0].ID))
						}
					}
					if v.LastScan.AgeHours > 24 {
						v.Next = append(v.Next, "syssec scan --vulns --json  # last scan is over a day old")
					}
					v.Next = append(v.Next, nextSteps(r)...)
				}
				if v.Intel.KEVEntries == 0 {
					v.Next = append(v.Next, "syssec intel sync --json  # KEV catalog never synced: P0 detection is blind")
				}
				for _, id := range v.Waivers.Expired {
					v.Next = append(v.Next, fmt.Sprintf("syssec waive rm %s  # expired; renew with `waive add` or fix it", id))
				}
				if v.Next == nil {
					v.Next = []string{}
				}
				return &Output{Data: v, Human: func(w io.Writer) { renderStatus(w, v) }}, nil
			}
		},
	}
}

func renderStatus(w io.Writer, v *statusView) {
	h := v.Host
	fmt.Fprintf(w, "%s  %s  root=%v", h.Hostname, h.Pretty, h.Privileged)
	if h.Container != "" {
		fmt.Fprintf(w, "  container=%s", h.Container)
	}
	fmt.Fprintln(w)
	if s := v.LastScan; s != nil {
		reg := "n/a"
		if s.Regression != nil {
			reg = fmt.Sprint(*s.Regression)
		}
		fmt.Fprintf(w, "last scan #%d, %.1fh ago: score %d (%s), failed %s; vulns %d %s; regression %s\n",
			s.ID, s.AgeHours, s.Score, s.Grade, counts(s.Failed, "critical", "high", "medium", "low"), s.Vulns, counts(s.ByPriority, "P0", "P1", "P2", "P3"), reg)
	}
	fmt.Fprintf(w, "intel: ecosystem %q, KEV %d (synced %s), advisories %d, EPSS %d\n",
		v.Intel.OSVEcosystem, v.Intel.KEVEntries, v.Intel.KEVSyncedAt, v.Intel.Advisories, v.Intel.EPSSScores)
	fmt.Fprintf(w, "waivers: %d active, %d expired\n", v.Waivers.Active, len(v.Waivers.Expired))
	if len(v.Next) > 0 {
		fmt.Fprintln(w, "\nNext:")
		for _, n := range v.Next {
			fmt.Fprintln(w, "  "+n)
		}
	}
}

// counts renders a counter map in a fixed key order, e.g. "high 1, low 7".
func counts(m map[string]int, keys ...string) string {
	var parts []string
	for _, k := range keys {
		if m[k] > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", k, m[k]))
		}
	}
	if parts == nil {
		return "none"
	}
	return "(" + strings.Join(parts, ", ") + ")"
}
