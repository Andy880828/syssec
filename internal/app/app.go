// Package app is the application layer: it wires infrastructure (host
// probes, SQLite, OSV/KEV/EPSS, waivers) into the use cases the CLI exposes.
// Nothing here formats output, and nothing here talks to people: alerting
// is the job of whichever agent or scheduler drives syssec.
package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/Andy880828/syssec/internal/checks"
	"github.com/Andy880828/syssec/internal/checks/builtin"
	"github.com/Andy880828/syssec/internal/config"
	"github.com/Andy880828/syssec/internal/core"
	"github.com/Andy880828/syssec/internal/diff"
	"github.com/Andy880828/syssec/internal/intel"
	"github.com/Andy880828/syssec/internal/inventory"
	"github.com/Andy880828/syssec/internal/reach"
	"github.com/Andy880828/syssec/internal/store"
	"github.com/Andy880828/syssec/internal/sysenv"
	"github.com/Andy880828/syssec/internal/version"
	"github.com/Andy880828/syssec/internal/waiver"
)

// App holds long-lived dependencies for one CLI invocation.
type App struct {
	Cfg      config.Config
	Env      *sysenv.Env
	Checks   *checks.Registry
	Warnings []string // non-fatal setup problems (e.g. malformed custom rules)

	http  *http.Client
	store *store.Store
}

// New builds the application with built-in and custom rules registered.
func New(ctx context.Context, cfg config.Config) *App {
	a := &App{
		Cfg:    cfg,
		Env:    sysenv.Detect(ctx),
		Checks: checks.NewRegistry(),
		http:   &http.Client{Timeout: cfg.HTTPTimeout},
	}
	builtin.Register(a.Checks)
	custom, errs := checks.LoadRules(cfg.RulesDirs...)
	for _, c := range custom {
		if err := a.Checks.Register(c); err != nil {
			errs = append(errs, err)
		}
	}
	for _, err := range errs {
		a.Warnings = append(a.Warnings, "custom rules: "+err.Error())
	}
	return a
}

// Store lazily opens the history database.
func (a *App) Store(ctx context.Context) (*store.Store, error) {
	if a.store == nil {
		s, err := store.Open(ctx, a.Cfg.DBPath)
		if err != nil {
			return nil, fmt.Errorf("open database %s: %w", a.Cfg.DBPath, err)
		}
		a.store = s
	}
	return a.store, nil
}

// Close releases resources.
func (a *App) Close() {
	if a.store != nil {
		a.store.Close()
	}
}

// Intel returns the vulnerability intelligence service.
func (a *App) Intel(ctx context.Context) (*intel.Service, error) {
	st, err := a.Store(ctx)
	if err != nil {
		return nil, err
	}
	return &intel.Service{
		OSV:         &intel.OSVClient{BaseURL: a.Cfg.OSVURL, HTTP: a.http, UserAgent: "syssec/" + version.Version},
		HTTP:        a.http,
		Cache:       st,
		KEVURL:      a.Cfg.KEVURL,
		EPSSURL:     a.Cfg.EPSSURL,
		Concurrency: 16,
		QueryTTL:    a.Cfg.IntelTTL,
	}, nil
}

// Waivers loads the accepted-risk file.
func (a *App) Waivers() (*waiver.File, error) { return waiver.Load(a.Cfg.WaiversPath) }

// ScanOptions selects what a scan does.
type ScanOptions struct {
	Filter  checks.Filter
	Vulns   bool
	Save    bool
	Refresh bool     // ignore the intel query cache TTL
	Paths   []string // directories to scan for lockfiles and Go binaries
}

// ScanOutcome is the result of the Scan use case.
type ScanOutcome struct {
	Report   *core.Report
	Diff     *diff.Diff // vs. previous complete scan; nil if none or not saved
	Match    *intel.MatchStats
	Warnings []string
}

// Scan runs checks, inventory and (optionally) vuln matching, applies
// waivers, persists the report and diffs it against the previous scan.
func (a *App) Scan(ctx context.Context, opt ScanOptions) (*ScanOutcome, error) {
	start := time.Now()
	opt.Filter.Platform = a.Env.GOOS
	selected := a.Checks.Select(opt.Filter)
	if len(selected) == 0 {
		return nil, errors.New("no checks match the given filters on this platform")
	}
	out := &ScanOutcome{Warnings: append([]string{}, a.Warnings...)}
	r := &core.Report{
		StartedAt:        start.UTC(),
		Host:             a.Env.Host,
		Partial:          opt.Filter.Restrictive(),
		Results:          checks.Engine{Timeout: 30 * time.Second}.Run(ctx, a.Env, selected),
		InventoryScanned: true,
	}
	pkgs, errs := inventory.Collect(ctx, a.Env)
	if len(opt.Paths) > 0 {
		lang, langErrs := inventory.CollectPaths(ctx, a.Env, opt.Paths)
		pkgs, errs = append(pkgs, lang...), append(errs, langErrs...)
		r.Paths = slices.Sorted(slices.Values(opt.Paths))
	}
	r.Packages = pkgs
	for _, e := range errs {
		r.Errors = append(r.Errors, e.Error())
	}
	if opt.Vulns {
		svc, err := a.Intel(ctx)
		if err != nil {
			return nil, err
		}
		if opt.Refresh {
			svc.QueryTTL = 0
		}
		if svc.KEVStale(ctx, 24*time.Hour) { // without KEV, P0 detection is blind
			if _, err := svc.SyncKEV(ctx); err != nil {
				out.Warnings = append(out.Warnings, "KEV refresh failed, P0 may be incomplete: "+err.Error())
			}
		}
		vulns, stats, err := svc.Match(ctx, r.Packages)
		out.Match = &stats
		out.Warnings = append(out.Warnings, stats.Warnings...)
		if err != nil {
			r.Errors = append(r.Errors, "vuln match: "+err.Error())
		} else {
			r.Vulns, r.VulnScanned = vulns, true
			if a.Env.GOOS == "linux" {
				a.annotateReachability(ctx, r)
			}
			if stats.Unmatchable == stats.Packages && stats.Packages > 0 {
				out.Warnings = append(out.Warnings, "no package on this host maps to an OSV ecosystem; vuln matching covers dpkg (Debian/Ubuntu), apk (Alpine), rpm (Rocky/Alma)")
			}
		}
	}
	if ws, err := a.Waivers(); err != nil {
		out.Warnings = append(out.Warnings, "waivers ignored: "+err.Error())
	} else {
		for _, id := range ws.Apply(r.Results, r.Vulns, time.Now()) {
			out.Warnings = append(out.Warnings, fmt.Sprintf("waiver for %s has expired and no longer applies", id))
		}
	}
	core.SortResults(r.Results)
	r.Summary = core.Summarize(r.Results, len(r.Packages), r.Vulns)
	r.DurationMS = time.Since(start).Milliseconds()
	out.Report = r

	if opt.Save && !r.Partial {
		st, err := a.Store(ctx)
		if err != nil {
			return nil, err
		}
		var prev *core.Report
		if id, err := st.LatestID(ctx, true); err == nil {
			prev, _ = st.LoadReport(ctx, id)
		}
		if _, err := st.SaveReport(ctx, r); err != nil {
			return nil, fmt.Errorf("save report: %w", err)
		}
		if prev != nil {
			out.Diff = diff.Compute(prev, r)
		}
	}
	return out, nil
}

// annotateReachability marks vulns whose package code is mapped by a
// running process, then re-prioritises: running + fixable + high is P1.
func (a *App) annotateReachability(ctx context.Context, r *core.Report) {
	u, err := reach.Scan(a.Env)
	if err != nil {
		r.Errors = append(r.Errors, "reachability: "+err.Error())
		return
	}
	owners := inventory.Owners(ctx, a.Env, u.Files(), reach.Canonicalizer(a.Env.FS))
	u.Annotate(r.Vulns, r.Packages, owners)
	for i := range r.Vulns {
		r.Vulns[i].Prioritize()
	}
	core.SortVulns(r.Vulns)
}

// LoadReport loads a stored scan (0 = latest).
func (a *App) LoadReport(ctx context.Context, id int64) (*core.Report, error) {
	st, err := a.Store(ctx)
	if err != nil {
		return nil, err
	}
	if id == 0 {
		if id, err = st.LatestID(ctx, false); err != nil {
			return nil, err
		}
	}
	return st.LoadReport(ctx, id)
}

// Diff compares two stored scans (0 = defaults: latest vs. the one before).
func (a *App) Diff(ctx context.Context, fromID, toID int64) (*diff.Diff, error) {
	st, err := a.Store(ctx)
	if err != nil {
		return nil, err
	}
	if toID == 0 {
		if toID, err = st.LatestID(ctx, true); err != nil {
			return nil, err
		}
	}
	if fromID == 0 {
		if fromID, err = st.PreviousID(ctx, toID); err != nil {
			return nil, err
		}
	}
	from, err := st.LoadReport(ctx, fromID)
	if err != nil {
		return nil, err
	}
	to, err := st.LoadReport(ctx, toID)
	if err != nil {
		return nil, err
	}
	return diff.Compute(from, to), nil
}
