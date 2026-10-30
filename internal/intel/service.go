package intel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Andy880828/syssec/internal/core"
)

// Cache is the persistence port the intel service needs. The SQLite store
// implements it; tests can use an in-memory map.
type Cache interface {
	GetVuln(ctx context.Context, id string) (raw []byte, modified string, ok bool, err error)
	PutVuln(ctx context.Context, id, modified string, raw []byte) error
	KEV(ctx context.Context, cve string) (*core.KEVEntry, error)
	KEVIDs(ctx context.Context) (map[string]bool, error)
	ReplaceKEV(ctx context.Context, entries []core.KEVEntry) error
	Meta(ctx context.Context, key string) (string, error)
	SetMeta(ctx context.Context, key, value string) error
	// GetQuery/PutQuery cache querybatch answers per package version.
	GetQuery(ctx context.Context, key string) (refs []byte, fetchedAt time.Time, ok bool, err error)
	PutQuery(ctx context.Context, key string, refs []byte) error
	PurgeVulns(ctx context.Context) error
	// EPSS returns cached scores and which of them are newer than freshAfter.
	EPSS(ctx context.Context, cves []string, freshAfter time.Time) (map[string]core.EPSSScore, map[string]bool, error)
	// PutEPSS records scores; CVEs in asked but absent from got are stored as
	// unscored so they are not re-requested until the TTL passes.
	PutEPSS(ctx context.Context, asked []string, got []core.EPSSScore) error
}

// advisoryFormat versions the Slim projection; bump it whenever OSVVuln
// gains a field so stale cached copies are discarded.
const advisoryFormat = "2"

// Service orchestrates OSV matching, advisory caching and KEV enrichment.
type Service struct {
	OSV         *OSVClient
	HTTP        *http.Client
	Cache       Cache
	KEVURL      string
	EPSSURL     string
	Concurrency int
	// QueryTTL is how long a package version's advisory list is trusted
	// before OSV is asked again. Zero forces a refresh.
	QueryTTL time.Duration

	formatOnce sync.Once
	formatErr  error
}

// ensureFormat purges cached advisories written by an older projection.
func (s *Service) ensureFormat(ctx context.Context) error {
	s.formatOnce.Do(func() {
		cur, err := s.Cache.Meta(ctx, "advisory_format")
		if err != nil || cur == advisoryFormat {
			s.formatErr = err
			return
		}
		if s.formatErr = s.Cache.PurgeVulns(ctx); s.formatErr == nil {
			s.formatErr = s.Cache.SetMeta(ctx, "advisory_format", advisoryFormat)
		}
	})
	return s.formatErr
}

// MatchStats describes the cost of a match run.
type MatchStats struct {
	Packages    int      `json:"packages"`
	Unmatchable int      `json:"unmatchable"` // no OSV ecosystem for this manager/distro
	Queries     int      `json:"queries"`
	Excluded    int      `json:"excluded"`       // build-time-only packages (kernel headers, sources)
	QueryCached int      `json:"queries_cached"` // answered from the local query cache (no network)
	Advisories  int      `json:"advisories"`
	CacheHits   int      `json:"cache_hits"`
	Fetched     int      `json:"fetched"`
	Merged      int      `json:"merged"` // duplicate advisories folded into one CVE
	Warnings    []string `json:"warnings,omitempty"`
}

// Runtime reports whether a package ships code that runs on this host.
// Kernel headers and kernel source packages map to the kernel's source
// package, which drags thousands of kernel CVEs into hosts (and containers)
// that never run that kernel. The running kernel is still covered through
// linux-image-* / kernel packages.
func Runtime(p core.Package) bool {
	n := p.Name
	switch {
	case n == "linux-libc-dev", n == "kernel-headers", n == "linux-headers",
		strings.HasPrefix(n, "linux-headers-"), strings.HasPrefix(n, "linux-source-"),
		strings.HasPrefix(n, "linux-tools-common"), strings.HasSuffix(n, "-doc"):
		return false
	}
	return true
}

// Match returns the vulnerabilities affecting pkgs.
func (s *Service) Match(ctx context.Context, pkgs []core.Package) ([]core.Vuln, MatchStats, error) {
	st := MatchStats{Packages: len(pkgs)}
	if err := s.ensureFormat(ctx); err != nil {
		return nil, st, err
	}
	type key struct{ eco, name, ver string }
	var queries []Query
	seen := map[key]bool{}
	paths := map[key][]string{} // lockfiles/binaries a language package came from
	for _, p := range pkgs {
		if p.Ecosystem == "" {
			st.Unmatchable++
			continue
		}
		if !Runtime(p) {
			st.Excluded++
			continue
		}
		name, ver := p.Query()
		k := key{p.Ecosystem, name, ver}
		if p.Path != "" && !slices.Contains(paths[k], p.Path) {
			paths[k] = append(paths[k], p.Path)
		}
		if !seen[k] {
			seen[k] = true
			queries = append(queries, Query{Name: name, Ecosystem: p.Ecosystem, Version: ver})
		}
	}
	st.Queries = len(queries)
	if len(queries) == 0 {
		return nil, st, nil
	}
	hits, cached, err := s.queryCached(ctx, queries)
	st.QueryCached = cached
	if err != nil {
		return nil, st, err
	}
	refs := map[string]string{}
	for _, hs := range hits {
		for _, h := range hs {
			refs[h.ID] = h.Modified
		}
	}
	st.Advisories = len(refs)
	advisories, hitsN, fetched, err := s.resolve(ctx, refs)
	st.CacheHits, st.Fetched = hitsN, fetched
	if err != nil {
		return nil, st, err
	}
	kev, err := s.Cache.KEVIDs(ctx)
	if err != nil {
		return nil, st, err
	}
	s.backfillSeverity(ctx, advisories)

	var raw []core.Vuln
	for i, q := range queries {
		for _, h := range hits[i] {
			a, ok := advisories[h.ID]
			if !ok {
				continue
			}
			v := core.Vuln{
				ID: a.raw.ID, Package: q.Name, Version: q.Version, Ecosystem: q.Ecosystem,
				Severity: a.severity, CVSS: a.cvss, FixedIn: fixedVersion(a.raw, q.Name, q.Ecosystem),
				Summary: summarize(a.raw), Aliases: cveAliases(a.raw),
				Path: joinPaths(paths[key{q.Ecosystem, q.Name, q.Version}]),
			}
			for _, id := range append([]string{v.ID}, v.Aliases...) {
				v.KEV = v.KEV || kev[id]
			}
			raw = append(raw, v)
		}
	}
	out := mergeByCVE(raw)
	st.Merged = len(raw) - len(out)
	if err := s.enrichEPSS(ctx, out); err != nil {
		st.Warnings = append(st.Warnings, "EPSS enrichment skipped: "+err.Error())
	}
	for i := range out {
		out[i].Prioritize()
	}
	core.SortVulns(out)
	return out, st, nil
}

// joinPaths renders where a language package was found, capped at three.
func joinPaths(ps []string) string {
	slices.Sort(ps)
	if len(ps) > 3 {
		return strings.Join(ps[:3], ",") + fmt.Sprintf(",+%d more", len(ps)-3)
	}
	return strings.Join(ps, ",")
}

// mergeByCVE collapses advisories that describe the same CVE on the same
// package (e.g. USN-8956-1 and UBUNTU-CVE-2026-111497) into one finding
// keyed by the CVE, keeping the other advisory IDs as aliases.
func mergeByCVE(in []core.Vuln) []core.Vuln {
	var out []core.Vuln
	index := map[string]int{} // package|CVE -> position in out
	for _, v := range in {
		at := -1
		for _, c := range v.Aliases {
			if i, ok := index[v.Package+v.Path+"|"+c]; ok {
				at = i
				break
			}
		}
		if at < 0 {
			if len(v.Aliases) > 0 && v.ID != v.Aliases[0] {
				v.Aliases = append(v.Aliases, v.ID)
				v.ID = v.Aliases[0]
			}
			out = append(out, v)
			at = len(out) - 1
		} else {
			m := &out[at]
			m.KEV = m.KEV || v.KEV
			if v.Severity > m.Severity || v.CVSS > m.CVSS {
				m.Severity, m.CVSS = max(m.Severity, v.Severity), max(m.CVSS, v.CVSS)
			}
			if m.FixedIn == "" {
				m.FixedIn = v.FixedIn
			}
			if len(v.Summary) > len(m.Summary) {
				m.Summary = v.Summary
			}
			for _, a := range append([]string{v.ID}, v.Aliases...) {
				if a != m.ID && !slices.Contains(m.Aliases, a) {
					m.Aliases = append(m.Aliases, a)
				}
			}
		}
		for _, c := range out[at].Aliases {
			index[v.Package+v.Path+"|"+c] = at
		}
		index[v.Package+v.Path+"|"+out[at].ID] = at
	}
	for i := range out { // the ID is never repeated in its own alias list
		out[i].Aliases = slices.DeleteFunc(out[i].Aliases, func(a string) bool { return a == out[i].ID })
	}
	return out
}

func (q Query) cacheKey() string { return q.Ecosystem + "|" + q.Name + "|" + q.Version }

// queryCached answers fresh queries from the cache and sends only stale or
// unseen package versions to OSV.
func (s *Service) queryCached(ctx context.Context, qs []Query) ([][]VulnRef, int, error) {
	out := make([][]VulnRef, len(qs))
	var missQ []Query
	var missI []int
	for i, q := range qs {
		if s.QueryTTL > 0 {
			raw, at, ok, err := s.Cache.GetQuery(ctx, q.cacheKey())
			if err == nil && ok && time.Since(at) < s.QueryTTL && json.Unmarshal(raw, &out[i]) == nil {
				continue
			}
		}
		missQ, missI = append(missQ, q), append(missI, i)
	}
	if len(missQ) == 0 {
		return out, len(qs), nil
	}
	hits, err := s.OSV.QueryBatch(ctx, missQ)
	if err != nil {
		return nil, 0, err
	}
	for j, i := range missI {
		out[i] = hits[j]
		raw, _ := json.Marshal(hits[j])
		if err := s.Cache.PutQuery(ctx, missQ[j].cacheKey(), raw); err != nil {
			return nil, 0, err
		}
	}
	return out, len(qs) - len(missQ), nil
}

type advisory struct {
	raw      OSVVuln
	severity core.Severity
	cvss     float64
}

// resolve loads advisories from cache when their modified stamp matches,
// fetching only new or changed ones.
func (s *Service) resolve(ctx context.Context, refs map[string]string) (map[string]*advisory, int, int, error) {
	out := map[string]*advisory{}
	var mu sync.Mutex
	var hits, fetched int
	var firstErr error
	sem := make(chan struct{}, max(s.Concurrency, 1))
	var wg sync.WaitGroup
	for id, modified := range refs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			a, fromCache, err := s.load(ctx, id, modified)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil && !errors.Is(err, ErrNotFound) {
					firstErr = err
				}
				return
			}
			if fromCache {
				hits++
			} else {
				fetched++
			}
			out[id] = a
		}()
	}
	wg.Wait()
	return out, hits, fetched, firstErr
}

// load returns an advisory; modified=="" accepts any cached copy.
func (s *Service) load(ctx context.Context, id, modified string) (*advisory, bool, error) {
	raw, cachedMod, ok, err := s.Cache.GetVuln(ctx, id)
	if err != nil {
		return nil, false, err
	}
	fromCache := ok && (modified == "" || sameInstant(cachedMod, modified))
	if !fromCache {
		if raw, err = s.OSV.Vuln(ctx, id); err != nil {
			return nil, false, err
		}
	}
	var v OSVVuln
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, false, fmt.Errorf("decode %s: %w", id, err)
	}
	if !fromCache {
		slim, err := json.Marshal(Slim(v))
		if err != nil {
			return nil, false, err
		}
		if err := s.Cache.PutVuln(ctx, id, v.Modified, slim); err != nil {
			return nil, false, err
		}
	}
	sev, score := Severity(v)
	return &advisory{raw: v, severity: sev, cvss: score}, fromCache, nil
}

// sameInstant compares OSV timestamps: querybatch reports microseconds
// while full records carry nanoseconds, so exact string equality misses.
func sameInstant(a, b string) bool {
	if a == b {
		return true
	}
	ta, errA := time.Parse(time.RFC3339Nano, a)
	tb, errB := time.Parse(time.RFC3339Nano, b)
	return errA == nil && errB == nil && ta.Truncate(time.Microsecond).Equal(tb.Truncate(time.Microsecond))
}

// Slim drops everything syssec never reads (per-version lists, binary
// package maps, long prose). Distro kernel advisories shrink from ~1 MB to
// a few KB, keeping the cache small and decoding fast.
func Slim(v OSVVuln) OSVVuln {
	keep := func(m map[string]any, keys ...string) map[string]any {
		var out map[string]any
		for _, k := range keys {
			if val, ok := m[k]; ok {
				if out == nil {
					out = map[string]any{}
				}
				out[k] = val
			}
		}
		return out
	}
	if len(v.Details) > 2000 {
		v.Details = v.Details[:2000]
	}
	if len(v.References) > 10 {
		v.References = v.References[:10]
	}
	v.DatabaseSpecific = keep(v.DatabaseSpecific, "severity")
	for i := range v.Affected {
		a := &v.Affected[i]
		a.EcosystemSpecific = keep(a.EcosystemSpecific, "severity", "urgency")
		a.DatabaseSpecific = keep(a.DatabaseSpecific, "severity")
		for j := range a.Ranges {
			if a.Ranges[j].Type == "GIT" {
				a.Ranges[j].Events = nil
			}
		}
	}
	return v
}

// backfillSeverity resolves distro advisories (DSA/USN/DEBIAN-CVE...) that
// carry no rating by looking at their upstream CVE record, which is cached too.
func (s *Service) backfillSeverity(ctx context.Context, advs map[string]*advisory) {
	// First borrow ratings from sibling advisories for the same CVE
	// (e.g. USN-xxxx inherits from UBUNTU-CVE-yyyy) — no network needed.
	best := map[string]*advisory{}
	for _, a := range advs {
		for _, c := range cveAliases(a.raw) {
			if b := best[c]; b == nil || a.severity > b.severity {
				best[c] = a
			}
		}
	}
	for _, a := range advs {
		if a.severity != core.SeverityUnknown {
			continue
		}
		for _, c := range cveAliases(a.raw) {
			if b := best[c]; b != nil && b.severity > a.severity {
				a.severity, a.cvss = b.severity, b.cvss
			}
		}
	}
	sem := make(chan struct{}, max(s.Concurrency, 1))
	var wg sync.WaitGroup
	for _, a := range advs {
		if a.severity != core.SeverityUnknown {
			continue
		}
		var cves []string
		for _, c := range cveAliases(a.raw) {
			if c != a.raw.ID {
				cves = append(cves, c)
			}
		}
		if len(cves) == 0 {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			for _, c := range cves[:min(len(cves), 3)] {
				if up, _, err := s.load(ctx, c, ""); err == nil && up.severity > a.severity {
					a.severity, a.cvss = up.severity, up.cvss
				}
			}
		}()
	}
	wg.Wait()
}

// Severity derives a qualitative rating and best CVSS v3 score.
func Severity(v OSVVuln) (core.Severity, float64) {
	best := 0.0
	scan := func(typ, score string) {
		if strings.HasPrefix(typ, "CVSS_V3") {
			if s, err := CVSS3Base(score); err == nil && s > best {
				best = s
			}
		}
	}
	for _, s := range v.Severity {
		scan(s.Type, s.Score)
	}
	for _, a := range v.Affected {
		for _, s := range a.Severity {
			scan(s.Type, s.Score)
		}
	}
	if best > 0 {
		return core.SeverityFromCVSS(best), best
	}
	// Vendor qualitative ratings: GHSA/OSV database_specific, Ubuntu priority, Debian urgency.
	labels := []any{v.DatabaseSpecific["severity"]}
	for _, s := range v.Severity {
		if s.Type == "Ubuntu" {
			labels = append(labels, s.Score)
		}
	}
	for _, a := range v.Affected {
		labels = append(labels, a.EcosystemSpecific["severity"], a.EcosystemSpecific["urgency"], a.DatabaseSpecific["severity"])
	}
	sev := core.SeverityUnknown
	for _, l := range labels {
		if str, ok := l.(string); ok {
			if s, err := core.ParseSeverity(strings.TrimSuffix(str, "*")); err == nil && s > sev {
				sev = s
			}
		}
	}
	return sev, 0
}

func fixedVersion(v OSVVuln, pkg, ecosystem string) string {
	for _, a := range v.Affected {
		if a.Package.Name != pkg || a.Package.Ecosystem != ecosystem {
			continue
		}
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					return e.Fixed
				}
			}
		}
	}
	return ""
}

func summarize(v OSVVuln) string {
	s := v.Summary
	if s == "" {
		s = v.Details
	}
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 160 {
		s = s[:157] + "..."
	}
	return s
}

func cveAliases(v OSVVuln) []string {
	var out []string
	for _, a := range slices.Concat([]string{v.ID}, v.Aliases, v.Upstream, v.Related) {
		if strings.HasPrefix(a, "CVE-") && !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return out
}

// Detail is the agent-facing view of a single advisory.
type Detail struct {
	ID         string          `json:"id"`
	Summary    string          `json:"summary"`
	Details    string          `json:"details,omitempty"`
	Severity   core.Severity   `json:"severity"`
	CVSS       float64         `json:"cvss,omitempty"`
	Aliases    []string        `json:"aliases,omitempty"`
	Published  string          `json:"published,omitempty"`
	Modified   string          `json:"modified,omitempty"`
	Affected   []AffectedPkg   `json:"affected,omitempty"`
	References []string        `json:"references,omitempty"`
	KEV        *core.KEVEntry  `json:"kev,omitempty"`
	EPSS       *core.EPSSScore `json:"epss,omitempty"`
	URL        string          `json:"url"`
}

// AffectedPkg summarises one affected package entry.
type AffectedPkg struct {
	Package   string   `json:"package"`
	Ecosystem string   `json:"ecosystem"`
	Fixed     []string `json:"fixed,omitempty"`
}

// Lookup returns an advisory, from the cache when present.
func (s *Service) Lookup(ctx context.Context, id string) (*Detail, error) {
	id = strings.TrimSpace(id)
	if err := s.ensureFormat(ctx); err != nil {
		return nil, err
	}
	var a *advisory
	if raw, _, ok, err := s.Cache.GetVuln(ctx, id); err == nil && ok {
		var v OSVVuln
		if err := json.Unmarshal(raw, &v); err == nil {
			sev, score := Severity(v)
			a = &advisory{raw: v, severity: sev, cvss: score}
		}
	}
	if a == nil {
		var err error
		if a, _, err = s.load(ctx, id, ""); err != nil {
			return nil, err
		}
	}
	s.backfillSeverity(ctx, map[string]*advisory{id: a})
	v := a.raw
	d := &Detail{
		ID: v.ID, Summary: summarize(v), Severity: a.severity, CVSS: a.cvss,
		Aliases: v.Aliases, Published: v.Published, Modified: v.Modified,
		URL: "https://osv.dev/vulnerability/" + v.ID,
	}
	if d.Details = strings.TrimSpace(v.Details); len(d.Details) > 1500 {
		d.Details = d.Details[:1497] + "..."
	}
	for _, af := range v.Affected {
		if af.Package.Name == "" {
			continue // upstream CVE records describe git ranges, not packages
		}
		ap := AffectedPkg{Package: af.Package.Name, Ecosystem: af.Package.Ecosystem}
		for _, r := range af.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					ap.Fixed = append(ap.Fixed, e.Fixed)
				}
			}
		}
		if len(d.Affected) < 10 {
			d.Affected = append(d.Affected, ap)
		}
	}
	for _, r := range v.References {
		if len(d.References) < 8 {
			d.References = append(d.References, r.URL)
		}
	}
	cves := cveAliases(v)
	for _, cve := range cves {
		if k, err := s.Cache.KEV(ctx, cve); err == nil && k != nil {
			d.KEV = k
			break
		}
	}
	if len(cves) > 0 {
		if scores, err := s.epss(ctx, cves[:1]); err == nil {
			if e, ok := scores[cves[0]]; ok {
				d.EPSS = &e
			}
		}
	}
	return d, nil
}
