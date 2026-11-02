package intel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
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
	Packages    int `json:"packages"`
	Unmatchable int `json:"unmatchable"` // no OSV ecosystem for this manager/distro
	Queries     int `json:"queries"`
	Excluded    int `json:"excluded"`       // build-time-only packages (kernel headers, sources)
	QueryCached int `json:"queries_cached"` // answered from the local query cache (no network)
	Advisories  int `json:"advisories"`
	CacheHits   int `json:"cache_hits"`
	Fetched     int `json:"fetched"`
	Merged      int `json:"merged"`  // rows for the same CVE folded together
	Rollups     int `json:"rollups"` // advisories covering several CVEs, expanded per CVE
	// CVE records read to rate unrated findings, and how many needed the network.
	SeverityLookups int      `json:"severity_lookups"`
	SeverityFetched int      `json:"severity_fetched"`
	Warnings        []string `json:"warnings,omitempty"`
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
	var raw []row
	for i, q := range queries {
		var found []*advisory
		for _, h := range hits[i] {
			if a, ok := advisories[h.ID]; ok {
				found = append(found, a)
			}
		}
		rows, rollups := buildRows(found, q, joinPaths(paths[key{q.Ecosystem, q.Name, q.Version}]), kev)
		raw, st.Rollups = append(raw, rows...), st.Rollups+rollups
	}
	out := mergeByCVE(raw)
	st.Merged = len(raw) - len(out)
	var unrated int
	st.SeverityLookups, st.SeverityFetched, unrated = s.backfillSeverity(ctx, out)
	if unrated > 0 {
		st.Warnings = append(st.Warnings, fmt.Sprintf("%d findings left unrated: severity lookup budget (%d records) reached; they rate on later scans as records get cached", unrated, maxSeverityLookups))
	}
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

// row is a finding before merging; rollup marks rows expanded from an
// advisory that covers several CVEs, whose summary and rating describe the
// whole notice rather than this CVE.
type row struct {
	core.Vuln
	rollup bool
}

// buildRows turns the advisories that matched one package version into one
// row per CVE. This is the single place that applies the rollup rule:
//
//   - An advisory covering at most one CVE (GHSA-x = CVE-y, UBUNTU-CVE-y, a
//     DSA for a single CVE) yields one row keyed by that CVE.
//   - An advisory covering several CVEs (USN/DSA/RHSA notices) is a rollup:
//     its CVEs are siblings, not aliases. Each CVE gets its own row carrying
//     the notice ID as an alias and the notice's fixed version, with KEV
//     judged on that CVE alone and no rating borrowed from the notice.
//   - When some of a rollup's CVEs also have their own per-CVE record in
//     these results, the source publishes per-CVE data for this package:
//     the rollup only annotates those CVEs, because a notice lists CVEs for
//     every package it touches and the per-CVE record is authoritative.
func buildRows(found []*advisory, q Query, path string, kev map[string]bool) ([]row, int) {
	own := map[string]bool{} // CVEs with their own single-CVE record here
	for _, a := range found {
		if c := coveredCVEs(a.raw); len(c) == 1 {
			own[c[0]] = true
		}
	}
	var rows []row
	rollups := 0
	for _, a := range found {
		base := core.Vuln{
			Package: q.Name, Version: q.Version, Ecosystem: q.Ecosystem, Path: path,
			FixedIn: fixedVersion(a.raw, q.Name, q.Ecosystem, q.Version), Summary: summarize(a.raw),
		}
		cves := coveredCVEs(a.raw)
		if len(cves) <= 1 {
			v := base
			v.ID, v.Severity, v.CVSS = a.raw.ID, a.severity, a.cvss
			if len(cves) == 1 && cves[0] != a.raw.ID {
				v.ID, v.Aliases = cves[0], []string{a.raw.ID}
			}
			v.KEV = kev[v.ID]
			rows = append(rows, row{Vuln: v})
			continue
		}
		rollups++
		annotateOnly := slices.ContainsFunc(cves, func(c string) bool { return own[c] })
		for _, c := range cves {
			if annotateOnly && !own[c] {
				continue
			}
			v := base
			v.ID, v.Aliases, v.Severity, v.KEV = c, []string{a.raw.ID}, core.SeverityUnknown, kev[c]
			rows = append(rows, row{Vuln: v, rollup: true})
		}
	}
	return rows, rollups
}

// mergeByCVE folds rows for the same CVE on the same package (e.g. DSA-1 and
// USN-1 both fixing CVE-y) into one finding. Rows merge only on their own
// ID, never through shared aliases, and every merged field is chosen by an
// order-independent rule.
func mergeByCVE(in []row) []core.Vuln {
	var out []row
	index := map[string]int{}
	for _, r := range in {
		k := r.Package + r.Path + "|" + r.ID
		i, ok := index[k]
		if !ok {
			index[k] = len(out)
			out = append(out, r)
			continue
		}
		m := &out[i]
		m.KEV = m.KEV || r.KEV
		m.Severity, m.CVSS = max(m.Severity, r.Severity), max(m.CVSS, r.CVSS)
		m.FixedIn = pickFixed([]string{m.FixedIn, r.FixedIn}, m.Version)
		// Per-CVE text beats a notice's generic title; then longer, then lexical.
		if (m.rollup && !r.rollup) || (m.rollup == r.rollup &&
			(len(r.Summary) > len(m.Summary) || (len(r.Summary) == len(m.Summary) && r.Summary < m.Summary))) {
			m.Summary = r.Summary
		}
		m.rollup = m.rollup && r.rollup
		m.Aliases = append(m.Aliases, r.Aliases...)
	}
	res := make([]core.Vuln, len(out))
	for i, r := range out {
		v := r.Vuln
		slices.Sort(v.Aliases)
		v.Aliases = slices.DeleteFunc(slices.Compact(v.Aliases), func(a string) bool { return a == v.ID })
		res[i] = v
	}
	return res
}

// pickFixed chooses among fixed versions from several advisories with the
// same rule as fixedVersion: a single candidate as-is, otherwise the
// smallest one above the installed version, or "" when none is.
func pickFixed(candidates []string, installed string) string {
	var c []string
	for _, f := range candidates {
		if f != "" && !slices.Contains(c, f) {
			c = append(c, f)
		}
	}
	if len(c) <= 1 || installed == "" {
		return strings.Join(c, "")
	}
	best := ""
	for _, f := range c {
		if core.CompareVersions(f, installed) > 0 && (best == "" || core.CompareVersions(f, best) < 0) {
			best = f
		}
	}
	return best
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

// maxSeverityLookups bounds the records read per match to rate findings, so
// a host with many unrated rollup CVEs cannot turn into unbounded requests.
// Records are cached, so the cost is paid once per CVE.
const maxSeverityLookups = 1000

// distroRecordPrefix maps an ecosystem to the prefix of its per-CVE records
// (UBUNTU-CVE-*, DEBIAN-CVE-*), which rate the CVE for that distro.
var distroRecordPrefix = map[string]string{"Ubuntu": "UBUNTU-", "Debian": "DEBIAN-"}

// ratingSources lists where a CVE's rating may come from, best first: the
// distro's per-CVE record, then the CVE record itself.
func ratingSources(cve, ecosystem string) []string {
	distro, _, _ := strings.Cut(ecosystem, ":")
	if p, ok := distroRecordPrefix[distro]; ok {
		return []string{p + cve, cve}
	}
	return []string{cve}
}

// backfillSeverity rates findings that still have no severity from their
// per-CVE records (cached like any advisory). A rollup notice is never a
// rating source: its rating describes the whole notice, not one CVE.
// Fixable findings go first because severity decides their P1 eligibility.
// It returns how many records were read, how many network requests that
// took (404s included) and how many findings were left unrated because the
// network budget ran out.
func (s *Service) backfillSeverity(ctx context.Context, vs []core.Vuln) (lookups, fetched, unrated int) {
	type target struct{ cve, ecosystem string }
	byTarget := map[target][]int{}
	fixable := map[target]bool{}
	for i, v := range vs {
		if v.Severity == core.SeverityUnknown && strings.HasPrefix(v.ID, "CVE-") {
			t := target{v.ID, v.Ecosystem}
			byTarget[t] = append(byTarget[t], i)
			fixable[t] = fixable[t] || v.FixedIn != ""
		}
	}
	targets := slices.Collect(maps.Keys(byTarget))
	slices.SortFunc(targets, func(a, b target) int {
		if fixable[a] != fixable[b] {
			if fixable[a] {
				return -1
			}
			return 1
		}
		return strings.Compare(a.cve+a.ecosystem, b.cve+b.ecosystem)
	})
	var mu sync.Mutex
	budget := maxSeverityLookups
	// take accounts for one record read; only network requests (including
	// 404s) spend the budget, so later scans progress past cached records.
	take := func(cached bool) bool {
		mu.Lock()
		defer mu.Unlock()
		if !cached {
			if budget == 0 {
				return false
			}
			budget--
			fetched++
		}
		lookups++
		return true
	}
	var offline atomic.Bool // first network failure stops further requests this run
	rate := func(t target, a *advisory) bool {
		if len(coveredCVEs(a.raw)) > 1 || a.severity == core.SeverityUnknown {
			return false // itself a rollup, or unrated: try the next source
		}
		for _, i := range byTarget[t] {
			vs[i].Severity, vs[i].CVSS = a.severity, a.cvss
		}
		return true
	}
	sem := make(chan struct{}, max(s.Concurrency, 1))
	var wg sync.WaitGroup
	for _, t := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			sources := ratingSources(t.cve, t.ecosystem)
			var uncached []string
			for _, id := range sources { // cached sources first: no network at all
				if _, _, ok, _ := s.Cache.GetVuln(ctx, id); !ok {
					uncached = append(uncached, id)
				} else if take(true) {
					if a, _, err := s.load(ctx, id, ""); err == nil && rate(t, a) {
						return
					}
				}
			}
			for _, id := range uncached {
				if s.knownMissing(ctx, id) {
					continue
				}
				if offline.Load() || !take(false) {
					mu.Lock()
					unrated += len(byTarget[t])
					mu.Unlock()
					return
				}
				a, _, err := s.load(ctx, id, "")
				switch {
				case errors.Is(err, ErrNotFound):
					s.markMissing(ctx, id)
				case err != nil:
					offline.Store(true)
				case rate(t, a):
					return
				}
			}
		}()
	}
	wg.Wait()
	return lookups, fetched, unrated
}

// missingTTL is how long a 404 for a per-CVE record is remembered, so
// records that do not exist (many CVEs have no DEBIAN-/UBUNTU- record) are
// not re-requested on every scan.
const missingTTL = 7 * 24 * time.Hour

func (s *Service) knownMissing(ctx context.Context, id string) bool {
	at, err := s.Cache.Meta(ctx, "osv_missing:"+id)
	if err != nil || at == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, at)
	return err == nil && time.Since(t) < missingTTL
}

func (s *Service) markMissing(ctx context.Context, id string) {
	_ = s.Cache.SetMeta(ctx, "osv_missing:"+id, time.Now().UTC().Format(time.RFC3339))
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

// fixedVersion 回傳「從已安裝版本升級就能修好」的版本。
// 一則公告常對多條維護線各列一個修補版（如 Go stdlib 的 1.26.10 與 1.27.3），
// 直接取第一個會叫 1.27.1 的使用者「降級」到 1.26.10，所以多個候選時
// 取大於已安裝版本的最小者；全都不大於時回傳空字串，代表此維護線尚無修補。
// 只有一個候選時沿用原值、不做比較，避免啟發式比較誤判 distro 版本字串。
func fixedVersion(v OSVVuln, pkg, ecosystem, installed string) string {
	var fixed []string
	for _, a := range v.Affected {
		if a.Package.Name != pkg || a.Package.Ecosystem != ecosystem {
			continue
		}
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" && !slices.Contains(fixed, e.Fixed) {
					fixed = append(fixed, e.Fixed)
				}
			}
		}
	}
	if len(fixed) <= 1 || installed == "" {
		return strings.Join(fixed, "")
	}
	best := ""
	for _, f := range fixed {
		if core.CompareVersions(f, installed) > 0 && (best == "" || core.CompareVersions(f, best) < 0) {
			best = f
		}
	}
	return best
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

// coveredCVEs lists the CVEs an advisory is about: its own ID, its aliases
// and the CVEs it fixes (upstream/related). For a single-CVE record these
// are aliases of one vulnerability; for a rollup notice they are distinct
// vulnerabilities. buildRows is the one place that tells the two apart.
func coveredCVEs(v OSVVuln) []string {
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
	KEV        *core.KEVEntry  `json:"kev,omitempty"`  // single-CVE advisories only
	EPSS       *core.EPSSScore `json:"epss,omitempty"` // single-CVE advisories only
	// A rollup notice fixes several CVEs: they are listed here instead of
	// being folded into KEV/EPSS/severity, which describe one CVE each.
	CVEs    []string `json:"cves,omitempty"`
	KEVCVEs []string `json:"kev_cves,omitempty"`
	URL     string   `json:"url"`
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
	v := a.raw
	cves := coveredCVEs(v)
	if a.severity == core.SeverityUnknown && len(cves) == 1 && cves[0] != v.ID {
		if up, _, err := s.load(ctx, cves[0], ""); err == nil && len(coveredCVEs(up.raw)) <= 1 {
			a.severity, a.cvss = up.severity, up.cvss
		}
	}
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
	if len(cves) > 1 {
		d.CVEs = cves
		for _, cve := range cves {
			if k, err := s.Cache.KEV(ctx, cve); err == nil && k != nil {
				d.KEVCVEs = append(d.KEVCVEs, cve)
			}
		}
		return d, nil
	}
	if len(cves) == 1 {
		if k, err := s.Cache.KEV(ctx, cves[0]); err == nil && k != nil {
			d.KEV = k
		}
		if scores, err := s.epss(ctx, cves[:1]); err == nil {
			if e, ok := scores[cves[0]]; ok {
				d.EPSS = &e
			}
		}
	}
	return d, nil
}
