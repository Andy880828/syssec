package intel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Andy880828/syssec/internal/core"
	"github.com/Andy880828/syssec/internal/waiver"
)

func TestCVSS3Base(t *testing.T) {
	cases := map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
		"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 7.8,
		"CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N": 3.1,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0,
		"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N": 6.4,
	}
	for v, want := range cases {
		got, err := CVSS3Base(v)
		if err != nil || got != want {
			t.Errorf("%s = %v, %v; want %v", v, got, err, want)
		}
	}
	if _, err := CVSS3Base("CVSS:3.1/AV:N"); err == nil {
		t.Error("incomplete vector should error")
	}
}

type memCache struct {
	mu   sync.Mutex
	q    map[string][]byte
	v    map[string][2]string
	kev  map[string]bool
	meta map[string]string
}

func newMemCache() *memCache {
	return &memCache{q: map[string][]byte{}, v: map[string][2]string{}, kev: map[string]bool{}, meta: map[string]string{}}
}
func (m *memCache) GetVuln(_ context.Context, id string) ([]byte, string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.v[id]
	return []byte(e[1]), e[0], ok, nil
}
func (m *memCache) PutVuln(_ context.Context, id, mod string, raw []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.v[id] = [2]string{mod, string(raw)}
	return nil
}
func (m *memCache) KEV(_ context.Context, c string) (*core.KEVEntry, error) {
	if m.kev[c] {
		return &core.KEVEntry{CVE: c}, nil
	}
	return nil, nil
}
func (m *memCache) KEVIDs(context.Context) (map[string]bool, error) { return m.kev, nil }
func (m *memCache) ReplaceKEV(_ context.Context, es []core.KEVEntry) error {
	m.kev = map[string]bool{}
	for _, e := range es {
		m.kev[e.CVE] = true
	}
	return nil
}
func (m *memCache) Meta(_ context.Context, k string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.meta[k], nil
}
func (m *memCache) SetMeta(_ context.Context, k, v string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.meta[k] = v
	return nil
}

func (m *memCache) GetQuery(_ context.Context, k string) ([]byte, time.Time, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.q[k]
	return b, time.Now(), ok, nil
}
func (m *memCache) PutQuery(_ context.Context, k string, b []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.q[k] = b
	return nil
}

func (m *memCache) PurgeVulns(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.v = map[string][2]string{}
	return nil
}

func (m *memCache) EPSS(_ context.Context, cves []string, _ time.Time) (map[string]core.EPSSScore, map[string]bool, error) {
	return map[string]core.EPSSScore{}, map[string]bool{}, nil
}
func (m *memCache) PutEPSS(context.Context, []string, []core.EPSSScore) error { return nil }

func fakeOSV(t *testing.T, fetches *int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/querybatch":
			var req struct {
				Queries []osvQuery `json:"queries"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			var results []map[string]any
			for _, q := range req.Queries {
				if q.Package.Name == "openssl" {
					results = append(results, map[string]any{"vulns": []VulnRef{{ID: "DSA-1", Modified: "2026-10-30T03:03:16.726006Z"}, {ID: "USN-1", Modified: "x"}}})
				} else {
					results = append(results, map[string]any{})
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"results": results})
		case r.URL.Path == "/v1/vulns/DSA-1":
			*fetches++
			w.Write([]byte(`{"id":"DSA-1","modified":"2026-10-30T03:03:16.726006473Z","summary":"openssl bug","upstream":["CVE-2099-0001"],
				"affected":[{"package":{"name":"openssl","ecosystem":"Debian:11"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"9.9"}]}]},
				            {"package":{"name":"openssl","ecosystem":"Debian:12"},"versions":["a","b"],"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0.15-1"}]}]}]}`))
		case r.URL.Path == "/epss":
			w.Write([]byte(`{"data":[{"cve":"CVE-2099-0001","epss":"0.42","percentile":"0.99","date":"2026-10-29"}]}`))
		case r.URL.Path == "/v1/vulns/USN-1":
			w.Write([]byte(`{"id":"USN-1","modified":"x","summary":"openssl vulnerability","related":["CVE-2099-0001"],
				"affected":[{"package":{"name":"openssl","ecosystem":"Debian:12"}}]}`))
		case r.URL.Path == "/v1/vulns/CVE-2099-0001":
			w.Write([]byte(`{"id":"CVE-2099-0001","modified":"x","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestMatchCachesAndEnriches(t *testing.T) {
	fetches := 0
	srv := fakeOSV(t, &fetches)
	defer srv.Close()
	cache := newMemCache()
	cache.kev["CVE-2099-0001"] = true
	svc := &Service{OSV: &OSVClient{BaseURL: srv.URL, HTTP: srv.Client()}, HTTP: srv.Client(), Cache: cache, Concurrency: 4, EPSSURL: srv.URL + "/epss"}
	pkgs := []core.Package{
		{Name: "libssl3", Version: "3.0.11-1", Manager: "dpkg", Ecosystem: "Debian:12", SourceName: "openssl"},
		{Name: "openssl", Version: "3.0.11-1", Manager: "dpkg", Ecosystem: "Debian:12"},
		{Name: "curl", Version: "8", Manager: "homebrew"},
		{Name: "linux-libc-dev", Version: "6.8", Manager: "dpkg", Ecosystem: "Debian:12", SourceName: "linux"},
	}
	vulns, st, err := svc.Match(context.Background(), pkgs)
	if err != nil {
		t.Fatal(err)
	}
	if st.Queries != 1 || st.Unmatchable != 1 || st.Excluded != 1 || st.Merged != 1 {
		t.Errorf("dedupe/unmatchable stats wrong: %+v", st)
	}
	if len(vulns) != 1 {
		t.Fatalf("DSA-1 and USN-1 share a CVE and must merge into one finding, got %+v", vulns)
	}
	v := vulns[0]
	if v.ID != "CVE-2099-0001" || len(v.Aliases) != 2 || !v.KEV || v.Priority != "P0" || v.EPSS != 0.42 ||
		v.Severity != core.SeverityCritical || v.CVSS != 9.8 || v.FixedIn != "3.0.15-1" {
		t.Errorf("merge/enrichment wrong: %+v", v)
	}
	if strings.Contains(cache.v["DSA-1"][1], `"versions"`) {
		t.Error("cache should store the slim projection")
	}
	if _, st2, _ := svc.Match(context.Background(), pkgs); st2.CacheHits != 2 || fetches != 1 || st2.QueryCached != 0 {
		t.Errorf("second run should hit advisory cache: %+v fetches=%d", st2, fetches)
	}
	srv.Close() // with a query TTL the third run must not touch the network at all
	svc.QueryTTL = time.Hour
	if v3, st3, err := svc.Match(context.Background(), pkgs); err != nil || st3.QueryCached != 1 || len(v3) != 1 {
		t.Errorf("TTL run should be offline: %+v %v", st3, err)
	}
}

func TestSeverityFallbacks(t *testing.T) {
	var v OSVVuln
	json.Unmarshal([]byte(`{"id":"GHSA-x","database_specific":{"severity":"MODERATE"}}`), &v)
	if s, _ := Severity(v); s != core.SeverityMedium {
		t.Errorf("GHSA moderate -> %v", s)
	}
	json.Unmarshal([]byte(`{"id":"UBUNTU-CVE-1","severity":[{"type":"Ubuntu","score":"high"}]}`), &v)
	if s, _ := Severity(v); s != core.SeverityHigh {
		t.Errorf("Ubuntu priority -> %v", s)
	}
}

func TestSyncKEVUsesETag(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Write([]byte(`{"catalogVersion":"2026.10.30","vulnerabilities":[{"cveID":"CVE-1"},{"cveID":"CVE-2"}]}`))
	}))
	defer srv.Close()
	svc := &Service{HTTP: srv.Client(), Cache: newMemCache(), KEVURL: srv.URL}
	r1, err := svc.SyncKEV(context.Background())
	if err != nil || !r1.Updated || r1.Entries != 2 {
		t.Fatalf("first sync: %+v %v", r1, err)
	}
	r2, err := svc.SyncKEV(context.Background())
	if err != nil || r2.Updated || r2.Entries != 2 || calls != 2 {
		t.Fatalf("second sync should be a 304: %+v %v", r2, err)
	}
}

func TestPrioritize(t *testing.T) {
	cases := []struct {
		v    core.Vuln
		want string
	}{
		{core.Vuln{KEV: true, Severity: core.SeverityLow}, "P0"},
		{core.Vuln{EPSS: 0.2}, "P1"},
		{core.Vuln{Severity: core.SeverityCritical, FixedIn: "1.2"}, "P1"},
		{core.Vuln{Severity: core.SeverityCritical}, "P2"},
		{core.Vuln{Severity: core.SeverityLow, EPSS: 0.02}, "P2"},
		{core.Vuln{Severity: core.SeverityMedium}, "P3"},
	}
	for _, c := range cases {
		c.v.Prioritize()
		if c.v.Priority != c.want {
			t.Errorf("%+v: got %s want %s", c.v, c.v.Priority, c.want)
		}
	}
}

// 回歸：GO-2026-6809 對 1.26 與 1.27 線各列一個修補版，舊實作對 1.27.1 回報 1.26.10（等於叫人降級）。
func TestFixedVersionPicksInstalledBranch(t *testing.T) {
	var v OSVVuln
	if err := json.Unmarshal([]byte(`{"id":"GO-2026-6809","affected":[{"package":{"name":"stdlib","ecosystem":"Go"},
		"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.26.10"},{"introduced":"1.27.0-0"},{"fixed":"1.27.3"}]}]}]}`), &v); err != nil {
		t.Fatal(err)
	}
	cases := []struct{ installed, want string }{
		{"1.27.1", "1.27.3"},
		{"1.25.5", "1.26.10"},
		{"1.28.0", ""}, // 所在維護線沒有修補版：回空字串，不建議降級
	}
	for _, c := range cases {
		if got := fixedVersion(v, "stdlib", "Go", c.installed); got != c.want {
			t.Errorf("installed %s: fixed_in = %q, want %q", c.installed, got, c.want)
		}
	}
	if got := fixedVersion(v, "other", "Go", "1.0"); got != "" {
		t.Errorf("unrelated package: %q", got)
	}
}

// 回歸測試：一份公告修補多個 CVE 時，KEV 只能標在真正列入 KEV 的 CVE 上。
func TestRollupAdvisoryKEVAttribution(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			json.NewEncoder(w).Encode(map[string]any{"results": []map[string]any{
				{"vulns": []VulnRef{{ID: "USN-9", Modified: "x"}}},
			}})
		case "/v1/vulns/USN-9":
			w.Write([]byte(`{"id":"USN-9","modified":"x","summary":"kernel rollup",
				"upstream":["CVE-2099-1000","CVE-2099-2000","UBUNTU-CVE-2099-1000","UBUNTU-CVE-2099-2000"],
				"related":["UBUNTU-CVE-2099-1000","UBUNTU-CVE-2099-2000"],
				"affected":[{"package":{"name":"linux-hwe-6.17","ecosystem":"Ubuntu:24.04:LTS"},
				  "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"6.17.0-35"}]}]}]}`))
		case "/epss":
			w.Write([]byte(`{"data":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	cache := newMemCache()
	cache.kev["CVE-2099-2000"] = true // 只有第二個 CVE 在 KEV
	svc := &Service{OSV: &OSVClient{BaseURL: srv.URL, HTTP: srv.Client()}, HTTP: srv.Client(), Cache: cache, Concurrency: 2, EPSSURL: srv.URL + "/epss"}
	vulns, _, err := svc.Match(context.Background(), []core.Package{{
		Name: "linux-modules-6.17.0-14-generic", Version: "6.17.0-14", Manager: "dpkg",
		Ecosystem: "Ubuntu:24.04:LTS", SourceName: "linux-hwe-6.17",
	}})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]core.Vuln{}
	for _, v := range vulns {
		t.Logf("row id=%s kev=%v priority=%s aliases=%v fixed=%s", v.ID, v.KEV, v.Priority, v.Aliases, v.FixedIn)
		got[v.ID] = v
	}
	if a, ok := got["CVE-2099-1000"]; !ok {
		t.Error("CVE-2099-1000 應有自己的一列")
	} else if a.KEV {
		t.Error("CVE-2099-1000 不在 KEV，卻被標成 KEV")
	}
	if k, ok := got["CVE-2099-2000"]; !ok {
		t.Error("CVE-2099-2000 被併進別列，失去自己的一列")
	} else if !k.KEV || k.Priority != "P0" {
		t.Errorf("CVE-2099-2000 應為 KEV/P0，實際 %+v", k)
	}
}

// 有逐 CVE 紀錄（UBUNTU-CVE-*）時，彙總公告只替這些 CVE 補別名與修補版，
// 不替沒有逐 CVE 紀錄的 CVE 開列；彙總公告的評級也不套到任何 CVE。
func TestRollupAnnotatesPerCVERecordsAndLendsNoRating(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			json.NewEncoder(w).Encode(map[string]any{"results": []map[string]any{
				{"vulns": []VulnRef{{ID: "USN-9", Modified: "x"}, {ID: "UBUNTU-CVE-2099-1000", Modified: "x"}}},
			}})
		case "/v1/vulns/USN-9": // 公告本身評為 critical：不能借給 CVE
			w.Write([]byte(`{"id":"USN-9","modified":"x","summary":"kernel rollup",
				"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
				"upstream":["CVE-2099-1000","CVE-2099-2000"],
				"affected":[{"package":{"name":"linux","ecosystem":"Ubuntu:24.04:LTS"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"6.8.0-90"}]}]}]}`))
		case "/v1/vulns/UBUNTU-CVE-2099-1000":
			w.Write([]byte(`{"id":"UBUNTU-CVE-2099-1000","modified":"x","summary":"use-after-free in netfilter allows local escalation",
				"upstream":["CVE-2099-1000"],"severity":[{"type":"Ubuntu","score":"medium"}],
				"affected":[{"package":{"name":"linux","ecosystem":"Ubuntu:24.04:LTS"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}`))
		case "/epss":
			w.Write([]byte(`{"data":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	cache := newMemCache()
	cache.kev["CVE-2099-2000"] = true
	svc := &Service{OSV: &OSVClient{BaseURL: srv.URL, HTTP: srv.Client()}, HTTP: srv.Client(), Cache: cache, Concurrency: 2, EPSSURL: srv.URL + "/epss"}
	vulns, st, err := svc.Match(context.Background(), []core.Package{{Name: "linux-image-6.8.0-80-generic", Version: "6.8.0-80", Manager: "dpkg", Ecosystem: "Ubuntu:24.04:LTS", SourceName: "linux"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(vulns) != 1 {
		t.Fatalf("only CVE-2099-1000 has a per-CVE record for this package; got %+v", vulns)
	}
	v := vulns[0]
	if v.ID != "CVE-2099-1000" || v.KEV || v.Severity != core.SeverityMedium || v.CVSS != 0 {
		t.Errorf("rating must come from the per-CVE record, not the critical notice: %+v", v)
	}
	if v.FixedIn != "6.8.0-90" || !slices.Equal(v.Aliases, []string{"UBUNTU-CVE-2099-1000", "USN-9"}) {
		t.Errorf("notice should annotate the row: fixed=%q aliases=%v", v.FixedIn, v.Aliases)
	}
	if !strings.Contains(v.Summary, "netfilter") {
		t.Errorf("per-CVE summary beats the notice title: %q", v.Summary)
	}
	if st.Rollups != 1 {
		t.Errorf("rollups stat: %+v", st)
	}
}

// 彙總公告展開的 CVE 若沒有逐 CVE 紀錄，就查 CVE 本身的紀錄評級；查不到維持 unknown。
func TestRollupCVEsRatedFromTheirOwnRecords(t *testing.T) {
	var cveFetches atomic.Int64 // handlers run concurrently
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			json.NewEncoder(w).Encode(map[string]any{"results": []map[string]any{{"vulns": []VulnRef{{ID: "DSA-7", Modified: "x"}}}}})
		case "/v1/vulns/DSA-7":
			w.Write([]byte(`{"id":"DSA-7","modified":"x","summary":"openssl security update","upstream":["CVE-2099-0001","CVE-2099-0002"],
				"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
				"affected":[{"package":{"name":"openssl","ecosystem":"Debian:12"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0.15-1"}]}]}]}`))
		case "/v1/vulns/CVE-2099-0001":
			cveFetches.Add(1)
			w.Write([]byte(`{"id":"CVE-2099-0001","modified":"x","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"}]}`))
		case "/epss":
			w.Write([]byte(`{"data":[]}`))
		default:
			cveFetches.Add(1)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	svc := &Service{OSV: &OSVClient{BaseURL: srv.URL, HTTP: srv.Client()}, HTTP: srv.Client(), Cache: newMemCache(), Concurrency: 2, EPSSURL: srv.URL + "/epss"}
	vulns, st, err := svc.Match(context.Background(), []core.Package{{Name: "openssl", Version: "3.0.11-1", Manager: "dpkg", Ecosystem: "Debian:12"}})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]core.Vuln{}
	for _, v := range vulns {
		got[v.ID] = v
	}
	if a := got["CVE-2099-0001"]; a.CVSS != 5.5 || a.Severity != core.SeverityMedium {
		t.Errorf("CVE-2099-0001 should be rated from its own record (5.5), not the notice (10.0): %+v", a)
	}
	if b := got["CVE-2099-0002"]; b.Severity != core.SeverityUnknown || b.CVSS != 0 {
		t.Errorf("CVE-2099-0002 has no record: stays unknown instead of inheriting 10.0: %+v", b)
	}
	// 每個 CVE 先查 DEBIAN-CVE-*（此處不存在），再查 CVE 紀錄：共 4 次請求，404 也算。
	if st.SeverityLookups != 4 || st.SeverityFetched != 4 || cveFetches.Load() != 4 {
		t.Errorf("rating lookups: stats %+v, requests %d", st, cveFetches.Load())
	}
	// 第二次掃描：評級來自快取，404 有負快取，不再發任何評級請求。
	if _, st2, err := svc.Match(context.Background(), []core.Package{{Name: "openssl", Version: "3.0.11-1", Manager: "dpkg", Ecosystem: "Debian:12"}}); err != nil || st2.SeverityFetched != 0 || cveFetches.Load() != 4 {
		t.Errorf("second scan re-requested rating records: stats %+v, requests %d, err %v", st2, cveFetches.Load(), err)
	}
}

func TestPickFixedIsOrderIndependent(t *testing.T) {
	for _, order := range [][]string{{"6.17.0-35", "6.17.0-30", ""}, {"", "6.17.0-30", "6.17.0-35"}} {
		if got := pickFixed(order, "6.17.0-14"); got != "6.17.0-30" {
			t.Errorf("%v: %q", order, got)
		}
	}
	if got := pickFixed([]string{"1.2", "1.2"}, "1.0"); got != "1.2" {
		t.Errorf("duplicates: %q", got)
	}
}

// 端到端：Match 拆出的列交給 waiver.Apply，豁免 CVE-A 不可波及同公告的 KEV CVE-B。
// 舊實作把兄弟 CVE 放進 aliases，這裡的豁免會連帶蓋掉 KEV 那一筆。
func TestWaiverOnRollupRowsStaysOnOneCVE(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			json.NewEncoder(w).Encode(map[string]any{"results": []map[string]any{{"vulns": []VulnRef{{ID: "USN-9", Modified: "x"}}}}})
		case "/v1/vulns/USN-9":
			w.Write([]byte(`{"id":"USN-9","modified":"x","upstream":["CVE-2099-1000","CVE-2099-2000"],
				"affected":[{"package":{"name":"linux-hwe-6.17","ecosystem":"Ubuntu:24.04:LTS"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"6.17.0-35"}]}]}]}`))
		case "/epss":
			w.Write([]byte(`{"data":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	cache := newMemCache()
	cache.kev["CVE-2099-2000"] = true
	svc := &Service{OSV: &OSVClient{BaseURL: srv.URL, HTTP: srv.Client()}, HTTP: srv.Client(), Cache: cache, Concurrency: 2, EPSSURL: srv.URL + "/epss"}
	vulns, _, err := svc.Match(context.Background(), []core.Package{{Name: "linux-image-6.17.0-14-generic", Version: "6.17.0-14", Manager: "dpkg", Ecosystem: "Ubuntu:24.04:LTS", SourceName: "linux-hwe-6.17"}})
	if err != nil {
		t.Fatal(err)
	}
	f := &waiver.File{Waivers: []core.Waiver{{ID: "CVE-2099-1000", Reason: "not reachable"}}}
	f.Apply(nil, vulns, time.Now())
	for _, v := range vulns {
		if v.KEV && v.Waiver != nil {
			t.Errorf("waiving CVE-2099-1000 hid the KEV finding %s: %+v", v.ID, v)
		}
	}
}
