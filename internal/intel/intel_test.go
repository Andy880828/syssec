package intel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Andy880828/syssec/internal/core"
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
func (m *memCache) Meta(_ context.Context, k string) (string, error) { return m.meta[k], nil }
func (m *memCache) SetMeta(_ context.Context, k, v string) error     { m.meta[k] = v; return nil }

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
