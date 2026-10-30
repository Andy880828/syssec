package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Andy880828/syssec/internal/core"
)

// DefaultEPSSURL is FIRST's EPSS API. Scores are refreshed daily upstream.
const DefaultEPSSURL = "https://api.first.org/data/v1/epss"

const (
	epssTTL   = 24 * time.Hour
	epssBatch = 100 // CVEs per request (URL length bound)
)

// enrichEPSS sets Vuln.EPSS for every CVE-keyed vuln.
func (s *Service) enrichEPSS(ctx context.Context, vs []core.Vuln) error {
	var cves []string
	seen := map[string]bool{}
	for _, v := range vs {
		if strings.HasPrefix(v.ID, "CVE-") && !seen[v.ID] {
			seen[v.ID] = true
			cves = append(cves, v.ID)
		}
	}
	scores, err := s.epss(ctx, cves)
	for i := range vs {
		vs[i].EPSS = scores[vs[i].ID].Score
	}
	return err
}

// epss returns scores, serving fresh ones from the cache and fetching only
// missing or stale CVEs. Partial results are returned with the error.
func (s *Service) epss(ctx context.Context, cves []string) (map[string]core.EPSSScore, error) {
	out, fresh, err := s.Cache.EPSS(ctx, cves, time.Now().Add(-epssTTL))
	if err != nil {
		return out, err
	}
	var missing []string
	for _, c := range cves {
		if !fresh[c] {
			missing = append(missing, c)
		}
	}
	var mu sync.Mutex
	var firstErr error
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for start := 0; start < len(missing); start += epssBatch {
		chunk := missing[start:min(start+epssBatch, len(missing))]
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			got, err := s.fetchEPSS(ctx, chunk)
			if err == nil {
				err = s.Cache.PutEPSS(ctx, chunk, got)
			}
			mu.Lock()
			defer mu.Unlock()
			if err != nil && firstErr == nil {
				firstErr = err
			}
			for _, e := range got {
				out[e.CVE] = e
			}
		}()
	}
	wg.Wait()
	return out, firstErr
}

func (s *Service) fetchEPSS(ctx context.Context, cves []string) ([]core.EPSSScore, error) {
	base := s.EPSSURL
	if base == "" {
		base = DefaultEPSSURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"?limit=1000&cve="+url.QueryEscape(strings.Join(cves, ",")), nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("epss: HTTP %d", resp.StatusCode)
	}
	var body struct {
		Data []struct {
			CVE        string `json:"cve"`
			EPSS       string `json:"epss"`
			Percentile string `json:"percentile"`
			Date       string `json:"date"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&body); err != nil {
		return nil, fmt.Errorf("epss: %w", err)
	}
	out := make([]core.EPSSScore, 0, len(body.Data))
	for _, d := range body.Data {
		score, _ := strconv.ParseFloat(d.EPSS, 64)
		pct, _ := strconv.ParseFloat(d.Percentile, 64)
		out = append(out, core.EPSSScore{CVE: d.CVE, Score: score, Percentile: pct, Date: d.Date})
	}
	return out, nil
}
