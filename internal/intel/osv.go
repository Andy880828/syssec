// Package intel turns an installed-package inventory into vulnerability
// intelligence without mirroring any database: it asks OSV.dev only about
// what is installed, caches advisories by their `modified` stamp, and
// enriches them with the CISA KEV catalog (fetched with ETag revalidation).
package intel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// DefaultOSVURL is the public OSV API.
const DefaultOSVURL = "https://api.osv.dev"

const (
	batchSize     = 50 // OSV accepts up to 1000 queries per batch; small chunks parallelise better
	batchParallel = 8
)

// OSVClient is a minimal OSV.dev v1 client.
type OSVClient struct {
	BaseURL   string
	HTTP      *http.Client
	UserAgent string
}

// Query asks which advisories affect one package version.
type Query struct {
	Name, Ecosystem, Version string
}

// VulnRef is a hit from querybatch: an ID plus its last-modified stamp,
// which drives cache revalidation.
type VulnRef struct {
	ID       string `json:"id"`
	Modified string `json:"modified"`
}

type osvQuery struct {
	Version   string `json:"version"`
	Package   osvPkg `json:"package"`
	PageToken string `json:"page_token,omitempty"`
}

type osvPkg struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// QueryBatch resolves many queries; result i corresponds to qs[i]. Chunks
// are sent concurrently because OSV's batch latency grows with chunk size.
func (c *OSVClient) QueryBatch(ctx context.Context, qs []Query) ([][]VulnRef, error) {
	out := make([][]VulnRef, len(qs))
	errs := make(chan error, (len(qs)+batchSize-1)/batchSize)
	sem := make(chan struct{}, batchParallel)
	var wg sync.WaitGroup
	for start := 0; start < len(qs); start += batchSize {
		end := min(start+batchSize, len(qs))
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if err := c.queryChunk(ctx, qs, start, end, out); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	if err := <-errs; err != nil {
		return nil, err
	}
	return out, nil
}

// queryChunk fills out[start:end], following per-query pagination.
func (c *OSVClient) queryChunk(ctx context.Context, qs []Query, start, end int, out [][]VulnRef) error {
	pending := make([]osvQuery, 0, end-start)
	index := make([]int, 0, end-start)
	for i := start; i < end; i++ {
		pending = append(pending, osvQuery{Version: qs[i].Version, Package: osvPkg{qs[i].Name, qs[i].Ecosystem}})
		index = append(index, i)
	}
	for len(pending) > 0 {
		var resp struct {
			Results []struct {
				Vulns         []VulnRef `json:"vulns"`
				NextPageToken string    `json:"next_page_token"`
			} `json:"results"`
		}
		if err := c.post(ctx, "/v1/querybatch", map[string]any{"queries": pending}, &resp); err != nil {
			return err
		}
		var nextQ []osvQuery
		var nextI []int
		for j, r := range resp.Results {
			if j >= len(index) {
				break
			}
			out[index[j]] = append(out[index[j]], r.Vulns...)
			if r.NextPageToken != "" {
				q := pending[j]
				q.PageToken = r.NextPageToken
				nextQ, nextI = append(nextQ, q), append(nextI, index[j])
			}
		}
		pending, index = nextQ, nextI
	}
	return nil
}

// Vuln fetches one advisory as raw JSON.
func (c *OSVClient) Vuln(ctx context.Context, id string) ([]byte, error) {
	return c.do(ctx, http.MethodGet, "/v1/vulns/"+url.PathEscape(id), nil)
}

func (c *OSVClient) post(ctx context.Context, path string, body, into any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	b, err := c.do(ctx, http.MethodPost, path, payload)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, into)
}

// ErrNotFound is returned for unknown advisory IDs.
var ErrNotFound = fmt.Errorf("advisory not found")

func (c *OSVClient) do(ctx context.Context, method, path string, payload []byte) ([]byte, error) {
	base := c.BaseURL
	if base == "" {
		base = DefaultOSVURL
	}
	var lastErr error
	for attempt := range 4 {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(1<<attempt) * 250 * time.Millisecond):
			}
		}
		req, err := http.NewRequestWithContext(ctx, method, base+path, bytes.NewReader(payload))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		if c.UserAgent != "" {
			req.Header.Set("User-Agent", c.UserAgent)
		}
		resp, err := c.HTTP.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		resp.Body.Close()
		switch {
		case err != nil:
			lastErr = err
		case resp.StatusCode == http.StatusNotFound:
			return nil, ErrNotFound
		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
			lastErr = fmt.Errorf("osv %s: HTTP %d", path, resp.StatusCode)
		case resp.StatusCode != http.StatusOK:
			return nil, fmt.Errorf("osv %s: HTTP %d: %.200s", path, resp.StatusCode, body)
		default:
			return body, nil
		}
	}
	return nil, lastErr
}

// OSVVuln is the subset of the OSV schema syssec uses.
type OSVVuln struct {
	ID        string   `json:"id"`
	Summary   string   `json:"summary,omitempty"`
	Details   string   `json:"details,omitempty"`
	Aliases   []string `json:"aliases,omitempty"`
	Upstream  []string `json:"upstream,omitempty"`
	Related   []string `json:"related,omitempty"`
	Modified  string   `json:"modified,omitempty"`
	Published string   `json:"published,omitempty"`
	Severity  []struct {
		Type  string `json:"type,omitempty"`
		Score string `json:"score,omitempty"`
	} `json:"severity,omitempty"`
	Affected []struct {
		Package struct {
			Name      string `json:"name,omitempty"`
			Ecosystem string `json:"ecosystem,omitempty"`
		} `json:"package,omitempty"`
		Ranges []struct {
			Type   string `json:"type,omitempty"`
			Events []struct {
				Introduced string `json:"introduced,omitempty"`
				Fixed      string `json:"fixed,omitempty"`
			} `json:"events,omitempty"`
		} `json:"ranges,omitempty"`
		Severity []struct {
			Type  string `json:"type"`
			Score string `json:"score"`
		} `json:"severity,omitempty"`
		EcosystemSpecific map[string]any `json:"ecosystem_specific,omitempty"`
		DatabaseSpecific  map[string]any `json:"database_specific,omitempty"`
	} `json:"affected,omitempty"`
	DatabaseSpecific map[string]any `json:"database_specific,omitempty"`
	References       []struct {
		Type string `json:"type,omitempty"`
		URL  string `json:"url,omitempty"`
	} `json:"references,omitempty"`
}
