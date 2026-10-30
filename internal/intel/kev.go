package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Andy880828/syssec/internal/core"
)

// DefaultKEVURL is CISA's Known Exploited Vulnerabilities feed.
const DefaultKEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// KEVSyncResult reports what a catalog refresh did.
type KEVSyncResult struct {
	Updated  bool   `json:"updated"`
	Entries  int    `json:"entries"`
	Version  string `json:"catalog_version,omitempty"`
	SyncedAt string `json:"synced_at"`
}

// SyncKEV refreshes the catalog using ETag revalidation, so an unchanged
// catalog costs one 304 round-trip.
func (s *Service) SyncKEV(ctx context.Context) (*KEVSyncResult, error) {
	u := s.KEVURL
	if u == "" {
		u = DefaultKEVURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	etag, _ := s.Cache.Meta(ctx, "kev_etag")
	count, _ := s.Cache.Meta(ctx, "kev_count")
	if etag != "" && count != "" && count != "0" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch KEV: %w", err)
	}
	defer resp.Body.Close()
	now := time.Now().UTC().Format(time.RFC3339)
	res := &KEVSyncResult{SyncedAt: now}
	switch resp.StatusCode {
	case http.StatusNotModified:
		fmt.Sscan(count, &res.Entries)
		res.Version, _ = s.Cache.Meta(ctx, "kev_version")
		_ = s.Cache.SetMeta(ctx, "kev_synced_at", now)
		return res, nil
	case http.StatusOK:
	default:
		return nil, fmt.Errorf("fetch KEV: HTTP %d", resp.StatusCode)
	}
	var feed struct {
		CatalogVersion  string          `json:"catalogVersion"`
		Vulnerabilities []core.KEVEntry `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&feed); err != nil {
		return nil, fmt.Errorf("decode KEV: %w", err)
	}
	if err := s.Cache.ReplaceKEV(ctx, feed.Vulnerabilities); err != nil {
		return nil, err
	}
	for k, v := range map[string]string{
		"kev_etag": resp.Header.Get("ETag"), "kev_count": fmt.Sprint(len(feed.Vulnerabilities)),
		"kev_version": feed.CatalogVersion, "kev_synced_at": now,
	} {
		if err := s.Cache.SetMeta(ctx, k, v); err != nil {
			return nil, err
		}
	}
	res.Updated, res.Entries, res.Version = true, len(feed.Vulnerabilities), feed.CatalogVersion
	return res, nil
}

// KEVStale reports whether the catalog was never synced or is older than maxAge.
func (s *Service) KEVStale(ctx context.Context, maxAge time.Duration) bool {
	at, err := s.Cache.Meta(ctx, "kev_synced_at")
	if err != nil || at == "" {
		return true
	}
	t, err := time.Parse(time.RFC3339, at)
	return err != nil || time.Since(t) > maxAge
}
