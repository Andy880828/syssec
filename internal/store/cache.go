package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/Andy880828/syssec/internal/core"
)

// The methods below implement intel.Cache.

func (s *Store) GetVuln(ctx context.Context, id string) ([]byte, string, bool, error) {
	var raw []byte
	var mod string
	err := s.db.QueryRowContext(ctx, `SELECT raw, modified FROM vuln_cache WHERE id = ?`, id).Scan(&raw, &mod)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", false, nil
	}
	return raw, mod, err == nil, err
}

func (s *Store) PutVuln(ctx context.Context, id, modified string, raw []byte) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO vuln_cache (id, modified, fetched_at, raw) VALUES (?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET modified = excluded.modified, fetched_at = excluded.fetched_at, raw = excluded.raw`,
		id, modified, ts(time.Now()), raw)
	return err
}

func (s *Store) KEV(ctx context.Context, cve string) (*core.KEVEntry, error) {
	var k core.KEVEntry
	err := s.db.QueryRowContext(ctx, `SELECT cve, vendor, product, name, date_added, due_date, ransomware FROM kev WHERE cve = ?`, cve).
		Scan(&k.CVE, &k.Vendor, &k.Product, &k.Name, &k.DateAdded, &k.DueDate, &k.Ransomware)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &k, nil
}

func (s *Store) KEVIDs(ctx context.Context) (map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT cve FROM kev`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

func (s *Store) ReplaceKEV(ctx context.Context, entries []core.KEVEntry) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM kev`); err != nil {
		return err
	}
	if err := bulk(ctx, tx, `INSERT OR REPLACE INTO kev VALUES (?,?,?,?,?,?,?)`, len(entries), func(i int) []any {
		k := entries[i]
		return []any{k.CVE, k.Vendor, k.Product, k.Name, k.DateAdded, k.DueDate, k.Ransomware}
	}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Meta(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

func (s *Store) SetMeta(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

func (s *Store) GetQuery(ctx context.Context, key string) ([]byte, time.Time, bool, error) {
	var refs []byte
	var at string
	err := s.db.QueryRowContext(ctx, `SELECT refs, fetched_at FROM query_cache WHERE key = ?`, key).Scan(&refs, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, time.Time{}, false, nil
	}
	if err != nil {
		return nil, time.Time{}, false, err
	}
	t, _ := time.Parse(time.RFC3339Nano, at)
	return refs, t, true, nil
}

func (s *Store) PutQuery(ctx context.Context, key string, refs []byte) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO query_cache (key, refs, fetched_at) VALUES (?,?,?)
		ON CONFLICT(key) DO UPDATE SET refs = excluded.refs, fetched_at = excluded.fetched_at`, key, refs, ts(time.Now()))
	return err
}

func (s *Store) PurgeVulns(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM vuln_cache`)
	return err
}

func (s *Store) EPSS(ctx context.Context, cves []string, freshAfter time.Time) (map[string]core.EPSSScore, map[string]bool, error) {
	out, fresh := map[string]core.EPSSScore{}, map[string]bool{}
	for start := 0; start < len(cves); start += 500 {
		chunk := cves[start:min(start+500, len(cves))]
		args := make([]any, len(chunk))
		for i, c := range chunk {
			args[i] = c
		}
		rows, err := s.db.QueryContext(ctx, `SELECT cve, score, percentile, date, fetched_at FROM epss WHERE cve IN (?`+
			strings.Repeat(",?", len(chunk)-1)+`)`, args...)
		if err != nil {
			return out, fresh, err
		}
		for rows.Next() {
			var e core.EPSSScore
			var at string
			if err := rows.Scan(&e.CVE, &e.Score, &e.Percentile, &e.Date, &at); err != nil {
				rows.Close()
				return out, fresh, err
			}
			if e.Date != "" {
				out[e.CVE] = e
			}
			t, _ := time.Parse(time.RFC3339Nano, at)
			fresh[e.CVE] = t.After(freshAfter)
		}
		rows.Close()
	}
	return out, fresh, nil
}

func (s *Store) PutEPSS(ctx context.Context, asked []string, got []core.EPSSScore) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	byCVE := map[string]core.EPSSScore{}
	for _, e := range got {
		byCVE[e.CVE] = e
	}
	now := ts(time.Now())
	if err := bulk(ctx, tx, `INSERT INTO epss (cve, score, percentile, date, fetched_at) VALUES (?,?,?,?,?)
		ON CONFLICT(cve) DO UPDATE SET score = excluded.score, percentile = excluded.percentile, date = excluded.date, fetched_at = excluded.fetched_at`,
		len(asked), func(i int) []any {
			e := byCVE[asked[i]] // zero value = not scored (yet)
			return []any{asked[i], e.Score, e.Percentile, e.Date, now}
		}); err != nil {
		return err
	}
	return tx.Commit()
}
