// Package store persists scan history and the intel cache in a single
// SQLite file using the pure-Go modernc.org/sqlite driver (no cgo).
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Andy880828/syssec/internal/core"

	_ "modernc.org/sqlite"
)

// ErrNoScans is returned when history is empty.
var ErrNoScans = errors.New("no scans recorded yet (run `syssec scan` first)")

// Store is the SQLite-backed repository.
type Store struct {
	db   *sql.DB
	Path string
}

var migrations = []string{
	`CREATE TABLE scans (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		started_at TEXT NOT NULL,
		duration_ms INTEGER NOT NULL,
		hostname TEXT NOT NULL,
		host_json TEXT NOT NULL,
		score INTEGER NOT NULL,
		grade TEXT NOT NULL,
		summary_json TEXT NOT NULL,
		inventory_scanned INTEGER NOT NULL,
		vuln_scanned INTEGER NOT NULL,
		partial INTEGER NOT NULL,
		errors_json TEXT NOT NULL
	);
	CREATE TABLE results (
		scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
		check_id TEXT NOT NULL, title TEXT NOT NULL, category TEXT NOT NULL,
		severity TEXT NOT NULL, status TEXT NOT NULL, evidence TEXT NOT NULL, remediation TEXT NOT NULL,
		PRIMARY KEY (scan_id, check_id)
	);
	CREATE INDEX results_by_check ON results(check_id, scan_id);
	CREATE TABLE packages (
		scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
		manager TEXT NOT NULL, name TEXT NOT NULL, version TEXT NOT NULL, arch TEXT NOT NULL,
		ecosystem TEXT NOT NULL, source_name TEXT NOT NULL, source_version TEXT NOT NULL
	);
	CREATE INDEX packages_by_scan ON packages(scan_id);
	CREATE TABLE vulns (
		scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
		vuln_id TEXT NOT NULL, package TEXT NOT NULL, version TEXT NOT NULL, ecosystem TEXT NOT NULL,
		severity TEXT NOT NULL, cvss REAL NOT NULL, kev INTEGER NOT NULL, fixed_in TEXT NOT NULL,
		summary TEXT NOT NULL, aliases TEXT NOT NULL
	);
	CREATE INDEX vulns_by_scan ON vulns(scan_id);
	CREATE INDEX vulns_by_id ON vulns(vuln_id);
	CREATE TABLE vuln_cache (id TEXT PRIMARY KEY, modified TEXT NOT NULL, fetched_at TEXT NOT NULL, raw BLOB NOT NULL);
	CREATE TABLE kev (cve TEXT PRIMARY KEY, vendor TEXT, product TEXT, name TEXT, date_added TEXT, due_date TEXT, ransomware TEXT);
	CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);`,
	`CREATE TABLE query_cache (key TEXT PRIMARY KEY, refs BLOB NOT NULL, fetched_at TEXT NOT NULL);`,
	`CREATE TABLE epss (cve TEXT PRIMARY KEY, score REAL NOT NULL, percentile REAL NOT NULL, date TEXT NOT NULL, fetched_at TEXT NOT NULL);
	ALTER TABLE vulns ADD COLUMN epss REAL NOT NULL DEFAULT 0;
	ALTER TABLE vulns ADD COLUMN priority TEXT NOT NULL DEFAULT '';
	ALTER TABLE vulns ADD COLUMN waiver TEXT NOT NULL DEFAULT '';
	ALTER TABLE results ADD COLUMN waiver TEXT NOT NULL DEFAULT '';`,
	`ALTER TABLE vulns ADD COLUMN in_use INTEGER NOT NULL DEFAULT -1;
	ALTER TABLE vulns ADD COLUMN processes TEXT NOT NULL DEFAULT '';
	ALTER TABLE vulns ADD COLUMN path TEXT NOT NULL DEFAULT '';
	ALTER TABLE packages ADD COLUMN path TEXT NOT NULL DEFAULT '';`,
}

// Open opens (creating if needed) the database and applies migrations.
func Open(ctx context.Context, path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	dsn := "file:" + filepath.ToSlash(path) + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // single writer; avoids SQLITE_BUSY under concurrent cache writes
	s := &Store{db: db, Path: path}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate %s: %w", path, err)
	}
	_ = os.Chmod(path, 0o600) // scan history reveals the host's weak spots
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	var v int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v); err != nil {
		return err
	}
	for i := v; i < len(migrations); i++ {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, migrations[i]); err != nil {
			tx.Rollback()
			return err
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", i+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// optJSON encodes an optional pointer as JSON, or "" when nil.
func optJSON[T any](v *T) string {
	if v == nil {
		return ""
	}
	return mustJSON(v)
}

func parseOpt[T any](s string) *T {
	if s == "" {
		return nil
	}
	v := new(T)
	if json.Unmarshal([]byte(s), v) != nil {
		return nil
	}
	return v
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// SaveReport persists a report and sets its ID.
func (s *Store) SaveReport(ctx context.Context, r *core.Report) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `INSERT INTO scans
		(started_at, duration_ms, hostname, host_json, score, grade, summary_json, inventory_scanned, vuln_scanned, partial, errors_json)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		ts(r.StartedAt), r.DurationMS, r.Host.Hostname, mustJSON(r.Host), r.Summary.Score, r.Summary.Grade,
		mustJSON(r.Summary), b2i(r.InventoryScanned), b2i(r.VulnScanned), b2i(r.Partial), mustJSON(r.Errors))
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if err := bulk(ctx, tx, `INSERT INTO results (scan_id, check_id, title, category, severity, status, evidence, remediation, waiver)
		VALUES (?,?,?,?,?,?,?,?,?)`, len(r.Results), func(i int) []any {
		x := r.Results[i]
		return []any{id, x.ID, x.Title, x.Category, x.Severity.String(), string(x.Status), x.Evidence, x.Remediation, optJSON(x.Waiver)}
	}); err != nil {
		return 0, err
	}
	if err := bulk(ctx, tx, `INSERT INTO packages (scan_id, manager, name, version, arch, ecosystem, source_name, source_version, path)
		VALUES (?,?,?,?,?,?,?,?,?)`, len(r.Packages), func(i int) []any {
		p := r.Packages[i]
		return []any{id, p.Manager, p.Name, p.Version, p.Arch, p.Ecosystem, p.SourceName, p.SourceVersion, p.Path}
	}); err != nil {
		return 0, err
	}
	if err := bulk(ctx, tx, `INSERT INTO vulns (scan_id, vuln_id, package, version, ecosystem, severity, cvss, kev, fixed_in, summary, aliases, epss, priority, waiver, in_use, processes, path)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, len(r.Vulns), func(i int) []any {
		v := r.Vulns[i]
		inUse := -1
		if v.InUse != nil {
			inUse = b2i(*v.InUse)
		}
		return []any{id, v.ID, v.Package, v.Version, v.Ecosystem, v.Severity.String(), v.CVSS, b2i(v.KEV), v.FixedIn, v.Summary,
			strings.Join(v.Aliases, ","), v.EPSS, v.Priority, optJSON(v.Waiver), inUse, strings.Join(v.Processes, ","), v.Path}
	}); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	r.ID = id
	return id, nil
}

func bulk(ctx context.Context, tx *sql.Tx, query string, n int, row func(int) []any) error {
	if n == 0 {
		return nil
	}
	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for i := range n {
		if _, err := stmt.ExecContext(ctx, row(i)...); err != nil {
			return err
		}
	}
	return nil
}

// ScanInfo is one row of scan history.
type ScanInfo struct {
	ID               int64        `json:"scan_id"`
	StartedAt        time.Time    `json:"started_at"`
	Hostname         string       `json:"hostname"`
	Score            int          `json:"score"`
	Grade            string       `json:"grade"`
	Summary          core.Summary `json:"summary"`
	VulnScanned      bool         `json:"vuln_scanned"`
	InventoryScanned bool         `json:"inventory_scanned"`
	Partial          bool         `json:"partial,omitempty"`
}

// ListScans returns the most recent scans, newest first.
func (s *Store) ListScans(ctx context.Context, limit int) ([]ScanInfo, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, started_at, hostname, score, grade, summary_json, vuln_scanned, inventory_scanned, partial
		FROM scans ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ScanInfo
	for rows.Next() {
		var si ScanInfo
		var at, sum string
		if err := rows.Scan(&si.ID, &at, &si.Hostname, &si.Score, &si.Grade, &sum, &si.VulnScanned, &si.InventoryScanned, &si.Partial); err != nil {
			return nil, err
		}
		si.StartedAt, _ = time.Parse(time.RFC3339Nano, at)
		_ = json.Unmarshal([]byte(sum), &si.Summary)
		out = append(out, si)
	}
	return out, rows.Err()
}

// LatestID returns the newest scan ID, optionally only complete scans.
func (s *Store) LatestID(ctx context.Context, completeOnly bool) (int64, error) {
	q := `SELECT id FROM scans ORDER BY id DESC LIMIT 1`
	if completeOnly {
		q = `SELECT id FROM scans WHERE partial = 0 ORDER BY id DESC LIMIT 1`
	}
	var id int64
	err := s.db.QueryRowContext(ctx, q).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNoScans
	}
	return id, err
}

// PreviousID returns the complete scan preceding id.
func (s *Store) PreviousID(ctx context.Context, id int64) (int64, error) {
	var prev int64
	err := s.db.QueryRowContext(ctx, `SELECT id FROM scans WHERE id < ? AND partial = 0 ORDER BY id DESC LIMIT 1`, id).Scan(&prev)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("no complete scan before #%d", id)
	}
	return prev, err
}

// LoadReport reconstructs a stored report.
func (s *Store) LoadReport(ctx context.Context, id int64) (*core.Report, error) {
	r := &core.Report{ID: id}
	var at, host, sum, errs string
	err := s.db.QueryRowContext(ctx, `SELECT started_at, duration_ms, host_json, summary_json, inventory_scanned, vuln_scanned, partial, errors_json
		FROM scans WHERE id = ?`, id).Scan(&at, &r.DurationMS, &host, &sum, &r.InventoryScanned, &r.VulnScanned, &r.Partial, &errs)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("scan #%d not found", id)
	} else if err != nil {
		return nil, err
	}
	r.StartedAt, _ = time.Parse(time.RFC3339Nano, at)
	_ = json.Unmarshal([]byte(host), &r.Host)
	_ = json.Unmarshal([]byte(sum), &r.Summary)
	_ = json.Unmarshal([]byte(errs), &r.Errors)

	if err := each(ctx, s.db, `SELECT check_id, title, category, severity, status, evidence, remediation, waiver FROM results WHERE scan_id = ?`, id,
		func(sc func(...any) error) error {
			var x core.Result
			var sev, st, waiver string
			if err := sc(&x.ID, &x.Title, &x.Category, &sev, &st, &x.Evidence, &x.Remediation, &waiver); err != nil {
				return err
			}
			x.Waiver = parseOpt[core.Waiver](waiver)
			x.Severity, _ = core.ParseSeverity(sev)
			x.Status = core.Status(st)
			r.Results = append(r.Results, x)
			return nil
		}); err != nil {
		return nil, err
	}
	core.SortResults(r.Results)
	if err := each(ctx, s.db, `SELECT manager, name, version, arch, ecosystem, source_name, source_version, path FROM packages WHERE scan_id = ?`, id,
		func(sc func(...any) error) error {
			var p core.Package
			if err := sc(&p.Manager, &p.Name, &p.Version, &p.Arch, &p.Ecosystem, &p.SourceName, &p.SourceVersion, &p.Path); err != nil {
				return err
			}
			r.Packages = append(r.Packages, p)
			return nil
		}); err != nil {
		return nil, err
	}
	if err := each(ctx, s.db, `SELECT vuln_id, package, version, ecosystem, severity, cvss, kev, fixed_in, summary, aliases, epss, priority, waiver, in_use, processes, path
		FROM vulns WHERE scan_id = ?`, id,
		func(sc func(...any) error) error {
			var v core.Vuln
			var sev, aliases, waiver, procs string
			var inUse int
			if err := sc(&v.ID, &v.Package, &v.Version, &v.Ecosystem, &sev, &v.CVSS, &v.KEV, &v.FixedIn, &v.Summary, &aliases, &v.EPSS, &v.Priority, &waiver, &inUse, &procs, &v.Path); err != nil {
				return err
			}
			if inUse >= 0 {
				v.InUse = new(bool)
				*v.InUse = inUse == 1
			}
			if procs != "" {
				v.Processes = strings.Split(procs, ",")
			}
			v.Waiver = parseOpt[core.Waiver](waiver)
			if v.Priority == "" { // scans recorded before priorities existed
				v.Prioritize()
			}
			v.Severity, _ = core.ParseSeverity(sev)
			if aliases != "" {
				v.Aliases = strings.Split(aliases, ",")
			}
			r.Vulns = append(r.Vulns, v)
			return nil
		}); err != nil {
		return nil, err
	}
	core.SortVulns(r.Vulns)
	return r, nil
}

func each(ctx context.Context, db *sql.DB, q string, arg any, fn func(scan func(...any) error) error) error {
	rows, err := db.QueryContext(ctx, q, arg)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := fn(rows.Scan); err != nil {
			return err
		}
	}
	return rows.Err()
}

// CheckPoint is the status of one check in one scan.
type CheckPoint struct {
	ScanID    int64       `json:"scan_id"`
	StartedAt time.Time   `json:"started_at"`
	Status    core.Status `json:"status"`
	Evidence  string      `json:"evidence,omitempty"`
}

// CheckHistory returns a check's status timeline, newest first.
func (s *Store) CheckHistory(ctx context.Context, checkID string, limit int) ([]CheckPoint, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT r.scan_id, s.started_at, r.status, r.evidence
		FROM results r JOIN scans s ON s.id = r.scan_id WHERE r.check_id = ? ORDER BY r.scan_id DESC LIMIT ?`,
		strings.ToUpper(checkID), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CheckPoint
	for rows.Next() {
		var p CheckPoint
		var at, st string
		if err := rows.Scan(&p.ScanID, &at, &st, &p.Evidence); err != nil {
			return nil, err
		}
		p.StartedAt, _ = time.Parse(time.RFC3339Nano, at)
		p.Status = core.Status(st)
		out = append(out, p)
	}
	return out, rows.Err()
}

// VulnFirstSeen returns when a vuln ID (or alias) first appeared in history.
func (s *Store) VulnFirstSeen(ctx context.Context, vulnID string) (scanID int64, at time.Time, err error) {
	var a string
	err = s.db.QueryRowContext(ctx, `SELECT v.scan_id, s.started_at FROM vulns v JOIN scans s ON s.id = v.scan_id
		WHERE v.vuln_id = ?1 OR ',' || v.aliases || ',' LIKE '%,' || ?1 || ',%' ORDER BY v.scan_id ASC LIMIT 1`, vulnID).Scan(&scanID, &a)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, time.Time{}, nil
	}
	at, _ = time.Parse(time.RFC3339Nano, a)
	return scanID, at, err
}

// Prune keeps the newest `keep` scans and returns how many were (or, with
// dryRun, would be) deleted.
func (s *Store) Prune(ctx context.Context, keep int, dryRun bool) (int64, error) {
	if dryRun {
		var n int64
		err := s.db.QueryRowContext(ctx, `SELECT MAX(COUNT(*) - ?, 0) FROM scans`, keep).Scan(&n)
		return n, err
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM scans WHERE id NOT IN (SELECT id FROM scans ORDER BY id DESC LIMIT ?)`, keep)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		_, _ = s.db.ExecContext(ctx, `VACUUM`)
	}
	return n, nil
}

// Stats summarises database contents.
type Stats struct {
	Path        string `json:"path"`
	Scans       int    `json:"scans"`
	CachedVulns int    `json:"cached_advisories"`
	KEVEntries  int    `json:"kev_entries"`
	EPSSScores  int    `json:"epss_scores"`
	KEVSyncedAt string `json:"kev_synced_at,omitempty"`
	KEVVersion  string `json:"kev_catalog_version,omitempty"`
	LastScanAt  string `json:"last_scan_at,omitempty"`
}

func (s *Store) Stats(ctx context.Context) (*Stats, error) {
	st := &Stats{Path: s.Path}
	for q, dst := range map[string]*int{
		`SELECT COUNT(*) FROM scans`: &st.Scans, `SELECT COUNT(*) FROM vuln_cache`: &st.CachedVulns, `SELECT COUNT(*) FROM kev`: &st.KEVEntries,
		`SELECT COUNT(*) FROM epss`: &st.EPSSScores,
	} {
		if err := s.db.QueryRowContext(ctx, q).Scan(dst); err != nil {
			return nil, err
		}
	}
	st.KEVSyncedAt, _ = s.Meta(ctx, "kev_synced_at")
	st.KEVVersion, _ = s.Meta(ctx, "kev_version")
	_ = s.db.QueryRowContext(ctx, `SELECT started_at FROM scans ORDER BY id DESC LIMIT 1`).Scan(&st.LastScanAt)
	return st, nil
}
