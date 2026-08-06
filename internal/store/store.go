// Package store persists assessment history in an embedded SQLite database.
//
// It uses the pure-Go modernc.org/sqlite driver so the project keeps building
// with CGO_ENABLED=0 (static binaries, distroless images).
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"github.com/ghe-wizard/ghe-wizard/internal/engine"
	"github.com/ghe-wizard/ghe-wizard/internal/rules"
)

// Store is a handle to the history database.
type Store struct {
	db *sql.DB
}

// Open opens (and migrates) the database at path. An empty path or ":memory:"
// uses a private in-memory database.
func Open(path string) (*Store, error) {
	dsn := path
	if path == "" || path == ":memory:" {
		// Shared-cache in-memory DB that survives for the life of the handle.
		dsn = "file::memory:?cache=shared"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	db.SetMaxOpenConns(1) // SQLite: serialize writers; simplest correct default.
	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	const schema = `
CREATE TABLE IF NOT EXISTS scan_runs (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  enterprise   TEXT NOT NULL,
  created_at   TEXT NOT NULL,
  score        INTEGER NOT NULL,
  total        INTEGER NOT NULL,
  pass         INTEGER NOT NULL,
  fail         INTEGER NOT NULL,
  warn         INTEGER NOT NULL,
  manual       INTEGER NOT NULL,
  error        INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_runs_ent_time ON scan_runs(enterprise, created_at);

CREATE TABLE IF NOT EXISTS rule_results (
  run_id    INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
  rule_id   TEXT NOT NULL,
  domain    TEXT NOT NULL,
  severity  TEXT NOT NULL,
  status    TEXT NOT NULL,
  detail    TEXT
);
CREATE INDEX IF NOT EXISTS idx_results_run ON rule_results(run_id);

CREATE TABLE IF NOT EXISTS remediation_logs (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL,
  enterprise TEXT NOT NULL,
  rule_id    TEXT NOT NULL,
  applied    INTEGER NOT NULL,
  dry_run    INTEGER NOT NULL,
  changes    TEXT,
  errors     TEXT
);
`
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}

// RunSummary is a lightweight view of a stored scan run.
type RunSummary struct {
	ID         int64     `json:"id"`
	Enterprise string    `json:"enterprise"`
	CreatedAt  time.Time `json:"created_at"`
	Score      int       `json:"score"`
	Total      int       `json:"total"`
	Pass       int       `json:"pass"`
	Fail       int       `json:"fail"`
	Warn       int       `json:"warn"`
	Manual     int       `json:"manual"`
	Error      int       `json:"error"`
}

// SaveRun persists a scorecard and returns the new run's summary (with ID).
func (s *Store) SaveRun(ctx context.Context, sc *engine.Scorecard) (RunSummary, error) {
	c := sc.Summary.Counts
	rs := RunSummary{
		Enterprise: sc.Enterprise,
		CreatedAt:  sc.GeneratedAt,
		Score:      sc.Summary.Score,
		Total:      sc.Summary.Total,
		Pass:       c["pass"], Fail: c["fail"], Warn: c["warn"],
		Manual: c["manual"], Error: c["error"],
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return rs, err
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx,
		`INSERT INTO scan_runs(enterprise,created_at,score,total,pass,fail,warn,manual,error)
		 VALUES(?,?,?,?,?,?,?,?,?)`,
		rs.Enterprise, rs.CreatedAt.UTC().Format(time.RFC3339), rs.Score, rs.Total,
		rs.Pass, rs.Fail, rs.Warn, rs.Manual, rs.Error)
	if err != nil {
		return rs, fmt.Errorf("insert run: %w", err)
	}
	id, _ := res.LastInsertId()
	rs.ID = id

	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO rule_results(run_id,rule_id,domain,severity,status,detail) VALUES(?,?,?,?,?,?)`)
	if err != nil {
		return rs, err
	}
	defer stmt.Close()
	for _, r := range sc.Results {
		if _, err := stmt.ExecContext(ctx, id, r.Meta.ID, string(r.Meta.Domain),
			string(r.Meta.Severity), string(r.Status), r.Detail); err != nil {
			return rs, fmt.Errorf("insert result %s: %w", r.Meta.ID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return rs, err
	}
	return rs, nil
}

// Runs returns up to limit most-recent runs for an enterprise (newest first).
func (s *Store) Runs(ctx context.Context, enterprise string, limit int) ([]RunSummary, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,enterprise,created_at,score,total,pass,fail,warn,manual,error
		   FROM scan_runs WHERE enterprise=? ORDER BY id DESC LIMIT ?`,
		enterprise, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RunSummary
	for rows.Next() {
		var r RunSummary
		var ts string
		if err := rows.Scan(&r.ID, &r.Enterprise, &ts, &r.Score, &r.Total,
			&r.Pass, &r.Fail, &r.Warn, &r.Manual, &r.Error); err != nil {
			return nil, err
		}
		r.CreatedAt, _ = time.Parse(time.RFC3339, ts)
		out = append(out, r)
	}
	return out, rows.Err()
}

// RuleStatuses returns a rule_id -> status map for a given run (for diffing).
func (s *Store) RuleStatuses(ctx context.Context, runID int64) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT rule_id,status FROM rule_results WHERE run_id=?`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]string{}
	for rows.Next() {
		var id, st string
		if err := rows.Scan(&id, &st); err != nil {
			return nil, err
		}
		m[id] = st
	}
	return m, rows.Err()
}

// Drift describes how a scorecard changed relative to a previous run.
type Drift struct {
	PreviousRunID int64    `json:"previous_run_id"`
	ScoreDelta    int      `json:"score_delta"`
	NewlyFailing  []string `json:"newly_failing"`
	NewlyFixed    []string `json:"newly_fixed"`
	Regressed     []string `json:"regressed"` // pass/warn -> fail
}

// DriftAgainstPrevious compares the newest run for the enterprise (excluding the
// given currentRunID) with the provided current scorecard.
func (s *Store) DriftAgainstPrevious(ctx context.Context, currentRunID int64, sc *engine.Scorecard) (*Drift, error) {
	runs, err := s.Runs(ctx, sc.Enterprise, 2)
	if err != nil {
		return nil, err
	}
	var prev *RunSummary
	for i := range runs {
		if runs[i].ID != currentRunID {
			prev = &runs[i]
			break
		}
	}
	if prev == nil {
		return nil, nil // no prior run to compare
	}
	prevStatus, err := s.RuleStatuses(ctx, prev.ID)
	if err != nil {
		return nil, err
	}
	d := &Drift{PreviousRunID: prev.ID, ScoreDelta: sc.Summary.Score - prev.Score}
	for _, r := range sc.Results {
		old := prevStatus[r.Meta.ID]
		cur := string(r.Status)
		if old == "" {
			continue
		}
		wasBad := old == string(rules.StatusFail)
		isBad := cur == string(rules.StatusFail)
		if !wasBad && isBad {
			d.NewlyFailing = append(d.NewlyFailing, r.Meta.ID)
			if old == string(rules.StatusPass) || old == string(rules.StatusWarn) {
				d.Regressed = append(d.Regressed, r.Meta.ID)
			}
		}
		if wasBad && !isBad {
			d.NewlyFixed = append(d.NewlyFixed, r.Meta.ID)
		}
	}
	return d, nil
}

// SaveRemediations records remediation results.
func (s *Store) SaveRemediations(ctx context.Context, enterprise string, results []rules.RemediationResult) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	now := time.Now().UTC().Format(time.RFC3339)
	for _, r := range results {
		changes, _ := json.Marshal(r.Changes)
		errs, _ := json.Marshal(r.Errors)
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO remediation_logs(created_at,enterprise,rule_id,applied,dry_run,changes,errors)
			 VALUES(?,?,?,?,?,?,?)`,
			now, enterprise, r.RuleID, b2i(r.Applied), b2i(r.DryRun), string(changes), string(errs)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
