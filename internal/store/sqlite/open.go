// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Package sqlite implements store.Store on SQLite (modernc.org/sqlite, pure
// Go, no cgo) with goose migrations and sqlc-generated queries.
//
// open.go: connection setup and schema versioning.
//
// One write connection, one read pool (spec 8.1). They are two *sql.DB on the
// same file:
//   - the writer has SetMaxOpenConns(1) and _txlock=immediate, so writes are
//     serialised in-process and a transaction takes the write lock up front
//     (a deferred transaction that upgrades later can fail with SQLITE_BUSY
//     without the busy handler getting a chance to wait);
//   - the readers run with query_only=1, so a write sent to the wrong pool fails
//     loudly instead of silently becoming a second write path.
//
// The server and the admin CLI are separate processes on one file. WAL mode and
// busy_timeout serialise them. Only Migrate changes the schema, and only the
// "serve" and "migrate" commands call it, so two processes never migrate at once.
//
// Dependencies: modernc.org/sqlite, github.com/pressly/goose/v3, the embedded
// migrations package.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"

	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver

	"github.com/clamfleet/clamfleet/migrations"
)

// ErrPendingMigrations is returned by CheckMigrated when the database is
// older than this binary. The CLI shows the hint to run "clamfleet-server migrate".
var ErrPendingMigrations = errors.New("database schema is out of date: run `clamfleet-server migrate`")

// Store is the SQLite implementation of store.Store.
type Store struct {
	path string
	w    *sql.DB // single write connection
	r    *sql.DB // read pool, query_only
	prov *goose.Provider

	// onPruneTx is a test hook: pruneBatches calls it before each batch
	// transaction, so a test can count them. Always nil in production.
	onPruneTx func()
	// afterTokenUpdate is a test hook: SetToken calls it between the token
	// update and the audit insert, so a test can prove that a failure there
	// rolls both back. Always nil in production.
	afterTokenUpdate func() error
	// afterAckUpdate is a test hook: AckEvent and AckEvents call it between the
	// acknowledgement UPDATE and the audit row, so a test can prove the two are
	// one transaction.
	afterAckUpdate func() error

	// beforeHealthWrite is a test hook: EvaluateHosts calls it after reading
	// its inputs and before writing, so a test can interleave a competing
	// report at exactly the point where a read-outside-the-lock design would
	// go wrong. Always nil in production.
	beforeHealthWrite func() error

	// beforeAlertPlanWrite is a test hook: PlanAlerts calls it after the planner
	// ran and before anything is written, to prove a failure leaves no delivery,
	// no notify row, no log row and the flags still set. Always nil in production.
	beforeAlertPlanWrite func() error
	// afterAlertPlanDeliveries is a test hook: PlanAlerts calls it after the
	// windows and deliveries are written and before the flags are cleared, so a
	// test can prove that a window is closed together with its summary or not at all.
	afterAlertPlanDeliveries func() error

	// betweenExpireWrites is a test hook: ExpireLeases calls it between failing a
	// delivery and writing its 'failed' log row, to prove the two are one
	// transaction. Always nil in production.
	betweenExpireWrites func() error

	// betweenResealRows is a test hook: ResealSecrets calls it after each row, to
	// prove a failure midway rolls every row back. Always nil in production.
	betweenResealRows func() error

	// afterHostDelete is a test hook: DeleteHost calls it between the delete
	// and the audit insert, to prove a failure there rolls both back.
	afterHostDelete func() error
}

// dsn builds the modernc DSN. Pragmas go in the DSN (not in an Exec after
// Open) because the pool opens new connections at will and every one of them
// must carry the same settings. extra are additional _pragma values.
func dsn(path, txlock string, extraPragmas ...string) string {
	q := url.Values{}
	for _, p := range append([]string{
		"journal_mode(WAL)", "busy_timeout(5000)", "synchronous(NORMAL)", "foreign_keys(1)",
	}, extraPragmas...) {
		q.Add("_pragma", p)
	}
	if txlock != "" {
		q.Set("_txlock", txlock)
	}
	u := url.URL{Scheme: "file", Path: path, RawQuery: q.Encode()}
	return u.String()
}

// Open opens (creating it if missing) the database at path, applies no
// migration, and refuses a database whose schema is newer than this binary.
//
// A missing file is pre-created with O_EXCL and mode 0600, because the
// database holds token hashes, host names and file paths of detections
// (GDPR). SQLite creates the -wal and -shm files with the mode of the main
// file, so they come out 0600 too (a test proves it). An existing file keeps
// its mode.
//
// Side effects: creates the file; opens connections; does not write the schema.
func Open(ctx context.Context, path string) (*Store, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	switch {
	case err == nil:
		f.Close()
	case errors.Is(err, fs.ErrExist):
	default:
		return nil, fmt.Errorf("create database %s: %w", path, err)
	}

	w, err := sql.Open("sqlite", dsn(path, "immediate"))
	if err != nil {
		return nil, fmt.Errorf("open database %s: %w", path, err)
	}
	w.SetMaxOpenConns(1)
	r, err := sql.Open("sqlite", dsn(path, "", "query_only(1)"))
	if err != nil {
		w.Close()
		return nil, fmt.Errorf("open database %s: %w", path, err)
	}
	sub, err := fs.Sub(migrations.SQLite, "sqlite")
	if err != nil {
		w.Close()
		r.Close()
		return nil, err
	}
	// WithDisableGlobalRegistry: no process-global goose state, so tests can
	// open many stores in one process.
	prov, err := goose.NewProvider(goose.DialectSQLite3, w, sub, goose.WithDisableGlobalRegistry(true))
	if err != nil {
		w.Close()
		r.Close()
		return nil, fmt.Errorf("migrations: %w", err)
	}
	s := &Store{path: path, w: w, r: r, prov: prov}
	if err := s.checkNotNewer(ctx); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// Close closes both pools.
func (s *Store) Close() error {
	return errors.Join(s.r.Close(), s.w.Close())
}

// newestEmbedded is the highest migration version in this binary.
func (s *Store) newestEmbedded() int64 {
	src := s.prov.ListSources()
	return src[len(src)-1].Version
}

// SchemaVersion returns the highest migration applied to the database, 0 for
// a database without any.
func (s *Store) SchemaVersion(ctx context.Context) (int64, error) {
	// An empty file has no goose table yet; ask SQLite instead of parsing
	// goose's error text for that case.
	var n int
	err := s.w.QueryRowContext(ctx,
		`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='goose_db_version'`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("read schema version: %w", err)
	}
	if n == 0 {
		return 0, nil
	}
	v, err := s.prov.GetDBVersion(ctx)
	if err != nil {
		return 0, fmt.Errorf("read schema version: %w", err)
	}
	return v, nil
}

// checkNotNewer is the downgrade guard: an old binary on a database a newer
// one migrated could misread what it finds. Refused, never attempted.
func (s *Store) checkNotNewer(ctx context.Context) error {
	v, err := s.SchemaVersion(ctx)
	if err != nil {
		return err
	}
	if max := s.newestEmbedded(); v > max {
		return fmt.Errorf("database schema version %d is newer than this binary supports (%d): upgrade clamfleet-server, never run an older one on this database", v, max)
	}
	return nil
}

// Migrate applies every pending migration. Called by "serve" and "migrate"
// only. Side effect: DDL on the database.
func (s *Store) Migrate(ctx context.Context) error {
	if _, err := s.prov.Up(ctx); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}

// CheckMigrated returns ErrPendingMigrations unless the schema is exactly at
// this binary's version. The CLI commands other than "migrate" call it so
// they never migrate themselves.
func (s *Store) CheckMigrated(ctx context.Context) error {
	v, err := s.SchemaVersion(ctx)
	if err != nil {
		return err
	}
	if v != s.newestEmbedded() {
		return ErrPendingMigrations
	}
	return nil
}

// MigrateDown reverts the most recent migration. Development and tests only;
// no command calls it.
func (s *Store) MigrateDown(ctx context.Context) error {
	if _, err := s.prov.Down(ctx); err != nil {
		return fmt.Errorf("migrate down: %w", err)
	}
	return nil
}
