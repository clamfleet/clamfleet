// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// store.go: the store.Store implementation on top of the sqlc queries.
//
// Responsibilities: transactions (report write path, rotate/revoke with its
// audit row), conversion between domain types and SQL rows (unix-second
// integers for time, decision 1), and the read-pool/write-connection split:
// reads use s.r, everything that writes uses a transaction on s.w.
// Dependencies: the generated sqlcdb package, internal/store, internal/proto.
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/clamfleet/clamfleet/internal/proto"
	"github.com/clamfleet/clamfleet/internal/store"
	"github.com/clamfleet/clamfleet/internal/store/sqlite/sqlcdb"
)

var _ store.Store = (*Store)(nil)

func unix(t time.Time) int64            { return t.Unix() }
func nullInt(t time.Time) sql.NullInt64 { return sql.NullInt64{Int64: t.Unix(), Valid: true} }

func nullTime(n sql.NullInt64) *time.Time {
	if !n.Valid {
		return nil
	}
	t := time.Unix(n.Int64, 0).UTC()
	return &t
}

func nullString(n sql.NullString) *string {
	if !n.Valid {
		return nil
	}
	return &n.String
}

// rawJSON passes stored JSON text through; NULL becomes a nil RawMessage,
// which encodes as null.
func rawJSON(n sql.NullString) json.RawMessage {
	if !n.Valid {
		return nil
	}
	return json.RawMessage(n.String)
}

func lower(s string) string { return strings.ToLower(s) }

func nullStr(s string) sql.NullString { return sql.NullString{String: s, Valid: true} }

// inTx runs fn in one immediate transaction on the write connection.
func (s *Store) inTx(ctx context.Context, fn func(q *sqlcdb.Queries) error) error {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() // no-op after a successful Commit
	if err := fn(sqlcdb.New(tx)); err != nil {
		return err
	}
	return tx.Commit()
}

// writeAudit adds the audit row inside the caller's transaction. detail must
// never hold a secret.
func writeAudit(ctx context.Context, q *sqlcdb.Queries, now time.Time, a store.Audit, action, target string) error {
	return writeAuditKind(ctx, q, now, a, action, store.TargetHost, target, nil)
}

// writeAuditKind is writeAudit for any target kind, with a detail object
// (nil is "{}"). The detail is JSON text; keys and values are plain strings.
func writeAuditKind(ctx context.Context, q *sqlcdb.Queries, now time.Time, a store.Audit, action, targetKind, target string, detail map[string]string) error {
	d := []byte("{}")
	if len(detail) > 0 {
		var err error
		if d, err = json.Marshal(detail); err != nil {
			return fmt.Errorf("encode audit detail: %w", err)
		}
	}
	return q.InsertAudit(ctx, sqlcdb.InsertAuditParams{
		Ts: unix(now), ActorKind: a.Kind, Actor: a.Actor, Action: action,
		TargetKind: targetKind, Target: target, Detail: sql.NullString{String: string(d), Valid: true},
	})
}

// CreateHost implements store.Store.
func (s *Store) CreateHost(ctx context.Context, name string, tokenHash []byte, now time.Time, a store.Audit) (store.Host, error) {
	name, err := store.NormalizeHostName(name)
	if err != nil {
		return store.Host{}, err
	}
	var id int64
	err = s.inTx(ctx, func(q *sqlcdb.Queries) error {
		// Checked inside the immediate transaction, so it cannot race another
		// writer, and the caller gets a typed error without parsing driver text.
		if _, err := q.HostIDByName(ctx, name); err == nil {
			return store.ErrHostExists
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		id, err = q.CreateHost(ctx, sqlcdb.CreateHostParams{Name: name, TokenHash: tokenHash, Now: nullInt(now)})
		if err != nil {
			return err
		}
		return writeAudit(ctx, q, now, a, store.ActionHostAdd, name)
	})
	if err != nil {
		return store.Host{}, err
	}
	return store.Host{ID: id, Name: name, CreatedAt: time.Unix(unix(now), 0).UTC()}, nil
}

// HostByTokenHash implements store.Store.
func (s *Store) HostByTokenHash(ctx context.Context, hash []byte) (store.HostRef, error) {
	// A revoked host has token_hash NULL, which no equality can match; the
	// length check also keeps an empty input from ever reaching the query.
	if len(hash) == 0 {
		return store.HostRef{}, store.ErrNotFound
	}
	row, err := sqlcdb.New(s.r).HostRefByTokenHash(ctx, hash)
	if errors.Is(err, sql.ErrNoRows) {
		return store.HostRef{}, store.ErrNotFound
	}
	if err != nil {
		return store.HostRef{}, err
	}
	return store.HostRef{ID: row.ID, Name: row.Name}, nil
}

// SetToken implements store.Store.
func (s *Store) SetToken(ctx context.Context, name string, hash []byte, now time.Time, a store.Audit) error {
	name = lower(name)
	return s.inTx(ctx, func(q *sqlcdb.Queries) error {
		id, err := q.HostIDByName(ctx, name)
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return err
		}
		action := store.ActionTokenRotate
		if hash == nil {
			action = store.ActionTokenRevoke
			_, err = q.RevokeHostToken(ctx, sqlcdb.RevokeHostTokenParams{Now: nullInt(now), ID: id})
		} else {
			_, err = q.SetHostToken(ctx, sqlcdb.SetHostTokenParams{TokenHash: hash, Now: nullInt(now), ID: id})
		}
		if err != nil {
			return err
		}
		if s.afterTokenUpdate != nil {
			if err := s.afterTokenUpdate(); err != nil {
				return err
			}
		}
		return writeAudit(ctx, q, now, a, action, name)
	})
}

// DeleteHost implements store.Store.
func (s *Store) DeleteHost(ctx context.Context, name string, now time.Time, a store.Audit) error {
	name = lower(name)
	return s.inTx(ctx, func(q *sqlcdb.Queries) error {
		id, err := q.HostIDByName(ctx, name)
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return err
		}
		if _, err := q.DeleteHost(ctx, id); err != nil {
			return err
		}
		if s.afterHostDelete != nil {
			if err := s.afterHostDelete(); err != nil {
				return err
			}
		}
		return writeAudit(ctx, q, now, a, store.ActionHostDelete, name)
	})
}

// RecordReport implements store.Store.
//
// One immediate transaction:
//  1. insert the report, ignoring a duplicate (host_id, ts);
//  2. update last_seen (first_seen if unset), duplicate or not: a retry is
//     still proof the agent is alive;
//  3. if the report is new, make it the host's last_report unless a newer one
//     is already there, and replace the tags only then.
//
// Rule: "newer" is decided by min(agent ts, received_at). A late spooled
// report (Milestone 5) can then never overwrite a newer last_report, and a
// host whose clock runs ahead cannot lock last_report against its own later,
// correct reports. No report is rejected for clock skew.
func (s *Store) RecordReport(ctx context.Context, r store.ReportRecord) (store.ReportResult, error) {
	payload, err := json.Marshal(r.Report)
	if err != nil {
		return store.ReportResult{}, fmt.Errorf("encode report: %w", err)
	}
	ts := unix(proto.UTC(r.Report.TS))
	recv := unix(r.ReceivedAt)
	ord := min(ts, recv)

	// Fleet columns copied from the report (plain columns keep the fleet-wide
	// "newest daily" query portable, no JSON functions).
	var dailyVersion, dailyBuilt sql.NullInt64
	if d := r.Report.Sigs.Daily; d != nil {
		dailyVersion = sql.NullInt64{Int64: int64(d.Version), Valid: true}
		dailyBuilt = nullInt(d.Built)
	}
	var clamdVersion sql.NullString
	if v := r.Report.Clamd.Version; v != nil {
		clamdVersion = nullStr(*v)
	}

	var res store.ReportResult
	err = s.inTx(ctx, func(q *sqlcdb.Queries) error {
		prev, err := q.HostForReport(ctx, r.HostID)
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return err
		}
		res.PreviousReportedName = prev.String

		n, err := q.InsertReport(ctx, sqlcdb.InsertReportParams{
			HostID: r.HostID, Ts: ts, ReceivedAt: recv, Payload: string(payload),
		})
		if err != nil {
			return err
		}
		res.Stored = n == 1
		if err := q.TouchHostSeen(ctx, sqlcdb.TouchHostSeenParams{Now: nullInt(r.ReceivedAt), ID: r.HostID}); err != nil {
			return err
		}
		if !res.Stored {
			return nil
		}
		n, err = q.SetHostLastReport(ctx, sqlcdb.SetHostLastReportParams{
			Payload: nullStr(string(payload)), Ord: sql.NullInt64{Int64: ord, Valid: true},
			ReportedName: nullStr(r.Report.Host), AgentVersion: nullStr(r.Report.AgentVersion), ID: r.HostID,
			DailyVersion: dailyVersion, DailyBuilt: dailyBuilt, ClamdVersion: clamdVersion,
		})
		if err != nil {
			return err
		}
		res.Newest = n == 1
		if !res.Newest {
			return nil
		}
		if err := q.DeleteHostTags(ctx, r.HostID); err != nil {
			return err
		}
		for _, tag := range r.Report.Tags {
			if err := q.InsertHostTag(ctx, sqlcdb.InsertHostTagParams{HostID: r.HostID, Tag: tag}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return store.ReportResult{}, err
	}
	return res, nil
}

// RecordEvent implements store.Store.
func (s *Store) RecordEvent(ctx context.Context, e store.EventRecord) (bool, error) {
	var stored bool
	err := s.inTx(ctx, func(q *sqlcdb.Queries) error {
		n, err := q.InsertEvent(ctx, sqlcdb.InsertEventParams{
			HostID: e.HostID, Ts: unix(proto.UTC(e.Event.TS)), ReceivedAt: unix(e.ReceivedAt),
			Path: e.Event.Path, Signature: e.Event.Signature, Source: e.Event.Source,
		})
		stored = n == 1
		return err
	})
	return stored, err
}

// ListHosts implements store.Store.
func (s *Store) ListHosts(ctx context.Context) ([]store.HostSummary, error) {
	q := sqlcdb.New(s.r)
	rows, err := q.ListHosts(ctx)
	if err != nil {
		return nil, err
	}
	tagRows, err := q.ListAllHostTags(ctx)
	if err != nil {
		return nil, err
	}
	// One query for all tags, grouped here: no N+1.
	tags := map[int64][]string{}
	for _, t := range tagRows {
		tags[t.HostID] = append(tags[t.HostID], t.Tag)
	}
	out := make([]store.HostSummary, 0, len(rows))
	for _, r := range rows {
		hs := store.HostSummary{
			ID: r.ID, Name: r.Name, Tags: tags[r.ID], HasToken: r.HasToken,
			CreatedAt: time.Unix(r.CreatedAt, 0).UTC(), FirstSeen: nullTime(r.FirstSeen), LastSeen: nullTime(r.LastSeen),
			ReportedName: r.ReportedName.String, AgentVersion: r.AgentVersion.String,
			State: nullString(r.State), StateReason: rawJSON(r.StateReason), StateSince: nullTime(r.StateSince),
		}
		if hs.Tags == nil {
			hs.Tags = []string{}
		}
		out = append(out, hs)
	}
	return out, nil
}

// HostByName implements store.Store.
func (s *Store) HostByName(ctx context.Context, name string) (store.HostDetail, error) {
	name = lower(name)
	q := sqlcdb.New(s.r)
	h, err := q.HostByName(ctx, name)
	if errors.Is(err, sql.ErrNoRows) {
		return store.HostDetail{}, store.ErrNotFound
	}
	if err != nil {
		return store.HostDetail{}, err
	}
	tags, err := q.ListHostTags(ctx, h.ID)
	if err != nil {
		return store.HostDetail{}, err
	}
	reports, err := q.CountHostReports(ctx, h.ID)
	if err != nil {
		return store.HostDetail{}, err
	}
	events, err := q.CountHostEvents(ctx, h.ID)
	if err != nil {
		return store.HostDetail{}, err
	}
	audit, err := q.ListAuditForTarget(ctx, sqlcdb.ListAuditForTargetParams{TargetKind: "host", Target: name, MaxRows: 50})
	if err != nil {
		return store.HostDetail{}, err
	}
	changes, err := q.ListStateChanges(ctx, sqlcdb.ListStateChangesParams{HostID: h.ID, MaxRows: 50})
	if err != nil {
		return store.HostDetail{}, err
	}
	d := store.HostDetail{
		HostSummary: store.HostSummary{
			ID: h.ID, Name: h.Name, Tags: append([]string{}, tags...), HasToken: h.HasToken,
			CreatedAt: time.Unix(h.CreatedAt, 0).UTC(), FirstSeen: nullTime(h.FirstSeen), LastSeen: nullTime(h.LastSeen),
			ReportedName: h.ReportedName.String, AgentVersion: h.AgentVersion.String,
			State: nullString(h.State), StateReason: rawJSON(h.StateReason), StateSince: nullTime(h.StateSince),
		},
		TokenCreatedAt: nullTime(h.TokenCreatedAt),
		ReportCount:    reports, EventCount: events,
	}
	if h.LastReport.Valid {
		d.LastReport = json.RawMessage(h.LastReport.String)
	}
	for _, a := range audit {
		d.Audit = append(d.Audit, store.AuditEntry{
			TS: time.Unix(a.Ts, 0).UTC(), ActorKind: a.ActorKind, Actor: a.Actor, Action: a.Action,
			TargetKind: a.TargetKind, Target: a.Target, Detail: a.Detail.String,
		})
	}
	for _, c := range changes {
		d.StateChanges = append(d.StateChanges, store.StateChange{
			TS: time.Unix(c.Ts, 0).UTC(), From: nullString(c.FromState), To: c.ToState, Reason: json.RawMessage(c.Reason),
		})
	}
	return d, nil
}

// Ping implements store.Store.
func (s *Store) Ping(ctx context.Context) error {
	var one int
	return s.r.QueryRowContext(ctx, `SELECT 1`).Scan(&one)
}
