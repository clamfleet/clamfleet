// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// events.go: detection events in SQLite (Milestone 5): ingest with receipts
// and occurrence counting, the console's list and counts, acknowledgement
// (audited in the same transaction) and retention.
//
// Dependencies: the generated sqlcdb package and internal/store. Paths are
// carried to the console and never into an audit row, an error or a log line.

package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/clamfleet/clamfleet/internal/proto"
	"github.com/clamfleet/clamfleet/internal/store"
	"github.com/clamfleet/clamfleet/internal/store/sqlite/sqlcdb"
)

// RecordEvent implements store.Store; see the interface for the rules.
//
// All of it is one transaction on the write connection, so two racing posts of
// the same detection cannot both pass the receipt check.
func (s *Store) RecordEvent(ctx context.Context, e store.EventRecord) (bool, error) {
	ts := unix(proto.UTC(e.Event.TS))
	recv := unix(e.ReceivedAt)
	var stored bool
	err := s.inTx(ctx, func(q *sqlcdb.Queries) error {
		agentID := ""
		if e.Event.ID != nil {
			agentID = *e.Event.ID
		}
		if agentID != "" {
			// A retry of an event we already took: nothing to do. This is what
			// tells a retry from a second, genuine detection with the same key.
			seen, err := q.EventReceiptExists(ctx, sqlcdb.EventReceiptExistsParams{HostID: e.HostID, AgentEventID: agentID})
			if err != nil {
				return err
			}
			if seen > 0 {
				return nil
			}
		}
		id, err := q.InsertEvent(ctx, sqlcdb.InsertEventParams{
			HostID: e.HostID, Ts: ts, ReceivedAt: recv,
			Path: e.Event.Path, Signature: e.Event.Signature, Source: e.Event.Source,
		})
		switch {
		case err == nil:
			stored = true
		case errors.Is(err, sql.ErrNoRows):
			// The natural key already exists.
			if agentID == "" {
				return nil // a client without ids: today's behaviour, a duplicate is dropped
			}
			// A different agent id on the same (host, second, path, signature): a
			// distinct detection. Count it on the existing row; no second alert.
			id, err = q.EventIDByKey(ctx, sqlcdb.EventIDByKeyParams{HostID: e.HostID, Ts: ts, Path: e.Event.Path, Signature: e.Event.Signature})
			if err != nil {
				return err
			}
			if err := q.BumpEventOccurrences(ctx, id); err != nil {
				return err
			}
		default:
			return err
		}
		if agentID == "" {
			return nil
		}
		return q.InsertEventReceipt(ctx, sqlcdb.InsertEventReceiptParams{HostID: e.HostID, AgentEventID: agentID, EventID: id, ReceivedAt: recv})
	})
	return stored, err
}

func eventRow(r sqlcdb.ListEventsRow) store.EventRow {
	return store.EventRow{
		ID: r.ID, HostID: r.HostID, Host: r.HostName,
		TS: time.Unix(r.Ts, 0).UTC(), ReceivedAt: time.Unix(r.ReceivedAt, 0).UTC(),
		Path: r.Path, Signature: r.Signature, Source: r.Source, Occurrences: r.Occurrences,
		AckBy: r.AckBy.String, AckAt: nullTime(r.AckAt),
	}
}

func eventRowByID(r sqlcdb.EventRowByIDRow) store.EventRow {
	return eventRow(sqlcdb.ListEventsRow(r))
}

// ListEvents implements store.EventStore.
func (s *Store) ListEvents(ctx context.Context, f store.EventFilter) ([]store.EventRow, error) {
	f, err := f.Normalised()
	if err != nil {
		return nil, err
	}
	rows, err := sqlcdb.New(s.r).ListEvents(ctx, sqlcdb.ListEventsParams{
		Host: f.Host, Sig: f.Signature, Ack: f.Ack, BeforeID: f.Before, UpTo: f.UpTo, MaxRows: int64(f.Limit),
	})
	if err != nil {
		return nil, err
	}
	out := make([]store.EventRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, eventRow(r))
	}
	return out, nil
}

// CountEvents implements store.EventStore.
func (s *Store) CountEvents(ctx context.Context, f store.EventFilter) (int64, error) {
	f, err := f.Normalised()
	if err != nil {
		return 0, err
	}
	return sqlcdb.New(s.r).CountEvents(ctx, sqlcdb.CountEventsParams{Host: f.Host, Sig: f.Signature, Ack: f.Ack, UpTo: f.UpTo})
}

// MaxEventID implements store.EventStore.
func (s *Store) MaxEventID(ctx context.Context, f store.EventFilter) (int64, error) {
	f, err := f.Normalised()
	if err != nil {
		return 0, err
	}
	return sqlcdb.New(s.r).MaxEventID(ctx, sqlcdb.MaxEventIDParams{Host: f.Host, Sig: f.Signature, Ack: f.Ack})
}

// CountOpenEvents implements store.EventStore.
func (s *Store) CountOpenEvents(ctx context.Context) (int64, error) {
	return sqlcdb.New(s.r).CountOpenEvents(ctx)
}

// AckEvent implements store.EventStore.
func (s *Store) AckEvent(ctx context.Context, id int64, now time.Time, a store.Audit) (store.EventRow, bool, error) {
	var row store.EventRow
	acked := false
	err := s.inTx(ctx, func(q *sqlcdb.Queries) error {
		r, err := q.EventRowByID(ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return err
		}
		n, err := q.AckEventByID(ctx, sqlcdb.AckEventByIDParams{AckBy: nullStr(a.Actor), AckAt: nullInt(now), ID: id})
		if err != nil {
			return err
		}
		if n == 1 {
			acked = true
			if s.afterAckUpdate != nil {
				if err := s.afterAckUpdate(); err != nil {
					return err
				}
			}
			// The audit row is in the same transaction: an acknowledgement without
			// its audit row cannot exist. It names the signature, never the path.
			if err := writeAuditKind(ctx, q, now, a, store.ActionEventAck, store.TargetEvent, r.HostName, map[string]string{
				"event_id": strconv.FormatInt(id, 10), "signature": store.TruncateForAudit(r.Signature),
			}); err != nil {
				return err
			}
		}
		// Re-read: when n == 0 somebody else acknowledged it first, and the row
		// shows who.
		r, err = q.EventRowByID(ctx, id)
		if err != nil {
			return err
		}
		row = eventRowByID(r)
		return nil
	})
	if err != nil {
		return store.EventRow{}, false, err
	}
	return row, acked, nil
}

// AckEvents implements store.EventStore.
func (s *Store) AckEvents(ctx context.Context, f store.EventFilter, upto, expected int64, now time.Time, a store.Audit) (int64, error) {
	if upto <= 0 {
		// Without a bound "acknowledge all" would also take detections that
		// arrived after the admin looked: refuse rather than guess.
		return 0, errors.New("bulk acknowledgement needs an upper event id")
	}
	var n int64
	err := s.inTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		n, err = q.AckEventsBulk(ctx, sqlcdb.AckEventsBulkParams{
			AckBy: nullStr(a.Actor), AckAt: nullInt(now), UpTo: upto, Host: f.Host, Sig: f.Signature,
		})
		if err != nil || n == 0 {
			return err
		}
		if s.afterAckUpdate != nil {
			if err := s.afterAckUpdate(); err != nil {
				return err
			}
		}
		target := f.Host
		if target == "" {
			target = "*"
		}
		return writeAuditKind(ctx, q, now, a, store.ActionEventAckBulk, store.TargetEvent, target, map[string]string{
			"count": strconv.FormatInt(n, 10), "upto": strconv.FormatInt(upto, 10), "expected": strconv.FormatInt(expected, 10),
			"signature_filter": store.TruncateForAudit(f.Signature),
		})
	})
	if err != nil {
		return 0, fmt.Errorf("acknowledge events: %w", err)
	}
	return n, nil
}

// PruneEvents implements store.EventStore. Each batch is its own transaction,
// so a large backlog never holds the write lock for long.
func (s *Store) PruneEvents(ctx context.Context, before time.Time, batch int) (int64, error) {
	return s.pruneBatches(ctx, batch, func(q *sqlcdb.Queries) (int64, error) {
		return q.PruneEvents(ctx, sqlcdb.PruneEventsParams{Before: unix(before), Batch: int64(batch)})
	})
}

// PruneAlertWindows implements store.EventStore.
func (s *Store) PruneAlertWindows(ctx context.Context, before time.Time, batch int) (int64, error) {
	return s.pruneBatches(ctx, batch, func(q *sqlcdb.Queries) (int64, error) {
		return q.PruneClosedWindows(ctx, sqlcdb.PruneClosedWindowsParams{Before: nullInt(before), Batch: int64(batch)})
	})
}

// pruneBatches repeats del, one transaction per call, until a call deletes
// fewer than batch rows.
func (s *Store) pruneBatches(ctx context.Context, batch int, del func(q *sqlcdb.Queries) (int64, error)) (int64, error) {
	if batch < 1 {
		return 0, errors.New("prune batch must be at least 1")
	}
	var total int64
	for {
		var n int64
		if err := s.inTx(ctx, func(q *sqlcdb.Queries) error {
			var err error
			n, err = del(q)
			return err
		}); err != nil {
			return total, err
		}
		total += n
		if n < int64(batch) || ctx.Err() != nil {
			return total, ctx.Err()
		}
	}
}
