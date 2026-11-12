// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// health.go: store.HealthStore on SQLite. One method, EvaluateHosts, which
// reads the evaluation inputs and writes the result under one write lock.
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/clamfleet/clamfleet/internal/proto"
	"github.com/clamfleet/clamfleet/internal/store"
	"github.com/clamfleet/clamfleet/internal/store/sqlite/sqlcdb"
)

var _ store.HealthStore = (*Store)(nil)

// healthRow is the common shape of the two input queries.
type healthRow struct {
	id          int64
	name        string
	createdAt   int64
	lastSeen    sql.NullInt64
	lastReport  sql.NullString
	state       sql.NullString
	stateReason sql.NullString
}

// EvaluateHosts implements store.HealthStore.
//
// The transaction is immediate (the writer's DSN), so it holds the write lock
// from BeginTx on: a report arriving meanwhile waits for the commit and gets
// its own evaluation afterwards. Reading the inputs outside this transaction
// would let a slow evaluation overwrite a newer one (plan 4.2, mutation 18).
func (s *Store) EvaluateHosts(ctx context.Context, now time.Time, ids []int64, eval func(store.HealthInput) store.HealthOutcome) ([]store.Transition, error) {
	var out []store.Transition
	err := s.inTx(ctx, func(q *sqlcdb.Queries) error {
		newest, err := q.FleetNewestDaily(ctx)
		if err != nil {
			return err
		}
		rows, err := healthRows(ctx, q, ids)
		if err != nil {
			return err
		}
		type decided struct {
			row healthRow
			out store.HealthOutcome
		}
		var todo []decided
		for _, r := range rows {
			in := store.HealthInput{
				HostID: r.id, Name: r.name, CreatedAt: time.Unix(r.createdAt, 0).UTC(),
				LastSeen: nullTime(r.lastSeen), FleetNewestDaily: int(newest),
			}
			if r.lastReport.Valid {
				var rep proto.Report
				// NOTE: assumption. The stored text is our own canonical encoding, so a
				// decode failure means a corrupt row. The host is then evaluated as if
				// it had no report (it can still go STALE) instead of blocking the
				// evaluation of every other host.
				if json.Unmarshal([]byte(r.lastReport.String), &rep) == nil {
					in.Report = &rep
				}
			}
			todo = append(todo, decided{r, eval(in)})
		}

		if s.beforeHealthWrite != nil {
			if err := s.beforeHealthWrite(); err != nil {
				return err
			}
		}

		for _, d := range todo {
			if d.out.State == "" { // pending: nothing to record
				continue
			}
			reason := string(d.out.Reasons)
			if reason == "" {
				reason = "[]"
			}
			switch {
			case !d.row.state.Valid || d.row.state.String != d.out.State:
				if err := q.SetHostState(ctx, sqlcdb.SetHostStateParams{
					State: nullStr(d.out.State), Reason: nullStr(reason), Since: nullInt(now), ID: d.row.id,
				}); err != nil {
					return err
				}
				if err := q.InsertStateChange(ctx, sqlcdb.InsertStateChangeParams{
					HostID: d.row.id, Ts: unix(now), FromState: d.row.state, ToState: d.out.State, Reason: reason,
				}); err != nil {
					return err
				}
				out = append(out, store.Transition{
					HostID: d.row.id, Host: d.row.name, TS: time.Unix(unix(now), 0).UTC(),
					From: nullString(d.row.state), To: d.out.State, Reasons: json.RawMessage(reason),
				})
			case d.row.stateReason.String != reason:
				// Same state, different reasons: keep the current reasons fresh, but
				// it is not a transition and gets no history row.
				if err := q.SetHostStateReason(ctx, sqlcdb.SetHostStateReasonParams{Reason: nullStr(reason), ID: d.row.id}); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// healthRows reads the inputs of ids (all hosts with a token when nil). An id
// that is unknown or revoked is skipped: the host may have been revoked or
// deleted between a report and its evaluation.
func healthRows(ctx context.Context, q *sqlcdb.Queries, ids []int64) ([]healthRow, error) {
	var out []healthRow
	if ids == nil {
		rs, err := q.HealthInputs(ctx)
		if err != nil {
			return nil, err
		}
		for _, r := range rs {
			out = append(out, healthRow{r.ID, r.Name, r.CreatedAt, r.LastSeen, r.LastReport, r.State, r.StateReason})
		}
		return out, nil
	}
	for _, id := range ids {
		r, err := q.HealthInputByID(ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("host %d: %w", id, err)
		}
		out = append(out, healthRow{r.ID, r.Name, r.CreatedAt, r.LastSeen, r.LastReport, r.State, r.StateReason})
	}
	return out, nil
}
