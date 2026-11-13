-- SPDX-License-Identifier: AGPL-3.0-only
-- SPDX-FileCopyrightText: The ClamFleet Authors

-- Milestone 5 schema: detection events, their idempotency receipts, and the
-- durable windows behind detection summaries (docs/plans/milestone-5.md 4.7).
--
-- Additive only: indexes, ADD COLUMNs with a constant default, new tables. No
-- table rebuild, no CHECK constraints (M3 decision 11). The events table keeps its
-- UNIQUE (host_id, ts, path, signature): dropping it would mean rebuilding
-- events, which the alert tables reference with cascades. A second detection
-- that collides on that key is counted in `occurrences`, not dropped.
--
-- Downgrade safety: an M4 binary would not plan summaries, would count nothing
-- in event_receipts and would treat replayed reports as live. checkNotNewer
-- refuses a database whose schema is newer than the binary.

-- +goose Up
CREATE INDEX events_host_id   ON events(host_id, id);
-- Partial: they only ever hold the open (unacknowledged) rows.
CREATE INDEX events_open      ON events(id)      WHERE ack_at IS NULL;
CREATE INDEX events_open_host ON events(host_id) WHERE ack_at IS NULL;
ALTER TABLE events ADD COLUMN occurrences INTEGER NOT NULL DEFAULT 1; -- distinct detections merged on the natural key

CREATE TABLE event_receipts (            -- agent idempotency keys (proto event.id)
  host_id        INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  agent_event_id TEXT    NOT NULL,       -- 32 lowercase hex
  event_id       INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  received_at    INTEGER NOT NULL,
  PRIMARY KEY (host_id, agent_event_id)
);
CREATE INDEX event_receipts_event ON event_receipts(event_id);

ALTER TABLE alert_targets ADD COLUMN detection_burst INTEGER NOT NULL DEFAULT 10; -- 0 = every detection alone

CREATE TABLE alert_detection_windows (
  id           INTEGER PRIMARY KEY AUTOINCREMENT, -- durable identity; never reused
  target_id    INTEGER NOT NULL REFERENCES alert_targets(id) ON DELETE CASCADE,
  host_id      INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  window_start INTEGER NOT NULL,           -- received_at of the opening event (server clock)
  sent         INTEGER NOT NULL DEFAULT 0, -- individual alerts in this window
  closed_at    INTEGER,                    -- set in the same transaction as the summary (or the discard)
  outcome      TEXT                        -- 'summarised' | 'empty' | 'discarded'
);
-- At most one open window per (target, host): the planner relies on it.
CREATE UNIQUE INDEX alert_detection_windows_open   ON alert_detection_windows(target_id, host_id) WHERE closed_at IS NULL;
CREATE INDEX        alert_detection_windows_closed ON alert_detection_windows(closed_at) WHERE closed_at IS NOT NULL;

CREATE TABLE alert_window_events (        -- membership: the held detections of a window
  window_id INTEGER NOT NULL REFERENCES alert_detection_windows(id) ON DELETE CASCADE,
  event_id  INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  PRIMARY KEY (window_id, event_id)
);
CREATE INDEX alert_window_events_event ON alert_window_events(event_id);

-- The summary delivery that consumed a window (NULL for every other delivery).
ALTER TABLE alert_deliveries ADD COLUMN window_id INTEGER REFERENCES alert_detection_windows(id) ON DELETE SET NULL;

-- +goose Down
-- Development only: a production downgrade is refused by the server, not attempted.
ALTER TABLE alert_deliveries DROP COLUMN window_id;
DROP INDEX alert_window_events_event;
DROP TABLE alert_window_events;
DROP INDEX alert_detection_windows_closed;
DROP INDEX alert_detection_windows_open;
DROP TABLE alert_detection_windows;
ALTER TABLE alert_targets DROP COLUMN detection_burst;
DROP INDEX event_receipts_event;
DROP TABLE event_receipts;
ALTER TABLE events DROP COLUMN occurrences;
DROP INDEX events_open_host;
DROP INDEX events_open;
DROP INDEX events_host_id;
