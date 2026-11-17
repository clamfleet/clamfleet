-- SPDX-License-Identifier: AGPL-3.0-only
-- SPDX-FileCopyrightText: The ClamFleet Authors

-- Milestone 6a schema: the child-side indexes behind cascaded prunes.
--
-- SQLite looks up child rows on every cascaded delete. Without these indexes
-- each pruned event or state change scans alert_deliveries and alert_log in
-- full, once per deleted parent row: a prune of 100,000 events would walk the
-- 90-day alert history 100,000 times.
--
-- Additive only (indexes). Building them holds the write lock for a moment;
-- alert_log holds 90 days at most. checkNotNewer refuses an M5 binary on a
-- 00006 database like every earlier migration.

-- +goose Up
CREATE INDEX alert_deliveries_state_change ON alert_deliveries(state_change_id);
CREATE INDEX alert_log_state_change        ON alert_log(state_change_id);
CREATE INDEX alert_log_event               ON alert_log(event_id);

-- +goose Down
-- Development only: a production downgrade is refused by the server, not attempted.
DROP INDEX alert_log_event;
DROP INDEX alert_log_state_change;
DROP INDEX alert_deliveries_state_change;
