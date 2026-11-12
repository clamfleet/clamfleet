-- SPDX-License-Identifier: AGPL-3.0-only
-- SPDX-FileCopyrightText: The ClamFleet Authors

-- TOTP second factor (Milestone 3b): per-user state, recovery codes, login
-- challenges and the pending enrolment of a session. Portable SQL only.
-- Every state change that is a decision (replay, one-time recovery code,
-- version, expiry) is a conditional UPDATE or DELETE whose row count the Go
-- code reads: never a read followed by a write.

-- name: UserTOTP :one
SELECT id, email, totp_secret, totp_enabled_at, totp_last_step, totp_failures, auth_version, disabled_at
FROM users WHERE id = sqlc.arg(id);

-- name: CreateLoginChallenge :execrows
-- Conditional on exactly what the password step saw (hash, version) and on the
-- user being active; 0 rows is ErrCredentialChanged.
INSERT INTO user_login_challenges (token_hash, user_id, auth_version, next, created_at, expires_at)
SELECT sqlc.arg(token_hash), u.id, u.auth_version, sqlc.arg(next), sqlc.arg(now), sqlc.arg(expires_at)
FROM users u
WHERE u.id = sqlc.arg(user_id) AND u.password_hash = sqlc.arg(expected_hash) AND u.disabled_at IS NULL
  AND u.auth_version = sqlc.arg(expected_version);

-- name: PruneLoginChallenges :exec
-- Keeps at most 5 open challenges per user (the oldest go) and drops the user's expired ones.
DELETE FROM user_login_challenges
WHERE user_login_challenges.user_id = sqlc.arg(user_id)
  AND (user_login_challenges.expires_at <= sqlc.arg(now)
       OR user_login_challenges.id NOT IN (SELECT c.id FROM user_login_challenges c WHERE c.user_id = sqlc.arg(user_id) ORDER BY c.id DESC LIMIT 5));

-- name: LoginChallengeByHash :one
SELECT id, user_id, auth_version, next, created_at, expires_at
FROM user_login_challenges
WHERE token_hash = sqlc.arg(token_hash) AND expires_at > sqlc.arg(now);

-- name: ConsumeLoginChallenge :one
-- The challenge is single use: the one transaction that deletes it is the one
-- that may complete the login. No row means it was used by a parallel request,
-- expired, or was killed by a reset.
DELETE FROM user_login_challenges
WHERE token_hash = sqlc.arg(token_hash) AND expires_at > sqlc.arg(now)
RETURNING user_id, auth_version, next;

-- name: DeleteUserChallenges :exec
DELETE FROM user_login_challenges WHERE user_id = sqlc.arg(user_id);

-- name: DeleteExpiredChallenges :execrows
DELETE FROM user_login_challenges WHERE expires_at <= sqlc.arg(now);

-- name: ConsumeTOTPStep :execrows
-- The replay guard: a step is accepted only if it is above the last accepted one.
UPDATE users SET totp_last_step = sqlc.arg(step)
WHERE id = sqlc.arg(id) AND (totp_last_step IS NULL OR totp_last_step < sqlc.arg(step));

-- name: ConsumeRecoveryCode :execrows
-- One time: only a code that is still unused can be marked used.
UPDATE user_recovery_codes SET used_at = sqlc.arg(now)
WHERE user_id = sqlc.arg(user_id) AND code_hash = sqlc.arg(code_hash) AND used_at IS NULL;

-- name: CompleteLoginUser :exec
UPDATE users SET totp_failures = 0, last_login_at = sqlc.arg(now) WHERE id = sqlc.arg(id);

-- name: InsertSession :exec
-- Plain insert: CompleteLogin has already checked the user inside its transaction.
INSERT INTO user_sessions (token_hash, user_id, csrf_token, created_at, last_seen_at, expires_at)
VALUES (sqlc.arg(token_hash), sqlc.arg(user_id), sqlc.arg(csrf_token), sqlc.arg(now), sqlc.arg(now), sqlc.arg(expires_at));

-- name: AddTOTPFailure :one
-- Counted in SQL, never read-modify-write in Go.
UPDATE users SET totp_failures = totp_failures + 1 WHERE id = sqlc.arg(id) RETURNING totp_failures;

-- name: SetPendingTOTP :execrows
UPDATE user_sessions SET totp_pending = sqlc.arg(sealed), totp_pending_at = sqlc.arg(now) WHERE id = sqlc.arg(id);

-- name: PendingTOTP :one
SELECT totp_pending, totp_pending_at FROM user_sessions WHERE id = sqlc.arg(id);

-- name: ClearPendingTOTP :exec
UPDATE user_sessions SET totp_pending = NULL, totp_pending_at = NULL WHERE id = sqlc.arg(id);

-- name: ClearUserPendingTOTP :exec
UPDATE user_sessions SET totp_pending = NULL, totp_pending_at = NULL WHERE user_id = sqlc.arg(user_id);

-- name: EnableUserTOTP :execrows
-- Compare-and-swap on auth_version, and bumps it: every other login in flight
-- for this user dies with this change.
UPDATE users SET totp_secret = sqlc.arg(secret), totp_enabled_at = sqlc.arg(now), totp_last_step = sqlc.arg(step),
       totp_failures = 0, auth_version = auth_version + 1, updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND auth_version = sqlc.arg(expected_version) AND disabled_at IS NULL;

-- name: DisableUserTOTP :execrows
UPDATE users SET totp_secret = NULL, totp_enabled_at = NULL, totp_last_step = NULL,
       totp_failures = 0, auth_version = auth_version + 1, updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id);

-- name: DeleteRecoveryCodes :exec
DELETE FROM user_recovery_codes WHERE user_id = sqlc.arg(user_id);

-- name: InsertRecoveryCode :exec
INSERT INTO user_recovery_codes (user_id, code_hash, created_at) VALUES (sqlc.arg(user_id), sqlc.arg(code_hash), sqlc.arg(now));

-- name: CountRecoveryCodesLeft :one
SELECT count(*) FROM user_recovery_codes WHERE user_id = sqlc.arg(user_id) AND used_at IS NULL;

-- name: SealedTOTPSecrets :many
SELECT id, email, totp_secret FROM users WHERE totp_secret IS NOT NULL ORDER BY id;

-- name: ResealTOTPSecret :execrows
-- Compare-and-swap on the old blob: a secret that changed meanwhile (replaced or
-- reset) is left alone.
UPDATE users SET totp_secret = sqlc.arg(new_secret) WHERE id = sqlc.arg(id) AND totp_secret = sqlc.arg(old_secret);
