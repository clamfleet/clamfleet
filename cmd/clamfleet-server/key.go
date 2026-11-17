// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// key.go: the "key" admin commands and the start-up check of the secret key
// file.
//
//	key generate [--file PATH] [--add]   create the key file (run as root at install)
//	key reencrypt                        re-seal stored secrets with the active key
//	key check                            open every stored secret; exit 0 only when all use the active key
//
// Output contract: nothing on stdout (a key must never reach a pipe or a log);
// the key id and the next step go to stderr.
//
// Rotation: `key generate --add` puts a new key at the top of the file (the
// first key seals, all open), restart the server, `key reencrypt` (repeat until
// it exits 0), `key check` (must exit 0), delete the old key line, restart. The
// server reads the key file only at start.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/clamfleet/clamfleet/internal/secrets"
	"github.com/clamfleet/clamfleet/internal/server"
	"github.com/clamfleet/clamfleet/internal/store"
)

func (a *app) key(ctx context.Context, args []string) int {
	if len(args) == 0 {
		fmt.Fprint(a.stderr, usage)
		return exitUsage
	}
	sub, rest := args[0], args[1:]
	fs, cfgFlag := newFlags("key "+sub, a.stderr)
	file := fs.String("file", "", "key file to create (generate; default: secret_key_file of the configuration)")
	add := fs.Bool("add", false, "add a new key on top of an existing file (generate)")
	if sub != "generate" && sub != "reencrypt" && sub != "check" {
		fmt.Fprintf(a.stderr, "key: unknown subcommand %q\n\n%s", sub, usage)
		return exitUsage
	}
	if err := fs.Parse(rest); err != nil {
		return exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(a.stderr, "key %s: unexpected argument %q\n", sub, fs.Arg(0))
		return exitUsage
	}
	if sub != "generate" && (*file != "" || *add) {
		fmt.Fprintf(a.stderr, "key %s: --file and --add only apply to generate\n", sub)
		return exitUsage
	}
	log := a.logger(slog.LevelInfo)
	cfg, err := a.loadConfig(log, *cfgFlag)
	if err != nil {
		log.Error("invalid configuration", "error", err.Error())
		return exitError
	}
	if sub == "generate" {
		path := *file
		if path == "" {
			path = cfg.SecretKeyFile
		}
		if !filepath.IsAbs(path) {
			fmt.Fprintf(a.stderr, "key generate: the key file path must be absolute, got %q\n", path)
			return exitUsage
		}
		id, err := generateKeyFile(path, *add, a.now())
		if err != nil {
			log.Error("cannot create the key file", "error", err.Error())
			return exitError
		}
		fmt.Fprintf(a.stderr, "key %s written to %s\nnext: chgrp clamfleet-server %s && chmod 0640 %s   (the server refuses a file others can read)\nback this file up apart from the database backups\n", id, path, path, path)
		return exitOK
	}
	st, err := a.openExisting(ctx, log, cfg)
	if err != nil {
		log.Error("database", "error", err.Error())
		return exitError
	}
	defer st.Close()
	ring, err := secrets.LoadFile(cfg.SecretKeyFile)
	if err != nil {
		log.Error("cannot load the key file", "error", err.Error())
		return exitError
	}
	if sub == "check" {
		return a.keyCheck(ctx, log, st, ring)
	}
	return a.keyReencrypt(ctx, log, st, ring)
}

// keyReencrypt runs reencrypt and maps its outcome to the exit code: 0 only when
// the rotation is complete.
func (a *app) keyReencrypt(ctx context.Context, log *slog.Logger, st resealer, ring *secrets.Keyring) int {
	audit := store.Audit{Kind: store.ActorCLI, Actor: a.actor}
	res, skipped, err := reencrypt(ctx, st, ring, a.now(), audit)
	if err != nil {
		log.Error("re-encryption failed; nothing was changed", "error", err.Error())
		return exitError
	}
	if len(skipped) > 0 {
		log.Warn("webhook targets whose secret cannot be opened were skipped: re-encryption cannot fix them; enter each URL again and rotate its key in the console, or delete the target",
			"targets", strings.Join(skipped, ","))
	}
	conflicts := len(res.TOTPConflicts) + len(res.AlertConflicts)
	if conflicts > 0 {
		// Some rows changed between the read and the write (an admin rotated a
		// webhook key, a user re-enrolled TOTP): they were left alone. The server
		// seals changed rows with its active key, so a re-run normally finds them
		// current. Saying "done" here would let the old key be deleted too early.
		fmt.Fprintf(a.stderr, "incomplete: %d re-sealed, %d changed meanwhile; run key reencrypt again\n", res.TOTP+res.AlertTargets, conflicts)
		return exitError
	}
	log.Info("secrets re-encrypted with the active key", "count", res.TOTP+res.AlertTargets, "totp", res.TOTP,
		"alert_target", res.AlertTargets, "key_id", ring.ActiveID(), "actor", a.actor)
	return exitOK
}

// keyCheck opens every stored secret and reports, per purpose, how many are
// sealed with the active key, with an older key still in the file, or cannot be
// opened at all. Exit 0 only when every secret opens and every one uses the
// active key: only then is it safe to delete the old key line. Read-only.
func (a *app) keyCheck(ctx context.Context, log *slog.Logger, st sealedLister, ring *secrets.Keyring) int {
	type tally struct{ active, older, bad int }
	count := func(blob []byte, purpose string, id uint64, t *tally) {
		switch _, err := ring.Open(purpose, blob, id); {
		case err != nil:
			t.bad++
		case ring.NeedsReseal(blob):
			t.older++
		default:
			t.active++
		}
	}
	var totp, targets tally
	tot, err := st.SealedTOTPSecrets(ctx)
	if err != nil {
		log.Error("read stored secrets", "error", err.Error())
		return exitError
	}
	for _, s := range tot {
		count(s.Sealed, secrets.PurposeTOTP, uint64(s.UserID), &totp)
	}
	tg, err := st.SealedAlertSecrets(ctx)
	if err != nil {
		log.Error("read stored secrets", "error", err.Error())
		return exitError
	}
	for _, s := range tg {
		count(s.Sealed, secrets.PurposeAlertTarget, uint64(s.ID), &targets)
	}
	line := func(name string, n int, t tally) {
		fmt.Fprintf(a.stdout, "%s: %d secret(s): %d sealed with the active key, %d sealed with an older key, %d cannot be opened\n", name, n, t.active, t.older, t.bad)
	}
	line("totp", len(tot), totp)
	line("alert-target", len(tg), targets)
	older, bad := totp.older+targets.older, totp.bad+targets.bad
	if older == 0 && bad == 0 {
		return exitOK
	}
	if older > 0 {
		fmt.Fprintf(a.stderr, "key check failed: %d secret(s) are sealed with an older key: run `key reencrypt` (repeat until it exits 0); do NOT delete the old key line yet\n", older)
	}
	if bad > 0 {
		fmt.Fprintf(a.stderr, "key check failed: %d secret(s) cannot be opened with the keys in the key file: put the key they were sealed with back, or reset them (user reset-totp; for a webhook target enter the URL again in the console, or delete it)\n", bad)
	}
	return exitError
}

// generateKeyFile creates path with one fresh key (mode 0600, never overwriting),
// or with add=true puts a fresh key at the top of the existing file. It returns the key id.
//
// For add, the new content is written to a temp file in the same directory,
// fsynced, given the old file's mode and owner, and renamed over the original,
// so a crash leaves either the old file or the new one, never half of one.
func generateKeyFile(path string, add bool, now time.Time) (string, error) {
	key, err := secrets.GenerateKey()
	if err != nil {
		return "", err
	}
	header := "# ClamFleet server secret key file, created " + now.UTC().Format(time.RFC3339) + "\n" +
		"# The first key seals, every key opens. Do not edit or share. See docs/web.md.\n"
	if !add {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, fs.ErrExist) {
			return "", fmt.Errorf("%s already exists: refusing to overwrite a key (use --add to add a new one on top)", path)
		}
		if err != nil {
			return "", err
		}
		if _, err := io.WriteString(f, header+secrets.EncodeKeyLine(key)); err != nil {
			f.Close()
			os.Remove(path)
			return "", err
		}
		if err := f.Sync(); err != nil {
			f.Close()
			os.Remove(path)
			return "", err
		}
		return secrets.KeyID(key), f.Close()
	}

	// LoadFile validates the old file first (format and permissions): never
	// build on a file the server would refuse.
	if _, err := secrets.LoadFile(path); err != nil {
		return "", err
	}
	old, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	fi, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	tmp, err := os.OpenFile(path+".new", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("%w (a leftover %s.new from an interrupted run? remove it and retry)", err, path)
	}
	cleanup := func() { tmp.Close(); os.Remove(path + ".new") }
	if _, err := io.WriteString(tmp, header+secrets.EncodeKeyLine(key)+"\n"); err != nil {
		cleanup()
		return "", err
	}
	if _, err := tmp.Write(old); err != nil {
		cleanup()
		return "", err
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		if err := tmp.Chown(int(st.Uid), int(st.Gid)); err != nil {
			cleanup()
			return "", fmt.Errorf("cannot keep the owner of %s (run as root or as its owner): %w", path, err)
		}
	}
	if err := tmp.Chmod(fi.Mode().Perm()); err != nil {
		cleanup()
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(path + ".new")
		return "", err
	}
	if err := os.Rename(path+".new", path); err != nil {
		os.Remove(path + ".new")
		return "", err
	}
	if d, err := os.Open(filepath.Dir(path)); err == nil { // make the rename durable
		_ = d.Sync()
		d.Close()
	}
	return secrets.KeyID(key), nil
}

// sealedLister is the part of the store the start-up check, key check and
// reencrypt read.
type sealedLister interface {
	SealedTOTPSecrets(ctx context.Context) ([]store.SealedSecret, error)
	SealedAlertSecrets(ctx context.Context) ([]store.SealedTargetSecret, error)
}

// resealer adds the one write of key rotation: both kinds of secret in one
// transaction (see store.AlertStore.ResealSecrets).
type resealer interface {
	sealedLister
	ResealSecrets(ctx context.Context, totp []store.Reseal, alerts []store.AlertReseal, now time.Time, a store.Audit) (store.ResealResult, error)
}

// reencrypt re-seals every TOTP and alert-target secret that is not sealed with
// the active key, in ONE transaction (each row a compare-and-swap on its old
// blob). All TOTP secrets are opened first: if one cannot be, nothing is changed
// and the error says which user, so a half-rotated state cannot come out of a
// typo. A webhook target whose secret cannot be opened is skipped and returned by
// name: unlike a TOTP secret it cannot lock anyone out, and re-encryption cannot
// fix it (`key check` keeps failing until it is re-entered or deleted).
func reencrypt(ctx context.Context, st resealer, ring *secrets.Keyring, now time.Time, audit store.Audit) (res store.ResealResult, skipped []string, err error) {
	all, err := st.SealedTOTPSecrets(ctx)
	if err != nil {
		return res, nil, err
	}
	var rs []store.Reseal
	for _, s := range all {
		if !ring.NeedsReseal(s.Sealed) {
			continue
		}
		pt, err := ring.Open(secrets.PurposeTOTP, s.Sealed, uint64(s.UserID))
		if err != nil {
			return res, nil, fmt.Errorf("the secret of %s cannot be opened (%v): keep the old key in the key file until it can, or run `user reset-totp` for that user", s.Email, err)
		}
		fresh, err := ring.Seal(secrets.PurposeTOTP, pt, uint64(s.UserID))
		if err != nil {
			return res, nil, err
		}
		rs = append(rs, store.Reseal{UserID: s.UserID, Old: s.Sealed, New: fresh})
	}
	targets, err := st.SealedAlertSecrets(ctx)
	if err != nil {
		return res, nil, err
	}
	var as []store.AlertReseal
	for _, t := range targets {
		pt, err := ring.Open(secrets.PurposeAlertTarget, t.Sealed, uint64(t.ID))
		if err != nil {
			skipped = append(skipped, t.Name)
			continue
		}
		if !ring.NeedsReseal(t.Sealed) {
			continue
		}
		fresh, err := ring.Seal(secrets.PurposeAlertTarget, pt, uint64(t.ID))
		if err != nil {
			return res, nil, err
		}
		as = append(as, store.AlertReseal{TargetID: t.ID, Old: t.Sealed, New: fresh})
	}
	if len(rs) == 0 && len(as) == 0 {
		return res, skipped, nil
	}
	res, err = st.ResealSecrets(ctx, rs, as, now, audit)
	return res, skipped, err
}

// startupKeys loads the key file for serve and decides whether the server may
// start, so a missing or wrong key can never silently turn the second factor off.
//
//   - file absent and nothing needs it: warn, run with TOTP unavailable (nil ring);
//   - file absent and totp_required is on or users have TOTP: refuse;
//   - file present but unreadable, with wrong permissions or unparsable: refuse
//     (a file that exists must be valid, or a permissions slip would hide until
//     users had burned their recovery codes);
//   - file valid: every stored TOTP secret must open, else refuse naming the count.
//
// Alert-target secrets are different (M4 decision 10): the server STARTS even
// when some cannot be opened (no key file, an unknown key, a failed decrypt),
// because email and the other targets must keep working (spec 13). The count and
// the fix are logged at error; those webhook deliveries fail permanently with a
// clear text and the Alerts page shows a banner per target.
func startupKeys(ctx context.Context, log *slog.Logger, cfg server.Config, st sealedLister) (*secrets.Keyring, error) {
	stored, err := st.SealedTOTPSecrets(ctx)
	if err != nil {
		return nil, fmt.Errorf("read stored secrets: %w", err)
	}
	targets, err := st.SealedAlertSecrets(ctx)
	if err != nil {
		return nil, fmt.Errorf("read stored secrets: %w", err)
	}
	ring, err := secrets.LoadFile(cfg.SecretKeyFile)
	if errors.Is(err, fs.ErrNotExist) {
		switch {
		case cfg.Auth.Local.TOTPRequired:
			return nil, fmt.Errorf("auth.local.totp_required is on but the secret key file %s does not exist: create it with `clamfleet-server key generate` (as root), then chgrp clamfleet-server and chmod 0640", cfg.SecretKeyFile)
		case len(stored) > 0:
			return nil, fmt.Errorf("%d user(s) have TOTP enabled but the secret key file %s does not exist: restore it from backup, or run `clamfleet-server user reset-totp EMAIL` for each of them (see `user list`) and create a new key with `key generate`", len(stored), cfg.SecretKeyFile)
		}
		log.Warn("no secret key file: two-factor sign-in (TOTP) is unavailable until one is created with `clamfleet-server key generate`", "secret_key_file", cfg.SecretKeyFile)
		warnUnopenableTargets(log, cfg, len(targets), len(targets))
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	bad := 0
	for _, s := range stored {
		if _, err := ring.Open(secrets.PurposeTOTP, s.Sealed, uint64(s.UserID)); err != nil {
			bad++
		}
	}
	if bad > 0 {
		return nil, fmt.Errorf("%d of %d stored TOTP secrets cannot be opened with the keys in %s (wrong or replaced key file?): restore the key file they were sealed with, or run `clamfleet-server user reset-totp EMAIL` for the affected users (see `user list`)", bad, len(stored), cfg.SecretKeyFile)
	}
	badTargets := 0
	for _, t := range targets {
		if _, err := ring.Open(secrets.PurposeAlertTarget, t.Sealed, uint64(t.ID)); err != nil {
			badTargets++
		}
	}
	warnUnopenableTargets(log, cfg, badTargets, len(targets))
	return ring, nil
}

// warnUnopenableTargets logs the alert-target part of the start-up check.
func warnUnopenableTargets(log *slog.Logger, cfg server.Config, bad, total int) {
	if bad == 0 {
		return
	}
	log.Error("webhook alert targets cannot be opened with the keys in the key file: their alerts fail until fixed; restore the key file they were sealed with, or enter each URL again and rotate its key in the console (email and other targets keep working)",
		"unreadable", bad, "webhook_targets", total, "secret_key_file", cfg.SecretKeyFile)
}
