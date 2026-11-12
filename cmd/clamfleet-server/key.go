// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// key.go: the "key" admin commands and the start-up check of the secret key
// file (docs/plans/milestone-3b.md 4.4).
//
//	key generate [--file PATH] [--add]   create the key file (run as root at install)
//	key reencrypt                        re-seal stored secrets with the active key
//
// Output contract: nothing on stdout (a key must never reach a pipe or a log);
// the key id and the next step go to stderr.
//
// Rotation: `key generate --add` puts a new key at the top of the file (the
// first key seals, all open), restart the server, `key reencrypt`, delete the
// old key line, restart. The server reads the key file only at start.
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
	if sub != "generate" && sub != "reencrypt" {
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
	if sub == "reencrypt" && (*file != "" || *add) {
		fmt.Fprintf(a.stderr, "key reencrypt: --file and --add only apply to generate\n")
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
	n, err := reencrypt(ctx, st, ring, a.now(), store.Audit{Kind: store.ActorCLI, Actor: a.actor})
	if err != nil {
		log.Error("re-encryption failed; nothing was changed", "error", err.Error())
		return exitError
	}
	log.Info("secrets re-encrypted with the active key", "count", n, "key_id", ring.ActiveID(), "actor", a.actor)
	return exitOK
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

// sealedLister is the part of the store the start-up check and reencrypt need.
type sealedLister interface {
	SealedTOTPSecrets(ctx context.Context) ([]store.SealedSecret, error)
}

// reencrypt re-seals every TOTP secret that is not sealed with the active key.
// All of them are opened first: if one cannot be, nothing is changed and the
// error says which user, so a half-rotated state cannot come out of a typo.
func reencrypt(ctx context.Context, st interface {
	sealedLister
	ResealTOTPSecrets(ctx context.Context, rs []store.Reseal, now time.Time, a store.Audit) (int, error)
}, ring *secrets.Keyring, now time.Time, audit store.Audit) (int, error) {
	all, err := st.SealedTOTPSecrets(ctx)
	if err != nil {
		return 0, err
	}
	var rs []store.Reseal
	for _, s := range all {
		if !ring.NeedsReseal(s.Sealed) {
			continue
		}
		pt, err := ring.Open(secrets.PurposeTOTP, s.Sealed, uint64(s.UserID))
		if err != nil {
			return 0, fmt.Errorf("the secret of %s cannot be opened (%v): keep the old key in the key file until it can, or run `user reset-totp` for that user", s.Email, err)
		}
		fresh, err := ring.Seal(secrets.PurposeTOTP, pt, uint64(s.UserID))
		if err != nil {
			return 0, err
		}
		rs = append(rs, store.Reseal{UserID: s.UserID, Old: s.Sealed, New: fresh})
	}
	if len(rs) == 0 {
		return 0, nil
	}
	return st.ResealTOTPSecrets(ctx, rs, now, audit)
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
func startupKeys(ctx context.Context, log *slog.Logger, cfg server.Config, st sealedLister) (*secrets.Keyring, error) {
	stored, err := st.SealedTOTPSecrets(ctx)
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
	return ring, nil
}
