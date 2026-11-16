// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// user.go: the "user" admin commands. Console accounts are managed here and
// nowhere else in Milestone 3: shell access to the server is the root of
// trust, which also makes `user reset-password` the recovery path for a
// locked-out admin.
//
// Output contract (as for host add): a generated password goes to stdout once
// and nothing else does, so PW=$(clamfleet-server user add ...) works and the
// password never reaches a log. A password is never accepted as a command-line
// argument (it would show in `ps` and shell history): --password-stdin reads
// one line instead. A password set this way is also a one-time password: the
// user must change it at first login, because whoever typed or piped it knows it.
//
// `user reset-totp` is the admin reset of the second factor (there is no console
// UI for resetting another user). Like reset-password it prints nothing on stdout.
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/clamfleet/clamfleet/internal/store"
	"github.com/clamfleet/clamfleet/internal/webauth"
)

// maxStdinPassword bounds what --password-stdin reads, so a wrong pipe cannot
// buffer an unbounded stream. Longer than the policy maximum on purpose, so
// the policy message (not a truncation) is what the operator sees.
const maxStdinPassword = 1024

func (a *app) user(ctx context.Context, args []string) int {
	if len(args) == 0 {
		fmt.Fprint(a.stderr, usage)
		return exitUsage
	}
	sub, rest := args[0], args[1:]
	fs, cfgFlag := newFlags("user "+sub, a.stderr)
	asJSON := fs.Bool("json", false, "machine-readable output (list)")
	role := fs.String("role", "", "viewer or admin (add)")
	name := fs.String("name", "", "display name (add)")
	pwStdin := fs.Bool("password-stdin", false, "read the password from one line of stdin instead of generating one (add, reset-password)")
	var pos []string
	for {
		if err := fs.Parse(rest); err != nil {
			return exitUsage
		}
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		rest = fs.Args()[1:]
	}
	want := map[string]int{"add": 1, "list": 0, "set-role": 2, "disable": 1, "enable": 1, "reset-password": 1, "reset-totp": 1}
	n, known := want[sub]
	switch {
	case !known:
		fmt.Fprintf(a.stderr, "user: unknown subcommand %q\n\n%s", sub, usage)
		return exitUsage
	case len(pos) != n:
		fmt.Fprintf(a.stderr, "user %s: wrong number of arguments\n\n%s", sub, usage)
		return exitUsage
	case sub == "add" && !store.ValidRole(*role):
		fmt.Fprintf(a.stderr, "user add: --role viewer or --role admin is required\n")
		return exitUsage
	case sub == "set-role" && !store.ValidRole(pos[1]):
		fmt.Fprintf(a.stderr, "user set-role: role must be viewer or admin, got %q\n", pos[1])
		return exitUsage
	case *pwStdin && sub != "add" && sub != "reset-password":
		fmt.Fprintf(a.stderr, "user %s: --password-stdin only applies to add and reset-password\n", sub)
		return exitUsage
	}
	if sub == "add" {
		if _, err := store.NormalizeEmail(pos[0]); err != nil {
			fmt.Fprintf(a.stderr, "user %s: %v\n", sub, err)
			return exitUsage
		}
	} else if sub != "list" {
		if _, _, ext := externalRef(pos[0]); !ext {
			if _, err := store.NormalizeEmail(pos[0]); err != nil {
				fmt.Fprintf(a.stderr, "user %s: %v (an external user is named ldap:NAME or oidc:NAME)\n", sub, err)
				return exitUsage
			}
		}
	}

	// The password is read before the database is opened: a bad pipe or a policy
	// violation fails fast and leaves nothing half done.
	var password string
	if sub == "add" || sub == "reset-password" {
		var err error
		if password, err = a.passwordFor(*pwStdin); err != nil {
			fmt.Fprintf(a.stderr, "user %s: %v\n", sub, err)
			return exitError
		}
	}

	log := a.logger(slog.LevelInfo)
	cfg, err := a.loadConfig(log, *cfgFlag)
	if err != nil {
		log.Error("invalid configuration", "error", err.Error())
		return exitError
	}
	st, err := a.openExisting(ctx, log, cfg)
	if err != nil {
		log.Error("database", "error", err.Error())
		return exitError
	}
	defer st.Close()
	audit := store.Audit{Kind: store.ActorCLI, Actor: a.actor}

	switch sub {
	case "list":
		return a.userList(ctx, log, st, *asJSON)
	case "add":
		return a.userAdd(ctx, log, st, pos[0], *role, *name, password, *pwStdin, audit)
	case "reset-password":
		return a.userResetPassword(ctx, log, st, pos[0], password, *pwStdin, audit)
	}
	u, ok := a.findUser(ctx, log, st, pos[0])
	if !ok {
		return exitError
	}
	if sub == "set-role" || sub == "reset-totp" {
		if reason := externalRefusal(sub, u); reason != "" {
			log.Error(reason, "user", userLabel(u))
			return exitError
		}
	}
	switch sub {
	case "set-role":
		err = st.SetRole(ctx, u.ID, pos[1], a.now(), audit)
	case "disable":
		err = st.SetDisabled(ctx, u.ID, true, a.now(), audit)
	case "enable":
		err = st.SetDisabled(ctx, u.ID, false, a.now(), audit)
	case "reset-totp":
		// Removes the authenticator and the recovery codes, lifts the second-factor
		// lock and ends every session and pending login of the user. It needs no key
		// file, which is the way out of a lost key. With totp_required the user
		// enrols again at their next sign-in.
		err = st.DisableTOTP(ctx, u.ID, nil, store.ActionTOTPReset, a.now(), audit)
	}
	if err != nil {
		log.Error("cannot change user", "user", userLabel(u), "error", err.Error())
		return exitError
	}
	log.Info("user changed", "user", userLabel(u), "command", sub, "actor", audit.Actor)
	return exitOK
}

// passwordFor returns the password to set: one line of stdin, or a generated
// one-time password. A stdin password must satisfy the policy.
func (a *app) passwordFor(fromStdin bool) (string, error) {
	if !fromStdin {
		return webauth.GeneratePassword()
	}
	line, err := bufio.NewReader(io.LimitReader(a.stdin, maxStdinPassword)).ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && line != "") {
		return "", errors.New("--password-stdin: expected one line with the password on stdin")
	}
	pw := strings.TrimRight(line, "\r\n")
	if err := webauth.CheckPolicy(pw); err != nil {
		return "", err
	}
	return pw, nil
}

func (a *app) userAdd(ctx context.Context, log *slog.Logger, st store.Store, email, role, name, password string, fromStdin bool, audit store.Audit) int {
	hash, err := webauth.NewHasher().Hash(ctx, password)
	if err != nil {
		log.Error("hash password", "error", err.Error())
		return exitError
	}
	u, err := st.CreateUser(ctx, store.NewUser{Email: email, DisplayName: name, Role: role, PasswordHash: hash, MustChange: true}, a.now(), audit)
	if err != nil {
		// A duplicate or an invalid address: the message names the user, never the password.
		log.Error("cannot add user", "user", store.TruncateForAudit(strings.ToLower(email)), "error", err.Error())
		return exitError
	}
	log.Info("user added; the password must be changed at first login", "user", u.Email, "role", u.Role, "actor", audit.Actor)
	if !fromStdin {
		fmt.Fprintln(a.stdout, password) // shown once; it exists nowhere else in clear
	}
	return exitOK
}

func (a *app) userResetPassword(ctx context.Context, log *slog.Logger, st store.Store, email, password string, fromStdin bool, audit store.Audit) int {
	u, ok := a.findUser(ctx, log, st, email)
	if !ok {
		return exitError
	}
	if reason := externalRefusal("reset-password", u); reason != "" {
		log.Error(reason, "user", userLabel(u))
		return exitError
	}
	hash, err := webauth.NewHasher().Hash(ctx, password)
	if err != nil {
		log.Error("hash password", "error", err.Error())
		return exitError
	}
	if err := st.SetPassword(ctx, u.ID, store.PasswordChange{Hash: hash, MustChange: true}, a.now(), audit); err != nil {
		log.Error("cannot reset password", "user", u.Email, "error", err.Error())
		return exitError
	}
	log.Info("password reset; all sessions of the user ended; the password must be changed at next login", "user", u.Email, "actor", audit.Actor)
	if !fromStdin {
		fmt.Fprintln(a.stdout, password)
	}
	return exitOK
}

func (a *app) userList(ctx context.Context, log *slog.Logger, st store.Store, asJSON bool) int {
	users, err := st.ListUsers(ctx)
	if err != nil {
		log.Error("cannot list users", "error", err.Error())
		return exitError
	}
	if asJSON {
		if users == nil {
			users = []store.User{}
		}
		return a.printJSON(log, users)
	}
	tw := newTab(a.stdout)
	fmt.Fprintln(tw, "USER\tSOURCE\tROLE\tSTATUS\tLAST LOGIN\tMUST CHANGE PASSWORD\tTOTP")
	for _, u := range users {
		status := "active"
		if u.Disabled {
			status = "disabled"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%v\t%s\n", userLabel(u), u.AuthSource, u.Role, status, fmtTime(u.LastLoginAt), u.MustChange, totpText(u))
	}
	tw.Flush()
	return exitOK
}

// externalRef parses "ldap:NAME" or "oidc:NAME", the way the operator names an external user
// (it may have no email at all).
func externalRef(ident string) (source, name string, ok bool) {
	for _, src := range []string{store.AuthLDAP, store.AuthOIDC} {
		if n, found := strings.CutPrefix(ident, src+":"); found && n != "" {
			return src, n, true
		}
	}
	return "", "", false
}

// userLabel is how a user is named in output and logs: the email, or source:name.
func userLabel(u store.User) string {
	if u.Email != "" {
		return u.Email
	}
	return u.AuthSource + ":" + u.ExternalName
}

// findUser resolves what the operator typed (an email, or ldap:NAME / oidc:NAME) to one user. It
// logs why and returns false when there is none, or when a source:name is ambiguous.
func (a *app) findUser(ctx context.Context, log *slog.Logger, st store.Store, ident string) (store.User, bool) {
	if src, name, ext := externalRef(ident); ext {
		us, err := st.UsersByExternalName(ctx, src, name)
		switch {
		case err != nil:
			log.Error("cannot read user", "error", err.Error())
		case len(us) == 0:
			log.Error("no such user", "user", store.TruncateForAudit(ident))
		case len(us) > 1:
			// Two people can share a preferred_username at a provider. Never guess which is meant.
			log.Error("more than one user has that name; use the email of the one you mean", "user", store.TruncateForAudit(ident), "matches", len(us))
		default:
			return us[0], true
		}
		return store.User{}, false
	}
	u, err := st.UserByEmail(ctx, ident)
	switch {
	case errors.Is(err, store.ErrNotFound):
		log.Error("no such user", "user", strings.ToLower(store.TruncateForAudit(ident)))
	case err != nil:
		log.Error("cannot read user", "error", err.Error())
	default:
		return u, true
	}
	return store.User{}, false
}

// externalRefusal is the reason a command does not apply to an external user, or "" when it does:
// their role, password and second factor belong to the provider and are overwritten or ignored there
// (decision 20). disable and enable apply to everyone and take effect at once.
func externalRefusal(cmd string, u store.User) string {
	var what string
	switch u.AuthSource {
	case store.AuthLocal:
		return ""
	case store.AuthLDAP:
		what = "LDAP"
	case store.AuthOIDC:
		what = "the OIDC provider"
	default:
		what = "its identity provider"
	}
	switch cmd {
	case "set-role":
		if u.AuthSource == store.AuthLDAP {
			return "the role of this user comes from LDAP groups at every sign-in; change it there (an edit here would be overwritten at the next sign-in)"
		}
		return "the role of this user comes from the OIDC claim at every sign-in; change it at " + what + " (an edit here would be overwritten at the next sign-in)"
	case "reset-password":
		return "this user has no ClamFleet password: it is managed by " + what
	case "reset-totp":
		return "this user has no ClamFleet second factor: it belongs to " + what
	}
	return ""
}

// totpText is the TOTP column of `user list`: off, on, or locked after too many
// wrong second-factor attempts (reset-password or reset-totp lifts it).
func totpText(u store.User) string {
	switch {
	case !u.TOTPEnabled:
		return "off"
	case u.TOTPFailures >= store.SecondFactorLockLimit:
		return "locked"
	}
	return "on"
}
