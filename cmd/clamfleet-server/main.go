// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Command clamfleet-server is the ClamFleet server: the ingest API, its SQLite
// database and the admin commands that manage hosts and their agent tokens.
//
// Output contract: data goes to stdout (a new token, a list, JSON) and nothing
// else does, so TOKEN=$(clamfleet-server host add web01) works and a token can
// never end up in a log. Logs go to stderr as slog JSON lines and never
// contain a token. Exit codes: 0 ok, 1 runtime or configuration error, 2 usage.
//
// Concurrency: the admin commands run as separate processes next to a running
// "serve" on the same SQLite file; WAL mode and busy_timeout serialise them.
// Only "serve" and "migrate" change the schema; every other command refuses to
// run against an out-of-date database instead of migrating it, so two processes
// never migrate at once.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/clamfleet/clamfleet/internal/agentauth"
	"github.com/clamfleet/clamfleet/internal/config"
	"github.com/clamfleet/clamfleet/internal/health"
	"github.com/clamfleet/clamfleet/internal/server"
	"github.com/clamfleet/clamfleet/internal/store"
	"github.com/clamfleet/clamfleet/internal/store/sqlite"
	"github.com/clamfleet/clamfleet/internal/version"
	"github.com/clamfleet/clamfleet/internal/webauth"
)

const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

const usage = `usage: clamfleet-server <command>

commands:
  serve [--config FILE] [--log-level LEVEL]   run the server (migrates the database first)
  migrate [--config FILE]                     create or upgrade the database schema
  host add NAME                               register a host; prints its token once
  host list [--json]                          list hosts with their state
  host show NAME [--json]                     show one host: state, reasons, history, newest report
  host rotate-token NAME                      issue a new token; the old one stops working at once
  host revoke-token NAME                      disable the host's token (history is kept)
  host delete NAME --yes                      delete the host and ALL its reports, events and history
  user add EMAIL --role viewer|admin [--name TEXT] [--password-stdin]
                                              create a console user; prints a one-time password once
                                              (or reads one line from stdin); it must be changed at first login
  user list [--json]                          list console users
  user set-role EMAIL viewer|admin            change a role (ends the user's sessions)
  user disable EMAIL | enable EMAIL           disable (ends sessions) or re-enable a login
  user reset-password EMAIL [--password-stdin]
                                              issue a new one-time password and end the user's sessions
  user reset-totp EMAIL                       remove the user's authenticator and recovery codes, lift a second-factor
                                              lock and end their sessions (needs no key file)
  key generate [--file PATH] [--add]          create the secret key file (as root; default: secret_key_file);
                                              --add puts a new key on top of an existing file (rotation)
  key reencrypt                               re-seal stored secrets (TOTP and webhook targets) with the active key
                                              (after key generate --add); exit 1 when incomplete: run it again
  key check                                   open every stored secret; exit 0 only when all open with the ACTIVE key
                                              (run it before deleting an old key line)
  version                                     print the version

Host and user commands and migrate take --config FILE too (default: $CLAMFLEET_SERVER_CONFIG or ` + server.DefaultConfigPath + `).
`

// run is main without os.Exit, so it can be tested.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	a := &app{stdout: stdout, stderr: stderr, stdin: os.Stdin, actor: osActor(), now: time.Now}
	switch args[0] {
	case "version":
		fmt.Fprintf(stdout, "clamfleet-server %s\n", version.Version)
		return exitOK
	case "serve":
		return a.serve(ctx, args[1:])
	case "migrate":
		return a.migrate(ctx, args[1:])
	case "host":
		return a.host(ctx, args[1:])
	case "user":
		return a.user(ctx, args[1:])
	case "key":
		return a.key(ctx, args[1:])
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usage)
		return exitOK
	default:
		fmt.Fprintf(stderr, "clamfleet-server: unknown command %q\n\n%s", args[0], usage)
		return exitUsage
	}
}

type app struct {
	stdout, stderr io.Writer
	stdin          io.Reader // only --password-stdin reads it
	actor          string
	now            func() time.Time // the clock for timestamps written by admin commands
}

// osActor names who runs an admin command, for the audit log. SUDO_USER wins:
// under sudo the accountable person is the one who typed it, not root.
func osActor() string {
	if u := os.Getenv("SUDO_USER"); u != "" {
		return u
	}
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return "unknown"
}

func (a *app) logger(level slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(a.stderr, &slog.HandlerOptions{Level: level}))
}

// loadConfig resolves and validates the configuration; it logs warnings.
func (a *app) loadConfig(log *slog.Logger, flagValue string) (server.Config, error) {
	path, explicit := config.ResolvePath(server.EnvPrefix, flagValue, server.DefaultConfigPath, nil)
	cfg, warnings, err := server.LoadConfig(path, explicit, config.Options{})
	for _, w := range warnings {
		log.Warn(w)
	}
	if err == nil {
		err = cfg.Validate()
	}
	return cfg, err
}

func newFlags(name string, stderr io.Writer) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfg := fs.String("config", "", "config file (default: $CLAMFLEET_SERVER_CONFIG or "+server.DefaultConfigPath+")")
	return fs, cfg
}

func (a *app) serve(ctx context.Context, args []string) int {
	fs, cfgFlag := newFlags("serve", a.stderr)
	lvl := fs.String("log-level", "info", "debug, info, warn or error (info logs every request; debug adds health checks)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(a.stderr, "serve: unexpected argument %q\n", fs.Arg(0))
		return exitUsage
	}
	var level slog.Level
	if err := level.UnmarshalText([]byte(*lvl)); err != nil {
		fmt.Fprintf(a.stderr, "serve: invalid --log-level %q\n", *lvl)
		return exitUsage
	}
	log := a.logger(level)
	cfg, err := a.loadConfig(log, *cfgFlag)
	if err != nil {
		log.Error("invalid configuration", "error", err.Error())
		return exitError
	}
	err = checkCanCreate(cfg.DBPath, os.Geteuid())
	var st *sqlite.Store
	if err == nil {
		st, err = sqlite.Open(ctx, cfg.DBPath)
	}
	if err == nil {
		defer st.Close()
		err = st.Migrate(ctx)
	}
	if err != nil {
		log.Error("database", "error", err.Error())
		return exitError
	}
	// The key file is checked after the database is open (the check needs the
	// stored secrets) and before anything is served: a missing or wrong key must
	// stop the server, never turn the second factor off.
	keys, err := startupKeys(ctx, log, cfg, st)
	if err != nil {
		log.Error("secret key", "error", err.Error())
		return exitError
	}
	if keys != nil {
		log.Info("secret key file loaded", "key_id", keys.ActiveID(), "keys", keys.Len())
	}
	// The evaluator is built before the handler so both share it: ingest calls
	// Host after each report, the loop below notices hosts that went silent.
	// Its start time is the restart-grace reference (see health.Evaluate).
	ev := health.New(st, a.now, cfg.Health.Thresholds(), log)
	// Alerting: files named in the configuration (smtp.password_file, CA bundles)
	// are read here, so a bad one refuses the start with its reason.
	alerts, err := server.BuildAlerts(cfg, st, keys, a.now, log)
	if err != nil {
		log.Error("invalid alert configuration", "error", err.Error())
		return exitError
	}
	if err := alerts.Dispatcher.Start(ctx); err != nil {
		log.Error("alerting", "error", err.Error())
		return exitError
	}
	h, err := server.NewHandlerFromConfig(cfg, server.Deps{Store: st, Now: a.now, Log: log, AfterReport: ev.Host, Keys: keys})
	if err != nil {
		log.Error("invalid configuration", "error", err.Error())
		return exitError
	}
	if !cfg.Auth.CookieSecure {
		log.Warn("auth.cookie_secure is false: the session cookie is sent without the Secure flag and the __Host- prefix; use this only for plain-HTTP development")
	}
	loopCtx, stopLoop := context.WithCancel(ctx)
	tick := time.NewTicker(cfg.Health.EvalInterval)
	cleanTick := time.NewTicker(time.Hour)
	alertTick := time.NewTicker(alertInterval)
	loopDone := make(chan struct{}, 3)
	go func() {
		defer func() { loopDone <- struct{}{} }()
		ev.Run(loopCtx, tick.C)
	}()
	go func() {
		defer func() { loopDone <- struct{}{} }()
		webauth.RunCleanup(loopCtx, st, a.now, cfg.Auth.SessionIdle, log, cleanTick.C)
	}()
	go func() {
		defer func() { loopDone <- struct{}{} }()
		alerts.Dispatcher.Run(loopCtx, alertTick.C)
	}()
	err = server.Serve(ctx, cfg, h, log)
	// Wait for the loops before the deferred st.Close(): an evaluation cut off by
	// a closing database would log a spurious error at every shutdown.
	stopLoop()
	tick.Stop()
	cleanTick.Stop()
	alertTick.Stop()
	<-loopDone
	<-loopDone
	<-loopDone
	if err != nil {
		log.Error("server stopped", "error", err.Error())
		return exitError
	}
	return exitOK
}

// alertInterval is how often the dispatcher looks for work besides being woken
// by a finished send: it is what notices a due retry or a hold whose window ended.
const alertInterval = 5 * time.Second

func (a *app) migrate(ctx context.Context, args []string) int {
	fs, cfgFlag := newFlags("migrate", a.stderr)
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	log := a.logger(slog.LevelInfo)
	cfg, err := a.loadConfig(log, *cfgFlag)
	if err != nil {
		log.Error("invalid configuration", "error", err.Error())
		return exitError
	}
	err = checkCanCreate(cfg.DBPath, os.Geteuid())
	var st *sqlite.Store
	if err == nil {
		st, err = sqlite.Open(ctx, cfg.DBPath)
	}
	if err == nil {
		defer st.Close()
		err = st.Migrate(ctx)
	}
	if err != nil {
		log.Error("migrate", "error", err.Error())
		return exitError
	}
	v, _ := st.SchemaVersion(ctx)
	log.Info("database is up to date", "db", cfg.DBPath, "schema_version", v)
	return exitOK
}

// openExisting opens the database for an admin command. It refuses to create
// one (a typo in db_path must not leave a stray empty database behind) and to
// work on an out-of-date schema (only serve and migrate migrate).
func (a *app) openExisting(ctx context.Context, log *slog.Logger, cfg server.Config) (*sqlite.Store, error) {
	fi, err := os.Stat(cfg.DBPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("database %s does not exist: run `clamfleet-server migrate` (or start the server) first", cfg.DBPath)
		}
		return nil, err
	}
	if owner, bad := ownerMismatch(fi, os.Geteuid()); bad {
		// Not a file-ownership hazard for an existing database: SQLite's unix VFS
		// chowns -wal/-shm to the database owner when running as root. The reasons
		// to run as the server user are audit attribution (SUDO_USER) and least
		// privilege. The real ownership hazard is creating the database as the
		// wrong user (see checkCanCreate). Warn; do not refuse.
		log.Warn("database is owned by another user: run admin commands as the server user (sudo -u clamfleet-server clamfleet-server ...) for correct audit attribution and least privilege",
			"owner_uid", owner, "running_as_uid", os.Geteuid())
	}
	st, err := sqlite.Open(ctx, cfg.DBPath)
	if err != nil {
		return nil, err
	}
	if err := st.CheckMigrated(ctx); err != nil {
		st.Close()
		return nil, err
	}
	return st, nil
}

// checkCanCreate refuses to create a missing database file when the effective
// user does not own the parent directory. The state directory belongs to the
// server user; `sudo clamfleet-server migrate` (or serve) as root on a fresh
// install would create clamfleet.db as root:root and the server user could
// never open it. An existing database is left alone.
func checkCanCreate(path string, euid int) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	fi, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return nil // Open reports the missing directory with its own message
	}
	if owner, bad := ownerMismatch(fi, euid); bad {
		return fmt.Errorf("refusing to create the database %s as uid %d: its directory is owned by uid %d, and a file created by another user cannot be opened by the server user; run this as the directory owner (sudo -u clamfleet-server clamfleet-server ...)", path, euid, owner)
	}
	return nil
}

// ownerMismatch reports whether the file's owner differs from euid, and the owner.
func ownerMismatch(fi os.FileInfo, euid int) (owner uint32, mismatch bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, int(st.Uid) != euid
}

func (a *app) host(ctx context.Context, args []string) int {
	if len(args) == 0 {
		fmt.Fprint(a.stderr, usage)
		return exitUsage
	}
	sub, rest := args[0], args[1:]
	fs, cfgFlag := newFlags("host "+sub, a.stderr)
	asJSON := fs.Bool("json", false, "machine-readable output (list, show)")
	yes := fs.Bool("yes", false, "confirm a deletion (delete)")
	// Go's flag package stops at the first non-flag: accept flags after NAME
	// too ("host show web01 --json"), which is how people type it.
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
	log := a.logger(slog.LevelInfo)

	needName := sub != "list"
	switch {
	case sub != "add" && sub != "list" && sub != "show" && sub != "rotate-token" && sub != "revoke-token" && sub != "delete":
		fmt.Fprintf(a.stderr, "host: unknown subcommand %q\n\n%s", sub, usage)
		return exitUsage
	case needName && len(pos) != 1, !needName && len(pos) != 0:
		fmt.Fprintf(a.stderr, "host %s: wrong number of arguments\n\n%s", sub, usage)
		return exitUsage
	case sub == "delete" && !*yes:
		// Irreversible and cascading (reports, events, state history): never on a
		// slip of the keyboard, and checked before the database is even opened.
		fmt.Fprintf(a.stderr, "host delete: this removes %q and all of its reports, events and history for good; repeat with --yes to confirm\n", pos[0])
		return exitUsage
	}

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
	case "add":
		return a.addHost(ctx, log, st, pos[0], audit)
	case "rotate-token":
		return a.setToken(ctx, log, st, pos[0], true, audit)
	case "revoke-token":
		return a.setToken(ctx, log, st, pos[0], false, audit)
	case "delete":
		return a.deleteHost(ctx, log, st, pos[0], audit)
	case "list":
		return a.list(ctx, log, st, *asJSON)
	default:
		return a.show(ctx, log, st, pos[0], *asJSON)
	}
}

func (a *app) addHost(ctx context.Context, log *slog.Logger, st store.Store, name string, audit store.Audit) int {
	token, hash, err := agentauth.Generate()
	if err != nil {
		log.Error("generate token", "error", err.Error())
		return exitError
	}
	h, err := st.CreateHost(ctx, name, hash, a.now(), audit)
	if err != nil {
		log.Error("cannot add host", "host", name, "error", err.Error())
		return exitError
	}
	log.Info("host added", "host", h.Name, "actor", audit.Actor)
	// The token is shown once, here, and exists nowhere else in clear.
	fmt.Fprintln(a.stdout, token)
	return exitOK
}

func (a *app) setToken(ctx context.Context, log *slog.Logger, st store.Store, name string, rotate bool, audit store.Audit) int {
	var token string
	var hash []byte // nil revokes
	if rotate {
		var err error
		if token, hash, err = agentauth.Generate(); err != nil {
			log.Error("generate token", "error", err.Error())
			return exitError
		}
	}
	if err := st.SetToken(ctx, name, hash, a.now(), audit); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			log.Error("no such host", "host", name)
		} else {
			log.Error("cannot change token", "host", name, "error", err.Error())
		}
		return exitError
	}
	if rotate {
		log.Info("token rotated; the old token no longer works", "host", strings.ToLower(name), "actor", audit.Actor)
		fmt.Fprintln(a.stdout, token)
	} else {
		log.Info("token revoked", "host", strings.ToLower(name), "actor", audit.Actor)
	}
	return exitOK
}

func (a *app) deleteHost(ctx context.Context, log *slog.Logger, st store.Store, name string, audit store.Audit) int {
	if err := st.DeleteHost(ctx, name, a.now(), audit); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			log.Error("no such host", "host", name)
		} else {
			log.Error("cannot delete host", "host", name, "error", err.Error())
		}
		return exitError
	}
	log.Info("host deleted with all its data", "host", strings.ToLower(name), "actor", audit.Actor)
	return exitOK
}

func newTab(w io.Writer) *tabwriter.Writer { return tabwriter.NewWriter(w, 0, 4, 2, ' ', 0) }

func fmtTime(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.Format(time.RFC3339)
}

func (a *app) list(ctx context.Context, log *slog.Logger, st store.Store, asJSON bool) int {
	hosts, err := st.ListHosts(ctx)
	if err != nil {
		log.Error("cannot list hosts", "error", err.Error())
		return exitError
	}
	if asJSON {
		return a.printJSON(log, hosts)
	}
	tw := newTab(a.stdout)
	fmt.Fprintln(tw, "NAME\tSTATE\tTOKEN\tLAST SEEN\tAGENT\tTAGS")
	for _, h := range hosts {
		tok := "active"
		if !h.HasToken {
			tok = "revoked"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", h.Name, stateText(h.State), tok, fmtTime(h.LastSeen), orDash(h.AgentVersion), orDash(strings.Join(h.Tags, ",")))
	}
	tw.Flush()
	return exitOK
}

// stateText: a host that was never evaluated is "pending". A revoked host's
// state is frozen at what it was; the TOKEN column says it is revoked.
func stateText(s *string) string {
	if s == nil {
		return "pending"
	}
	return *s
}

// reason is one entry of hosts.state_reason (internal/health.Reason). The
// CLI reads the stored JSON instead of importing the evaluator.
type reason struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Msg      string `json:"msg"`
}

// printReasons writes the reasons, one per line. The message may hold agent
// text; the evaluator already strips control characters from it.
func (a *app) printReasons(raw []byte, indent string) {
	var rs []reason
	if json.Unmarshal(raw, &rs) != nil {
		return
	}
	for _, r := range rs {
		fmt.Fprintf(a.stdout, "%s%-5s %s: %s\n", indent, r.Severity, r.Rule, r.Msg)
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func (a *app) show(ctx context.Context, log *slog.Logger, st store.Store, name string, asJSON bool) int {
	d, err := st.HostByName(ctx, name)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			log.Error("no such host", "host", name)
		} else {
			log.Error("cannot read host", "host", name, "error", err.Error())
		}
		return exitError
	}
	if asJSON {
		return a.printJSON(log, d)
	}
	tok := "active"
	if !d.HasToken {
		tok = "revoked"
	}
	fmt.Fprintf(a.stdout, "name:           %s\ntoken:          %s (set %s)\ncreated:        %s\nfirst seen:     %s\nlast seen:      %s\nreported as:    %s\nagent version:  %s\ntags:           %s\nreports:        %d\nevents:         %d\n",
		d.Name, tok, fmtTime(d.TokenCreatedAt), fmtTime(&d.CreatedAt), fmtTime(d.FirstSeen), fmtTime(d.LastSeen),
		orDash(d.ReportedName), orDash(d.AgentVersion), orDash(strings.Join(d.Tags, ",")), d.ReportCount, d.EventCount)
	since := ""
	if d.StateSince != nil {
		since = " (since " + fmtTime(d.StateSince) + ")"
	}
	fmt.Fprintf(a.stdout, "state:          %s%s\n", stateText(d.State), since)
	a.printReasons(d.StateReason, "  reason:       ")
	if len(d.StateChanges) > 0 {
		fmt.Fprintln(a.stdout, "state history (newest first):")
		for _, c := range d.StateChanges {
			from := "none"
			if c.From != nil {
				from = *c.From
			}
			fmt.Fprintf(a.stdout, "  %s  %s -> %s\n", c.TS.Format(time.RFC3339), from, c.To)
		}
	}
	if d.LastReport != nil {
		fmt.Fprintf(a.stdout, "last report:    %s\n", d.LastReport)
	}
	return exitOK
}

func (a *app) printJSON(log *slog.Logger, v any) int {
	enc := json.NewEncoder(a.stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		log.Error("cannot write output", "error", err.Error())
		return exitError
	}
	return exitOK
}
