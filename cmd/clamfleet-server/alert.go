// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// alert.go: the "alert" admin commands (docs/plans/milestone-4.md 4.12), for
// automation and the container e2e. Editing a target stays in the console.
//
//	alert list [--json]
//	alert log [--target NAME] [--limit N] [--json]
//	alert add-webhook NAME (--url-stdin | --url-file PATH) [--min-severity S] [--tags a,b] [--no-state-changes] [--no-detections]
//	alert add-email NAME --to a@x,b@y [same flags]
//	alert test NAME
//	alert delete NAME --yes
//
// A webhook URL is a credential for many receivers (chat tools carry their
// token in the path). It therefore NEVER goes on the command line, where it
// would land in shell history, `ps` output and sudo logs: it is read from one
// line of stdin or from a file under the key-file permission rule. A positional
// URL is a usage error, and no message of this file, not even a usage error,
// echoes an argument or the URL.
//
// Output contract of add-webhook: stdout carries exactly one line, the whsec_
// signing key, shown once (the `host add` pattern).
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"strings"
	"time"

	"github.com/clamfleet/clamfleet/internal/alert"
	"github.com/clamfleet/clamfleet/internal/secrets"
	"github.com/clamfleet/clamfleet/internal/server"
	"github.com/clamfleet/clamfleet/internal/store"
)

// maxURLLine bounds what --url-stdin reads.
const maxURLLine = alert.MaxURLBytes + 2

// loadKeysOptional loads the key file; an absent file is (nil, nil), a present
// but invalid one is an error (the same rule as serve).
func loadKeysOptional(cfg server.Config) (*secrets.Keyring, error) {
	ring, err := secrets.LoadFile(cfg.SecretKeyFile)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return ring, err
}

func (a *app) alert(ctx context.Context, args []string) int {
	if len(args) == 0 {
		fmt.Fprint(a.stderr, usage)
		return exitUsage
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list", "log", "add-webhook", "add-email", "test", "delete":
	default:
		fmt.Fprintf(a.stderr, "alert: unknown subcommand\n\n%s", usage)
		return exitUsage
	}
	fs, cfgFlag := newFlags("alert "+sub, io.Discard) // never print flag values: a URL may be among them
	asJSON := fs.Bool("json", false, "machine-readable output (list, log)")
	yes := fs.Bool("yes", false, "confirm a deletion (delete)")
	target := fs.String("target", "", "only this target (log)")
	limit := fs.Int("limit", 50, "number of rows (log)")
	urlStdin := fs.Bool("url-stdin", false, "read the webhook URL from one line of stdin (add-webhook)")
	urlFile := fs.String("url-file", "", "read the webhook URL from a file with mode 0600 or 0640 (add-webhook)")
	minSev := fs.String("min-severity", "WARN", "WARN, CRIT or STALE (add-webhook, add-email)")
	tags := fs.String("tags", "", "comma-separated tags: only hosts with any of them (add-webhook, add-email)")
	noState := fs.Bool("no-state-changes", false, "do not send state changes (add-webhook, add-email)")
	noDet := fs.Bool("no-detections", false, "do not send detections (add-webhook, add-email)")
	to := fs.String("to", "", "comma-separated recipients (add-email)")
	// Flags may follow NAME ("alert delete ops --yes"), as for the host commands.
	var pos []string
	for {
		if err := fs.Parse(rest); err != nil {
			// The flag package's own message would quote the offending value.
			fmt.Fprintf(a.stderr, "alert %s: invalid or unknown option (arguments are never echoed)\n", sub)
			if sub == "add-webhook" {
				fmt.Fprintln(a.stderr, "the webhook URL is never an argument: use --url-stdin or --url-file")
			}
			return exitUsage
		}
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		rest = fs.Args()[1:]
	}

	needName := sub != "list" && sub != "log"
	switch {
	case !needName && len(pos) != 0, needName && len(pos) != 1:
		if sub == "add-webhook" && len(pos) > 1 {
			fmt.Fprintln(a.stderr, "alert add-webhook: the webhook URL is never an argument (it would show in shell history and ps): use --url-stdin or --url-file")
		} else {
			fmt.Fprintf(a.stderr, "alert %s: wrong number of arguments\n", sub)
		}
		return exitUsage
	case sub == "delete" && !*yes:
		fmt.Fprintf(a.stderr, "alert delete: this deletes the target and its pending alerts; repeat with --yes to confirm\n")
		return exitUsage
	case sub == "add-webhook" && *urlStdin == (*urlFile != ""):
		fmt.Fprintln(a.stderr, "alert add-webhook: give the URL with exactly one of --url-stdin or --url-file")
		return exitUsage
	case sub == "add-email" && *to == "":
		fmt.Fprintln(a.stderr, "alert add-email: --to a@x.example,b@x.example is required")
		return exitUsage
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
		return a.alertList(ctx, log, st, *asJSON)
	case "log":
		return a.alertLog(ctx, log, st, *target, *limit, *asJSON)
	case "delete":
		if err := st.DeleteAlertTarget(ctx, pos[0], a.now(), audit); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				log.Error("no such alert target")
			} else {
				log.Error("cannot delete the alert target", "error", err.Error())
			}
			return exitError
		}
		log.Info("alert target deleted", "target", strings.ToLower(pos[0]), "actor", a.actor)
		return exitOK
	case "test":
		return a.alertTest(ctx, log, cfg, st, pos[0], audit)
	}

	// add-webhook / add-email
	filter, err := alert.ParseTags(*tags)
	if err != nil {
		fmt.Fprintf(a.stderr, "alert %s: %v\n", sub, err)
		return exitUsage
	}
	if !alert.ValidMinSeverity(*minSev) {
		fmt.Fprintf(a.stderr, "alert %s: --min-severity must be WARN, CRIT or STALE\n", sub)
		return exitUsage
	}
	nt := store.NewAlertTarget{Name: pos[0], MinSeverity: *minSev, TagFilter: filter,
		SendStateChanges: !*noState, SendDetections: !*noDet, Enabled: true}
	if sub == "add-email" {
		return a.addEmail(ctx, log, cfg, st, nt, *to, audit)
	}
	return a.addWebhook(ctx, log, cfg, st, nt, *urlStdin, *urlFile, audit)
}

func (a *app) addEmail(ctx context.Context, log *slog.Logger, cfg server.Config, st store.AlertStore, nt store.NewAlertTarget, toRaw string, audit store.Audit) int {
	if cfg.SMTP.Host == "" {
		log.Error("email is not configured: set smtp.host and smtp.from in the server configuration first")
		return exitError
	}
	rcpts, err := alert.ParseRecipients(toRaw)
	if err != nil {
		log.Error(err.Error())
		return exitError
	}
	nt.Type = store.TargetTypeEmail
	nt.Config = mustJSONBytes(alert.EmailConfig{To: rcpts})
	if _, err := st.CreateAlertTarget(ctx, nt, nil, a.now(), audit); err != nil {
		return a.createFailed(log, err)
	}
	log.Info("alert target added", "target", strings.ToLower(nt.Name), "type", "email", "actor", a.actor)
	return exitOK
}

func (a *app) addWebhook(ctx context.Context, log *slog.Logger, cfg server.Config, st store.AlertStore, nt store.NewAlertTarget, fromStdin bool, file string, audit store.Audit) int {
	var raw string
	if fromStdin {
		line, err := bufio.NewReader(io.LimitReader(a.stdin, maxURLLine)).ReadString('\n')
		if err != nil && err != io.EOF {
			log.Error("--url-stdin: cannot read the URL")
			return exitError
		}
		if raw = strings.TrimSpace(line); raw == "" {
			log.Error("--url-stdin: expected one line with the webhook URL on stdin")
			return exitError
		}
	} else {
		var err error
		if raw, err = secrets.ReadProtectedFile(file, "--url-file"); err != nil {
			// The error names the file and the problem, never its content.
			log.Error("cannot read the URL file", "error", err.Error())
			return exitError
		}
	}
	policy := alertPolicy(cfg)
	vu, err := alert.ValidateWebhookURL(raw, policy)
	if err != nil {
		log.Error("the URL was refused", "reason", err.Error()) // validation errors never contain the URL
		return exitError
	}
	keys, err := loadKeysOptional(cfg)
	if err != nil {
		log.Error("cannot load the key file", "error", err.Error())
		return exitError
	}
	if keys == nil {
		log.Error("webhook targets need the secret key file, which does not exist: create it with `clamfleet-server key generate` (as root, then chgrp clamfleet-server and chmod 0640), then run this again")
		return exitError
	}
	signing, err := alert.NewSigningKey()
	if err != nil {
		log.Error("cannot generate a signing key", "error", err.Error())
		return exitError
	}
	nt.Type = store.TargetTypeWebhook
	nt.Config = mustJSONBytes(alert.WebhookConfig{URLDisplay: vu.Display, Plaintext: vu.Plaintext})
	_, err = st.CreateAlertTarget(ctx, nt, func(id int64) ([]byte, error) {
		plain, err := alert.WebhookSecret{URL: raw, SigningKey: signing}.Marshal()
		if err != nil {
			return nil, err
		}
		return keys.Seal(secrets.PurposeAlertTarget, plain, uint64(id))
	}, a.now(), audit)
	if err != nil {
		return a.createFailed(log, err)
	}
	log.Info("alert target added", "target", strings.ToLower(nt.Name), "type", "webhook", "destination", vu.Display, "actor", a.actor)
	// The signing key is shown once, here, and exists nowhere else in clear.
	fmt.Fprintln(a.stdout, signing)
	return exitOK
}

func (a *app) createFailed(log *slog.Logger, err error) int {
	if errors.Is(err, store.ErrTargetExists) {
		log.Error("an alert target with that name already exists")
	} else {
		log.Error("cannot add the alert target", "error", err.Error())
	}
	return exitError
}

func alertPolicy(cfg server.Config) alert.Policy {
	deny, _ := server.ParseDenyNetworks(cfg.Alert.Webhook.DenyNetworks) // Validate already checked them
	return alert.Policy{AllowPrivate: cfg.Alert.Webhook.AllowPrivate, AllowLoopback: cfg.Alert.Webhook.AllowLoopback, DenyNetworks: deny}
}

type alertListEntry struct {
	Name             string     `json:"name"`
	Type             string     `json:"type"`
	Destination      string     `json:"destination"`
	MinSeverity      string     `json:"min_severity"`
	Tags             []string   `json:"tags"`
	SendStateChanges bool       `json:"send_state_changes"`
	SendDetections   bool       `json:"send_detections"`
	Enabled          bool       `json:"enabled"`
	LastStatus       string     `json:"last_status"`
	LastAt           *time.Time `json:"last_at"`
}

// destinationOf is the display form of a target's destination (the URL's
// scheme and host, or the recipients), never anything secret.
func destinationOf(t store.AlertTarget) string {
	if t.Type == store.TargetTypeWebhook {
		return jsonField(t.Config, "url_display")
	}
	to, _ := alert.Recipients(t.Config)
	return strings.Join(to, ",")
}

func (a *app) alertList(ctx context.Context, log *slog.Logger, st store.AlertStore, asJSON bool) int {
	ts, err := st.ListAlertTargets(ctx)
	if err != nil {
		log.Error("cannot list alert targets", "error", err.Error())
		return exitError
	}
	out := make([]alertListEntry, 0, len(ts))
	for _, t := range ts {
		tg := t.TagFilter
		if tg == nil {
			tg = []string{}
		}
		out = append(out, alertListEntry{Name: t.Name, Type: t.Type, Destination: destinationOf(t.AlertTarget), MinSeverity: t.MinSeverity, Tags: tg,
			SendStateChanges: t.SendStateChanges, SendDetections: t.SendDetections, Enabled: t.Enabled, LastStatus: t.LastStatus, LastAt: t.LastAt})
	}
	if asJSON {
		return a.printJSON(log, out)
	}
	tw := newTab(a.stdout)
	fmt.Fprintln(tw, "NAME\tTYPE\tDESTINATION\tMIN\tTAGS\tENABLED\tLAST")
	for _, e := range out {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%v\t%s %s\n", e.Name, e.Type, e.Destination, e.MinSeverity, orDash(strings.Join(e.Tags, ",")), e.Enabled, orDash(e.LastStatus), fmtTime(e.LastAt))
	}
	tw.Flush()
	return exitOK
}

type alertLogJSON struct {
	TS         time.Time `json:"ts"`
	Target     string    `json:"target"`
	Recipient  string    `json:"recipient"`
	Host       string    `json:"host"`
	Kind       string    `json:"kind"`
	Attempt    int       `json:"attempt"`
	Status     string    `json:"status"`
	Code       string    `json:"code"`
	Error      string    `json:"error"`
	DurationMS int64     `json:"duration_ms"`
}

func (a *app) alertLog(ctx context.Context, log *slog.Logger, st store.AlertStore, target string, limit int, asJSON bool) int {
	es, err := st.AlertLog(ctx, store.AlertLogFilter{TargetName: target, Limit: limit})
	if err != nil {
		log.Error("cannot read the alert log", "error", err.Error())
		return exitError
	}
	out := make([]alertLogJSON, 0, len(es))
	for _, e := range es {
		out = append(out, alertLogJSON{TS: e.TS, Target: e.TargetName, Recipient: e.Recipient, Host: e.Host, Kind: e.Kind, Attempt: e.Attempt,
			Status: e.Status, Code: e.Code, Error: e.Error, DurationMS: e.DurationMS})
	}
	if asJSON {
		return a.printJSON(log, out)
	}
	tw := newTab(a.stdout)
	fmt.Fprintln(tw, "TIME\tTARGET\tRECIPIENT\tHOST\tKIND\tATT\tSTATUS\tCODE\tDETAIL")
	for _, e := range out {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\n", e.TS.Format(time.RFC3339), e.Target, orDash(e.Recipient), orDash(e.Host), e.Kind, e.Attempt, e.Status, orDash(e.Code), e.Error)
	}
	tw.Flush()
	return exitOK
}

// alertTest sends a test message through the same senders and policy as real
// alerts and prints one result line per recipient; exit 1 when any failed.
func (a *app) alertTest(ctx context.Context, log *slog.Logger, cfg server.Config, st store.Store, name string, audit store.Audit) int {
	t, err := st.AlertTarget(ctx, name)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			log.Error("no such alert target")
		} else {
			log.Error("cannot read the alert target", "error", err.Error())
		}
		return exitError
	}
	keys, err := loadKeysOptional(cfg)
	if err != nil {
		log.Error("cannot load the key file", "error", err.Error())
		return exitError
	}
	al, err := server.BuildAlerts(cfg, st, keys, a.now, log)
	if err != nil {
		log.Error("invalid alert configuration", "error", err.Error())
		return exitError
	}
	recs, err := al.Dispatcher.TestSend(ctx, t)
	if err != nil {
		log.Error("the test could not be run", "error", err.Error())
		return exitError
	}
	if err := st.RecordTestSend(ctx, t.Name, recs, a.now(), audit); err != nil {
		log.Error("cannot record the test send", "error", err.Error())
	}
	code := exitOK
	for _, r := range recs {
		who := ""
		if r.Recipient != "" {
			who = " " + r.Recipient
		}
		if r.Result.Status == store.AlertLogSent {
			fmt.Fprintf(a.stdout, "delivered%s: %s in %d ms\n", who, r.Result.Code, r.Result.Duration.Milliseconds())
		} else {
			fmt.Fprintf(a.stdout, "failed%s: %s: %s\n", who, orDash(r.Result.Code), r.Result.Error)
			code = exitError
		}
	}
	return code
}

// mustJSONBytes encodes plain strings and slices of them: it cannot fail.
func mustJSONBytes(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// jsonField reads one string field of a flat JSON object ("" when absent).
func jsonField(raw []byte, key string) string {
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return ""
	}
	s, _ := m[key].(string)
	return s
}
