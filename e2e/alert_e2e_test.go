//go:build e2e

// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Milestone 4 acceptance (spec 14), in the container with the real server, the
// real agent and a loopback sink (hack/alertsink): stopping clamd gives exactly
// one webhook and one email, restarting it gives exactly one recovery on each,
// and every attempt is in `alert log`. A target that cannot be reached is
// recorded as a failure while the server keeps serving.
//
// Cooldown is 0 here (deploy/test/server.yaml): the cooldown itself is proven
// with an injected clock; this proves wiring and real delivery.
package e2e

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/alert"
)

const (
	sinkUnit = "clamfleet-alertsink-e2e"
	sinkFile = "/run/alertsink/sink.jsonl"
	sinkHook = "http://127.0.0.1:9100/hook"
)

// startSink builds, pushes and starts the sink as the server user (it needs no
// privilege; /run/alertsink is its RuntimeDirectory).
func startSink(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	out := dir + "/alertsink"
	if err := build(out, "hack/alertsink"); err != nil {
		t.Fatal(err)
	}
	pushBinary(t, out, "alertsink")
	sh(t, "systemd-run --quiet --collect --unit="+sinkUnit+" --uid=clamfleet-server -p RuntimeDirectory=alertsink "+
		"/usr/local/bin/alertsink --http 127.0.0.1:9100 --smtp 127.0.0.1:2525 --out "+sinkFile)
	sh(t, "for _ in $(seq 1 20); do [ -f "+sinkFile+" ] && exit 0; sleep 0.5; done; journalctl -u "+sinkUnit+" --no-pager >&2; echo sink did not start >&2; exit 1")
}

type sinkLine struct {
	Kind   string              `json:"kind"`
	Path   string              `json:"path"`
	Header map[string][]string `json:"header"`
	Body   string              `json:"body"`
	To     []string            `json:"to"`
	Data   string              `json:"data"`
}

func readSink(t *testing.T) (hooks []sinkLine, mails []sinkLine) {
	t.Helper()
	sc := bufio.NewScanner(strings.NewReader(sh(t, "cat "+sinkFile)))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var l sinkLine
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			t.Fatalf("sink line: %v: %q", err, sc.Text())
		}
		if l.Kind == "webhook" {
			hooks = append(hooks, l)
		} else {
			mails = append(mails, l)
		}
	}
	return hooks, mails
}

// stateOf decodes a webhook line as a state-change payload.
func stateOf(t *testing.T, l sinkLine) alert.StateChangePayload {
	t.Helper()
	var p alert.StateChangePayload
	if err := json.Unmarshal([]byte(l.Body), &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func transitionText(p alert.StateChangePayload) string {
	from := "none"
	if p.From != nil {
		from = *p.From
	}
	return from + ">" + p.To
}

// waitSink polls until pred(hooks, mails) holds or the timeout passes, and
// returns the last view (the caller asserts on it).
func waitSink(t *testing.T, timeout time.Duration, pred func(h, m []sinkLine) bool) (hooks, mails []sinkLine) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		hooks, mails = readSink(t)
		if pred(hooks, mails) || time.Now().After(deadline) {
			return hooks, mails
		}
		time.Sleep(time.Second)
	}
}

func hooksText(hooks []sinkLine, t *testing.T) string {
	var parts []string
	for _, h := range hooks {
		parts = append(parts, transitionText(stateOf(t, h)))
	}
	return strings.Join(parts, " ")
}

func mailSubjects(mails []sinkLine) string {
	var subjects []string
	for _, m := range mails {
		for _, line := range strings.Split(m.Data, "\r\n") {
			if strings.HasPrefix(line, "Subject: ") {
				subjects = append(subjects, strings.TrimPrefix(line, "Subject: "))
			}
		}
	}
	return strings.Join(subjects, " | ")
}

// addWebhookTarget creates the webhook target with the CLI (URL through stdin)
// and returns the signing key it printed.
func addWebhookTarget(t *testing.T, name, hookURL string) string {
	t.Helper()
	out := sh(t, "printf '%s\\n' '"+hookURL+"' | runuser -u clamfleet-server -- env SUDO_USER="+operator+
		" /usr/local/bin/clamfleet-server alert add-webhook "+name+" --url-stdin")
	key := strings.TrimSpace(out)
	if !strings.HasPrefix(key, "whsec_") || strings.ContainsAny(key, "\n \t") {
		t.Fatalf("add-webhook must print only the signing key, got %q", out)
	}
	return key
}

type alertLogRow struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Code   string `json:"code"`
	Kind   string `json:"kind"`
}

func alertLogRows(t *testing.T) []alertLogRow {
	t.Helper()
	var rows []alertLogRow
	if err := json.Unmarshal([]byte(srvCLI(t, "alert", "log", "--json", "--limit", "200")), &rows); err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestAlertClamdStoppedAndRecovered(t *testing.T) {
	freshServer(t)
	startSink(t)
	key := addWebhookTarget(t, "ops", sinkHook)
	srvCLI(t, "alert", "add-email", "mail", "--to", "ops@test.example")

	startAgentService(t, critInterval)
	// The baseline is WARN (freshclam_inactive): the first evaluation, NULL to WARN, is alerted.
	hooks, mails := waitSink(t, 40*time.Second, func(h, m []sinkLine) bool { return len(h) >= 1 && len(m) >= 1 })
	if hooksText(hooks, t) != "none>WARN" || len(mails) != 1 || !strings.Contains(mailSubjects(mails), "none -> WARN") {
		t.Fatalf("baseline alerts: hooks %q, mails %q\nserver journal:\n%s", hooksText(hooks, t), mailSubjects(mails), journal(t, serverUnit))
	}

	// clamd down (service and socket): exactly one WARN>CRIT on each target, within the
	// report interval plus the dispatcher's 5 s tick and slack.
	sh(t, "systemctl stop clamav-daemon.socket clamav-daemon.service")
	hooks, mails = waitSink(t, critInterval+15*time.Second, func(h, m []sinkLine) bool { return len(h) >= 2 && len(m) >= 2 })
	if got := hooksText(hooks, t); got != "none>WARN WARN>CRIT" || len(mails) != 2 || !strings.Contains(mailSubjects(mails), "WARN -> CRIT") {
		t.Fatalf("after stopping clamd: hooks %q, mails %q\nserver journal:\n%s", got, mailSubjects(mails), journal(t, serverUnit))
	}
	// Every webhook request is signed with the key the CLI printed (verified here,
	// independently of the server), and carries the alert id as webhook-id.
	raw, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(key, "whsec_"))
	for _, h := range hooks {
		ts, _ := strconv.ParseInt(h.Header["Webhook-Timestamp"][0], 10, 64)
		if !alert.VerifySignature(raw, h.Header["Webhook-Id"][0], ts, []byte(h.Body), h.Header["Webhook-Signature"][0]) {
			t.Fatalf("a webhook request does not verify: %v", h.Header)
		}
	}

	// Recovery: exactly one CRIT>WARN on each.
	sh(t, "systemctl start clamav-daemon.socket clamav-daemon.service")
	waitClamd(t)
	hooks, mails = waitSink(t, 40*time.Second, func(h, m []sinkLine) bool { return len(h) >= 3 && len(m) >= 3 })
	if got := hooksText(hooks, t); got != "none>WARN WARN>CRIT CRIT>WARN" || len(mails) != 3 {
		t.Fatalf("after restarting clamd: hooks %q, mails %q", got, mailSubjects(mails))
	}
	if last := stateOf(t, hooks[2]); !last.Resolved && last.To != "WARN" {
		t.Fatalf("%+v", last)
	}
	time.Sleep(8 * time.Second) // two more dispatcher ticks: nothing may be re-sent
	if h, m := readSink(t); len(h) != 3 || len(m) != 3 {
		t.Fatalf("redelivery: %d webhooks, %d emails", len(h), len(m))
	}

	// The log has a sent row for each target.
	sent := map[string]int{}
	for _, r := range alertLogRows(t) {
		if r.Status == "sent" {
			sent[r.Target]++
		}
	}
	if sent["ops"] != 3 || sent["mail"] != 3 {
		t.Fatalf("alert log sent rows: %v", sent)
	}
}

// A webhook target pointing at a closed loopback port: the attempts are recorded
// with the connection error and the server keeps answering ingest.
func TestAlertTargetDownIsRecorded(t *testing.T) {
	freshServer(t)
	addWebhookTarget(t, "dead", "http://127.0.0.1:9/hook")
	startAgentService(t, critInterval)

	deadline := time.Now().Add(40 * time.Second)
	var retrying int
	for time.Now().Before(deadline) {
		retrying = 0
		for _, r := range alertLogRows(t) {
			if r.Target == "dead" && r.Status == "retrying" && r.Code == "connection refused" {
				retrying++
			}
		}
		if retrying > 0 {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if retrying == 0 {
		t.Fatalf("no retrying row with code 'connection refused':\n%+v\nserver journal:\n%s", alertLogRows(t), journal(t, serverUnit))
	}
	// The server still accepts reports (a one-shot report by the agent user).
	before := showHost(t).ReportCount
	if _, e, code := agentOnce(t); code != 0 {
		t.Fatalf("ingest stopped working while a target is down: %d %s", code, e)
	}
	if after := showHost(t).ReportCount; after <= before {
		t.Fatalf("no new report stored: %d -> %d", before, after)
	}
}
