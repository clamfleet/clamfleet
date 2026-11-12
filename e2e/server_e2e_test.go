//go:build e2e

// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Server ingest end to end: the real server binary runs as the unprivileged
// "clamfleet-server" user in a transient systemd unit, listening on
// 127.0.0.1:8443 INSIDE the container (nothing listens on a non-loopback
// address anywhere), and the real agent binary, run as the unprivileged
// "clamfleet" user, reports to it over TLS with a private CA. Every scenario
// starts from the clean snapshot (the reset removes the users, files and units).
//
// Not covered here, on purpose: unknown JSON fields and body limits are tested
// through the real router and listener at functional level; the container may
// lack curl and adding it only for this is not worth it.
package e2e

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/proto"
	"github.com/clamfleet/clamfleet/internal/testtls"
)

const (
	serverUnit = "clamfleet-server-e2e"
	agentUnit  = "clamfleet-agent-e2e"
	hostName   = "e2e-host"
	// operator is the name the audit log should record. Admin commands run as
	// the server user (least privilege, as in production: sudo -u
	// clamfleet-server); SUDO_USER, which the CLI prefers for the audit
	// actor, stands in for the human who typed `sudo -u clamfleet-server ...`.
	operator = "e2e-operator"
)

// freshServer returns the container to the clean snapshot with the agent
// prepared, then installs and starts the server and registers hostName. It
// returns the host's token (also written to /etc/clamfleet/token).
func freshServer(t *testing.T) string {
	t.Helper()
	fresh(t)
	if err := script("prepare-server.sh"); err != nil {
		t.Fatal(err)
	}
	pushBinary(t, srvBin, "clamfleet-server")

	b, err := testtls.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	read := func(p string) string {
		d, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return string(d)
	}
	// PEM is plain base64 text, so heredocs carry it safely over stdin.
	sh(t, "cat > /etc/clamfleet/ca.pem <<'EOF'\n"+read(b.CA)+"EOF\n"+
		"cat > /etc/clamfleet/tls.crt <<'EOF'\n"+read(b.Cert)+"EOF\n"+
		"cat > /etc/clamfleet/tls.key <<'EOF'\n"+read(b.Key)+"EOF\n"+
		"chmod 644 /etc/clamfleet/ca.pem /etc/clamfleet/tls.crt\n"+
		"chown clamfleet-server:clamfleet-server /etc/clamfleet/tls.key; chmod 600 /etc/clamfleet/tls.key\n")

	// Default (info) level: the journal must already hold the successful request lines.
	sh(t, "systemd-run --quiet --collect --unit="+serverUnit+" --uid=clamfleet-server "+
		"/usr/local/bin/clamfleet-server serve")
	sh(t, "for _ in $(seq 1 30); do journalctl -u "+serverUnit+" -o cat --no-pager -q | grep -q '\"msg\":\"listening\"' && exit 0; sleep 1; done; "+
		"journalctl -u "+serverUnit+" --no-pager >&2; echo server did not start >&2; exit 1")

	tok := srvCLI(t, "host", "add", hostName)
	if !strings.HasPrefix(tok, "cfa_") || len(tok) != 47 {
		t.Fatalf("host add printed %q, want only the token", tok)
	}
	writeToken(t, tok)
	return tok
}

// srvCLI runs the admin CLI as the server user and returns its stdout.
func srvCLI(t *testing.T, args ...string) string {
	t.Helper()
	return sh(t, "runuser -u clamfleet-server -- env SUDO_USER="+operator+" /usr/local/bin/clamfleet-server "+strings.Join(args, " "))
}

// writeToken installs the token for the agent: root:clamfleet 0640, like a real deployment.
func writeToken(t *testing.T, tok string) {
	t.Helper()
	sh(t, "printf '%s\\n' '"+tok+"' > /etc/clamfleet/token; chown root:clamfleet /etc/clamfleet/token; chmod 640 /etc/clamfleet/token")
}

type shownHost struct {
	Name        string        `json:"name"`
	FirstSeen   *string       `json:"first_seen"`
	LastSeen    *string       `json:"last_seen"`
	ReportCount int           `json:"report_count"`
	LastReport  *proto.Report `json:"last_report"`
	Audit       []struct {
		Action string `json:"action"`
		Actor  string `json:"actor"`
	} `json:"audit"`
}

func showHost(t *testing.T) shownHost {
	t.Helper()
	var h shownHost
	if err := json.Unmarshal([]byte(srvCLI(t, "host", "show", hostName, "--json")), &h); err != nil {
		t.Fatal(err)
	}
	return h
}

// agentOnce runs `clamfleet-agent run --once` as the unprivileged agent user,
// trusting the test CA through SSL_CERT_FILE (the documented private-CA way).
func agentOnce(t *testing.T) (stdout, stderr string, code int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return ct(ctx, nil, "runuser", "-u", "clamfleet", "--", "env", "SSL_CERT_FILE=/etc/clamfleet/ca.pem",
		"/usr/local/bin/clamfleet-agent", "run", "--once")
}

func journal(t *testing.T, unit string) string {
	t.Helper()
	return sh(t, "journalctl -u "+unit+" -o cat --no-pager -q")
}

// A registered host reports once and the server holds a report that matches
// independent facts about the container, not just what the agent said.
func TestServerIngestRegisterThenRunOnce(t *testing.T) {
	freshServer(t)
	if h := showHost(t); h.ReportCount != 0 || h.LastReport != nil || h.FirstSeen != nil {
		t.Fatalf("a host with no report yet: %+v", h)
	}
	out, errOut, code := agentOnce(t)
	if code != 0 || out != "" {
		t.Fatalf("run --once: exit %d\nstdout: %s\nstderr: %s", code, out, errOut)
	}
	h := showHost(t)
	if h.ReportCount != 1 || h.LastReport == nil || h.FirstSeen == nil || h.LastSeen == nil {
		t.Fatalf("after run --once: %+v", h)
	}
	if want := sh(t, "hostname"); h.LastReport.Host != want {
		t.Errorf("stored host %q, container says %q", h.LastReport.Host, want)
	}
	wv, _ := sigtoolInfo(t, filepath.Base(sh(t, "ls /var/lib/clamav/daily.c[vl]d | head -n1")))
	if daily := h.LastReport.Sigs.Daily; daily == nil || daily.Version != wv {
		t.Errorf("stored sigs.daily = %+v, sigtool says version %d", daily, wv)
	}
	// The request line carries the client IP, always (decision 10).
	if j := journal(t, serverUnit); !strings.Contains(j, `"client_ip":"127.0.0.1"`) || !strings.Contains(j, `"status":202`) {
		t.Errorf("server journal lacks the request line:\n%s", j)
	}
}

// The agent as a service: one report immediately, then one per interval, and a
// clean stop on SIGTERM.
func TestServerIngestAgentServiceLoop(t *testing.T) {
	freshServer(t)
	sh(t, "systemd-run --quiet --collect --unit="+agentUnit+" --uid=clamfleet "+
		"--setenv=SSL_CERT_FILE=/etc/clamfleet/ca.pem --setenv=CLAMFLEET_AGENT_INTERVAL=5s "+
		"/usr/local/bin/clamfleet-agent run")
	time.Sleep(12 * time.Second)
	sh(t, "systemctl stop "+agentUnit)
	// 12 s at 5 s intervals: the immediate send plus two ticks; two is the safe floor.
	if h := showHost(t); h.ReportCount < 2 {
		t.Fatalf("%d reports after 12 s at a 5 s interval, want at least 2\nagent journal:\n%s", h.ReportCount, journal(t, agentUnit))
	}
	if j := journal(t, agentUnit); !strings.Contains(j, "agent started") {
		t.Fatalf("agent journal:\n%s", j)
	}
}

func TestServerIngestWrongTokenStoresNothing(t *testing.T) {
	good := freshServer(t)
	bad := "cfa_" + strings.Repeat("A", 43)
	writeToken(t, bad)
	_, errOut, code := agentOnce(t)
	if code != 1 || !strings.Contains(errOut, "unauthorized") {
		t.Fatalf("wrong token: exit %d\nstderr: %s", code, errOut)
	}
	if h := showHost(t); h.ReportCount != 0 || h.LastReport != nil {
		t.Fatalf("a rejected report was stored: %+v", h)
	}
	// Neither side logged either token.
	j := journal(t, serverUnit)
	for _, tok := range []string{good, bad} {
		if strings.Contains(j, tok) || strings.Contains(errOut, tok) || strings.Contains(j, tok[4:]) {
			t.Fatalf("a token appears in a log:\nserver journal:\n%s\nagent stderr:\n%s", j, errOut)
		}
	}
	if !strings.Contains(j, `"status":401`) {
		t.Fatalf("the rejection is not in the server journal:\n%s", j)
	}
}

func TestServerIngestRotateTokenCutsOverImmediately(t *testing.T) {
	old := freshServer(t)
	if _, e, code := agentOnce(t); code != 0 {
		t.Fatalf("first run: exit %d: %s", code, e)
	}
	fresh := srvCLI(t, "host", "rotate-token", hostName)
	if fresh == old || !strings.HasPrefix(fresh, "cfa_") {
		t.Fatalf("rotate printed %q", fresh)
	}
	// The agent still holds the old token: refused at once, no grace period.
	if _, e, code := agentOnce(t); code != 1 || !strings.Contains(e, "unauthorized") {
		t.Fatalf("old token after rotation: exit %d: %s", code, e)
	}
	// The token file is re-read on every send: no agent restart needed.
	writeToken(t, fresh)
	if _, e, code := agentOnce(t); code != 0 {
		t.Fatalf("new token: exit %d: %s", code, e)
	}
	h := showHost(t)
	rot := 0
	for _, a := range h.Audit {
		if a.Action == "host.token.rotate" {
			rot++
			if a.Actor != operator {
				t.Errorf("rotate audited as %q, want %q", a.Actor, operator)
			}
		}
	}
	if rot != 1 {
		t.Fatalf("%d rotate audit rows, want exactly 1: %+v", rot, h.Audit)
	}
	if j := journal(t, serverUnit); strings.Contains(j, old) || strings.Contains(j, fresh) {
		t.Fatalf("a token appears in the server journal:\n%s", j)
	}
}
