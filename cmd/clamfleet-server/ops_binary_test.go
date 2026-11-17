// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Retention and restore through the real server binary (milestone 6, plan 6.3): nothing
// is injected between the test and the process, the clock is the real one, and the
// database is the file `hack/seeddb` wrote, with rows of known ages.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/testtls"
)

// seedManifest mirrors hack/seeddb's output.
type seedManifest struct {
	AfterDefaults  seedCounts `json:"after_defaults"`
	AfterReports14 seedCounts `json:"after_reports_days_14"`
}

type seedCounts struct {
	Reports      int `json:"reports"`
	Events       int `json:"events"`
	StateChanges int `json:"state_changes"`
	Audit        int `json:"audit"`
	AlertLog     int `json:"alert_log"`
}

func seedDatabase(t *testing.T) (db string, m seedManifest) {
	t.Helper()
	db = filepath.Join(t.TempDir(), "seed.db")
	out, err := exec.Command(seeddbBin, "--db", db, "--now", time.Now().UTC().Format(time.RFC3339)).Output()
	if err != nil {
		t.Fatalf("seeddb: %v", err)
	}
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	return db, m
}

// prunedCounts waits for the retention pass to log its counts and returns them by table.
func prunedCounts(t *testing.T, srv *liveServer) map[string]int {
	t.Helper()
	msgs := map[string]string{
		"events": "old events pruned", "state_changes": "old state changes pruned", "reports": "old reports pruned",
		"alert_log": "old alert history pruned", "audit": "old audit rows pruned",
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		got := map[string]int{}
		for _, line := range strings.Split(srv.stderr.String(), "\n") {
			var m map[string]any
			if json.Unmarshal([]byte(line), &m) != nil {
				continue
			}
			for table, msg := range msgs {
				if m["msg"] == msg {
					got[table] = int(m["count"].(float64))
				}
			}
		}
		if len(got) == len(msgs) {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("not every table logged a prune within 10 s (%v):\n%s", got, srv.stderr.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// The acceptance at function level: a database with rows on both sides of every
// cutoff, served by the real binary with the default retention. One "pruned" line
// per table with the expected count; host show reports the young rows only; the
// state change and the event with a retrying delivery are still there. A second
// run with retention.reports_days: 14 prunes more. Mutation: unwire one table
// from the runner (that table never logs).
func TestRetentionThroughBinary(t *testing.T) {
	tlsb, err := testtls.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name      string
		env       []string
		reports   int // rows that must be pruned
		wantAfter func(m seedManifest) (reports int)
	}{
		{"defaults", nil, 1, func(m seedManifest) int { return m.AfterDefaults.Reports }},
		{"reports_days 14", []string{"CLAMFLEET_SERVER_RETENTION_REPORTS_DAYS=14"}, 2, func(m seedManifest) int { return m.AfterReports14.Reports }},
	} {
		t.Run(c.name, func(t *testing.T) {
			db, m := seedDatabase(t)
			srv := startServe(t, tlsb, db, c.env...)
			got := prunedCounts(t, srv)
			want := map[string]int{"events": 1, "state_changes": 1, "reports": c.reports, "alert_log": 1, "audit": 1}
			for table, n := range want {
				if got[table] != n {
					t.Errorf("%s: pruned %d, want %d", table, got[table], n)
				}
			}
			var s struct {
				ReportCount int `json:"report_count"`
				EventCount  int `json:"event_count"`
			}
			r := runServer(t, srv.env, "host", "show", "seed01", "--json")
			if r.code != 0 || json.Unmarshal([]byte(r.stdout), &s) != nil {
				t.Fatalf("host show: %+v", r)
			}
			if s.ReportCount != c.wantAfter(m) || s.EventCount != m.AfterDefaults.Events {
				t.Errorf("host show: %d reports, %d events; want %d and %d", s.ReportCount, s.EventCount, c.wantAfter(m), m.AfterDefaults.Events)
			}
			// The guards: the state change and the event whose delivery is still retrying survive,
			// and so does the delivery itself. The two seeded deliveries are counted by id, not "every
			// pending one": the server is live, its health evaluator finds the seeded host (no report
			// for days) STALE, records a state change and queues a delivery of its own for the seeded
			// target. Reproduced with health.eval_interval=1s and a 5 s wait (3 state changes, 3
			// deliveries); with the default interval it depends on the machine whether that has happened
			// by the time of this query (it had on one CI run). It has nothing to do with retention.
			for q, want := range map[string]int{
				`SELECT count(*) FROM state_changes WHERE id = 104`:                                                     1,
				`SELECT count(*) FROM events WHERE path = '/srv/seed/2'`:                                                1,
				`SELECT count(*) FROM alert_deliveries WHERE status = 'pending' AND alert_id IN ('seed-ev', 'seed-sc')`: 2,
			} {
				if n := dbCount(t, db, q); n != want {
					t.Errorf("%s = %d, want %d\nall deliveries: %s\nserver log:\n%s", q, n, want, deliveryRows(t, db), srv.stderr.String())
				}
			}
			if strings.Contains(srv.stderr.String(), "/srv/seed") {
				t.Fatal("a path reached the server log")
			}
		})
	}
}

// deliveryRows lists every alert delivery (id, kind, status, attempts, creation time) for a failure
// message. Added after the first CI run found a third pending delivery that nobody could explain from
// "= 3, want 2" (it never happened locally, 60 runs under CPU load included): the next occurrence
// names the row and, with the server log, who queued it.
func deliveryRows(t *testing.T, db string) string {
	t.Helper()
	d, err := sql.Open("sqlite", "file:"+db+"?mode=ro")
	if err != nil {
		return err.Error()
	}
	defer d.Close()
	rows, err := d.Query(`SELECT alert_id, kind, status, attempts, created_at FROM alert_deliveries ORDER BY id`)
	if err != nil {
		return err.Error()
	}
	defer rows.Close()
	var b strings.Builder
	for rows.Next() {
		var id, kind, status string
		var attempts, created int64
		if err := rows.Scan(&id, &kind, &status, &attempts, &created); err != nil {
			return err.Error()
		}
		fmt.Fprintf(&b, "\n  %s kind=%s status=%s attempts=%d created_at=%d", id, kind, status, attempts, created)
	}
	return b.String()
}

func dbCount(t *testing.T, db, q string) int {
	t.Helper()
	d, err := sql.Open("sqlite", "file:"+db+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	var n int
	if err := d.QueryRow(q).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// postEvent sends one detection straight to /v1/event.
func postEvent(t *testing.T, addr, caFile, token, host string, n int) {
	t.Helper()
	ca, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	body := fmt.Sprintf(`{"schema":1,"id":"%032x","host":%q,"ts":%q,"path":"/srv/restore/%d","signature":"S","source":"clamd"}`,
		n, host, time.Now().UTC().Format(time.RFC3339), n)
	req, _ := http.NewRequest("POST", "https://"+addr+"/v1/event", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil || resp.StatusCode != 202 {
		t.Fatalf("post event %d: %v %v", n, resp, err)
	}
	resp.Body.Close()
}

// The documented restore (docs/operations.md), run for real: stop the server, copy the
// backup over db_path, delete -wal and -shm, start. The fleet is the state at backup
// time, with its events, and the restored server serves a report. Mutation: a backup
// that is not consistent, or a restore that leaves the old -wal behind.
func TestRestoreFromBackup(t *testing.T) {
	tlsb, err := testtls.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(t.TempDir(), "cf.db")
	addr := freeAddr(t)
	backups := privateDir(t)
	srv := startServeAt(t, tlsb, db, addr, "CLAMFLEET_SERVER_BACKUP_DIR="+backups)

	tokens := map[string]string{}
	for _, name := range []string{"web01", "web02"} {
		r := runServer(t, srv.env, "host", "add", name)
		if r.code != 0 {
			t.Fatal(r)
		}
		tokens[name] = strings.TrimSpace(r.stdout)
		ag := newAgent(t, addr, tlsb.CA, "")
		ag.token(tokens[name])
		if res := ag.runOnce(); res.code != 0 {
			t.Fatalf("agent %s: %s", name, res.stderr)
		}
	}
	postEvent(t, addr, tlsb.CA, tokens["web01"], "web01", 1)
	postEvent(t, addr, tlsb.CA, tokens["web01"], "web01", 2)

	b := runServer(t, srv.env, "backup", "--verify")
	if b.code != 0 {
		t.Fatalf("backup: %+v", b)
	}
	backup := strings.TrimSpace(b.stdout)

	// More happens after the backup; none of it may be in the restored server.
	r := runServer(t, srv.env, "host", "add", "web03")
	if r.code != 0 {
		t.Fatal(r)
	}
	postEvent(t, addr, tlsb.CA, tokens["web01"], "web01", 3)
	srv.Stop()

	// Restore, as the docs say.
	data, err := os.ReadFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(db, data, 0o600); err != nil {
		t.Fatal(err)
	}
	os.Remove(db + "-wal")
	os.Remove(db + "-shm")
	srv2 := startServeAt(t, tlsb, db, addr)

	var hosts []struct {
		Name string `json:"name"`
	}
	lr := runServer(t, srv2.env, "host", "list", "--json")
	if lr.code != 0 || json.Unmarshal([]byte(lr.stdout), &hosts) != nil {
		t.Fatalf("host list: %+v", lr)
	}
	if len(hosts) != 2 || hosts[0].Name != "web01" || hosts[1].Name != "web02" {
		t.Fatalf("the restored fleet is %v, want web01 and web02 (web03 was added after the backup)", hosts)
	}
	var s struct {
		EventCount  int `json:"event_count"`
		ReportCount int `json:"report_count"`
	}
	sr := runServer(t, srv2.env, "host", "show", "web01", "--json")
	if sr.code != 0 || json.Unmarshal([]byte(sr.stdout), &s) != nil || s.EventCount != 2 {
		t.Fatalf("web01 after the restore: %+v (events %d, want 2)", sr, s.EventCount)
	}
	// The restored server serves: the old token still works.
	ag := newAgent(t, addr, tlsb.CA, "")
	ag.token(tokens["web02"])
	time.Sleep(1100 * time.Millisecond) // report ts has one-second resolution
	if res := ag.runOnce(); res.code != 0 {
		t.Fatalf("the restored server did not accept a report: %s", res.stderr)
	}
}
