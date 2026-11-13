// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/clamfleet/clamfleet/internal/proto"
	"github.com/clamfleet/clamfleet/internal/version"
)

// binary is the real agent, built once. These tests run the compiled program
// through its real command dispatch: a handler test calling run() directly
// could not notice a subcommand that is not registered, or a report printed
// to the wrong stream.
var binary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "cfagent")
	if err != nil {
		panic(err)
	}
	binary = filepath.Join(dir, "clamfleet-agent")
	if out, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		os.Stderr.Write(out)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type result struct {
	stdout, stderr string
	code           int
}

func runAgent(t *testing.T, path string, env []string, args ...string) result {
	t.Helper()
	cmd := exec.Command(binary, args...)
	// A clean environment: the developer's own CLAMFLEET_AGENT_* variables must not leak in.
	cmd.Env = append([]string{"PATH=" + path}, env...)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return result{so.String(), se.String(), code}
}

// fakeBin writes a "systemctl" that reports every unit as active and a
// "journalctl" with no output.
func fakeBin(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	scripts := map[string]string{
		"systemctl":  "#!/bin/sh\nprintf 'LoadState=loaded\\nActiveState=active\\n'\n",
		"journalctl": "#!/bin/sh\nexit 0\n",
	}
	for n, s := range scripts {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(s), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// serveClamd answers PING, VERSION and STATS on a unix socket.
func serveClamd(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "cf")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 64)
				n, _ := c.Read(buf)
				switch strings.TrimRight(string(buf[:n]), "\x00") {
				case "zPING":
					c.Write([]byte("PONG\x00"))
				case "zVERSION":
					c.Write([]byte("ClamAV 1.4.3/28181/Thu Nov 12 06:27:14 2026\x00"))
				case "zSTATS":
					c.Write([]byte("POOLS: 1\n\nQUEUE: 2 items\nEND\x00"))
				}
			}()
		}
	}()
	return sock
}

func writeConfig(t *testing.T, sock string) string {
	t.Helper()
	dir := t.TempDir()
	conf := filepath.Join(dir, "clamd.conf")
	if err := os.WriteFile(conf, []byte("LocalSocket "+sock+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "agent.yaml")
	yml := "tags: [e2e]\nclamd_conf: " + conf + "\ndb_dir: " + dir + "\nfreshclam_log: " + dir + "/none.log\nscan: {summary: " + dir + "/none.json}\n"
	if err := os.WriteFile(cfg, []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestCollectDryRunThroughCLI(t *testing.T) {
	cfg := writeConfig(t, serveClamd(t))
	res := runAgent(t, fakeBin(t), nil, "collect", "--dry-run", "--config", cfg)
	if res.code != 0 {
		t.Fatalf("exit %d, stderr: %s", res.code, res.stderr)
	}
	// stdout is exactly one report and nothing else.
	dec := json.NewDecoder(strings.NewReader(res.stdout))
	dec.DisallowUnknownFields()
	var r proto.Report
	if err := dec.Decode(&r); err != nil {
		t.Fatalf("stdout is not a report: %v\n%s", err, res.stdout)
	}
	if dec.More() {
		t.Fatal("stdout has data after the report")
	}
	if r.Schema != 1 || r.Host == "" || r.AgentVersion != version.Version || len(r.Tags) != 1 {
		t.Fatalf("report: %+v", r)
	}
	if !r.Clamd.Up || r.Clamd.Version == nil || *r.Clamd.Version != "1.4.3" || r.Clamd.Queue == nil || *r.Clamd.Queue != 2 {
		t.Fatalf("clamd: %+v", r.Clamd)
	}
	if r.Services.Clamd != "active" {
		t.Fatalf("services: %+v", r.Services)
	}
	// stderr holds only JSON log lines (the missing freshclam log and databases are problems).
	lines := strings.Split(strings.TrimSpace(res.stderr), "\n")
	for _, l := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("stderr line is not JSON: %q", l)
		}
	}
	if !strings.Contains(res.stderr, "collection problem") {
		t.Fatalf("problems must be logged on stderr: %s", res.stderr)
	}
}

func TestCollectWithoutDryRunIsUsageError(t *testing.T) {
	if res := runAgent(t, fakeBin(t), nil, "collect"); res.code != 2 || res.stdout != "" {
		t.Fatalf("exit %d stdout %q", res.code, res.stdout)
	}
}

func TestVersionAndUsage(t *testing.T) {
	if res := runAgent(t, "", nil, "version"); res.code != 0 || !strings.Contains(res.stdout, version.Version) {
		t.Fatalf("version: %+v", res)
	}
	for _, args := range [][]string{nil, {"bogus"}, {"collect", "--nope"}, {"collect", "--dry-run", "extra"}} {
		if res := runAgent(t, "", nil, args...); res.code != 2 {
			t.Errorf("%v: exit %d, want 2", args, res.code)
		}
	}
	// Subcommands of later milestones are not advertised.
	if res := runAgent(t, "", nil, "bogus"); strings.Contains(res.stderr, "scan") || strings.Contains(res.stderr, "event") {
		t.Errorf("usage mentions commands that do not exist yet: %s", res.stderr)
	}
}

func TestConfigErrorsExitOne(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.yaml")
	_ = os.WriteFile(bad, []byte("intervall: 5m\n"), 0o600)
	if res := runAgent(t, fakeBin(t), nil, "collect", "--dry-run", "--config", bad); res.code != 1 || res.stdout != "" {
		t.Fatalf("unknown key: %+v", res)
	}
	if res := runAgent(t, fakeBin(t), nil, "collect", "--dry-run", "--config", filepath.Join(dir, "missing.yaml")); res.code != 1 {
		t.Fatalf("missing explicit config: %+v", res)
	}
	good := writeConfig(t, "/nonexistent/sock")
	if res := runAgent(t, fakeBin(t), []string{"CLAMFLEET_AGENT_INTERVAL=soon"}, "collect", "--dry-run", "--config", good); res.code != 1 || !strings.Contains(res.stderr, "CLAMFLEET_AGENT_INTERVAL") {
		t.Fatalf("bad env: %+v", res)
	}
	if res := runAgent(t, fakeBin(t), []string{"CLAMFLEET_AGENT_DB_DIR=relative"}, "collect", "--dry-run", "--config", good); res.code != 1 {
		t.Fatalf("relative path must fail validation: %+v", res)
	}
}

// CLAMFLEET_SERVER_* is reserved for the server and must not reach the agent's
// config, even for a name that matches an agent key.
func TestServerPrefixEnvDoesNotChangeAgent(t *testing.T) {
	cfg := writeConfig(t, serveClamd(t))
	base := runAgent(t, fakeBin(t), nil, "collect", "--dry-run", "--config", cfg)
	res := runAgent(t, fakeBin(t), []string{"CLAMFLEET_SERVER_TAGS=leak"}, "collect", "--dry-run", "--config", cfg)
	var b, r proto.Report
	if err := json.Unmarshal([]byte(base.stdout), &b); err != nil {
		t.Fatalf("baseline: %v %+v", err, base)
	}
	if err := json.Unmarshal([]byte(res.stdout), &r); err != nil {
		t.Fatalf("err=%v %+v", err, res)
	}
	if !reflect.DeepEqual(r.Tags, b.Tags) || strings.Contains(res.stderr, "CLAMFLEET_SERVER_TAGS") {
		t.Fatalf("tags=%v want %v, stderr=%q", r.Tags, b.Tags, res.stderr)
	}
}

func TestEnvOverridesConfigFile(t *testing.T) {
	cfg := writeConfig(t, serveClamd(t))
	res := runAgent(t, fakeBin(t), []string{"CLAMFLEET_AGENT_TAGS=a, b"}, "collect", "--dry-run", "--config", cfg)
	var r proto.Report
	if err := json.Unmarshal([]byte(res.stdout), &r); err != nil || len(r.Tags) != 2 || r.Tags[1] != "b" {
		t.Fatalf("err=%v tags=%v", err, r.Tags)
	}
}

func TestRunUsageAndConfigErrors(t *testing.T) {
	if res := runAgent(t, fakeBin(t), nil, "run", "extra"); res.code != 2 {
		t.Fatalf("run with an argument: %+v", res)
	}
	if res := runAgent(t, fakeBin(t), nil, "run", "--nope"); res.code != 2 {
		t.Fatalf("run with an unknown flag: %+v", res)
	}
	cfg := writeConfig(t, serveClamd(t))
	// No server configured: `run` cannot send anywhere. Exit 1 with the reason, nothing on stdout.
	res := runAgent(t, fakeBin(t), nil, "run", "--once", "--config", cfg)
	if res.code != 1 || res.stdout != "" || !strings.Contains(res.stderr, "server is required") {
		t.Fatalf("%+v", res)
	}
	// Plain http to a non-loopback host is refused before anything is sent.
	res = runAgent(t, fakeBin(t), []string{"CLAMFLEET_AGENT_SERVER=http://clamfleet.example"}, "run", "--once", "--config", cfg)
	if res.code != 1 || !strings.Contains(res.stderr, "plain http") {
		t.Fatalf("%+v", res)
	}
	// A missing token file is reported by path and fails the pass (server is a closed loopback port).
	res = runAgent(t, fakeBin(t), []string{
		"CLAMFLEET_AGENT_SERVER=https://127.0.0.1:1", "CLAMFLEET_AGENT_TOKEN_FILE=/nonexistent/token",
	}, "run", "--once", "--config", cfg)
	if res.code != 1 || !strings.Contains(res.stderr, "/nonexistent/token") || !strings.Contains(res.stderr, `"class":"token"`) {
		t.Fatalf("%+v", res)
	}
}

// The agent must stay free of the server's storage stack: SQLite, goose and
// the store packages would blow the 30 MB RSS budget of the spec (section 13)
// and widen the attack surface of every monitored host.
func TestAgentBinaryHasNoSQLite(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	deps := string(out)
	if !strings.Contains(deps, "github.com/clamfleet/clamfleet/internal/agent") {
		t.Fatalf("go list did not report the agent's dependencies (the test would be vacuous):\n%s", deps)
	}
	for _, banned := range []string{"modernc.org/", "github.com/pressly/goose", "database/sql", "clamfleet/internal/store", "clamfleet/internal/server", "clamfleet/internal/alert", "net/smtp", "clamfleet/migrations"} {
		if strings.Contains(deps, banned) {
			t.Errorf("the agent depends on %s", banned)
		}
	}
}
