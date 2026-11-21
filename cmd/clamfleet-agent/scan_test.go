// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/proto"
)

// scanSetup writes a config with scan.paths and a PATH directory holding a fake
// systemctl (every unit active) and the given clamdscan script.
func scanSetup(t *testing.T, clamdscan string) (cfg, path, summary string) {
	t.Helper()
	path = fakeBin(t)
	if err := os.WriteFile(filepath.Join(path, "clamdscan"), []byte(clamdscan), 0o755); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	summary = filepath.Join(dir, "last_scan.json")
	cfg = filepath.Join(dir, "agent.yaml")
	body := "scan:\n  paths: [/srv/data]\n  summary: " + summary + "\n"
	if err := os.WriteFile(cfg, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return cfg, path, summary
}

// `scan` is registered, runs the clamdscan on PATH, exits with its code and writes
// the summary the report carries.
func TestScanThroughTheBinary(t *testing.T) {
	cfg, path, summary := scanSetup(t, "#!/bin/sh\nprintf '/srv/MARKER-PATH/x: Eicar-Signature FOUND\\n\\n----------- SCAN SUMMARY -----------\\nInfected files: 1\\n'\nexit 1\n")
	r := runAgent(t, path, nil, "scan", "--config", cfg)
	if r.code != 1 || r.stdout != "" {
		t.Fatalf("%+v", r)
	}
	if strings.Contains(r.stderr, "MARKER") {
		t.Fatalf("a path reached the log: %s", r.stderr)
	}
	b, err := os.ReadFile(summary)
	if err != nil {
		t.Fatal(err)
	}
	var s proto.LastScan
	if err := json.Unmarshal(b, &s); err != nil || s.Exit != 1 || s.Infected != 1 {
		t.Fatalf("%s %v", b, err)
	}
	if r := runAgent(t, path, nil, "scan", "--config", cfg, "extra"); r.code != 2 {
		t.Fatalf("a stray argument: %+v", r)
	}
	if r := runAgent(t, path, nil, "scan", "--config", filepath.Join(t.TempDir(), "none.yaml")); r.code == 0 {
		t.Fatalf("a missing config: %+v", r)
	}
}

// With the clamd unit inactive: exit 2, no summary, clamdscan never started.
func TestScanRefusesWhileClamdIsInactive(t *testing.T) {
	ran := filepath.Join(t.TempDir(), "ran")
	cfg, path, summary := scanSetup(t, "#!/bin/sh\ntouch "+ran+"\n")
	if err := os.WriteFile(filepath.Join(path, "systemctl"), []byte("#!/bin/sh\nprintf 'LoadState=loaded\\nActiveState=inactive\\n'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := runAgent(t, path, nil, "scan", "--config", cfg)
	if r.code != 2 || !strings.Contains(r.stderr, "never starts clamd") {
		t.Fatalf("%+v", r)
	}
	if _, err := os.Stat(summary); err == nil {
		t.Fatal("a summary was written")
	}
	if _, err := os.Stat(ran); err == nil {
		t.Fatal("clamdscan ran")
	}
}

// A clamdscan that prints one million OK lines keeps the agent's memory bounded
// (VmHWM below 30 MB, the M5 figure), read while the agent is still alive.
func TestScanMemoryStaysBoundedOnAMillionLines(t *testing.T) {
	cfg, path, _ := scanSetup(t, "#!/bin/sh\nawk 'BEGIN{for(i=0;i<1000000;i++) printf \"/srv/data/some/directory/file-%d.bin: OK\\n\", i}'\nsleep 3\nexit 0\n")
	cmd := exec.Command(binary, "scan", "--config", cfg)
	cmd.Env = []string{"PATH=" + path + ":" + os.Getenv("PATH")}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var hwm int64
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) && hwm == 0 {
		time.Sleep(500 * time.Millisecond) // the lines are out after about a second; clamdscan then sleeps
		b, err := os.ReadFile("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/status")
		if err != nil {
			break
		}
		for _, l := range strings.Split(string(b), "\n") {
			if f := strings.Fields(l); len(f) >= 2 && f[0] == "VmHWM:" {
				hwm, _ = strconv.ParseInt(f[1], 10, 64)
			}
		}
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	if hwm == 0 {
		t.Fatal("could not read VmHWM while the agent was running")
	}
	if hwm > 30*1024 {
		t.Fatalf("VmHWM %d kB: the scan wrapper is not bounded", hwm)
	}
}
