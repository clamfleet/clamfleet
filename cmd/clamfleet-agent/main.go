// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Command clamfleet-agent reports ClamAV health to a ClamFleet server.
//
// Milestone 1 registers only "collect --dry-run" and "version". The other
// subcommands of the spec (run, event, scan) are added by the milestones that
// implement them, so the usage text never advertises something that does not
// exist.
//
// Output contract: the report JSON goes to stdout and nothing else does, so
// "clamfleet-agent collect --dry-run | jq" works. Logs and collection
// problems go to stderr as slog JSON lines.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/clamfleet/clamfleet/internal/agent"
	"github.com/clamfleet/clamfleet/internal/config"
	"github.com/clamfleet/clamfleet/internal/version"
)

// Exit codes: 0 report produced (even a degraded one), 1 configuration or
// runtime error, 2 usage error.
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

const usage = `usage: clamfleet-agent <command>

commands:
  collect --dry-run [--config FILE]   print the report JSON, send nothing
  version                             print the agent version
`

// run is main without os.Exit, so it can be tested.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	switch args[0] {
	case "version":
		fmt.Fprintf(stdout, "clamfleet-agent %s\n", version.Version)
		return exitOK
	case "collect":
		return runCollect(ctx, args[1:], stdout, stderr)
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usage)
		return exitOK
	default:
		fmt.Fprintf(stderr, "clamfleet-agent: unknown command %q\n\n%s", args[0], usage)
		return exitUsage
	}
}

func runCollect(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("collect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dry := fs.Bool("dry-run", false, "print the report as JSON and send nothing")
	cfgFlag := fs.String("config", "", "config file (default: $CLAMFLEET_AGENT_CONFIG or "+agent.DefaultConfigPath+")")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "collect: unexpected argument %q\n", fs.Arg(0))
		return exitUsage
	}
	if !*dry {
		// Sending arrives with Milestone 2; refusing is safer than silently doing nothing.
		fmt.Fprintln(stderr, "collect: only --dry-run is available in this version")
		return exitUsage
	}

	log := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	path, explicit := config.ResolvePath(agent.EnvPrefix, *cfgFlag, agent.DefaultConfigPath, nil)
	cfg, warnings, err := agent.LoadConfig(path, explicit, config.Options{})
	for _, w := range warnings {
		log.Warn(w)
	}
	if err == nil {
		err = cfg.Validate()
	}
	if err != nil {
		log.Error("invalid configuration", "error", err.Error())
		return exitError
	}

	c := &agent.Collector{
		Cfg:            cfg,
		Version:        version.Version,
		Now:            time.Now,
		Loc:            time.Local,
		Exec:           agent.RealExec,
		Hostname:       os.Hostname,
		OSReleasePaths: agent.DefaultOSReleasePaths,
	}
	report, problems, err := c.Collect(ctx)
	if err != nil {
		log.Error("collect failed", "error", err.Error())
		return exitError
	}
	for _, p := range problems {
		log.Warn("collection problem", "source", p.Source, "error", p.Err.Error())
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		log.Error("cannot write report", "error", err.Error())
		return exitError
	}
	return exitOK
}
