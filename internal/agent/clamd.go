// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// clamd.go: talks to a running clamd over its unix socket and reads its socket
// path from clamd.conf.
//
// Responsibilities: ParseLocalSocket (the clamd.conf parser, mirroring ClamAV's
// own), one-connection-per-command zPING/zVERSION/zSTATS with a capped reply,
// and turning the replies into proto.Clamd.
// Dependencies: net and the proto package only. Callers must check the clamd
// unit state first (collect.go), because connecting can start a
// socket-activated clamd.

package agent

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/clamfleet/clamfleet/internal/proto"
)

const (
	// clamdMaxReply caps what we read from the socket: a misbehaving peer
	// must not make the agent allocate without bound (spec 13: 30 MB RSS).
	clamdMaxReply = 64 << 10
	// defaultClamdTimeout is the deadline per connection (connect, send, reply).
	defaultClamdTimeout = 3 * time.Second
)

// ErrNoLocalSocket means clamd.conf gives no unix socket (missing, commented
// out, or TCP-only). The agent supports only LocalSocket (spec 6.2).
var ErrNoLocalSocket = errors.New("clamd.conf: no LocalSocket")

// ParseLocalSocket returns the LocalSocket value of a clamd.conf.
//
// It mirrors optparse() in ClamAV's common/optparser.c (read 2026-11-12), not
// the manual page, because the agent must see the socket clamd itself uses:
//   - leading blanks are skipped; empty lines and lines starting with "#" are ignored;
//   - key and value are split at the first space or TAB;
//   - the key is matched case-SENSITIVELY (strcmp): "localsocket" is an
//     unknown option to clamd, which then refuses to start, so it is not accepted here;
//   - a value starting with '"' runs to the LAST '"' on the line (no closing
//     quote, or an empty value, is an error clamd refuses to start on);
//   - '#' inside the value starts an inline comment, and trailing blanks are trimmed;
//   - LocalSocket is single-valued: the FIRST occurrence wins, later ones are ignored.
//
// Include directives do not exist in this format (A5, confirmed on Debian 13).
// Deliberately not mirrored: clamd aborts on any line with a key but no value
// or an unknown key; the agent only needs the socket, so it skips such lines.
func ParseLocalSocket(conf []byte) (string, error) {
	sc := bufio.NewScanner(bytes.NewReader(conf))
	for sc.Scan() {
		line := strings.TrimLeft(sc.Text(), " \t")
		if len(line) <= 1 || line[0] == '#' {
			continue
		}
		i := strings.IndexAny(line, " \t")
		if i < 0 || line[:i] != "LocalSocket" {
			continue
		}
		val := strings.TrimRight(strings.TrimLeft(line[i+1:], " \t"), " \t\r\n")
		if val == "" {
			continue
		}
		if val[0] == '"' {
			end := strings.LastIndexByte(val[1:], '"')
			if end <= 0 {
				return "", errors.New("clamd.conf: LocalSocket has an unterminated or empty quoted value")
			}
			val = val[1 : 1+end]
		}
		if h := strings.IndexByte(val, '#'); h >= 0 {
			val = strings.TrimRight(val[:h], " \t")
		}
		if val == "" {
			return "", ErrNoLocalSocket
		}
		return val, nil
	}
	return "", ErrNoLocalSocket
}

// clamdCommand sends one z-prefixed command on a fresh connection and
// returns the reply without its NUL terminator. One connection per command
// avoids IDSESSION state. The reply is read up to the first NUL; an EOF after
// some data is accepted too. Side effect: opens a unix socket connection,
// which on a socket-activated clamd STARTS the service, so callers must check
// the unit state first (decision Q4).
func clamdCommand(ctx context.Context, socket, cmd string, timeout time.Duration) (string, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return "", err
	}
	if _, err := io.WriteString(conn, "z"+cmd+"\x00"); err != nil {
		return "", err
	}
	// One byte over the cap proves the reply is too large.
	r := bufio.NewReader(io.LimitReader(conn, clamdMaxReply+1))
	reply, err := r.ReadString(0)
	if len(reply) > clamdMaxReply {
		return "", fmt.Errorf("reply larger than %d bytes", clamdMaxReply)
	}
	if err != nil && !(errors.Is(err, io.EOF) && reply != "") {
		if errors.Is(err, io.EOF) {
			return "", errors.New("connection closed without a reply")
		}
		return "", err
	}
	return strings.TrimRight(reply, "\x00\n"), nil
}

// describeSocketErr turns a socket error into a short operator-facing text.
func describeSocketErr(err error, socket string) string {
	var ne net.Error
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "socket " + socket + " not found"
	case errors.Is(err, fs.ErrPermission):
		return "permission denied on socket " + socket
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused on " + socket
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	}
	return err.Error()
}

// parseVersion extracts the clamd version from a VERSION reply such as
// "ClamAV 1.4.3/28181/Thu Nov 12 06:27:14 2026" (assumption A6, confirmed):
// the text before the first "/", without the "ClamAV " prefix, matching the
// bare "1.4.1" of the spec example.
func parseVersion(reply string) (string, bool) {
	head, _, _ := strings.Cut(reply, "/")
	v, ok := strings.CutPrefix(head, "ClamAV ")
	v = strings.TrimSpace(v)
	return v, ok && v != ""
}

// parseQueue sums the N of every "QUEUE: N items" line of a STATS reply: one
// line per thread pool (assumption A7; only a single pool was recorded, the
// multi-pool case is hand-made). ok is false when no such line exists.
func parseQueue(reply string) (int, bool) {
	total, found := 0, false
	for _, line := range strings.Split(reply, "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "QUEUE:")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		n, err := strconv.Atoi(fields[0])
		if err != nil || n < 0 {
			continue
		}
		total += n
		found = true
	}
	return total, found
}

// collectClamd probes clamd on socket. Up means zPING returned PONG; a failed
// VERSION or STATS leaves that field null and sets Error, but does not
// clear Up.
func collectClamd(ctx context.Context, socket string, timeout time.Duration) proto.Clamd {
	var out proto.Clamd
	fail := func(msg string) proto.Clamd {
		out.Error = &msg
		return out
	}
	pong, err := clamdCommand(ctx, socket, "PING", timeout)
	if err != nil {
		return fail("ping: " + describeSocketErr(err, socket))
	}
	if pong != "PONG" {
		return fail(fmt.Sprintf("ping: unexpected reply %q", truncate(pong, 64)))
	}
	out.Up = true

	var errs []string
	if reply, err := clamdCommand(ctx, socket, "VERSION", timeout); err != nil {
		errs = append(errs, "version: "+describeSocketErr(err, socket))
	} else if v, ok := parseVersion(reply); !ok {
		errs = append(errs, fmt.Sprintf("version: unexpected reply %q", truncate(reply, 64)))
	} else {
		out.Version = &v
	}
	if reply, err := clamdCommand(ctx, socket, "STATS", timeout); err != nil {
		errs = append(errs, "stats: "+describeSocketErr(err, socket))
	} else if q, ok := parseQueue(reply); !ok {
		errs = append(errs, "stats: no QUEUE line in reply")
	} else {
		out.Queue = &q
	}
	if len(errs) > 0 {
		msg := strings.Join(errs, "; ")
		out.Error = &msg
	}
	return out
}

// truncate shortens s to at most n bytes, on a rune boundary.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !isRuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }
