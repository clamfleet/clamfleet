<!--
SPDX-License-Identifier: AGPL-3.0-only
SPDX-FileCopyrightText: The ClamFleet Authors
-->

# Detections

When ClamAV finds a virus, ClamFleet records it, shows it on the **Detections** page, and alerts the targets
that take detections (see `docs/alerts.md`). This page is the reference: how a detection gets from clamd to
the server, how to set it up and check it, what survives an outage, who is trusted with what, how long the
data lives, and what the page shows.

## Contents

1. [How a detection reaches ClamFleet](#how-a-detection-reaches-clamfleet)
2. [Set up](#set-up)
3. [Check it with an EICAR file](#check-it-with-an-eicar-file)
4. [The 30 second promise, and its conditions](#the-30-second-promise-and-its-conditions)
5. [What clamd waits for](#what-clamd-waits-for)
6. [The spool](#the-spool)
7. [The trust boundary](#the-trust-boundary)
8. [AppArmor](#apparmor)
9. [The Detections page and acknowledgement](#the-detections-page-and-acknowledgement)
10. [Collisions, "x2" and the path encoding](#collisions-x2-and-the-path-encoding)
11. [Retention and privacy](#retention-and-privacy)
12. [Troubleshooting](#troubleshooting)

## How a detection reaches ClamFleet

```
clamd finds a virus ── VirusEvent ──> /bin/sh ──> clamfleet-agent event   (runs as clamd's user)
        writes one file into the spool  (/var/lib/clamfleet/spool/events)
clamfleet-agent run  (the service, user clamfleet)  picks it up within a second
        validates it, re-encodes it, POST /v1/event  ──>  the server stores it, wakes the alert dispatcher
```

- **Only `VirusEvent`.** clamd runs the configured command for every detection, whichever way the scan was
  asked for: `clamdscan`, clamonacc through clamd, and later the agent's own scan command. Reading clamd's
  log instead would mean parsing several log formats across rotation, and paths that contain `": "`.
- **`event` only writes a file.** It never touches the network or the token: it runs as clamd's user, which
  cannot read the token and must not be able to. The agent service sends what it finds in the spool.
- **What clamd gives the command.** ClamAV 1.4.3 runs `/bin/sh -c "<VirusEvent>"` with an environment of
  exactly `PATH`, `CLAM_VIRUSEVENT_FILENAME` and `CLAM_VIRUSEVENT_VIRUSNAME`, as clamd's own user, and the
  scanning thread **waits** for it to exit and discards its exit status.
- **The file name `clamd` reports.** A path scan gives the real path. A scan that passes a file descriptor
  (`clamdscan --fdpass`) gives the path resolved through `/proc`, or `fd[N]` when that fails. A stream scan
  gives the literal text `stream`; the page then says "stream (no file path)".

## Set up

**1. The `VirusEvent` line.** Add this to `clamd.conf` (`/etc/clamav/clamd.conf` on Debian and Ubuntu,
`/etc/clamd.d/scan.conf` on the RHEL family) and restart clamd:

```
VirusEvent /usr/bin/clamfleet-agent event
```

If clamd already runs a `VirusEvent` command, keep it and call ours from it: write a wrapper script that does
what you do today and then runs `/usr/bin/clamfleet-agent event` (the two variables are in its environment).
clamd accepts one `VirusEvent` line, and the first occurrence wins. The agent reports `clamd.virus_event` as
`clamfleet` (our command), `other` (anything else, a wrapper included: it cannot look inside) or `none`; only
`none` raises the WARN reason `virusevent_missing` (server key `health.require_virus_event`, default on).

**2. Directories and groups.** The installer (milestone 6; by hand until then) creates

| Path | Owner:group | Mode | Why |
|---|---|---|---|
| `/var/lib/clamfleet/` | `clamfleet:clamav` | `0750` | clamd's group must traverse it |
| `spool/` | `clamfleet:clamav` | `2750` | setgid: subdirectories inherit the group |

and the agent service creates the rest at start: `spool/events/` (`3770`: clamd's user creates files; the
sticky bit means only the owner of a file, or the agent, can remove it), `spool/reports/` and
`spool/quarantine/` (`0700`, agent only), `spool/usage` (`0660`, the accounting file) and `spool/.lock`.
The group is `clamav` on Debian and `clamscan` on the RHEL family. The agent user (`clamfleet`) is a member of
that group, so it can read what clamd's user writes (mode `0640`, group inherited). The agent config file must be readable by
clamd's user (`0644` is fine: it holds no secret, the token is a separate file), and the **spool keys must be
set in that file**, not in the environment: `event` runs with no environment of ours and would use a different
directory from the service. The service warns when a `CLAMFLEET_AGENT_SPOOL_*` variable is set.

```yaml
spool:
  dir: /var/lib/clamfleet/spool
  max_mb: 50           # 1 to 10240: a hard cap on the real disk use of everything under dir
  max_event_days: 365  # 30 to 3650: spooled events older than this are deleted, not sent
```

**3. On a host with AppArmor** (the Debian default), install the two files of [AppArmor](#apparmor) below.
Without them clamd cannot even start `/bin/sh` for `VirusEvent`, and nothing is ever reported. RHEL 9 with
SELinux is not verified yet (milestone 6).

**4. Upgrade order: server first, then agents.** An agent from this milestone against an older server falls
back to the older ordering rule for replayed heartbeats; an older agent against this server works as before.

## Check it with an EICAR file

The EICAR test file is harmless and every scanner detects it. Build it from two halves so your editor and
your own antivirus do not react (do not save it in a repository):

```
printf '%s%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR' '-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.com
chmod 644 /tmp/eicar.com
clamdscan --no-summary /tmp/eicar.com        # exit 1: FOUND
```

Within a couple of seconds the file appears and disappears in `spool/events` and the detection is on the
Detections page. If nothing arrives:

- **clamd's journal** (`journalctl -u clamav-daemon`, `clamd@scan` on RHEL): a failed `event` writes exactly one
  JSON line there, `event not spooled: <reason>`, with the signature and the spool directory, never the path.
  The reasons: `cannot read config <file>: permission denied` (clamd's user cannot read `agent.yaml`: it is
  deliberately **not** replaced by a default directory), `spool/events is not a directory owned by the agent`,
  `spool full`, `spool busy`, an `ENOSPC` or I/O error from the disk, `timed out after 10 s`.
- **The agent's journal**: `event not sent` with a class (`network`, `unauthorized`, ...) explains a file that
  stays in the spool; `permission denied` on a spooled item means the agent user cannot read what clamd's user
  wrote (it is not in clamd's group, or the item has an odd mode); items are never quarantined for that.
- **AppArmor**: `journalctl -k | grep 'apparmor="DENIED"'` names the profile and the path. A denial for
  `/usr/bin/dash` under clamd's profile means the local include is missing; one under
  `profile="/usr/sbin/clamd"` for the agent means `Px` is missing.

## The 30 second promise, and its conditions

**An EICAR file produces an alert within 30 seconds**, under these conditions:

1. the agent service is running and the server answers ingest within 10 s;
2. the target is a webhook at the default 10 s timeout (an email target is bounded by `smtp.timeout`, default
   30 s, plus the relay's own delay);
3. that target has sent fewer than its burst limit of individual detections for this host in the current
   10 minute window (otherwise the detection arrives in the window's summary, see `docs/alerts.md`);
4. the host's disk completes the spool's fsyncs promptly.

The path: `event` exits (milliseconds) → the agent's event lane polls every second → `POST /v1/event`
(10 s request timeout) → the server stores it and wakes the dispatcher (no 5 s wait) → a worker sends (10 s
for a webhook). The bound is about 1 + 10 + 10 s. Detections younger than a minute jump ahead of an older
backlog, and the report lane is separate from the event lane, so a stuck heartbeat never holds up a
detection. The test suite measures it idle, behind a 300-event backlog, behind a held report request and
with a dead second target (`make e2e`, `cmd/clamfleet-server`'s two-process tests).

## What clamd waits for

clamd's scanning thread waits until `event` exits. `event` never waits for the network or the server. It waits
for: process start, reading the config, the usage lock (at most 2 s, then it exits with `spool busy`), one
write and two fsyncs, under a 10 s watchdog (then `timed out after 10 s`). Normally that is milliseconds.
What cannot be bounded is a `write` or `fsync` stuck in the kernel on a failing disk: a process in
uninterruptible sleep cannot be killed, so clamd waits until the kernel returns. On such a host scanning
slows down; that is the price of a durable record.

## The spool

- **Publishing an event** (`event`): create `.tmp-<id>` exclusively, `fchmod 0640`, write, `fsync`, close,
  `link()` it to its final name `<unix nanoseconds>-<event id>.json`, remove the temp name, `fsync` the
  directory. `link()`, not `rename()`: it cannot replace an existing item. A failed `fsync` is never retried
  (after a failure the page cache state is unknown). A file with two names (a crash between the link and the
  remove) is skipped by the reader and cleaned up.
- **Admission and the cap.** `spool/usage` holds the running total of real disk blocks (`st_blocks`) of
  everything under the spool, under a lock shared with the service. `event` adds the event's size under that
  lock and refuses when the total would pass `max_mb` (`spool full`): the cap is hard, and eight concurrent
  `event` processes cannot jointly exceed it. Admission never scans the directory. The service recounts the
  true usage after changes. **Heartbeats are evicted oldest first to make room; events never are**, so
  detections alone can fill the cap, and new ones are then refused with a journal line.
- **Order.** Events younger than one minute go first (newest first), then the backlog oldest first. Reports:
  the newest first, then older ones marked `replay` and paced at two per second (the server stores them as
  history only: they never change the host's state, `last_seen` or tags).
- **Delivery.** An item is deleted only after a 2xx. A network error, timeout, 5xx, 3xx, 401, 403, 404, 408
  or 429 keeps it and backs off 1 s doubling to 30 s (a fresh detection resets the event lane's backoff).
  400 and 413 move it to `spool/quarantine` (30 days or 100 files). The server deduplicates on the event id.
- **Expiry.** Events older than `max_event_days` are deleted with a log line (count and signature, no path);
  heartbeats older than 7 days are dropped; temp files older than 10 minutes are removed.
- **Memory.** The directory is read in chunks of 512 entries and the agent holds at most 256 old plus the
  fresh names, so 20,000 spooled events cost no more memory than 200.

## The trust boundary

**clamd's user and group are trusted to originate events.** `VirusEvent` is clamd's own statement, so anything
that runs as clamd can report a detection, real or not, and can fill the events share of the cap. They
**cannot**:

- read the token, the heartbeats or the quarantine;
- reach the server;
- delete or replace items they did not write (sticky bit);
- make the agent open anything outside `spool/events/`, or anything that is not a regular file;
- make the agent send anything it has not validated and re-encoded.

So the reader treats every item in `spool/events` as untrusted input. It `lstat`s the name and opens only
regular files, `O_NOFOLLOW|O_NONBLOCK`, compares the opened file's device and inode with the `lstat`
(a swap in between is detected), skips a name with several hard links and removes it after ten minutes (the
name only: the other link and its file are untouched), reads at most 64 KiB, validates every field (schema,
id matching the file name, host, a time not before 2000 and not more than 10 minutes ahead, a path of 1 to
4096 bytes of valid UTF-8 without NUL, a signature of printable ASCII, source `clamd`), and sends
`json.Marshal` of the validated struct, never the bytes it read. Before deleting or quarantining it compares
the inode again; a replaced item is left for the next pass. **A residual gap** remains between that last
check and the `unlink`, because Linux has no unlink-by-fd: only clamd's group could use it, and the worst
result is one lost, re-creatable item.

The server keeps treating `path` and `signature` as untrusted text, and a viewer sees the same paths an admin
does. **A user who can write to clamd's group can forge detections**: that is the price of letting clamd report
without credentials.

## AppArmor

Debian's clamd profile (`/etc/apparmor.d/usr.sbin.clamd`) has no exec rule and no write access to
`/var/lib/clamfleet`, so with AppArmor enforcing `VirusEvent` cannot start `/bin/sh`. Two files fix that and
keep the blast radius small (both are in `deploy/apparmor/`; the package installs them in milestone 6):

- **`usr.sbin.clamd.local`**: append to `/etc/apparmor.d/local/usr.sbin.clamd`. It allows the shell clamd uses
  (`/usr/bin/dash mrix`, inheriting clamd's profile) and one transition,
  `/usr/bin/clamfleet-agent Px -> clamfleet-agent-event`. Nothing else in clamd's profile changes, and nothing
  else may be executed.
- **`clamfleet-agent-event`**: a profile of its own for the event command, attached by name only (so `run`
  is not confined by it). It allows mapping the binary, the Go runtime's harmless reads (the host name, its own
  cgroup and mount table), `agent.yaml`, `spool/usage`, create/write/link/unlink in `spool/events/`, and
  append to clamd's log (clamd leaves it open in the processes it starts; without the rule AppArmor logs a
  `file_inherit` denial on every detection). Everything else is denied: **the token, `spool/reports` and
  `spool/quarantine`, the network, and exec of anything.**

Install and load:

```
install -m 644 deploy/apparmor/clamfleet-agent-event /etc/apparmor.d/clamfleet-agent-event
cat deploy/apparmor/usr.sbin.clamd.local >> /etc/apparmor.d/local/usr.sbin.clamd
apparmor_parser -r /etc/apparmor.d/clamfleet-agent-event /etc/apparmor.d/usr.sbin.clamd
systemctl restart clamav-daemon
```

A different `spool.dir` needs the same rules for it. One denial you will see in the kernel log is not ours:
Debian's stock clamd profile does not let clamd read `/etc/hostname`, and clamd tries on every detection
whether or not `VirusEvent` is set (`apparmor="DENIED" ... profile="/usr/sbin/clamd" name="/etc/hostname"`);
it is harmless and the profiles here do not widen clamd's for it. The profile was written and proven on Debian 13 with
ClamAV 1.4.3 by **`make e2e-apparmor`** (see `docs/testing.md`), which checks the allowed path, that the
transition really happens, and every denial named above. The plain container suite cannot test AppArmor, so
`make e2e-apparmor` is part of the milestone's acceptance. Not verified yet: RHEL 9 and SELinux.

## The Detections page and acknowledgement

**Detections** in the menu shows an open-count badge. The page lists every detection, newest first, 50 per
page ("Older"/"Newest" by id, so rows arriving meanwhile neither repeat nor skip), with filters for host,
signature (a case-insensitive substring) and state (Open by default, Acknowledged, All). There is no path
filter, so no path is ever in a URL. Columns: when it was detected (the agent's time), when it **arrived** if
that is more than a minute later ("received 3 h later, spooled"), host, signature, path, "x2", source, status.
The fleet page has a Detections column and an open total, and each host page a Detections card with its ten
newest.

**Acknowledging** records who and when and removes the detection from the open counts. It does **not** cancel
or change any alert and does not change a host's health. There is no undo and no comment. **Only admins
acknowledge**; a viewer's page contains no acknowledgement markup. Per row, the button swaps the row to
"Acknowledged by <email>" without a page load; without JavaScript it is a normal form. **"Acknowledge all N
open detections matching these filters, up to #ID"** (admins, on the Open filter) acknowledges exactly the open
detections matching the filters with an id up to the one the page was rendered with: a detection that
arrived after you loaded the page stays open, and the confirmation says how many were done and, if someone
else got there first, how many were already acknowledged. Each acknowledgement is an audit row (`event.ack`,
`event.ack.bulk`) in the same transaction as the change; audit rows hold the id, the signature and counts,
never a path.

**Paths are shown safely.** A file name can contain a right-to-left override that makes `invoice‮txt.exe`
read as `invoicexe.txt`, zero-width characters, or a line separator. The page shows every invisible or
direction-changing character (controls, format characters, U+2028 and U+2029, private use, variation selectors,
and the blank-looking fillers) as a visible, styled escape, `\u{202E}`, with its name on hover. A file that
literally has the characters `\u{202E}` in its name is shown as plain text, so the two can always be told
apart. HTML is text, never markup.

## Collisions, "x2" and the path encoding

The server stores a detection once per (host, second, path, signature). Two **different** detections that
agree on that (two infected copies in one second, or two very long paths that the agent cut to the same
length) are not merged away: the second raises the row's counter, shown as **x2**, with a receipt of its own
id, and no second alert is sent. A **retry** of an event the server already took is recognised by its id and
changes nothing. A client without ids gets the old behaviour (the natural key alone).

The agent sends the path in one encoding, so two different file names never become one string: a backslash
becomes `\\`, and every byte that is not part of valid UTF-8 becomes `\xNN` (lowercase hex). A path longer than
4096 bytes after encoding is cut on a rune boundary to at most 4093 bytes plus `...`, and the page then says
"(truncated)". The page undoes the doubling and shows `\xNN` as an escape element.

## Retention and privacy

File paths are personal data: they can name a person's files. They live in the host's spool, in
`events.path` and in detection alert payloads, and **never** in logs, audit rows, URLs or summary payloads.

| Data | Where | Rule |
|---|---|---|
| events | server | `retention.events_days` (default 365, 7 to 3650) after they **arrived**, checked daily |
| receipts, window membership, an event's alert rows | server | with the event |
| detection alert payloads (contain the path) | server | with the event, or 90 days after finishing, whichever is first |
| summaries (no paths), closed windows, `alert_log` | server | 90 days (the alert history) |
| spooled events | host | until delivered, or `spool.max_event_days` (default 365) |
| quarantine | host | 30 days or 100 files |

- `received_at` can be much later than the agent's time for an event that waited in a spool. Retention counts
  from **arrival**, so a path can live up to `spool.max_event_days` on the host plus `retention.events_days`
  on the server. Lower both if that is too long.
- **Backups** (a copy of the database file, `VACUUM INTO` from milestone 6) keep paths beyond retention:
  give them a retention that matches.
- Detections go to the server over TLS and are shown to every signed-in user.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `virusevent_missing` on a host | no `VirusEvent` line in `clamd.conf` (clamd not restarted?). `other` never raises it. |
| a detection never arrives | see "Check it" above: clamd's journal first, then the agent's, then the kernel log for AppArmor |
| `spool full` in clamd's journal | detections alone fill `spool.max_mb` (the server is unreachable for a long time, or the cap is small): fix the server, raise `max_mb`, or accept that new ones are refused |
| items stay in `spool/events` | the server is down or rejecting (see the agent's journal for the class); they wait, oldest first after the fresh ones |
| `permission denied` reading a spooled item | the agent user cannot read what clamd's user wrote: check the group of `spool/events` (setgid, `clamav`) |
| the page shows `(truncated)` | the path was over 4096 bytes after encoding |
