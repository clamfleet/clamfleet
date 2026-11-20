#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# packages_test.sh - the maintainer scripts of deploy/packaging/scripts, run under sh with
# stub commands (no systemd, no SELinux, no AppArmor, no root, no container). `make
# scripts-test` runs it. The real install, upgrade and removal on Debian 13 and AlmaLinux 9
# is `make e2e` and `make e2e-el9`; this test is what catches an argument convention or an
# ordering mistake in seconds.
#
# How it works. Each script starts with plain path assignments (ETC_DIR=/etc/clamfleet ...),
# not environment overrides. For a test, a COPY of the script is made with those lines
# rewritten to point into a temporary directory, and PATH holds stubs that log their
# arguments to calls.log and keep a little state (enabled units, loaded SELinux modules
# with their priority, the files they create). The stubs behave like the real tools where
# it matters: `semodule -r` without `-X 300` removes only priority 400, so the bug the test
# for the rpm removal pins (a module left loaded) is real.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
src="$here/../packaging/scripts"
fails=0
fail() { echo "packages_test: FAIL: $*" >&2; fails=$((fails + 1)); }
ok() { :; }

# new_env: a fresh sandbox in $T with the stubs and rewritten copies of the scripts.
new_env() {
	T="$(mktemp -d)"
	mkdir -p "$T/bin" "$T/etc" "$T/var/agent" "$T/var/server" "$T/run/systemd/system" "$T/usr/lib/sysusers.d" "$T/usr/lib/tmpfiles.d" "$T/apparmor.d" "$T/selinux" "$T/state"
	: >"$T/calls.log"
	: >"$T/enabled"
	: >"$T/modules"
	echo clamav >"$T/users"
	echo "ok" >"$T/aa-enabled.state"   # "ok": aa-enabled succeeds; "no": it fails
	echo "yes" >"$T/selinux.state"     # selinuxenabled: yes | no
	: >"$T/agent.yaml.placeholder"
	for scr in agent-postinstall agent-preremove agent-postremove server-postinstall server-preremove server-postremove; do
		sed -E \
			-e "s#^ETC_DIR=.*#ETC_DIR=$T/etc#" \
			-e "s#^STATE_DIR=/var/lib/clamfleet-server#STATE_DIR=$T/var/server#" \
			-e "s#^STATE_DIR=/var/lib/clamfleet\$#STATE_DIR=$T/var/agent#" \
			-e "s#^KEY_FILE=.*#KEY_FILE=$T/etc/server-secret.key#" \
			-e "s#^SYSUSERS=.*#SYSUSERS=$T/usr/lib/sysusers.d/x.conf#" \
			-e "s#^TMPFILES=.*#TMPFILES=$T/usr/lib/tmpfiles.d/x.conf#" \
			-e "s#^APPARMOR_PROFILE=.*#APPARMOR_PROFILE=$T/apparmor.d/clamfleet-agent-event#" \
			-e "s#^SELINUX_MODULE=.*#SELINUX_MODULE=$T/selinux/clamfleet.cil#" \
			-e "s#^SD_RUN=.*#SD_RUN=$T/run/systemd/system#" \
			-e "s#^MOUNTINFO=.*#MOUNTINFO=$T/mountinfo#" \
			-e "s#^SERVER_BIN=.*#SERVER_BIN=$T/bin/clamfleet-server#" \
			"$src/$scr.sh" >"$T/$scr.sh"
	done
	# A mount table with the lines the purge must not trip over (field 5 is the mount point).
	printf '%s\n' '24 1 8:1 / / rw - ext4 /dev/sda1 rw' '31 24 0:27 / /var/lib rw - tmpfs tmpfs rw' >"$T/mountinfo"
	: >"$T/apparmor.d/clamfleet-agent-event"
	cat >"$T/bin/log" <<'STUB'
#!/bin/sh
printf '%s\n' "$*" >>"$T/calls.log"
STUB
	# A generic logging stub, then the ones with behaviour.
	for c in systemd-tmpfiles restorecon chmod; do
		printf '#!/bin/sh\nprintf "%%s %%s\\n" "%s" "$*" >>"$T/calls.log"\n' "$c" >"$T/bin/$c"
	done
	cat >"$T/bin/systemd-sysusers" <<'STUB'
#!/bin/sh
echo "systemd-sysusers $*" >>"$T/calls.log"
# Fail once when asked to (the failed-install recovery test).
if [ -e "$T/fail-sysusers-once" ]; then rm -f "$T/fail-sysusers-once"; echo "sysusers: injected failure" >&2; exit 1; fi
touch "$T/state/sysusers-done"
STUB
	cat >"$T/bin/systemctl" <<'STUB'
#!/bin/sh
echo "systemctl $*" >>"$T/calls.log"
case "$1" in
enable) shift; for u in "$@"; do grep -qx "$u" "$T/enabled" || echo "$u" >>"$T/enabled"; done ;;
disable) shift; for u in "$@"; do grep -vx "$u" "$T/enabled" >"$T/enabled.new"; mv "$T/enabled.new" "$T/enabled"; done ;;
esac
exit 0
STUB
	cat >"$T/bin/apparmor_parser" <<'STUB'
#!/bin/sh
echo "apparmor_parser $*" >>"$T/calls.log"
case "$1" in -r) touch "$T/state/profile-loaded" ;; -R) rm -f "$T/state/profile-loaded" ;; esac
STUB
	cat >"$T/bin/aa-enabled" <<'STUB'
#!/bin/sh
[ "$(cat "$T/aa-enabled.state")" = ok ]
STUB
	cat >"$T/bin/selinuxenabled" <<'STUB'
#!/bin/sh
[ "$(cat "$T/selinux.state")" = yes ]
STUB
	cat >"$T/bin/semodule" <<'STUB'
#!/bin/sh
# Like the real tool: -X N is the priority (default 400); -r removes only at that priority.
echo "semodule $*" >>"$T/calls.log"
prio=400; mode=; name=
while [ $# -gt 0 ]; do
	case "$1" in
	-X) prio=$2; shift ;;
	-i) mode=i; name=$(basename "$2" .cil) ;;
	-r) mode=r; name=$2; shift ;;
	-l) mode=l ;;
	esac
	shift
done
case "$mode" in
i) grep -vx "$name $prio" "$T/modules" >"$T/modules.new"; echo "$name $prio" >>"$T/modules.new"; mv "$T/modules.new" "$T/modules" ;;
r) grep -vx "$name $prio" "$T/modules" >"$T/modules.new"; mv "$T/modules.new" "$T/modules" ;;
l) awk '{print $1}' "$T/modules" | sort -u ;;
esac
STUB
	cat >"$T/bin/runuser" <<'STUB'
#!/bin/sh
echo "runuser $*" >>"$T/calls.log"
[ ! -e "$T/runuser-fails" ] || exit 1
# runuser -u USER -- test -r FILE
shift 3
exec "$@"
STUB
	cat >"$T/bin/id" <<'STUB'
#!/bin/sh
# id -u NAME: exists when listed in $T/users
[ "$1" = -u ] && grep -qx "$2" "$T/users"
STUB
	cat >"$T/bin/clamfleet-server" <<'STUB'
#!/bin/sh
echo "clamfleet-server $*" >>"$T/calls.log"
# key generate --file PATH
if [ "$1 $2" = "key generate" ]; then echo "key-material" >"$4"; fi
STUB
	cat >"$T/bin/chgrp" <<'STUB'
#!/bin/sh
echo "chgrp $*" >>"$T/calls.log"
STUB
	chmod +x "$T"/bin/*
	: >"$T/etc/server.yaml"
	: >"$T/etc/agent.yaml"
	export T
	# A PATH of the stubs and a few basic tools only: a real aa-enabled, semodule or systemctl of the
	# developer machine must never leak in (a test of "aa-enabled is not installed" needs it absent).
	mkdir -p "$T/tools"
	for t in sh dash bash dirname basename grep sed awk find stat rm rmdir cat mkdir touch sort mv ls tr head test; do
		p="$(command -v "$t" 2>/dev/null || true)"
		case "$p" in /*) ln -sf "$p" "$T/tools/$t" ;; esac
	done
	ln -sf /usr/bin/test "$T/tools/test" # a shell builtin, so `command -v` gave no path above
	SCRIPT_PATH="$T/bin:$T/tools"
}
run() { # run SCRIPT ARGS... ; captures stdout/stderr in $T/out, status in $rc
	local name=$1; shift
	PATH="$SCRIPT_PATH" "$T/tools/sh" "$T/$name.sh" "$@" >"$T/out" 2>&1
	rc=$?
}
calls() { cat "$T/calls.log"; }
has_call() { grep -qE -- "$1" "$T/calls.log"; }
count_calls() { grep -cE -- "$1" "$T/calls.log" || true; }
expect() { # expect "name" command...
	local name=$1; shift
	if ! "$@"; then fail "$name"; echo "---- calls:" >&2; calls >&2; echo "---- output:" >&2; cat "$T/out" >&2 2>/dev/null; fi
}
snapshot() { # a stable description of everything the scripts can change
	(cd "$T" && { find etc var state -printf '%p %y %m\n' 2>/dev/null | sort; cat enabled modules 2>/dev/null | sort; })
}
cleanup() { rm -rf "$T"; }

# ---------------------------------------------------------------- agent, deb
new_env
run agent-postinstall configure ""
expect "agent deb first install: exit 0" test "$rc" -eq 0
expect "agent deb first install: sysusers and tmpfiles on our files" has_call "systemd-sysusers .*usr/lib/sysusers.d/x.conf"
expect "agent deb first install: tmpfiles --create" has_call "systemd-tmpfiles --create"
expect "agent deb first install: daemon-reload" has_call "^systemctl daemon-reload"
expect "agent deb first install: the AppArmor profile is loaded" has_call "apparmor_parser -r -W .*clamfleet-agent-event"
expect "agent deb first install: enabled and started" bash -c "has_call() { grep -qE -- \"\$1\" '$T/calls.log'; }; has_call '^systemctl enable clamfleet-agent.service' && has_call '^systemctl start clamfleet-agent.service'"
expect "agent deb first install: no SELinux call" test "$(count_calls '^semodule')" -eq 0
expect "agent deb first install: the notice names the VirusEvent line" grep -q "VirusEvent /usr/bin/clamfleet-agent event" "$T/out"
expect "agent deb first install: the notice names EnableVersionCommand and EnableStatsCommand" bash -c "grep -q EnableVersionCommand '$T/out' && grep -q EnableStatsCommand '$T/out'"
# The notice prints the two AppArmor lines itself: a minimized Ubuntu image drops /usr/share/doc, so a
# pointer to a file there leaves the administrator with nothing. The lines are compared with the shipped
# include, so the notice cannot drift from it.
expect "agent deb first install: the notice prints every rule of the AppArmor include" bash -c "n=0; while IFS= read -r l; do n=\$((n+1)); grep -qxF -- \"       \$l\" '$T/out' || exit 1; done < <(grep -v '^#' '$here/../apparmor/usr.sbin.clamd.local' | grep -v '^\$'); test \$n -eq 2"
expect "agent deb first install: the notice does not send the administrator to /usr/share/doc" bash -c "! grep -q 'usr/share/doc/clamfleet-agent/usr.sbin' '$T/out'"
# Rule: the agent package puts nothing but README and LICENSE under /usr/share/doc (dpkg excludes it on
# minimized Ubuntu images). Examples and the include live in /usr/share/clamfleet-agent.
expect "agent package: only README and LICENSE under /usr/share/doc" bash -c "! grep -E 'dst: /usr/share/doc/' '$here/../packaging/nfpm-agent.yaml' | grep -vE '/(README.md|LICENSE)\$'"
expect "server package: only README and LICENSE under /usr/share/doc" bash -c "! grep -E 'dst: /usr/share/doc/' '$here/../packaging/nfpm-server.yaml' | grep -vE '/(README.md|LICENSE)\$'"
expect "server package: the example is packaged under /usr/share/clamfleet-server" bash -c "grep -qE 'dst: /usr/share/clamfleet-server/server.yaml.example\$' '$here/../packaging/nfpm-server.yaml'"
expect "agent package: the include and the examples are packaged under /usr/share/clamfleet-agent" bash -c "n=\$(grep -cE 'dst: /usr/share/clamfleet-agent/(usr.sbin.clamd.local|agent.yaml.example|agent.rhel9.yaml.example)\$' '$here/../packaging/nfpm-agent.yaml'); test \$n -eq 3"
expect "agent deb first install: the scan timer is NOT enabled" bash -c "! grep -q 'clamfleet-scan.timer' '$T/enabled'"
cleanup

# upgrade: try-restart, no enable
new_env
run agent-postinstall configure 0.5.0
expect "agent deb upgrade: exit 0" test "$rc" -eq 0
expect "agent deb upgrade: try-restart" has_call "^systemctl try-restart clamfleet-agent.service"
expect "agent deb upgrade: nothing enabled or started" test "$(count_calls '^systemctl (enable|start|preset)')" -eq 0
expect "agent deb upgrade: no first-install notice" bash -c "! grep -q 'Next steps' '$T/out'"
cleanup

# AppArmor not enabled: no apparmor_parser call, the script still succeeds
new_env
echo no >"$T/aa-enabled.state"
run agent-postinstall configure ""
expect "agent deb without AppArmor: exit 0" test "$rc" -eq 0
expect "agent deb without AppArmor: no apparmor_parser call" test "$(count_calls '^apparmor_parser')" -eq 0
cleanup
new_env
rm "$T/bin/aa-enabled" # the tool is not even installed
run agent-postinstall configure ""
expect "agent deb with no aa-enabled binary: exit 0, no parser call" bash -c "test $rc -eq 0 && test \$(grep -c '^apparmor_parser' '$T/calls.log') -eq 0"
cleanup

# no systemd running (a chroot or an image build): enable still happens, nothing runtime is attempted
new_env
rmdir "$T/run/systemd/system"
run agent-postinstall configure ""
expect "agent deb in a chroot: exit 0" test "$rc" -eq 0
expect "agent deb in a chroot: enable yes, daemon-reload and start no" bash -c "grep -q '^systemctl enable clamfleet-agent.service' '$T/calls.log' && ! grep -qE '^systemctl (daemon-reload|start|try-restart)' '$T/calls.log'"
cleanup

# readability warning
new_env
touch "$T/runuser-fails"
run agent-postinstall configure ""
expect "agent: the agent.yaml readability warning appears when clamd's user cannot read it" grep -q "WARNING.*agent.yaml is not readable by clamav" "$T/out"
expect "agent: the warning does not fail the install" test "$rc" -eq 0
cleanup
new_env
run agent-postinstall configure ""
expect "agent: no warning when clamd's user can read the config" bash -c "! grep -q WARNING '$T/out'"
cleanup

# ---------------------------------------------------------------- agent, rpm
new_env
echo clamscan >"$T/users"
run agent-postinstall 1
expect "agent rpm install: exit 0" test "$rc" -eq 0
expect "agent rpm install: semodule -X 300 -i" has_call "^semodule -X 300 -i .*clamfleet.cil"
expect "agent rpm install: restorecon of the state directory" has_call "^restorecon -R .*var/agent"
expect "agent rpm install: preset, not enable or start" bash -c "grep -q '^systemctl preset clamfleet-agent.service' '$T/calls.log' && ! grep -qE '^systemctl (enable|start)' '$T/calls.log'"
expect "agent rpm install: no AppArmor call" test "$(count_calls '^apparmor_parser')" -eq 0
expect "agent rpm install: the module is loaded at priority 300" grep -qx "clamfleet 300" "$T/modules"
expect "agent rpm install: the readability check uses clamscan" has_call "^runuser -u clamscan"
cleanup

# EL9 and EL10 with the extra package: `antivirus` is loaded, so no notice.
new_env
echo clamscan >"$T/users"; echo "antivirus 100" >"$T/modules"
run agent-postinstall 1
expect "agent rpm with antivirus loaded: exit 0" test "$rc" -eq 0
expect "agent rpm with antivirus loaded: no notice" bash -c "! grep -q 'NOTICE: the SELinux module' '$T/out'"
cleanup

# Stock EL10: no `antivirus`. One notice, after the module load, naming the package; install still succeeds.
new_env
echo clamscan >"$T/users"
run agent-postinstall 1
expect "agent rpm without antivirus: exit 0" test "$rc" -eq 0
expect "agent rpm without antivirus: exactly one notice naming selinux-policy-targeted-extra" bash -c "test \$(grep -c 'NOTICE: the SELinux module' '$T/out') -eq 1 && grep 'NOTICE: the SELinux module' '$T/out' | grep -q selinux-policy-targeted-extra"
expect "agent rpm without antivirus: the module is still loaded at 300" grep -qx "clamfleet 300" "$T/modules"
expect "agent rpm without antivirus: semodule -l is asked after the module load" bash -c "test \$(grep -n '^semodule -X 300 -i' '$T/calls.log' | cut -d: -f1) -lt \$(grep -n '^semodule -l' '$T/calls.log' | cut -d: -f1)"
# Exact, not a flag regex: a regex on "-r"/"-d"/"-e" misses forms like `semodule -d antivirus`.
# The only semodule calls allowed are the priority-300 install and then the read-only list.
expect "agent rpm without antivirus: the only semodule calls are the install at 300 and -l" bash -c "grep '^semodule' '$T/calls.log' | sed -e 's# -i .*clamfleet.cil\$# -i CIL#' | paste -sd'|' | grep -qx 'semodule -X 300 -i CIL|semodule -l'"
expect "agent rpm without antivirus: no other module appeared" test "$(wc -l <"$T/modules")" -eq 1
cleanup

# `antivirus_local` is not `antivirus`: the anchor after the name must not accept a longer module name.
new_env
echo clamscan >"$T/users"; echo "antivirus_local 400" >"$T/modules"
run agent-postinstall 1
expect "agent rpm with only antivirus_local loaded: the notice is printed" bash -c "test \$(grep -c 'NOTICE: the SELinux module' '$T/out') -eq 1"
cleanup

# The notice must never fail the install: a semodule -l that errors prints nothing and exits 0.
new_env
echo clamscan >"$T/users"
mv "$T/bin/semodule" "$T/bin/semodule.real"
cat >"$T/bin/semodule" <<'STUB'
#!/bin/sh
echo "semodule $*" >>"$T/calls.log"
for a in "$@"; do [ "$a" = -l ] && exit 1; done
exit 0
STUB
chmod +x "$T/bin/semodule"
run agent-postinstall 1
expect "agent rpm with a failing semodule -l: exit 0, no notice" bash -c "test $rc -eq 0 && ! grep -q 'NOTICE: the SELinux module' '$T/out'"
cleanup

# SELinux disabled: no semodule
new_env
echo clamscan >"$T/users"; echo no >"$T/selinux.state"
run agent-postinstall 1
expect "agent rpm without SELinux: exit 0 and no semodule" bash -c "test $rc -eq 0 && test \$(grep -c '^semodule' '$T/calls.log') -eq 0"
cleanup

# THE RPM UPGRADE ORDER: new %post (2), then the OLD %preun and %postun with 1.
new_env
echo clamscan >"$T/users"
run agent-postinstall 1
echo "clamfleet 300" >"$T/modules"
: >"$T/calls.log"
run agent-postinstall 2
expect "agent rpm upgrade: new post exit 0" test "$rc" -eq 0
run agent-preremove 1
expect "agent rpm upgrade: old preun exit 0" test "$rc" -eq 0
run agent-postremove 1
expect "agent rpm upgrade: old postun exit 0" test "$rc" -eq 0
expect "agent rpm upgrade: the module is still loaded at 300" grep -qx "clamfleet 300" "$T/modules"
expect "agent rpm upgrade: no semodule -r and no profile unload" test "$(count_calls '^(semodule .*-r|apparmor_parser -R)')" -eq 0
expect "agent rpm upgrade: the service is restarted exactly once" test "$(count_calls '^systemctl try-restart clamfleet-agent.service')" -eq 1
expect "agent rpm upgrade: nothing stopped or disabled" test "$(count_calls '^systemctl (stop|disable)')" -eq 0
cleanup

# rpm removal (0): stop, disable, and the module is gone at priority 300
new_env
echo clamscan >"$T/users"
echo "clamfleet 300" >"$T/modules"
echo clamfleet-agent.service >"$T/enabled"
run agent-preremove 0
expect "agent rpm removal: preun stops and disables" bash -c "grep -q '^systemctl stop .*clamfleet-agent.service' '$T/calls.log' && grep -q '^systemctl disable .*clamfleet-agent.service' '$T/calls.log'"
run agent-postremove 0
expect "agent rpm removal: semodule -X 300 -r clamfleet" has_call "^semodule -X 300 -r clamfleet"
expect "agent rpm removal: no module left at ANY priority" bash -c "! grep -q clamfleet '$T/modules'"
cleanup
# with the module only at the DEFAULT priority a -X 300 removal would not remove it; the
# stub must really tell the two apart, or the assertion above proves nothing.
new_env
echo "clamfleet 400" >"$T/modules"
"$T/bin/semodule" -X 300 -r clamfleet
expect "the semodule stub keeps a module of another priority (the stub is faithful)" grep -qx "clamfleet 400" "$T/modules"
cleanup

# ---------------------------------------------------------------- agent, deb remove and purge
new_env
mkdir -p "$T/var/agent/spool/events"; echo x >"$T/var/agent/spool/events/e.json"; echo ok >"$T/state/profile-loaded"
run agent-preremove remove
expect "agent deb remove: stops and disables" has_call "^systemctl disable clamfleet-scan.timer clamfleet-agent.service"
run agent-postremove remove
expect "agent deb remove: the profile is unloaded" has_call "^apparmor_parser -R .*clamfleet-agent-event"
expect "agent deb remove: the state directory stays until purge" test -e "$T/var/agent/spool/events/e.json"
run agent-postremove purge
expect "agent deb purge: the spool and state are removed" test ! -e "$T/var/agent"
cleanup
new_env
run agent-preremove upgrade
expect "agent deb upgrade preremove: nothing" test "$(count_calls '^systemctl')" -eq 0
run agent-postremove upgrade
expect "agent deb upgrade postremove: nothing" test "$(count_calls '^(systemctl|apparmor_parser|semodule)')" -eq 0
cleanup

# PURGE SAFETY: a symlinked state directory loses only the link
new_env
mkdir -p "$T/precious"; echo keep >"$T/precious/marker"
rmdir "$T/var/agent" 2>/dev/null || rm -rf "$T/var/agent"
ln -s "$T/precious" "$T/var/agent"
run agent-postremove purge
expect "purge safety: the symlink is removed" test ! -e "$T/var/agent" -a ! -L "$T/var/agent"
expect "purge safety: the target and its marker survive" test -f "$T/precious/marker"
cleanup
# a symlink INSIDE the state directory is removed, never followed
new_env
mkdir -p "$T/precious"; echo keep >"$T/precious/marker"
mkdir -p "$T/var/agent/spool"; ln -s "$T/precious" "$T/var/agent/spool/link"; echo x >"$T/var/agent/last_scan.json"
run agent-postremove purge
expect "purge safety: an inner symlink is removed without touching its target" test -f "$T/precious/marker"
expect "purge safety: the rest is removed" test ! -e "$T/var/agent"
cleanup
# A mount point below the state directory (a line in the mount table): NOTHING is removed, and the
# notice says which mount. The marker inside it and everything beside it survive.
new_env
mkdir -p "$T/var/agent/spool/events" "$T/var/agent/spool/quarantine"
echo keep >"$T/var/agent/spool/events/marker"; echo stays >"$T/var/agent/spool/quarantine/q"; echo stays >"$T/var/agent/last_scan.json"
echo "40 24 0:35 / $T/var/agent/spool/events rw - tmpfs tmpfs rw" >>"$T/mountinfo"
run agent-postremove purge
expect "purge across a mount: exit 0" test "$rc" -eq 0
expect "purge across a mount: the marker inside the mount survives" test -f "$T/var/agent/spool/events/marker"
expect "purge across a mount: the notice names the mount" grep -q "spool/events" "$T/out"
expect "purge across a mount: nothing at all is removed" bash -c "test -f '$T/var/agent/last_scan.json' && test -f '$T/var/agent/spool/quarantine/q'"
cleanup
# The state directory itself being a mount point: kept.
new_env
echo x >"$T/var/agent/last_scan.json"
echo "41 24 0:36 / $T/var/agent rw - ext4 /dev/sdb1 rw" >>"$T/mountinfo"
run agent-postremove purge
expect "purge of a mounted state directory: kept" test -f "$T/var/agent/last_scan.json"
cleanup
# A mount elsewhere that merely shares a prefix (/var/agent2) is not below the directory.
new_env
echo x >"$T/var/agent/last_scan.json"
echo "42 24 0:37 / $T/var/agent2 rw - ext4 /dev/sdb1 rw" >>"$T/mountinfo"
run agent-postremove purge
expect "purge: a sibling mount with the same prefix does not block it" test ! -e "$T/var/agent"
cleanup

# THE RACE: the purge must never check a path and then act on it in a second step (a glob loop that
# tests -d and then expands "$entry"/* can be raced into deleting what a swapped-in symlink points at).
# It is ONE rm walk: the recorded rm calls are exactly one, rm -rf --one-file-system -- STATE_DIR, and the
# purge branch of the script contains no glob.
new_env
mkdir -p "$T/var/agent/spool/events"; echo x >"$T/var/agent/spool/events/e.json"
cat >"$T/bin/rm" <<'STUB'
#!/bin/sh
echo "rm $*" >>"$T/calls.log"
exec /usr/bin/rm "$@"
STUB
chmod +x "$T/bin/rm"
run agent-postremove purge
expect "purge: exactly one rm, a single --one-file-system walk" bash -c "test \$(grep -c '^rm ' '$T/calls.log') -eq 1 && grep -qx 'rm -rf --one-file-system -- $T/var/agent' '$T/calls.log'"
expect "purge: the state directory is gone" test ! -e "$T/var/agent"
cleanup
new_env
sed -n '/^\tpurge)/,/^\t\t;;/p' "$src/agent-postremove.sh" | sed 's/#.*$//' >"$T/purge-branch"
expect "purge: the purge branch was extracted (an empty extract would pass the glob check)" test -s "$T/purge-branch"
expect "purge: the purge branch uses no shell glob" bash -c "! grep -E '/\*|\.\[|\*\.' '$T/purge-branch'"
expect "purge: the script has no per-entry loop (no check-then-use)" bash -c "! grep -E 'for entry|purge_tree|is_mount' '$src/agent-postremove.sh'"
cleanup

# ---------------------------------------------------------------- idempotence and recovery
for case in "agent-postinstall configure ''" "agent-postinstall configure 0.5.0" "agent-postinstall 1" "agent-postinstall 2" "server-postinstall configure ''" "server-postinstall 1" "server-postinstall 2"; do
	new_env
	[[ $case == *" 1" || $case == *" 2" ]] && echo clamscan >"$T/users"
	eval "run $case"
	first=$(snapshot); rc1=$rc
	eval "run $case"
	second=$(snapshot)
	expect "idempotent: '$case' exits 0 twice" test "$rc1" -eq 0 -a "$rc" -eq 0
	expect "idempotent: '$case' second run changes nothing" test "$first" = "$second"
	cleanup
done

# failed-install recovery: sysusers fails once, the script exits non-zero, a second run completes
# and the outcome equals a clean first run.
for s in agent server; do
	new_env
	run $s-postinstall configure ""
	clean=$(snapshot)
	cleanup
	new_env
	touch "$T/fail-sysusers-once"
	run $s-postinstall configure ""
	expect "recovery ($s): the failing step makes the script exit non-zero" test "$rc" -ne 0
	run $s-postinstall configure ""
	expect "recovery ($s): the second run completes" test "$rc" -eq 0
	expect "recovery ($s): the outcome equals a clean first run" test "$(snapshot)" = "$clean"
	cleanup
done

# ---------------------------------------------------------------- server
new_env
run server-postinstall configure ""
expect "server deb first install: exit 0" test "$rc" -eq 0
expect "server deb first install: sysusers, tmpfiles, daemon-reload" bash -c "grep -q '^systemd-sysusers' '$T/calls.log' && grep -q '^systemd-tmpfiles --create' '$T/calls.log' && grep -q '^systemctl daemon-reload' '$T/calls.log'"
expect "server deb first install: the key is generated" has_call "^clamfleet-server key generate --file .*server-secret.key"
expect "server deb first install: the key file is given to the server group, mode 0640" bash -c "grep -q '^chgrp clamfleet-server .*server-secret.key' '$T/calls.log' && grep -q '^chmod 0640 .*server-secret.key' '$T/calls.log'"
expect "server deb first install: the configuration is given to the server group" has_call "^chgrp clamfleet-server .*server.yaml"
expect "server deb first install: enabled and started" bash -c "grep -q '^systemctl enable clamfleet-server.service' '$T/calls.log' && grep -q '^systemctl start clamfleet-server.service' '$T/calls.log'"
expect "server deb first install: the notice does not send the administrator to a /usr/share/doc example" bash -c "! grep -q 'doc/clamfleet-server/server.yaml' '$T/out'"
expect "server deb first install: the backup timer is NOT enabled" bash -c "! grep -q backup '$T/enabled'"
cleanup

# the key is generated only when absent, and only on a first install
new_env
echo "existing-key" >"$T/etc/server-secret.key"
run server-postinstall configure ""
expect "server first install with a key already present: not replaced" bash -c "test \"\$(cat '$T/etc/server-secret.key')\" = existing-key && ! grep -q 'key generate' '$T/calls.log'"
cleanup
new_env
run server-postinstall configure 0.5.0
expect "server deb upgrade: no key generate even when the key is absent" test "$(count_calls 'key generate')" -eq 0
expect "server deb upgrade: try-restart, no enable" bash -c "grep -q '^systemctl try-restart clamfleet-server.service' '$T/calls.log' && ! grep -qE '^systemctl (enable|start)' '$T/calls.log'"
cleanup

new_env
run server-postinstall 1
expect "server rpm install: preset, not enable or start" bash -c "grep -q '^systemctl preset clamfleet-server.service' '$T/calls.log' && ! grep -qE '^systemctl (enable|start)' '$T/calls.log'"
expect "server rpm install: the key is generated" has_call "key generate"
cleanup
new_env
run server-postinstall 2
run server-preremove 1
run server-postremove 1
expect "server rpm upgrade order: restarted once, nothing stopped, disabled or removed" bash -c "test \$(grep -c '^systemctl try-restart clamfleet-server.service' '$T/calls.log') -eq 1 && ! grep -qE '^systemctl (stop|disable)' '$T/calls.log'"
cleanup

# removal and purge: the units stop, the database and the key file are KEPT
new_env
echo "db" >"$T/var/server/clamfleet.db"; echo "key" >"$T/etc/server-secret.key"
echo clamfleet-server.service >"$T/enabled"
run server-preremove remove
expect "server deb remove: stops and disables" bash -c "grep -q '^systemctl stop .*clamfleet-server.service' '$T/calls.log' && grep -q '^systemctl disable .*clamfleet-server.service' '$T/calls.log'"
run server-postremove remove
run server-postremove purge
expect "server deb purge: the database is kept" test -f "$T/var/server/clamfleet.db"
expect "server deb purge: the key file is kept" test -f "$T/etc/server-secret.key"
expect "server deb purge: the notice says where they are" grep -q "were NOT removed" "$T/out"
cleanup
new_env
echo "db" >"$T/var/server/clamfleet.db"; echo "key" >"$T/etc/server-secret.key"
run server-preremove 0
run server-postremove 0
expect "server rpm removal: database and key kept, notice printed" bash -c "test -f '$T/var/server/clamfleet.db' && test -f '$T/etc/server-secret.key' && grep -q 'were NOT removed' '$T/out'"
cleanup

# every script is POSIX sh: parse with dash when it is installed
if command -v dash >/dev/null 2>&1; then
	for f in "$src"/*.sh; do dash -n "$f" || fail "$f does not parse under dash"; done
fi

if [ "$fails" -ne 0 ]; then echo "packages_test: $fails failure(s)" >&2; exit 1; fi
echo "packages_test: ok"
