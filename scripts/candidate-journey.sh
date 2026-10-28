#!/bin/bash
# Offline acceptance journey on release-profile binaries (FORNX-472). It runs
# entirely under a throwaway HOME/FORNAX_HOME/CODEX_HOME: no launchctl, no real
# ~/.codex ~/.claude ~/.fornax ~/Library/LaunchAgents, no network, no model, no
# credentials. It never runs a fornax binary with --version. It does NOT run a
# real Codex or Claude Code session, so it proves install/uninstall/doctor/
# preservation behavior only, not host capture of a real model run.
# Usage: candidate-journey.sh <dir-with-fornax-and-fornax-daemon> <receipt-file>
set -u
BIN=$1; RECEIPT=$2
J=$(mktemp -d "${TMPDIR:-/tmp}/fnx-journey.XXXXXX")
trap 'kill "$(cat "$J/daemon.pid" 2>/dev/null)" 2>/dev/null; rm -rf "$J"' EXIT
mkdir -p "$J/bin" "$J/home/.codex" "$J/home/.claude" "$J/home/Library/LaunchAgents"
cp "$BIN/fornax" "$BIN/fornax-daemon" "$BIN/fornax-hook-claude" "$J/bin/"
export HOME="$J/home" CODEX_HOME="$J/home/.codex" FORNAX_HOME="$J/fh" FORNAX_HTTP_PORT=47393
export PATH="$J/bin:/usr/bin:/bin"
F="$J/bin/fornax"; LA="$HOME/Library/LaunchAgents/com.horonomy.fornax-daemon.plist"
fail=0
check(){ if eval "$2"; then echo "PASS: $1"; else echo "FAIL: $1"; fail=1; fi; }
step(){ echo; echo "== $*"; }
{
step "A1 doctor on a fresh machine"
$F doctor
check "fresh doctor reports gaps" "$F doctor | grep -q '^  \[!!\]'"

step "A2 foreign binary plist already at the LaunchAgent path"
printf 'bplist00\321\001\002\377\376' > "$LA"; before=$(shasum -a 256 < "$LA")
inst=$($F install codex 2>&1); inst_rc=$?; echo "$inst"
uninst=$($F uninstall codex 2>&1); uninst_rc=$?; echo "$uninst"
after=$(shasum -a 256 < "$LA")
check "install ran and refused to touch the foreign plist" "[ $inst_rc = 0 ] && echo \"\$inst\" | grep -q 'leaving it alone'"
check "uninstall ran and refused to remove the foreign plist" "[ $uninst_rc = 0 ] && echo \"\$uninst\" | grep -q 'leaving it alone'"
check "foreign plist byte-identical after install + uninstall" "[ '$before' = '$after' ]"
rm -f "$LA"

step "B1 codex install on a clean LaunchAgents dir"
$F install codex
check "plist written by install" "[ -f '$LA' ] && grep -q 'managed by fornax' '$LA'"
check "notify wiring present" "grep -q fornax-codex-notify.sh '$CODEX_HOME/config.toml'"
step "B2 doctor before the daemon runs"
$F doctor
check "daemon gap, codex wiring ok" "$F doctor | grep -q '^  \[!!\] daemon' && $F doctor | grep -q '^  \[ok\] codex wiring'"
step "B3 start the daemon (stand-in for launchctl bootstrap)"
( "$J/bin/fornax-daemon" >"$J/daemon.log" 2>&1 & echo $! >"$J/daemon.pid" )
for _ in $(seq 1 40); do [ -S "$FORNAX_HOME/fornax.sock" ] && break; sleep 0.5; done
$F doctor
check "daemon reachable, capture ok" "$F doctor | grep -q '^  \[ok\] daemon' && $F doctor | grep -q '^  \[ok\] codex capture'"
kill "$(cat "$J/daemon.pid")" 2>/dev/null
for _ in $(seq 1 20); do kill -0 "$(cat "$J/daemon.pid")" 2>/dev/null || break; sleep 0.5; done
step "B4 uninstall codex"
$F uninstall codex
check "our plist removed" "[ ! -e '$LA' ]"
check "notify wiring removed" "! grep -q fornax-codex-notify.sh '$CODEX_HOME/config.toml' 2>/dev/null"

step "D1 redirected CODEX_HOME (FORNX-474): one active root for install, capture and doctor"
DEF="$HOME/.codex"; RED="$J/redirected-codex"; EMPTY="$J/unwired-codex"; mkdir -p "$RED" "$EMPTY"
CODEX_HOME="$DEF" $F install codex
check "default tree is wired" "grep -q fornax-codex-notify.sh '$DEF/config.toml'"
cp "$DEF/config.toml" "$J/default-config.before"
check "doctor on an unwired redirected home is a gap although the default tree is wired" "CODEX_HOME='$EMPTY' $F doctor | grep -q '^  \[!!\] codex wiring' && ! CODEX_HOME='$EMPTY' $F doctor | grep -q '^  \[ok\] codex wiring'"
printf 'model = "x"\n' > "$RED/config.toml"
CODEX_HOME="$RED" $F install codex
check "install wired the redirected home" "grep -q fornax-codex-notify.sh '$RED/config.toml'"
check "foreign key in the redirected config survived" "grep -q 'model = \"x\"' '$RED/config.toml'"
check "default tree config untouched by the redirected install" "cmp -s '$DEF/config.toml' '$J/default-config.before'"
check "capture marker names the redirected sessions dir" "grep -q '$RED/sessions' '$FORNAX_HOME/codex-watch.json'"
check "doctor on the redirected home is ok" "CODEX_HOME='$RED' $F doctor | grep -q '^  \[ok\] codex wiring' && CODEX_HOME='$RED' $F doctor | grep -q '^  \[ok\] codex capture'"
rel_out=$(CODEX_HOME=relative/codex $F install codex 2>&1); rel_rc=$?
check "relative CODEX_HOME is refused with a clear error and no side effects" "[ $rel_rc != 0 ] && echo \"\$rel_out\" | grep -q CODEX_HOME && [ ! -e relative ] && cmp -s '$DEF/config.toml' '$J/default-config.before'"
CODEX_HOME="$RED" $F uninstall codex
check "uninstall removed our wiring from the redirected home only" "! grep -q fornax-codex-notify.sh '$RED/config.toml' && grep -q fornax-codex-notify.sh '$DEF/config.toml'"
CODEX_HOME="$DEF" $F uninstall codex

step "C1 claude code: foreign hook + setting, install, idempotence, doctor, uninstall"
cat > "$HOME/.claude/settings.json" <<'JSON'
{"theme":"dark","hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/usr/local/bin/foreign-hook"}]}]}}
JSON
$F install claude-code
cp "$HOME/.claude/settings.json" "$J/after1.json"
$F install claude-code
check "second install byte-identical" "cmp -s '$HOME/.claude/settings.json' '$J/after1.json'"
check "foreign hook and theme kept after install" "grep -q foreign-hook '$J/after1.json' && grep -q '\"theme\"' '$J/after1.json'"
$F doctor
check "doctor says configuration only, never Verified" "$F doctor | grep -q 'configuration only' && $F doctor | grep -q 'never Verified'"
$F uninstall claude-code
check "uninstall keeps foreign hook" "grep -q foreign-hook '$HOME/.claude/settings.json'"
check "uninstall removes fornax hook" "! grep -q fornax-hook-claude '$HOME/.claude/settings.json'"
echo; [ $fail = 0 ] && echo "JOURNEY-PASS" || echo "JOURNEY-FAIL"
} 2>&1 | tee "$RECEIPT"
grep -q JOURNEY-PASS "$RECEIPT"
