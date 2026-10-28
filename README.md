# Fornax

Evidence-first execution-truth infrastructure for AI agents: it checks what
an agent claims it did against the observable evidence of what actually ran.

Currently supports coding agents (Claude Code, Codex, opencode) — see
`docs/research/adapter-capability-matrix.md` for the exact adapter surface.

**What should I believe about what this agent is telling me, given the
evidence currently available?**

Fornax watches a coding agent session in real time, captures immutable
evidence (tool calls, exit codes, transcripts), and checks the agent's own
claims against that evidence — surfacing `VERIFIED` / `UNVERIFIED` /
`CONTRADICTED` / `REVIEW` / `UNAVAILABLE`, never a made-up trust score.

## Status

Implementation is being replayed ticket-by-ticket as reviewed PRs after a
one-time history normalization — see
`docs/migration/0001-pr-governance-migration.md` for what moved where, and
`docs/adr/` for the architecture invariants. `main` now has a working local
daemon, verifiers, adapters, and CLI (see Quick Start below); the prior
bootstrap implementation this was replayed from is preserved in full at tag
`archive-v0.0.1-bootstrap` / branch `archive/pre-pr-governance-20260828`.

Jira: FORNX-20 (epic), FORNX-52 (this migration).

## Quick Start

Reproduces the "aha moment" locally: an agent claims its tests passed while
the actual command it ran exited non-zero, and Fornax surfaces the
contradiction — no cloud dependency required.

```bash
cargo build --workspace

# Everything below reads/writes under $FORNAX_HOME (defaults to ~/.fornax).
# Use a scratch directory so this doesn't touch a real Fornax install.
export FORNAX_HOME=/tmp/fornax-quickstart
rm -rf "$FORNAX_HOME"

# 1. Start the daemon (owns the local DB + Unix socket + localhost HTTP API
#    on :4317). Leave this running in its own terminal/background job.
./target/debug/fornax-daemon &

# 2. Feed it hook events directly on stdin, exactly as Claude Code would
#    invoke `fornax-hook-claude` (see that binary's module doc for the real
#    ~/.claude/settings.json wiring). This simulates: the agent ran a Bash
#    command that failed (PostToolUse, exit_code 1), then claimed at the end
#    of the turn that tests passed (Stop, transcript with that claim text).
SESSION=quickstart-demo

echo '{"hook_event_name":"PostToolUse","session_id":"'"$SESSION"'","tool_name":"Bash","tool_input":{"command":"cargo test --workspace"},"tool_response":{"exit_code":1,"stdout":"","stderr":"test failed"}}' \
  | ./target/debug/fornax-hook-claude

cat > /tmp/fornax-quickstart-transcript.jsonl <<'EOF'
{"type":"assistant","message":{"content":[{"type":"text","text":"All tests passed."}]}}
EOF
echo '{"hook_event_name":"Stop","session_id":"'"$SESSION"'","transcript_path":"/tmp/fornax-quickstart-transcript.jsonl"}' \
  | ./target/debug/fornax-hook-claude

# 3. Check the verdict — CONTRADICTED, with the rationale spelling out why.
./target/debug/fornax status   # compact one-liner: 🛡 ✕ CONTRADICTED (host-wide)
./target/debug/fornax detail   # full claim/evidence/rationale/verifier detail
```

### Installing the Claude Code integration (FORNX-15)

Run `./target/debug/fornax adapter list` to see every known adapter id,
what it wires, and its config path before installing one.

The Quick Start above feeds hook events by hand. For a real Claude Code
session, wire the hooks into `~/.claude/settings.json` with:

```bash
./target/debug/fornax install claude-code
```

This idempotently adds `SessionStart`, `UserPromptSubmit`, `PreToolUse`,
`PostToolUse`, and `Stop` hook entries that invoke `fornax-hook-claude` —
running it again is a no-op, and it never touches any other hook or setting
already in that file. `fornax-hook-claude` must be on `PATH` for Claude Code
to find it. To stop Fornax observing Claude Code sessions and return the
file to a clean state:

```bash
./target/debug/fornax uninstall claude-code
```

### Installing the Codex integration (FORNX-16, FORNX-468, FORNX-474)

```bash
./target/debug/fornax install codex     # opt in
./target/debug/fornax doctor            # what is wired, what is missing, the next step
./target/debug/fornax uninstall codex   # exactly undoes it
```

`fornax install codex` does four things, and prints each on its own line:

1. **Turns on daemon capture of Codex sessions.** The Fornax daemon then reads
   **every Codex session on this machine** (tool commands and their output,
   and the final assistant message) so that a claim such as "tests passed"
   can be checked against the run's own exit code. It stores them locally with
   secret-pattern redaction only (no PII redaction). This is the opt-in; it is
   recorded in `$FORNAX_HOME/codex-watch.json`, and `fornax uninstall codex`
   turns it off.
2. **Wires the ambient-status `notify` entry** in `config.toml` to a script
   under `$FORNAX_HOME/bin` (so Codex writes its turn status to
   `$FORNAX_HOME/last-status`).
3. **Adds optional lifecycle hooks** (`PreToolUse`, `PostToolUse`,
   `SessionStart`) to `hooks.json`. Codex skips them until you trust them
   with `/hooks`; findings do not need them.
4. **Writes a LaunchAgent plist file** for the daemon and prints the exact
   `launchctl bootstrap` command. Fornax never runs `launchctl` itself:
   loading a login item is your call. Until the daemon is running, nothing is
   recorded. An existing plist that Fornax did not write (or cannot read) is
   left untouched.

**Which Codex home.** An explicit, non-empty `CODEX_HOME` selects the Codex
home (config, hooks and the sessions directory the daemon watches); unset or
empty means `~/.codex`. A relative or non-UTF-8 `CODEX_HOME` is refused before
anything is written. `uninstall` acts on the home currently selected, and
leaves capture on (and says so) if it is watching a different one.

Codex's `notify` holds exactly one command, unlike Claude's per-event hook
arrays. If `notify` is already wired to something else, or `config.toml` does
not parse, `install codex` refuses to touch that file and leaves it
byte-for-byte unchanged, rather than replacing or corrupting an unrelated
integration; wire Fornax in manually in that case (the capture opt-in and the
hooks are separate and still apply). Running it again is safe (it is
idempotent), and `uninstall codex` removes exactly what `install`
added (never a foreign `notify` value), leaving every other key, table and
comment alone.

`fornax doctor` is the first-run checklist: daemon reachable, Codex wiring and
capture (judged by the same rules the daemon uses, so a comment, a leftover
marker or a config file alone is never reported as working), and the Claude
Code hooks. A hook entry in Claude's `settings.json` is reported as
configuration only; only recorded events show it ran. For Claude Code (no exit
code in its hook payload) a test result shows as Review, never Verified
(ADR-0025). A finding appears after an agent says it ran tests and the run's
own output is seen; see them with `fornax status` and `fornax detail`.

For the optional ambient-status surface only, see
`docs/dogfooding-codex-notify.md`.

The dashboard at `/dashboard` on the daemon's HTTP port works the same way
across every adapter.

opencode monitoring uses a third, distinct mechanism: an in-process
`@opencode-ai/plugin` (`crates/fornax-adapter-opencode/plugin/fornax-capture.js`)
that opencode's own runtime invokes synchronously, forwarding each hook
event to the long-lived `fornax-hook-opencode` binary over stdin. Enable it
by putting the plugin file (or a path to it) where opencode loads plugins
from — either project-local at `.opencode/plugin/fornax-capture.js`, or
referenced by path in an opencode project's `opencode.json`
(`{"plugin": ["<path>/fornax-capture.js"]}`) — with `fornax-hook-opencode` on
`PATH`. See `crates/fornax-adapter-opencode` and
`docs/research/0002-third-provider-fitness-report.md` for the full design
and its capability gaps versus Claude Code/Codex, and
`docs/research/0003-opencode-live-transport-verification.md` (FORNX-291) for
the real end-to-end run that proved this transport leg and the one bug it
surfaced (fixed).

## Local storage, privacy and known limitations

Everything above reads/writes under `$FORNAX_HOME` (default `~/.fornax`): an
on-disk SQLite database, a Unix domain socket, and a localhost-only HTTP API.
Nothing leaves your machine unless you explicitly turn on cloud sync
(`FORNAX_CLOUD_SYNC_ENABLED`, see below) — there is no telemetry and no
hosted Beta/production service to opt out of, because none exists at this
version. `$FORNAX_HOME`'s on-disk schema is not yet guaranteed stable across
releases.

Claude Code and Codex CLI support is not symmetric: Codex's hook surface is
opt-in and can be admin-disabled, so its adapter relies primarily on tailing
Codex's own rollout-file transcripts rather than hooks — see
`docs/research/adapter-capability-matrix.md` for the exact, empirically
verified differences before relying on a specific hook/field existing on the
Codex side.

### Exporting a session for cloud sync (optional)

`fornax export-spool` reads `$FORNAX_HOME/fornax.db` directly (no daemon
dependency) and writes one wire-compatible envelope JSON file per
event/claim/evidence/capability into `<out>/pending/`, in the layout
`horonomy/fornax-cloud`'s `fornax-uploader` spool expects:

```bash
./target/debug/fornax export-spool --session "$SESSION" --out /tmp/fornax-uploader-spool
```

Point `fornax-uploader`'s `FORNAX_UPLOADER_SPOOL_DIR` at that same directory
to sync the exported session to a running fornax-cloud stack — see
`horonomy/fornax-infra`'s README for standing up that stack locally, and
`horonomy/fornax-cloud`'s README for running `fornax-uploader` itself. Cloud
sync is opt-in and off by default (`FORNAX_CLOUD_SYNC_ENABLED`) — nothing
above requires it, and the local daemon/CLI path works fully with cloud
access disabled.

## License

MIT.
