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
./target/debug/fornax uninstall codex   # removes the entries install added
```

`fornax install codex` does four things, and prints each on its own line:

1. **Turns on daemon capture of Codex sessions.** The Fornax daemon then reads
   **every Codex session on this machine** (tool commands and their output,
   and the final assistant message) so that a claim such as "tests passed"
   can be checked against the run's own output. It stores them locally with
   secret-pattern redaction only (no PII redaction). This is the opt-in; it is
   recorded in `$FORNAX_HOME/codex-watch.json`, and `fornax uninstall codex`
   turns it off. In practice it watches the `sessions/` directory of the
   selected Codex home (below) and only activity that happens after capture is
   on; sessions already on disk are not backfilled. A `test_result` claim
   from Codex is at most Review, even when Codex reports a literal exit code
   (Codex 0.160+ item format), because no shipped sensor attests test runs
   (see "Which commands count as a test run"). A genuine non-zero exit is
   still Contradicted; older default shell modes expose no exit code and stay
   Review/Unverified (ADR-0025).
2. **Wires the ambient-status `notify` entry** in `config.toml` to a script
   under `$FORNAX_HOME/bin` (so Codex writes its turn status to
   `$FORNAX_HOME/last-status`).
3. **Adds optional lifecycle hooks** (`PreToolUse`, `PostToolUse`,
   `SessionStart`) to `hooks.json`. Codex skips them until you trust them
   with `/hooks`; findings do not need them.
4. **Writes a LaunchAgent plist file** for the daemon (macOS only, and only
   when `fornax-daemon` sits next to `fornax`; on other platforms it says
   autostart is macOS-only, and when it cannot write the file it prints
   "daemon autostart skipped" with the reason) and prints the exact `launchctl bootstrap`
   command. Fornax never runs `launchctl` itself:
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
idempotent). `uninstall codex` removes the entries `install` added (never a
foreign `notify` value) and leaves every other key, table and comment alone;
it does not delete the notify script file under `$FORNAX_HOME/bin`, and it
stops with an error if `config.toml` cannot be parsed (capture and hooks are
already off by then, but the LaunchAgent plist is not removed; fix the file
and run `uninstall codex` again).

`fornax doctor` is the first-run checklist: daemon reachable, Codex wiring and
capture (judged by the same rules the daemon uses, so a comment, a leftover
marker or a config file alone is never reported as working), and the Claude
Code hooks. A hook entry in Claude's `settings.json` is reported as
configuration only; only recorded events show it ran. For Claude Code (no exit
code in its hook payload) a test result shows as Review, never Verified
(ADR-0025); the same cap now applies to every provider's test result. A finding appears after an agent says it ran tests and the run's
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

### Which commands count as a test run

A "tests passed" claim is checked against the exit code of a command Fornax
can identify as a test-runner execution (FORNX-477). The command must be one
simple command, or an `&&` list containing one, optionally run as an argv
wrapper `["sh"|"bash"|"zsh", "-c"|"-lc", "<script>"]` (Codex form; a Claude
string command is parsed as the script itself, and `bash -c "..."` typed inside
it is `Unverified`), whose program is one of: `pytest` / `py.test`, `python -m pytest`,
`cargo test`, `cargo nextest run`, `npm test`, `vitest`, `jest`, or one of
those started by `npx`, `pnpx`, `bunx`, `pnpm exec`, `uv run` or `poetry run`.
A few harmless environment assignments (`CI=1`, `RUST_BACKTRACE=1`, ...) may
precede it.

* A single runner command keeps its own exit code: 0 is at most `Review`
  (see the cap below), non-zero is `Contradicted`. `2>&1` after the command is allowed (it does not
  change the exit status); other redirections are not.
* An `&&` list (`cd dir && cargo test`) can be a pass only when it exits 0,
  because `&&` runs the next command only after the previous one succeeded. A
  non-zero exit says nothing about which command failed, so it is `Unverified`.
  A list containing a shell-state command (`exit`, `exec`, `source`, `export`,
  `eval`, ...) or an assignment-only step is never identified.
* Everything else is `Unverified`, never `Verified`: a command that only
  mentions a runner (`echo pytest`, `pip install pytest`, `git commit -m "add
  vitest"`), `;`, `||`, pipes, redirections, backgrounding, expansions
  (`$VAR`, backticks), other runners (`python -m unittest`, `go test`,
  `mocha`, ...) and list/help/version/compile-only invocations
  (`--collect-only`, `--no-run`, `--list`, `-h`, `-V`, ...).
* A more recent command that mentions a runner but cannot be identified as a
  test run (for example `pytest | tail`, or `git commit -m "fix pytest"`) stops
  an older run from deciding the claim: it becomes `Unverified`.

**A test run reported from the agent's own transcript is at most `Review`
(FORNX-477).** The exit code and the printed summary both come from the
agent's session, so they cannot establish that the tests ran and passed,
however convincing the runner name, exit code or summary looks. An executable
named `pytest` that prints `3 passed in 0.01s` and exits 0 is indistinguishable
from the real runner in that data. `Verified` for a `test_result` claim needs
evidence from a collector this verifier lists as a test-run attestor with
trust class `HostObserved` or `IndependentExternal`. No such collector ships
in v0.0.9 (the production attestor list is empty), so a passing test run from
Claude Code, Codex (default and `shell_command`) or OpenCode is `Review`.
Unchanged: a genuine non-zero literal exit is still `Contradicted`, and the
conditions below still withhold the result (`Unverified`) for fake runners,
zero tests and missing or malformed summaries. Host-controlled runner receipts
or CI evidence, the route to `Verified`, are tracked as FORNX-443 and are not
part of v0.0.9.

The conditions below are therefore necessary but not sufficient. A recognised
runner exiting 0 is not enough even for `Review`. The runner's
own final summary must also be seen in that command's output: a QA-owned
executable named `pytest` that only does `exit 0`, or `cargo test no_such_test`
(`running 0 tests`), exits 0 without running any test. Fornax therefore reads
only the *counts* from the output's end and requires all of:

* exactly one runner command (any other `&&` step must be a plain `cd <dir>`,
  so `echo '3 passed in 0.1s' && cargo test no_such` is `Unverified`);
* a summary in that runner's own format: pytest's final line
  (`=== 3 passed, 1 skipped in 0.04s ===`) or every `test result:` line of
  `cargo test` (all must be `ok.`, each preceded by its `running N tests`
  header);
* at least one test passed and none failed (errors count as failed).

Missing, zero-test, mismatched or unparseable summaries are `Unverified`. The
summary only ever withholds a pass, it never grants `Verified`: a failing runner is still
`Contradicted` by its exit code, and a heuristic exit code stays capped at
`Review` whatever the output says. In this release only pytest and `cargo test`
output is read, so `cargo nextest run`, `npm test`, `jest` and `vitest` are
recognised (a failure is still `Contradicted`) but a pass is `Unverified`
(summary support for them, FORNX-479, is outside v0.0.9).

Known limits: the summary is text the executed program itself printed, so a
program that deliberately prints a convincing summary (a custom `pytest`
script, a `conftest.py` hook, `harness = false`, `--nocapture`, a Jest
reporter) passes the summary conditions. That is why the result stops at
`Review`; only host-attested exit status, a controlled runner receipt or CI
evidence can raise it (ADR-0025, FORNX-443).

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
