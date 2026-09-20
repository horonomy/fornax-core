# Codex's ambient Fornax state (FORNX-17)

## What already works with zero Codex-specific code

`fornax status` (compact ambient state) and `fornax detail` (session/finding
drill-down) are already fully provider-agnostic: they read from the daemon's
`/api/status`/`/api/findings/recent`, and `fornax_types::Finding` carries no
`provider` field at all (see `fornax-daemon/src/main.rs`'s `handle_message` —
the same `TestResultVerifier` runs for every session regardless of which
adapter produced its `Claim`/`Evidence`). A Codex session's finding shows up
in both commands identically to a Claude Code session's — same icons, same
`claim`/`rationale`/`verifier`/`when` fields, same CONTRADICTED detail
referencing the exact underlying evidence (the verifier's rationale embeds
the real provenance string, e.g.
`codex:<version>:rollout:custom_tool_call_output#exit_code_text`, and the
literal observed exit code — see `fornax-verify`'s `TestResultVerifier::verify`).
This is proven end to end by `fornax-daemon`'s
`codex_session_finding_is_surfaced_by_status_and_detail_identically_to_claude`
integration test.

So the first two AC bullets — "user can invoke one documented command to
inspect session/finding details" and "contradiction detail references the
exact underlying evidence" — already hold for Codex with no changes.

## The real capability gap: no live-refreshing surface

What Codex genuinely lacks, unlike Claude Code's `statusLine` config (see
`docs/dogfooding-status-line.md`), is any host-provided place for a
third-party command's output to appear continuously while the agent works.
Codex's terminal UI is not extensible that way. This is a structural gap,
not an unwired integration — there is nothing to "wire up" to get a
Claude-style live segment out of Codex today (see
`docs/research/adapter-capability-matrix.md`'s Codex section).

## The closest supported, non-invasive equivalent

Codex's legacy `notify`/`notify_command` config (`~/.codex/config.toml`) is
real, user-config-only, and fires a single coarse `agent-turn-complete`
event once per turn. It's explicitly being deprecated in favor of a `Stop`
hook, but that hook path is opt-in/unstable/admin-suppressible (same
caveats as every other Codex hook — see the capability matrix), so
`notify` remains the more broadly available surface today.

**Live-verified invocation shape** (codex-cli 0.147.0, 2026-08-31,
`codex exec -c 'notify=["<script>"]' ... "reply hi, then stop"`, with
`<script>` dumping its own `argv` to a file): the configured command is
invoked with **exactly one argument**, the JSON payload itself — not
appended after any configured extra args (this repo's own
`~/.codex/config.toml` happens to configure `notify = [cmd, "turn-ended"]`
for an unrelated tool, but that second array element is that tool's own
extra arg, not something Codex adds to every notify command). Real captured
payload:

```json
{"type":"agent-turn-complete","thread-id":"<uuid>","turn-id":"<uuid>","cwd":"<path>","client":"codex_exec","last-assistant-message":"hi","input-messages":["..."]}
```

confirming every field the capability matrix's binary-strings survey
predicted (`type`, `thread-id`, `turn-id`, `cwd`, `client`,
`input-messages`, `last-assistant-message`) with `type` fixed at
`"agent-turn-complete"` for a normal turn.

**Critical, also live-verified 2026-08-31: Codex discards the notify
command's stdout.** A first version of this integration tried to `echo`
the ambient segment directly, the same way `scripts/fornax-statusline.sh`
does for Claude Code's `statusLine`. Confirmed live that this text never
reaches the terminal or any visible surface — unlike hook output, which
Codex does print (`hook: SessionStart` / `hook: SessionStart Completed`
appear in every transcript above), a `notify` command's stdout is a pure
side-effect sink. `notify`/`notify_command` is fundamentally a
desktop-notification hook (this machine's own `~/.codex/config.toml`
points its `notify` at a native notifier app, not a text producer), and a
fire-and-forget side-effect command's stdout being discarded is the
mechanism's actual design, not a bug to work around.

So `scripts/fornax-codex-notify.sh` writes the ambient segment to a small
**state file**, `$FORNAX_HOME/last-status` (default `~/.fornax/last-status`),
instead of printing it — degrading honestly to what the mechanism can
actually deliver, the same way the FORNX-16 adapter degrades honestly to
`Unavailable` rather than inventing evidence it doesn't have. Live-verified
end to end: running a real `codex exec` turn with `notify` pointed at this
script produces a real `last-status` file with the daemon-backed segment
inside it.

A user embeds that file's content wherever their terminal setup allows,
e.g. in a shell prompt:

```bash
# ~/.bashrc
fornax_ambient() { cat "${FORNAX_HOME:-$HOME/.fornax}/last-status" 2>/dev/null; }
PS1='$(fornax_ambient) '"$PS1"
```

```zsh
# ~/.zshrc — zsh does not expand command substitution in a prompt without
# this option; without it the prompt shows the literal text
# "$(fornax_ambient)" instead of running it.
setopt PROMPT_SUBST
fornax_ambient() { cat "${FORNAX_HOME:-$HOME/.fornax}/last-status" 2>/dev/null; }
PROMPT='$(fornax_ambient) '"$PROMPT"
```

or a tmux status-bar command polling the same file. This is coarser than
Claude Code's continuously-refreshing `statusLine` — it updates once per
turn, on the next prompt render — which is the honest ceiling of what
`notify` plus a static file can deliver, not a design choice.

### Setup

1. Build the binaries: `cargo build --workspace` (from the repo root).
2. Start the daemon once per session: `./target/debug/fornax-daemon &`
3. Add to `~/.codex/config.toml` (global — `notify` has no project-local
   scope in Codex, unlike Claude Code's settings layering):

   ```toml
   notify = ["<REPO_ROOT>/scripts/fornax-codex-notify.sh"]
   ```

   Replace `<REPO_ROOT>` with this repo's real absolute path.
4. Optionally wire `$FORNAX_HOME/last-status` into your shell prompt/tmux
   status bar as shown above to actually see it update.

### Failure containment

Same fail-safe contract as `scripts/fornax-statusline.sh`: an unbuilt
`fornax` binary, an unreachable daemon, or an unparseable/unexpected
payload (including no `jq` on `PATH`, in which case every invocation is
just treated as worth refreshing the state file for) all degrade to a
plain diagnostic message written to the state file, never breaking the
user's Codex turn. `agent-turn-complete` is the only event type that
rewrites the file at all — a low-noise property confirmed by the wrapper
script's own early-exit branch, not merely asserted.

### Cloud outage does not break this

`fornax status`/`fornax detail` read only the local `fornax-daemon`'s
local SQLite-backed store — no network call to any SaaS backend is on this
path at all, for either provider. A Fornax Cloud outage has no way to
reach this code.
