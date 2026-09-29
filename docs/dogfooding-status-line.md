# Dogfooding Fornax's status line in this project (FORNX-30)

> **Superseded by the shared statusline host (HORO-1567).** The setup below
> still works and nothing in this repository will change or remove it. It is
> no longer the recommended way to see Fornax on your statusline — see
> [Migrating to the shared host](#migrating-to-the-shared-host) at the end of
> this document.

Isolated to this repository only — never touches your global Claude Code
config (`~/.claude/settings.json`, `~/.claude/statusline.py`). Uses Claude
Code's project-local settings scope instead.

## Why project-scoped, not global

A Fornax integration bug must not make Claude Code sessions in unrelated
repositories misbehave, and this integration shouldn't be imposed on other
contributors who clone this repo. Claude Code's `.claude/settings.local.json`
is scoped to exactly one project (this repo/worktree), is never committed
(Claude Code adds it to your global git excludes automatically the first
time it writes there), and takes precedence over both the shared project
`.claude/settings.json` and your user-global `~/.claude/settings.json`.

## Setup

1. Build the binaries: `cargo build --workspace` (from the repo root).
2. Start the daemon once per session: `./target/debug/fornax-daemon &`
3. Create `.claude/settings.local.json` in this repo's root (main checkout,
   not a worktree) with the contents below — replace every `<REPO_ROOT>`
   with this repo's real absolute path on your machine (settings.local.json
   is per-machine and gitignored, so a hardcoded local path here is correct,
   unlike in committed files).

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash", "hooks": [{ "type": "command", "command": "rtk hook claude" }] },
      { "matcher": "Grep|Glob", "hooks": [{ "type": "command", "command": "~/.claude/hooks/cbm-code-discovery-gate", "timeout": 5 }] }
    ],
    "PostToolUse": [
      { "matcher": "Bash|Monitor|Workflow", "hooks": [{ "type": "command", "command": "python3 ~/.claude/hooks/bg-track.py", "timeout": 3 }] },
      { "matcher": "Bash", "hooks": [{ "type": "command", "command": "<REPO_ROOT>/scripts/fornax-hook.sh" }] }
    ],
    "Stop": [
      { "hooks": [{ "type": "command", "command": "<REPO_ROOT>/scripts/fornax-hook.sh" }] }
    ],
    "SubagentStart": [{ "hooks": [{ "type": "command", "command": "python3 ~/.claude/hooks/bg-track.py", "timeout": 3 }] }],
    "SubagentStop": [{ "hooks": [{ "type": "command", "command": "python3 ~/.claude/hooks/bg-track.py", "timeout": 3 }] }],
    "UserPromptSubmit": [{ "hooks": [{ "type": "command", "command": "codegraph prompt-hook" }] }],
    "SessionStart": [
      { "matcher": "startup", "hooks": [{ "type": "command", "command": "~/.claude/hooks/cbm-session-reminder" }] },
      { "matcher": "resume", "hooks": [{ "type": "command", "command": "~/.claude/hooks/cbm-session-reminder" }] },
      { "matcher": "clear", "hooks": [{ "type": "command", "command": "~/.claude/hooks/cbm-session-reminder" }] },
      { "matcher": "compact", "hooks": [{ "type": "command", "command": "~/.claude/hooks/cbm-session-reminder" }] }
    ]
  },
  "statusLine": {
    "type": "command",
    "command": "<REPO_ROOT>/scripts/fornax-statusline.sh",
    "padding": 1,
    "refreshInterval": 3
  }
}
```

**Why the global hook entries are copied in verbatim**: Claude Code's docs
don't guarantee whether a project-level `hooks` object merges with the
global one or replaces it outright (see the FORNX-30 Jira comment for the
research). Treating it as full-replace and copying every existing global
hook entry forward, alongside the new Fornax ones, is what prevents `rtk`,
`codegraph`, and the other global hooks from silently stopping inside this
one project.

**Why the status line is a wrapper script, not a raw Fornax command**: a
project-level `statusLine` fully replaces the global one (it's a single
command, not a mergeable list) — `scripts/fornax-statusline.sh` calls your
existing `~/.claude/statusline.py` with the same stdin JSON first, so its
output is preserved, then appends the Fornax segment as an extra line.

## Verifying isolation

From inside this repo: open a Claude Code session, run a Bash tool call,
confirm the Fornax segment appears in the status line and `fornax detail`
shows real findings after a session ends.

From an unrelated repo/path: open a separate Claude Code session, confirm
the status line looks exactly as it did before this setup existed, and no
`fornax-hook.sh`/`fornax-statusline.sh` process ever runs (project-local
settings never apply outside this repo — this is a Claude Code platform
guarantee, not something Fornax enforces itself).

## Failure containment

Both wrapper scripts fail safe: if `target/debug/fornax*` isn't built, or
the daemon isn't running, they degrade to a plain message rather than
erroring — a Fornax problem never breaks your ability to use Claude Code in
this project, let alone any other.

## Migrating to the shared host

### Why the wrapper approach could not be the answer

The wrapper works, and it worked for exactly one product. Claude Code has a
single `statusLine.command`, so a second product that wanted a segment would
have to displace this script to get one — and whichever product installed
last would win. FORNX-30 proved the UX and the failure containment; it could
not be generalised without every Horonom product fighting over one slot.

The shared host (HORO-1565/1566) owns the slot instead. It runs your original
statusline unchanged, then asks each registered product for a structured
answer and composes them. Fornax's answer is `fornax statusline provider`.

### What Fornax now ships

| Surface | What it is |
|---|---|
| `fornax statusline provider` | One JSON payload per render, for the host to compose. Read-only, one local HTTP call, about 18 ms warm. |
| `fornax statusline explain` | Read-only, off the hot path. Everything bounded that Fornax knows about the latest finding, including what it does *not* know. |

Neither writes anything. Fornax deliberately has no second Claude Code
settings patcher: enabling and disabling is the shared lifecycle tool's job,
so there is exactly one piece of code in the company that edits that file.

### Enabling it

From a `horonomy/.github` checkout, with `fornax` on your `PATH`:

```bash
python3 scripts/statusline_lifecycle.py enable \
  --provider fornax --scope host \
  --command fornax --command statusline --command provider
```

Add `--dry-run` first to see the plan without changing anything, and
`doctor` at any time to see who currently owns the slot. The host preserves
your existing statusline command exactly as configured — it is never read,
parsed, edited or assumed to be `~/.claude/statusline.py`.

`--scope host` is not a formality. `/api/status` is
`recent_findings(1)`: one row ordered by `computed_at` across every session
on this machine, with no session filter. The latest finding may belong to a
different session than the one you are looking at, so the host labels the
reading as machine-wide. Declaring `session` would be a false claim about
what the number means.

### Migrating off the FORNX-30 setup

Nothing Fornax ships will touch `.claude/settings.local.json`. It is your
file, it is per-machine, and it may contain hook entries that have nothing to
do with Fornax. Migration is therefore a manual edit you make when you are
ready:

1. Enable the shared host as above, and confirm with `doctor` that it owns
   the slot and that Fornax is registered.
2. Remove **only** the `statusLine` block from this repository's
   `.claude/settings.local.json`. Leave the `hooks` object alone — it is what
   feeds Fornax its observations, and it is unrelated to rendering.
3. Open a Claude Code session in this repo and confirm the composed line
   appears.

Until step 2, **the old wrapper still wins inside this repository.** A
project-level `statusLine` fully replaces the user-global one, so a
project-local wrapper takes precedence over the host you just enabled at
host scope. That is not a conflict the host can detect or resolve for you: it
would have to write to a project file it does not own.

### Compatibility disposition

| Artifact | Disposition |
|---|---|
| `scripts/fornax-statusline.sh` | **Retained and frozen.** Existing configs point at it by absolute path; its behaviour and its output stay byte-identical so nothing silently changes underneath a working setup. It gains no fixes — the three limitations below are why it is superseded, not a backlog. |
| `scripts/fornax-hook.sh` | Unaffected and still required. Rendering changed; observation did not. |
| This document's FORNX-30 sections | Retained as the record of a setup people are still running. |
| Your `.claude/settings.local.json` | Never read or written by anything Fornax ships. |

The frozen wrapper's three limitations, for the record: it assumes your
statusline is `~/.claude/statusline.py`; it calls `target/debug/fornax`, which
only exists in a developer checkout; and it emits a bare shield codepoint
with no variation selector, so its presentation is font-dependent. The last
one cannot recur under the host, because a provider chooses no glyph at all —
iconography belongs to the host so that two products reporting "needs your
attention" cannot pick incompatible emoji.
