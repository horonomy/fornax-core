# Adapter capability matrix — Claude Code vs. Codex CLI vs. opencode

Status: living doc, empirically grounded. Re-verify hook schemas against the
installed CLI version before an adapter hard-codes field names — all three
surfaces are actively changing.

## Consolidated compatibility matrix (FORNX-219, v0.0.3)

Every cell below is read directly from each adapter's compiled
`CapabilityProbe::probe()` (`crates/fornax-adapter-{claude,codex,opencode}/src/lib.rs`),
not from this doc's prose — this is the "matches conformance-tested reality"
table FORNX-219's AC requires, and it will drift the moment code changes
without a corresponding update here. Verify against source before trusting a
cell in a future release.

States, per `fornax_types::capabilities::SignalAvailability`:

- **Available** — confirmed present and observed for real, no heuristic.
- **Unsupported** — this runtime fundamentally cannot expose the signal (a
  structural gap, not a missing translation).
- **Unavailable** — exists in principle (the provider's real event stream
  carries it, or another exec-tool configuration on the same provider
  exposes it) but this adapter version doesn't confirm/translate it.
- **Unknown** — the adapter does not declare a `CapabilitySignal` for this
  class at all; `RuntimeCapabilities::state_of` returns `Unknown` for any
  undeclared class. Distinct from `Unsupported`/`Unavailable`: it means "not
  yet assessed," not "assessed and found absent."

| `SignalClass` | Claude Code | Codex CLI | opencode |
|---|---|---|---|
| `ToolInvocation` (pre-execution interception) | Available | Unsupported — hooks opt-in/admin-suppressible, no input-rewrite support | Available — `tool.execute.before`, observe-only in this adapter |
| `ToolTrace` (post-execution observation) | Available | Available — via rollout `custom_tool_call`/`_output` pairing, not hooks | Available |
| `ToolResultPayload` (provider-serialized result body) | Available | Available | Available |
| `ProcessResult` (literal exit code) | **Unsupported** — Bash `tool_response` carries no literal exit code as of Claude Code v2.1.238; evidence is heuristic from stdout/stderr/interrupted | **Unavailable** — `exec_command_end` not emitted by codex-cli 0.147.0; `custom_tool_call_output` does carry a real parseable exit code when the session's exec tool is `tools.shell_command`, but the default `tools.exec_command` (`unified_exec`) shape exposes none at all, so the provider-wide declaration stays the conservative `Unavailable` | **Available** — `tool.execute.after`'s `output.metadata.exit` is a literal integer, confirmed real against opencode v1.18.25 — the first of the three adapters to expose a genuine (non-heuristic) exit code |
| `SessionLifecycle` | Available | Available — `task_complete` in rollout | Available — `event` hook's `session.created`/`session.idle` |
| `SubagentLifecycle` | Available | Unsupported — rollout-tail surfaces no subagent lines; Codex's own hooks exist but are opt-in/unstable/admin-suppressible, same as `ToolInvocation` | **Unsupported** — the `@opencode-ai/plugin` Hooks interface (v1.18.25) has no subagent-specific hook at all, structurally absent |
| `FinalResponse` | Available | Available | **Unavailable** — the `event` hook's `message.updated`/`message.part.updated` text events genuinely carry the final response, but this adapter version doesn't translate them (scoped out per FORNX-161's single-event-path AC, not a structural gap) |
| `ReasoningSummary` | Unknown (undeclared) | Unknown (undeclared) | Unsupported — no reasoning-summary hook or message-part type observed in the Hooks interface for a local tool-calling model session |
| `RawReasoning` | Unknown (undeclared) | Unknown (undeclared) | Unsupported |
| `TokenLogprobs` | Unknown (undeclared) | Unknown (undeclared) | Unsupported — no logprobs field anywhere in the Hooks interface (v1.18.25) |
| `InternalModelSignals` | Unknown (undeclared) | Unknown (undeclared) | Unavailable — `message.updated` carries token/cost telemetry in principle, not translated by this adapter version |

Notes:

- Claude Code and Codex CLI declare no `CapabilitySignal` at all for
  `ReasoningSummary`/`RawReasoning`/`TokenLogprobs`/`InternalModelSignals` —
  this is not the same claim as opencode's explicit `Unsupported`/
  `Unavailable` for those classes, which were positively assessed and found
  absent or untranslated. A future adapter version for Claude Code/Codex may
  declare these explicitly once assessed; until then, `Unknown` is the
  honest state, not an implied `Unsupported`.
- opencode is the sharpest illustration of the three-state design (`SignalAvailability`)
  paying off: it declares `ProcessResult` `Available` (genuine literal exit
  code) while declaring `SubagentLifecycle` `Unsupported` (no such hook
  exists) and `FinalResponse` `Unavailable` (the signal exists in the real
  event stream, this adapter version just doesn't translate it) — three
  different states for three materially different reasons, on one adapter.
- See each adapter's own section below for the full narrative and evidence
  behind each cell, and `docs/research/0002-third-provider-fitness-report.md`
  for the opencode architecture-fitness proof this matrix's third column
  substantiates.

## Claude Code

Source: this machine's `~/.claude/settings.json` + `~/.claude/statusline.py` +
`~/.claude/hooks/bg-track.py` (read directly, 2026-08-28).

Hooks are on by default once configured in `settings.json`. Every hook payload
is JSON on stdin with common fields `session_id`, `transcript_path`, `cwd`,
`hook_event_name`, plus event-specific fields.

| Event | Event-specific fields | Evidence obtainable |
|---|---|---|
| `PreToolUse` | `tool_name`, `tool_input` | Exact tool name + args before execution; can block/rewrite input |
| `PostToolUse` | `tool_name`, `tool_input`, `tool_response` | Provider-serialized result (exit-code-ish data for Bash) — CC's own summarized view, may be truncated; no independent raw stdout capture |
| `SessionStart` | `source` (`startup`/`resume`/`clear`/`compact`) | Session lifecycle only, no tool evidence |
| `UserPromptSubmit` | `prompt` | Raw user prompt text |
| `SubagentStart`/`SubagentStop` | `agent_id`, `agent_type` | Exact subagent lifecycle |
| `Stop` | (turn end) | **Available but not wired in this machine's config** — must add a matcher to observe agent-turn completion |
| `Notification`, `PreCompact` | — | Available per docs but unconfirmed payload shape here; not wired in this config |

Known gaps even with hooks fully wired: no hook fires when a *backgrounded*
shell/Monitor/Workflow tool call actually completes; no raw unbuffered stdout
tap independent of `tool_response`; no PreToolUse/PostToolUse for Edit/Write/
Read/WebFetch/Task unless a matcher is added.

## Codex CLI

Source: openai/codex `docs/config.md`/`docs/hooks.md`, GitHub issues
#4005/#21148/#25141/#18491/#21660/#24948, PR #19905 (research pass, not primary
docs read directly — re-verify against the actually-installed Codex version).

| Capability | Codex CLI | Notes |
|---|---|---|
| Hooks (`PreToolUse`/`PostToolUse`/`Stop`/`SessionStart`/`SessionEnd`/`SubagentStart`/`SubagentStop`/`PermissionRequest`/`UserPromptSubmit`/`PreCompact`/`PostCompact`/`Interrupt`) | Exists, JSON on stdin | **Opt-in**: requires `[features].codex_hooks = true` in `~/.codex/config.toml`; `Stage::UnderDevelopment`; schema actively changing; org admin can force `allow_managed_hooks_only = true` in `requirements.toml` to lock it out entirely |
| PreToolUse blocking | Partial | Bash/shell + reportedly `apply_patch`/MCP; Read-style ops reportedly don't fire it; **no `updatedInput` rewrite support** (rejected at runtime, open FR #18491) |
| Legacy `notify`/`notify_command` | Yes, user-config only (`~/.codex/config.toml`, project-local ignored) | Single coarse `agent-turn-complete` event, JSON-string arg (`type`, `thread-id`, `turn-id`, `cwd`, `client`, `input-messages`, `last-assistant-message`); being deprecated in favor of `Stop` hook — don't build new integrations on it |
| On-disk session transcript | **Yes — "rollout" files**, `~/.codex/sessions/YYYY/MM/DD/rollout-<timestamp>-<uuid>.jsonl` | Always-on (not feature-flagged), JSONL, one `RolloutLine` (`{type, timestamp, payload:RolloutItem}`) per line — user msg / assistant reply / shell invocation / patch proposal / sandbox response. World-readable (mode 0644, issue #21660). Can grow 700MB–2GB (issue #24948) — a tailing reader must handle rotation/size. **This is the primary integration point**, not hooks. |
| Tool-call args/results (cmd, exit code, diffs) | Observable via rollout JSONL (and hooks if enabled) | Exact field names (e.g. an `exit_code` key) not confirmed against a live file in this pass — **must dump a real rollout-*.jsonl and confirm field names empirically before FORNX-29 codes the parser** |

### Explicit UNAVAILABLE / capability gaps for Codex (report, never infer around)

- Universal tool-call interception with input rewriting.
- A stable, versioned public hook JSON Schema shipped with a release.
- Hooks enabled out-of-the-box (requires opt-in feature flag).
- Guaranteed non-suppressible hook execution (admin can disable via `requirements.toml`).

## Adapter design consequence (FORNX-24 / FORNX-28 / FORNX-29)

- `fornax-adapter-claude`: a hook command wired to `PreToolUse`/`PostToolUse`/
  `Stop`/`SessionStart`/`UserPromptSubmit`/`SubagentStart`/`SubagentStop`
  (add `Stop` — not currently wired), reading stdin JSON, normalizing to
  `AgentEvent`, writing to the daemon over the Unix Domain Socket.
- `fornax-adapter-codex`: **primary path is a rollout-file tailer**, not hooks
  — hooks are opt-in/unstable and can be admin-disabled, so a Codex
  integration that only used hooks could go completely dark. Tail the active
  session's `rollout-*.jsonl`, normalize known `RolloutItem` variants to
  `AgentEvent`, and mark `RuntimeCapabilities.supports_pre_tool_use` /
  `supports_post_tool_use` / `supports_session_stop_event` per what the
  installed Codex version actually proves out (feature-flag hooks as a
  secondary, best-effort input if `codex_hooks` happens to be on).
- Before writing the Codex rollout parser: capture one real `rollout-*.jsonl`
  from an actual Codex session on this machine and confirm field names —
  do not hard-code shapes from secondary sources.

## Confirmed rollout JSONL schema (empirical, 2026-08-28)

Verified against real local rollout files (field names only — no payload
values reproduced here; some historical rollout files were found to contain
plaintext secrets in captured command output, tracked as a non-blocking
finding on FORNX-33, not reproduced in this doc).

Top-level line shape: `{"type": <str>, "payload": {...}}` (plus `timestamp`
present on most lines). Observed top-level `type` values: `session_meta`,
`turn_context`, `response_item`, `event_msg`, `compacted`, `world_state`.

Shell/tool execution evidence lives under `type: "event_msg"` with
`payload.type` one of `exec_command_begin` / `exec_command_end` (and
`task_started` / `task_complete` / `user_message` / `token_count` for
turn-level bookkeeping). Confirmed `exec_command_end` payload fields:

```
{
  "type": "exec_command_end",
  "call_id": "<string>",
  "turn_id": "<string>",
  "command": ["<argv...>"],
  "cwd": "<path>",
  "aggregated_output": "<string, stdout+stderr merged>",
  "exit_code": <int>,
  "duration": { "secs": <int>, "nanos": <int> },
  "status": "completed" | "failed",
  "formatted_output": "<string>",
  "source": "<string, e.g. user_shell | unified_exec_startup>"
}
```

This is the exact field Fornax needs for the epic's canonical aha scenario:
`exit_code` + `command` + `aggregated_output` from `exec_command_end` maps
directly to `EvidenceKind::ExitCode` / `EvidenceKind::ToolResult` with
provenance `codex:rollout:exec_command_end`. `aggregated_output` is command
stdout+stderr merged — treat as sensitive-by-default for the privacy
classifier (FORNX-33), same as Claude Code's `tool_response`.

> **STALE — corrected by two later live captures against the same
> codex-cli 0.147.0 install (FORNX-55, 2026-08-29; FORNX-16, 2026-08-31).**
> The `exec_command_end` shape above was never actually reproduced from a
> real `codex exec` turn on this machine. What a real session's rollout
> JSONL actually contains for shell execution is a `response_item` pair —
> `custom_tool_call` (`payload.name == "exec"`, the invocation, command
> embedded in a JS snippet string under `payload.input`, matched to its
> result by `payload.call_id`) followed later by `custom_tool_call_output`
> (`payload.output`, an array of `{type, text}` blocks) — never the
> `event_msg{type:"exec_command_end"}` shape documented above. See
> `crates/fornax-adapter-codex/src/lib.rs::translate_line`'s
> `response_item` handling (kept as a defensive fallback, not the primary
> path).
>
> That `custom_tool_call_output` free-text shape itself has **two distinct
> wire variants**, depending on which exec tool the model actually invoked
> (both observed live, same codex-cli 0.147.0 binary, differing only by
> whether the `unified_exec` feature is enabled):
>
> - `tools.exec_command` (the persistent/`unified_exec` shell — what a
>   flagless `codex exec` chose on this install, no `features.*` set in
>   `~/.codex/config.toml`; not verified as codex-cli's shipped default
>   across every install/config): output text is always `"Script completed\n..."`
>   regardless of the wrapped command's real exit status. Confirmed live
>   with a genuinely failing command (`false`, `exit 1`) still reporting
>   `"Script completed"` — **no exit code, no failure marker, no
>   distinguishing signal at all is exposed by this shape**. This is a real,
>   structural capability gap, not an unwired evidence path — there is
>   nothing in the text to parse. `fornax-adapter-codex` correctly declares
>   `SignalClass::ProcessResult` `Unavailable` for this reason and falls
>   back to a zero-guess heuristic (`heuristic: true` in the Evidence
>   payload) rather than inventing a verdict.
> - `tools.shell_command` (a stateless one-shot exec tool, reached when
>   `unified_exec` is disabled, e.g. `codex exec --disable unified_exec`):
>   output text embeds a literal `"Exit code: <n>"` for **both** outcomes —
>   `"Script completed\n..."` + `"Exit code: 0\n...Output:\n<stdout>"` on
>   success, `"Script failed\n..."` + `"Script error:\nExit code: <n>\n...
>   Output:\n<stdout>"` on failure. Live-captured 2026-08-31 running both a
>   bare `exit 1`/`exit 42` and a real failing `pytest -q` (one deliberately
>   failing assertion) through this exact tool — see
>   `crates/fornax-adapter-conformance/fixtures/codex/custom_tool_call_exec_pair_failure.json`
>   for the pinned real payload. `fornax-adapter-codex`'s
>   `CodexCustomToolCallOutputSensor` now parses this literal `"Exit code:
>   "` text first (real value, `heuristic: false`), falling back to the old
>   zero-guess only when that text is absent — i.e. only on the
>   `unified_exec` shape above.
>
> Net effect: Codex's failure-marker gap (FORNX-16) is resolved for
> `tools.shell_command` sessions and remains a genuine, correctly-reported
> `Unavailable` limitation for `tools.exec_command` (`unified_exec`, the
> flagless-invocation shape on this install) sessions — this is a real
> capability boundary of the installed CLI version/config, not something
> this adapter can paper over without inventing evidence.

## opencode (FORNX-161)

Source: `@opencode-ai/plugin` v1.18.25's shipped TypeScript definitions
(`dist/index.d.ts`, read directly — no secondary sources), confirmed against
a real, live opencode v1.18.25 session on this machine (2026-08-30) with a
plugin logging every hook invocation verbatim.

opencode's integration point is a `Plugin` function
(`(input: PluginInput, options?) => Promise<Hooks>`) that opencode's own
runtime loads **in-process** and invokes synchronously — genuinely distinct
from both Claude Code (external hook-script process, spawned per event) and
Codex (poll/tail of a file the provider writes on its own schedule).

| Hook | Fields | Evidence obtainable |
|---|---|---|
| `tool.execute.before` | `input: {tool, sessionID, callID}`, `output: {args}` (mutable) | Exact tool name + args before execution; can rewrite `args` (this adapter only observes, never rewrites) |
| `tool.execute.after` | `input: {tool, sessionID, callID, args}`, `output: {title, output, metadata: {output, exit, truncated}}` | **`metadata.exit` is a literal integer exit code** — confirmed real (bash tool), no heuristic needed. First of the three providers to expose this. |
| `event` (event-bus passthrough) | `{id, type, properties}` — many `type`s (`session.created`, `session.idle`, `session.updated`, `message.updated`, `message.part.updated`, ...) | `session.created`/`session.idle` give session-lifecycle start/end. `message.part.updated` with `part.type === "tool"` mirrors the `tool.execute.*` hooks' state machine (`running` → `completed`) — confirmed present but not translated by this adapter (scoped out per FORNX-161's single-event-path AC). `message.updated`/text parts genuinely carry the agent's final response — same scope note. |
| `chat.message` | `input: {sessionID, agent, model}`, `output: {message, parts}` | The user's own turn content — recognized, deliberately `Ignored` |
| `permission.ask` | `Permission` in, `{status}` out | Can allow/deny/ask on a pending action — not translated by this adapter (out of FORNX-161's scope) |

### Explicit UNSUPPORTED / capability gaps for opencode (report, never infer around)

- No subagent-specific hook anywhere in the Hooks interface — genuinely
  structural, not merely unobserved (`SignalClass::SubagentLifecycle`:
  `Unsupported`).
- No reasoning-summary/raw-reasoning hook or message-part type observed for
  a local tool-calling model session, and no logprobs field anywhere in the
  Hooks interface (`ReasoningSummary`/`RawReasoning`/`TokenLogprobs`:
  `Unsupported`).

### A real, reproducible local-Ollama tool-calling limitation (2026-08-30)

Every locally available Ollama tool-calling model
(`qwen2.5-coder:7b`/`:14b`, `mistral-nemo:latest`) reliably degrades a real
`tool_calls` response into plain-text JSON once the request carries
opencode's actual production system prompt (~20k tokens, ~10 tool
definitions) — reproduced directly against Ollama v0.32.11's HTTP API
(`/v1/chat/completions` and `/api/chat`, streaming and non-streaming),
independent of opencode. The same models emit well-formed `tool_calls`
against a minimal (~160-token, 1-tool) prompt. This means the "genuinely
distinct integration mechanism, zero-cost local-Ollama path" premise
FORNX-161 was scoped around holds for the *integration mechanism* (the
in-process plugin API is real and works), but not, on this machine/Ollama
version, for driving that mechanism through fully autonomous local
tool-calling at opencode's real prompt size — see
`docs/research/0002-third-provider-fitness-report.md` for how the golden
fixtures were captured despite this (a deterministic stub standing in for
only the LLM turn; every tool-execution event downstream of it is
opencode's own genuine code).

## Formalized capability taxonomy (FORNX-155)

The per-adapter capability declarations this doc's tables describe (Claude
Code's/Codex's confirmed-vs-gap signal availability) are now expressed in
code as `fornax_types::capabilities::{SignalClass, SignalAvailability}`
(`crates/fornax-types/src/capabilities.rs`) rather than the six fixed
`RuntimeCapabilities` bools this doc originally motivated. `Unsupported`
("this runtime fundamentally cannot expose this") and `Unavailable` ("exists
in principle, not observed this session/version") are now distinct states —
e.g. `fornax-adapter-codex` declares `ToolInvocation`/`SubagentLifecycle` as
`Unsupported` (Codex hooks are opt-in/admin-suppressible per this doc) and
`ProcessResult` as `Unavailable` — real per-session, not just unwired: as
the corrected section above documents (FORNX-16), a real literal exit code
*is* parseable when a session's exec tool is `tools.shell_command`, but the
flagless-invocation `tools.exec_command` (`unified_exec`) shape structurally
exposes none at all, even for a genuinely failing command — so the
provider-wide declaration stays the conservative `Unavailable` rather than
`Available`.
`fornax-adapter-opencode` (FORNX-161) is the sharpest illustration of the
three-state design paying off: it declares `ProcessResult` `Available` (a
genuine literal exit code, no heuristic) while declaring
`SubagentLifecycle` `Unsupported` (no such hook exists at all) and
`FinalResponse` `Unavailable` (the signal exists in the real event stream,
this adapter version just doesn't translate it yet) — three different
states for three materially different reasons, on one adapter. See that
module's doc comments for the full taxonomy and each adapter's
`*_capabilities()`/`probe()` function for the field-by-field mapping.
