# opencode live transport-leg verification (FORNX-291)

Jira: FORNX-291, parent FORNX-138. FORNX-161 built the opencode adapter and
proved its `AgentAdapter`/`EvidenceSensor` translation logic against real,
sanitized fixtures, but explicitly disclosed that the actual wiring — the
plugin (`fornax-capture.js`, in-process inside opencode) spawning and piping
NDJSON to the `fornax-hook-opencode` binary, which forwards to `fornax-daemon`
over a Unix domain socket — was written but never run end-to-end as one live
pipeline. This ticket closes that gap.

## What was actually run, not simulated

- `opencode` CLI v1.18.25 reinstalled locally via `npm install -g opencode-ai`
  (same version FORNX-161 used).
- Ollama v0.32.11 was already running locally; **no new model was pulled**
  (517 GiB free on `/System/Volumes/Data` before starting, checked per
  `~/CLAUDE.md`'s disk-pressure incident log).
- A real opencode project with a custom `openai-compatible` provider pointed
  at `http://localhost:11499/v1`, and the actual shipped plugin file (not a
  copy or investigation stand-in) enabled two separate ways, **both verified
  live**: dropped at the project-local auto-load path
  `.opencode/plugin/fornax-capture.js`, and separately (with that directory
  removed) referenced by absolute path from `opencode.json`'s
  `{"plugin": ["<path>/fornax-capture.js"]}`. FORNX-161 only asserted the
  latter form from opencode's own docs, never having run either live — both
  are now confirmed to actually load and run the plugin.
- A real `fornax-daemon` process, built from this repo, bound to a scratch
  `FORNAX_HOME` and a real Unix domain socket.
- `opencode run "List files in the current directory using bash"` — a real
  opencode process, loading the real plugin in-process, which spawned the
  real `fornax-hook-opencode` binary, which connected to the real daemon
  socket.
- Same disclosed technique as FORNX-161: the one thing stubbed was the LLM's
  own turn (a minimal local HTTP server returning a fixed `bash` tool call,
  then a fixed final answer), because local Ollama tool-calling under
  opencode's real production prompt has the same known degradation FORNX-161
  already documented. Everything downstream of that one stubbed HTTP
  response — opencode's own tool-invocation plumbing, the real `ls -la .`
  process it spawned, the real plugin's real `spawn()`/stdin-write path, the
  real `fornax-hook-opencode` binary, and the real daemon's real Unix-socket
  server and SQLite writes — is genuine, unstubbed code running for real.

## What was proved

After the live run, the daemon's own on-disk SQLite store
(`$FORNAX_HOME/fornax.db`) contained, for the real opencode session id:

```
agent_events: session_start, pre_tool_use(bash), post_tool_use(bash), session_end
evidence:     {"command":"ls -la .","exit_code":0,"heuristic":false}
runtime_capabilities: provider = open_code
```

This is the daemon's own storage, inspected independently of the plugin's or
binary's own exit status — proof the event genuinely reached and was
persisted by a running daemon, not just that the plugin believed it sent
something.

## The one real bug found and fixed

`fornax-capture.js` spawned `fornax-hook-opencode` with no `'error'`
listener on the returned `ChildProcess`. Reproduced directly (independent of
opencode): with `fornax-hook-opencode` not on `PATH`, `spawn()` still
returns immediately, but the child's async `ENOENT` failure fires an
unhandled `'error'` event — and because this plugin runs **in-process**
inside opencode (unlike Claude Code's external hook-script process or
Codex's separate tailer), an unhandled event there is a fatal, uncaught
exception in **opencode itself**, not just in the capture pipeline. A
best-effort integration must never be able to take down its host on a
missing or dead binary; this is exactly the kind of bug the ticket's
disclosed gap predicted and unit/fixture tests against static payloads
cannot catch, because it isn't a translation-logic bug at all.

Fix: added a `child.on("error", ...)` listener (and the equivalent
`child.stdin.on("error", ...)` for the pipe itself) that swallows the
failure the same way the existing `send()` best-effort `try`/`catch`
already intended. Also hardened `dispose()` to wait (bounded, 200ms) for
`stdin.end()`'s queued-write flush to actually complete before resolving,
closing the second, related risk FORNX-161 flagged (a fast opencode
shutdown racing the last queued write) even though it did not reproduce in
either live run.

Everything else in the transport leg — the wire envelope shape
(`{"hook", "at", "payload"}`), the UDS connect/reconnect logic in
`fornax-hook-opencode`, and the daemon's ingest/serialization logic — worked
correctly on the first live run with no changes needed.

## What is stubbed vs. real, restated for clarity

| Component | Status |
|---|---|
| opencode CLI process | Real |
| `.opencode/plugin/fornax-capture.js` | Real (the shipped file) |
| `fornax-hook-opencode` binary | Real |
| Unix domain socket to `fornax-daemon` | Real |
| `fornax-daemon` process + SQLite store | Real |
| The `ls -la .` process opencode's `bash` tool spawned | Real |
| The LLM turn (tool-call decision + final answer text) | Stubbed (deterministic local HTTP server) |

## Automated regression

`crates/fornax-adapter-opencode/tests/live_transport.rs` is the CI-safe,
automated version of this proof: it spawns a real `fornax-daemon`, drives
the real `plugin/fornax-capture.js` file under `node` (opencode itself is
not installed in CI, so only opencode's runtime is stood in for — the
plugin file, the binary, and the daemon are all real, unstubbed code), and
asserts against the daemon's real on-disk SQLite store. Requires `node` on
`PATH`, which GitHub's `ubuntu-latest` runners provide without an extra
setup step.
