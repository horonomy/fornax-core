# Runtime recipe: fornax-core local daemon path

Jira: FORNX-232. Schema and field meanings are defined in
[`docs/release-qa-signoff.md`](../../release-qa-signoff.md) §5. This is the
seed recipe for the local `fornax-daemon` + `fornax-hook-claude` + `fornax`
CLI path that golden journeys `GJ-0001` and `GJ-0002` exercise, plus the
daemon side of `GJ-0004`'s malformed-payload handling. `GJ-0003` (the Codex
hook path, `fornax-hook-codex`) is **not** covered by this recipe — it
needs its own seed recipe, not yet written (see the parent document's
"Populating the remaining recipes" note). Grounded directly
in this repo's own `README.md` Quick Start — the same sequence
`docs/release/v0.0.1-qa-security-signoff.md`'s FORNX-34 evidence and its
own adversarial/XSS follow-up passes (§7.1/§7.2) already executed for real.

| Field | Value |
|---|---|
| Working directory | repo root |
| Prerequisites | Rust toolchain (`cargo`); `CARGO_TARGET_DIR=./target` per `.claude/CLAUDE.md`'s build convention. No secrets required. |
| Variant | `source-development` — `fornax-core` has no published binary artifact yet as of v0.0.1 (see `release/v0.0.1-candidate-manifest.json`). A public-artifact variant is added here once one exists; until then a public-golden-journey run against this surface is understood to be source-development, not silently treated as "the public path." |
| Expected ports/artifacts | `localhost:4317` (daemon HTTP API); a local Unix socket and SQLite store under `$FORNAX_HOME`. |

## Start command

```bash
cargo build --workspace
export FORNAX_HOME=/tmp/fornax-qa-<worker-id>   # isolate per concurrent worker
rm -rf "$FORNAX_HOME"
./target/debug/fornax-daemon &
DAEMON_PID=$!   # capture explicitly; `kill %1` inside a compound command
                # can silently no-op and leave a stray daemon (see
                # Execution record below) — always kill by captured PID
```

Each concurrent QA worker uses its own `$FORNAX_HOME` rather than one
shared instance: this surface's whole purpose is observing state mutation,
so sharing one daemon across workers would make a finding non-attributable
to a specific worker's input — unlike a genuinely read-only shared surface,
where FORNX-230's shared-runtime-reuse guidance would apply instead.

## Readiness probe

The daemon accepts a hook event on stdin without error (README Quick Start
step 2):

```bash
echo '{"hook_event_name":"PostToolUse","session_id":"qa-probe","tool_name":"Bash","tool_input":{"command":"true"},"tool_response":{"exit_code":0,"stdout":"","stderr":""}}' \
  | ./target/debug/fornax-hook-claude
```

No error/non-zero exit from `fornax-hook-claude` is the readiness signal.

## Minimum verification probe

```bash
SESSION=qa-probe
echo '{"hook_event_name":"PostToolUse","session_id":"'"$SESSION"'","tool_name":"Bash","tool_input":{"command":"cargo test --workspace"},"tool_response":{"exit_code":1,"stdout":"","stderr":"test failed"}}' \
  | ./target/debug/fornax-hook-claude
cat > /tmp/fornax-qa-probe-transcript.jsonl <<'EOF'
{"type":"assistant","message":{"content":[{"type":"text","text":"All tests passed."}]}}
EOF
echo '{"hook_event_name":"Stop","session_id":"'"$SESSION"'","transcript_path":"/tmp/fornax-qa-probe-transcript.jsonl"}' \
  | ./target/debug/fornax-hook-claude
./target/debug/fornax status   # expect: CONTRADICTED, not an error or a bare "passed"
```

Expected result: `fornax status` reports `CONTRADICTED` — the daemon
computed a verdict, not a crash or a silently-accepted claim.

## Cleanup

```bash
kill "$DAEMON_PID"
rm -rf "$FORNAX_HOME" /tmp/fornax-qa-probe-transcript.jsonl
```

Populating the remaining recipes (`fornax-hook-codex`, `fornax-cloud`/
`fornax-website` surfaces) is ongoing work, the same way
`release/golden-journeys.json`'s four-entry seed catalog is a starting
point, not a claim of exhaustive coverage — each is added when a real QA
pass first needs it, following this same shape.

## Execution record

Executed 2026-09-01 from a clean `$FORNAX_HOME`, exactly as documented
above (`export DAEMON_PID=$!` captured at start so cleanup could target the
exact process rather than a job-control guess):

- Readiness probe: passed (no error from `fornax-hook-claude`).
- Minimum verification probe: passed — `fornax status` reported
  `CONTRADICTED`, matching the expected result.
- Cleanup verified, not merely run: `kill "$DAEMON_PID"` followed by
  `ps -p "$DAEMON_PID"` (no such process) and `lsof -i :4317` (no listener)
  confirmed the daemon actually exited and the port was free; `$FORNAX_HOME`
  and the scratch transcript file were both removed and confirmed absent.
  An earlier attempt in this same session used `kill %1` inside a compound
  `&&` command, which silently failed to kill the backgrounded job and left
  a stray daemon holding `:4317` — this is exactly the "stale-process false
  finding" this recipe's cleanup field exists to prevent; capturing `$!`
  explicitly and using it for `kill` (as documented in "Start command"
  above) is the fix, not a shell-specific workaround.
