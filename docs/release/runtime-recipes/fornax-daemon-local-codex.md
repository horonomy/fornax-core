# Runtime recipe: fornax-core local daemon path (Codex rollout-tail)

Jira: FORNX-232, HORO-1712. Schema and field meanings are defined in
[`docs/release-qa-signoff.md`](../../release-qa-signoff.md) §5. This is the
seed recipe for `GJ-0003` (`fornax-hook-codex`, the rollout-tail transport) —
flagged as missing by
[`fornax-daemon-local.md`](fornax-daemon-local.md)'s own note since that
file only covers the Claude Code hook path. Grounded in a real, bounded,
disposable `codex exec` dogfood session (2026-10-13/14, codex-cli 0.160.0,
founder-authorized real OpenAI auth, isolated `CODEX_HOME`/`FORNAX_HOME`,
never touching a real `~/.codex` or `~/.claude/settings.json`) — every
command below was actually run, including a first draft that used a bare
`exit 7` instead of `pytest` and correctly reached `UNVERIFIED` rather than
`CONTRADICTED` (the verifier only treats `pytest`/`cargo test`/`npm test`-
shaped commands as test-runner evidence — see `is_test_runner_evidence` in
`fornax-verify`) — caught by actually running it, not assumed; the
commands below are the corrected, re-verified version.

`fornax-hook-codex` (this recipe) and the separate HORO-1712-part-B
lifecycle-hook binding (`fornax-hook-codex-event`) are two different
transports for the same provider — see
[`crates/fornax-adapter-codex/src/hook.rs`](../../../crates/fornax-adapter-codex/src/hook.rs)'s
module docs for why they coexist rather than one replacing the other. This
recipe covers only the rollout-tail path, which is the one `GJ-0003` names.

| Field | Value |
|---|---|
| Working directory | repo root |
| Prerequisites | Rust toolchain (`cargo`); `CARGO_TARGET_DIR=./target`; real `codex` CLI installed and authenticated (`codex --version`); `pytest` on `PATH`; a disposable `CODEX_HOME` with the real `auth.json` **symlinked, never copied**, from the real one. No new secrets, no new paid endpoints beyond the one bounded `codex exec` call below. |
| Variant | `source-development` — same as `fornax-daemon-local.md`. |
| Expected ports/artifacts | A local Unix socket and SQLite store under `$FORNAX_HOME`; a real rollout JSONL file under `$CODEX_HOME/sessions/**/*.jsonl`, written by the real `codex` binary, not this recipe. |

## Setup — disposable Codex environment (never the real one)

```bash
SCRATCH=/tmp/fornax-gj0003-recipe   # any disposable scratch dir
mkdir -p "$SCRATCH/codex-home" "$SCRATCH/workdir/tests"
ln -sf "$HOME/.codex/auth.json" "$SCRATCH/codex-home/auth.json"
cat > "$SCRATCH/workdir/tests/test_fail.py" <<'EOF'
def test_always_fails():
    assert False
EOF
cd "$SCRATCH/workdir" && git init -q && git -c user.email=t@t -c user.name=t commit -q --allow-empty -m init
```

## Start command

```bash
cargo build --workspace
export FORNAX_HOME=/tmp/fnx-gj0003-home   # short path -- a deeply nested
                                            # scratch path overflows the
                                            # UDS SUN_LEN limit on macOS
rm -rf "$FORNAX_HOME" && mkdir -p "$FORNAX_HOME"
./target/debug/fornax-daemon &
DAEMON_PID=$!   # capture explicitly, same precedent as fornax-daemon-local.md
```

## Readiness probe — a real, bounded `codex exec` call

```bash
export CODEX_HOME="$SCRATCH/codex-home"
cd "$SCRATCH/workdir"
codex exec \
  --ignore-user-config --skip-git-repo-check -s workspace-write \
  -c approval_policy=\"never\" \
  "Run exactly this shell command: pytest -q tests/test_fail.py . Report the real result honestly." \
  < /dev/null

ROLLOUT=$(ls "$CODEX_HOME"/sessions/*/*/*/*.jsonl | tail -1)
./target/debug/fornax-hook-codex --file "$ROLLOUT" &
HOOK_PID=$!
sleep 2   # let it finish tailing the (short, already-complete) file
kill "$HOOK_PID"; wait "$HOOK_PID" 2>/dev/null
```

No error from `fornax-hook-codex` tailing the file is the readiness signal
(same policy as the Claude recipe's hook readiness probe). The real
command genuinely fails (`exit_code: 1`), and — observed across repeated
real runs — Codex reliably reports this failure honestly rather than
claiming success, so `task_complete`'s own `claims_tests_passed()` prefilter
correctly produces **no** claim from the real transcript. That is expected,
correct behavior, not a readiness failure: it is exactly why the minimum
verification probe below injects a controlled claim directly, instead of
depending on the model volunteering a false one.

**The `kill "$HOOK_PID"` above is not just cleanup — it is load-bearing.**
Found by actually running this recipe: while `fornax-hook-codex`'s UDS
connection for this session stays open (its normal, long-lived-tailer
state), the verifier conservatively reports `REVIEW`, not a definite
verdict, with rationale `"...downgraded from a definite verdict: a
connection for this session was still mid-handoff when this claim was
evaluated, so currently-visible evidence may not yet be complete
(HORO-1712)"` — correct, intentional behavior: more evidence could still
arrive while an adapter is actively connected. Only once that connection
closes does the daemon commit to `CONTRADICTED`. A finding already
computed as `REVIEW` is not retroactively recomputed just because the
connection later closes — the claim must be (re-)submitted after the
adapter has disconnected, which is why the sequence above closes the hook
process before the minimum verification probe sends its claim.

## Minimum verification probe

```bash
# Real event id for this session's PostToolUse AgentEvent, needed as the
# injected claim's source_event_id:
EVENT_ID=$(sqlite3 "$FORNAX_HOME/fornax.db" \
  "SELECT id FROM agent_events WHERE kind='post_tool_use' ORDER BY observed_at DESC LIMIT 1;")
SESSION_ID=$(sqlite3 "$FORNAX_HOME/fornax.db" \
  "SELECT session_id FROM agent_events WHERE id='$EVENT_ID';")

python3 - "$FORNAX_HOME/fornax.sock" "$SESSION_ID" "$EVENT_ID" <<'PYEOF'
import socket, json, uuid, datetime, sys
sock_path, session_id, event_id = sys.argv[1:4]
msg = {
    "type": "claim", "id": str(uuid.uuid4()), "session_id": session_id,
    "source_event_id": event_id, "text": "All tests passed.",
    "subject": "test_result",
    "claimed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
}
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sock_path)
s.sendall((json.dumps(msg) + "\n").encode())
s.close()
PYEOF

sleep 1
./target/debug/fornax status
```

Expected result: `fornax status` reports `CONTRADICTED` — the daemon
computed a real verdict from a real codex-cli 0.160.0 session's real
`pytest` failure (through `fornax-hook-codex`'s real rollout-tailing
transport) against the controlled claim, not a crash, not a bare "passed",
and not a false `VERIFIED`. This is `GJ-0003`'s pass condition: the same
computation path as `GJ-0001` (the Claude hook), reached through the
structurally different rollout-tail transport (ADR-0001's "adapter
boundary is thin, provider-agnostic").

The claim is injected directly over the UDS socket as a controlled,
deterministic `IngestMessage::Claim` rather than relying on the model to
volunteer a false one — see the readiness probe's note above for why. This
keeps the probe deterministic and independent of model behavior on any
given run, matching the same "genuine test-runner failure, controlled
claim input" pattern `fornax-verify`'s own unit tests use.

## Real session evidence (this recipe's own dogfood run)

| Field | Value |
|---|---|
| codex-cli version | 0.160.0 |
| Real command run | `/bin/zsh -lc 'pytest -q tests/test_fail.py'` |
| Real `exit_code` / `status` | `1` / `"failed"` |
| Injected claim text | `"All tests passed."` (`subject: "test_result"`) |
| Resulting verdict | `contradicted` |
| Rationale (daemon's own text) | `claim states tests passed, but observed test-runner exit_code=1 (codex:0.160.0:rollout:item_completed:CommandExecution#exit_code)` |
| Verifier | `test_result_verifier_v1` |

## Credential-free real-host variant (2026-10-23, codex-cli 0.163.0)

Same journey with no OpenAI credential and no `auth.json`: a model already pulled into a
local Ollama server drives a real `codex exec`. `CODEX_HOME`, `HOME` and `FORNAX_HOME` are
disposable, `env -i` passes only `PATH`, and nothing is installed into any Codex or Claude
configuration (the rollout-tail transport is passive).

```bash
env -i PATH="$PATH" HOME="$SCRATCH/home" CODEX_HOME="$SCRATCH/codex-home" \
  codex exec --oss --local-provider ollama -m mistral-nemo:latest \
  --ignore-user-config --skip-git-repo-check -s workspace-write -c approval_policy=\"never\" \
  "Call your shell command tool exactly once with cmd set to: pytest -q tests/test_fail.py   Do not run any other command. Then report the real result honestly." < /dev/null
```

Run the daemon with `RUST_LOG=info` (otherwise its log is empty) and a private
`FORNAX_HTTP_PORT` if 4317 is taken. Observed: 3 attempts; `qwen2.5-coder:7b` printed its tool
call as text (no command ran), the first `mistral-nemo` prompt ran `bash` instead of pytest,
the explicit prompt above ran `pytest` once. Result: one stored session, `post_tool_use`
+ `session_end`, `finding computed verdict=Contradicted`, evidence source
`codex:0.163.0:rollout:item_completed:CommandExecution#exit_code`. `fornax-hook-codex`
logs `unrecognized rollout line shape ... skipping` for 0.163.0 lines it does not map
(`response_item:*`, `turn_context`, ...); the verdict path does not depend on them. The result
depends on a local model following the instruction, so treat a miss as a model failure first.

## Cleanup

```bash
# $HOOK_PID was already killed in the readiness probe above (load-bearing,
# not redundant) -- only $DAEMON_PID remains here.
kill "$DAEMON_PID"
rm -rf "$FORNAX_HOME" "$SCRATCH"
```

## What this recipe does not cover

- `fornax-hook-codex-event` (HORO-1712 part B's lifecycle-hook binding) —
  deliberately out of scope; see that module's own docs and its crate's
  `tests/live_transport.rs` for its own real-binary coverage.
- A real VERIFIED run through this same transport — `GJ-0001`'s analogous
  probe already covers the positive case for the Claude path; this recipe
  reuses the CONTRADICTED shape because it is the one this repo's own
  false-green regression history (the historical Beta finding, FORNX-444)
  makes the more valuable probe to keep current.
- A command that is NOT `pytest`/`cargo test`/`npm test`-shaped (e.g. a
  bare `exit <n>`) never reaches `CONTRADICTED` even with a false claim —
  it correctly stays `UNVERIFIED` (`fornax-verify`'s
  `is_test_runner_evidence` gate). This was found by actually running that
  case first; noted here so a future reader doesn't have to rediscover it.
