//! FORNX-433: automated regression for the real `fornax-hook-claude` ->
//! `fornax-daemon` (over a real Unix domain socket) transport leg, carried
//! all the way through to a persisted `Verdict` -- not just events/evidence
//! landing in storage (the bar `fornax-adapter-opencode`'s
//! `live_transport.rs` set for FORNX-291).
//!
//! Everything here is genuine, unstubbed code on the Fornax side: a real
//! `fornax-daemon` process, bound to a real Unix domain socket, and the
//! real, compiled `fornax-hook-claude` binary invoked exactly the way
//! Claude Code's own hook runner invokes it -- spawned fresh per hook call,
//! fed one hook JSON payload on stdin, exiting. The one thing stood in for
//! is Claude Code's own runtime: this test does not run a live `claude`
//! CLI session (which would cost real API spend and isn't installed in
//! CI).
//!
//! The `PostToolUse` payloads below use the exact field shape already
//! confirmed real against live Claude Code v2.1.238
//! (`fornax-adapter-conformance/fixtures/claude/post_tool_use_bash_heuristic_*.json`,
//! FORNX-161: `hook_event_name`/`session_id`/`tool_name`/`tool_input`/
//! `tool_response{stdout,stderr,interrupted,isImage,noOutputExpected}`, no
//! literal exit code), with the command text changed to a real test-runner
//! invocation (`pytest -q`) -- those FORNX-161 fixtures intentionally used
//! `echo hi`/`false` to probe the adapter's generic exit-code heuristic, so
//! they carry no `is_test_runner_evidence` match and can never reach
//! `TestResultVerifier` (the only verifier `fornax_adapter_claude`'s
//! Stop-derived `test_result` Claim can ever be checked against). Per the
//! fixtures README's own documented process ("Capture (or, for a
//! breaking-change probe, construct) the native shape"), this is a
//! constructed-from-confirmed-shape payload, not a new live capture -- no
//! new native `claude`/API invocation, no new spend. The `Stop` hook
//! payload (real shape: `hook_event_name`/`session_id`/`transcript_path`)
//! points at a real on-disk transcript file, matching
//! `fornax_adapter_claude`'s own `stop_event_finds_text_block_...` unit
//! test, since Claude Code's own Claim-bearing hook is `Stop` with a
//! `transcript_path`, not a second `PostToolUse` variant.
//!
//! This file proves FORNX-433 AC1's negative half for the Claude provider --
//! "a false claim against real contrary evidence never reaches Verified" --
//! end-to-end through the real daemon. It does NOT prove the positive half
//! (a genuine success claim reaching `Verified`) for Claude specifically:
//! see the "real finding" section below for why that is a real ceiling of
//! Claude Code's own tool_response shape, not a gap in this test. The
//! differential Verified-vs-Contradicted pair AC1 asks for is proven by the
//! sibling `fornax-adapter-codex` `live_transport.rs`, whose `tools.shell_command`
//! shape does carry a literal, authoritative exit code. No new native
//! `claude`/API invocation, no new spend.
//!
//! # A real finding this test suite surfaced (and fixed) along the way
//!
//! An earlier version of this file's negative control used an *unrealistic*
//! failure shape (`stderr` carrying the failure text). A real `pytest -q`
//! failure writes its summary to **stdout**, with `stderr` empty -- and with
//! that realistic shape, `ClaudeBashExitCodeSensor`'s "stderr empty implies
//! exit_code 0" heuristic fired, and `TestResultVerifier` (pre-fix) returned
//! `Verified` for a *false* "all tests passed" claim against a genuine
//! failure. That is exactly the false-VERIFIED path FORNX-433 AC1 exists to
//! rule out, and it was real production behavior, not a test bug.
//!
//! Fixed in `fornax-verify` (not here): `TestResultVerifier`/
//! `CommandSuccessVerifier` now downgrade any `exit_code=0` evidence whose
//! `heuristic` flag is `true` to `Review`, never `Verified` -- a heuristic
//! absence-of-stderr is not proof of success. That is safety-monotonic (it
//! only removes `Verified` outcomes) and leaves every *authoritative*
//! exit-code path (a real literal exit code, from any provider) untouched.
//!
//! The consequence for the Claude provider specifically: since Claude Code's
//! real `PostToolUse` `tool_response` never carries a literal exit code at
//! all (see the module doc above), `TestResultVerifier` can **never** reach
//! `Verified` for a Claude-derived `test_result` claim today -- only `Review`
//! at best, or `Unverified`. Both tests below assert against that real
//! ceiling rather than against a wished-for `Verified`. Giving the Claude
//! provider an authoritative exit-code signal (so a real positive case can
//! reach `Verified`) is tracked separately -- see FORNX-146's linked
//! follow-up ticket -- since it is a materially different question
//! (parsing stdout content vs. gating on provenance, with its own review and
//! blast radius) from what this PR's test infrastructure is responsible for.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn sibling_workspace_bin(name: &str) -> PathBuf {
    let mut dir = std::env::current_exe().expect("current_exe");
    loop {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return candidate;
        }
        let is_profile_dir = dir
            .file_name()
            .map(|f| f == "debug" || f == "release")
            .unwrap_or(false);
        if is_profile_dir {
            panic!(
                "could not find sibling binary `{name}` under {}; build the workspace first \
                 (`cargo build --workspace`)",
                dir.display()
            );
        }
        if !dir.pop() {
            panic!("walked past filesystem root looking for `{name}`");
        }
    }
}

/// The real, confirmed Claude Code v2.1.238 `Bash` `PostToolUse` field
/// shape (see module docs), with the command text set to a real
/// test-runner invocation so the evidence this produces actually matches
/// `is_test_runner_evidence` and can reach `TestResultVerifier`.
///
/// Both the passing and failing shape put their summary text in `stdout`
/// with `stderr` empty -- that is what a real `pytest -q` run actually does
/// in both directions; stderr only gets used for interpreter/startup
/// errors, not test failures. See the module doc's "A real finding..."
/// section for why this realistic shape (not an unrealistic stderr-based
/// failure) is the one that matters here.
fn pytest_post_tool_use_payload(session_id: &str, passed: bool) -> serde_json::Value {
    let stdout = if passed {
        "....                                                                     [100%]\n1 passed in 0.02s\n"
    } else {
        "F                                                                        [100%]\n=== FAILURES ===\n1 failed in 0.02s\n"
    };
    let stderr = "";
    serde_json::json!({
        "hook_event_name": "PostToolUse",
        "session_id": session_id,
        "tool_name": "Bash",
        "tool_input": {"command": "pytest -q"},
        "tool_response": {
            "stdout": stdout,
            "stderr": stderr,
            "interrupted": false,
            "isImage": false,
            "noOutputExpected": false,
        },
    })
}

/// Runs the real, compiled `fornax-hook-claude` binary once, feeding it
/// `payload` on stdin exactly as Claude Code's hook runner would -- a fresh
/// process per hook call, no persistent connection.
fn run_hook_claude(fornax_home: &Path, payload: &serde_json::Value) {
    let hook_bin = env!("CARGO_BIN_EXE_fornax-hook-claude");
    let mut child = Command::new(hook_bin)
        .env("FORNAX_HOME", fornax_home)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn fornax-hook-claude");
    {
        use std::io::Write;
        let stdin = child.stdin.as_mut().expect("hook stdin");
        stdin
            .write_all(payload.to_string().as_bytes())
            .expect("write hook payload");
    }
    let status = child.wait().expect("wait for fornax-hook-claude");
    assert!(status.success(), "fornax-hook-claude exited non-zero");
}

/// Writes a real on-disk transcript file in the exact JSONL shape
/// `fornax_adapter_claude::last_assistant_text` reads, and returns a `Stop`
/// hook payload pointing at it -- the real shape Claude Code's own `Stop`
/// hook carries (`hook_event_name`, `session_id`, `transcript_path`).
fn stop_payload_with_transcript(
    dir: &Path,
    session_id: &str,
    assistant_text: &str,
) -> serde_json::Value {
    let transcript_path = dir.join(format!("transcript-{session_id}.jsonl"));
    let line = serde_json::json!({
        "type": "assistant",
        "message": {
            "content": [
                {"type": "text", "text": assistant_text}
            ]
        }
    });
    std::fs::write(&transcript_path, format!("{line}\n")).expect("write transcript");
    serde_json::json!({
        "hook_event_name": "Stop",
        "session_id": session_id,
        "transcript_path": transcript_path.to_str().expect("transcript path is valid utf8"),
    })
}

fn poll_until<T>(
    timeout: Duration,
    label: &str,
    diagnostics: impl FnOnce() -> String,
    mut f: impl FnMut() -> Option<T>,
) -> T {
    let start = Instant::now();
    loop {
        if let Some(v) = f() {
            return v;
        }
        if start.elapsed() > timeout {
            panic!(
                "{label}: condition not met within {timeout:?}\n--- diagnostics ---\n{}",
                diagnostics()
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn tail_log(path: &Path) -> String {
    match std::fs::read_to_string(path) {
        Ok(contents) if contents.trim().is_empty() => "(empty)".to_string(),
        Ok(contents) => {
            let lines: Vec<&str> = contents.lines().collect();
            let start = lines.len().saturating_sub(40);
            lines[start..].join("\n")
        }
        Err(e) => format!("(could not read {}: {e})", path.display()),
    }
}

/// Deliberately short and under `/tmp` directly rather than
/// `std::env::temp_dir()` -- the daemon binds a real Unix domain socket
/// inside this directory, and `sockaddr_un` has a short, fixed-size path
/// buffer; a long temp path reliably overflows it (same precedent as
/// fornax-adapter-opencode's `live_transport.rs`).
fn tempdir(label: &str) -> PathBuf {
    let dir = PathBuf::from("/tmp").join(format!("fx433-claude-{label}-{:x}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).expect("mkdir tempdir");
    dir
}

fn free_tcp_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local_addr")
        .port()
}

struct KillOnDrop(std::process::Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_daemon(fornax_home: &Path) -> (KillOnDrop, PathBuf) {
    let daemon_bin = sibling_workspace_bin("fornax-daemon");
    let http_port = free_tcp_port();
    let sock_path = fornax_home.join("fornax.sock");
    let daemon_log_path = fornax_home.join("daemon.log");
    let daemon_log = std::fs::File::create(&daemon_log_path).expect("create daemon.log");

    let daemon = Command::new(&daemon_bin)
        .env("FORNAX_HOME", fornax_home)
        .env("FORNAX_HTTP_PORT", http_port.to_string())
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(daemon_log)
        .spawn()
        .expect("spawn fornax-daemon");
    let guard = KillOnDrop(daemon);

    poll_until(
        Duration::from_secs(5),
        "waiting for daemon UDS socket to be created",
        || tail_log(&daemon_log_path),
        || sock_path.exists().then_some(()),
    );
    (guard, daemon_log_path)
}

/// The shared positive/negative shape: feed one real `PostToolUse` fixture
/// through the real hook binary, then a real-shaped `Stop` hook claiming
/// `assistant_text`, and poll the real on-disk store (the same store the
/// daemon itself reads/writes) for the resulting `Finding`.
fn run_case(
    label: &str,
    passed: bool,
    session_id: &str,
    assistant_text: &str,
) -> fornax_store::FindingRow {
    let tmp = tempdir(label);
    let fornax_home = tmp.clone();
    let db_path = fornax_home.join("fornax.db");
    let (daemon_guard, daemon_log_path) = spawn_daemon(&fornax_home);

    let post_tool_use = pytest_post_tool_use_payload(session_id, passed);
    run_hook_claude(&fornax_home, &post_tool_use);

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    // The hook binary exiting only means it finished writing to its socket
    // connection -- the daemon's own ingest/evidence-insert is a separate,
    // concurrent async task with no ack anywhere by design (fire-and-forget,
    // same precedent as fornax-adapter-opencode's live_transport.rs). Wait
    // for the real evidence row to actually land before sending the Stop
    // hook, or the claim can be evaluated against zero evidence and
    // persist a premature Unverified finding that nothing ever re-checks.
    poll_until(
        Duration::from_secs(5),
        "waiting for the PostToolUse fixture's evidence to be persisted",
        || tail_log(&daemon_log_path),
        || {
            rt.block_on(async {
                let store = fornax_store::Store::open(&db_path).await.ok()?;
                let evidence = store.evidence_for_session(session_id).await.ok()?.evidence;
                (!evidence.is_empty()).then_some(())
            })
        },
    );

    let stop = stop_payload_with_transcript(&tmp, session_id, assistant_text);
    run_hook_claude(&fornax_home, &stop);

    let finding = poll_until(
        Duration::from_secs(5),
        "waiting for the daemon to persist a real Finding for this session",
        || tail_log(&daemon_log_path),
        || {
            rt.block_on(async {
                let store = fornax_store::Store::open(&db_path).await.ok()?;
                let findings = store.findings_for_session(session_id).await.ok()?;
                findings.into_iter().next()
            })
        },
    );

    drop(daemon_guard);
    std::fs::remove_dir_all(&tmp).ok();
    finding
}

#[test]
fn real_claude_bash_success_fixture_never_falsely_reaches_verified_end_to_end() {
    // AC1's positive case, against the real ceiling: Claude Code's genuine
    // PostToolUse shape carries no literal exit code (see module docs), so
    // even a true "tests passed" claim backed by a real passing pytest run
    // can only reach Review today, never Verified -- a heuristic exit_code=0
    // is not proof. The thing this test actually proves end-to-end is that
    // the real ingest path produces *some* Finding citing real evidence, and
    // that the fix (`fornax-verify`'s heuristic downgrade) does not also
    // suppress the legitimate non-adversarial case into Unverified.
    let finding = run_case(
        "positive",
        true,
        "fx433-claude-positive",
        "all tests passed",
    );
    assert_eq!(
        finding.verdict, "review",
        "a heuristic exit_code=0 (Claude Code's tool_response carries no real exit code) \
         must land on Review, not Verified and not Unverified, got verdict={} evidence_ids={}",
        finding.verdict, finding.evidence_ids
    );
    let evidence_ids: Vec<uuid::Uuid> =
        serde_json::from_str(&finding.evidence_ids).expect("decode evidence_ids");
    assert!(
        !evidence_ids.is_empty(),
        "the finding must actually cite the real evidence the fixture produced"
    );
    assert_eq!(
        finding.verifier_name, "test_result_verifier_v1",
        "the Review must come from TestResultVerifier's heuristic-exit-code-0 downgrade, \
         not some other verifier reaching Review for an unrelated reason, got verifier_name={}",
        finding.verifier_name
    );
    assert!(
        finding.rationale.contains("heuristic"),
        "the rationale must name the heuristic exit_code=0 as the reason, got rationale={}",
        finding.rationale
    );
}

#[test]
fn real_claude_bash_failure_fixture_never_falsely_reaches_verified_end_to_end() {
    // The adversarial negative control (FORNX-433 AC1), using the *realistic*
    // shape (see module doc's "A real finding..." section): a genuine
    // `pytest -q` failure writes its summary to stdout with stderr empty --
    // the exact shape the independent review of this PR's earlier revision
    // demonstrated was being hit by `ClaudeBashExitCodeSensor`'s stderr-empty
    // heuristic, which (pre-fix) produced a false Verified here. Post-fix,
    // this and the "positive" case above land on the *same* Review verdict,
    // because Claude's tool_response genuinely cannot distinguish them --
    // the one invariant this test exists to prove is that the false claim
    // never reaches Verified.
    let finding = run_case(
        "negative",
        false,
        "fx433-claude-negative",
        "all tests passed",
    );
    assert_ne!(
        finding.verdict, "verified",
        "a false success claim against a real pytest failure must never reach Verified, \
         got verdict={} evidence_ids={}",
        finding.verdict, finding.evidence_ids
    );
    assert_eq!(
        finding.verdict, "review",
        "expected Review (heuristic exit_code=0, cannot be confirmed as success or failure \
         from this evidence alone), got verdict={} evidence_ids={}",
        finding.verdict, finding.evidence_ids
    );
    assert_eq!(
        finding.verifier_name, "test_result_verifier_v1",
        "the Review must come from TestResultVerifier's heuristic-exit-code-0 downgrade, \
         not some other verifier reaching Review for an unrelated reason, got verifier_name={}",
        finding.verifier_name
    );
    assert!(
        finding.rationale.contains("heuristic"),
        "the rationale must name the heuristic exit_code=0 as the reason, got rationale={}",
        finding.rationale
    );
}
