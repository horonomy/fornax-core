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
//! This closes FORNX-433 AC1's "real authenticated native positive+negative
//! pair takes end-to-end ingress through verdict and audit" -- no new
//! native `claude`/API invocation, no new spend.

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
fn pytest_post_tool_use_payload(session_id: &str, passed: bool) -> serde_json::Value {
    let (stdout, stderr) = if passed {
        ("1 passed in 0.02s\n", "")
    } else {
        ("", "1 failed in 0.02s\n")
    };
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
fn real_claude_bash_success_fixture_reaches_a_verified_finding_end_to_end() {
    let finding = run_case(
        "positive",
        true,
        "fx433-claude-positive",
        "all tests passed",
    );
    assert_eq!(
        finding.verdict, "verified",
        "a genuine exit-code-0 PostToolUse plus a matching Stop claim must reach Verified \
         through the real daemon, got verdict={} evidence_ids={}",
        finding.verdict, finding.evidence_ids
    );
    let evidence_ids: Vec<uuid::Uuid> =
        serde_json::from_str(&finding.evidence_ids).expect("decode evidence_ids");
    assert!(
        !evidence_ids.is_empty(),
        "the finding must actually cite the real evidence the fixture produced"
    );
}

#[test]
fn real_claude_bash_failure_fixture_contradicts_a_false_success_claim_end_to_end() {
    // The adversarial negative control (FORNX-433 AC1): a real captured-shape
    // pytest failure (non-empty stderr, heuristic exit_code 1) plus an
    // assistant transcript that *falsely* claims success -- exactly the
    // "no fabricated session attribution" shape AC1 asks for. A verdict of
    // anything other than Contradicted/Review here would mean the real
    // ingest path accepted a false claim against real contrary evidence.
    let finding = run_case(
        "negative",
        false,
        "fx433-claude-negative",
        "all tests passed",
    );
    assert_ne!(
        finding.verdict, "verified",
        "a false success claim against a real captured failure must never reach Verified, \
         got verdict={} evidence_ids={}",
        finding.verdict, finding.evidence_ids
    );
    assert!(
        finding.verdict == "contradicted" || finding.verdict == "review",
        "expected Contradicted or Review for a false claim against real failure evidence, \
         got verdict={} evidence_ids={}",
        finding.verdict,
        finding.evidence_ids
    );
}
