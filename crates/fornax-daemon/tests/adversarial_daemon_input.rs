//! FORNX-238 gap closure: bounded dynamic adversarial input exercise against
//! the *real* running daemon + Claude Code hook adapter
//! (`crates/fornax-daemon`, `crates/fornax-adapter-claude`,
//! `crates/fornax-store`). This is not the broad QA campaign and not an
//! unbounded fuzz run — it closes exactly the gap the FORNX-238 sign-off
//! marked NOT RUN: a fixed corpus of 12 representative adversarial
//! PostToolUse/Stop hook-event JSON payloads, fed on stdin to
//! `fornax-hook-claude` exactly as the README Quick Start does, run once
//! each, deterministically, against one live daemon process for the whole
//! module.
//!
//! Test-only use of `std::process::Command` here does not touch fornax-core's
//! production zero-subprocess-spawn invariant — `subprocess_surface_is_still_zero_in_production_code`
//! below asserts that invariant by source inspection of the *production*
//! crates, not this test file.
//!
//! Harness shape: a single `#[tokio::test]` drives the whole bounded corpus
//! sequentially against one daemon instance (spinning up 12 daemons would
//! fight over one TCP port and buys nothing — the invariant under test is
//! per-case behavior, not process isolation). Each case uses its own session
//! id so evidence/claim counts before/after a case are unambiguous, and
//! every wait is a bounded async poll, never a fixed sleep, so the test is
//! not sensitive to machine load.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use fornax_store::Store;

// ---------------------------------------------------------------------
// Binary + environment plumbing
// ---------------------------------------------------------------------

/// Locate a sibling workspace binary. `CARGO_BIN_EXE_<name>` is only set by
/// Cargo for binaries in *this* test's own package (fornax-daemon); the hook
/// adapter and CLI binaries live in other workspace crates, so their paths
/// are derived from `CARGO_MANIFEST_DIR` (this crate's directory) plus the
/// conventional `<workspace_root>/target/<profile>/<bin>` layout that both
/// local dev (`CARGO_TARGET_DIR=./target`, per this repo's CLAUDE.md) and CI
/// (`cargo test --workspace` from the repo root, default target dir) share.
fn workspace_bin(name: &str) -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("crates/<name> is two levels below the workspace root");
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let path = workspace_root.join("target").join(profile).join(name);
    assert!(
        path.exists(),
        "expected workspace binary at {path:?} — run `cargo build --workspace` first"
    );
    path
}

struct DaemonHandle {
    child: Child,
    home: PathBuf,
    port: u16,
    log_path: PathBuf,
}

impl DaemonHandle {
    /// True while the OS still reports this PID as running — the exact
    /// "did the process crash/panic" signal the corpus needs after every
    /// adversarial case.
    fn is_alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    fn log_contents(&self) -> String {
        std::fs::read_to_string(&self.log_path).unwrap_or_default()
    }
}

impl Drop for DaemonHandle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        std::fs::remove_dir_all(&self.home).ok();
    }
}

/// Spawn a real `fornax-daemon` against an isolated `$FORNAX_HOME` and an
/// off-default HTTP port, with `RUST_LOG=info` so both the "dropping
/// malformed ingest line" warning and the "finding computed" info line
/// actually emit (the daemon uses `EnvFilter::from_default_env()`, which is
/// silent with no `RUST_LOG` at all) — captured to a log file so later
/// assertions can inspect it without racing the daemon's own stdout/stderr.
async fn start_daemon() -> DaemonHandle {
    // Deliberately *not* `std::env::temp_dir()`: on macOS that resolves to a
    // long per-user path under `/private/var/folders/...`, and `$FORNAX_HOME`
    // becomes a Unix domain socket path (`fornax.sock`) — `sockaddr_un`'s
    // `sun_path` is capped at ~104 bytes on macOS / ~108 on Linux, so a
    // temp-dir-based home plus a UUID reliably blows that budget
    // ("UDS server exited error=path must be shorter than SUN_LEN",
    // confirmed while building this harness). `/tmp` plus a short id keeps
    // the whole path well under the limit.
    let home = PathBuf::from("/tmp").join(format!("fnx-adv-{}", short_id()));
    std::fs::create_dir_all(&home).expect("create scratch FORNAX_HOME");
    // An OS-assigned ephemeral port, not a fixed one: a fixed port risks
    // colliding with a leftover daemon process from an earlier aborted test
    // run (confirmed while building this harness — a prior run that hit a
    // stack overflow via SIGABRT skipped all `Drop` cleanup, leaking a
    // daemon that kept squatting on the fixed port; every later run's own
    // daemon then failed `TcpListener::bind` and exited, while `fornax
    // status`/`detail` kept silently talking to the stale one instead).
    let port = free_tcp_port();
    let log_path = home.join("daemon.log");
    let log_file = std::fs::File::create(&log_path).expect("create daemon log file");
    let log_file_err = log_file.try_clone().expect("clone log file handle");

    let child = Command::new(workspace_bin("fornax-daemon"))
        .env("FORNAX_HOME", &home)
        .env("FORNAX_HTTP_PORT", port.to_string())
        .env("RUST_LOG", "info")
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_file_err))
        .stdin(Stdio::null())
        .spawn()
        .expect("spawn fornax-daemon");

    let mut handle = DaemonHandle {
        child,
        home,
        port,
        log_path,
    };

    wait_for(Duration::from_secs(10), || {
        let alive = handle.is_alive();
        let ready = alive && fornax_status(&handle) != "🛡 fornax: daemon unreachable";
        if !alive {
            panic!(
                "daemon exited during startup; log:\n{}",
                handle.log_contents()
            );
        }
        async move { ready }
    })
    .await;

    handle
}

/// Bounded async poll: run `check` every 20ms until it returns `true` or
/// `timeout` elapses. Used for daemon readiness and for "has the async
/// ingest caught up yet" — the hook's socket write is fire-and-forget, so
/// nothing about this system is synchronous end-to-end.
async fn wait_for<F, Fut>(timeout: Duration, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if check().await {
            return;
        }
        if tokio::time::Instant::now() > deadline {
            panic!("condition not met within {timeout:?}");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn fornax_status(daemon: &DaemonHandle) -> String {
    let out = Command::new(workspace_bin("fornax"))
        .arg("status")
        .env("FORNAX_HTTP_PORT", daemon.port.to_string())
        .env("FORNAX_HOME", &daemon.home)
        .output()
        .expect("run fornax status");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Feed `stdin` to `fornax-hook-claude`, exactly as Claude Code would invoke
/// it, pointed at the test daemon's socket. Returns (exit_code, stdout,
/// stderr) — the adapter is designed to be silent and always exit 0 (see its
/// module doc: "a daemon that isn't running must never block/fail the
/// agent's own turn"), so exit code is *not* usable as a reject/accept
/// signal for this corpus; DB state is (see `assert_no_data_for_session`).
struct HookResult {
    status: i32,
    stdout: String,
    stderr: String,
}

fn send_hook(daemon: &DaemonHandle, stdin: &[u8]) -> HookResult {
    let mut child = Command::new(workspace_bin("fornax-hook-claude"))
        .env("FORNAX_HOME", &daemon.home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn fornax-hook-claude");
    child
        .stdin
        .take()
        .expect("hook stdin handle")
        .write_all(stdin)
        .expect("write hook stdin");
    let out = child.wait_with_output().expect("wait for hook to exit");
    HookResult {
        status: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

async fn open_store(daemon: &DaemonHandle) -> Store {
    Store::open(daemon.home.join("fornax.db"))
        .await
        .expect("open store db")
}

/// Every table this corpus can observe is empty for `session_id` — the
/// discriminator between "input was silently dropped" (this) and "input was
/// silently accepted as if valid" (a real finding) for the cases that must
/// produce nothing at all.
async fn assert_no_data_for_session(store: &Store, session_id: &str) {
    assert!(
        store
            .events_for_session(session_id)
            .await
            .expect("query events")
            .is_empty(),
        "expected no events persisted for session {session_id}"
    );
    assert!(
        store
            .claims_for_session(session_id)
            .await
            .expect("query claims")
            .is_empty(),
        "expected no claims persisted for session {session_id}"
    );
    assert!(
        store
            .evidence_for_session(session_id)
            .await
            .expect("query evidence")
            .evidence
            .is_empty(),
        "expected no evidence persisted for session {session_id}"
    );
}

/// Send the README's exact CONTRADICTED aha-scenario pair (PostToolUse with
/// a failing exit code, then a Stop claiming tests passed) under a fresh
/// session id, and confirm the daemon still computes CONTRADICTED — the
/// "did an earlier adversarial case corrupt daemon state" check that must
/// pass after every corpus case.
async fn assert_valid_processing_still_works(daemon: &DaemonHandle, probe_session: &str) {
    let transcript_path = daemon
        .home
        .join(format!("{probe_session}-transcript.jsonl"));
    std::fs::write(
        &transcript_path,
        serde_json::json!({
            "type": "assistant",
            "message": {"content": [{"type": "text", "text": "All tests passed."}]}
        })
        .to_string(),
    )
    .expect("write probe transcript");

    let post = send_hook(
        daemon,
        serde_json::json!({
            "hook_event_name": "PostToolUse",
            "session_id": probe_session,
            "tool_name": "Bash",
            "tool_input": {"command": "cargo test --workspace"},
            "tool_response": {"exit_code": 1, "stdout": "", "stderr": "test failed"}
        })
        .to_string()
        .as_bytes(),
    );
    assert_eq!(post.status, 0, "PostToolUse probe hook must exit 0");

    let stop = send_hook(
        daemon,
        serde_json::json!({
            "hook_event_name": "Stop",
            "session_id": probe_session,
            "transcript_path": transcript_path.to_str().unwrap()
        })
        .to_string()
        .as_bytes(),
    );
    assert_eq!(stop.status, 0, "Stop probe hook must exit 0");

    struct DebugOnFail<'a>(&'a DaemonHandle, &'a str);
    impl<'a> Drop for DebugOnFail<'a> {
        fn drop(&mut self) {
            if std::thread::panicking() {
                eprintln!(
                    "=== daemon log at failure for probe {} ===\n{}",
                    self.1,
                    self.0.log_contents()
                );
            }
        }
    }
    let _dbg = DebugOnFail(daemon, probe_session);

    wait_for(Duration::from_secs(5), || async {
        let out = Command::new(workspace_bin("fornax"))
            .arg("detail")
            .env("FORNAX_HTTP_PORT", daemon.port.to_string())
            .env("FORNAX_HOME", &daemon.home)
            .output()
            .expect("run fornax detail");
        let text = String::from_utf8_lossy(&out.stdout);
        text.contains("CONTRADICTED") && text.contains("All tests passed.")
    })
    .await;

    let status = fornax_status(daemon);
    assert!(
        status.contains("CONTRADICTED"),
        "expected fornax status to report CONTRADICTED after probe {probe_session}, got: {status}"
    );
}

// ---------------------------------------------------------------------
// The corpus
// ---------------------------------------------------------------------

#[tokio::test]
async fn adversarial_corpus_against_live_daemon() {
    let mut daemon = start_daemon().await;
    let store = open_store(&daemon).await;

    // Baseline: valid processing works before any adversarial input at all.
    assert_valid_processing_still_works(&daemon, "probe-00-baseline").await;
    assert!(daemon.is_alive(), "daemon died after baseline probe");

    // -- Case 1: malformed / truncated JSON (unparseable) -----------------
    {
        let session = "case-01-truncated";
        let res = send_hook(
            &daemon,
            br#"{"hook_event_name": "PostToolUse", "session_id": "case-01-truncated""#,
        );
        assert_eq!(res.status, 0, "hook must exit 0 (see module doc)");
        assert!(res.stdout.is_empty() && res.stderr.is_empty());
        assert_no_data_for_session(&store, session).await;
        assert!(daemon.is_alive(), "daemon died on truncated JSON");
        assert_valid_processing_still_works(&daemon, "probe-01").await;
    }

    // -- Case 2: missing required fields (no session_id, no hook_event_name)
    {
        let res = send_hook(
            &daemon,
            serde_json::json!({"tool_name": "Bash", "tool_input": {"command": "echo hi"}})
                .to_string()
                .as_bytes(),
        );
        assert_eq!(res.status, 0);
        // No hook_event_name at all -> translate() matches no known kind ->
        // no IngestMessage is ever built, so nothing lands under any
        // session, including the "unknown" default.
        assert_no_data_for_session(&store, "unknown").await;
        assert!(daemon.is_alive(), "daemon died on missing required fields");
        assert_valid_processing_still_works(&daemon, "probe-02").await;
    }

    // -- Case 3: null values where a field is expected non-null -----------
    {
        let session = "case-03-nulls";
        let res = send_hook(
            &daemon,
            serde_json::json!({
                "hook_event_name": null,
                "session_id": session,
                "tool_name": null,
                "tool_input": null,
                "tool_response": null
            })
            .to_string()
            .as_bytes(),
        );
        assert_eq!(res.status, 0);
        assert_no_data_for_session(&store, session).await;
        assert!(daemon.is_alive(), "daemon died on null hook_event_name");
        assert_valid_processing_still_works(&daemon, "probe-03").await;
    }

    // -- Case 4: wrong-type fields ------------------------------------------
    {
        let session = "case-04-wrong-types";
        let res = send_hook(
            &daemon,
            serde_json::json!({
                "hook_event_name": "PostToolUse",
                "session_id": session,
                "tool_name": "Bash",
                "tool_input": "not-an-object",
                "tool_response": {"exit_code": "one"}
            })
            .to_string()
            .as_bytes(),
        );
        assert_eq!(res.status, 0);
        assert!(daemon.is_alive(), "daemon died on wrong-type fields");
        wait_for(Duration::from_secs(5), || async {
            !store
                .events_for_session(session)
                .await
                .expect("events")
                .is_empty()
        })
        .await;
        let events = store.events_for_session(session).await.expect("events");
        assert_eq!(
            events.len(),
            1,
            "the Event itself is still well-typed and lands"
        );
        assert_eq!(
            events[0].tool_input,
            Some(serde_json::Value::String("not-an-object".to_string())),
            "tool_input is stored as whatever JSON value it actually was, not coerced"
        );
        // exit_code "one" is not an i64 and the heuristic fallback also finds
        // no usable shape (no stdout/stderr/interrupted keys) -> no Evidence.
        let evidence = store
            .evidence_for_session(session)
            .await
            .expect("evidence")
            .evidence;
        assert!(
            evidence.is_empty(),
            "a non-numeric exit_code and no heuristic fields must not fabricate Evidence"
        );
        assert_valid_processing_still_works(&daemon, "probe-04").await;
    }

    // -- Case 5: unknown/extra fields alongside valid ones -----------------
    {
        let session = "case-05-extra-fields";
        let res = send_hook(
            &daemon,
            serde_json::json!({
                "hook_event_name": "PostToolUse",
                "session_id": session,
                "tool_name": "Bash",
                "tool_input": {"command": "pytest", "unexpected_field": {"nested": "junk"}},
                "tool_response": {"exit_code": 1},
                "totally_unrecognized_top_level_field": "should be ignored, not rejected",
                "another_one": [1, 2, 3]
            })
            .to_string()
            .as_bytes(),
        );
        assert_eq!(res.status, 0);
        assert!(daemon.is_alive(), "daemon died on extra fields");
        wait_for(Duration::from_secs(5), || async {
            !store
                .evidence_for_session(session)
                .await
                .expect("evidence")
                .evidence
                .is_empty()
        })
        .await;
        let evidence = store
            .evidence_for_session(session)
            .await
            .expect("evidence")
            .evidence;
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].payload["exit_code"], 1);
        assert_valid_processing_still_works(&daemon, "probe-05").await;
    }

    // -- Case 6: deeply nested JSON -----------------------------------------
    {
        // 60 levels: must be processed exactly like any other well-formed
        // input (task's literal ask: "50+ levels").
        let session = "case-06-nested-60";
        let nested = nested_object(60);
        let res = send_hook(
            &daemon,
            serde_json::json!({
                "hook_event_name": "PostToolUse",
                "session_id": session,
                "tool_name": "Bash",
                "tool_input": {"command": "pytest", "nested": nested},
                "tool_response": {"exit_code": 1}
            })
            .to_string()
            .as_bytes(),
        );
        assert_eq!(res.status, 0);
        assert!(daemon.is_alive(), "daemon died on 60-level nesting");
        wait_for(Duration::from_secs(5), || async {
            !store
                .evidence_for_session(session)
                .await
                .expect("evidence")
                .evidence
                .is_empty()
        })
        .await;
        assert_valid_processing_still_works(&daemon, "probe-06a").await;

        // 3000 levels: informational stretch beyond the literal ask, only to
        // confirm depth is bounded (by a parser/serializer guard, or simply
        // by not exhausting the stack at this depth) before it becomes a
        // stack-overflow risk in fornax's own recursive code
        // (`redact_json`). Not a requirement that it succeeds — only that it
        // never crashes the daemon.
        //
        // Built as a raw JSON *string* (prefix/suffix concatenation), not
        // via `serde_json::json!`/`Value` construction: hand-building a
        // 3000-deep `Value` tree and then dropping it inside *this test's
        // own* tokio worker thread reliably stack-overflows this test
        // process itself (confirmed while building this harness — Rust's
        // derived `Drop` for a recursive enum has no depth guard, unlike
        // `fornax-hook-claude`'s parse-from-text path, which was separately
        // confirmed by hand to survive even 500,000 levels). Avoiding ever
        // materializing the nested `Value` natively in this process's
        // memory sidesteps that self-inflicted overflow entirely.
        let session_deep = "case-06-nested-3000";
        let nested_deep_json = format!("{}\"leaf\"{}", "{\"n\":".repeat(3000), "}".repeat(3000));
        let payload_deep = format!(
            r#"{{"hook_event_name":"PostToolUse","session_id":"{session_deep}","tool_name":"Bash","tool_input":{{"command":"pytest","nested":{nested_deep_json}}},"tool_response":{{"exit_code":1}}}}"#
        );
        let res_deep = send_hook(&daemon, payload_deep.as_bytes());
        assert_eq!(res_deep.status, 0, "hook must still exit 0 at 3000 levels");
        assert!(daemon.is_alive(), "daemon died on 3000-level nesting");
        assert_valid_processing_still_works(&daemon, "probe-06b").await;
    }

    // -- Case 7: unusually large string (5MB) -------------------------------
    {
        let session = "case-07-large-string";
        let big = "A".repeat(5 * 1024 * 1024);
        let res = send_hook(
            &daemon,
            serde_json::json!({
                "hook_event_name": "PostToolUse",
                "session_id": session,
                "tool_name": "Bash",
                "tool_input": {"command": "pytest", "giant": big},
                "tool_response": {"exit_code": 1}
            })
            .to_string()
            .as_bytes(),
        );
        assert_eq!(res.status, 0);
        assert!(daemon.is_alive(), "daemon died on 5MB string field");
        wait_for(Duration::from_secs(10), || async {
            !store
                .evidence_for_session(session)
                .await
                .expect("evidence")
                .evidence
                .is_empty()
        })
        .await;
        assert_valid_processing_still_works(&daemon, "probe-07").await;
    }

    // -- Case 8: control characters and embedded newlines -------------------
    {
        let session = "case-08-control-chars";
        let nasty = "line1\nline2\u{0000}\u{001b}[31mred\u{001b}[0m\ttab\rcr";
        let res = send_hook(
            &daemon,
            serde_json::json!({
                "hook_event_name": "PostToolUse",
                "session_id": session,
                "tool_name": "Bash",
                "tool_input": {"command": nasty},
                "tool_response": {"stdout": "", "stderr": nasty, "interrupted": false}
            })
            .to_string()
            .as_bytes(),
        );
        assert_eq!(res.status, 0);
        assert!(
            daemon.is_alive(),
            "daemon died on embedded control characters"
        );
        wait_for(Duration::from_secs(5), || async {
            !store
                .evidence_for_session(session)
                .await
                .expect("evidence")
                .evidence
                .is_empty()
        })
        .await;
        let evidence = store
            .evidence_for_session(session)
            .await
            .expect("evidence")
            .evidence;
        assert_eq!(evidence.len(), 1);
        // stderr is non-empty -> heuristic exit_code=1, regardless of its
        // exact (redacted or not) content: proves the control characters
        // never broke the UDS line-based framing (JSON escaping keeps them
        // out of the wire's newline-delimited protocol).
        assert_eq!(evidence[0].payload["exit_code"], 1);
        assert_valid_processing_still_works(&daemon, "probe-08").await;
    }

    // -- Case 9: path-traversal-looking strings ------------------------------
    {
        // 9a: inert fields (session_id, tool_input.command) — these are only
        // ever used as a SQL bind parameter / stored JSON value, never as a
        // filesystem path. Confirm no traversal-shaped path is created
        // anywhere under $FORNAX_HOME.
        let traversal_session = "../../../../etc/passwd";
        let res = send_hook(
            &daemon,
            serde_json::json!({
                "hook_event_name": "PostToolUse",
                "session_id": traversal_session,
                "tool_name": "Bash",
                "tool_input": {"command": "../../../../etc/passwd", "path": "/etc/passwd"},
                "tool_response": {"exit_code": 1}
            })
            .to_string()
            .as_bytes(),
        );
        assert_eq!(res.status, 0);
        assert!(
            daemon.is_alive(),
            "daemon died on path-traversal-looking session_id"
        );
        wait_for(Duration::from_secs(5), || async {
            !store
                .evidence_for_session(traversal_session)
                .await
                .expect("evidence")
                .evidence
                .is_empty()
        })
        .await;
        assert_no_unexpected_paths_created(&daemon);

        // 9b: the *real* filesystem surface — `Stop`'s `transcript_path` is
        // read verbatim via `std::fs::read_to_string`, with no confinement
        // to $FORNAX_HOME. Documented as an Informational observation in the
        // PR body — not a crash, not privilege escalation (the hook already
        // runs as the interactive user with their own file access), but a
        // real "read whatever path the hook JSON names" primitive.
        //
        // 9b-i: an actual sensitive path that won't parse as the expected
        // JSONL transcript shape — read is attempted, nothing bad happens,
        // no claim is fabricated from it.
        let res_etc = send_hook(
            &daemon,
            serde_json::json!({
                "hook_event_name": "Stop",
                "session_id": "case-09b-etc-passwd",
                "transcript_path": "/etc/passwd"
            })
            .to_string()
            .as_bytes(),
        );
        assert_eq!(res_etc.status, 0);
        assert!(
            daemon.is_alive(),
            "daemon died reading /etc/passwd as a transcript"
        );
        // The bare `Stop` Event is still recorded (translate() always emits
        // one for a recognized hook_event_name) — what must NOT happen is a
        // Claim fabricated from /etc/passwd's content, since it never
        // parses as the expected per-line JSONL transcript shape.
        wait_for(Duration::from_secs(5), || async {
            !store
                .events_for_session("case-09b-etc-passwd")
                .await
                .expect("events")
                .is_empty()
        })
        .await;
        assert!(
            store
                .claims_for_session("case-09b-etc-passwd")
                .await
                .expect("claims")
                .is_empty(),
            "/etc/passwd's content must never be turned into a fabricated Claim"
        );

        // 9b-ii: a validly-shaped JSONL transcript placed *outside*
        // $FORNAX_HOME, referenced by an absolute path with a `../../`
        // traversal component — proves content from arbitrary readable
        // paths does reach the claims table when it happens to parse.
        let outside_dir = std::env::temp_dir().join(format!(
            "fornax-adversarial-outside-home-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(outside_dir.join("nested/deeper")).unwrap();
        let outside_transcript = outside_dir.join("nested/deeper/transcript.jsonl");
        std::fs::write(
            &outside_transcript,
            serde_json::json!({
                "type": "assistant",
                "message": {"content": [{"type": "text", "text": "tests passed via traversal"}]}
            })
            .to_string(),
        )
        .unwrap();
        let traversal_path =
            outside_dir.join("nested/deeper/../deeper/../../nested/deeper/transcript.jsonl");
        let session_traversal_read = "case-09b-traversal-read";
        let res_traverse = send_hook(
            &daemon,
            serde_json::json!({
                "hook_event_name": "Stop",
                "session_id": session_traversal_read,
                "transcript_path": traversal_path.to_str().unwrap()
            })
            .to_string()
            .as_bytes(),
        );
        assert_eq!(res_traverse.status, 0);
        assert!(
            daemon.is_alive(),
            "daemon died reading traversal-path transcript"
        );
        wait_for(Duration::from_secs(5), || async {
            !store
                .claims_for_session(session_traversal_read)
                .await
                .expect("claims")
                .is_empty()
        })
        .await;
        let claims = store
            .claims_for_session(session_traversal_read)
            .await
            .expect("claims");
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].text, "tests passed via traversal");
        std::fs::remove_dir_all(&outside_dir).ok();

        assert_valid_processing_still_works(&daemon, "probe-09").await;
    }

    // -- Case 10: shell metacharacters --------------------------------------
    {
        let session = "case-10-shell-meta";
        let payload = "; rm -rf / #";
        let res = send_hook(
            &daemon,
            serde_json::json!({
                "hook_event_name": "PostToolUse",
                "session_id": session,
                "tool_name": "Bash",
                "tool_input": {"command": format!("echo hi {payload} $(whoami) `id` | cat")},
                "tool_response": {"exit_code": 1}
            })
            .to_string()
            .as_bytes(),
        );
        assert_eq!(res.status, 0);
        assert!(daemon.is_alive(), "daemon died on shell metacharacters");
        wait_for(Duration::from_secs(5), || async {
            !store
                .events_for_session(session)
                .await
                .expect("events")
                .is_empty()
        })
        .await;
        let events = store.events_for_session(session).await.expect("events");
        // Stored as an inert JSON string, never executed: this repo has zero
        // std::process::Command surface in production code (asserted in
        // `subprocess_surface_is_still_zero_in_production_code`), so there
        // is no path by which this string could ever be interpreted by a
        // shell.
        assert!(events[0]
            .tool_input
            .as_ref()
            .unwrap()
            .get("command")
            .unwrap()
            .as_str()
            .unwrap()
            .contains("rm -rf"));
        assert_valid_processing_still_works(&daemon, "probe-10").await;
    }

    // -- Case 11: duplicate / replayed valid event -------------------------
    {
        let session = "case-11-replay";
        let transcript_path = daemon.home.join("case-11-transcript.jsonl");
        std::fs::write(
            &transcript_path,
            serde_json::json!({
                "type": "assistant",
                "message": {"content": [{"type": "text", "text": "All tests passed."}]}
            })
            .to_string(),
        )
        .unwrap();
        let post_payload = serde_json::json!({
            "hook_event_name": "PostToolUse",
            "session_id": session,
            "tool_name": "Bash",
            "tool_input": {"command": "cargo test --workspace"},
            "tool_response": {"exit_code": 1, "stdout": "", "stderr": "test failed"}
        })
        .to_string();
        let stop_payload = serde_json::json!({
            "hook_event_name": "Stop",
            "session_id": session,
            "transcript_path": transcript_path.to_str().unwrap()
        })
        .to_string();

        for _ in 0..2 {
            let r1 = send_hook(&daemon, post_payload.as_bytes());
            assert_eq!(r1.status, 0);
            let r2 = send_hook(&daemon, stop_payload.as_bytes());
            assert_eq!(r2.status, 0);
        }
        assert!(
            daemon.is_alive(),
            "daemon died on replayed identical event pair"
        );

        wait_for(Duration::from_secs(5), || async {
            store
                .claims_for_session(session)
                .await
                .expect("claims")
                .len()
                == 2
        })
        .await;
        let claims = store.claims_for_session(session).await.expect("claims");
        assert_eq!(
            claims.len(),
            2,
            "replay is additive by design (fresh UUID per event)"
        );
        assert_ne!(claims[0].id, claims[1].id);

        // Both claims are identical text under the same session, so both
        // should independently verify — no error, no dedupe, no corruption.
        wait_for(Duration::from_secs(5), || async {
            daemon.log_contents().matches("finding computed").count() >= 2
        })
        .await;
        assert_valid_processing_still_works(&daemon, "probe-11").await;
    }

    // -- Case 12: extreme identifiers ---------------------------------------
    // (Timestamps are not attacker-influenced anywhere in this adapter: every
    // observed_at/claimed_at value is `chrono::Utc::now()` computed locally
    // at translate() time, never read from the hook JSON — so there is no
    // "extreme timestamp" surface to probe here.)
    {
        let huge_session = "x".repeat(100 * 1024);
        let res = send_hook(
            &daemon,
            serde_json::json!({
                "hook_event_name": "PostToolUse",
                "session_id": huge_session,
                "tool_name": "Bash",
                "tool_input": {"command": "pytest"},
                "tool_response": {"exit_code": 1}
            })
            .to_string()
            .as_bytes(),
        );
        assert_eq!(res.status, 0);
        assert!(daemon.is_alive(), "daemon died on a 100KB session_id");
        wait_for(Duration::from_secs(5), || async {
            !store
                .evidence_for_session(&huge_session)
                .await
                .expect("evidence")
                .evidence
                .is_empty()
        })
        .await;
        let evidence = store
            .evidence_for_session(&huge_session)
            .await
            .expect("evidence")
            .evidence;
        assert_eq!(evidence.len(), 1);
        assert_valid_processing_still_works(&daemon, "probe-12").await;
    }

    // Final liveness + no-corruption confirmation for the whole run.
    assert!(
        daemon.is_alive(),
        "daemon must still be alive after the full corpus"
    );
    assert_valid_processing_still_works(&daemon, "probe-final").await;
}

/// FORNX-238 acceptance also asks to re-confirm this repo's zero
/// `std::process::Command`/`sh -c` surface still holds in *production* code
/// (this test file itself uses `std::process::Command` deliberately, to
/// drive the real binaries end-to-end black-box — that is not part of the
/// claim being checked here, and is excluded by the `tests/` path check
/// below).
#[test]
fn subprocess_surface_is_still_zero_in_production_code() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/<name> is two levels below the workspace root");
    let crates_dir = workspace_root.join("crates");

    let mut offenders = Vec::new();
    visit_rs_files(&crates_dir, &mut |path| {
        if path.components().any(|c| c.as_os_str() == "tests") {
            return;
        }
        let contents = std::fs::read_to_string(path).unwrap_or_default();
        // Coarse but sufficient: this repo's convention (confirmed by
        // inspection) is that no production module contains a `mod tests`
        // block using process spawning either, so a plain substring scan
        // over the whole file is an accurate proxy without needing a real
        // Rust parser.
        for (i, line) in contents.lines().enumerate() {
            if line.contains("process::Command")
                || line.contains("Command::new")
                || line.contains("sh -c")
            {
                offenders.push(format!("{}:{}: {}", path.display(), i + 1, line.trim()));
            }
        }
    });

    assert!(
        offenders.is_empty(),
        "found subprocess-spawn surface in production fornax-core code:\n{}",
        offenders.join("\n")
    );
}

fn visit_rs_files(dir: &Path, f: &mut impl FnMut(&Path)) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().map(|n| n == "target").unwrap_or(false) {
                continue;
            }
            visit_rs_files(&path, f);
        } else if path.extension().map(|e| e == "rs").unwrap_or(false) {
            f(&path);
        }
    }
}

/// Nothing this corpus sends should ever cause a file to be created outside
/// `$FORNAX_HOME` as a side effect of a path-traversal-looking *value*
/// stored in the DB (as opposed to `transcript_path`, which is a real,
/// deliberate read surface documented separately) — the daemon never writes
/// anywhere except its own SQLite file/WAL/SHM under `$FORNAX_HOME`.
fn assert_no_unexpected_paths_created(daemon: &DaemonHandle) {
    let entries: Vec<_> = std::fs::read_dir(&daemon.home)
        .expect("read FORNAX_HOME")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    for name in &entries {
        assert!(
            !name.contains(".."),
            "unexpected traversal-shaped file created under FORNAX_HOME: {name}"
        );
    }
}

/// Ask the OS for an ephemeral port by binding to port 0, then release it
/// immediately for the daemon to bind moments later. A tiny TOCTOU window
/// exists (another process could grab the port in between) but is far safer
/// than a fixed port that reliably collides with a leaked prior-run daemon.
fn free_tcp_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local addr").port()
}

/// Short enough that `$FORNAX_HOME/fornax.sock` never risks `sockaddr_un`'s
/// `SUN_LEN` cap — see the comment in `start_daemon`.
fn short_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..8].to_string()
}

fn nested_object(depth: usize) -> serde_json::Value {
    let mut v = serde_json::json!("leaf");
    for _ in 0..depth {
        v = serde_json::json!({ "n": v });
    }
    v
}
