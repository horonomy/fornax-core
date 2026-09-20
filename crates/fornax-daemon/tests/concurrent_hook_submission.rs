//! FORNX-13 gap closure: "WAL/concurrency behavior is tested under realistic
//! hook submission concurrency" was an unchecked acceptance criterion — no
//! test exercised the daemon's serialization (see `AppState::processing` in
//! `crates/fornax-daemon/src/main.rs`, added for FORNX-281) under *real*
//! concurrent hook submissions. This closes that gap against a live daemon
//! process, mirroring `adversarial_daemon_input.rs`'s harness shape (real
//! `fornax-daemon` + `fornax-hook-claude` binaries, isolated
//! `$FORNAX_HOME`, bounded async polling, no fixed sleeps) rather than
//! calling `handle_message` in-process, which would prove nothing about
//! real OS-level connection races.
//!
//! Two concurrency shapes are exercised:
//! 1. Many independent sessions submitted at once (cross-session isolation
//!    under load: no session's events/claims/findings bleed into another's).
//! 2. A two-phase barrier across many sessions: every session's PostToolUse
//!    fired as N truly-concurrent connections, then (once every session's
//!    Evidence is confirmed durable) every session's Stop fired as N more
//!    truly-concurrent connections — maximizing real contention on the
//!    daemon's single global `processing` mutex while keeping each
//!    session's own Evidence-before-Claim ordering an actual host-side
//!    guarantee rather than a hopeful race. A genuinely simultaneous
//!    Post/Stop race for the *same* session was deliberately not used here:
//!    the daemon has no ordering contract between two independently-opened
//!    connections with no temporal precedence between them (see
//!    `handle_message`'s doc comment — the mutex serializes *processing*,
//!    it does not reorder arrival), so asserting a specific verdict for
//!    that case would be asserting behavior nothing promises.
//!
//! Test-only `std::process::Command` use here does not touch fornax-core's
//! production zero-subprocess-spawn invariant, exactly as in
//! `adversarial_daemon_input.rs` (that invariant is asserted there, by
//! source inspection of the production crates; not duplicated here).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use fornax_store::Store;

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

/// See the equivalent function in `adversarial_daemon_input.rs` for why
/// `/tmp` (not `std::env::temp_dir()`) and an OS-assigned ephemeral port.
async fn start_daemon() -> DaemonHandle {
    let home = PathBuf::from("/tmp").join(format!("fnx-conc-{}", short_id()));
    std::fs::create_dir_all(&home).expect("create scratch FORNAX_HOME");
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

/// Fire-and-forget from the caller's point of view except for the exit
/// code: spawns its own fresh `fornax-hook-claude` process/UDS connection,
/// exactly as a real Claude Code hook invocation would — this is the unit
/// of concurrency the test races. Takes `$FORNAX_HOME` directly (not a
/// `DaemonHandle`) so it can be called from a `spawn_blocking` closure that
/// only owns the handful of plain, `Send`-friendly values it needs.
fn send_hook(home: &Path, stdin: &[u8]) -> i32 {
    let mut child = Command::new(workspace_bin("fornax-hook-claude"))
        .env("FORNAX_HOME", home)
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
    out.status.code().unwrap_or(-1)
}

async fn open_store(daemon: &DaemonHandle) -> Store {
    Store::open(daemon.home.join("fornax.db"))
        .await
        .expect("open store db")
}

fn free_tcp_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local addr").port()
}

fn short_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..8].to_string()
}

fn post_tool_use_payload(session_id: &str, exit_code: i64) -> Vec<u8> {
    serde_json::json!({
        "hook_event_name": "PostToolUse",
        "session_id": session_id,
        "tool_name": "Bash",
        "tool_input": {"command": "cargo test --workspace"},
        "tool_response": {"exit_code": exit_code, "stdout": "", "stderr": ""}
    })
    .to_string()
    .into_bytes()
}

fn stop_payload(transcript_path: &Path, session_id: &str) -> Vec<u8> {
    serde_json::json!({
        "hook_event_name": "Stop",
        "session_id": session_id,
        "transcript_path": transcript_path.to_str().unwrap()
    })
    .to_string()
    .into_bytes()
}

fn write_passed_transcript(home: &Path, session_id: &str) -> PathBuf {
    let transcript_path = home.join(format!("{session_id}-transcript.jsonl"));
    std::fs::write(
        &transcript_path,
        serde_json::json!({
            "type": "assistant",
            "message": {"content": [{"type": "text", "text": "All tests passed."}]}
        })
        .to_string(),
    )
    .expect("write transcript");
    transcript_path
}

/// Concurrency shape 1: N independent sessions, each a complete
/// PostToolUse(exit 0) + Stop("All tests passed") pair, all launched at
/// once (not sequentially awaited) so their OS processes/UDS connections
/// genuinely overlap. Every session must end up with exactly its own
/// event/claim/finding — none lost, none bled into another session.
#[tokio::test]
async fn independent_sessions_submitted_concurrently_are_not_lost_or_mixed_up() {
    let daemon = start_daemon().await;
    let store = open_store(&daemon).await;

    const N: usize = 10;
    let sessions: Vec<String> = (0..N)
        .map(|i| format!("concurrent-independent-{i}-{}", short_id()))
        .collect();

    // Pre-write every transcript before racing the hooks themselves — file
    // creation is not the concurrency behavior under test.
    let transcripts: Vec<PathBuf> = sessions
        .iter()
        .map(|s| write_passed_transcript(&daemon.home, s))
        .collect();

    let mut tasks = tokio::task::JoinSet::new();
    for (session, transcript_path) in sessions.iter().cloned().zip(transcripts.iter().cloned()) {
        let home = daemon.home.clone();
        tasks.spawn_blocking(move || {
            let post = send_hook(&home, &post_tool_use_payload(&session, 0));
            let stop = send_hook(&home, &stop_payload(&transcript_path, &session));
            (session, post, stop)
        });
    }
    while let Some(res) = tasks.join_next().await {
        let (session, post_status, stop_status) = res.expect("hook task panicked");
        assert_eq!(post_status, 0, "PostToolUse hook failed for {session}");
        assert_eq!(stop_status, 0, "Stop hook failed for {session}");
    }

    for session in &sessions {
        wait_for(Duration::from_secs(15), || {
            let store = &store;
            let session = session.clone();
            async move {
                !store
                    .claims_for_session(&session)
                    .await
                    .expect("claims")
                    .is_empty()
            }
        })
        .await;

        let events = store
            .events_for_session(session)
            .await
            .expect("events for session");
        // One PostToolUse (the adapter's normalization of the tool-call
        // event) plus one SessionEnd (the adapter's normalization of the
        // Stop hook itself, independent of the Claim it also extracts) —
        // exactly this session's own two events, none lost, none
        // duplicated, none bled in from another concurrently-submitted
        // session.
        assert_eq!(
            events.len(),
            2,
            "session {session} should have exactly its own two events, got {events:?}"
        );

        let claims = store
            .claims_for_session(session)
            .await
            .expect("claims for session");
        assert_eq!(
            claims.len(),
            1,
            "session {session} should have exactly its own one claim"
        );
        assert!(
            claims[0].text.contains("All tests passed"),
            "session {session} claim text corrupted/mixed up: {}",
            claims[0].text
        );

        let findings: Vec<_> = store
            .recent_findings(500)
            .await
            .expect("recent findings")
            .into_iter()
            .filter(|f| f.session_id == *session)
            .collect();
        assert_eq!(
            findings.len(),
            1,
            "session {session} should produce exactly its own one finding"
        );
        assert_eq!(
            findings[0].verdict, "verified",
            "session {session}: a concurrently-submitted PostToolUse(exit 0) + Stop pair \
             should resolve VERIFIED, not {:?}",
            findings[0].verdict
        );
    }
}

/// Concurrency shape 2: a two-phase barrier across many sessions at once —
/// phase 1 fires every session's PostToolUse (the Evidence a Claim needs)
/// as N truly-concurrent OS processes/connections and waits for the store
/// to actually contain all N rows (not just "the hook process exited",
/// which only proves the bytes left the client — the daemon is
/// fire-and-forget with no ack, exactly per the `processing` field's doc
/// comment in `main.rs`); phase 2 then fires every session's Stop as N more
/// truly-concurrent connections. This is the realistic shape of the
/// FORNX-281 hazard: many *different* sessions' Events and Claims all
/// contending for the same global `processing` mutex at once, with each
/// individual session's own Claim only ever dispatched (host-side) after
/// its own Evidence — if the mutex ever let two `handle_message` calls
/// interleave instead of fully serializing, some session here would
/// observe a torn/partial write or an evidence-before-claim ordering
/// violation instead of a clean, deterministic `VERIFIED`.
#[tokio::test]
async fn many_sessions_evidence_then_claim_phases_stay_serialized_under_contention() {
    let daemon = start_daemon().await;
    let store = open_store(&daemon).await;

    const N: usize = 10;
    let sessions: Vec<String> = (0..N)
        .map(|i| format!("concurrent-phased-{i}-{}", short_id()))
        .collect();
    let transcripts: Vec<PathBuf> = sessions
        .iter()
        .map(|s| write_passed_transcript(&daemon.home, s))
        .collect();

    // Phase 1: N PostToolUse hooks, one per session, all dispatched at once.
    let mut post_tasks = tokio::task::JoinSet::new();
    for session in &sessions {
        let home = daemon.home.clone();
        let session = session.clone();
        post_tasks.spawn_blocking(move || send_hook(&home, &post_tool_use_payload(&session, 0)));
    }
    while let Some(res) = post_tasks.join_next().await {
        assert_eq!(
            res.expect("post task panicked"),
            0,
            "a PostToolUse hook failed"
        );
    }

    // Barrier: don't start phase 2 until every session's Evidence is
    // actually durable — a real synchronization point, not a guess at
    // timing. This is what makes phase 2's "PostToolUse precedes Stop for
    // this session" true in substance, not just in dispatch order.
    for session in &sessions {
        wait_for(Duration::from_secs(15), || {
            let store = &store;
            let session = session.clone();
            async move {
                !store
                    .events_for_session(&session)
                    .await
                    .expect("events")
                    .is_empty()
            }
        })
        .await;
    }

    // Phase 2: N Stop hooks, one per session, all dispatched at once —
    // every one of these Claims now genuinely races N-1 *other* sessions'
    // Claims for the daemon's single global `processing` mutex.
    let mut stop_tasks = tokio::task::JoinSet::new();
    for (session, transcript_path) in sessions.iter().cloned().zip(transcripts.iter().cloned()) {
        let home = daemon.home.clone();
        stop_tasks
            .spawn_blocking(move || send_hook(&home, &stop_payload(&transcript_path, &session)));
    }
    while let Some(res) = stop_tasks.join_next().await {
        assert_eq!(res.expect("stop task panicked"), 0, "a Stop hook failed");
    }

    for session in &sessions {
        wait_for(Duration::from_secs(15), || {
            let store = &store;
            let session = session.clone();
            async move {
                store
                    .recent_findings(500)
                    .await
                    .expect("recent findings")
                    .iter()
                    .any(|f| f.session_id == session)
            }
        })
        .await;

        let findings: Vec<_> = store
            .recent_findings(500)
            .await
            .expect("recent findings")
            .into_iter()
            .filter(|f| f.session_id == *session)
            .collect();
        assert_eq!(
            findings.len(),
            1,
            "session {session} should produce exactly one finding under contention"
        );
        assert_eq!(
            findings[0].verdict, "verified",
            "session {session}: concurrent multi-session contention on the processing mutex \
             must still resolve VERIFIED, not {:?} — a regression here means concurrent \
             Events/Claims from other sessions are corrupting or reordering this session's own \
             evidence-before-claim guarantee (FORNX-281)",
            findings[0].verdict
        );

        let events = store
            .events_for_session(session)
            .await
            .expect("events for session");
        assert_eq!(
            events.len(),
            2,
            "session {session} should have exactly its own two events under contention, got {events:?}"
        );
    }
}
