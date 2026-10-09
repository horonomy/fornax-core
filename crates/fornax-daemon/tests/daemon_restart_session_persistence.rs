//! HORO-1604 multi-session matrix items 7 ("session resume/continue") and
//! 10 ("process restart"): a real `fornax-daemon` process restarted on the
//! *same* `$FORNAX_HOME` must still answer each pre-existing session's own
//! `/api/status?session=<id>` with that session's own verdict, never a
//! different session's, and never fall back to a stale or globally-latest
//! answer just because its in-memory `AppState::caps` cache (see
//! `crates/fornax-daemon/src/main.rs`'s `AppState`) is empty again after
//! restart.
//!
//! No existing test restarts the daemon binary. `cross_session_identity_handshake.rs`
//! and `concurrent_hook_submission.rs` always start *fresh*, distinct
//! `$FORNAX_HOME`s per daemon — they never kill and relaunch one daemon
//! against the SQLite file a prior instance of itself already wrote. That
//! is the one property this file adds: the daemon's per-session verdict
//! state is fully owned by the durable store, not by anything living only
//! in the restarted process's own memory.
//!
//! Seeds two sessions' claims/findings directly via `fornax_store::Store`
//! (not through the real verification pipeline) for the same determinism
//! reason given in `crates/fornax-daemon/src/main.rs`'s
//! `api_status_with_session_confirms_scoping_and_isolates_sessions`: this
//! test is about restart/persistence behavior at the HTTP route, not about
//! exercising the verifiers.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use fornax_store::Store;
use fornax_types::{AgentEvent, Claim, EventKind, Finding, Provider, Verdict};
use uuid::Uuid;

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
    log_path: PathBuf,
}

impl DaemonHandle {
    fn is_alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    fn log_contents(&self) -> String {
        std::fs::read_to_string(&self.log_path).unwrap_or_default()
    }

    async fn kill_and_wait(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        // Don't let `Drop` also try to remove `self.home` — the restarted
        // daemon in this test reuses it.
        std::mem::forget(self);
    }
}

impl Drop for DaemonHandle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_tcp_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local addr").port()
}

fn short_id() -> String {
    Uuid::new_v4().simple().to_string()[..8].to_string()
}

/// Launches `fornax-daemon` against `home` on `port`, waiting until it
/// actually answers `fornax status` before returning — same readiness
/// convention as `cross_session_identity_handshake.rs`.
async fn start_daemon(home: &Path, port: u16) -> DaemonHandle {
    let log_path = home.join("daemon.log");
    let log_file = std::fs::File::create(&log_path).expect("create daemon log file");
    let log_file_err = log_file.try_clone().expect("clone log file handle");

    let child = Command::new(workspace_bin("fornax-daemon"))
        .env("FORNAX_HOME", home)
        .env("FORNAX_HTTP_PORT", port.to_string())
        .env("RUST_LOG", "info")
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_file_err))
        .stdin(Stdio::null())
        .spawn()
        .expect("spawn fornax-daemon");

    let mut handle = DaemonHandle { child, log_path };

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if !handle.is_alive() {
            panic!(
                "daemon exited during startup; log:\n{}",
                handle.log_contents()
            );
        }
        if fornax_status_output(home, port) != "🛡 fornax: daemon unreachable" {
            break;
        }
        if tokio::time::Instant::now() > deadline {
            panic!(
                "daemon never became reachable; log:\n{}",
                handle.log_contents()
            );
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    handle
}

fn fornax_status_output(home: &Path, port: u16) -> String {
    let out = Command::new(workspace_bin("fornax"))
        .arg("status")
        .env("FORNAX_HOME", home)
        .env("FORNAX_HTTP_PORT", port.to_string())
        .output()
        .expect("run fornax status");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Raw `GET /api/status?session=<id>` against the real HTTP port, returning
/// the decoded JSON body. Avoids adding an HTTP client dependency, matching
/// `cross_session_identity_handshake.rs`'s `raw_get_headers` convention.
fn api_status_for_session(port: u16, session_id: &str) -> serde_json::Value {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let request = format!(
        "GET /api/status?session={session_id} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).expect("write request");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read response");
    let body = response
        .split("\r\n\r\n")
        .nth(1)
        .expect("response must have a body");
    serde_json::from_str(body).unwrap_or_else(|e| panic!("body was not JSON: {e}\n{body}"))
}

async fn seed_session_verdict(
    store: &Store,
    session_id: &str,
    verdict: Verdict,
    observed_at: &str,
) {
    let event_id = Uuid::new_v4();
    store
        .insert_event(&AgentEvent {
            id: event_id,
            session_id: session_id.to_string(),
            provider: Provider::ClaudeCode,
            kind: EventKind::PostToolUse,
            observed_at: observed_at.to_string(),
            tool_name: Some("exec_command".to_string()),
            tool_input: None,
            tool_response: None,
            raw: serde_json::json!({}),
        })
        .await
        .expect("insert event");
    let claim_id = Uuid::new_v4();
    store
        .insert_claim(&Claim {
            id: claim_id,
            session_id: session_id.to_string(),
            source_event_id: event_id,
            text: "claim text".to_string(),
            subject: "test_result".to_string(),
            claimed_at: observed_at.to_string(),
        })
        .await
        .expect("insert claim");
    store
        .insert_finding(&Finding {
            id: Uuid::new_v4(),
            claim_id,
            verdict,
            evidence_ids: vec![],
            verifier_name: "test_result_verifier_v1".to_string(),
            rationale: "test".to_string(),
            computed_at: observed_at.to_string(),
        })
        .await
        .expect("insert finding");
}

/// The core HORO-1604 matrix proof: restart the daemon on the same
/// `$FORNAX_HOME`/SQLite file, with two sessions' *different* verdicts
/// committed during the FIRST instance's own lifetime, and confirm each
/// session still sees only its own verdict after a kill + relaunch of a
/// second instance against that same file -- resume/continue (item 7) and
/// process restart (item 10) together, since restart is strictly the
/// harder case resume already implies.
///
/// Deliberately seeds AFTER the first daemon is already up, not before: a
/// startup step that silently clears persisted findings (a realistic
/// regression -- e.g. an over-eager "reset on launch" migration/cleanup
/// step) would be a no-op against an empty table on the very first start,
/// so seeding before that point would never exercise it. Seeding only after
/// the first instance is confirmed live is what makes the second instance's
/// startup the one place such a bug could actually bite -- see this test's
/// own mutation evidence in the PR description.
#[tokio::test]
async fn each_sessions_own_verdict_survives_a_real_daemon_restart() {
    let home = PathBuf::from("/tmp").join(format!("fnx-restart-{}", short_id()));
    std::fs::create_dir_all(&home).expect("create scratch FORNAX_HOME");
    let port_before = free_tcp_port();
    let db_path = home.join("fornax.db");

    let daemon = start_daemon(&home, port_before).await;

    // Seed two sessions with distinct verdicts directly against the same
    // database file the already-running daemon opened in WAL mode
    // (`crates/fornax-store/src/lib.rs`'s `Store::open` -- WAL mode is what
    // makes a second connection to the same file from this test process
    // safe here). This test is about restart/persistence at the HTTP
    // route, not about exercising the verifiers -- same determinism
    // reasoning as `crates/fornax-daemon/src/main.rs`'s
    // `api_status_with_session_confirms_scoping_and_isolates_sessions`.
    {
        let store = Store::open(&db_path).await.expect("open db to seed");
        seed_session_verdict(
            &store,
            "sess-restart-a",
            Verdict::Verified,
            "2026-01-01T00:00:01Z",
        )
        .await;
        seed_session_verdict(
            &store,
            "sess-restart-b",
            Verdict::Contradicted,
            "2026-01-01T00:00:02Z",
        )
        .await;
    }

    // Sanity before restart: each session already sees its own verdict,
    // not the other's, through the real running process.
    let a_before = api_status_for_session(port_before, "sess-restart-a");
    let b_before = api_status_for_session(port_before, "sess-restart-b");
    assert_eq!(
        a_before["latest"]["verdict"], "verified",
        "sanity before restart: {a_before}"
    );
    assert_eq!(
        b_before["latest"]["verdict"], "contradicted",
        "sanity before restart: {b_before}"
    );

    daemon.kill_and_wait().await;

    // Relaunch on the SAME $FORNAX_HOME, deliberately on a different port
    // (the daemon in production always rebinds fresh; a different port
    // also proves nothing about this is riding leftover client-side state
    // from before the restart).
    let port_after = free_tcp_port();
    let restarted = start_daemon(&home, port_after).await;

    let a_after = api_status_for_session(port_after, "sess-restart-a");
    let b_after = api_status_for_session(port_after, "sess-restart-b");

    assert_eq!(
        a_after["session_scoped"], true,
        "restarted daemon must still confirm session scoping: {a_after}"
    );
    assert_eq!(
        a_after["latest"]["verdict"], "verified",
        "session A's verdict must survive a real daemon restart unchanged: {a_after}"
    );
    assert_eq!(
        b_after["latest"]["verdict"], "contradicted",
        "session B's verdict must survive a real daemon restart unchanged: {b_after}"
    );
    assert_ne!(
        a_after["latest"]["verdict"], b_after["latest"]["verdict"],
        "the two sessions' verdicts must remain distinct after restart, not collapsed onto \
         whichever is globally latest: {a_after} vs {b_after}"
    );

    restarted.kill_and_wait().await;
    std::fs::remove_dir_all(&home).ok();
}
