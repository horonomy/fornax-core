//! FORNX-212 gap closure: a malformed/unprocessable ingest line must not
//! silently vanish (previously `tracing::warn!` + drop, nothing queryable)
//! and must not stall any connection queued behind it. Exercised against a
//! real `fornax-daemon` process over its real UDS path -- not
//! `handle_message`/`process_line` called in-process, which would prove
//! nothing about the real connection-ordering/turn machinery.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use fornax_store::Store;
use fornax_types::{AgentEvent, EventKind, IngestMessage, Provider};
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
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
    home: PathBuf,
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

async fn start_daemon() -> DaemonHandle {
    let home = PathBuf::from("/tmp").join(format!("fnx-quar-{}", short_id()));
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
        log_path,
    };

    wait_for(Duration::from_secs(10), || {
        let alive = handle.is_alive();
        let ready = alive && handle.home.join("fornax.sock").exists();
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

fn free_tcp_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local addr").port()
}

fn short_id() -> String {
    Uuid::new_v4().simple().to_string()[..8].to_string()
}

async fn send_raw_line(home: &Path, line: &str) {
    let mut stream = UnixStream::connect(home.join("fornax.sock"))
        .await
        .expect("connect to daemon UDS socket");
    stream
        .write_all(line.as_bytes())
        .await
        .expect("write raw line");
    stream.write_all(b"\n").await.expect("write newline");
    stream.shutdown().await.expect("shutdown write half");
}

async fn send_event(home: &Path, session_id: &str) -> Uuid {
    let event = AgentEvent {
        id: Uuid::new_v4(),
        session_id: session_id.to_string(),
        provider: Provider::ClaudeCode,
        kind: EventKind::PostToolUse,
        observed_at: chrono::Utc::now().to_rfc3339(),
        tool_name: Some("fornx212-test-tool".to_string()),
        tool_input: Some(serde_json::json!({"ok": true})),
        tool_response: Some(serde_json::json!({"ok": true})),
        raw: serde_json::json!({"fornx212_test": true}),
    };
    let event_id = event.id;
    let msg = IngestMessage::Event(event);
    let line = serde_json::to_string(&msg).expect("serialize event");
    send_raw_line(home, &line).await;
    event_id
}

async fn open_store(daemon: &DaemonHandle) -> Store {
    Store::open(daemon.home.join("fornax.db"))
        .await
        .expect("open store db")
}

/// A malformed line (not valid JSON) must not stall the daemon's
/// single-accept-loop/turn-ordering machinery: a *subsequent* connection's
/// valid event must still commit, and the malformed line itself must land
/// in `ingest_quarantine` rather than vanishing.
#[tokio::test]
async fn malformed_line_is_quarantined_and_does_not_stall_later_connections() {
    let daemon = start_daemon().await;
    let store = open_store(&daemon).await;

    let before_count = store
        .quarantine_count()
        .await
        .expect("read quarantine count before");

    let marker = format!("fornx212-garbage-{}", short_id());
    // Not valid JSON at all -- the real-world case this closes is a
    // buggy/mismatched adapter sending a malformed line, not merely
    // unexpected-but-parseable JSON.
    let garbage_line = format!("{{not json at all, marker={marker}");
    send_raw_line(&daemon.home, &garbage_line).await;

    let session_id = format!("fornx212-session-{}", short_id());
    let event_id = send_event(&daemon.home, &session_id).await;

    // The valid event on a later connection must still commit -- proves
    // the poisoned line did not stall the turn/accept loop.
    let committed = wait_for_event(&store, &session_id, event_id, Duration::from_secs(5)).await;
    assert!(
        committed,
        "valid event sent after a malformed line never committed — \
         the malformed line appears to have stalled a later connection's turn"
    );

    // The malformed line itself must be durably recorded, not just
    // warned-and-dropped.
    wait_for(Duration::from_secs(5), || {
        let store = &store;
        let marker = marker.clone();
        async move {
            store
                .quarantine_count()
                .await
                .map(|c| c > before_count)
                .unwrap_or(false)
                && store
                    .list_quarantine(50)
                    .await
                    .map(|rows| {
                        rows.iter()
                            .any(|r| r.raw_line.contains(&marker) && r.reason_kind == "parse_error")
                    })
                    .unwrap_or(false)
        }
    })
    .await;
    // wait_for panics on timeout; reaching here means the quarantine row was found.
}

async fn wait_for_event(
    store: &Store,
    session_id: &str,
    event_id: Uuid,
    timeout: Duration,
) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Ok(events) = store.events_for_session(session_id).await {
            if events.iter().any(|e| e.id == event_id) {
                return true;
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
