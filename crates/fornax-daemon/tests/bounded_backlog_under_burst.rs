//! FORNX-212's last AC bullet: "Load/failure tests demonstrate bounded
//! memory/backlog behavior." `AppState::inflight`'s semaphore
//! (`MAX_INFLIGHT_CONNECTIONS = 256`, see `run_uds_server`'s doc comment in
//! `crates/fornax-daemon/src/main.rs`) already *structurally* bounds
//! concurrently-open connections — this test does not re-derive that from
//! first principles. What it proves instead, against a real daemon process
//! over the real UDS path: submitting well beyond that cap concurrently
//! (2x) does not lose a single event to the backpressure, and the backlog
//! drains within a bounded wall-clock time rather than stalling indefinitely
//! once the burst subsides. "Bounded memory" here is proven structurally
//! (the semaphore caps live connections, each with a fixed-size in-flight
//! buffer) rather than by sampling process RSS, which this crate's test
//! suite has no portable, non-flaky way to do — stated plainly rather than
//! left implicit.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

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
    let home = PathBuf::from("/tmp").join(format!("fnx-burst-{}", short_id()));
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
    let deadline = Instant::now() + timeout;
    loop {
        if check().await {
            return;
        }
        if Instant::now() > deadline {
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

async fn submit_event(sock_path: &Path, session_id: &str) -> Uuid {
    let event = AgentEvent {
        id: Uuid::new_v4(),
        session_id: session_id.to_string(),
        provider: Provider::ClaudeCode,
        kind: EventKind::PostToolUse,
        observed_at: chrono::Utc::now().to_rfc3339(),
        tool_name: Some("fornx212-burst-tool".to_string()),
        tool_input: Some(serde_json::json!({"synthetic": true})),
        tool_response: Some(serde_json::json!({"ok": true})),
        raw: serde_json::json!({"synthetic_test": "bounded_backlog_under_burst"}),
    };
    let event_id = event.id;
    let msg = IngestMessage::Event(event);
    let line = serde_json::to_string(&msg).expect("serialize event");

    // This machine's kernel listen backlog (`kern.ipc.somaxconn`, 128 on
    // macOS by default) is a *lower*, OS-level limit than the daemon's own
    // 256-connection semaphore — a burst fired as truly-simultaneous raw
    // connects can hit ECONNREFUSED from the kernel before the
    // application-level semaphore this test actually targets ever comes
    // into play. A real client (a hook process) retries on connection
    // refusal rather than treating it as fatal, so this mirrors that
    // instead of asserting on an artifact of firing every connect() in the
    // same tokio tick.
    let mut attempt = 0;
    let mut stream = loop {
        match UnixStream::connect(sock_path).await {
            Ok(stream) => break stream,
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused && attempt < 50 => {
                attempt += 1;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(e) => panic!("connect to daemon UDS socket (attempt {attempt}): {e}"),
        }
    };
    stream
        .write_all(line.as_bytes())
        .await
        .expect("write event line");
    stream.write_all(b"\n").await.expect("write newline");
    stream.shutdown().await.expect("shutdown stream");
    event_id
}

/// 2x `MAX_INFLIGHT_CONNECTIONS` (256) concurrent submissions, each its own
/// session — exceeding the semaphore cap so the accept loop's documented
/// backpressure (queue in the OS backlog, not unbounded open fds) actually
/// engages, not just the common case under the cap.
#[tokio::test]
async fn burst_of_events_beyond_inflight_cap_is_neither_lost_nor_stalled() {
    let mut daemon = start_daemon().await;
    let store = Store::open(daemon.home.join("fornax.db"))
        .await
        .expect("open store db");
    let sock_path = daemon.home.join("fornax.sock");

    const BURST_SIZE: usize = 512; // 2x MAX_INFLIGHT_CONNECTIONS
    let sessions: Vec<String> = (0..BURST_SIZE)
        .map(|i| format!("fornx212-burst-{}-{i}", short_id()))
        .collect();

    let submit_started = Instant::now();
    let mut handles = Vec::with_capacity(BURST_SIZE);
    for session in sessions.clone() {
        let sock_path = sock_path.clone();
        handles.push(tokio::spawn(async move {
            submit_event(&sock_path, &session).await
        }));
    }
    let mut expected_ids = Vec::with_capacity(BURST_SIZE);
    for handle in handles {
        expected_ids.push(handle.await.expect("submit task panicked"));
    }
    let submit_wall_clock = submit_started.elapsed();

    // Bounded drain: every session's event must become durable within a
    // generous but finite window. This is the actual claim under test — not
    // that the burst completes instantly, but that it completes at all and
    // within a bound, rather than ever stalling past the burst.
    let drain_deadline = Instant::now() + Duration::from_secs(30);
    let mut committed_ids = std::collections::HashSet::new();
    loop {
        committed_ids.clear();
        for session in &sessions {
            if let Ok(events) = store.events_for_session(session).await {
                committed_ids.extend(events.iter().map(|e| e.id));
            }
        }
        if committed_ids.len() == BURST_SIZE {
            break;
        }
        if Instant::now() >= drain_deadline {
            panic!(
                "backlog did not drain within 30s: {}/{BURST_SIZE} events committed; daemon log:\n{}",
                committed_ids.len(),
                daemon.log_contents()
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let drain_wall_clock = drain_deadline.saturating_duration_since(Instant::now());

    for expected_id in &expected_ids {
        assert!(
            committed_ids.contains(expected_id),
            "event {expected_id} submitted but never committed — backpressure must not drop events"
        );
    }
    assert_eq!(
        committed_ids.len(),
        BURST_SIZE,
        "exactly {BURST_SIZE} events submitted; no duplicates, no loss"
    );

    assert!(
        daemon.is_alive(),
        "daemon must survive a 2x-over-cap burst, not crash under backpressure"
    );

    const INFLIGHT_CAP: usize = 256; // mirrors MAX_INFLIGHT_CONNECTIONS in src/main.rs
    eprintln!(
        "burst of {BURST_SIZE} events (2x the {INFLIGHT_CAP} inflight cap): submit took {submit_wall_clock:?}, drained with {drain_wall_clock:?} of the 30s budget remaining"
    );
}
