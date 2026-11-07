//! FORNX-466 / HORO-1597 downstream check against a live daemon: identity
//! propagation (real Claude hook payloads -> hook binary -> daemon -> store),
//! persistence and query scoping, concurrent session isolation, subagent
//! attribution, and no invented identity. Harness shape mirrors
//! `concurrent_hook_submission.rs` (real binaries, isolated `$FORNAX_HOME`,
//! OS-assigned port, bounded polling).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use fornax_store::Store;
use serde_json::Value;

mod common;
use common::free_tcp_port;

fn workspace_bin(name: &str) -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let path = root.join("target").join(profile).join(name);
    assert!(
        path.exists(),
        "expected workspace binary at {path:?} — run `cargo build --workspace` first"
    );
    path
}

struct Daemon {
    child: Child,
    home: PathBuf,
    port: u16,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        std::fs::remove_dir_all(&self.home).ok();
    }
}

fn short_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..8].to_string()
}

fn fornax_status(daemon: &Daemon) -> String {
    let out = Command::new(workspace_bin("fornax"))
        .arg("status")
        .env("FORNAX_HTTP_PORT", daemon.port.to_string())
        .env("FORNAX_HOME", &daemon.home)
        .output()
        .expect("run fornax status");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

async fn start_daemon() -> Daemon {
    let home = PathBuf::from("/tmp").join(format!("fnx-ident-{}", short_id()));
    std::fs::create_dir_all(&home).unwrap();
    let port = free_tcp_port();
    let log = std::fs::File::create(home.join("daemon.log")).unwrap();
    let child = Command::new(workspace_bin("fornax-daemon"))
        .env("FORNAX_HOME", &home)
        .env("FORNAX_HTTP_PORT", port.to_string())
        .env("RUST_LOG", "info")
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .stdin(Stdio::null())
        .spawn()
        .expect("spawn fornax-daemon");
    let daemon = Daemon { child, home, port };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while fornax_status(&daemon) == "🛡 fornax: daemon unreachable" {
        assert!(
            tokio::time::Instant::now() < deadline,
            "daemon did not start"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    daemon
}

fn send_hook(home: &Path, payload: &Value) -> i32 {
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
        .unwrap()
        .write_all(payload.to_string().as_bytes())
        .unwrap();
    child
        .wait_with_output()
        .unwrap()
        .status
        .code()
        .unwrap_or(-1)
}

fn post_tool_use(session: &str, exit_code: i64, agent: Option<(&str, &str)>) -> Value {
    // FORNX-477: Verified needs the runner's own passing summary, not just exit 0.
    let stdout = if exit_code == 0 {
        "running 3 tests\ntest result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n"
    } else {
        ""
    };
    let mut v = serde_json::json!({
        "hook_event_name": "PostToolUse",
        "session_id": session,
        "tool_name": "Bash",
        "tool_input": {"command": "cargo test --workspace"},
        "tool_response": {"exit_code": exit_code, "stdout": stdout, "stderr": ""}
    });
    if let Some((id, kind)) = agent {
        v["agent_id"] = id.into();
        v["agent_type"] = kind.into();
    }
    v
}

fn stop(home: &Path, session: &str) -> Value {
    let transcript = home.join(format!("{session}-transcript.jsonl"));
    std::fs::write(
        &transcript,
        serde_json::json!({
            "type": "assistant",
            "message": {"content": [{"type": "text", "text": "All tests passed."}]}
        })
        .to_string(),
    )
    .unwrap();
    serde_json::json!({
        "hook_event_name": "Stop",
        "session_id": session,
        "transcript_path": transcript.to_str().unwrap()
    })
}

/// Minimal blocking HTTP GET against the loopback API.
fn http_get_json(port: u16, path: &str) -> Value {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .unwrap();
    let mut body = String::new();
    stream.read_to_string(&mut body).unwrap();
    let json = body.split("\r\n\r\n").nth(1).expect("http body");
    serde_json::from_str(json.trim()).unwrap_or_else(|e| panic!("json body {json:?}: {e}"))
}

async fn wait_for_verdict(store: &Store, session: &str, want: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(row) = store.latest_finding_for_session(session).await.unwrap() {
            assert_eq!(row.verdict, want, "{session}");
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no finding for {session} in 15s"
        );
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
}

#[tokio::test]
async fn two_live_sessions_and_a_subagent_keep_identity_attribution_and_scope() {
    let daemon = start_daemon().await;
    let store = Store::open(daemon.home.join("fornax.db")).await.unwrap();
    let a = format!("sess-a-{}", short_id());
    let b = format!("sess-b-{}", short_id());
    let c = format!("sess-c-{}", short_id());

    // A passes, B fails, concurrently-live sessions; C carries a subagent
    // event (the parent's session_id plus agent_id/agent_type).
    assert_eq!(send_hook(&daemon.home, &post_tool_use(&a, 0, None)), 0);
    assert_eq!(send_hook(&daemon.home, &post_tool_use(&b, 1, None)), 0);
    assert_eq!(
        send_hook(
            &daemon.home,
            &post_tool_use(&c, 0, Some(("agent-7", "Explore")))
        ),
        0
    );
    assert_eq!(send_hook(&daemon.home, &stop(&daemon.home, &a)), 0);
    assert_eq!(send_hook(&daemon.home, &stop(&daemon.home, &b)), 0);

    // FORNX-477: an unattested passing run is capped at review.
    wait_for_verdict(&store, &a, "review").await;
    wait_for_verdict(&store, &b, "contradicted").await;

    // Persistence + query scoping: each session's scoped answer is its own,
    // declared session-scoped, and carries native (not legacy) attribution.
    let ra = http_get_json(daemon.port, &format!("/api/status?session={a}"));
    assert_eq!(ra["scope"], "session");
    assert_eq!(ra["session_scoped"], true);
    assert_eq!(ra["latest"]["verdict"], "review");
    assert_eq!(ra["latest"]["session_id"], a.as_str());
    assert_eq!(ra["latest"]["attribution"], "native");
    let rb = http_get_json(daemon.port, &format!("/api/status?session={b}"));
    assert_eq!(rb["latest"]["verdict"], "contradicted");
    assert_eq!(rb["latest"]["session_id"], b.as_str());

    // A session with no findings (C's only event is subagent evidence) never
    // borrows another session's finding.
    let rc = http_get_json(daemon.port, &format!("/api/status?session={c}"));
    assert_eq!(rc["session_scoped"], true);
    assert!(
        rc["latest"].is_null(),
        "C must not show A's or B's finding: {rc}"
    );

    // No invented identity: the host-wide answer says so, and a legacy
    // placeholder is never answered as a session.
    let host = http_get_json(daemon.port, "/api/status");
    assert_eq!(host["scope"], "host");
    assert!(host.get("session_scoped").is_none());
    let legacy = http_get_json(daemon.port, "/api/status?session=unknown");
    assert_eq!(legacy["session_scoped"], false);
    assert!(legacy["latest"].is_null());
    assert!(
        fornax_status(&daemon).ends_with("(host-wide)"),
        "fornax status must label its host-wide reading: {}",
        fornax_status(&daemon)
    );

    // Subagent attribution: the event is filed under the PARENT's session,
    // attributed to (session, agent); the main-agent events carry none.
    let events_c = store.events_for_session(&c).await.unwrap();
    assert_eq!(
        events_c.len(),
        1,
        "subagent event is stored under the parent session"
    );
    let attr = store
        .attribution_for_event(&events_c[0].id.to_string())
        .await
        .unwrap()
        .expect("subagent event is attributed");
    assert_eq!(attr.agent_id.as_deref(), Some("agent-7"));
    assert_eq!(attr.agent_type.as_deref(), Some("Explore"));
    assert_eq!(attr.lineage_status, "unknown");
    for session in [&a, &b] {
        for e in store.events_for_session(session).await.unwrap() {
            assert!(
                store
                    .attribution_for_event(&e.id.to_string())
                    .await
                    .unwrap()
                    .is_none(),
                "main-agent events must stay unattributed, not 'root'"
            );
        }
    }
}
