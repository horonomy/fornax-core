//! FORNX-434 AC2: "Seed critical evidence into queue failure/restart, trace
//! through intake/restore; loss and delayed/unavailable distinguishable."
//!
//! `daemon_restart_session_persistence.rs` already proves restart/
//! persistence at the HTTP route level, but seeds its claims/findings
//! directly via `Store` -- by its own doc comment, deliberately bypassing
//! the real verification pipeline. That leaves a real gap this file closes:
//! evidence submitted through the real UDS ingest path (capability
//! announcement, event, evidence, claim -- the same real pipeline
//! `provenance_enforcement.rs` exercises), committed to a real `Verified`
//! finding, must survive a hard kill (`SIGKILL`, not a graceful shutdown)
//! and restart of the daemon process against the same `$FORNAX_HOME`. A
//! session that was never submitted at all must still, after that same
//! restart, answer "no finding" rather than fabricating one -- loss and
//! legitimate absence must stay distinguishable, not conflated.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use fornax_store::Store;
use fornax_types::{
    AgentEvent, Claim, CollectionMethod, EventKind, Evidence, EvidenceKind, EvidenceSource,
    IngestMessage, Provider, TrustClass,
};
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use uuid::Uuid;
mod common;
use common::free_tcp_port;

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

    /// A hard kill (`SIGKILL` on Unix, via `std::process::Child::kill`) --
    /// deliberately not a graceful shutdown, since the property under test
    /// is durability against abrupt termination, not clean-shutdown
    /// behavior. Leaves `home` on disk for the caller to restart against.
    fn kill_hard_and_wait(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        std::mem::forget(self); // Drop would also try to kill an already-dead child; harmless either way, skipped for clarity.
    }
}

impl Drop for DaemonHandle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

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
        let alive = handle.is_alive();
        if !alive {
            panic!(
                "daemon exited during startup; log:\n{}",
                handle.log_contents()
            );
        }
        if home.join("fornax.sock").exists() {
            break;
        }
        if tokio::time::Instant::now() > deadline {
            panic!(
                "daemon socket never appeared; log:\n{}",
                handle.log_contents()
            );
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    handle
}

fn short_id() -> String {
    Uuid::new_v4().simple().to_string()[..8].to_string()
}

async fn send_line(sock_path: &Path, msg: &IngestMessage) {
    let line = serde_json::to_string(msg).expect("serialize message");
    let mut stream = UnixStream::connect(sock_path)
        .await
        .expect("connect to daemon UDS socket");
    stream.write_all(line.as_bytes()).await.expect("write line");
    stream.write_all(b"\n").await.expect("write newline");
    stream.shutdown().await.expect("shutdown stream");
}

fn capability_announcement(session_id: &str) -> IngestMessage {
    use fornax_types::{CapabilitySignal, RuntimeCapabilities, SignalAvailability, SignalClass};
    IngestMessage::Capabilities(RuntimeCapabilities {
        schema_version: fornax_types::CAPABILITY_SCHEMA_VERSION,
        provider: Provider::ClaudeCode,
        signals: vec![CapabilitySignal {
            class: SignalClass::ToolTrace,
            state: SignalAvailability::Available,
            detail: None,
        }],
        notes: [("session_id".to_string(), session_id.to_string())].into(),
    })
}

fn command_success_event(session_id: &str) -> AgentEvent {
    AgentEvent {
        id: Uuid::new_v4(),
        session_id: session_id.to_string(),
        provider: Provider::ClaudeCode,
        kind: EventKind::PostToolUse,
        observed_at: chrono::Utc::now().to_rfc3339(),
        tool_name: Some("Bash".to_string()),
        tool_input: Some(serde_json::json!({"command": "cargo build"})),
        tool_response: Some(serde_json::json!({"exit_code": 0})),
        raw: serde_json::json!({"synthetic_test": "restart_critical_evidence_durability"}),
    }
}

fn legitimate_evidence(session_id: &str, source_event_id: Uuid) -> Evidence {
    Evidence {
        id: Uuid::new_v4(),
        session_id: session_id.to_string(),
        source_event_id,
        kind: EvidenceKind::ExitCode,
        observed_at: chrono::Utc::now().to_rfc3339(),
        payload: serde_json::json!({"command": "cargo build", "exit_code": 0}),
        provenance: "fornx434-restart-durability-fixture".to_string(),
        source: Some(EvidenceSource::now(
            "claude_bash_exit_code_sensor_v1",
            TrustClass::AgentAdjacent,
            Some(Provider::ClaudeCode),
            CollectionMethod::HookCallback,
            None,
        )),
        extension: None,
        evidence_purged: false,
    }
}

fn command_success_claim(session_id: &str, source_event_id: Uuid) -> Claim {
    Claim {
        id: Uuid::new_v4(),
        session_id: session_id.to_string(),
        source_event_id,
        text: "the command `cargo build` succeeded".to_string(),
        subject: "command_succeeded".to_string(),
        claimed_at: chrono::Utc::now().to_rfc3339(),
    }
}

async fn wait_for_verdict(store: &Store, session_id: &str, claim_id: Uuid) -> Option<String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(findings) = store.findings_for_session(session_id).await {
            if let Some(f) = findings.iter().find(|f| f.claim_id == claim_id.to_string()) {
                return Some(f.verdict.clone());
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn critical_evidence_submitted_through_real_pipeline_survives_a_hard_restart() {
    let home = PathBuf::from("/tmp").join(format!("fnx-restart-durability-{}", short_id()));
    std::fs::create_dir_all(&home).expect("create scratch FORNAX_HOME");

    let session_id = format!("fornx434-restart-{}", short_id());
    let event = command_success_event(&session_id);
    let event_id = event.id;
    let claim = command_success_claim(&session_id, event_id);
    let claim_id = claim.id;
    let evidence = legitimate_evidence(&session_id, event_id);

    // Phase 1: submit through the real pipeline and confirm it actually
    // reaches a verdict before we kill anything.
    let port1 = free_tcp_port();
    let daemon1 = start_daemon(&home, port1).await;
    let sock = home.join("fornax.sock");
    let db = home.join("fornax.db");

    let store = Store::open(&db).await.expect("open store db");
    send_line(&sock, &capability_announcement(&session_id)).await;
    send_line(&sock, &IngestMessage::Event(event)).await;
    send_line(&sock, &IngestMessage::Evidence(evidence)).await;
    send_line(&sock, &IngestMessage::Claim(claim)).await;

    let verdict_before = wait_for_verdict(&store, &session_id, claim_id).await;
    assert_eq!(
        verdict_before,
        Some("verified".to_string()),
        "setup failed: the claim must reach Verified before a restart can even be \
         meaningfully tested; daemon log:\n{}",
        daemon1.log_contents()
    );

    // Phase 2: hard-kill the daemon (SIGKILL, not graceful shutdown) and
    // restart against the exact same FORNAX_HOME.
    daemon1.kill_hard_and_wait();

    let port2 = free_tcp_port();
    let daemon2 = start_daemon(&home, port2).await;

    // Phase 3: the pre-existing session's finding must still be there,
    // with the same verdict -- not lost, not silently regenerated.
    let store_after = Store::open(&db)
        .await
        .expect("reopen store db after restart");
    let findings_after = store_after
        .findings_for_session(&session_id)
        .await
        .expect("query findings after restart");
    let finding_after = findings_after
        .iter()
        .find(|f| f.claim_id == claim_id.to_string());
    assert!(
        finding_after.is_some(),
        "the claim's finding must survive a hard daemon restart against the same \
         FORNAX_HOME -- it must not be lost; daemon log:\n{}",
        daemon2.log_contents()
    );
    assert_eq!(
        finding_after.unwrap().verdict,
        "verified",
        "the surviving finding's verdict must be unchanged by the restart"
    );

    // Phase 4: a session that was NEVER submitted must still, after this
    // same restart, correctly answer "no finding" -- proving the daemon
    // distinguishes real absence from the kind of loss phase 3 just
    // disproved, rather than always answering "found" or always
    // answering "not found" regardless of what actually happened.
    let never_submitted_session = format!("fornx434-never-submitted-{}", short_id());
    let findings_for_unknown = store_after
        .findings_for_session(&never_submitted_session)
        .await
        .expect("query findings for a session that was never submitted");
    assert!(
        findings_for_unknown.is_empty(),
        "a session that was never submitted must have zero findings after restart -- \
         a non-empty result here would mean the daemon can't tell legitimate absence \
         from a real survived finding"
    );
}
