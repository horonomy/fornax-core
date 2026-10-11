//! FORNX-431 slice 4: the actual enforcement half of the provenance guard.
//! Slices 1-3 built the pure decision functions, the persisted ledger, and
//! the origin-stamping at write time -- but nothing on the live verdict
//! path called any of it. This file proves `run_verifiers_and_persist_
//! findings` (the one real choke point all 3 daemon callers route
//! through) now actually enforces admission and replay, against a real
//! daemon process over its real UDS path -- not any function called
//! in-process.
//!
//! AC1 (forged/foreign/invalid/replayed evidence can never promote a claim
//! to VERIFIED): `forged_host_observed_label_never_reaches_verified`,
//! `unregistered_sensor_never_reaches_verified`,
//! `uds_evidence_with_no_source_never_reaches_verified`,
//! `cross_anchor_replay_is_downgraded_not_verified`.
//!
//! AC2 (an authorized source still verifies correctly; related-claim reuse
//! and identical retry don't false-contradict):
//! `legitimate_evidence_still_reaches_verified` (positive control --
//! if this fails, the guard broke the normal path, not just attacks),
//! `same_anchor_related_claims_both_reach_verified_without_downgrade`.
//!
//! Fixture potency (AC4): each negative fixture is also run directly
//! through the raw `Verifier` (bypassing admission) to confirm it WOULD
//! have verified without the guard -- proving the guard is doing
//! something, not that the fixture is simply inert input.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use fornax_store::Store;
use fornax_types::{
    AgentEvent, Claim, CollectionMethod, EventKind, Evidence, EvidenceKind, EvidenceSource,
    IngestMessage, Provider, TrustClass,
};
use fornax_verify::{CommandSuccessVerifier, Verifier};
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
    let home = PathBuf::from("/tmp").join(format!("fnx-enforce-{}", short_id()));
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

async fn send_line(sock_path: &Path, msg: &IngestMessage) {
    let line = serde_json::to_string(msg).expect("serialize message");
    let mut stream = UnixStream::connect(sock_path)
        .await
        .expect("connect to daemon UDS socket");
    stream.write_all(line.as_bytes()).await.expect("write line");
    stream.write_all(b"\n").await.expect("write newline");
    stream.shutdown().await.expect("shutdown stream");
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
        raw: serde_json::json!({"synthetic_test": "provenance_enforcement"}),
    }
}

/// `source: None` -- the acquisition-shaped hole AC1 names explicitly.
fn evidence_with_no_source(session_id: &str, source_event_id: Uuid) -> Evidence {
    Evidence {
        id: Uuid::new_v4(),
        session_id: session_id.to_string(),
        source_event_id,
        kind: EvidenceKind::ExitCode,
        observed_at: chrono::Utc::now().to_rfc3339(),
        payload: serde_json::json!({"command": "cargo build", "exit_code": 0}),
        provenance: "fornx431-enforcement-fixture".to_string(),
        source: None,
        extension: None,
        evidence_purged: false,
    }
}

/// A forged `HostObserved` label from a sensor only ever authorized for
/// `AgentAdjacent` (FORNX-380 fixture 11's shape, routed through the real
/// live daemon path instead of `authorize_evidence_source` directly).
fn evidence_with_forged_trust_class(session_id: &str, source_event_id: Uuid) -> Evidence {
    let mut ev = evidence_with_no_source(session_id, source_event_id);
    ev.source = Some(EvidenceSource::now(
        "claude_bash_exit_code_sensor_v1", // only ever AgentAdjacent, see known_sensors()
        TrustClass::HostObserved,
        Some(Provider::ClaudeCode),
        CollectionMethod::HookCallback,
        None,
    ));
    ev
}

fn evidence_with_unregistered_sensor(session_id: &str, source_event_id: Uuid) -> Evidence {
    let mut ev = evidence_with_no_source(session_id, source_event_id);
    ev.source = Some(EvidenceSource::now(
        "totally_made_up_sensor",
        TrustClass::AgentAdjacent,
        Some(Provider::ClaudeCode),
        CollectionMethod::HookCallback,
        None,
    ));
    ev
}

fn legitimate_evidence(session_id: &str, source_event_id: Uuid) -> Evidence {
    let mut ev = evidence_with_no_source(session_id, source_event_id);
    ev.source = Some(EvidenceSource::now(
        "claude_bash_exit_code_sensor_v1",
        TrustClass::AgentAdjacent,
        Some(Provider::ClaudeCode),
        CollectionMethod::HookCallback,
        None,
    ));
    ev
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

/// Announces `ToolTrace` availability for `session_id` -- without this,
/// `CommandSuccessVerifier`/`CommandExecutedVerifier` return `Unavailable`
/// unconditionally (both gate on `caps.is_observable`), regardless of
/// anything the provenance guard admits. `notes["session_id"]` is how the
/// real protocol keys an announcement that may arrive before any Event
/// sets `session_hint` (see `handle_message`'s `Capabilities` arm).
fn capability_announcement(session_id: &str) -> IngestMessage {
    capability_announcement_as(session_id, Provider::ClaudeCode)
}

/// FORNX-435: same as [`capability_announcement`], but with the announced
/// owning `provider` parameterized -- needed to test
/// `Store::session_owner`'s real effect on `admission_decision` (a session
/// whose only announcement names a DIFFERENT provider than the evidence it
/// later receives) against the live daemon, not just the pure function in
/// isolation.
fn capability_announcement_as(session_id: &str, provider: Provider) -> IngestMessage {
    use fornax_types::{CapabilitySignal, RuntimeCapabilities, SignalAvailability, SignalClass};
    IngestMessage::Capabilities(RuntimeCapabilities {
        schema_version: fornax_types::CAPABILITY_SCHEMA_VERSION,
        provider,
        signals: vec![CapabilitySignal {
            class: SignalClass::ToolTrace,
            state: SignalAvailability::Available,
            detail: None,
        }],
        notes: [("session_id".to_string(), session_id.to_string())].into(),
    })
}

/// Submits `event` + `evidence` over UDS, then the claim, and waits for a
/// finding to be computed, returning its verdict. Returns `None` if no
/// finding ever appears within the timeout (e.g. the claim's `applies_to`
/// never matched, or every row was quarantined and nothing got computed).
async fn submit_and_await_verdict(
    sock_path: &Path,
    store: &Store,
    event: AgentEvent,
    evidence: Evidence,
    claim: Claim,
) -> Option<String> {
    let session_id = claim.session_id.clone();
    send_line(sock_path, &capability_announcement(&session_id)).await;
    send_line(sock_path, &IngestMessage::Event(event)).await;
    send_line(sock_path, &IngestMessage::Evidence(evidence)).await;
    send_line(sock_path, &IngestMessage::Claim(claim.clone())).await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(findings) = store.findings_for_session(&session_id).await {
            if let Some(f) = findings.iter().find(|f| f.claim_id == claim.id.to_string()) {
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
async fn forged_host_observed_label_never_reaches_verified() {
    let daemon = start_daemon().await;
    let store = Store::open(daemon.home.join("fornax.db"))
        .await
        .expect("open store db");
    let session_id = format!("fornx431-forged-{}", short_id());
    let event = command_success_event(&session_id);
    let event_id = event.id;
    let claim = command_success_claim(&session_id, event_id);
    let evidence = evidence_with_forged_trust_class(&session_id, event_id);

    let verdict = submit_and_await_verdict(
        &daemon.home.join("fornax.sock"),
        &store,
        event,
        evidence,
        claim,
    )
    .await;

    assert_ne!(
        verdict,
        Some("verified".to_string()),
        "a forged HostObserved label must never promote a claim to Verified; daemon log:\n{}",
        daemon.log_contents()
    );
}

#[tokio::test]
async fn unregistered_sensor_never_reaches_verified() {
    let daemon = start_daemon().await;
    let store = Store::open(daemon.home.join("fornax.db"))
        .await
        .expect("open store db");
    let session_id = format!("fornx431-unregistered-{}", short_id());
    let event = command_success_event(&session_id);
    let event_id = event.id;
    let claim = command_success_claim(&session_id, event_id);
    let evidence = evidence_with_unregistered_sensor(&session_id, event_id);

    let verdict = submit_and_await_verdict(
        &daemon.home.join("fornax.sock"),
        &store,
        event,
        evidence,
        claim,
    )
    .await;

    assert_ne!(
        verdict,
        Some("verified".to_string()),
        "an unregistered sensor must never promote a claim to Verified; daemon log:\n{}",
        daemon.log_contents()
    );
}

#[tokio::test]
async fn uds_evidence_with_no_source_never_reaches_verified() {
    let daemon = start_daemon().await;
    let store = Store::open(daemon.home.join("fornax.db"))
        .await
        .expect("open store db");
    let session_id = format!("fornx431-nosource-{}", short_id());
    let event = command_success_event(&session_id);
    let event_id = event.id;
    let claim = command_success_claim(&session_id, event_id);
    let evidence = evidence_with_no_source(&session_id, event_id);

    let verdict = submit_and_await_verdict(
        &daemon.home.join("fornax.sock"),
        &store,
        event,
        evidence,
        claim,
    )
    .await;

    assert_ne!(
        verdict,
        Some("verified".to_string()),
        "acquisition-shaped evidence (no source) injected over UDS must never \
         promote a claim to Verified -- UdsIngest requires a vouched-for source; \
         daemon log:\n{}",
        daemon.log_contents()
    );
}

/// Positive control: if this fails, the guard broke the normal path, not
/// just attacks -- a real registered sensor, correct trust class, matching
/// provider, must still verify exactly as before FORNX-431.
#[tokio::test]
async fn legitimate_evidence_still_reaches_verified() {
    let daemon = start_daemon().await;
    let store = Store::open(daemon.home.join("fornax.db"))
        .await
        .expect("open store db");
    let session_id = format!("fornx431-legit-{}", short_id());
    let event = command_success_event(&session_id);
    let event_id = event.id;
    let claim = command_success_claim(&session_id, event_id);
    let evidence = legitimate_evidence(&session_id, event_id);

    let verdict = submit_and_await_verdict(
        &daemon.home.join("fornax.sock"),
        &store,
        event,
        evidence,
        claim,
    )
    .await;

    assert_eq!(
        verdict,
        Some("verified".to_string()),
        "a correctly-admitted, legitimate evidence row must still reach Verified \
         -- the guard must not break the normal path; daemon log:\n{}",
        daemon.log_contents()
    );
}

/// FORNX-437's disclosed residual: `adapter_registry_has_zero_references_in_
/// the_verdict_computing_daemon` proves the registry is structurally
/// unreachable from the daemon's source code, but that is not the same as a
/// runtime behavioral proof that an active *disabled* registration in the
/// same `FORNAX_HOME` the live daemon is running against has zero effect on
/// real verdict computation. This test closes that gap: registers a host
/// adapter descriptor via the real `fornax` CLI binary (not a copy of its
/// logic), disables it, then submits an ordinary legitimate claim over the
/// real daemon's UDS socket in that exact `FORNAX_HOME` and asserts it still
/// reaches `Verified` -- identical to `legitimate_evidence_still_reaches_verified`
/// above, just with a disabled registration sitting in the same home
/// directory the whole time.
#[tokio::test]
async fn disabled_adapter_registration_does_not_affect_live_verdict_computation() {
    let daemon = start_daemon().await;

    let manifest_path = daemon.home.join("fornx437-fixture-manifest.json");
    let adapter_id = format!("fornx437-disabled-fixture-{}", short_id());
    std::fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": 1,
            "id": adapter_id,
            "display_name": "FORNX-437 disabled-registration fixture",
            "summary": "A synthetic data-only adapter proving registry state is inert",
            "min_fornax_version": "0.0.1",
            "provenance": "https://example.com/fornx437-fixture",
            "capabilities": ["plan", "install", "uninstall"],
            "target": {"format": "json", "path": "~/.not-created/settings.json"},
            "operations": [{
                "kind": "ensure_marked_array_element",
                "pointer": "/hooks/PostToolUse",
                "marker_key": "command",
                "marker_value": "fornx437-fixture",
                "element": {"type": "command", "command": "fornx437-fixture"}
            }]
        }))
        .expect("serialize fixture manifest"),
    )
    .expect("write fixture manifest");

    let run_cli = |args: &[&str]| {
        Command::new(workspace_bin("fornax"))
            .env("FORNAX_HOME", &daemon.home)
            .args(args)
            .output()
            .expect("run fornax CLI")
    };

    let review = run_cli(&[
        "adapter",
        "register",
        "--manifest",
        manifest_path.to_str().unwrap(),
        "--json",
    ]);
    assert!(
        review.status.success(),
        "adapter register (review) failed: {}",
        String::from_utf8_lossy(&review.stderr)
    );
    let reviewed: serde_json::Value =
        serde_json::from_slice(&review.stdout).expect("parse review JSON");
    let digest = reviewed["digest"].as_str().expect("digest field present");

    let confirmed = run_cli(&[
        "adapter",
        "register",
        "--manifest",
        manifest_path.to_str().unwrap(),
        "--confirm-digest",
        digest,
    ]);
    assert!(
        confirmed.status.success(),
        "adapter register (confirm) failed: {}",
        String::from_utf8_lossy(&confirmed.stderr)
    );

    let disabled = run_cli(&["adapter", "disable", &adapter_id]);
    assert!(
        disabled.status.success(),
        "adapter disable failed: {}",
        String::from_utf8_lossy(&disabled.stderr)
    );

    // Sanity: the registration really is disabled in this exact FORNAX_HOME
    // before we trust the verdict-computation assertion below.
    let registry_path = daemon.home.join("adapters/registry.json");
    let registry: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&registry_path).expect("read registry.json"))
            .expect("parse registry.json");
    let entry = registry["entries"]
        .as_array()
        .expect("entries array")
        .iter()
        .find(|e| e["id"] == serde_json::json!(adapter_id))
        .expect("fixture entry present in registry");
    assert_eq!(
        entry["enabled"],
        serde_json::json!(false),
        "fixture registration must actually be disabled before this test's \
         assertion means anything"
    );

    let store = Store::open(daemon.home.join("fornax.db"))
        .await
        .expect("open store db");
    let session_id = format!("fornx437-disabled-registry-{}", short_id());
    let event = command_success_event(&session_id);
    let event_id = event.id;
    let claim = command_success_claim(&session_id, event_id);
    let evidence = legitimate_evidence(&session_id, event_id);

    let verdict = submit_and_await_verdict(
        &daemon.home.join("fornax.sock"),
        &store,
        event,
        evidence,
        claim,
    )
    .await;

    assert_eq!(
        verdict,
        Some("verified".to_string()),
        "a disabled host-adapter registration present in the same FORNAX_HOME \
         must have zero effect on live verdict computation for an unrelated, \
         legitimate claim -- daemon log:\n{}",
        daemon.log_contents()
    );
}

/// FORNX-433 AC3 Slice B fixtures: a test-runner-shaped event/evidence
/// pair carrying `agent_id`/`agent_type` in `raw`, mirroring the real
/// shape confirmed live this session -- a Task subagent's PostToolUse
/// hook payload carries both fields, while the main session's own calls
/// carry neither.
fn subagent_test_evidence_event(session_id: &str) -> AgentEvent {
    AgentEvent {
        id: Uuid::new_v4(),
        session_id: session_id.to_string(),
        provider: Provider::ClaudeCode,
        kind: EventKind::PostToolUse,
        observed_at: chrono::Utc::now().to_rfc3339(),
        tool_name: Some("Bash".to_string()),
        tool_input: Some(serde_json::json!({"command": "pytest -q"})),
        tool_response: Some(serde_json::json!({"exit_code": 0})),
        raw: serde_json::json!({
            "agent_id": "fornx433-sliceb-subagent",
            "agent_type": "general-purpose",
        }),
    }
}

fn test_runner_evidence(session_id: &str, source_event_id: Uuid) -> Evidence {
    Evidence {
        id: Uuid::new_v4(),
        session_id: session_id.to_string(),
        source_event_id,
        kind: EvidenceKind::ExitCode,
        observed_at: chrono::Utc::now().to_rfc3339(),
        payload: serde_json::json!({"command": "pytest -q", "exit_code": 0}),
        provenance: "fornx433-sliceb-fixture".to_string(),
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

/// The main session's own event (no `agent_id`) that produces the claim --
/// e.g. a `Stop`-derived summary reporting "tests passed", a different
/// event than whichever one actually produced the passing evidence.
fn main_session_summary_event(session_id: &str) -> AgentEvent {
    let mut ev = command_success_event(session_id);
    ev.kind = EventKind::SessionEnd;
    ev
}

fn test_result_claim(session_id: &str, source_event_id: Uuid) -> Claim {
    Claim {
        id: Uuid::new_v4(),
        session_id: session_id.to_string(),
        source_event_id,
        text: "All tests passed.".to_string(),
        subject: "test_result".to_string(),
        claimed_at: chrono::Utc::now().to_rfc3339(),
    }
}

/// FORNX-433 AC3 Slice B: a claim minted from the main session (no
/// `agent_id` -- e.g. a `Stop`-derived summary) must still reach Verified
/// against test-runner evidence that originated from a *different* event
/// in the same session (e.g. a Task subagent that actually ran the tests).
/// `fornax-verify`'s `TestResultVerifier` pools all evidence for the
/// session rather than filtering by which event produced it -- confirmed
/// by the FORNX-433 AC3 architecture review to be the intended "subagent
/// runs the tests, main agent reports the result" delegation pattern, not
/// a cross-agent leak (no code path today mints a claim *from* a
/// subagent's own output, so there is nothing yet for a wrong agent's
/// claim to wrongly borrow another agent's evidence). This test pins
/// delegation pooling as intended behavior, so a future agent-scoping
/// change (FORNX-433 Slice C, gated on a real subagent-originated claim
/// existing) can't silently break it while fixing an actual leak elsewhere.
#[tokio::test]
async fn main_session_claim_is_verified_by_subagent_originated_test_evidence() {
    let daemon = start_daemon().await;
    let store = Store::open(daemon.home.join("fornax.db"))
        .await
        .expect("open store db");
    let session_id = format!("fornx433-sliceb-pooling-{}", short_id());
    let sock_path = daemon.home.join("fornax.sock");

    let subagent_event = subagent_test_evidence_event(&session_id);
    let evidence = test_runner_evidence(&session_id, subagent_event.id);

    let main_event = main_session_summary_event(&session_id);
    let claim = test_result_claim(&session_id, main_event.id);

    send_line(&sock_path, &capability_announcement(&session_id)).await;
    send_line(&sock_path, &IngestMessage::Event(subagent_event)).await;
    send_line(&sock_path, &IngestMessage::Event(main_event)).await;
    send_line(&sock_path, &IngestMessage::Evidence(evidence)).await;
    send_line(&sock_path, &IngestMessage::Claim(claim.clone())).await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let verdict = loop {
        if let Ok(findings) = store.findings_for_session(&session_id).await {
            if let Some(f) = findings.iter().find(|f| f.claim_id == claim.id.to_string()) {
                break Some(f.verdict.clone());
            }
        }
        if tokio::time::Instant::now() >= deadline {
            break None;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    assert_eq!(
        verdict,
        Some("verified".to_string()),
        "the main session's claim must be verified by test evidence a \
         subagent produced in the same session -- delegation pooling is \
         intended behavior, not a leak; daemon log:\n{}",
        daemon.log_contents()
    );
}

/// Mutation proof for the sibling test above: with no test-runner evidence
/// anywhere in the session (the subagent's event/evidence deliberately
/// omitted), the same claim must NOT reach Verified -- proving the
/// sibling's Verified result genuinely depends on the pooled evidence,
/// not a vacuously-passing claim.
#[tokio::test]
async fn main_session_claim_without_any_test_evidence_stays_unverified() {
    let daemon = start_daemon().await;
    let store = Store::open(daemon.home.join("fornax.db"))
        .await
        .expect("open store db");
    let session_id = format!("fornx433-sliceb-nopool-{}", short_id());
    let sock_path = daemon.home.join("fornax.sock");

    let main_event = main_session_summary_event(&session_id);
    let claim = test_result_claim(&session_id, main_event.id);

    send_line(&sock_path, &capability_announcement(&session_id)).await;
    send_line(&sock_path, &IngestMessage::Event(main_event)).await;
    send_line(&sock_path, &IngestMessage::Claim(claim.clone())).await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let verdict = loop {
        if let Ok(findings) = store.findings_for_session(&session_id).await {
            if let Some(f) = findings.iter().find(|f| f.claim_id == claim.id.to_string()) {
                break Some(f.verdict.clone());
            }
        }
        if tokio::time::Instant::now() >= deadline {
            break None;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    assert_ne!(
        verdict,
        Some("verified".to_string()),
        "with no test-runner evidence anywhere in the session, the claim \
         must not reach Verified; daemon log:\n{}",
        daemon.log_contents()
    );
}

/// AC2: two claims minted from the *same* turn (same anchor) both reach
/// Verified against the same evidence row -- the anchor rule's whole
/// point, not a false cross-claim replay.
#[tokio::test]
async fn same_anchor_related_claims_both_reach_verified_without_downgrade() {
    let daemon = start_daemon().await;
    let store = Store::open(daemon.home.join("fornax.db"))
        .await
        .expect("open store db");
    let session_id = format!("fornx431-related-{}", short_id());
    let event = command_success_event(&session_id);
    let event_id = event.id;
    let evidence = legitimate_evidence(&session_id, event_id);
    let sock_path = daemon.home.join("fornax.sock");

    send_line(&sock_path, &capability_announcement(&session_id)).await;
    send_line(&sock_path, &IngestMessage::Event(event)).await;
    send_line(&sock_path, &IngestMessage::Evidence(evidence)).await;

    let claim_a = command_success_claim(&session_id, event_id);
    send_line(&sock_path, &IngestMessage::Claim(claim_a.clone())).await;

    let mut claim_b = command_success_claim(&session_id, event_id);
    claim_b.id = Uuid::new_v4();
    send_line(&sock_path, &IngestMessage::Claim(claim_b.clone())).await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let findings = store
            .findings_for_session(&session_id)
            .await
            .expect("read findings");
        let a = findings
            .iter()
            .find(|f| f.claim_id == claim_a.id.to_string());
        let b = findings
            .iter()
            .find(|f| f.claim_id == claim_b.id.to_string());
        if let (Some(a), Some(b)) = (a, b) {
            assert_eq!(
                a.verdict,
                "verified",
                "claim A (same anchor, first consumer) must reach Verified; log:\n{}",
                daemon.log_contents()
            );
            assert_eq!(
                b.verdict,
                "verified",
                "claim B (same anchor as A, legitimately related) must ALSO reach \
                 Verified, not be downgraded -- that's the anchor rule's whole point; \
                 log:\n{}",
                daemon.log_contents()
            );
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!(
                "findings for both claims never appeared; daemon log:\n{}",
                daemon.log_contents()
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// AC1/AC3: two claims from *different* anchors citing the same evidence --
/// the second is downgraded, never Verified. This is the actual replay
/// case FORNX-380 fixture 10 names.
#[tokio::test]
async fn cross_anchor_replay_is_downgraded_not_verified() {
    let daemon = start_daemon().await;
    let store = Store::open(daemon.home.join("fornax.db"))
        .await
        .expect("open store db");
    let session_id = format!("fornx431-crossanchor-{}", short_id());
    let sock_path = daemon.home.join("fornax.sock");

    // Claim A: a real turn, real evidence, reaches Verified.
    let event_a = command_success_event(&session_id);
    let event_a_id = event_a.id;
    let evidence = legitimate_evidence(&session_id, event_a_id);
    send_line(&sock_path, &capability_announcement(&session_id)).await;
    send_line(&sock_path, &IngestMessage::Event(event_a)).await;
    send_line(&sock_path, &IngestMessage::Evidence(evidence.clone())).await;
    let claim_a = command_success_claim(&session_id, event_a_id);
    send_line(&sock_path, &IngestMessage::Claim(claim_a.clone())).await;

    wait_for(Duration::from_secs(10), || {
        let store = &store;
        let session_id = session_id.clone();
        let claim_id = claim_a.id.to_string();
        async move {
            store
                .findings_for_session(&session_id)
                .await
                .unwrap_or_default()
                .iter()
                .any(|f| f.claim_id == claim_id && f.verdict == "verified")
        }
    })
    .await;

    // Claim B: a DIFFERENT turn (different source_event_id => different
    // anchor), but its own evidence row happens to have been produced
    // under the identical-looking payload -- the attack this guards
    // against is citing the SAME evidence_id across claims from different
    // turns. Build claim B's own event, but hand-craft its submitted
    // evidence with evidence.id == the first evidence's id (simulating a
    // replayed/reused evidence identifier rather than an honestly-new
    // one) is rejected at the store layer by the evidence `id` primary key
    // -- so instead we exercise the real mechanism `record_consumption`
    // actually guards: the SAME already-persisted evidence row visible to
    // a second claim from a different anchor, via `evidence_for_session`
    // returning the same row to both claims (which is exactly how a real
    // session's full evidence history is read for every claim evaluated
    // against it).
    let event_b = command_success_event(&session_id);
    let claim_b = command_success_claim(&session_id, event_b.id);
    send_line(&sock_path, &IngestMessage::Event(event_b)).await;
    send_line(&sock_path, &IngestMessage::Claim(claim_b.clone())).await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let findings = store
            .findings_for_session(&session_id)
            .await
            .expect("read findings");
        if let Some(b) = findings
            .iter()
            .find(|f| f.claim_id == claim_b.id.to_string())
        {
            assert_ne!(
                b.verdict,
                "verified",
                "claim B, a different turn citing the same already-consumed evidence \
                 row as claim A, must be downgraded -- never Verified; log:\n{}",
                daemon.log_contents()
            );
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!(
                "finding for claim B never appeared; daemon log:\n{}",
                daemon.log_contents()
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// FORNX-435: live-path proof of the "foreign session/acquisition" case --
/// `provider_mismatching_the_sessions_single_announced_owner_is_quarantined`
/// already proves this at the pure `admission_decision` unit level
/// (`fornax-types::provenance_guard`'s own test module), but FORNX-435
/// explicitly asks for it against the live request path too: a
/// *legitimate, correctly-registered* sensor's evidence (same fixture
/// `legitimate_evidence` uses elsewhere in this file) must still be
/// quarantined when the session it arrives under has announced a
/// DIFFERENT owning provider. If this only worked in the pure-function
/// unit test and not here, that would mean `Store::session_owner`'s real
/// `capabilities_for_session` wiring -- not exercised by the unit test at
/// all -- was broken.
#[tokio::test]
async fn foreign_session_provider_claim_is_quarantined_not_verified() {
    let daemon = start_daemon().await;
    let store = Store::open(daemon.home.join("fornax.db"))
        .await
        .expect("open store db");
    let session_id = format!("fornx435-foreign-session-{}", short_id());
    let sock_path = daemon.home.join("fornax.sock");

    // Session announces Codex as its sole owner...
    send_line(
        &sock_path,
        &capability_announcement_as(&session_id, Provider::Codex),
    )
    .await;

    // ...but the evidence's own EvidenceSource claims ClaudeCode --
    // `legitimate_evidence` is otherwise a registered sensor with the
    // correct trust class; the ONLY thing wrong here is the provider/
    // session-owner mismatch, isolating that one failure mode.
    let event = command_success_event(&session_id);
    let event_id = event.id;
    let claim = command_success_claim(&session_id, event_id);
    let evidence = legitimate_evidence(&session_id, event_id);

    let verdict = submit_and_await_verdict(&sock_path, &store, event, evidence, claim).await;

    assert_ne!(
        verdict,
        Some("verified".to_string()),
        "evidence claiming provider ClaudeCode under a session whose sole announced \
         owner is Codex must never promote a claim to Verified; daemon log:\n{}",
        daemon.log_contents()
    );
}

/// FORNX-435: live-path proof that two genuinely CONCURRENT cross-anchor
/// consumption attempts against the same evidence row are still
/// serialized correctly -- `cross_anchor_replay_is_downgraded_not_verified`
/// above only proves the sequential case (claim A fully resolved before
/// claim B is even sent). `Store::record_consumption`'s doc comment claims
/// `BEGIN IMMEDIATE` makes two racing callers serialize at the SQLite
/// level so the second never sees a stale read -- this test is the first
/// thing in this codebase to actually fire two such claims at once and
/// check the real outcome, rather than trusting that comment.
#[tokio::test]
async fn concurrent_cross_anchor_replay_is_serialized_not_double_verified() {
    let daemon = start_daemon().await;
    let store = Store::open(daemon.home.join("fornax.db"))
        .await
        .expect("open store db");
    let session_id = format!("fornx435-concurrent-{}", short_id());
    let sock_path = daemon.home.join("fornax.sock");

    // One evidence row, established up front (same shape as the existing
    // cross-anchor test), so both claims below contend over the SAME row.
    let event_a = command_success_event(&session_id);
    let event_a_id = event_a.id;
    let evidence = legitimate_evidence(&session_id, event_a_id);
    send_line(&sock_path, &capability_announcement(&session_id)).await;
    send_line(&sock_path, &IngestMessage::Event(event_a)).await;
    send_line(&sock_path, &IngestMessage::Evidence(evidence)).await;

    // Claim A's own anchor must exist and be known-consumed before the
    // race: otherwise "concurrent" would just mean "both attempts are
    // racing to be first," which `classify_consumption_by_anchor` already
    // treats as fine (either one may legitimately win FreshlyRecorded).
    // The actual guarantee under test is narrower and stronger: once an
    // owner anchor exists, a DIFFERENT anchor's concurrent attempt must
    // never also reach Verified.
    let claim_a = command_success_claim(&session_id, event_a_id);
    send_line(&sock_path, &IngestMessage::Claim(claim_a.clone())).await;
    wait_for(Duration::from_secs(10), || {
        let store = &store;
        let session_id = session_id.clone();
        let claim_id = claim_a.id.to_string();
        async move {
            store
                .findings_for_session(&session_id)
                .await
                .unwrap_or_default()
                .iter()
                .any(|f| f.claim_id == claim_id && f.verdict == "verified")
        }
    })
    .await;

    // Now fire TWO different-anchor claims, both citing the same
    // already-owned evidence row, genuinely concurrently -- each gets its
    // own UDS connection, and the daemon spawns a task per connection (see
    // `main.rs`'s accept loop), so these two really do race at the
    // application layer, not just appear sequential.
    let event_b = command_success_event(&session_id);
    let claim_b = command_success_claim(&session_id, event_b.id);
    let event_c = command_success_event(&session_id);
    let claim_c = command_success_claim(&session_id, event_c.id);

    let (send_b, send_c) = tokio::join!(
        async {
            send_line(&sock_path, &IngestMessage::Event(event_b)).await;
            send_line(&sock_path, &IngestMessage::Claim(claim_b.clone())).await;
        },
        async {
            send_line(&sock_path, &IngestMessage::Event(event_c)).await;
            send_line(&sock_path, &IngestMessage::Claim(claim_c.clone())).await;
        }
    );
    let _: ((), ()) = (send_b, send_c);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let findings = store
            .findings_for_session(&session_id)
            .await
            .expect("read findings");
        let b = findings
            .iter()
            .find(|f| f.claim_id == claim_b.id.to_string());
        let c = findings
            .iter()
            .find(|f| f.claim_id == claim_c.id.to_string());
        if let (Some(b), Some(c)) = (b, c) {
            assert_ne!(
                b.verdict,
                "verified",
                "claim B races claim C over an already-owned evidence row (owned by \
                 claim A) -- a different anchor must never reach Verified via this \
                 row even under real concurrency; daemon log:\n{}",
                daemon.log_contents()
            );
            assert_ne!(
                c.verdict,
                "verified",
                "claim C races claim B over an already-owned evidence row (owned by \
                 claim A) -- a different anchor must never reach Verified via this \
                 row even under real concurrency; daemon log:\n{}",
                daemon.log_contents()
            );
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!(
                "findings for both racing claims never appeared; daemon log:\n{}",
                daemon.log_contents()
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// FORNX-435: live-path proof of same-claim retry idempotency -- a client
/// (hook process) that resends an identical `claim_id` after, say, a
/// dropped response must not be treated as a hostile replay.
/// `insert_claim_idempotent_reports_duplicate_without_erroring` already
/// proves the store-level primitive is idempotent in isolation; this test
/// proves the live daemon path built on top of it (the `is_new_claim`
/// check in `handle_message`'s `Claim` arm, which skips re-verification
/// entirely on a duplicate) actually preserves the original Verified
/// outcome end-to-end, not just that the second insert doesn't error.
#[tokio::test]
async fn identical_claim_retry_over_uds_stays_verified_not_downgraded() {
    let daemon = start_daemon().await;
    let store = Store::open(daemon.home.join("fornax.db"))
        .await
        .expect("open store db");
    let session_id = format!("fornx435-retry-{}", short_id());
    let sock_path = daemon.home.join("fornax.sock");

    let event = command_success_event(&session_id);
    let event_id = event.id;
    let evidence = legitimate_evidence(&session_id, event_id);
    let claim = command_success_claim(&session_id, event_id);

    send_line(&sock_path, &capability_announcement(&session_id)).await;
    send_line(&sock_path, &IngestMessage::Event(event)).await;
    send_line(&sock_path, &IngestMessage::Evidence(evidence)).await;
    send_line(&sock_path, &IngestMessage::Claim(claim.clone())).await;

    wait_for(Duration::from_secs(10), || {
        let store = &store;
        let session_id = session_id.clone();
        let claim_id = claim.id.to_string();
        async move {
            store
                .findings_for_session(&session_id)
                .await
                .unwrap_or_default()
                .iter()
                .any(|f| f.claim_id == claim_id && f.verdict == "verified")
        }
    })
    .await;

    // Resend the EXACT same claim (identical id) -- simulating a client
    // retry after an uncertain/dropped response, not a new submission.
    send_line(&sock_path, &IngestMessage::Claim(claim.clone())).await;

    // Give the daemon a moment to have processed (or, correctly, skipped
    // re-processing) the retry, then confirm the original Verified finding
    // is unchanged -- no second/duplicate finding row, no downgrade.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let findings = store
        .findings_for_session(&session_id)
        .await
        .expect("read findings");
    let matching: Vec<_> = findings
        .iter()
        .filter(|f| f.claim_id == claim.id.to_string())
        .collect();
    assert_eq!(
        matching.len(),
        1,
        "a retried identical claim_id must not produce a second finding row; \
         found {} rows; daemon log:\n{}",
        matching.len(),
        daemon.log_contents()
    );
    assert_eq!(
        matching[0].verdict,
        "verified",
        "a retried identical claim_id must leave the original Verified finding \
         intact, not downgrade it; daemon log:\n{}",
        daemon.log_contents()
    );
}

/// Fixture potency (AC4): confirms each negative fixture is not simply
/// inert -- run directly through the raw `Verifier` (bypassing admission
/// entirely), it WOULD have verified. This proves the guard is actually
/// doing something, not that these fixtures could never have verified
/// anyway.
#[test]
fn negative_fixtures_would_have_verified_without_the_guard() {
    let session_id = "fornx431-potency";
    let event_id = Uuid::new_v4();
    let caps = fornax_types::RuntimeCapabilities {
        schema_version: fornax_types::CAPABILITY_SCHEMA_VERSION,
        provider: Provider::ClaudeCode,
        signals: vec![fornax_types::CapabilitySignal {
            class: fornax_types::SignalClass::ToolTrace,
            state: fornax_types::SignalAvailability::Available,
            detail: None,
        }],
        notes: Default::default(),
    };
    let verifier = CommandSuccessVerifier;

    for (name, evidence) in [
        (
            "forged_host_observed",
            evidence_with_forged_trust_class(session_id, event_id),
        ),
        (
            "unregistered_sensor",
            evidence_with_unregistered_sensor(session_id, event_id),
        ),
        ("no_source", evidence_with_no_source(session_id, event_id)),
    ] {
        let claim = command_success_claim(session_id, event_id);
        let finding = verifier.verify(&claim, std::slice::from_ref(&evidence), &caps);
        assert_eq!(
            finding.verdict,
            fornax_types::Verdict::Verified,
            "fixture {name:?} must verify when the guard is bypassed entirely -- \
             otherwise it is not a meaningful negative control for AC4"
        );
    }
}

/// FORNX-433 AC2 mutation-test proof, specifically for FORNX-441's
/// canonical `admit_evidence_rows` entry point -- one level more removed
/// from the live path than the live-daemon tests above: the real daemon's
/// `run_verifiers_and_persist_findings` calls `Store::
/// admitted_evidence_for_session` (`fornax-store/src/admitted_evidence.rs`),
/// which is the function that actually calls `admit_evidence_rows`. This
/// test calls `admit_evidence_rows` directly rather than going through the
/// store (no DB needed), so it is a proof about the guard's own real
/// entry-point function, not a full end-to-end proof through every
/// intervening layer -- the live-daemon tests above already cover that
/// end-to-end path for these same fixtures. Distinct from the test above,
/// which proves the raw `Verifier` would be fooled (bypass-and-verify), and
/// distinct from `fornax_types::provenance_guard`'s own
/// `authorize_evidence_source` unit tests, which only exercise one
/// sub-check in isolation. Note: all three fixtures below are rejected
/// before `admit_evidence_rows`'s session-owner comparison is ever reached
/// (no-source fails the missing-source check; the other two fail inside
/// `authorize_evidence_source`), so this test's hardcoded
/// `SessionOwner::Single(..)` is a safe stand-in here but does not itself
/// exercise the owner-mismatch branch -- that branch has its own coverage
/// elsewhere (see `fornax_types::provenance_guard`'s own module tests).
#[test]
fn admit_evidence_rows_rejects_every_fixture_that_would_have_verified_without_it() {
    use fornax_types::provenance_guard::{
        admit_evidence_rows, CollectorAuthority, EvidenceOrigin, SessionOwner,
    };

    let session_id = "fornx441-matrix-potency";
    let event_id = Uuid::new_v4();
    let authority = CollectorAuthority::known_sensors();

    for (name, evidence) in [
        (
            "forged_host_observed",
            evidence_with_forged_trust_class(session_id, event_id),
        ),
        (
            "unregistered_sensor",
            evidence_with_unregistered_sensor(session_id, event_id),
        ),
        ("no_source", evidence_with_no_source(session_id, event_id)),
    ] {
        let evidence_id = evidence.id;
        let outcome = admit_evidence_rows(
            vec![(evidence, EvidenceOrigin::UdsIngest)],
            session_id,
            SessionOwner::Single(Provider::ClaudeCode),
            &authority,
            None,
        );
        assert!(
            outcome.admitted.is_empty(),
            "fixture {name:?} must never reach `admitted` -- got {:?}",
            outcome.admitted
        );
        assert!(
            outcome
                .rejected
                .iter()
                .any(|r| r.evidence_id == evidence_id),
            "fixture {name:?}'s evidence id must appear in `rejected`, named by id, \
             not silently dropped: {:?}",
            outcome.rejected
        );
    }

    // Sanity control, mirroring the potency test above: legitimate evidence
    // through the same entry point must be admitted, proving this test
    // cannot pass by rejecting everything indiscriminately.
    let legit = legitimate_evidence(session_id, event_id);
    let legit_id = legit.id;
    let outcome = admit_evidence_rows(
        vec![(legit, EvidenceOrigin::UdsIngest)],
        session_id,
        SessionOwner::Single(Provider::ClaudeCode),
        &authority,
        None,
    );
    assert_eq!(
        outcome.admitted.len(),
        1,
        "legitimate evidence must be admitted: {:?}",
        outcome.rejected
    );
    assert_eq!(outcome.admitted[0].id, legit_id);
}

/// AC4 source-scan: `fornax-daemon`'s production code (excluding its own
/// `#[cfg(test)] mod tests` block and this `tests/` integration dir) must
/// contain exactly one call to `insert_finding` -- the one inside
/// `run_verifiers_and_persist_findings`, now gated by admission/consumption
/// above. A second unguarded path to persisting a finding would silently
/// defeat everything else in this file. Confirmed by inspection before
/// writing this test: `fornax-store`'s and `fornax-cli`'s own
/// `insert_finding` call sites are both inside their respective crates'
/// `#[cfg(test)] mod tests` blocks, not reachable from any real daemon
/// request path.
#[test]
fn insert_finding_has_exactly_one_production_call_site() {
    let main_rs_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs");
    let contents =
        std::fs::read_to_string(&main_rs_path).expect("read fornax-daemon's src/main.rs");

    let test_mod_start = contents
        .lines()
        .position(|line| line.trim() == "mod tests {")
        .map(|i| i + 1) // 1-indexed line number of the line itself
        .unwrap_or(usize::MAX);

    let production_call_sites: Vec<(usize, &str)> = contents
        .lines()
        .enumerate()
        .map(|(i, line)| (i + 1, line))
        .filter(|(lineno, _)| *lineno < test_mod_start)
        .filter(|(_, line)| line.contains("insert_finding("))
        .collect();

    assert_eq!(
        production_call_sites.len(),
        1,
        "expected exactly one production call site to insert_finding (inside \
         run_verifiers_and_persist_findings) before `mod tests` at line {test_mod_start}, \
         found: {production_call_sites:?} -- a second unguarded path would bypass \
         FORNX-431's admission/consumption enforcement entirely"
    );
}

/// FORNX-433 AC4 source-scan: registering a synthetic/passive adapter
/// descriptor (`fornax adapter register`, `fornax-store::adapter_registry`)
/// must never, by construction, be able to influence verdict computation --
/// "no PR considered green merely because a synthetic adapter descriptor
/// exists". The registry is designed to be inert bookkeeping (digest
/// confirmation only, explicitly "does not establish registration, trust,
/// or active capability" per `fornax-adapter-claude::host_binding`'s own
/// doc comment) -- this test makes that a structural, regression-proof
/// fact rather than only a convention: `fornax-daemon`'s production code
/// (the only crate that computes/persists a `Verdict`) contains zero
/// references to the registry's types/functions at all. If a future change
/// ever wires a registry lookup into the verdict path, this test fails
/// loudly rather than silently letting a descriptor's mere existence start
/// influencing trust.
#[test]
fn adapter_registry_has_zero_references_in_the_verdict_computing_daemon() {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let source_files: Vec<PathBuf> = std::fs::read_dir(&src_dir)
        .expect("read fornax-daemon's src/ directory")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("rs"))
        .collect();
    assert!(
        source_files.len() >= 4,
        "sanity check: expected to find at least main.rs plus the three mod files \
         declared in it (audit_checkpoint_submit, policy_poll, retention_sweep) -- \
         found {source_files:?}. If fornax-daemon's module layout changed, this \
         directory scan still finds every .rs file in src/ automatically; this \
         assertion only guards against read_dir itself silently returning nothing."
    );

    let registry_markers = [
        "adapter_registry",
        "AdapterRegistry",
        "RegistrySnapshot",
        "register_host_descriptor",
        "register_config",
        "RegistryEntry",
    ];

    let mut hits: Vec<(PathBuf, usize, &str, String)> = Vec::new();
    for path in &source_files {
        let contents = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));

        // Exclude each file's own `#[cfg(test)] mod tests` block, same
        // precedent as `insert_finding_has_exactly_one_production_call_site`
        // above -- a future unit test inside one of these files may need to
        // reference the registry's type names for an unrelated reason
        // (e.g. testing that THIS test's own scan logic works) without that
        // being a real production wiring.
        let test_mod_start = contents
            .lines()
            .position(|line| line.trim() == "mod tests {")
            .map(|i| i + 1)
            .unwrap_or(usize::MAX);

        for (i, line) in contents.lines().enumerate() {
            let lineno = i + 1;
            if lineno >= test_mod_start {
                break;
            }
            for marker in &registry_markers {
                if line.contains(marker) {
                    hits.push((path.clone(), lineno, marker, line.to_string()));
                }
            }
        }
    }

    assert!(
        hits.is_empty(),
        "fornax-daemon's production source (every .rs file in src/, excluding each \
         file's own #[cfg(test)] mod tests block) must contain zero references to \
         the adapter registry -- found {hits:?}. A descriptor's mere existence in \
         the registry must never be able to influence verdict computation; if this \
         now needs to change, it needs its own explicit trust-semantics design, not \
         an incidental import."
    );
}
