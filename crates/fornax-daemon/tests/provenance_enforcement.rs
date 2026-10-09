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
