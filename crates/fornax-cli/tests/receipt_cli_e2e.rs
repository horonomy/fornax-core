//! Real end-to-end CLI test for `fornax receipt issue`/`fornax receipt
//! verify` (FORNX-350): spawns the actual compiled `fornax` binary against
//! a real, seeded `$FORNAX_HOME` store, exercising issue -> verify -> gate
//! end to end, plus the committed policy fixtures in
//! `crates/fornax-cli/fixtures/receipts/`.

use std::path::Path;
use std::process::Command;
use uuid::Uuid;

fn fornax_bin() -> &'static str {
    env!("CARGO_BIN_EXE_fornax")
}

fn temp_home(label: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("fornax-receipt-e2e-{label}-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn fixture(name: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/receipts")
        .join(name)
        .to_str()
        .unwrap()
        .to_string()
}

/// Seeds a store with one session/claim/two-independently-correlated-
/// supporting-evidence trajectory -- the *only* combination that reaches
/// `Verdict::Verified` + `UncertaintyBand::Corroborated` (and therefore
/// `RecommendationAction::Proceed`) under `BaselineFusionPolicy`/
/// `DefaultRiskPolicy` today: two `Supports` links, each stamping a
/// distinct `correlation_group` (mirrors
/// `fusion_tests::two_supports_in_distinct_correlation_groups_are_corroborated`).
/// A single generic evidence item lands in `UncertaintyBand::Qualified`
/// (an `IndependenceUnverified` caveat fires) and decides `Review`, never
/// `Proceed` -- see `docs/adr/0017-evidence-source-independence.md` and
/// `docs/adr/0020-integrity-regression-lab.md` for the same finding.
/// Returns `(session_id, claim_id)`.
async fn seed_clean_claim(home: &std::path::Path) -> (String, String) {
    let db_path = home.join("fornax.db");
    let store = fornax_store::Store::open(&db_path).await.unwrap();
    let session_id = "s1".to_string();

    let event = fornax_types::AgentEvent {
        id: Uuid::new_v4(),
        session_id: session_id.clone(),
        provider: fornax_types::Provider::ClaudeCode,
        kind: fornax_types::EventKind::PostToolUse,
        observed_at: "2026-01-01T00:00:00Z".into(),
        tool_name: Some("Bash".into()),
        tool_input: None,
        tool_response: None,
        raw: serde_json::json!({}),
    };
    store.insert_event(&event).await.unwrap();

    let claim = fornax_types::Claim {
        id: Uuid::new_v4(),
        session_id: session_id.clone(),
        source_event_id: event.id,
        text: "the command exited successfully".into(),
        subject: "command_succeeded".into(),
        claimed_at: "2026-01-01T00:00:00Z".into(),
    };
    store.insert_claim(&claim).await.unwrap();

    for i in 0..2 {
        // A distinct AgentEvent per evidence item -- both the FK
        // (evidence.source_event_id -> agent_events.id) and
        // FusionRule::CommonSourceCollapsed (which would otherwise fold
        // two same-source_event_id AgentAdjacent supports into one
        // effective vote) require this, not just the correlation_group.
        let source_event = fornax_types::AgentEvent {
            id: Uuid::new_v4(),
            session_id: session_id.clone(),
            provider: fornax_types::Provider::ClaudeCode,
            kind: fornax_types::EventKind::PostToolUse,
            observed_at: "2026-01-01T00:00:00Z".into(),
            tool_name: Some(format!("Bash{i}")),
            tool_input: None,
            tool_response: None,
            raw: serde_json::json!({}),
        };
        store.insert_event(&source_event).await.unwrap();

        let mut evidence = fornax_types::Evidence {
            id: Uuid::new_v4(),
            session_id: session_id.clone(),
            source_event_id: source_event.id,
            kind: fornax_types::EvidenceKind::ExitCode,
            observed_at: "2026-01-01T00:00:00Z".into(),
            payload: serde_json::json!({"code": 0}),
            provenance: "test".into(),
            source: Some(fornax_types::EvidenceSource::now(
                "exit_code_probe",
                fornax_types::TrustClass::AgentAdjacent,
                None,
                fornax_types::CollectionMethod::HookCallback,
                None,
            )),
            extension: None,
            evidence_purged: false,
        };
        evidence.source.as_mut().unwrap().correlation_group = Some(Uuid::new_v4());
        // FORNX-441: `fornax receipt issue` now reads
        // `admitted_evidence_for_claim`, which rejects `EvidenceOrigin::
        // Unknown` (what plain `insert_evidence` stamps). This fixture's
        // "exit_code_probe" sensor name is illustrative, not a real
        // registered sensor, and this test is about receipt/gate
        // behavior, not sensor-trust enforcement -- `DaemonAcquisition`
        // admits by origin alone, same as a real acquisition-path row.
        store
            .insert_evidence_with_origin(
                &evidence,
                fornax_types::provenance_guard::EvidenceOrigin::DaemonAcquisition,
            )
            .await
            .unwrap();

        store
            .insert_evidence_link(&fornax_types::EvidenceLink {
                id: Uuid::new_v4(),
                session_id: session_id.clone(),
                claim_id: claim.id,
                evidence_id: evidence.id,
                relation: fornax_types::EvidenceRelation::Supports,
                linked_at: "2026-01-01T00:00:00Z".into(),
            })
            .await
            .unwrap();
    }

    (session_id, claim.id.to_string())
}

/// FORNX-441: per the independent security review of this PR, `fornax
/// receipt issue` had no adversarial (forged-sensor) regression test of
/// its own. Seeds one legitimate control evidence item (a real sensor
/// asserting its own authorized trust class) and one forged item (the
/// same sensor asserting a trust class it was never authorized for --
/// the fornx380-11 shape), both `Supports`-linked to the same claim.
/// Returns `(session_id, claim_id, control_evidence_id, forged_evidence_id)`.
async fn seed_claim_with_control_and_forged_evidence(
    home: &std::path::Path,
) -> (String, String, Uuid, Uuid) {
    let db_path = home.join("fornax.db");
    let store = fornax_store::Store::open(&db_path).await.unwrap();
    let session_id = "s-matrix".to_string();

    let event = fornax_types::AgentEvent {
        id: Uuid::new_v4(),
        session_id: session_id.clone(),
        provider: fornax_types::Provider::ClaudeCode,
        kind: fornax_types::EventKind::PostToolUse,
        observed_at: "2026-01-01T00:00:00Z".into(),
        tool_name: Some("Bash".into()),
        tool_input: None,
        tool_response: None,
        raw: serde_json::json!({}),
    };
    store.insert_event(&event).await.unwrap();

    let claim = fornax_types::Claim {
        id: Uuid::new_v4(),
        session_id: session_id.clone(),
        source_event_id: event.id,
        text: "the command exited successfully".into(),
        subject: "command_succeeded".into(),
        claimed_at: "2026-01-01T00:00:00Z".into(),
    };
    store.insert_claim(&claim).await.unwrap();

    // `claude_bash_exit_code_sensor_v1` is a real registered sensor, but
    // only ever authorized for AgentAdjacent (see
    // `CollectorAuthority::known_sensors`).
    let sensor_source = |trust: fornax_types::TrustClass| {
        fornax_types::EvidenceSource::now(
            "claude_bash_exit_code_sensor_v1",
            trust,
            None,
            fornax_types::CollectionMethod::HookCallback,
            None,
        )
    };
    let control = fornax_types::Evidence {
        id: Uuid::new_v4(),
        session_id: session_id.clone(),
        source_event_id: event.id,
        kind: fornax_types::EvidenceKind::ExitCode,
        observed_at: "2026-01-01T00:00:00Z".into(),
        payload: serde_json::json!({"code": 0}),
        provenance: "test".into(),
        source: Some(sensor_source(fornax_types::TrustClass::AgentAdjacent)),
        extension: None,
        evidence_purged: false,
    };
    let forged = fornax_types::Evidence {
        id: Uuid::new_v4(),
        session_id: session_id.clone(),
        source_event_id: event.id,
        kind: fornax_types::EvidenceKind::ExitCode,
        observed_at: "2026-01-01T00:00:00Z".into(),
        payload: serde_json::json!({"code": 0}),
        provenance: "test".into(),
        // Forges HostObserved under the same sensor identity -- never
        // authorized for it.
        source: Some(sensor_source(fornax_types::TrustClass::HostObserved)),
        extension: None,
        evidence_purged: false,
    };
    for ev in [&control, &forged] {
        store
            .insert_evidence_with_origin(
                ev,
                fornax_types::provenance_guard::EvidenceOrigin::UdsIngest,
            )
            .await
            .unwrap();
        store
            .insert_evidence_link(&fornax_types::EvidenceLink {
                id: Uuid::new_v4(),
                session_id: session_id.clone(),
                claim_id: claim.id,
                evidence_id: ev.id,
                relation: fornax_types::EvidenceRelation::Supports,
                linked_at: "2026-01-01T00:00:00Z".into(),
            })
            .await
            .unwrap();
    }

    (session_id, claim.id.to_string(), control.id, forged.id)
}

fn run(home: &std::path::Path, args: &[&str]) -> (bool, String, String) {
    let output = Command::new(fornax_bin())
        .env("FORNAX_HOME", home)
        .args(args)
        .output()
        .unwrap();
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

fn run_with_code(home: &std::path::Path, args: &[&str]) -> (i32, String) {
    let output = Command::new(fornax_bin())
        .env("FORNAX_HOME", home)
        .args(args)
        .output()
        .unwrap();
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
    )
}

#[tokio::test]
async fn issuing_and_verifying_a_receipt_with_ttl_accepts() {
    let home = temp_home("accept");
    let (session, claim) = seed_clean_claim(&home).await;
    let out = home.join("receipt.json");

    let (ok, stdout, stderr) = run(
        &home,
        &[
            "receipt",
            "issue",
            "--session",
            &session,
            "--claim",
            &claim,
            "--ttl-seconds",
            "86400",
            "--out",
            out.to_str().unwrap(),
        ],
    );
    assert!(ok, "issue failed: stdout={stdout} stderr={stderr}");
    assert!(out.exists());

    let (code, stdout) = run_with_code(&home, &["receipt", "verify", out.to_str().unwrap()]);
    assert_eq!(code, 0, "expected Accept exit code 0: {stdout}");
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed["gate"]["outcome"], "accept");
    assert_eq!(parsed["verdict"], "verified");

    std::fs::remove_dir_all(&home).ok();
}

#[tokio::test]
async fn issuing_a_receipt_with_no_ttl_holds_on_verify_under_the_default_policy() {
    let home = temp_home("no-ttl-hold");
    let (session, claim) = seed_clean_claim(&home).await;
    let out = home.join("receipt.json");

    run(
        &home,
        &[
            "receipt",
            "issue",
            "--session",
            &session,
            "--claim",
            &claim,
            "--out",
            out.to_str().unwrap(),
        ],
    );

    let (code, stdout) = run_with_code(&home, &["receipt", "verify", out.to_str().unwrap()]);
    assert_eq!(
        code, 11,
        "no declared expiry must Hold (11) under the default require_expiry policy: {stdout}"
    );
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed["gate"]["outcome"], "hold");

    std::fs::remove_dir_all(&home).ok();
}

#[tokio::test]
async fn a_tampered_receipt_body_is_rejected_on_verify() {
    let home = temp_home("tampered");
    let (session, claim) = seed_clean_claim(&home).await;
    let out = home.join("receipt.json");

    run(
        &home,
        &[
            "receipt",
            "issue",
            "--session",
            &session,
            "--claim",
            &claim,
            "--ttl-seconds",
            "86400",
            "--out",
            out.to_str().unwrap(),
        ],
    );

    // Flip the finding's verdict after issuance -- the digest was computed
    // over the original body, so this must fail the digest check.
    let mut json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
    json["body"]["finding"]["verdict"] = serde_json::json!("contradicted");
    std::fs::write(&out, serde_json::to_string_pretty(&json).unwrap()).unwrap();

    let output = Command::new(fornax_bin())
        .env("FORNAX_HOME", &home)
        .args(["receipt", "verify", out.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "a tampered receipt must never verify successfully"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("digest") || stderr.contains("does not match"),
        "expected a digest-mismatch error: {stderr}"
    );

    std::fs::remove_dir_all(&home).ok();
}

#[tokio::test]
async fn the_committed_uncalibrated_policy_fixture_always_resolves_untested() {
    let home = temp_home("uncalibrated");
    let (session, claim) = seed_clean_claim(&home).await;
    let out = home.join("receipt.json");
    run(
        &home,
        &[
            "receipt",
            "issue",
            "--session",
            &session,
            "--claim",
            &claim,
            "--ttl-seconds",
            "86400",
            "--out",
            out.to_str().unwrap(),
        ],
    );

    let policy = fixture("uncalibrated-policy.json");
    let (code, stdout) = run_with_code(
        &home,
        &[
            "receipt",
            "verify",
            out.to_str().unwrap(),
            "--policy",
            &policy,
        ],
    );
    assert_eq!(
        code, 12,
        "the committed uncalibrated policy must never resolve to Accept: {stdout}"
    );

    std::fs::remove_dir_all(&home).ok();
}

#[tokio::test]
async fn the_committed_require_signature_policy_holds_an_unsigned_receipt() {
    let home = temp_home("require-sig");
    let (session, claim) = seed_clean_claim(&home).await;
    let out = home.join("receipt.json");
    run(
        &home,
        &[
            "receipt",
            "issue",
            "--session",
            &session,
            "--claim",
            &claim,
            "--ttl-seconds",
            "86400",
            "--out",
            out.to_str().unwrap(),
        ],
    );

    let policy = fixture("require-signature-policy.json");
    let (code, stdout) = run_with_code(
        &home,
        &[
            "receipt",
            "verify",
            out.to_str().unwrap(),
            "--policy",
            &policy,
        ],
    );
    assert_eq!(
        code, 11,
        "an unsigned receipt under a signature-required policy must Hold, never Accept or \
         silently pass: {stdout}"
    );

    std::fs::remove_dir_all(&home).ok();
}

/// FORNX-441 adversarial matrix: `fornax receipt issue` must never
/// reference the forged row in its coverage, and must still reference the
/// legitimate control (proving this test can't pass by rejecting
/// everything).
#[tokio::test]
async fn issuing_a_receipt_excludes_forged_evidence_but_references_the_control() {
    let home = temp_home("matrix");
    let (session, claim, control_id, forged_id) =
        seed_claim_with_control_and_forged_evidence(&home).await;
    let out = home.join("receipt.json");

    let (ok, stdout, stderr) = run(
        &home,
        &[
            "receipt",
            "issue",
            "--session",
            &session,
            "--claim",
            &claim,
            "--out",
            out.to_str().unwrap(),
        ],
    );
    assert!(ok, "issue failed: stdout={stdout} stderr={stderr}");

    let body: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    let referenced: Vec<String> = body["body"]["coverage"]["referenced_evidence"]
        .as_array()
        .expect("referenced_evidence array")
        .iter()
        .map(|e| e["evidence_id"].as_str().unwrap_or_default().to_string())
        .collect();
    assert!(
        referenced.contains(&control_id.to_string()),
        "the control evidence must be referenced in the receipt's coverage, proving this test \
         cannot pass by rejecting everything: {body}"
    );
    assert!(
        !referenced.contains(&forged_id.to_string()),
        "the forged evidence must never be referenced in a signed receipt's coverage: {body}"
    );

    std::fs::remove_dir_all(&home).ok();
}
