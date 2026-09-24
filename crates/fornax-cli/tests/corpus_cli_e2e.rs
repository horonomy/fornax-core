//! Real end-to-end CLI-flow test for `fornax corpus` (FORNX-341): spawns the
//! actual compiled `fornax` binary against a real, seeded `$FORNAX_HOME`
//! store -- not a function call inside the crate -- mirroring
//! `experiment_cli_e2e.rs`'s precedent for this crate.

use std::process::Command;
use uuid::Uuid;

fn fornax_bin() -> &'static str {
    env!("CARGO_BIN_EXE_fornax")
}

fn temp_home(label: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("fornax-corpus-e2e-{label}-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&path).unwrap();
    path
}

/// Seed a real store with one session that mines as a `BenignControl`: a
/// `Verified` claim, one `ExitCode` evidence item linked as `Supports`, no
/// conflict.
async fn seed_benign_session(home: &std::path::Path, session_id: &str) -> Uuid {
    let db_path = home.join("fornax.db");
    let store = fornax_store::Store::open(&db_path).await.unwrap();

    let event = fornax_types::AgentEvent {
        id: Uuid::new_v4(),
        session_id: session_id.to_string(),
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
        session_id: session_id.to_string(),
        source_event_id: event.id,
        text: "the command exited successfully".into(),
        subject: "command_succeeded".into(),
        claimed_at: "2026-01-01T00:00:00Z".into(),
    };
    store.insert_claim(&claim).await.unwrap();

    let evidence = fornax_types::Evidence {
        id: Uuid::new_v4(),
        session_id: session_id.to_string(),
        source_event_id: event.id,
        kind: fornax_types::EvidenceKind::ExitCode,
        observed_at: "2026-01-01T00:00:00Z".into(),
        payload: serde_json::json!({"code": 0}),
        provenance: "test".into(),
        source: None,
        extension: None,
        evidence_purged: false,
    };
    store.insert_evidence(&evidence).await.unwrap();

    store
        .insert_evidence_link(&fornax_types::EvidenceLink {
            id: Uuid::new_v4(),
            session_id: session_id.to_string(),
            claim_id: claim.id,
            evidence_id: evidence.id,
            relation: fornax_types::EvidenceRelation::Supports,
            linked_at: "2026-01-01T00:00:00Z".into(),
        })
        .await
        .unwrap();

    claim.id
}

#[tokio::test]
async fn mine_refuses_with_a_clear_message_when_the_gate_is_closed() {
    let home = temp_home("gate-closed");
    seed_benign_session(&home, "s1").await;

    let output = Command::new(fornax_bin())
        .env("FORNAX_HOME", &home)
        .env_remove("FORNAX_CORPUS_MINING_ENABLED")
        .args(["corpus", "mine", "--session", "s1"])
        .output()
        .unwrap();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("FORNAX_CORPUS_MINING_ENABLED"),
        "refusal must name the env var an operator needs to set: {combined}"
    );

    std::fs::remove_dir_all(&home).ok();
}

#[tokio::test]
async fn mine_then_export_produces_a_manifest_with_a_benign_control() {
    let home = temp_home("mine-export");
    seed_benign_session(&home, "s1").await;

    let mine_output = Command::new(fornax_bin())
        .env("FORNAX_HOME", &home)
        .env("FORNAX_CORPUS_MINING_ENABLED", "1")
        .args(["corpus", "mine", "--session", "s1"])
        .output()
        .unwrap();
    let mine_text = String::from_utf8_lossy(&mine_output.stdout);
    assert!(
        mine_text.contains("1 candidate(s) mined"),
        "expected exactly one candidate mined: {mine_text}"
    );

    let out_path = home.join("corpus-manifest.json");
    let export_output = Command::new(fornax_bin())
        .env("FORNAX_HOME", &home)
        .env("FORNAX_CORPUS_MINING_ENABLED", "1")
        .args([
            "corpus",
            "export",
            "--out",
            out_path.to_str().unwrap(),
            "--corpus-version",
            "test-v1",
        ])
        .output()
        .unwrap();
    let export_text = String::from_utf8_lossy(&export_output.stdout);
    assert!(
        export_text.contains("1 candidate(s) (1 control(s))"),
        "expected the mined candidate to be a benign control: {export_text}"
    );

    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&out_path).unwrap()).unwrap();
    assert_eq!(manifest["candidate_count"], 1);
    assert_eq!(manifest["control_count"], 1);
    assert_eq!(manifest["contains_adjudicated_labels"], false);
    // No candidate carries an adjudication field.
    for candidate in manifest["candidates"].as_array().unwrap() {
        assert!(candidate.get("adjudicated_expected_outcome").is_none());
        assert!(candidate.get("labeling_provenance").is_none());
    }

    std::fs::remove_dir_all(&home).ok();
}

#[tokio::test]
async fn export_writes_only_to_the_exact_path_given_never_deriving_one() {
    let home = temp_home("export-path");
    seed_benign_session(&home, "s1").await;

    Command::new(fornax_bin())
        .env("FORNAX_HOME", &home)
        .env("FORNAX_CORPUS_MINING_ENABLED", "1")
        .args(["corpus", "mine", "--session", "s1"])
        .output()
        .unwrap();

    // A session/candidate id could contain path-hostile characters in
    // principle; the CLI never derives a filename from one -- `--out` is
    // the only source of the output path.
    let out_dir = home.join("nested").join("dir");
    std::fs::create_dir_all(&out_dir).unwrap();
    let out_path = out_dir.join("exact-name.json");

    let export_output = Command::new(fornax_bin())
        .env("FORNAX_HOME", &home)
        .env("FORNAX_CORPUS_MINING_ENABLED", "1")
        .args([
            "corpus",
            "export",
            "--out",
            out_path.to_str().unwrap(),
            "--corpus-version",
            "test-v1",
        ])
        .output()
        .unwrap();
    assert!(export_output.status.success());
    assert!(
        out_path.exists(),
        "the manifest must exist at exactly --out"
    );

    std::fs::remove_dir_all(&home).ok();
}
