//! Real end-to-end CLI-flow test for `fornax adjudicate` (FORNX-342): spawns
//! the actual compiled `fornax` binary against a real, seeded `$FORNAX_HOME`
//! store, exercising blinded review -> disagreement -> adjudication ->
//! frozen gold label -> export end to end.
//!
//! **Every reviewer registered here is `--kind mechanism-test`.** No test in
//! this file registers a `Human` reviewer or reports a real inter-rater
//! agreement figure -- doing so requires a real person actually using
//! `fornax adjudicate`. See `docs/adr/0014-corpus-adjudication.md`.

use std::process::Command;
use uuid::Uuid;

fn fornax_bin() -> &'static str {
    env!("CARGO_BIN_EXE_fornax")
}

fn temp_home(label: &str) -> std::path::PathBuf {
    let path =
        std::env::temp_dir().join(format!("fornax-adjudicate-e2e-{label}-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&path).unwrap();
    path
}

/// Seed a store with `n` sessions, each mining as a distinct
/// `EvidenceContradiction` candidate (a real conflict, not a benign
/// control), and return their candidate ids.
async fn seed_contradiction_sessions(home: &std::path::Path, n: usize) -> Vec<String> {
    let db_path = home.join("fornax.db");
    let store = fornax_store::Store::open(&db_path).await.unwrap();
    let mut case_ids = Vec::new();

    for i in 0..n {
        let session_id = format!("s{i}");
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

        let ev1 = fornax_types::Evidence {
            id: Uuid::new_v4(),
            session_id: session_id.clone(),
            source_event_id: event.id,
            kind: fornax_types::EvidenceKind::ExitCode,
            observed_at: "2026-01-01T00:00:00Z".into(),
            payload: serde_json::json!({"code": 0}),
            provenance: "test".into(),
            source: None,
            extension: None,
            evidence_purged: false,
        };
        let ev2 = fornax_types::Evidence {
            id: Uuid::new_v4(),
            session_id: session_id.clone(),
            source_event_id: event.id,
            kind: fornax_types::EvidenceKind::ExitCode,
            observed_at: "2026-01-01T00:00:00Z".into(),
            payload: serde_json::json!({"code": 1}),
            provenance: "test".into(),
            source: None,
            extension: None,
            evidence_purged: false,
        };
        store.insert_evidence(&ev1).await.unwrap();
        store.insert_evidence(&ev2).await.unwrap();

        store
            .insert_evidence_link(&fornax_types::EvidenceLink {
                id: Uuid::new_v4(),
                session_id: session_id.clone(),
                claim_id: claim.id,
                evidence_id: ev1.id,
                relation: fornax_types::EvidenceRelation::Supports,
                linked_at: "2026-01-01T00:00:00Z".into(),
            })
            .await
            .unwrap();
        store
            .insert_evidence_link(&fornax_types::EvidenceLink {
                id: Uuid::new_v4(),
                session_id: session_id.clone(),
                claim_id: claim.id,
                evidence_id: ev2.id,
                relation: fornax_types::EvidenceRelation::Contradicts,
                linked_at: "2026-01-01T00:00:00Z".into(),
            })
            .await
            .unwrap();

        let mine = Command::new(fornax_bin())
            .env("FORNAX_HOME", home)
            .env("FORNAX_CORPUS_MINING_ENABLED", "1")
            .args(["corpus", "mine", "--session", &session_id])
            .output()
            .unwrap();
        assert!(mine.status.success());

        let candidates = store
            .corpus_candidates_for_session(&session_id)
            .await
            .unwrap();
        assert_eq!(candidates.len(), 1);
        case_ids.push(candidates[0].id.clone());
    }

    case_ids
}

fn run(home: &std::path::Path, args: &[&str]) -> String {
    let output = Command::new(fornax_bin())
        .env("FORNAX_HOME", home)
        .env("FORNAX_CORPUS_MINING_ENABLED", "1")
        .args(args)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    assert!(
        output.status.success(),
        "command {args:?} failed: stdout={stdout} stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    stdout
}

#[tokio::test]
async fn single_review_resolves_and_exports_as_synthetic() {
    let home = temp_home("single-review");
    let case_ids = seed_contradiction_sessions(&home, 1).await;
    let case = &case_ids[0];

    run(
        &home,
        &[
            "adjudicate",
            "reviewer-add",
            "--id",
            "fixture-1",
            "--role",
            "primary",
            "--kind",
            "mechanism-test",
        ],
    );
    run(&home, &["adjudicate", "enqueue", "--case", case]);

    let next_out = run(
        &home,
        &[
            "adjudicate",
            "next",
            "--reviewer",
            "fixture-1",
            "--case",
            case,
        ],
    );
    assert!(
        !next_out.to_lowercase().contains("contradicted"),
        "blinded view must not leak the verdict"
    );
    let view_id = next_out
        .lines()
        .find(|l| l.starts_with("view: "))
        .unwrap()
        .trim_start_matches("view: ")
        .to_string();

    run(
        &home,
        &[
            "adjudicate",
            "submit",
            "--view",
            &view_id,
            "--label",
            "contradicted",
            "--critical-failure",
            "--failure-class",
            "claim-contradicted-by-evidence",
            "--confidence",
            "high",
            "--rationale",
            "clear contradiction",
        ],
    );

    let queue_out = run(&home, &["adjudicate", "queue"]);
    assert!(
        queue_out.contains("Resolved"),
        "expected Resolved state: {queue_out}"
    );

    run(
        &home,
        &[
            "adjudicate",
            "freeze",
            "--case",
            case,
            "--by",
            "fixture-adjudicator",
        ],
    );

    let out_path = home.join("dataset.json");
    let export_out = run(
        &home,
        &[
            "adjudicate",
            "export",
            "--out",
            out_path.to_str().unwrap(),
            "--dataset-version",
            "v1",
        ],
    );
    assert!(export_out.contains("wrote 1 trajectory"), "{export_out}");

    let dataset: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&out_path).unwrap()).unwrap();
    let trajectories = dataset["trajectories"].as_array().unwrap();
    assert_eq!(trajectories.len(), 1);
    assert_eq!(
        trajectories[0]["labeling_provenance"]["kind"], "synthetic_mechanism_test",
        "a mechanism-test reviewer must never export as human_adjudicated"
    );
    assert_eq!(
        trajectories[0]["adjudicated_expected_outcome"]["expected_verdict"],
        "contradicted"
    );

    std::fs::remove_dir_all(&home).ok();
}

#[tokio::test]
async fn double_review_disagreement_requires_adjudicator_then_freezes() {
    let home = temp_home("disagreement");
    let case_ids = seed_contradiction_sessions(&home, 1).await;
    let case = &case_ids[0];

    run(
        &home,
        &[
            "adjudicate",
            "reviewer-add",
            "--id",
            "fixture-primary",
            "--role",
            "primary",
            "--kind",
            "mechanism-test",
        ],
    );
    run(
        &home,
        &[
            "adjudicate",
            "reviewer-add",
            "--id",
            "fixture-secondary",
            "--role",
            "secondary",
            "--kind",
            "mechanism-test",
        ],
    );
    run(
        &home,
        &[
            "adjudicate",
            "reviewer-add",
            "--id",
            "fixture-adj",
            "--role",
            "adjudicator",
            "--kind",
            "mechanism-test",
        ],
    );
    run(
        &home,
        &[
            "adjudicate",
            "enqueue",
            "--case",
            case,
            "--double-review",
            "--reason",
            "contradiction",
        ],
    );

    let view1 = view_id_from(&run(
        &home,
        &[
            "adjudicate",
            "next",
            "--reviewer",
            "fixture-primary",
            "--case",
            case,
        ],
    ));
    run(
        &home,
        &[
            "adjudicate",
            "submit",
            "--view",
            &view1,
            "--label",
            "contradicted",
            "--confidence",
            "high",
            "--rationale",
            "r1",
        ],
    );

    let queue_after_one = run(&home, &["adjudicate", "queue"]);
    assert!(
        queue_after_one.contains("AwaitingSecondary"),
        "{queue_after_one}"
    );

    let view2 = view_id_from(&run(
        &home,
        &[
            "adjudicate",
            "next",
            "--reviewer",
            "fixture-secondary",
            "--case",
            case,
        ],
    ));
    run(
        &home,
        &[
            "adjudicate",
            "submit",
            "--view",
            &view2,
            "--label",
            "unreliable",
            "--confidence",
            "medium",
            "--rationale",
            "r2",
        ],
    );

    let disagreements = run(&home, &["adjudicate", "disagreements"]);
    assert!(disagreements.contains(case.as_str()), "{disagreements}");

    let view3 = view_id_from(&run(
        &home,
        &[
            "adjudicate",
            "next",
            "--reviewer",
            "fixture-adj",
            "--case",
            case,
            "--unblinded",
        ],
    ));
    run(
        &home,
        &[
            "adjudicate",
            "submit",
            "--view",
            &view3,
            "--label",
            "contradicted",
            "--critical-failure",
            "--confidence",
            "high",
            "--rationale",
            "adjudicator sides with primary",
        ],
    );

    let queue_final = run(&home, &["adjudicate", "queue"]);
    assert!(queue_final.contains("Resolved"), "{queue_final}");

    run(
        &home,
        &[
            "adjudicate",
            "freeze",
            "--case",
            case,
            "--by",
            "fixture-adj",
        ],
    );

    let report = run(&home, &["adjudicate", "report"]);
    assert!(
        report.contains("Insufficient"),
        "kappa must not fabricate a number with 1 double-reviewed case: {report}"
    );

    std::fs::remove_dir_all(&home).ok();
}

#[tokio::test]
async fn a_repeat_submission_by_the_same_reviewer_is_refused() {
    let home = temp_home("repeat-reviewer");
    let case_ids = seed_contradiction_sessions(&home, 1).await;
    let case = &case_ids[0];

    run(
        &home,
        &[
            "adjudicate",
            "reviewer-add",
            "--id",
            "fixture-1",
            "--role",
            "primary",
            "--kind",
            "mechanism-test",
        ],
    );
    run(&home, &["adjudicate", "enqueue", "--case", case]);

    let view1 = view_id_from(&run(
        &home,
        &[
            "adjudicate",
            "next",
            "--reviewer",
            "fixture-1",
            "--case",
            case,
        ],
    ));
    run(
        &home,
        &[
            "adjudicate",
            "submit",
            "--view",
            &view1,
            "--label",
            "contradicted",
            "--confidence",
            "high",
            "--rationale",
            "r1",
        ],
    );

    let view2 = view_id_from(&run(
        &home,
        &[
            "adjudicate",
            "next",
            "--reviewer",
            "fixture-1",
            "--case",
            case,
        ],
    ));
    let output = Command::new(fornax_bin())
        .env("FORNAX_HOME", &home)
        .env("FORNAX_CORPUS_MINING_ENABLED", "1")
        .args([
            "adjudicate",
            "submit",
            "--view",
            &view2,
            "--label",
            "reliable",
            "--confidence",
            "low",
            "--rationale",
            "changed my mind",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("already reviewed"), "{stderr}");

    std::fs::remove_dir_all(&home).ok();
}

fn view_id_from(output: &str) -> String {
    output
        .lines()
        .find(|l| l.starts_with("view: "))
        .unwrap()
        .trim_start_matches("view: ")
        .to_string()
}

/// FORNX-349 AC1/AC2/AC3/AC4: `fornax feedback submit` records an
/// agent-authored disagreement, and `fornax adjudicate sample` picks the
/// disagreed-with case up as a real, named `HumanFeedbackDisagreement`
/// signal -- without that feedback ever becoming a `ReviewOutcome`/
/// `CaseLabel` (see `feedback_module_never_references_adjudication_label_or_gold_types`
/// in `fornax-corpus` for the structural half of that guarantee).
#[tokio::test]
async fn feedback_disagreement_surfaces_in_sample_and_is_enqueued_once() {
    let home = temp_home("sample-feedback");
    let case_ids = seed_contradiction_sessions(&home, 1).await;
    let case = &case_ids[0];

    let submit_out = run(
        &home,
        &[
            "feedback",
            "submit",
            "--case",
            case,
            "--disposition",
            "disagrees-with-finding",
            "--reason",
            "the exit-code contradiction looks like a flaky retry, not a real conflict",
            "--confidence",
            "medium",
            "--as-agent",
            "fixture-agent-1",
        ],
    );
    assert!(submit_out.contains("recorded"), "{submit_out}");

    let dry_run_out = run(
        &home,
        &["adjudicate", "sample", "--budget", "5", "--dry-run"],
    );
    assert!(
        dry_run_out.contains(case.as_str()),
        "case with feedback disagreement must be selected: {dry_run_out}"
    );
    assert!(
        dry_run_out.contains("HumanFeedbackDisagreement"),
        "selection must be attributed to the real signal it was found by: {dry_run_out}"
    );
    assert!(
        dry_run_out.contains("dry run, nothing enqueued"),
        "{dry_run_out}"
    );

    let queue_after_dry_run = run(&home, &["adjudicate", "queue"]);
    assert!(
        !queue_after_dry_run.contains(case.as_str()),
        "dry run must not enqueue: {queue_after_dry_run}"
    );

    let sample_out = run(&home, &["adjudicate", "sample", "--budget", "5"]);
    assert!(sample_out.contains("enqueued 1 case"), "{sample_out}");

    let queue_after_sample = run(&home, &["adjudicate", "queue"]);
    assert!(
        queue_after_sample.contains(case.as_str()),
        "{queue_after_sample}"
    );

    // Running `sample` again must never double-enqueue the same case.
    let second_sample_out = run(&home, &["adjudicate", "sample", "--budget", "5"]);
    assert!(
        second_sample_out.contains("0 selected"),
        "already-enqueued case must be excluded: {second_sample_out}"
    );

    std::fs::remove_dir_all(&home).ok();
}

/// `worksheet-export` should auto-enqueue and auto-issue views for a whole
/// batch in one command, and `worksheet-import` should submit every filled
/// entry in one command -- the FORNX-343 batch-prep ergonomics: no
/// per-case `next`/`submit` round trips.
#[tokio::test]
async fn worksheet_export_then_import_submits_every_filled_entry_in_one_command() {
    let home = temp_home("worksheet");
    let case_ids = seed_contradiction_sessions(&home, 2).await;

    run(
        &home,
        &[
            "adjudicate",
            "reviewer-add",
            "--id",
            "fixture-ws",
            "--role",
            "primary",
            "--kind",
            "mechanism-test",
        ],
    );

    let worksheet_path = home.join("worksheet.json");
    let export_out = run(
        &home,
        &[
            "adjudicate",
            "worksheet-export",
            "--reviewer",
            "fixture-ws",
            "--case",
            &case_ids.join(","),
            "--out",
            worksheet_path.to_str().unwrap(),
        ],
    );
    assert!(export_out.contains("wrote 2 entries"), "{export_out}");

    let mut worksheet: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&worksheet_path).unwrap()).unwrap();
    assert!(
        worksheet["instructions"]
            .as_str()
            .unwrap()
            .contains("reliable"),
        "worksheet must embed the rubric, not just point at a doc"
    );
    let entries = worksheet["entries"].as_array_mut().unwrap();
    assert_eq!(entries.len(), 2);
    for e in entries.iter() {
        assert!(
            !e["claim_text"].as_str().unwrap().is_empty(),
            "blinded view must still carry the claim text"
        );
        assert!(e["label"].is_null(), "must start unfilled");
    }

    // Fill in only the first entry -- the second stays blank, simulating a
    // reviewer who stopped partway through the batch.
    entries[0]["label"] = serde_json::json!("contradicted");
    entries[0]["critical_failure"] = serde_json::json!(true);
    entries[0]["failure_class"] = serde_json::json!("claim_contradicted_by_evidence");
    entries[0]["confidence"] = serde_json::json!("high");
    entries[0]["rationale"] = serde_json::json!("evidence pool directly contradicts the claim");
    std::fs::write(
        &worksheet_path,
        serde_json::to_vec_pretty(&worksheet).unwrap(),
    )
    .unwrap();

    let import_out = run(
        &home,
        &[
            "adjudicate",
            "worksheet-import",
            "--file",
            worksheet_path.to_str().unwrap(),
        ],
    );
    assert!(
        import_out.contains("1 submitted, 1 skipped, 0 failed"),
        "{import_out}"
    );

    let queue_out = run(&home, &["adjudicate", "queue"]);
    assert!(
        queue_out.contains("Resolved"),
        "the filled case must reach Resolved: {queue_out}"
    );
    assert!(
        !queue_out.contains(&format!("{} state=Resolved", case_ids[1])),
        "the unfilled case must not have been submitted: {queue_out}"
    );
    assert!(
        queue_out.contains(&format!("{} state=AwaitingPrimary", case_ids[1])),
        "the unfilled case must still be waiting on its first review: {queue_out}"
    );

    std::fs::remove_dir_all(&home).ok();
}
