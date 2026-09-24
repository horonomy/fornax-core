//! FORNX-98 AC 5: a real Claude Code session (via a sanitized golden
//! fixture from `fornax-adapter-conformance`) can be replayed end-to-end
//! through this engine.
//!
//! The fixture kit (`fornax_adapter_conformance::load_fixtures`) replays
//! provider-native events through a real `AgentAdapter` and yields
//! `IngestMessage`s -- exactly one step short of what this crate's
//! `ReplayManifest` needs (a `Claim` + evidence pool + graph). The glue this
//! test adds is the minimal piece described in the ticket: none of today's
//! simple one-shot fixtures happen to include a `SessionEnd`/`Stop` hook (the
//! only native shape `ClaudeAdapter` currently turns into a `Claim`), so this
//! test synthesizes the claim the fixture's real, adapter-derived `Evidence`
//! is about, then links that real evidence to it -- it does not fabricate
//! any evidence itself.
//!
//! This crate depends on `fornax-adapter-conformance` and
//! `fornax-adapter-claude` as `[dev-dependencies]` only (see `Cargo.toml`
//! and `src/glue.rs`'s module docs) -- the shipped `fornax_replay` library
//! and `fornax-replay` binary never gain an adapter-crate dependency.

use std::collections::BTreeSet;

use uuid::Uuid;

use fornax_adapter_claude::ClaudeAdapter;
use fornax_adapter_conformance::{load_fixtures, replay_fixture};
use fornax_types::{Claim, EvidenceRelation, IngestMessage, NormalizationOutcome, Provider};
use fornax_verify::decision::{DefaultRiskPolicy, RiskClass};
use fornax_verify::fusion::BaselineFusionPolicy;

use fornax_replay::engine::replay;
use fornax_replay::glue::link_all_evidence_to_claim;
use fornax_replay::manifest::build_manifest;

#[test]
fn real_claude_fixture_replays_end_to_end_through_the_engine() {
    let fixture = load_fixtures("claude")
        .into_iter()
        .find(|f| f.name == "post_tool_use_bash_heuristic_success")
        .expect("expected the post_tool_use_bash_heuristic_success fixture to exist");

    // Step 1: real adapter-level replay -- the exact pipeline
    // `fornax-adapter-conformance`'s own golden-fixture tests exercise.
    let mut adapter = ClaudeAdapter;
    let outcomes = replay_fixture(&mut adapter, "fixture-hint", &fixture);
    assert_eq!(outcomes.len(), 1);

    let evidence: Vec<fornax_types::Evidence> = match &outcomes[0] {
        NormalizationOutcome::Messages(msgs) => msgs
            .iter()
            .filter_map(|m| match m {
                IngestMessage::Evidence(ev) => Some(ev.clone()),
                _ => None,
            })
            .collect(),
        other => panic!("expected Messages, got {other:?}"),
    };
    assert!(
        !evidence.is_empty(),
        "expected the fixture to produce at least one real Evidence message"
    );
    assert_eq!(evidence[0].payload["exit_code"], 0);
    assert_eq!(evidence[0].payload["heuristic"], true);

    // Step 2 (the minimal glue): this fixture's native shape has no
    // Claim-producing SessionEnd hook, so the claim the evidence is about is
    // synthesized here -- the evidence linked to it is the real,
    // adapter-derived evidence from step 1, not fabricated data.
    let claim = Claim {
        id: Uuid::new_v4(),
        session_id: "fixture-claude-session-002".to_string(),
        source_event_id: evidence[0].source_event_id,
        text: "the Bash command exited successfully".to_string(),
        subject: "command_succeeded".to_string(),
        claimed_at: "2026-01-02T00:00:00Z".to_string(),
    };
    let graph = link_all_evidence_to_claim(
        &claim,
        &evidence,
        EvidenceRelation::Supports,
        "2026-01-02T00:00:00Z",
    );

    // Step 3: build a frozen manifest from this real, fixture-derived input
    // and replay it through the engine.
    let manifest = build_manifest(
        claim,
        evidence,
        graph,
        Provider::ClaudeCode,
        fixture.metadata.provider_runtime_version.clone(),
        &BaselineFusionPolicy,
        &DefaultRiskPolicy,
        RiskClass::Balanced,
        BTreeSet::new(),
        "2026-01-02T00:00:00Z",
    );

    let comparison = replay(&manifest).expect("a manifest built by build_manifest must validate");
    assert!(comparison.verdict_matches);
    assert!(comparison.uncertainty_matches);
    assert!(comparison.action_matches);
    assert!(comparison.fusion_policy_drift.is_none());
    assert!(comparison.decision_policy_drift.is_none());

    // Replaying the identical manifest again must be byte-identical (AC 1),
    // now proven over a real fixture-derived input, not just synthetic test
    // data.
    let second = replay(&manifest).unwrap();
    assert_eq!(comparison, second);
}
