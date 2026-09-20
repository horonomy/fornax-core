//! FORNX-16: proves the residual gap this ticket closes actually matters
//! end to end — not just that the adapter can parse a real exit code, but
//! that the resulting `Evidence`, combined with a false "tests passed"
//! `Claim` from the same Codex session, drives `fornax-verify`'s
//! `TestResultVerifier` to the `Contradicted` verdict. Before this ticket,
//! the adapter could only ever produce the zero-exit-code heuristic on this
//! path, so a false claim could never be contradicted — only left
//! `Unverified` at best. Consumes `fornax-verify`'s public `Verifier`
//! trait/`TestResultVerifier` as a [dev-dependency] only; does not modify
//! `fornax-verify` itself.

use fornax_adapter_codex::CodexAdapter;
use fornax_adapter_conformance::{load_fixtures, replay_fixture};
use fornax_types::{
    AgentAdapter, CapabilityProbe, Claim, Evidence, IngestMessage, NormalizationOutcome, Verdict,
};
use fornax_verify::{TestResultVerifier, Verifier};

#[test]
fn real_codex_failure_evidence_contradicts_a_false_tests_passed_claim() {
    let fixture = load_fixtures("codex")
        .into_iter()
        .find(|f| f.name == "custom_tool_call_exec_pair_failure")
        .expect("expected the custom_tool_call_exec_pair_failure fixture to exist");

    let mut adapter = CodexAdapter::new();

    // Real failed-command evidence (FORNX-16: the `Exit code: 1` / `Script
    // failed` shape live-captured against codex-cli 0.147.0).
    let outcomes = replay_fixture(&mut adapter, "sess-contradict", &fixture);
    let evidence: Vec<Evidence> = outcomes
        .into_iter()
        .flat_map(|outcome| match outcome {
            NormalizationOutcome::Messages(msgs) => msgs,
            _ => Vec::new(),
        })
        .filter_map(|msg| match msg {
            IngestMessage::Evidence(ev) => Some(ev),
            _ => None,
        })
        .collect();
    assert_eq!(
        evidence.len(),
        1,
        "expected exactly one Evidence from the failure fixture"
    );
    assert_eq!(evidence[0].payload["exit_code"], 1);
    assert_eq!(evidence[0].payload["heuristic"], false);

    // Same session, agent falsely claims the tests passed.
    let task_complete = serde_json::json!({
        "type": "event_msg",
        "payload": {
            "type": "task_complete",
            "last_agent_message": "All tests passed."
        }
    });
    let claim_outcome = adapter.normalize("sess-contradict", &task_complete);
    let claim: Claim = match claim_outcome {
        NormalizationOutcome::Messages(msgs) => msgs
            .into_iter()
            .find_map(|msg| match msg {
                IngestMessage::Claim(c) => Some(c),
                _ => None,
            })
            .expect("expected a Claim from the false 'tests passed' task_complete message"),
        other => panic!("expected Messages carrying a Claim, got {other:?}"),
    };
    assert_eq!(claim.subject, "test_result");
    assert!(TestResultVerifier::claims_tests_passed(&claim.text));

    let caps = adapter.probe();
    let verifier = TestResultVerifier;
    assert!(verifier.applies_to(&claim));

    let finding = verifier.verify(&claim, &evidence, &caps);
    assert_eq!(
        finding.verdict,
        Verdict::Contradicted,
        "a false 'tests passed' claim alongside real Evidence of a nonzero \
         exit code must be CONTRADICTED, got {:?} (rationale: {})",
        finding.verdict,
        finding.rationale
    );
}
