//! FORNX-488: a real-shaped Claude Code `Stop` payload carrying
//! `last_assistant_message` (and no flushed transcript) must yield the
//! "tests passed" claim, which a prior `PostToolUseFailure` pytest event
//! `Contradicted` (ADR 0025).

use fornax_adapter_claude::ClaudeAdapter;
use fornax_adapter_conformance::{load_fixtures, replay_fixture};
use fornax_types::{AgentAdapter, CapabilityProbe, IngestMessage, NormalizationOutcome, Verdict};
use fornax_verify::{TestResultVerifier, Verifier};

fn messages(outcome: NormalizationOutcome) -> Vec<IngestMessage> {
    match outcome {
        NormalizationOutcome::Messages(msgs) => msgs,
        _ => Vec::new(),
    }
}

#[test]
fn stop_last_assistant_message_claim_is_contradicted_by_failure_evidence() {
    let mut adapter = ClaudeAdapter;
    let fixture = load_fixtures("claude")
        .into_iter()
        .find(|f| f.name == "post_tool_use_failure_bash_pytest")
        .expect("fixture post_tool_use_failure_bash_pytest must exist");
    let evidence: Vec<_> = replay_fixture(&mut adapter, "hint", &fixture)
        .into_iter()
        .flat_map(messages)
        .filter_map(|m| match m {
            IngestMessage::Evidence(e) => Some(e),
            _ => None,
        })
        .collect();
    assert_eq!(evidence.len(), 1);

    let stop = serde_json::json!({
        "hook_event_name": "Stop",
        "session_id": "fixture-claude-session-failure-001",
        "transcript_path": "/nonexistent/unflushed-transcript.jsonl",
        "last_assistant_message": "All tests passed: `pytest -q test_ok.py` reported 1 passed in 0.00s.",
        "stop_hook_active": false
    });
    let claim = messages(adapter.normalize("hint", &stop))
        .into_iter()
        .find_map(|m| match m {
            IngestMessage::Claim(c) => Some(c),
            _ => None,
        })
        .expect("Stop with last_assistant_message must yield a Claim");

    let verifier = TestResultVerifier;
    assert!(verifier.applies_to(&claim));
    let finding = verifier.verify(&claim, &evidence, &adapter.probe());
    assert_eq!(
        finding.verdict,
        Verdict::Contradicted,
        "rationale: {}",
        finding.rationale
    );
}
