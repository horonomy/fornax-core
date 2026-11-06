//! FORNX-487: a real Claude Code `PostToolUseFailure` payload (a failing
//! `pytest` run) must yield literal-exit-code evidence that drives
//! `TestResultVerifier` to `Contradicted` for a later "tests passed" claim in
//! the same session (ADR 0025: a genuine non-zero literal exit is
//! `Contradicted`), while success evidence keeps its `Review` ceiling.

use fornax_adapter_claude::ClaudeAdapter;
use fornax_adapter_conformance::{load_fixtures, replay_fixture};
use fornax_types::{
    AgentAdapter, CapabilityProbe, Claim, EventKind, Evidence, IngestMessage, NormalizationOutcome,
    Verdict,
};
use fornax_verify::{TestResultVerifier, Verifier};

fn messages(outcome: NormalizationOutcome) -> Vec<IngestMessage> {
    match outcome {
        NormalizationOutcome::Messages(msgs) => msgs,
        _ => Vec::new(),
    }
}

fn evidence_of(msgs: Vec<IngestMessage>) -> Vec<Evidence> {
    msgs.into_iter()
        .filter_map(|m| match m {
            IngestMessage::Evidence(e) => Some(e),
            _ => None,
        })
        .collect()
}

fn failure_fixture_evidence(adapter: &mut ClaudeAdapter) -> Vec<Evidence> {
    let fixture = load_fixtures("claude")
        .into_iter()
        .find(|f| f.name == "post_tool_use_failure_bash_pytest")
        .expect("fixture post_tool_use_failure_bash_pytest must exist");
    replay_fixture(adapter, "hint", &fixture)
        .into_iter()
        .flat_map(|o| evidence_of(messages(o)))
        .collect()
}

fn tests_passed_claim(adapter: &mut ClaudeAdapter, session: &str) -> Claim {
    let dir = std::env::temp_dir().join(format!("fornax-487-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let transcript = dir.join("t.jsonl");
    std::fs::write(
        &transcript,
        "{\"type\":\"assistant\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"All tests passed.\"}]}}\n",
    )
    .unwrap();
    let stop = serde_json::json!({
        "hook_event_name": "Stop",
        "session_id": session,
        "transcript_path": transcript,
    });
    let claim = messages(adapter.normalize("hint", &stop))
        .into_iter()
        .find_map(|m| match m {
            IngestMessage::Claim(c) => Some(c),
            _ => None,
        })
        .expect("Stop with a 'tests passed' transcript must yield a Claim");
    std::fs::remove_dir_all(&dir).ok();
    claim
}

#[test]
fn real_post_tool_use_failure_payload_yields_literal_exit_code_evidence() {
    let evidence = failure_fixture_evidence(&mut ClaudeAdapter);
    assert_eq!(evidence.len(), 1);
    let p = &evidence[0].payload;
    assert_eq!(p["exit_code"], 1);
    assert_eq!(p["heuristic"], false, "the `Exit code N` prefix is literal");
    assert_eq!(p["command"], "pytest -q test_bad.py");
    assert_eq!(p["test_summary"]["failed"], 1);
    assert!(evidence[0].provenance.contains("PostToolUseFailure"));
}

#[test]
fn post_tool_use_failure_is_normalized_as_a_post_tool_event() {
    let fixture = load_fixtures("claude")
        .into_iter()
        .find(|f| f.name == "post_tool_use_failure_bash_pytest")
        .unwrap();
    let msgs: Vec<_> = replay_fixture(&mut ClaudeAdapter, "hint", &fixture)
        .into_iter()
        .flat_map(messages)
        .collect();
    assert!(msgs.iter().any(|m| matches!(
        m,
        IngestMessage::Event(e) if e.kind == EventKind::PostToolUse
    )));
}

#[test]
fn failing_pytest_evidence_contradicts_a_later_tests_passed_claim() {
    let mut adapter = ClaudeAdapter;
    let evidence = failure_fixture_evidence(&mut adapter);
    let claim = tests_passed_claim(&mut adapter, "fixture-claude-session-failure-001");
    assert_eq!(claim.subject, "test_result");
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

fn failure_payload(error: serde_json::Value, tool: &str, interrupt: bool) -> serde_json::Value {
    serde_json::json!({
        "hook_event_name": "PostToolUseFailure",
        "session_id": "s-neg",
        "tool_name": tool,
        "tool_input": {"command": "pytest -q"},
        "error": error,
        "is_interrupt": interrupt,
    })
}

fn evidence_for(raw: serde_json::Value) -> Vec<Evidence> {
    evidence_of(messages(ClaudeAdapter.normalize("hint", &raw)))
}

#[test]
fn failure_without_exit_code_prefix_yields_no_evidence() {
    for error in [
        serde_json::json!("1 failed in 0.01s"),
        serde_json::json!("exit code 1\nfoo"),
        serde_json::json!("Exit code abc\nfoo"),
        serde_json::json!("Exit code \nfoo"),
        serde_json::json!("Exit code 1x\nfoo"),
        serde_json::json!(null),
    ] {
        assert!(
            evidence_for(failure_payload(error.clone(), "Bash", false)).is_empty(),
            "{error}"
        );
    }
}

#[test]
fn interrupted_failure_yields_no_evidence() {
    let raw = failure_payload(serde_json::json!("Exit code 130\n^C"), "Bash", true);
    assert!(evidence_for(raw).is_empty());
}

#[test]
fn exit_code_zero_in_a_failure_event_never_mints_evidence() {
    let raw = failure_payload(serde_json::json!("Exit code 0\nok"), "Bash", false);
    assert!(evidence_for(raw).is_empty());
}

#[test]
fn non_bash_failure_yields_no_exit_code_evidence() {
    let raw = failure_payload(serde_json::json!("Exit code 1\nboom"), "Read", false);
    assert!(evidence_for(raw).is_empty());
}
