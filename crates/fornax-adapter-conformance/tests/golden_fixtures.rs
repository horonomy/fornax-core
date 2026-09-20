//! Golden-fixture kit (FORNX-160): both real Claude/Codex adapters proven
//! against real, sanitized captured event shapes, a genuine
//! historical schema-drift regression (FORNX-55), and a synthetic
//! breaking-change probe per provider, all through the
//! [`fornax_adapter_conformance::replay_fixture`] harness — this is the
//! same pipeline (`AgentAdapter::normalize`, including each adapter's
//! internal `EvidenceSensor`s) `main.rs` drives in production.
//!
//! This file (not `tests/conformance.rs`, which stays FORNX-156's original
//! property suite) is the entry point a future third-party adapter author
//! should copy from — see `docs/contributing/adding-an-adapter.md` step 6.

use fornax_adapter_claude::ClaudeAdapter;
use fornax_adapter_codex::CodexAdapter;
use fornax_adapter_conformance::{
    breaking_change_is_reported_not_silently_dropped, load_fixtures, replay_fixture,
};
use fornax_adapter_opencode::OpenCodeAdapter;
use fornax_types::{IngestMessage, NormalizationOutcome};

/// Every Claude fixture whose description doesn't mark it as a
/// breaking-change probe must replay clean: no panic, and the final outcome
/// is `Messages` or `Ignored` (never `Unrecognized` — a real/expected shape
/// this adapter is supposed to know about).
#[test]
fn every_non_breaking_claude_fixture_replays_as_a_known_shape() {
    for fixture in load_fixtures("claude") {
        if fixture.name.starts_with("unrecognized_") {
            continue;
        }
        let mut adapter = ClaudeAdapter;
        let outcomes = replay_fixture(&mut adapter, "fixture-hint", &fixture);
        for outcome in &outcomes {
            assert!(
                !matches!(outcome, NormalizationOutcome::Unrecognized { .. }),
                "fixture {} ({}) unexpectedly came back Unrecognized: {outcome:?}",
                fixture.name,
                fixture.metadata.description
            );
        }
    }
}

/// Same property for Codex, replayed against one adapter instance per
/// fixture (required for the call-id-pairing fixture to correlate
/// correctly).
#[test]
fn every_non_breaking_codex_fixture_replays_as_a_known_shape() {
    for fixture in load_fixtures("codex") {
        if fixture.name.starts_with("unrecognized_") {
            continue;
        }
        let mut adapter = CodexAdapter::new();
        let outcomes = replay_fixture(&mut adapter, "fixture-hint", &fixture);
        for outcome in &outcomes {
            assert!(
                !matches!(outcome, NormalizationOutcome::Unrecognized { .. }),
                "fixture {} ({}) unexpectedly came back Unrecognized: {outcome:?}",
                fixture.name,
                fixture.metadata.description
            );
        }
    }
}

/// Same property for opencode.
#[test]
fn every_non_breaking_opencode_fixture_replays_as_a_known_shape() {
    for fixture in load_fixtures("opencode") {
        if fixture.name.starts_with("unrecognized_") {
            continue;
        }
        let mut adapter = OpenCodeAdapter::new();
        let outcomes = replay_fixture(&mut adapter, "fixture-hint", &fixture);
        for outcome in &outcomes {
            assert!(
                !matches!(outcome, NormalizationOutcome::Unrecognized { .. }),
                "fixture {} ({}) unexpectedly came back Unrecognized: {outcome:?}",
                fixture.name,
                fixture.metadata.description
            );
        }
    }
}

/// Required test: a synthetic breaking Claude Code hook shape produces an
/// actionable `Unrecognized` error, never silent data loss (a fabricated
/// `Messages` outcome) and never a panic.
#[test]
fn claude_breaking_change_fixture_is_actionable_not_silently_dropped() {
    let fixture = load_fixtures("claude")
        .into_iter()
        .find(|f| f.name == "unrecognized_future_hook")
        .expect("expected the unrecognized_future_hook fixture to exist");
    let mut adapter = ClaudeAdapter;
    let outcomes = replay_fixture(&mut adapter, "fixture-hint", &fixture);
    assert_eq!(outcomes.len(), 1);
    breaking_change_is_reported_not_silently_dropped(&outcomes[0]);
}

/// Same required test for Codex.
#[test]
fn codex_breaking_change_fixture_is_actionable_not_silently_dropped() {
    let fixture = load_fixtures("codex")
        .into_iter()
        .find(|f| f.name == "unrecognized_future_event")
        .expect("expected the unrecognized_future_event fixture to exist");
    let mut adapter = CodexAdapter::new();
    let outcomes = replay_fixture(&mut adapter, "fixture-hint", &fixture);
    assert_eq!(outcomes.len(), 1);
    breaking_change_is_reported_not_silently_dropped(&outcomes[0]);
}

/// Same required test for opencode.
#[test]
fn opencode_breaking_change_fixture_is_actionable_not_silently_dropped() {
    let fixture = load_fixtures("opencode")
        .into_iter()
        .find(|f| f.name == "unrecognized_future_hook")
        .expect("expected the unrecognized_future_hook fixture to exist");
    let mut adapter = OpenCodeAdapter::new();
    let outcomes = replay_fixture(&mut adapter, "fixture-hint", &fixture);
    assert_eq!(outcomes.len(), 1);
    breaking_change_is_reported_not_silently_dropped(&outcomes[0]);
}

/// Required test: the FORNX-55 historical schema-drift regression fixture
/// (`custom_tool_call`/`custom_tool_call_output` call-id pairing) still
/// produces the documented heuristic exit-code Evidence when replayed
/// end-to-end. If a future change reintroduced the original bug — assuming
/// shell exec only ever arrives as `event_msg{type:exec_command_end}` — this
/// fixture's second event would come back `Unrecognized`/empty instead, and
/// this test would fail.
#[test]
fn fornx_55_historical_schema_drift_regression_still_produces_evidence() {
    let fixture = load_fixtures("codex")
        .into_iter()
        .find(|f| f.metadata.historical_schema_drift_ticket.as_deref() == Some("FORNX-55"))
        .expect("expected a fixture tagged as the FORNX-55 regression");

    let mut adapter = CodexAdapter::new();
    let outcomes = replay_fixture(&mut adapter, "fixture-hint", &fixture);
    assert_eq!(outcomes.len(), 2, "expected the call + output pair");

    // First half: the invocation, recognized-but-deliberately-untranslated.
    assert!(matches!(&outcomes[0], NormalizationOutcome::Ignored { .. }));

    // Second half: the paired output must produce the heuristic exit-code
    // Evidence — this is the regression assertion.
    match &outcomes[1] {
        NormalizationOutcome::Messages(msgs) => {
            let evidence = msgs.iter().find_map(|m| match m {
                IngestMessage::Evidence(ev) => Some(ev),
                _ => None,
            });
            let ev = evidence
                .unwrap_or_else(|| panic!("FORNX-55 regression: expected Evidence in {msgs:?}"));
            assert_eq!(ev.payload["exit_code"], 0);
            assert_eq!(ev.payload["heuristic"], true);
            assert!(ev.provenance.contains("script_completed"));
        }
        other => panic!("FORNX-55 regression: expected Messages, got {other:?}"),
    }
}

/// FORNX-16: the real captured *failure*-marker shape (`tools.shell_command`
/// with `unified_exec` disabled) must produce a literal (non-heuristic)
/// nonzero exit code — the case `fornx_55_historical_schema_drift_regression`
/// above deliberately does not cover, since that fixture is the
/// zero-exit-code `unified_exec` heuristic shape.
#[test]
fn fornx_16_real_failure_marker_fixture_produces_nonzero_non_heuristic_exit_code() {
    let fixture = load_fixtures("codex")
        .into_iter()
        .find(|f| f.name == "custom_tool_call_exec_pair_failure")
        .expect("expected the custom_tool_call_exec_pair_failure fixture to exist");

    let mut adapter = CodexAdapter::new();
    let outcomes = replay_fixture(&mut adapter, "fixture-hint", &fixture);
    assert_eq!(outcomes.len(), 2, "expected the call + output pair");

    assert!(matches!(&outcomes[0], NormalizationOutcome::Ignored { .. }));

    match &outcomes[1] {
        NormalizationOutcome::Messages(msgs) => {
            let evidence = msgs.iter().find_map(|m| match m {
                IngestMessage::Evidence(ev) => Some(ev),
                _ => None,
            });
            let ev = evidence.unwrap_or_else(|| {
                panic!("FORNX-16 failure fixture: expected Evidence in {msgs:?}")
            });
            assert_eq!(ev.payload["exit_code"], 1);
            assert_eq!(ev.payload["heuristic"], false);
            assert!(ev.provenance.contains("exit_code_text"));
        }
        other => panic!("FORNX-16 failure fixture: expected Messages, got {other:?}"),
    }
}

/// FORNX-161's flagship finding, pinned as a regression test: replaying the
/// real captured tool.execute.before/after pair must produce a literal
/// (non-heuristic) exit-code Evidence — the one thing neither Claude Code
/// nor Codex can do without a heuristic.
#[test]
fn opencode_tool_execute_pair_produces_literal_non_heuristic_exit_code() {
    let fixture = load_fixtures("opencode")
        .into_iter()
        .find(|f| f.name == "tool_execute_before_after_pair")
        .expect("expected the tool_execute_before_after_pair fixture to exist");
    let mut adapter = OpenCodeAdapter::new();
    let outcomes = replay_fixture(&mut adapter, "fixture-hint", &fixture);
    assert_eq!(outcomes.len(), 2, "expected the before + after pair");

    match &outcomes[1] {
        NormalizationOutcome::Messages(msgs) => {
            let evidence = msgs.iter().find_map(|m| match m {
                IngestMessage::Evidence(ev) => Some(ev),
                _ => None,
            });
            let ev = evidence.unwrap_or_else(|| {
                panic!("opencode tool.execute.after fixture: expected Evidence in {msgs:?}")
            });
            assert_eq!(ev.payload["exit_code"], 0);
            assert_eq!(ev.payload["heuristic"], false);
            assert!(ev.provenance.contains("metadata.exit"));
        }
        other => panic!("expected Messages, got {other:?}"),
    }
}
