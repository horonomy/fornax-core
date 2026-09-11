//! FORNX-346 Part 2 / ADR 0022: the injection-surface rules
//! `crate::rerun`/`crate::ci` implement, exercised end-to-end through the
//! real (non-mocked, except for `CheckRunSource`) public API.

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use fornax_acquire::{AcquisitionOutcome, AcquisitionRoots};
use fornax_acquire_exec::grants::ExecutorGrants;
use fornax_acquire_exec::{ci, rerun};
use fornax_ci::{CheckRunFetchError, CheckRunSource, CiCheckRunStatus};
use uuid::Uuid;

fn roots_here() -> AcquisitionRoots {
    AcquisitionRoots::new([Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()])
}

// --- RerunTest: argv[0] allowlist ------------------------------------------

#[test]
fn argv0_not_in_allowed_commands_is_refused() {
    let grants = ExecutorGrants::new(vec![vec!["cargo".to_string(), "test".to_string()]], vec![]);
    let outcome = rerun::run_rerun_test(
        &serde_json::json!(["/bin/rm", "-rf", "/"]),
        &grants,
        &roots_here(),
        ".",
        Duration::from_secs(5),
        "s1",
        Uuid::new_v4(),
        "2026-01-01T00:00:00Z",
    );
    assert!(matches!(
        outcome.outcome,
        AcquisitionOutcome::Refused { .. }
    ));
}

// --- RerunTest: Value::String is refused, never shell-parsed ---------------

#[test]
fn command_as_value_string_is_refused_not_shell_parsed() {
    let grants = ExecutorGrants::new(vec![vec!["echo".to_string()]], vec![]);
    let outcome = rerun::run_rerun_test(
        &serde_json::json!("echo hello; rm -rf /tmp/should-not-run"),
        &grants,
        &roots_here(),
        ".",
        Duration::from_secs(5),
        "s1",
        Uuid::new_v4(),
        "2026-01-01T00:00:00Z",
    );
    match outcome.outcome {
        AcquisitionOutcome::Refused { reason } => {
            assert!(reason.contains("shell string"));
        }
        other => panic!("expected Refused, got {other:?}"),
    }
}

// --- RerunTest: adversarial payload in a later argv element runs inert ----

#[test]
fn adversarial_payload_in_a_later_argv_element_is_an_inert_literal() {
    let sentinel =
        std::env::temp_dir().join(format!("fornax-exec-test-sentinel-{}", Uuid::new_v4()));
    std::fs::write(&sentinel, b"pre-existing").unwrap();

    let grants = ExecutorGrants::new(vec![vec!["/bin/echo".to_string()]], vec![]);
    let payload = format!("; rm -rf {}; $(whoami)", sentinel.display());
    let outcome = rerun::run_rerun_test(
        &serde_json::json!(["/bin/echo", payload]),
        &grants,
        &roots_here(),
        ".",
        Duration::from_secs(5),
        "s1",
        Uuid::new_v4(),
        "2026-01-01T00:00:00Z",
    );

    assert!(matches!(outcome.outcome, AcquisitionOutcome::Acquired(_)));
    assert!(
        sentinel.exists(),
        "sentinel file was removed -- the adversarial payload was interpreted, not passed as a literal"
    );
    assert!(
        outcome.stdout.contains(&payload),
        "expected the literal payload verbatim in captured stdout, got: {}",
        outcome.stdout
    );

    std::fs::remove_file(&sentinel).ok();
}

// --- RerunTest: cwd containment ---------------------------------------------

#[test]
fn cwd_outside_every_configured_root_is_refused() {
    let grants = ExecutorGrants::new(vec![vec!["/bin/echo".to_string()]], vec![]);
    let outcome = rerun::run_rerun_test(
        &serde_json::json!(["/bin/echo", "hi"]),
        &grants,
        &roots_here(),
        "/etc",
        Duration::from_secs(5),
        "s1",
        Uuid::new_v4(),
        "2026-01-01T00:00:00Z",
    );
    assert!(matches!(
        outcome.outcome,
        AcquisitionOutcome::Refused { .. }
    ));
}

// --- RerunTest: credential env stripping ------------------------------------

#[test]
fn github_token_set_in_parent_is_not_inherited_by_the_child() {
    // SAFETY (test-only, single-threaded w.r.t. this var): isolated to this
    // process's own env, restored immediately after use.
    std::env::set_var("GITHUB_TOKEN", "should-never-leak-into-child");
    std::env::set_var("GH_TOKEN", "also-should-never-leak");

    let grants = ExecutorGrants::new(vec![vec!["/usr/bin/env".to_string()]], vec![]);
    let outcome = rerun::run_rerun_test(
        &serde_json::json!(["/usr/bin/env"]),
        &grants,
        &roots_here(),
        ".",
        Duration::from_secs(5),
        "s1",
        Uuid::new_v4(),
        "2026-01-01T00:00:00Z",
    );

    std::env::remove_var("GITHUB_TOKEN");
    std::env::remove_var("GH_TOKEN");

    assert!(matches!(outcome.outcome, AcquisitionOutcome::Acquired(_)));
    assert!(
        !outcome.stdout.contains("GITHUB_TOKEN"),
        "GITHUB_TOKEN leaked into the child's own env output: {}",
        outcome.stdout
    );
    assert!(
        !outcome.stdout.contains("GH_TOKEN"),
        "GH_TOKEN leaked into the child's own env output: {}",
        outcome.stdout
    );
}

// --- QueryCiStatus: commit sha validation -----------------------------------

struct NeverCalledSource;
impl CheckRunSource for NeverCalledSource {
    fn fetch(
        &self,
        _repo_slug: &str,
        _commit_sha: &str,
    ) -> Result<CiCheckRunStatus, CheckRunFetchError> {
        panic!("fetch must never be called for a malformed commit sha");
    }
}

#[test]
fn malformed_commit_sha_is_refused_before_any_network_call() {
    let grants = ExecutorGrants::new(vec![], vec!["horonomy/fornax-core".to_string()]);
    let outcome = ci::query_ci_status(
        &grants,
        None,
        "../../../etc/passwd",
        &NeverCalledSource,
        "s1",
        Uuid::new_v4(),
        "2026-01-01T00:00:00Z",
    );
    assert!(matches!(outcome, AcquisitionOutcome::Refused { .. }));
}

// --- QueryCiStatus: repo comes only from ExecutorGrants ---------------------

struct RecordingSource {
    seen_repo: std::cell::RefCell<Option<String>>,
}

impl CheckRunSource for RecordingSource {
    fn fetch(
        &self,
        repo_slug: &str,
        _commit_sha: &str,
    ) -> Result<CiCheckRunStatus, CheckRunFetchError> {
        *self.seen_repo.borrow_mut() = Some(repo_slug.to_string());
        Ok(CiCheckRunStatus {
            total_count: 0,
            check_runs: vec![],
        })
    }
}

#[test]
fn an_embedded_repo_field_from_evidence_is_never_consulted_only_grants_are() {
    // There is no parameter on `query_ci_status` through which an
    // evidence-embedded `repo` field could even be threaded in -- this test
    // pins that the repo actually queried is exactly the operator-configured
    // one, regardless of anything an agent might claim.
    let grants = ExecutorGrants::new(vec![], vec!["horonomy/fornax-core".to_string()]);
    let source = RecordingSource {
        seen_repo: std::cell::RefCell::new(None),
    };
    let outcome = ci::query_ci_status(
        &grants,
        None,
        "abcdef1",
        &source,
        "s1",
        Uuid::new_v4(),
        "2026-01-01T00:00:00Z",
    );
    assert!(matches!(outcome, AcquisitionOutcome::Acquired(_)));
    assert_eq!(
        source.seen_repo.borrow().as_deref(),
        Some("horonomy/fornax-core")
    );
}

// --- RerunTest: real kill on timeout, not an abandoned thread ---------------

#[test]
fn a_long_running_allowlisted_command_is_actually_killed_on_timeout() {
    let marker = std::env::temp_dir().join(format!(
        "fornax-exec-test-timeout-marker-{}",
        Uuid::new_v4()
    ));
    std::fs::remove_file(&marker).ok();

    // `/bin/sleep 30` never reaches the point of creating `marker` within
    // the short budget below; if the process were merely abandoned (not
    // actually killed) rather than reaped, that would show up as this pid
    // still being reported as alive well after `run_rerun_test` returned.
    let grants = ExecutorGrants::new(vec![vec!["/bin/sleep".to_string()]], vec![]);
    let outcome = rerun::run_rerun_test(
        &serde_json::json!(["/bin/sleep", "30"]),
        &grants,
        &roots_here(),
        ".",
        Duration::from_millis(150),
        "s1",
        Uuid::new_v4(),
        "2026-01-01T00:00:00Z",
    );

    assert!(matches!(
        outcome.outcome,
        AcquisitionOutcome::TimedOut { .. }
    ));
    assert!(
        !marker.exists(),
        "marker file exists -- the long-running command was not actually stopped"
    );

    let pid = outcome.pid.expect("a child was spawned before timing out");
    // Test-only subprocess spawn (outside this crate's own `src/`, so it is
    // not scanned by the workspace's zero-subprocess-spawn / confinement
    // tests) to independently confirm the pid was really reaped.
    let still_running = Command::new("ps")
        .args(["-p", &pid.to_string()])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(
        !still_running,
        "pid {pid} is still reported as running -- the process was abandoned, not reaped"
    );
}
