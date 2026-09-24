//! Real end-to-end CLI-flow test for the counterfactual verification
//! subcommands (FORNX-101 AC6).
//!
//! AC6 asks for "verified against real coding-agent examples with
//! screenshots where applicable". A screenshot has no honest literal
//! equivalent for a CLI tool -- this test is the honest reinterpretation:
//! it spawns the actual compiled `fornax` binary (not a function call inside
//! the crate) with a real `ExperimentSpec` JSON file and a real filesystem
//! working tree, and asserts on the captured terminal output text, the same
//! way a screenshot would be inspected for the right content. See the PR
//! description for this same note.

use std::path::Path;
use std::process::Command;

fn write_spec(path: &Path, session_id: &str, file_path: &str, content: &str) {
    let spec = serde_json::json!({
        "schema_version": 1,
        "id": uuid::Uuid::new_v4(),
        "version": 1,
        "session_id": session_id,
        "hypothesis": {
            "claim_id": uuid::Uuid::new_v4(),
            "expected_observations": [
                {"signal_class": "process_result", "description": "exit code changes after reverting the file"}
            ],
            "narrative": "if the file caused the failure, reverting it fixes it"
        },
        "baseline": {
            "description": "file at HEAD before intervention",
            "evidence_ids": [uuid::Uuid::new_v4()]
        },
        "intervention": {
            "kind": "revert_file_to_baseline",
            "description": "revert file to baseline content",
            "params": {"path": file_path, "content": content}
        },
        "stop_conditions": [{"timeout_elapsed": {"max_seconds": 60}}],
        "allowed_side_effects": ["ephemeral_worktree_mutation"],
        "provenance": {
            "created_at": "2026-01-01T00:00:00Z",
            "created_by": "cli-e2e-test",
            "environment": "worktree:fornax-cli-e2e",
            "tool_version": "fornax-cli-0.0.4"
        }
    });
    std::fs::write(path, serde_json::to_vec_pretty(&spec).unwrap()).unwrap();
}

fn temp_dir(label: &str) -> std::path::PathBuf {
    let path =
        std::env::temp_dir().join(format!("fornax-cli-e2e-{label}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn fornax_bin() -> &'static str {
    env!("CARGO_BIN_EXE_fornax")
}

#[test]
fn preview_then_run_flow_produces_honest_terminal_output_for_a_low_risk_experiment() {
    let fornax_home = temp_dir("home"); // no config.toml -- default policy
    let source_root = temp_dir("source");
    std::fs::write(source_root.join("claimed.txt"), b"before\n").unwrap();
    let staging_root = temp_dir("staging");
    let spec_path = temp_dir("spec").join("spec.json");
    write_spec(&spec_path, "session-e2e-1", "claimed.txt", "after\n");

    // --- templates ---
    let templates_out = Command::new(fornax_bin())
        .args(["experiment", "templates"])
        .env("FORNAX_HOME", &fornax_home)
        .output()
        .unwrap();
    assert!(templates_out.status.success());
    let templates_text = String::from_utf8_lossy(&templates_out.stdout);
    assert!(templates_text.contains("revert_file_to_baseline"));
    assert!(templates_text.contains("[ELIGIBLE]"));

    // --- preview: must not touch the filesystem or run anything ---
    let preview_out = Command::new(fornax_bin())
        .args(["experiment", "preview", "--spec"])
        .arg(&spec_path)
        .env("FORNAX_HOME", &fornax_home)
        .output()
        .unwrap();
    assert!(preview_out.status.success());
    let preview_text = String::from_utf8_lossy(&preview_out.stdout);
    assert!(preview_text.contains("hypothesis claim:"));
    assert!(preview_text.contains("ephemeral_worktree_mutation"));
    assert!(preview_text.contains("low-risk -- eligible to auto-run"));
    assert!(preview_text.contains("preview only -- nothing was executed"));
    assert!(
        std::fs::read_dir(&staging_root).unwrap().next().is_none(),
        "preview must never stage anything"
    );
    assert_eq!(
        std::fs::read(source_root.join("claimed.txt")).unwrap(),
        b"before\n",
        "preview must never touch the source tree"
    );

    // --- run: real end-to-end execution through the real executor ---
    let run_out = Command::new(fornax_bin())
        .args(["experiment", "run", "--spec"])
        .arg(&spec_path)
        .arg("--source")
        .arg(&source_root)
        .arg("--staging-root")
        .arg(&staging_root)
        .env("FORNAX_HOME", &fornax_home)
        .output()
        .unwrap();
    assert!(
        run_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&run_out.stderr)
    );
    let run_text = String::from_utf8_lossy(&run_out.stdout);
    assert!(run_text.contains("COMPLETED"));
    assert!(run_text.contains("--- baseline"));
    assert!(run_text.contains("--- intervention"));

    // The real working tree must remain untouched even after a successful run.
    assert_eq!(
        std::fs::read(source_root.join("claimed.txt")).unwrap(),
        b"before\n",
        "the real working tree must never be mutated by the experiment"
    );
    // The staged copy is cleaned up unconditionally after the run.
    assert!(
        std::fs::read_dir(&staging_root).unwrap().next().is_none(),
        "staged worktree must be cleaned up after the run"
    );

    std::fs::remove_dir_all(&fornax_home).ok();
    std::fs::remove_dir_all(&source_root).ok();
    std::fs::remove_dir_all(&staging_root).ok();
    std::fs::remove_dir_all(spec_path.parent().unwrap()).ok();
}

#[test]
fn run_flow_blocks_a_higher_risk_experiment_and_reports_it_plainly() {
    let fornax_home = temp_dir("home-higher-risk"); // default policy denies network_call
    let source_root = temp_dir("source-higher-risk");
    std::fs::write(source_root.join("claimed.txt"), b"before\n").unwrap();
    let staging_root = temp_dir("staging-higher-risk");
    let spec_dir = temp_dir("spec-higher-risk");
    let spec_path = spec_dir.join("spec.json");

    let spec = serde_json::json!({
        "schema_version": 1,
        "id": uuid::Uuid::new_v4(),
        "version": 1,
        "session_id": "session-e2e-2",
        "hypothesis": {
            "claim_id": uuid::Uuid::new_v4(),
            "expected_observations": [
                {"signal_class": "process_result", "description": "exit code changes"}
            ]
        },
        "baseline": {
            "description": "file at HEAD before intervention",
            "evidence_ids": [uuid::Uuid::new_v4()]
        },
        "intervention": {
            "kind": "revert_file_to_baseline",
            "description": "revert file to baseline content",
            "params": {"path": "claimed.txt", "content": "after\n"}
        },
        "stop_conditions": [{"timeout_elapsed": {"max_seconds": 60}}],
        "allowed_side_effects": ["ephemeral_worktree_mutation", "network_call"],
        "provenance": {
            "created_at": "2026-01-01T00:00:00Z",
            "created_by": "cli-e2e-test",
            "environment": "worktree:fornax-cli-e2e",
            "tool_version": "fornax-cli-0.0.4"
        }
    });
    std::fs::write(&spec_path, serde_json::to_vec_pretty(&spec).unwrap()).unwrap();

    let run_out = Command::new(fornax_bin())
        .args(["experiment", "run", "--spec"])
        .arg(&spec_path)
        .arg("--source")
        .arg(&source_root)
        .arg("--staging-root")
        .arg(&staging_root)
        .env("FORNAX_HOME", &fornax_home)
        .output()
        .unwrap();
    assert!(run_out.status.success());
    let run_text = String::from_utf8_lossy(&run_out.stdout);
    assert!(run_text.contains("BLOCKED: needs policy approval"));
    assert!(run_text.contains("network_call"));
    assert!(run_text.contains("was NOT run"));
    assert!(!run_text.contains("COMPLETED"));
    assert!(
        std::fs::read_dir(&staging_root).unwrap().next().is_none(),
        "a blocked experiment must never stage anything"
    );

    std::fs::remove_dir_all(&fornax_home).ok();
    std::fs::remove_dir_all(&source_root).ok();
    std::fs::remove_dir_all(&staging_root).ok();
    std::fs::remove_dir_all(&spec_dir).ok();
}
