//! Domain 1: shadow-run a proposed file mutation inside a
//! [`crate::staging::StagedWorktree`] copy and compare the mutated file's
//! content against an expected value — reusing this crate's existing
//! isolation mechanism directly rather than building a parallel one.

use std::path::Path;

use crate::executor::Cancellation;
use crate::shadow::{
    contains_forbidden_parameter_key, EnvironmentFidelity, ShadowDomain, ShadowOutcome,
    ShadowResult,
};
use crate::staging::{StagedWorktree, StagingError};

/// One proposed file mutation: `relative_path` (resolved via
/// [`StagedWorktree::resolve_contained`] — never joined against the staged
/// root directly), `new_content`, and what content is *expected* to result
/// (for the comparison; `None` means "just prove the write and any parse
/// check below succeed").
#[derive(Debug, Clone)]
pub struct FileMutationProposal {
    pub relative_path: String,
    pub new_content: String,
    pub expected_content: Option<String>,
    /// When `true`, the mutated file's content is additionally parsed as
    /// JSON after being written — a real fragility passive evidence (a
    /// plain text diff) cannot reliably catch: a config file mutation that
    /// is textually plausible but syntactically broken (AC3).
    pub validate_as_json: bool,
}

/// Runs one [`FileMutationProposal`] against a fresh [`StagedWorktree`] copy
/// of `source_root`. Never mutates `source_root` itself — the same
/// guarantee [`StagedWorktree::provision`] already gives every FORNX-99
/// experiment. `params` is the proposal's own free-form parameter map,
/// checked for credential-shaped keys before anything else runs.
pub fn run_file_mutation_shadow(
    staging_root: &Path,
    source_root: &Path,
    proposal: &FileMutationProposal,
    params: &serde_json::Map<String, serde_json::Value>,
    cancellation: &Cancellation,
) -> ShadowResult {
    let fidelity = || EnvironmentFidelity {
        domain: ShadowDomain::FileMutation,
        covers: vec!["file_content".to_string(), "json_syntax".to_string()],
        unmodeled: vec![
            "does not execute any build or test command against the mutated tree".to_string(),
            "does not observe runtime behavior, only file content".to_string(),
        ],
    };

    if cancellation.is_cancelled() {
        return result(
            &proposal.relative_path,
            fidelity(),
            ShadowOutcome::Aborted {
                reason: "cancelled before the shadow environment was provisioned".to_string(),
            },
        );
    }

    if contains_forbidden_parameter_key(params) {
        return result(
            &proposal.relative_path,
            fidelity(),
            ShadowOutcome::Refused {
                reason: "proposal parameters contain a credential-shaped key".to_string(),
            },
        );
    }

    let staged = match StagedWorktree::provision(staging_root, source_root) {
        Ok(s) => s,
        Err(e) => {
            return result(
                &proposal.relative_path,
                fidelity(),
                ShadowOutcome::Failed {
                    reason: format!("failed to provision shadow environment: {e}"),
                },
            )
        }
    };
    // `staged` unconditionally cleans itself up (Drop) on every path out of
    // this function from here on, matching `ExperimentExecutor::run_inner`'s
    // own guarantee.

    if cancellation.is_cancelled() {
        return result(
            &proposal.relative_path,
            fidelity(),
            ShadowOutcome::Aborted {
                reason: "cancelled before the proposed mutation was applied".to_string(),
            },
        );
    }

    let resolved = match staged.resolve_contained(&proposal.relative_path) {
        Ok(p) => p,
        Err(StagingError::Escapes { attempted }) => {
            return result(
                &proposal.relative_path,
                fidelity(),
                ShadowOutcome::Refused {
                    reason: format!(
                        "proposed path '{attempted}' escapes the shadow environment boundary"
                    ),
                },
            )
        }
        Err(e) => {
            return result(
                &proposal.relative_path,
                fidelity(),
                ShadowOutcome::Failed {
                    reason: format!("failed to resolve proposed path: {e}"),
                },
            )
        }
    };

    if let Some(parent) = resolved.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return result(
                &proposal.relative_path,
                fidelity(),
                ShadowOutcome::Failed {
                    reason: format!(
                        "failed to create parent directories inside shadow environment: {e}"
                    ),
                },
            );
        }
    }
    if let Err(e) = std::fs::write(&resolved, &proposal.new_content) {
        return result(
            &proposal.relative_path,
            fidelity(),
            ShadowOutcome::Failed {
                reason: format!("failed to write mutated content inside shadow environment: {e}"),
            },
        );
    }

    if proposal.validate_as_json {
        if let Err(e) = serde_json::from_str::<serde_json::Value>(&proposal.new_content) {
            return result(
                &proposal.relative_path,
                fidelity(),
                ShadowOutcome::Failed {
                    reason: format!(
                        "mutated content failed JSON parsing inside the shadow environment: {e}"
                    ),
                },
            );
        }
    }

    let observed = std::fs::read_to_string(&resolved).unwrap_or_default();
    let outcome = match &proposal.expected_content {
        Some(expected) if expected == &observed => ShadowOutcome::Matched { observed },
        Some(expected) => ShadowOutcome::Diverged {
            observed,
            expected: expected.clone(),
        },
        None => ShadowOutcome::Matched { observed },
    };

    result(&proposal.relative_path, fidelity(), outcome)
}

fn result(
    proposed_action: &str,
    fidelity: EnvironmentFidelity,
    outcome: ShadowOutcome,
) -> ShadowResult {
    ShadowResult {
        proposed_action: proposed_action.to_string(),
        fidelity,
        outcome,
        related_claim_ref: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "fornax-shadow-file-test-{label}-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn no_params() -> serde_json::Map<String, serde_json::Value> {
        serde_json::Map::new()
    }

    #[test]
    fn a_matching_mutation_reports_matched_and_does_not_touch_source() {
        let source_root = temp_dir("source");
        std::fs::write(source_root.join("config.txt"), b"old\n").unwrap();
        let staging_root = temp_dir("staging-root");

        let proposal = FileMutationProposal {
            relative_path: "config.txt".to_string(),
            new_content: "new\n".to_string(),
            expected_content: Some("new\n".to_string()),
            validate_as_json: false,
        };
        let result = run_file_mutation_shadow(
            &staging_root,
            &source_root,
            &proposal,
            &no_params(),
            &Cancellation::new(),
        );

        assert!(matches!(result.outcome, ShadowOutcome::Matched { .. }));
        // AC7: production mutation impossible by default -- the real source
        // file is untouched.
        assert_eq!(
            std::fs::read_to_string(source_root.join("config.txt")).unwrap(),
            "old\n"
        );

        std::fs::remove_dir_all(&source_root).ok();
        std::fs::remove_dir_all(&staging_root).ok();
    }

    #[test]
    fn a_diverging_mutation_reports_diverged() {
        let source_root = temp_dir("source");
        std::fs::write(source_root.join("config.txt"), b"old\n").unwrap();
        let staging_root = temp_dir("staging-root");

        let proposal = FileMutationProposal {
            relative_path: "config.txt".to_string(),
            new_content: "actual\n".to_string(),
            expected_content: Some("expected\n".to_string()),
            validate_as_json: false,
        };
        let result = run_file_mutation_shadow(
            &staging_root,
            &source_root,
            &proposal,
            &no_params(),
            &Cancellation::new(),
        );

        assert!(matches!(result.outcome, ShadowOutcome::Diverged { .. }));

        std::fs::remove_dir_all(&source_root).ok();
        std::fs::remove_dir_all(&staging_root).ok();
    }

    /// AC3: a real fragility passive evidence (a plain text diff) cannot
    /// reliably catch -- a config mutation that is textually plausible but
    /// syntactically broken, caught only by actually parsing the result
    /// inside the isolated copy.
    #[test]
    fn a_syntactically_broken_json_mutation_is_a_real_detected_failure() {
        let source_root = temp_dir("source");
        std::fs::write(source_root.join("config.json"), b"{\"a\": 1}").unwrap();
        let staging_root = temp_dir("staging-root");

        let proposal = FileMutationProposal {
            relative_path: "config.json".to_string(),
            // Plausible-looking but invalid JSON: a trailing comma.
            new_content: "{\"a\": 1, \"b\": 2,}".to_string(),
            expected_content: None,
            validate_as_json: true,
        };
        let result = run_file_mutation_shadow(
            &staging_root,
            &source_root,
            &proposal,
            &no_params(),
            &Cancellation::new(),
        );

        assert!(
            matches!(result.outcome, ShadowOutcome::Failed { .. }),
            "{:?}",
            result.outcome
        );

        std::fs::remove_dir_all(&source_root).ok();
        std::fs::remove_dir_all(&staging_root).ok();
    }

    /// AC7 negative control: a path-traversal attempt is refused, never
    /// clamped, and the real source tree is never touched.
    #[test]
    fn a_path_traversal_attempt_is_refused_not_clamped() {
        let source_root = temp_dir("source");
        std::fs::write(source_root.join("keep.txt"), b"safe\n").unwrap();
        let staging_root = temp_dir("staging-root");

        let proposal = FileMutationProposal {
            relative_path: "../../../../../../../../etc/passwd".to_string(),
            new_content: "pwned".to_string(),
            expected_content: None,
            validate_as_json: false,
        };
        let result = run_file_mutation_shadow(
            &staging_root,
            &source_root,
            &proposal,
            &no_params(),
            &Cancellation::new(),
        );

        assert!(
            matches!(result.outcome, ShadowOutcome::Refused { .. }),
            "{:?}",
            result.outcome
        );

        std::fs::remove_dir_all(&source_root).ok();
        std::fs::remove_dir_all(&staging_root).ok();
    }

    /// AC7 negative control: a symlink present in the source tree pointing
    /// outside the sandbox is never followed into the staged copy at all —
    /// `StagedWorktree::provision` already skips symlinks entirely, so a
    /// proposal naming that path resolves against a copy where it simply
    /// does not exist, never against the real external target.
    #[cfg(unix)]
    #[test]
    fn a_symlink_escape_is_never_followed_into_the_shadow_copy() {
        let source_root = temp_dir("source");
        let outside_target = temp_dir("outside-secret");
        std::fs::write(outside_target.join("real_secret.txt"), b"do not leak").unwrap();
        std::os::unix::fs::symlink(&outside_target, source_root.join("escape_link")).unwrap();
        let staging_root = temp_dir("staging-root");

        let proposal = FileMutationProposal {
            relative_path: "escape_link/real_secret.txt".to_string(),
            new_content: "attempted overwrite".to_string(),
            expected_content: None,
            validate_as_json: false,
        };
        let result = run_file_mutation_shadow(
            &staging_root,
            &source_root,
            &proposal,
            &no_params(),
            &Cancellation::new(),
        );

        // The symlink was never copied, so the staged copy has no
        // `escape_link` directory at all -- the write fails closed rather
        // than following the link out to `outside_target`.
        assert!(
            !matches!(result.outcome, ShadowOutcome::Matched { .. }),
            "{:?}",
            result.outcome
        );
        assert_eq!(
            std::fs::read_to_string(outside_target.join("real_secret.txt")).unwrap(),
            "do not leak",
            "the real target outside the sandbox must be untouched"
        );

        std::fs::remove_dir_all(&source_root).ok();
        std::fs::remove_dir_all(&outside_target).ok();
        std::fs::remove_dir_all(&staging_root).ok();
    }

    /// AC5/AC7 negative control: a proposal whose own parameters carry a
    /// credential-shaped key is refused before the shadow environment is
    /// even provisioned.
    #[test]
    fn a_credential_shaped_parameter_key_is_refused_before_provisioning() {
        let source_root = temp_dir("source");
        let staging_root = temp_dir("staging-root");
        let mut params = serde_json::Map::new();
        params.insert("api_key".to_string(), serde_json::json!("shhh"));

        let proposal = FileMutationProposal {
            relative_path: "config.txt".to_string(),
            new_content: "new\n".to_string(),
            expected_content: None,
            validate_as_json: false,
        };
        let result = run_file_mutation_shadow(
            &staging_root,
            &source_root,
            &proposal,
            &params,
            &Cancellation::new(),
        );

        assert!(matches!(result.outcome, ShadowOutcome::Refused { .. }));
        // Nothing was provisioned at all -- the staging root stays empty.
        let entries: Vec<_> = std::fs::read_dir(&staging_root)
            .into_iter()
            .flatten()
            .collect();
        assert!(entries.is_empty());

        std::fs::remove_dir_all(&source_root).ok();
        std::fs::remove_dir_all(&staging_root).ok();
    }

    /// AC6: a cancellation requested before the run starts aborts before any
    /// side effect, and cleans up (nothing to clean up, since nothing was
    /// provisioned).
    #[test]
    fn a_pre_cancelled_run_aborts_before_provisioning() {
        let source_root = temp_dir("source");
        let staging_root = temp_dir("staging-root");
        let cancellation = Cancellation::new();
        cancellation.cancel();

        let proposal = FileMutationProposal {
            relative_path: "config.txt".to_string(),
            new_content: "new\n".to_string(),
            expected_content: None,
            validate_as_json: false,
        };
        let result = run_file_mutation_shadow(
            &staging_root,
            &source_root,
            &proposal,
            &no_params(),
            &cancellation,
        );

        assert!(matches!(result.outcome, ShadowOutcome::Aborted { .. }));
        let entries: Vec<_> = std::fs::read_dir(&staging_root)
            .into_iter()
            .flatten()
            .collect();
        assert!(entries.is_empty());

        std::fs::remove_dir_all(&source_root).ok();
        std::fs::remove_dir_all(&staging_root).ok();
    }

    /// AC6: after a completed run, the staged copy is gone -- `Drop`
    /// cleanup ran, no abandoned directory is left behind.
    #[test]
    fn the_staged_copy_is_removed_after_a_completed_run() {
        let source_root = temp_dir("source");
        std::fs::write(source_root.join("config.txt"), b"old\n").unwrap();
        let staging_root = temp_dir("staging-root");

        let proposal = FileMutationProposal {
            relative_path: "config.txt".to_string(),
            new_content: "new\n".to_string(),
            expected_content: None,
            validate_as_json: false,
        };
        let _ = run_file_mutation_shadow(
            &staging_root,
            &source_root,
            &proposal,
            &no_params(),
            &Cancellation::new(),
        );

        let entries: Vec<_> = std::fs::read_dir(&staging_root)
            .into_iter()
            .flatten()
            .collect();
        assert!(
            entries.is_empty(),
            "the staged worktree must be cleaned up after the run completes"
        );

        std::fs::remove_dir_all(&source_root).ok();
        std::fs::remove_dir_all(&staging_root).ok();
    }
}
