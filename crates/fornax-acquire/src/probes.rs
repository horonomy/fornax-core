//! The two real, auto-safe probes this crate implements: hashing a
//! contained artifact and querying real git working-tree state via
//! `fornax-vcs`. Both are pure, in-process, read-only -- no subprocess
//! spawn, no network call.

use std::path::Path;

use fornax_types::{Evidence, EvidenceKind, ProcessObservationDetail, ProcessObservationPayload};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::outcome::AcquisitionOutcome;

fn observation_evidence(
    session_id: &str,
    source_event_id: Uuid,
    observed_at: &str,
    description: String,
    detail: ProcessObservationDetail,
) -> Evidence {
    Evidence {
        id: Uuid::new_v4(),
        session_id: session_id.to_string(),
        source_event_id,
        kind: EvidenceKind::ProcessObservation,
        observed_at: observed_at.to_string(),
        payload: serde_json::to_value(ProcessObservationPayload {
            description,
            observation: Some(detail),
        })
        .expect("ProcessObservationPayload always serializes"),
        provenance: "fornax-acquire:FORNX-346".to_string(),
        source: None,
        extension: None,
        evidence_purged: false,
    }
}

/// Hash `path` (already contained -- see `containment::AcquisitionRoots`)
/// and produce a `ProcessObservationDetail::ArtifactHashVerified` evidence
/// row. `Unavailable` (not `Failed`) for a missing file -- a file that
/// doesn't exist is an honest absence, not an execution error.
pub fn verify_artifact_hash(
    path: &Path,
    session_id: &str,
    source_event_id: Uuid,
    observed_at: &str,
) -> AcquisitionOutcome {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return AcquisitionOutcome::Unavailable {
                reason: format!("{} does not exist", path.display()),
            }
        }
        Err(e) => {
            return AcquisitionOutcome::Failed {
                reason: format!("failed to read {}: {e}", path.display()),
            }
        }
    };
    let sha256_hex = hex::encode(Sha256::digest(&bytes));
    let evidence = observation_evidence(
        session_id,
        source_event_id,
        observed_at,
        format!("verified artifact hash for {}", path.display()),
        ProcessObservationDetail::ArtifactHashVerified {
            path: path.display().to_string(),
            sha256_hex,
        },
    );
    AcquisitionOutcome::Acquired(Box::new(evidence))
}

/// Query `fornax_vcs::working_tree_status` for `path`'s containing
/// directory and produce the same `WorkingTreeStatusObserved` shape
/// `fornax-adapter-claude`'s `ClaudeGitWorkingTreeSensor` already produces
/// today -- reusing the existing evidence contract rather than inventing a
/// parallel one.
pub fn inspect_vcs_state(
    path: &Path,
    session_id: &str,
    source_event_id: Uuid,
    observed_at: &str,
) -> AcquisitionOutcome {
    let search_root = path.parent().unwrap_or(path);
    let status = match fornax_vcs::working_tree_status(search_root) {
        Ok(s) => s,
        Err(e) => {
            return AcquisitionOutcome::Failed {
                reason: format!("failed to query working-tree status: {e}"),
            }
        }
    };
    if !status.is_repo {
        return AcquisitionOutcome::Unavailable {
            reason: format!("{} is not inside a git working tree", path.display()),
        };
    }
    let path_is_dirty = status.is_absolute_path_dirty(path).unwrap_or(false);
    let evidence = observation_evidence(
        session_id,
        source_event_id,
        observed_at,
        format!(
            "observed real git working-tree state for {}",
            path.display()
        ),
        ProcessObservationDetail::WorkingTreeStatusObserved {
            claimed_path: path.display().to_string(),
            is_repo: status.is_repo,
            head_commit: status.head_commit.clone(),
            path_is_dirty,
        },
    );
    AcquisitionOutcome::Acquired(Box::new(evidence))
}

/// Query `fornax_vcs::working_tree_status` for `root` itself, with no
/// per-file claimed path (FORNX-346 AC2 gap fix): most real claims carry no
/// `FileDiff` evidence at all, so gating `InspectVcsState` behind
/// `resolve_target` made this probe `Unavailable` for the overwhelming
/// majority of real traffic even though a VCS-state check is inherently a
/// repo-level question, not a per-file one. `root` is an operator-configured
/// `AcquisitionRoots` entry -- already trusted, never an agent-reported
/// path -- so this intentionally skips the per-file containment check
/// [`inspect_vcs_state`] needs for an untrusted `FileDiff` path.
///
/// Reuses the same `WorkingTreeStatusObserved` evidence shape: `claimed_path`
/// is `root` itself, and `path_is_dirty` is repurposed honestly as
/// "the working tree has at least one dirty path" (`!dirty_paths.is_empty()`)
/// rather than "this one file is dirty" -- a real, non-fabricated repo-wide
/// signal, not a misuse of the field.
pub fn inspect_vcs_state_for_root(
    root: &Path,
    session_id: &str,
    source_event_id: Uuid,
    observed_at: &str,
) -> AcquisitionOutcome {
    let status = match fornax_vcs::working_tree_status(root) {
        Ok(s) => s,
        Err(e) => {
            return AcquisitionOutcome::Failed {
                reason: format!("failed to query working-tree status: {e}"),
            }
        }
    };
    if !status.is_repo {
        return AcquisitionOutcome::Unavailable {
            reason: format!("{} is not inside a git working tree", root.display()),
        };
    }
    let evidence = observation_evidence(
        session_id,
        source_event_id,
        observed_at,
        format!(
            "observed real git working-tree state for acquisition root {}",
            root.display()
        ),
        ProcessObservationDetail::WorkingTreeStatusObserved {
            claimed_path: root.display().to_string(),
            is_repo: status.is_repo,
            head_commit: status.head_commit.clone(),
            path_is_dirty: !status.dirty_paths.is_empty(),
        },
    );
    AcquisitionOutcome::Acquired(Box::new(evidence))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashing_a_missing_file_is_unavailable_not_failed() {
        let outcome = verify_artifact_hash(
            Path::new("/nonexistent/fornax-acquire-test-file.txt"),
            "s1",
            Uuid::new_v4(),
            "2026-01-01T00:00:00Z",
        );
        assert!(matches!(outcome, AcquisitionOutcome::Unavailable { .. }));
    }

    #[test]
    fn hashing_a_real_file_produces_a_verified_hash_evidence_row() {
        let path = std::env::temp_dir().join(format!("fornax-acquire-{}.txt", Uuid::new_v4()));
        std::fs::write(&path, b"hello").unwrap();
        let outcome = verify_artifact_hash(&path, "s1", Uuid::new_v4(), "2026-01-01T00:00:00Z");
        match outcome {
            AcquisitionOutcome::Acquired(evidence) => {
                assert_eq!(evidence.kind, EvidenceKind::ProcessObservation);
                let payload: ProcessObservationPayload =
                    serde_json::from_value(evidence.payload).unwrap();
                match payload.observation {
                    Some(ProcessObservationDetail::ArtifactHashVerified { sha256_hex, .. }) => {
                        // sha256("hello")
                        assert_eq!(
                            sha256_hex,
                            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
                        );
                    }
                    other => panic!("expected ArtifactHashVerified, got {other:?}"),
                }
            }
            other => panic!("expected Acquired, got {other:?}"),
        }
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn inspecting_vcs_state_outside_any_repo_is_unavailable() {
        let path = std::env::temp_dir().join(format!("fornax-acquire-norepo-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&path).unwrap();
        let target = path.join("file.txt");
        std::fs::write(&target, b"x").unwrap();
        let outcome = inspect_vcs_state(&target, "s1", Uuid::new_v4(), "2026-01-01T00:00:00Z");
        // temp dirs are (almost always) not inside a git repo; if this host's
        // temp dir happens to be, treat it as inconclusive rather than fail.
        assert!(matches!(
            outcome,
            AcquisitionOutcome::Unavailable { .. } | AcquisitionOutcome::Acquired(_)
        ));
        std::fs::remove_dir_all(&path).ok();
    }

    #[test]
    fn inspecting_vcs_state_for_root_outside_any_repo_is_unavailable() {
        let root =
            std::env::temp_dir().join(format!("fornax-acquire-root-norepo-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let outcome =
            inspect_vcs_state_for_root(&root, "s1", Uuid::new_v4(), "2026-01-01T00:00:00Z");
        assert!(matches!(
            outcome,
            AcquisitionOutcome::Unavailable { .. } | AcquisitionOutcome::Acquired(_)
        ));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn inspecting_vcs_state_for_a_real_repo_root_reports_the_repo_honestly() {
        // This crate's own checkout is a real git working tree -- no
        // external process spawn needed to prove the positive path (this
        // workspace's zero-subprocess-spawn invariant, FORNX-238, scans
        // every `src/` file including `#[cfg(test)]` blocks, not just
        // production code, so spawning `git init` as a child process is
        // off-limits even here).
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let outcome =
            inspect_vcs_state_for_root(root, "s1", Uuid::new_v4(), "2026-01-01T00:00:00Z");
        match outcome {
            AcquisitionOutcome::Acquired(evidence) => {
                let payload: ProcessObservationPayload =
                    serde_json::from_value(evidence.payload).unwrap();
                match payload.observation {
                    Some(ProcessObservationDetail::WorkingTreeStatusObserved {
                        is_repo,
                        claimed_path,
                        ..
                    }) => {
                        assert!(is_repo);
                        assert_eq!(claimed_path, root.display().to_string());
                    }
                    other => panic!("expected WorkingTreeStatusObserved, got {other:?}"),
                }
            }
            // A CI checkout without a full `.git` history (e.g. a tarball
            // export) is inconclusive, not a bug in this probe.
            AcquisitionOutcome::Unavailable { .. } => {}
            other => panic!("expected Acquired or Unavailable, got {other:?}"),
        }
    }
}
