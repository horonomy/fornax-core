//! Resolves a concrete filesystem target from a claim's own evidence pool.
//!
//! Neither `fornax_types::Claim` nor `fornax_verify::voi::EvidenceRequest`
//! carries a target path field -- the only place a path shows up at all is
//! `fornax_types::FileDiffPayload::path` on an `EvidenceKind::FileDiff`
//! evidence row. This module never invents a target beyond that: unresolved
//! is an honest outcome, not a guess.

use fornax_types::{Evidence, EvidenceKind, FileDiffPayload};

/// What [`resolve_target`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetResolution {
    /// The exact, unmodified `path` string from a `FileDiff` payload --
    /// still untrusted, still subject to `containment::AcquisitionRoots`.
    Path(String),
    /// No evidence in the pool carries a resolvable target. Most real
    /// traffic hits this today (FORNX-346 ADR 0016 names this gap
    /// explicitly) -- never fabricated into a guessed path.
    NoTarget,
}

/// Scans `evidence` for the first `FileDiff` payload with a well-formed
/// `path` field. Deterministic: evidence is scanned in the order given,
/// same input always yields the same resolution.
pub fn resolve_target(evidence: &[Evidence]) -> TargetResolution {
    for e in evidence {
        if e.kind != EvidenceKind::FileDiff {
            continue;
        }
        if let Ok(payload) = serde_json::from_value::<FileDiffPayload>(e.payload.clone()) {
            if !payload.path.is_empty() {
                return TargetResolution::Path(payload.path);
            }
        }
    }
    TargetResolution::NoTarget
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn file_diff_evidence(path: &str) -> Evidence {
        Evidence {
            id: Uuid::new_v4(),
            session_id: "s1".to_string(),
            source_event_id: Uuid::new_v4(),
            kind: EvidenceKind::FileDiff,
            observed_at: "2026-01-01T00:00:00Z".to_string(),
            payload: serde_json::json!({ "path": path, "diff": "" }),
            provenance: "test".to_string(),
            source: None,
            extension: None,
            evidence_purged: false,
        }
    }

    #[test]
    fn resolves_the_first_file_diff_path() {
        let evidence = vec![file_diff_evidence("src/lib.rs")];
        assert_eq!(
            resolve_target(&evidence),
            TargetResolution::Path("src/lib.rs".to_string())
        );
    }

    #[test]
    fn no_file_diff_evidence_is_an_honest_no_target() {
        let evidence: Vec<Evidence> = vec![];
        assert_eq!(resolve_target(&evidence), TargetResolution::NoTarget);
    }

    #[test]
    fn an_empty_path_is_treated_as_no_target() {
        let evidence = vec![file_diff_evidence("")];
        assert_eq!(resolve_target(&evidence), TargetResolution::NoTarget);
    }
}
