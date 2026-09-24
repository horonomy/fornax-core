//! `QueryCiStatus` -- reuses `fornax-ci`'s existing GitHub check-runs client
//! and aggregation. This module adds zero new network code: the one HTTP
//! call is `fornax_ci::GitHubCheckRunSource::fetch`, the same production
//! implementor `fornax-ci`'s own (currently unused-in-production)
//! `GitHubCiStatusSensor` uses.
//!
//! # SSRF-safety rules
//!
//! - **`repo_slug` comes only from `ExecutorGrants::ci_repos()`** --
//!   operator-configured, never from evidence. This makes SSRF via a
//!   malicious repo target structurally impossible: there is no code path
//!   here that reads a repo name out of agent-reported JSON and hands it to
//!   an HTTP client. When more than one repo is configured, an explicit
//!   `--repo` naming one of them is required; ambiguity (multiple
//!   configured, none specified) is a refusal, not a guess.
//! - **`commit_sha` must match `^[0-9a-f]{7,40}$`** before any network call
//!   is attempted, else the attempt is refused. Blocks path/URL injection
//!   via a malformed sha (`fornax_ci::GitHubCheckRunSource::fetch` builds a
//!   URL by direct string interpolation of `commit_sha`).

use fornax_acquire::AcquisitionOutcome;
use fornax_ci::CheckRunSource;
use fornax_types::{Evidence, EvidenceKind, ProcessObservationDetail, ProcessObservationPayload};
use uuid::Uuid;

use crate::grants::ExecutorGrants;

/// `true` only for 7-40 lowercase hex characters -- deliberately stricter
/// than `str::is_ascii_hexdigit` (which also accepts uppercase `A-F`) to
/// match git's own canonical lowercase short/full sha rendering exactly.
fn is_valid_commit_sha(sha: &str) -> bool {
    (7..=40).contains(&sha.len())
        && sha
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Resolve which repo a `QueryCiStatus` attempt may query, from
/// operator-configured grants only -- `repo_flag` (an explicit `--repo`)
/// disambiguates when more than one repo is configured; it never
/// *introduces* a repo `grants` doesn't already name.
fn resolve_repo<'a>(
    grants: &'a ExecutorGrants,
    repo_flag: Option<&str>,
) -> Result<&'a str, String> {
    let repos = grants.ci_repos();
    match repos.len() {
        0 => Err(
            "no CI repo is operator-approved ([acquisition_exec].allowed_ci_repos is empty); \
             refusing"
                .to_string(),
        ),
        1 => Ok(repos[0].as_str()),
        _ => {
            let Some(flag) = repo_flag else {
                return Err(
                    "multiple CI repos are configured; --repo must name exactly one of them"
                        .to_string(),
                );
            };
            repos
                .iter()
                .find(|r| r.as_str() == flag)
                .map(String::as_str)
                .ok_or_else(|| format!("'{flag}' is not one of the operator-approved CI repos"))
        }
    }
}

/// Run one `QueryCiStatus` probe. `commit_sha` is agent-reported evidence
/// (untrusted, validated below); `repo_flag` is an operator-supplied CLI
/// flag, never evidence. A `repo` field embedded in evidence is never read
/// here at all -- only `grants.ci_repos()` is ever consulted.
#[allow(clippy::too_many_arguments)]
pub fn query_ci_status(
    grants: &ExecutorGrants,
    repo_flag: Option<&str>,
    commit_sha: &str,
    source: &impl CheckRunSource,
    session_id: &str,
    source_event_id: Uuid,
    observed_at: &str,
) -> AcquisitionOutcome {
    if !is_valid_commit_sha(commit_sha) {
        return AcquisitionOutcome::Refused {
            reason: format!(
                "'{commit_sha}' is not a valid commit sha (expected 7-40 lowercase hex \
                 characters); refusing before any network call"
            ),
        };
    }

    let repo = match resolve_repo(grants, repo_flag) {
        Ok(r) => r,
        Err(reason) => return AcquisitionOutcome::Refused { reason },
    };

    match source.fetch(repo, commit_sha) {
        Ok(status) => {
            let overall = status.overall();
            let evidence = Evidence {
                id: Uuid::new_v4(),
                session_id: session_id.to_string(),
                source_event_id,
                kind: EvidenceKind::ProcessObservation,
                observed_at: observed_at.to_string(),
                payload: serde_json::to_value(ProcessObservationPayload {
                    description: format!(
                        "GitHub check-runs for {repo}@{commit_sha}: {} run(s), overall {overall:?}",
                        status.total_count
                    ),
                    observation: Some(ProcessObservationDetail::CiCheckStatus {
                        repo: repo.to_string(),
                        commit_sha: commit_sha.to_string(),
                        total_count: status.total_count,
                        overall,
                    }),
                })
                .expect("ProcessObservationPayload always serializes"),
                provenance: "fornax-acquire-exec:query_ci_status:FORNX-346".to_string(),
                source: None,
                extension: None,
                evidence_purged: false,
            };
            AcquisitionOutcome::Acquired(Box::new(evidence))
        }
        Err(e) => AcquisitionOutcome::Failed {
            reason: e.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fornax_ci::{CheckRunFetchError, CiCheckRunStatus};

    struct FakeSource {
        result: Result<CiCheckRunStatus, CheckRunFetchError>,
        /// Records the exact args passed to `fetch`, so a test can prove a
        /// `repo` field embedded in evidence was never consulted.
        seen_repo: std::cell::RefCell<Option<String>>,
    }

    impl FakeSource {
        fn ok() -> Self {
            Self {
                result: Ok(CiCheckRunStatus {
                    total_count: 0,
                    check_runs: vec![],
                }),
                seen_repo: std::cell::RefCell::new(None),
            }
        }
    }

    impl CheckRunSource for FakeSource {
        fn fetch(
            &self,
            repo_slug: &str,
            _commit_sha: &str,
        ) -> Result<CiCheckRunStatus, CheckRunFetchError> {
            *self.seen_repo.borrow_mut() = Some(repo_slug.to_string());
            match &self.result {
                Ok(s) => Ok(s.clone()),
                Err(_) => Err(CheckRunFetchError::Http("boom".to_string())),
            }
        }
    }

    #[test]
    fn a_malformed_commit_sha_is_refused_before_any_network_call() {
        let grants = ExecutorGrants::new(vec![], vec!["horonomy/fornax-core".to_string()]);
        let source = FakeSource::ok();
        let outcome = query_ci_status(
            &grants,
            None,
            "../../../etc/passwd",
            &source,
            "s1",
            Uuid::new_v4(),
            "2026-01-01T00:00:00Z",
        );
        assert!(matches!(outcome, AcquisitionOutcome::Refused { .. }));
        assert!(
            source.seen_repo.borrow().is_none(),
            "fetch must never be called"
        );
    }

    #[test]
    fn no_configured_ci_repo_denies_by_default() {
        let grants = ExecutorGrants::default();
        let source = FakeSource::ok();
        let outcome = query_ci_status(
            &grants,
            None,
            "abc1234",
            &source,
            "s1",
            Uuid::new_v4(),
            "2026-01-01T00:00:00Z",
        );
        assert!(matches!(outcome, AcquisitionOutcome::Refused { .. }));
    }

    #[test]
    fn an_embedded_repo_field_from_evidence_is_ignored_only_grants_are_consulted() {
        let grants = ExecutorGrants::new(vec![], vec!["horonomy/fornax-core".to_string()]);
        let source = FakeSource::ok();
        // No API here even accepts an evidence-supplied repo -- `resolve_repo`
        // only ever reads `grants.ci_repos()` / `repo_flag`. This test pins
        // that by confirming the repo actually queried is the grants' repo,
        // not something else.
        let outcome = query_ci_status(
            &grants,
            None,
            "abc1234",
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

    #[test]
    fn multiple_configured_repos_with_no_flag_is_an_ambiguous_refusal() {
        let grants = ExecutorGrants::new(
            vec![],
            vec![
                "horonomy/fornax-core".to_string(),
                "horonomy/other".to_string(),
            ],
        );
        let source = FakeSource::ok();
        let outcome = query_ci_status(
            &grants,
            None,
            "abc1234",
            &source,
            "s1",
            Uuid::new_v4(),
            "2026-01-01T00:00:00Z",
        );
        assert!(matches!(outcome, AcquisitionOutcome::Refused { .. }));
    }

    #[test]
    fn valid_hex_shas_of_various_lengths_pass_validation() {
        assert!(is_valid_commit_sha("abc1234"));
        assert!(is_valid_commit_sha(&"a".repeat(40)));
        assert!(!is_valid_commit_sha("abc123")); // too short
        assert!(!is_valid_commit_sha(&"a".repeat(41))); // too long
        assert!(!is_valid_commit_sha("ABC1234")); // uppercase refused
        assert!(!is_valid_commit_sha("../../../etc/passwd"));
    }
}
