//! CI-provider evidence collection (FORNX-302, FORNX-91's own unmet scope).
//!
//! Standalone crate — not folded into any provider adapter — for the same
//! reason `fornax-vcs` is standalone (see that crate's module docs): CI
//! status is host/repository-level fact, not tied to any one coding-agent
//! provider, and `docs/contributing/adding-an-adapter.md`'s "Allowed core
//! dependencies" restricts adapter crates to `fornax-types` (plus the single
//! named `fornax-vcs` exception) — adding a second exception for this crate
//! was rejected in favor of not depending on it from an adapter at all.
//! `fornax-cli` is the intended consumer (already async, already depends on
//! `reqwest`, already has store access to persist evidence) rather than a
//! provider adapter's per-hook `translate()`, so a CI query never adds
//! network latency to the local hook-invocation critical path
//! (`docs/adr/0001-architecture-invariants.md`'s "no cloud dependency on the
//! local critical path" — this crate's own query is the one deliberate,
//! opt-in exception, invoked out-of-band from a CLI command, not from a hook).
//!
//! # Design: CI provider is GitHub Actions, credential is env-var-only
//!
//! Per FORNX-302's owner decision: GitHub Actions is this repo's own CI
//! provider, so the reusable production credential is whatever the host
//! already has configured for `gh`/`GITHUB_TOKEN` — never a new
//! credential-provisioning flow. **Only presence is checked, and only via
//! an environment variable** (`GITHUB_TOKEN`, then `GH_TOKEN`) — this
//! deliberately does *not* shell out to `gh auth token` or any other
//! subprocess, because
//! `crates/fornax-daemon/tests/adversarial_daemon_input.rs::
//! subprocess_surface_is_still_zero_in_production_code` asserts a zero
//! subprocess-spawn surface across every production module in this
//! workspace (scans for the process-spawning APIs the standard library
//! exposes for launching an external program, or an inline shell
//! invocation). The token's value is never read back, logged, or otherwise
//! surfaced by this crate — see [`GitHubCheckRunSource`]'s doc comment.
//!
//! No credential present is not a failure: [`GitHubCiStatusSensor::collect`]
//! reports [`fornax_types::SignalAvailability::Unavailable`] honestly,
//! exactly like every other sensor's "this signal cannot be observed right
//! now" outcome (`fornax_types::sensor`'s `SensorOutcome` doc comment) —
//! never a fabricated result.
//!
//! # Testability: HTTP behind a trait, not a live network call
//!
//! [`EvidenceSensor::collect`] must stay deterministic and offline-testable
//! like every other sensor in this workspace. The actual GitHub API call is
//! isolated behind [`CheckRunSource`], a small synchronous trait; unit tests
//! inject a fake implementation (no network, no real GitHub API calls in
//! CI) and the real [`GitHubCheckRunSource`] is the only production
//! implementor.

use fornax_types::{
    AgentEvent, CiOverallStatus, CollectionMethod, Evidence, EvidenceKind, EvidenceSensor,
    EvidenceSource, ProcessObservationDetail, ProcessObservationPayload, RuntimeCapabilities,
    SensorOutcome, SignalAvailability, SignalClass, TrustClass,
};
use uuid::Uuid;

/// One GitHub check-run, as reported by the `check-runs` API — only the
/// fields this crate's aggregation actually needs, not a full mirror of
/// GitHub's response shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckRun {
    pub name: String,
    /// `"queued"`, `"in_progress"`, or `"completed"`.
    pub status: String,
    /// Only meaningful when `status == "completed"`; `None` otherwise (and
    /// GitHub itself reports `null` for an incomplete run).
    pub conclusion: Option<String>,
}

/// GitHub's check-runs response for one commit SHA, aggregated to the point
/// this crate needs — `total_count` distinct from `check_runs.len()`
/// because GitHub's real API paginates; a real production caller is
/// expected to have already followed pagination before constructing this
/// (out of scope for FORNX-302's genuinely-minimal single-page query).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiCheckRunStatus {
    pub total_count: i64,
    pub check_runs: Vec<CheckRun>,
}

impl CiCheckRunStatus {
    /// Aggregate every check-run's `status`/`conclusion` into the closed
    /// [`CiOverallStatus`] vocabulary. Failure takes priority over pending
    /// (a run that already failed doesn't become "pending" because a
    /// second, slower run hasn't finished), and an empty or wholly
    /// unrecognized set of conclusions is `Unknown`, never guessed as
    /// `Success`.
    pub fn overall(&self) -> CiOverallStatus {
        if self.total_count == 0 || self.check_runs.is_empty() {
            return CiOverallStatus::Unknown;
        }

        let mut any_recognized = false;
        let mut any_pending = false;
        for run in &self.check_runs {
            if run.status != "completed" {
                any_pending = true;
                continue;
            }
            match run.conclusion.as_deref() {
                Some("failure")
                | Some("timed_out")
                | Some("cancelled")
                | Some("action_required") => return CiOverallStatus::Failure,
                Some("success") | Some("neutral") | Some("skipped") => {
                    any_recognized = true;
                }
                _ => {}
            }
        }
        if any_pending {
            return CiOverallStatus::Pending;
        }
        if any_recognized {
            CiOverallStatus::Success
        } else {
            CiOverallStatus::Unknown
        }
    }
}

/// Everything that can go wrong fetching CI check-run status, distinct from
/// the caller ever fabricating a result. [`Self::NoCredential`] is not a
/// bug — it's the expected outcome on a host with no GitHub credential
/// configured, and [`GitHubCiStatusSensor::collect`] maps it to
/// [`SignalAvailability::Unavailable`] rather than
/// [`SignalAvailability::CollectionFailed`].
#[derive(Debug, thiserror::Error)]
pub enum CheckRunFetchError {
    #[error("no GitHub credential present (checked GITHUB_TOKEN, GH_TOKEN)")]
    NoCredential,
    #[error("GitHub API request failed: {0}")]
    Http(String),
    #[error("failed to parse GitHub API response: {0}")]
    Parse(String),
}

/// The seam [`GitHubCiStatusSensor`] queries through — a synchronous trait
/// so `collect` (required sync by [`EvidenceSensor`]) never needs an async
/// runtime of its own. [`GitHubCheckRunSource`] is the one production
/// implementor; tests inject a fake.
pub trait CheckRunSource {
    fn fetch(
        &self,
        repo_slug: &str,
        commit_sha: &str,
    ) -> Result<CiCheckRunStatus, CheckRunFetchError>;
}

/// Production [`CheckRunSource`]: queries `GET
/// /repos/{repo}/commits/{sha}/check-runs` via a blocking `reqwest` client,
/// using whatever GitHub credential is already present in the process
/// environment.
///
/// **Never logs, returns, or otherwise surfaces the token value itself** —
/// [`Self::from_env`] only ever reports whether a credential was found
/// (`Some`/`None`), matching this project's standing secret-handling rule
/// (least privilege, presence-only checks, no persistence of the credential
/// itself). The token is used solely as an `Authorization` header value on
/// the one outbound request this type issues.
pub struct GitHubCheckRunSource {
    token: String,
}

impl GitHubCheckRunSource {
    /// Checks `GITHUB_TOKEN`, then `GH_TOKEN`, for a non-empty value.
    /// `None` means no credential is configured — callers must treat that
    /// as "cannot query GitHub", never fall back to an unauthenticated
    /// request (a private repository would silently look identical to "no
    /// CI evidence" instead of the credential gap it actually is).
    pub fn from_env() -> Option<Self> {
        for var in ["GITHUB_TOKEN", "GH_TOKEN"] {
            if let Ok(value) = std::env::var(var) {
                if !value.is_empty() {
                    return Some(Self { token: value });
                }
            }
        }
        None
    }
}

impl CheckRunSource for GitHubCheckRunSource {
    fn fetch(
        &self,
        repo_slug: &str,
        commit_sha: &str,
    ) -> Result<CiCheckRunStatus, CheckRunFetchError> {
        let url =
            format!("https://api.github.com/repos/{repo_slug}/commits/{commit_sha}/check-runs");
        let client = reqwest::blocking::Client::new();
        let response = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("User-Agent", "fornax-ci")
            .header("Accept", "application/vnd.github+json")
            .send()
            .map_err(|e| CheckRunFetchError::Http(e.to_string()))?;

        if !response.status().is_success() {
            return Err(CheckRunFetchError::Http(format!(
                "GitHub API returned {}",
                response.status()
            )));
        }

        let body: serde_json::Value = response
            .json()
            .map_err(|e| CheckRunFetchError::Parse(e.to_string()))?;
        parse_check_run_response(&body)
    }
}

/// Parses GitHub's real `check-runs` response shape
/// (`{"total_count": N, "check_runs": [{"name", "status", "conclusion"}, ...]}`)
/// into [`CiCheckRunStatus`]. A free function (not a method on the response
/// type) so unit tests can exercise it directly against a captured fixture
/// without a network round-trip.
fn parse_check_run_response(
    body: &serde_json::Value,
) -> Result<CiCheckRunStatus, CheckRunFetchError> {
    let total_count = body
        .get("total_count")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| CheckRunFetchError::Parse("missing total_count".to_string()))?;
    let check_runs = body
        .get("check_runs")
        .and_then(|v| v.as_array())
        .ok_or_else(|| CheckRunFetchError::Parse("missing check_runs array".to_string()))?
        .iter()
        .map(|run| {
            let name = run
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let status = run
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let conclusion = run
                .get("conclusion")
                .and_then(|v| v.as_str())
                .map(String::from);
            CheckRun {
                name,
                status,
                conclusion,
            }
        })
        .collect();

    Ok(CiCheckRunStatus {
        total_count,
        check_runs,
    })
}

/// [`fornax_types::sensor::EvidenceSensor`] for GitHub Actions check-run
/// status on one commit SHA. `TrustClass::IndependentExternal` — reported
/// by GitHub, a system outside both the coding agent and the local host.
///
/// Unlike the per-hook-event sensors in the adapter crates, this sensor is
/// not driven by a live `AgentEvent` stream — `repo_slug`/`commit_sha` are
/// fixed at construction time (analogous to `ClaudeGitWorkingTreeSensor`'s
/// `adapter_version` field). `event` is still accepted (matching
/// [`EvidenceSensor::collect`]'s required signature) purely to stamp
/// `session_id`/`observed_at`/`source_event_id` on the produced
/// [`Evidence`], the same provenance fields every other sensor stamps.
pub struct GitHubCiStatusSensor<S: CheckRunSource> {
    source: S,
    repo_slug: String,
    commit_sha: String,
    collector_version: Option<String>,
}

impl<S: CheckRunSource> GitHubCiStatusSensor<S> {
    pub fn new(
        source: S,
        repo_slug: impl Into<String>,
        commit_sha: impl Into<String>,
        collector_version: Option<String>,
    ) -> Self {
        Self {
            source,
            repo_slug: repo_slug.into(),
            commit_sha: commit_sha.into(),
            collector_version,
        }
    }

    fn build_evidence(&self, event: &AgentEvent, status: &CiCheckRunStatus) -> Evidence {
        let overall = status.overall();
        let description = format!(
            "GitHub check-runs for {repo}@{sha}: {count} run(s), overall {overall:?}",
            repo = self.repo_slug,
            sha = self.commit_sha,
            count = status.total_count
        );

        Evidence {
            id: Uuid::new_v4(),
            session_id: event.session_id.clone(),
            source_event_id: event.id,
            kind: EvidenceKind::ProcessObservation,
            observed_at: event.observed_at.clone(),
            payload: serde_json::to_value(ProcessObservationPayload {
                description,
                observation: Some(ProcessObservationDetail::CiCheckStatus {
                    repo: self.repo_slug.clone(),
                    commit_sha: self.commit_sha.clone(),
                    total_count: status.total_count,
                    overall,
                }),
            })
            .expect("ProcessObservationPayload always serializes"),
            provenance: format!(
                "{name}:github_check_runs:{repo}@{sha}",
                name = self.name(),
                repo = self.repo_slug,
                sha = self.commit_sha
            ),
            source: Some(EvidenceSource::now(
                self.name(),
                self.trust_class(),
                None,
                self.collection_method(),
                self.collector_version(),
            )),
            extension: None,
            evidence_purged: false,
        }
    }
}

impl<S: CheckRunSource> EvidenceSensor for GitHubCiStatusSensor<S> {
    fn name(&self) -> &'static str {
        "github_ci_status_sensor_v1"
    }

    fn required_capabilities(&self) -> &'static [SignalClass] {
        // No provider-runtime capability is needed — this sensor queries an
        // external HTTP API, not anything a coding-agent provider exposes.
        &[]
    }

    fn trust_class(&self) -> TrustClass {
        TrustClass::IndependentExternal
    }

    fn collection_method(&self) -> CollectionMethod {
        CollectionMethod::HttpQuery
    }

    fn collector_version(&self) -> Option<String> {
        self.collector_version.clone()
    }

    fn collect(&self, event: &AgentEvent, _caps: &RuntimeCapabilities) -> SensorOutcome {
        match self.source.fetch(&self.repo_slug, &self.commit_sha) {
            Ok(status) => SensorOutcome::collected(vec![self.build_evidence(event, &status)]),
            Err(CheckRunFetchError::NoCredential) => SensorOutcome::not_collected(
                SignalAvailability::Unavailable,
                Some(format!(
                    "no GitHub credential present — cannot query CI status for {}",
                    self.repo_slug
                )),
            ),
            Err(e @ CheckRunFetchError::Http(_)) => SensorOutcome::not_collected(
                SignalAvailability::CollectionFailed,
                Some(e.to_string()),
            ),
            Err(e @ CheckRunFetchError::Parse(_)) => SensorOutcome::not_collected(
                SignalAvailability::CollectionFailed,
                Some(e.to_string()),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fornax_types::{collect_with_disable_check, EventKind, Provider, SensorDisableConfig};

    fn dummy_event() -> AgentEvent {
        AgentEvent {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            provider: Provider::Unknown,
            kind: EventKind::SessionEnd,
            observed_at: "2026-01-01T00:00:00Z".into(),
            tool_name: None,
            tool_input: None,
            tool_response: None,
            raw: serde_json::json!({}),
        }
    }

    struct FakeSource {
        result: Result<CiCheckRunStatus, &'static str>,
    }

    impl CheckRunSource for FakeSource {
        fn fetch(
            &self,
            _repo_slug: &str,
            _commit_sha: &str,
        ) -> Result<CiCheckRunStatus, CheckRunFetchError> {
            match &self.result {
                Ok(status) => Ok(status.clone()),
                Err("no_credential") => Err(CheckRunFetchError::NoCredential),
                Err(other) => Err(CheckRunFetchError::Http(other.to_string())),
            }
        }
    }

    fn run(name: &str, status: &str, conclusion: Option<&str>) -> CheckRun {
        CheckRun {
            name: name.to_string(),
            status: status.to_string(),
            conclusion: conclusion.map(String::from),
        }
    }

    // --- CiCheckRunStatus::overall aggregation -----------------------------

    #[test]
    fn overall_is_success_when_every_run_completed_successfully() {
        let status = CiCheckRunStatus {
            total_count: 2,
            check_runs: vec![
                run("rust/lint", "completed", Some("success")),
                run("rust/test", "completed", Some("neutral")),
            ],
        };
        assert_eq!(status.overall(), CiOverallStatus::Success);
    }

    #[test]
    fn overall_is_failure_when_any_run_failed() {
        let status = CiCheckRunStatus {
            total_count: 2,
            check_runs: vec![
                run("rust/lint", "completed", Some("success")),
                run("rust/test", "completed", Some("failure")),
            ],
        };
        assert_eq!(status.overall(), CiOverallStatus::Failure);
    }

    #[test]
    fn overall_is_failure_even_when_a_different_run_is_still_pending() {
        // Failure takes priority: a run that already failed doesn't become
        // "pending" merely because a second, slower run hasn't finished.
        let status = CiCheckRunStatus {
            total_count: 2,
            check_runs: vec![
                run("rust/lint", "completed", Some("failure")),
                run("rust/test", "in_progress", None),
            ],
        };
        assert_eq!(status.overall(), CiOverallStatus::Failure);
    }

    #[test]
    fn overall_is_pending_when_a_run_has_not_completed_and_none_failed() {
        let status = CiCheckRunStatus {
            total_count: 2,
            check_runs: vec![
                run("rust/lint", "completed", Some("success")),
                run("rust/test", "in_progress", None),
            ],
        };
        assert_eq!(status.overall(), CiOverallStatus::Pending);
    }

    #[test]
    fn overall_is_unknown_when_there_are_no_check_runs() {
        let status = CiCheckRunStatus {
            total_count: 0,
            check_runs: vec![],
        };
        assert_eq!(status.overall(), CiOverallStatus::Unknown);
    }

    #[test]
    fn overall_is_unknown_rather_than_guessed_for_an_unrecognized_conclusion() {
        let status = CiCheckRunStatus {
            total_count: 1,
            check_runs: vec![run("weird/check", "completed", Some("quantum_verified"))],
        };
        assert_eq!(status.overall(), CiOverallStatus::Unknown);
    }

    // --- parse_check_run_response ------------------------------------------

    #[test]
    fn parses_a_real_shaped_github_response() {
        let body = serde_json::json!({
            "total_count": 1,
            "check_runs": [
                {"id": 1, "name": "rust", "status": "completed", "conclusion": "success"}
            ]
        });
        let status = parse_check_run_response(&body).unwrap();
        assert_eq!(status.total_count, 1);
        assert_eq!(status.check_runs.len(), 1);
        assert_eq!(status.check_runs[0].name, "rust");
        assert_eq!(status.overall(), CiOverallStatus::Success);
    }

    #[test]
    fn missing_check_runs_array_is_a_parse_error() {
        let body = serde_json::json!({"total_count": 0});
        assert!(matches!(
            parse_check_run_response(&body),
            Err(CheckRunFetchError::Parse(_))
        ));
    }

    // --- GitHubCheckRunSource::from_env — presence-only credential check --

    #[test]
    fn from_env_reports_none_when_neither_env_var_is_set() {
        // Isolated to this crate's own vars; does not touch any other
        // process-global state.
        std::env::remove_var("GITHUB_TOKEN");
        std::env::remove_var("GH_TOKEN");
        assert!(GitHubCheckRunSource::from_env().is_none());
    }

    // --- GitHubCiStatusSensor::collect --------------------------------------

    #[test]
    fn collect_reports_evidence_on_success() {
        let sensor = GitHubCiStatusSensor::new(
            FakeSource {
                result: Ok(CiCheckRunStatus {
                    total_count: 1,
                    check_runs: vec![run("rust", "completed", Some("success"))],
                }),
            },
            "horonomy/fornax-core",
            "abc123",
            Some("0.0.1".to_string()),
        );
        let caps = RuntimeCapabilities {
            schema_version: fornax_types::CAPABILITY_SCHEMA_VERSION,
            provider: Provider::Unknown,
            signals: vec![],
            notes: Default::default(),
        };
        let outcome = sensor.collect(&dummy_event(), &caps);
        assert_eq!(outcome.state, SignalAvailability::Available);
        assert_eq!(outcome.evidence.len(), 1);
        let ev = &outcome.evidence[0];
        assert_eq!(ev.kind, EvidenceKind::ProcessObservation);
        assert_eq!(
            ev.source.as_ref().unwrap().trust_class,
            TrustClass::IndependentExternal
        );
        assert_eq!(
            ev.source.as_ref().unwrap().collection_method,
            CollectionMethod::HttpQuery
        );
        let v = ev.payload.get("observation").unwrap();
        assert_eq!(
            v.get("observation_kind").unwrap().as_str().unwrap(),
            "ci_check_status"
        );
        assert_eq!(v.get("overall").unwrap().as_str().unwrap(), "success");
    }

    #[test]
    fn collect_reports_unavailable_not_failed_when_no_credential_present() {
        // Required test: explicit "no credential present" -> `Unavailable`,
        // not a fabricated result and not `CollectionFailed` (which would
        // imply a genuine attempt that errored, rather than an honestly
        // unattempted query).
        let sensor = GitHubCiStatusSensor::new(
            FakeSource {
                result: Err("no_credential"),
            },
            "horonomy/fornax-core",
            "abc123",
            None,
        );
        let caps = RuntimeCapabilities {
            schema_version: fornax_types::CAPABILITY_SCHEMA_VERSION,
            provider: Provider::Unknown,
            signals: vec![],
            notes: Default::default(),
        };
        let outcome = sensor.collect(&dummy_event(), &caps);
        assert!(!outcome.has_evidence());
        assert_eq!(outcome.state, SignalAvailability::Unavailable);
        assert!(outcome.detail.unwrap().contains("no GitHub credential"));
    }

    #[test]
    fn collect_reports_collection_failed_on_http_error() {
        let sensor = GitHubCiStatusSensor::new(
            FakeSource {
                result: Err("500 Internal Server Error"),
            },
            "horonomy/fornax-core",
            "abc123",
            None,
        );
        let caps = RuntimeCapabilities {
            schema_version: fornax_types::CAPABILITY_SCHEMA_VERSION,
            provider: Provider::Unknown,
            signals: vec![],
            notes: Default::default(),
        };
        let outcome = sensor.collect(&dummy_event(), &caps);
        assert!(!outcome.has_evidence());
        assert_eq!(outcome.state, SignalAvailability::CollectionFailed);
    }

    // --- FORNX-302: disable-config wiring -----------------------------------

    #[test]
    fn disabled_sensor_reports_disabled_without_querying_the_source() {
        let sensor = GitHubCiStatusSensor::new(
            FakeSource {
                result: Ok(CiCheckRunStatus {
                    total_count: 1,
                    check_runs: vec![run("rust", "completed", Some("success"))],
                }),
            },
            "horonomy/fornax-core",
            "abc123",
            None,
        );
        let caps = RuntimeCapabilities {
            schema_version: fornax_types::CAPABILITY_SCHEMA_VERSION,
            provider: Provider::Unknown,
            signals: vec![],
            notes: Default::default(),
        };
        let disable_config = SensorDisableConfig::from_toml_str(
            "[sensors]\ndisabled = [\"github_ci_status_sensor_v1\"]\n",
        )
        .unwrap();
        let outcome = collect_with_disable_check(&sensor, &dummy_event(), &caps, &disable_config);
        assert!(!outcome.has_evidence());
        assert_eq!(outcome.state, SignalAvailability::Disabled);
    }

    #[test]
    fn enabled_sensor_runs_normally_when_not_named_in_disable_config() {
        let sensor = GitHubCiStatusSensor::new(
            FakeSource {
                result: Ok(CiCheckRunStatus {
                    total_count: 1,
                    check_runs: vec![run("rust", "completed", Some("success"))],
                }),
            },
            "horonomy/fornax-core",
            "abc123",
            None,
        );
        let caps = RuntimeCapabilities {
            schema_version: fornax_types::CAPABILITY_SCHEMA_VERSION,
            provider: Provider::Unknown,
            signals: vec![],
            notes: Default::default(),
        };
        let disable_config = SensorDisableConfig::empty();
        let outcome = collect_with_disable_check(&sensor, &dummy_event(), &caps, &disable_config);
        assert!(outcome.has_evidence());
        assert_eq!(outcome.state, SignalAvailability::Available);
    }
}
