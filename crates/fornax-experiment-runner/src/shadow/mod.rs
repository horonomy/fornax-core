//! Shadow Execution / Digital Twin Verification (FORNX-386, Stage 9).
//!
//! Extends this crate's existing isolation mechanism — [`crate::staging::StagedWorktree`],
//! [`crate::policy::GlobalExperimentPolicy`]/[`crate::policy::is_permitted`],
//! [`crate::orphan::sweep_orphaned_staging_dirs`], and
//! [`crate::executor::Cancellation`] — into a bounded pre-flight verification
//! capability: run a proposed high-impact action against an isolated digital
//! twin and compare the observed effect to what was expected, before ever
//! recommending real execution. This module deliberately does **not** build a
//! second experiment runtime (FORNX-386's own scope item) — every shadow run
//! is staged, gated, and cleaned up exactly the way an FORNX-99/100
//! counterfactual experiment already is; the only genuinely new pieces are
//! the two domain-specific runners below and the baseline/shadow comparison
//! + fidelity-metadata types that wrap them.
//!
//! # Two domains, chosen for safety, not breadth
//!
//! [`file_mutation`] and [`db_migration`] are materially different (AC1):
//! one mutates files inside a [`crate::staging::StagedWorktree`] copy, the
//! other applies SQL against a throwaway, file-backed SQLite database created
//! fresh for the run. Both share one non-negotiable property: **every
//! resource either runner touches is created inside this run's own staging
//! directory and destroyed with it** — no shared database, no real cloud
//! endpoint, no real credential, ever. A domain requiring genuine external
//! infrastructure (Terraform, a cloud API, a real deployment target) is
//! explicitly out of this PR's scope — see `docs/security/shadow-execution-scope.md`.
//!
//! # What "passing" does not mean (AC4)
//!
//! Every [`ShadowResult`] carries an [`EnvironmentFidelity`] naming exactly
//! how the shadow environment differs from production for its domain (e.g.
//! SQLite is not the production database engine). [`ShadowResult::satisfies_production_obligation`]
//! is deliberately the only way to ask "does this discharge a specific
//! production proof obligation", and it requires the caller to name the
//! obligation and returns `false` for any obligation the fidelity notes
//! don't explicitly list as covered — a passing shadow run can never
//! silently stand in for a production-specific guarantee it didn't actually
//! exercise.

pub mod db_migration;
pub mod file_mutation;

use fornax_types::experiment::{SideEffectAllowList, SideEffectClass};

use crate::policy::{is_permitted, GlobalExperimentPolicy};

/// The two domains this PR implements (AC1). A closed, explicit vocabulary —
/// adding a third domain later means adding a new variant here, not
/// inferring one from a string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ShadowDomain {
    FileMutation,
    SqliteMigration,
}

/// How a [`ShadowResult`]'s environment differs from production for its
/// domain (AC2, AC4) — always populated, never claiming perfect fidelity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentFidelity {
    pub domain: ShadowDomain,
    /// Obligation *kinds* this fidelity level can genuinely stand in for
    /// (e.g. `"file_content"`, `"schema_mechanics"`). Free text by design —
    /// this module does not attempt to model every possible obligation
    /// taxonomy a caller's contract might use.
    pub covers: Vec<String>,
    /// Explicit, human-readable list of what this shadow run does **not**
    /// prove relative to a real production execution. Never empty: a runner
    /// with nothing to disclose here would be claiming perfect fidelity,
    /// which no runner in this module has.
    pub unmodeled: Vec<String>,
}

/// The outcome vocabulary for a shadow run — deliberately its own type,
/// never conflated with [`fornax_types::experiment::ExperimentOutcome`],
/// `fornax_verify`'s `SatisfactionState`, or any other verdict vocabulary
/// already in this workspace (docs/adr/0001-architecture-invariants.md).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShadowOutcome {
    /// The proposed action's effect matched the expected outcome.
    Matched { observed: String },
    /// The proposed action's effect diverged from what was expected — a
    /// genuine, informative result, not a failure of the mechanism.
    Diverged { observed: String, expected: String },
    /// The action itself could not be completed inside the shadow
    /// environment (e.g. a real fragility — AC3).
    Failed { reason: String },
    /// Refused before any side effect ran — policy denial, a sandbox-escape
    /// attempt, or a forbidden side-effect class (AC5/AC7). Distinct from
    /// `Failed`: nothing was even attempted.
    Refused { reason: String },
    /// Cancelled before completion (AC6).
    Aborted { reason: String },
}

/// One shadow run's canonical, evidence-shaped record (AC2): what was
/// proposed, what domain/environment ran it, what happened, and exactly how
/// much production confidence that result is entitled to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowResult {
    pub proposed_action: String,
    pub fidelity: EnvironmentFidelity,
    pub outcome: ShadowOutcome,
    /// Free-text identifier for the claim/obligation this run was requested
    /// on behalf of — evidence linkage back to a `fornax-verify` contract or
    /// VoI plan, kept as an opaque string rather than a hard dependency on
    /// `fornax-verify`/`fornax-types::epistemic_contract` types so this
    /// crate's dependency graph does not grow a cycle back toward the
    /// verification layer it feeds evidence into.
    pub related_claim_ref: Option<String>,
}

impl ShadowResult {
    /// The only sanctioned way to ask whether this result discharges a
    /// specific production obligation (AC4). Only returns `true` when the
    /// outcome is [`ShadowOutcome::Matched`] *and* `obligation_kind` appears
    /// in [`EnvironmentFidelity::covers`]. Any obligation kind not
    /// explicitly covered — including one this module has simply never
    /// heard of — returns `false`, never a default `true`.
    pub fn satisfies_production_obligation(&self, obligation_kind: &str) -> bool {
        matches!(self.outcome, ShadowOutcome::Matched { .. })
            && self.fidelity.covers.iter().any(|c| c == obligation_kind)
    }
}

/// The approval gate every shadow runner in this module goes through before
/// touching anything (Scope: "approval model for shadow environments that
/// use customer data, network access or privileged credentials"). Reuses
/// [`crate::policy`]'s existing two-layer [`SideEffectClass`] gate rather
/// than inventing a parallel permission system.
pub fn shadow_run_permitted(
    spec_allow: &SideEffectAllowList,
    global: &GlobalExperimentPolicy,
    required: &[SideEffectClass],
) -> bool {
    required
        .iter()
        .all(|class| is_permitted(spec_allow, global, *class))
}

/// Parameter keys refused outright before a shadow run even provisions its
/// environment — mirrors `fornax-acquire-exec`'s
/// `STRIPPED_CREDENTIAL_ENV_VARS` discipline (named explicitly, not
/// heuristically): a proposed action's own parameters are exactly as
/// untrusted as an agent-reported command, and must never be allowed to
/// smuggle a real credential into an isolated environment this module then
/// has to protect. Case-insensitive substring match against every parameter
/// *key*, not value — deliberately conservative.
pub const FORBIDDEN_PARAMETER_KEY_SUBSTRINGS: [&str; 5] =
    ["token", "password", "secret", "api_key", "credential"];

/// `true` if any key in `params` looks credential-shaped (case-insensitive
/// substring match against [`FORBIDDEN_PARAMETER_KEY_SUBSTRINGS`]).
pub fn contains_forbidden_parameter_key(
    params: &serde_json::Map<String, serde_json::Value>,
) -> bool {
    params.keys().any(|k| {
        let lower = k.to_lowercase();
        FORBIDDEN_PARAMETER_KEY_SUBSTRINGS
            .iter()
            .any(|bad| lower.contains(bad))
    })
}

/// A network-shaped connection target refused before a shadow run ever
/// attempts to open it (AC5/AC7's network-escape negative control).
/// `:memory:` (SQLite in-process) and a bare filesystem path (no `://`) are
/// the only two shapes any runner in this module ever constructs itself;
/// both are unambiguously local. Anything else names a scheme — `file://`
/// naming a local path is still local; every other scheme (`postgres`,
/// `mysql`, `http`, `https`, ...) is refused outright regardless of what
/// host it names, since no runner in this module has a legitimate reason to
/// construct one.
pub fn is_local_only_target(target: &str) -> bool {
    if target == ":memory:" || !target.contains("://") {
        return true;
    }
    target.starts_with("file://")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_targets_are_accepted() {
        assert!(is_local_only_target(":memory:"));
        assert!(is_local_only_target("/tmp/shadow/db.sqlite3"));
        assert!(is_local_only_target("file:///tmp/shadow/db.sqlite3"));
    }

    #[test]
    fn network_shaped_targets_are_refused() {
        assert!(!is_local_only_target("postgres://real-host/db"));
        assert!(!is_local_only_target("mysql://real-host/db"));
        assert!(!is_local_only_target("https://api.example.com/hook"));
    }

    #[test]
    fn credential_shaped_parameter_keys_are_detected_case_insensitively() {
        let mut params = serde_json::Map::new();
        params.insert("GITHUB_TOKEN".to_string(), serde_json::json!("x"));
        assert!(contains_forbidden_parameter_key(&params));

        let mut clean = serde_json::Map::new();
        clean.insert("path".to_string(), serde_json::json!("a.txt"));
        assert!(!contains_forbidden_parameter_key(&clean));
    }

    #[test]
    fn satisfies_production_obligation_requires_both_matched_and_covered() {
        let fidelity = EnvironmentFidelity {
            domain: ShadowDomain::SqliteMigration,
            covers: vec!["schema_mechanics".to_string()],
            unmodeled: vec!["not the production engine".to_string()],
        };
        let matched = ShadowResult {
            proposed_action: "alter table".to_string(),
            fidelity: fidelity.clone(),
            outcome: ShadowOutcome::Matched {
                observed: "ok".to_string(),
            },
            related_claim_ref: None,
        };
        assert!(matched.satisfies_production_obligation("schema_mechanics"));
        // An obligation kind not in `covers` is never satisfied, even on a
        // Matched outcome (AC4).
        assert!(!matched.satisfies_production_obligation("production_data_volume"));

        let diverged = ShadowResult {
            outcome: ShadowOutcome::Diverged {
                observed: "x".to_string(),
                expected: "y".to_string(),
            },
            ..matched
        };
        assert!(!diverged.satisfies_production_obligation("schema_mechanics"));
    }

    #[test]
    fn shadow_run_permitted_denies_when_either_layer_denies() {
        let spec_allow = SideEffectAllowList::new([SideEffectClass::EphemeralWorktreeMutation]);
        let global = GlobalExperimentPolicy::default();
        assert!(shadow_run_permitted(
            &spec_allow,
            &global,
            &[SideEffectClass::EphemeralWorktreeMutation]
        ));
        assert!(!shadow_run_permitted(
            &spec_allow,
            &global,
            &[SideEffectClass::NetworkCall]
        ));
    }
}
