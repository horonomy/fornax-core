//! Policy diagnostics (FORNX-116).
//!
//! Two different jobs, two different signatures — do not merge them.
//! `PolicyDraft::publish`, `BoundRevision::new`, and
//! `TryFrom<PolicyRevisionWire>` return `Result<_, PolicyValidationReport>`:
//! any Error-severity diagnostic means the whole operation failed.
//! `resolve()` returns `(ResolvedPolicy, Vec<PolicyDiagnostic>)` and never
//! `Err` — see `super::resolve`'s module docs (D2).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::resolve::PolicyFieldId;
use super::revision::PolicyRevisionRef;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    Error,
    Warning,
    Info,
}

/// Stable snake_case wire name for FORNX-117's authoring UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticCode {
    // -- publish/validate time -> Err -----------------------------------
    UnsupportedSchemaVersion,
    DigestMismatch,
    DuplicateActionClassRule,
    UnsortedEnforcementRules,
    PinAtLocalUserLayer,
    PinNamesUnsetField,
    EmptyDisplayName,
    SupersedesSelf,
    /// Reserved for a future check once a revision *history* exists to
    /// compare against (no `fornax-store` migration in this ticket — see
    /// `docs/adr/0006-policy-as-data.md`). Not emitted by anything in this
    /// crate yet.
    RevisionNotMonotonic,
    // -- resolve time -> diagnostics only, never Err ---------------------
    ConflictingBindingsAtLevel,
    PinViolation,
    SelectorNotUnderstood,
    RequiredSignalUnavailable,
    UnrecognizedEnvValue,
    NoApplicablePolicy,
    // -- FORNX-119 local policy cache -- additive only. This enum is
    // closed (no `Unrecognized` tail), so a cross-repo consumer (e.g.
    // fornax-cloud's authoring UI) built against a prior version of this
    // enum must be updated to handle these new variants; see
    // docs/adr/0008-local-policy-cache-and-activation.md.
    PolicyCacheStale,
    PolicyCacheExpired,
    PolicyCacheUnverifiable,
    PolicyCacheUnavailable,
    PolicyRollbackRejected,
    PolicyIssuerMismatch,
    TrustStoreUnavailable,
    // -- FORNX-123 policy revocation -- additive only, same closed-enum
    // caveat as the FORNX-119 block above: a cross-repo consumer built
    // against a prior version of this enum must be updated to handle these.
    /// A cached generation's member(s) were found on the local revocation
    /// list -- Error severity, since a revoked-but-still-cryptographically-
    /// valid bundle being unusable is the entire point of this ticket, not
    /// a mere warning.
    PolicyCacheRevoked,
    /// A revocation list entry named a `target_kind` this binary does not
    /// recognize -- forward-compat, never fatal to parsing the rest of the
    /// list. See `RevocationTarget::Unrecognized`.
    PolicyRevocationEntryNotUnderstood,
    /// A submitted revocation list was rejected (e.g. sequence did not
    /// advance) -- mirrors `PolicyRollbackRejected`'s severity choice.
    PolicyRevocationRejected,
    // -- FORNX-311 background policy poll transport -- additive only, same
    // closed-enum caveat as the two blocks above.
    /// The background policy poll task (`fornax-daemon::policy_poll`) has
    /// failed 3 or more consecutive cycles -- a silently-dead poller would
    /// otherwise only be visible in the in-memory `last_poll` field, which
    /// nothing surfaces proactively. Warning severity: the cache itself may
    /// still be perfectly usable via its existing staleness floors: this is
    /// an early warning that refresh has stalled, not a claim that
    /// enforcement is currently degraded.
    PolicyRefreshUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDiagnostic {
    pub code: DiagnosticCode,
    pub severity: DiagnosticSeverity,
    pub field: Option<PolicyFieldId>,
    pub bindings: Vec<Uuid>,
    pub revisions: Vec<PolicyRevisionRef>,
    /// What is wrong. Never empty.
    pub message: String,
    /// What to change. Never empty.
    pub remediation: String,
}

impl PolicyDiagnostic {
    pub fn new(
        code: DiagnosticCode,
        severity: DiagnosticSeverity,
        message: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self {
            code,
            severity,
            field: None,
            bindings: Vec::new(),
            revisions: Vec::new(),
            message: message.into(),
            remediation: remediation.into(),
        }
    }

    pub fn with_field(mut self, field: PolicyFieldId) -> Self {
        self.field = Some(field);
        self
    }

    pub fn with_bindings(mut self, bindings: Vec<Uuid>) -> Self {
        self.bindings = bindings;
        self
    }

    pub fn with_revisions(mut self, revisions: Vec<PolicyRevisionRef>) -> Self {
        self.revisions = revisions;
        self
    }
}

/// Returned by `PolicyDraft::publish`, `BoundRevision::new`, and
/// `TryFrom<PolicyRevisionWire>` when at least one Error-severity
/// [`PolicyDiagnostic`] was produced.
#[derive(Debug, Clone, thiserror::Error)]
#[error("policy validation failed with {} diagnostic(s)", diagnostics.len())]
pub struct PolicyValidationReport {
    pub diagnostics: Vec<PolicyDiagnostic>,
}

impl PolicyValidationReport {
    pub fn has_errors(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|d| d.severity == DiagnosticSeverity::Error)
    }
}
