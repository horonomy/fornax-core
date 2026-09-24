//! Immutable published policy revision (FORNX-116).
//!
//! **The bytes-to-signing boundary** (a future signing ticket signs exactly
//! this): [`canonical_bytes`] is `serde_json::to_vec` on the typed
//! [`PolicyRevisionBody`], never round-tripped through `serde_json::Value`.
//! Field order is declaration order. Every collection inside
//! [`super::content::PolicyContent`] is a `BTree*` or a
//! canonicalization-enforced `Vec` — no `HashMap`/`HashSet` anywhere. The
//! digest is not inside the body, so it cannot hash itself.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::content::{
    normalize_signal_classes, ActionClass, PolicyContent, POLICY_SCHEMA_VERSION,
    SUPPORTED_POLICY_SCHEMA_VERSIONS,
};
use super::diagnostics::{
    DiagnosticCode, DiagnosticSeverity, PolicyDiagnostic, PolicyValidationReport,
};
use super::resolve::{get_field, PolicyFieldId};

/// Newtype over `Uuid` identifying one policy (a lineage of revisions).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PolicyId(pub Uuid);

/// `"sha256:<64 lowercase hex>"`. Prefixed so the algorithm is on the wire
/// and can be migrated later without ambiguity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RevisionDigest(String);

impl RevisionDigest {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RevisionDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A pointer to exactly one published revision — never the content itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRevisionRef {
    pub policy_id: PolicyId,
    pub revision: u32,
    pub digest: RevisionDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRevisionBody {
    pub schema_version: u32,
    pub policy_id: PolicyId,
    pub revision: u32,
    pub supersedes: Option<RevisionDigest>,
    /// RFC3339. Injected by the caller of `PolicyDraft::publish`, never
    /// `Utc::now()` internally, so publishing is deterministic and
    /// canonical bytes are reproducible in tests.
    pub published_at: String,
    pub display_name: String,
    pub content: PolicyContent,
    pub pinned_fields: BTreeSet<PolicyFieldId>,
}

/// `serde_json::to_vec` on the typed body — see module docs for the full
/// bytes-to-sign boundary.
pub fn canonical_bytes(body: &PolicyRevisionBody) -> Vec<u8> {
    serde_json::to_vec(body).expect("PolicyRevisionBody always serializes")
}

pub fn digest_of(body: &PolicyRevisionBody) -> RevisionDigest {
    let bytes = canonical_bytes(body);
    let hash = Sha256::digest(&bytes);
    let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    RevisionDigest(format!("sha256:{hex}"))
}

/// Wire form: `{"body": {...}, "digest": "sha256:..."}`. Not
/// `#[serde(flatten)]` — flatten destroys deterministic field ordering,
/// which is the whole point.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PolicyRevisionWire {
    body: PolicyRevisionBody,
    digest: RevisionDigest,
}

/// Immutable. Private fields; accessors only. Constructed solely via
/// [`PolicyDraft::publish`] or the validating
/// `TryFrom<PolicyRevisionWire>` (used by `#[serde(try_from = ...)]`),
/// which recomputes the digest from [`canonical_bytes`] and rejects on
/// mismatch — without this, `#[derive(Deserialize)]` alone would let a
/// hand-edited body through as if it had been validated.
///
/// No `status: RevisionStatus` field exists on the body. Mutating a status
/// to `Revoked` would change the canonical bytes and invalidate the digest
/// (and any future signature over it). `supersedes` is safe because it is
/// forward-only — a *new* revision names what it replaces. Revocation is a
/// separate record referencing a digest, out of scope here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "PolicyRevisionWire")]
pub struct PublishedPolicyRevision {
    body: PolicyRevisionBody,
    digest: RevisionDigest,
}

impl TryFrom<PolicyRevisionWire> for PublishedPolicyRevision {
    type Error = PolicyValidationReport;

    fn try_from(wire: PolicyRevisionWire) -> Result<Self, Self::Error> {
        if !SUPPORTED_POLICY_SCHEMA_VERSIONS.contains(&wire.body.schema_version) {
            return Err(PolicyValidationReport {
                diagnostics: vec![PolicyDiagnostic::new(
                    DiagnosticCode::UnsupportedSchemaVersion,
                    DiagnosticSeverity::Error,
                    format!(
                        "schema_version {} is not supported (supported: {:?})",
                        wire.body.schema_version, SUPPORTED_POLICY_SCHEMA_VERSIONS
                    ),
                    "republish using a supported schema_version, or upgrade this binary",
                )],
            });
        }

        let recomputed = digest_of(&wire.body);
        if recomputed != wire.digest {
            return Err(PolicyValidationReport {
                diagnostics: vec![PolicyDiagnostic::new(
                    DiagnosticCode::DigestMismatch,
                    DiagnosticSeverity::Error,
                    format!(
                        "recomputed digest {recomputed} does not match wire digest {}",
                        wire.digest
                    ),
                    "the revision body was modified after publishing; republish a fresh revision",
                )],
            });
        }

        Ok(Self {
            body: wire.body,
            digest: wire.digest,
        })
    }
}

impl PublishedPolicyRevision {
    pub fn body(&self) -> &PolicyRevisionBody {
        &self.body
    }

    pub fn digest(&self) -> &RevisionDigest {
        &self.digest
    }

    pub fn reference(&self) -> PolicyRevisionRef {
        PolicyRevisionRef {
            policy_id: self.body.policy_id,
            revision: self.body.revision,
            digest: self.digest.clone(),
        }
    }
}

/// Same fields as [`PolicyRevisionBody`], minus `schema_version` (stamped by
/// [`Self::publish`]).
#[derive(Debug, Clone)]
pub struct PolicyDraft {
    pub policy_id: PolicyId,
    pub revision: u32,
    pub supersedes: Option<RevisionDigest>,
    pub display_name: String,
    pub content: PolicyContent,
    pub pinned_fields: BTreeSet<PolicyFieldId>,
}

impl PolicyDraft {
    /// `published_at` is a parameter, not `Utc::now()`, so publishing is
    /// deterministic and canonical bytes are reproducible in tests.
    pub fn publish(
        mut self,
        published_at: String,
    ) -> Result<PublishedPolicyRevision, PolicyValidationReport> {
        let mut diagnostics = Vec::new();

        if self.display_name.trim().is_empty() {
            diagnostics.push(PolicyDiagnostic::new(
                DiagnosticCode::EmptyDisplayName,
                DiagnosticSeverity::Error,
                "display_name must not be empty",
                "set a non-empty, human-readable display_name",
            ));
        }

        if let Some(rules) = &self.content.enforcement.rules {
            let mut seen = BTreeSet::new();
            for r in rules {
                if !seen.insert(r.action_class.clone()) {
                    diagnostics.push(
                        PolicyDiagnostic::new(
                            DiagnosticCode::DuplicateActionClassRule,
                            DiagnosticSeverity::Error,
                            format!(
                                "action_class {:?} appears more than once in enforcement.rules",
                                r.action_class
                            ),
                            "remove the duplicate rule, or merge its outcomes into one rule per action_class",
                        )
                        .with_field(PolicyFieldId::EnforcementRules),
                    );
                }
            }
            let mut sorted: Vec<ActionClass> =
                rules.iter().map(|r| r.action_class.clone()).collect();
            sorted.sort();
            let actual: Vec<ActionClass> = rules.iter().map(|r| r.action_class.clone()).collect();
            if sorted != actual {
                diagnostics.push(
                    PolicyDiagnostic::new(
                        DiagnosticCode::UnsortedEnforcementRules,
                        DiagnosticSeverity::Error,
                        "enforcement.rules must be sorted by action_class",
                        "sort the rules list by action_class before publishing",
                    )
                    .with_field(PolicyFieldId::EnforcementRules),
                );
            }
        }

        for field in &self.pinned_fields {
            // A pin naming a field id this binary doesn't recognize (a pin
            // from a newer publisher) is never rejected here -- rejecting it
            // would make a newer revision unreadable by an older binary,
            // destroying the forward-compat story `Unrecognized` tails
            // exist for. It is ignored for flooring at resolve time (this
            // binary cannot enforce a constraint it cannot identify).
            if matches!(field, PolicyFieldId::Unrecognized(_)) {
                continue;
            }
            if get_field(&self.content, field.clone()).is_none() {
                diagnostics.push(
                    PolicyDiagnostic::new(
                        DiagnosticCode::PinNamesUnsetField,
                        DiagnosticSeverity::Error,
                        format!("{field:?} is pinned but not set by this revision's content"),
                        "either set the field's value in content, or remove it from pinned_fields",
                    )
                    .with_field(field.clone()),
                );
            }
        }

        if diagnostics
            .iter()
            .any(|d| d.severity == DiagnosticSeverity::Error)
        {
            return Err(PolicyValidationReport { diagnostics });
        }

        // Canonicalize the two SignalClass-keyed collections so
        // semantically-equal content always produces identical canonical
        // bytes (SignalClass has no Ord -- see
        // content::SensorScope::required_signals doc).
        if let Some(signals) = &mut self.content.sensors.required_signals {
            normalize_signal_classes(signals);
        }
        if let Some(rules) = &mut self.content.enforcement.rules {
            rules.sort_by(|a, b| a.action_class.cmp(&b.action_class));
        }

        let body = PolicyRevisionBody {
            schema_version: POLICY_SCHEMA_VERSION,
            policy_id: self.policy_id,
            revision: self.revision,
            supersedes: self.supersedes,
            published_at,
            display_name: self.display_name,
            content: self.content,
            pinned_fields: self.pinned_fields,
        };

        let digest = digest_of(&body);

        if let Some(supersedes) = &body.supersedes {
            if supersedes == &digest {
                return Err(PolicyValidationReport {
                    diagnostics: vec![PolicyDiagnostic::new(
                        DiagnosticCode::SupersedesSelf,
                        DiagnosticSeverity::Error,
                        "supersedes must not name this revision's own digest",
                        "point supersedes at the actual prior revision, or leave it unset for the first revision",
                    )],
                });
            }
        }

        Ok(PublishedPolicyRevision { body, digest })
    }
}
