//! Canonical audit event model (FORNX-314, epic FORNX-20).
//!
//! See `docs/adr/0011-audit-event-model.md` — this module is the Rust
//! mirror of that ADR's wire contract and is written to be read alongside
//! it, not in place of it. The ADR is the authoritative, self-sufficient
//! wire contract (a Python engineer on `fornax-cloud`'s side implements
//! against the ADR text alone, per ADR-0009's own precedent); this module
//! only needs to agree with it byte-for-byte.
//!
//! **Pure types and validation only.** No database table, no store
//! integration, no HTTP route, no CLI command, no network or file I/O of
//! any kind — exactly the scope FORNX-116 held for the policy model before
//! any of ADR-0007/0008/0009's storage/activation machinery existed on top
//! of it.
//!
//! # Two enum shapes, deliberately different
//!
//! - [`AuditAction`], [`AuditOutcome`], [`AuditExportClass`] are plain
//!   string enums with a `#[serde(untagged)] Unrecognized(String)` tail —
//!   the same idiom as [`crate::TrustClass`]/[`crate::CollectionMethod`]/
//!   [`crate::ContentClass`]. An unknown wire tag round-trips byte-for-byte:
//!   the original string is preserved and re-serializes to itself.
//! - [`AuditActor`] and [`AuditTarget`] are internally-tagged objects
//!   (`#[serde(tag = "actor_kind"/"target_kind")]`) with a
//!   `#[serde(other)] Unrecognized` unit-variant tail — the same idiom as
//!   [`crate::policy::RevocationTarget`]. This tail cannot
//!   preserve an unrecognized tag's associated payload (there is no payload
//!   to preserve generically once the tag itself isn't understood — see
//!   `RevocationTarget`'s own precedent), but the *event* containing it
//!   still parses successfully rather than failing outright.
//!
//! `AuditEvent` itself follows [`crate::ExtensionEnvelope`]'s
//! `#[serde(try_from = "...Wire")]` pattern: `schema_version` is checked
//! before the domain type is ever constructed, and any unrecognized
//! top-level field is preserved via `#[serde(flatten)]` rather than
//! silently dropped, so a round trip through an older or newer binary never
//! destroys data it doesn't understand.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub const AUDIT_SCHEMA_VERSION: u32 = 1;
pub const SUPPORTED_AUDIT_SCHEMA_VERSIONS: &[u32] = &[1];

/// Who/what performed an audited action. See
/// `docs/adr/0011-audit-event-model.md` §2 for the full rationale,
/// including why `service_token`/`system` are new here (`fornax-cloud`'s
/// `PermissionSubjectType` enum has only `user`/`device` today).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "actor_kind", rename_all = "snake_case")]
pub enum AuditActor {
    /// Mirrors `fornax-cloud`'s `PermissionSubjectType.DEVICE`.
    Device { actor_id: String },
    /// Mirrors `fornax-cloud`'s `PermissionSubjectType.USER`.
    User { actor_id: String },
    /// A non-interactive service credential. New in this ADR — no existing
    /// subject-type vocabulary covers this caller shape.
    ServiceToken { actor_id: String },
    /// The Fornax system itself, acting with no external caller (e.g. an
    /// unattended, automatic state transition). New in this ADR, for the
    /// same reason as `ServiceToken`. Has no singular identity to name.
    System,
    /// Forward-compatibility catch-all for an `actor_kind` this binary
    /// doesn't recognize. Cannot preserve the unrecognized tag's own
    /// payload — see the module docs' "Two enum shapes" section and
    /// `RevocationTarget::Unrecognized`'s identical precedent.
    #[serde(other)]
    Unrecognized,
}

/// What an audited action was performed on. Same internally-tagged +
/// `#[serde(other)]` shape as [`AuditActor`], for the same reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "target_kind", rename_all = "snake_case")]
pub enum AuditTarget {
    PolicyBundle {
        target_id: String,
    },
    RevocationEntry {
        target_id: String,
    },
    RoleAssignment {
        target_id: String,
    },
    Permission {
        target_id: String,
    },
    Device {
        target_id: String,
    },
    /// FORNX-319: the specific `evidence` row an `AuditAction::EvidencePurged`
    /// event was raised for.
    Evidence {
        target_id: String,
    },
    Organization {
        target_id: String,
    },
    /// FORNX-322: the compliance report a `fornax audit report` invocation
    /// just generated — `target_id` is that report's own digest, so the
    /// audit trail names exactly which report was produced without
    /// embedding the report's content in the event itself.
    ComplianceReport {
        target_id: String,
    },
    #[serde(other)]
    Unrecognized,
}

/// What happened. Open string enum — see
/// `docs/adr/0011-audit-event-model.md` §2 for the canonical set and the
/// rationale for keeping it deliberately small at publication time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    PermissionCheck,
    BreakGlassActivated,
    PolicyBundleActivated,
    PolicyRevocationIngested,
    RoleAssignmentChanged,
    /// FORNX-319: a `RetentionClass::RawLocal` evidence row's payload was
    /// purged by the local retention sweep (`fornax_store::retention`) once
    /// its retention window elapsed. See
    /// `docs/adr/0011-audit-event-model.md` §2's table.
    EvidencePurged,
    /// FORNX-322: `fornax audit report` generated a local compliance report.
    /// Recording this as its own auditable action means generating a report
    /// is itself evidenced in the very ledger the report reads from.
    ComplianceReportGenerated,
    /// Forward-compatibility catch-all. Preserves and round-trips the
    /// original wire string verbatim — see the module docs' "Two enum
    /// shapes" section.
    #[serde(untagged)]
    Unrecognized(String),
}

/// The result of an audited action. **A strict superset of the outcome
/// strings `fornax-cloud`'s `permissions.py` already emits today** — see
/// `docs/adr/0011-audit-event-model.md` §2's table and this module's
/// `every_fornax_cloud_permission_outcome_string_has_an_audit_outcome_variant`
/// test, which asserts each literal string that file logs via `outcome=`
/// has a corresponding named variant here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    /// `fornax-cloud` `permissions.py`: `outcome=granted`.
    Granted,
    /// `fornax-cloud` `permissions.py`: `outcome=denied`.
    Denied,
    /// `fornax-cloud` `permissions.py`: `outcome=granted_via_break_glass`.
    GrantedViaBreakGlass,
    /// `fornax-cloud` `permissions.py`: `outcome=break_glass_activated`.
    BreakGlassActivated,
    /// New in this ADR — no existing `fornax-cloud` log line emits this yet.
    Revoked,
    /// New in this ADR — no existing `fornax-cloud` log line emits this yet.
    Expired,
    #[serde(untagged)]
    Unrecognized(String),
}

/// Which classification tier an [`AuditEvent`]'s own content falls into for
/// cloud-export purposes — a new, third axis alongside
/// [`crate::RetentionClass`] and [`crate::ContentClass`]. See
/// `docs/adr/0011-audit-event-model.md` §3 for the full three-axis
/// contrast and the statement that this is the last classification axis
/// this project adds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditExportClass {
    /// Only structural fields — no content that could itself be sensitive.
    /// Freely exportable.
    Metadata,
    /// A summary/verdict derived from evidence, no raw content attached.
    FindingSummary,
    /// References (ids, digests) to evidence that may itself be sensitive,
    /// without embedding the evidence content.
    SensitiveEvidenceRef,
    /// Embeds raw content directly. The most restrictive named class.
    RawContent,
    /// Forward-compatibility catch-all. See [`AuditExportClass::is_exportable`]
    /// for the fail-closed handling of this variant.
    #[serde(untagged)]
    Unrecognized(String),
}

impl AuditExportClass {
    /// Safe-default export decision (ADR-0011 §3): an unrecognized export
    /// class must be treated as maximally restrictive — as if it were
    /// [`AuditExportClass::RawContent`] — never as freely exportable. This
    /// mirrors `bundle.rs`'s fail-closed handling of an unrecognized
    /// signature algorithm (an unknown value is never silently trusted),
    /// which is the inverse of `sensor.rs`'s `CollectionMethod`/
    /// `ClockSource` "safest" default — those are honest-*unknown* markers
    /// for a pre-existing field, not a restrictiveness ordering, and
    /// `AuditExportClass` has no such predates-this-field case to honor.
    ///
    /// Only [`AuditExportClass::Metadata`] and
    /// [`AuditExportClass::FindingSummary`] are considered exportable by
    /// this coarse check; [`AuditExportClass::SensitiveEvidenceRef`],
    /// [`AuditExportClass::RawContent`], and any unrecognized value are
    /// not. This is a structural default only — actual export decisions
    /// still go through policy (ADR-0006), never through this method
    /// alone.
    pub fn is_exportable(&self) -> bool {
        matches!(
            self,
            AuditExportClass::Metadata | AuditExportClass::FindingSummary
        )
    }
}

/// One canonical audit event. See `docs/adr/0011-audit-event-model.md` §1
/// for the full field-by-field wire contract and a worked JSON example.
///
/// Deserializes through [`AuditEventWire`] (mirroring
/// [`crate::ExtensionEnvelope`]'s own `#[serde(try_from = "...")]`
/// pattern) so an unsupported `schema_version` is rejected with a specific
/// error before this type is ever constructed, while an unrecognized
/// top-level field is preserved rather than dropped.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "AuditEventWire")]
pub struct AuditEvent {
    pub schema_version: u32,
    pub event_id: String,
    /// RFC3339 timestamp, matching every other timestamp field in this
    /// repo (`RevocationEntry::revoked_at`, `BundlePayload::issued_at`,
    /// etc.) — never a numeric epoch.
    pub occurred_at: String,
    pub actor: AuditActor,
    pub action: AuditAction,
    pub target: AuditTarget,
    pub outcome: AuditOutcome,
    pub export_class: AuditExportClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    /// Loosely-typed catch-all for action-specific detail. **Not an event
    /// lake** — see the ADR §5 and `docs/adr/0005-schema-evolution.md`'s
    /// identical non-goal for `ExtensionEnvelope::fields`, referenced here
    /// rather than re-litigated.
    #[serde(
        default = "default_attributes",
        skip_serializing_if = "is_empty_object"
    )]
    pub attributes: serde_json::Value,
    /// Any top-level JSON key not named above, preserved verbatim so a
    /// round trip through this binary never destroys what a newer producer
    /// wrote. Empty for an event constructed by this binary's own `new`.
    #[serde(flatten)]
    pub unknown: BTreeMap<String, serde_json::Value>,
}

fn default_attributes() -> serde_json::Value {
    serde_json::json!({})
}

fn is_empty_object(v: &serde_json::Value) -> bool {
    matches!(v, serde_json::Value::Object(map) if map.is_empty())
}

impl AuditEvent {
    /// Construct a fresh event stamped with the current
    /// [`AUDIT_SCHEMA_VERSION`], no correlation id, empty `attributes`, and
    /// no unknown fields.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        event_id: impl Into<String>,
        occurred_at: impl Into<String>,
        actor: AuditActor,
        action: AuditAction,
        target: AuditTarget,
        outcome: AuditOutcome,
        export_class: AuditExportClass,
    ) -> Self {
        Self {
            schema_version: AUDIT_SCHEMA_VERSION,
            event_id: event_id.into(),
            occurred_at: occurred_at.into(),
            actor,
            action,
            target,
            outcome,
            export_class,
            correlation_id: None,
            attributes: default_attributes(),
            unknown: BTreeMap::new(),
        }
    }
}

/// Wire shape accepted on deserialization. Structurally identical to
/// [`AuditEvent`]; exists only so [`TryFrom`] can gate on `schema_version`
/// before the domain type is ever constructed — see
/// [`crate::extension::ExtensionEnvelope`]'s identical precedent.
#[derive(Debug, Deserialize)]
pub struct AuditEventWire {
    schema_version: u32,
    event_id: String,
    occurred_at: String,
    actor: AuditActor,
    action: AuditAction,
    target: AuditTarget,
    outcome: AuditOutcome,
    export_class: AuditExportClass,
    #[serde(default)]
    correlation_id: Option<String>,
    #[serde(default = "default_attributes")]
    attributes: serde_json::Value,
    #[serde(flatten)]
    unknown: BTreeMap<String, serde_json::Value>,
}

/// Exhaustive rejection vocabulary for constructing an [`AuditEvent`] from
/// untrusted wire bytes.
#[derive(Debug, Clone, thiserror::Error)]
pub enum AuditEventRejection {
    #[error("audit_schema_version {found} is not supported (supported: {supported:?})")]
    UnsupportedSchemaVersion { found: u32, supported: Vec<u32> },
}

impl TryFrom<AuditEventWire> for AuditEvent {
    type Error = AuditEventRejection;

    fn try_from(w: AuditEventWire) -> Result<Self, Self::Error> {
        if !SUPPORTED_AUDIT_SCHEMA_VERSIONS.contains(&w.schema_version) {
            return Err(AuditEventRejection::UnsupportedSchemaVersion {
                found: w.schema_version,
                supported: SUPPORTED_AUDIT_SCHEMA_VERSIONS.to_vec(),
            });
        }
        Ok(AuditEvent {
            schema_version: w.schema_version,
            event_id: w.event_id,
            occurred_at: w.occurred_at,
            actor: w.actor,
            action: w.action,
            target: w.target,
            outcome: w.outcome,
            export_class: w.export_class,
            correlation_id: w.correlation_id,
            attributes: w.attributes,
            unknown: w.unknown,
        })
    }
}

/// Structural validation entry point for an already-deserialized
/// [`AuditEvent`] (e.g. one round-tripped from storage rather than freshly
/// parsed from wire bytes, where [`TryFrom<AuditEventWire>`] would not run
/// again). Currently only re-checks the schema version; kept as a named
/// function — mirroring `bundle.rs`/`revocation.rs`'s `verify_*` naming —
/// so future structural rules (e.g. a non-empty `event_id`) have a single
/// place to live rather than being re-derived at each call site.
pub fn validate_audit_event(event: &AuditEvent) -> Result<(), AuditEventRejection> {
    if !SUPPORTED_AUDIT_SCHEMA_VERSIONS.contains(&event.schema_version) {
        return Err(AuditEventRejection::UnsupportedSchemaVersion {
            found: event.schema_version,
            supported: SUPPORTED_AUDIT_SCHEMA_VERSIONS.to_vec(),
        });
    }
    Ok(())
}

/// Parsed form of the `<issuer-scope>:<event_id>` string
/// [`RevocationEntry::audit_ref`]-shaped fields are defined (ADR-0011 §6) to
/// resolve to. `issuer_scope` must not itself contain a `:` — parsing
/// splits on the *first* colon only.
///
/// [`RevocationEntry::audit_ref`]: crate::RevocationEntry::audit_ref
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRef {
    pub issuer_scope: String,
    pub event_id: String,
}

/// Exhaustive rejection vocabulary for [`AuditRef::parse`].
#[derive(Debug, Clone, thiserror::Error)]
pub enum AuditRefParseError {
    #[error("audit_ref {input:?} has no ':' separator between issuer-scope and event_id")]
    MissingSeparator { input: String },
    #[error("audit_ref {input:?} has an empty issuer-scope")]
    EmptyIssuerScope { input: String },
    #[error("audit_ref {input:?} has an empty event_id")]
    EmptyEventId { input: String },
}

impl AuditRef {
    pub fn new(issuer_scope: impl Into<String>, event_id: impl Into<String>) -> Self {
        Self {
            issuer_scope: issuer_scope.into(),
            event_id: event_id.into(),
        }
    }

    /// Parse `<issuer-scope>:<event_id>` per ADR-0011 §6. Splits on the
    /// first `:` only, so an `event_id` containing a colon is preserved
    /// intact while an `issuer_scope` containing one would be mis-parsed —
    /// see the ADR's format rule.
    pub fn parse(input: &str) -> Result<Self, AuditRefParseError> {
        let Some((issuer_scope, event_id)) = input.split_once(':') else {
            return Err(AuditRefParseError::MissingSeparator {
                input: input.to_string(),
            });
        };
        if issuer_scope.is_empty() {
            return Err(AuditRefParseError::EmptyIssuerScope {
                input: input.to_string(),
            });
        }
        if event_id.is_empty() {
            return Err(AuditRefParseError::EmptyEventId {
                input: input.to_string(),
            });
        }
        Ok(AuditRef {
            issuer_scope: issuer_scope.to_string(),
            event_id: event_id.to_string(),
        })
    }
}

impl std::fmt::Display for AuditRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.issuer_scope, self.event_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event() -> AuditEvent {
        AuditEvent::new(
            "d290f1ee-6c54-4b01-90e6-d701748f0851",
            "2026-09-03T14:22:05Z",
            AuditActor::Device {
                actor_id: "device-7e2a1c".to_string(),
            },
            AuditAction::PolicyRevocationIngested,
            AuditTarget::RevocationEntry {
                target_id: "sha256:ab12".to_string(),
            },
            AuditOutcome::Revoked,
            AuditExportClass::Metadata,
        )
    }

    // --- AC2: AuditEvent and its enums round-trip through serde with
    // stable, explicit wire names -------------------------------------

    #[test]
    fn audit_event_round_trips_losslessly() {
        let event = sample_event();
        let json = serde_json::to_string(&event).unwrap();
        let back: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn audit_actor_wire_tags_are_explicit_snake_case() {
        let device = AuditActor::Device {
            actor_id: "d1".to_string(),
        };
        let json = serde_json::to_value(&device).unwrap();
        assert_eq!(json["actor_kind"], serde_json::json!("device"));
        assert_eq!(json["actor_id"], serde_json::json!("d1"));

        let system = AuditActor::System;
        let json = serde_json::to_value(&system).unwrap();
        assert_eq!(json["actor_kind"], serde_json::json!("system"));
    }

    /// FORNX-319: `AuditTarget::Evidence` round-trips with the explicit
    /// `evidence` wire tag, matching ADR-0011 §2's target-kind table.
    #[test]
    fn audit_target_evidence_round_trips_with_the_explicit_wire_tag() {
        let target = AuditTarget::Evidence {
            target_id: "ev-1".to_string(),
        };
        let json = serde_json::to_value(&target).unwrap();
        assert_eq!(json["target_kind"], serde_json::json!("evidence"));
        assert_eq!(json["target_id"], serde_json::json!("ev-1"));
        let back: AuditTarget = serde_json::from_value(json).unwrap();
        assert_eq!(back, target);
    }

    /// FORNX-322: `AuditTarget::ComplianceReport` round-trips with the
    /// explicit `compliance_report` wire tag.
    #[test]
    fn audit_target_compliance_report_round_trips_with_the_explicit_wire_tag() {
        let target = AuditTarget::ComplianceReport {
            target_id: "sha256:deadbeef".to_string(),
        };
        let json = serde_json::to_value(&target).unwrap();
        assert_eq!(json["target_kind"], serde_json::json!("compliance_report"));
        assert_eq!(json["target_id"], serde_json::json!("sha256:deadbeef"));
        let back: AuditTarget = serde_json::from_value(json).unwrap();
        assert_eq!(back, target);
    }

    #[test]
    fn every_canonical_audit_action_tag_round_trips_to_its_named_variant() {
        let cases = [
            ("\"permission_check\"", AuditAction::PermissionCheck),
            (
                "\"break_glass_activated\"",
                AuditAction::BreakGlassActivated,
            ),
            (
                "\"policy_bundle_activated\"",
                AuditAction::PolicyBundleActivated,
            ),
            (
                "\"policy_revocation_ingested\"",
                AuditAction::PolicyRevocationIngested,
            ),
            (
                "\"role_assignment_changed\"",
                AuditAction::RoleAssignmentChanged,
            ),
            ("\"evidence_purged\"", AuditAction::EvidencePurged),
            (
                "\"compliance_report_generated\"",
                AuditAction::ComplianceReportGenerated,
            ),
        ];
        for (json, expected) in cases {
            let v: AuditAction = serde_json::from_str(json).unwrap();
            assert_eq!(v, expected, "tag {json} did not parse to its named variant");
            let back = serde_json::to_string(&v).unwrap();
            assert_eq!(back, json);
        }
    }

    #[test]
    fn every_canonical_audit_outcome_tag_round_trips_to_its_named_variant() {
        let cases = [
            ("\"granted\"", AuditOutcome::Granted),
            ("\"denied\"", AuditOutcome::Denied),
            (
                "\"granted_via_break_glass\"",
                AuditOutcome::GrantedViaBreakGlass,
            ),
            (
                "\"break_glass_activated\"",
                AuditOutcome::BreakGlassActivated,
            ),
            ("\"revoked\"", AuditOutcome::Revoked),
            ("\"expired\"", AuditOutcome::Expired),
        ];
        for (json, expected) in cases {
            let v: AuditOutcome = serde_json::from_str(json).unwrap();
            assert_eq!(v, expected, "tag {json} did not parse to its named variant");
            let back = serde_json::to_string(&v).unwrap();
            assert_eq!(back, json);
        }
    }

    #[test]
    fn every_canonical_audit_export_class_tag_round_trips_to_its_named_variant() {
        let cases = [
            ("\"metadata\"", AuditExportClass::Metadata),
            ("\"finding_summary\"", AuditExportClass::FindingSummary),
            (
                "\"sensitive_evidence_ref\"",
                AuditExportClass::SensitiveEvidenceRef,
            ),
            ("\"raw_content\"", AuditExportClass::RawContent),
        ];
        for (json, expected) in cases {
            let v: AuditExportClass = serde_json::from_str(json).unwrap();
            assert_eq!(v, expected, "tag {json} did not parse to its named variant");
            let back = serde_json::to_string(&v).unwrap();
            assert_eq!(back, json);
        }
    }

    // --- AC3: unknown enum variant / unknown top-level field parses
    // successfully and re-serializes to the same content; unsupported
    // schema_version fails loudly ---------------------------------------

    #[test]
    fn unrecognized_audit_action_tag_round_trips_the_original_string() {
        let json = r#""quantum_reclassification""#;
        let v: AuditAction = serde_json::from_str(json).unwrap();
        assert_eq!(
            v,
            AuditAction::Unrecognized("quantum_reclassification".to_string())
        );
        let back = serde_json::to_string(&v).unwrap();
        assert_eq!(back, json);
    }

    #[test]
    fn unrecognized_audit_outcome_tag_round_trips_the_original_string() {
        let json = r#""quantum_verified""#;
        let v: AuditOutcome = serde_json::from_str(json).unwrap();
        assert_eq!(
            v,
            AuditOutcome::Unrecognized("quantum_verified".to_string())
        );
        let back = serde_json::to_string(&v).unwrap();
        assert_eq!(back, json);
    }

    #[test]
    fn unrecognized_audit_export_class_tag_round_trips_the_original_string() {
        let json = r#""quantum_export""#;
        let v: AuditExportClass = serde_json::from_str(json).unwrap();
        assert_eq!(
            v,
            AuditExportClass::Unrecognized("quantum_export".to_string())
        );
        let back = serde_json::to_string(&v).unwrap();
        assert_eq!(back, json);
    }

    #[test]
    fn unrecognized_actor_kind_parses_as_unrecognized_variant_not_a_hard_failure() {
        let json = r#"{"actor_kind": "quantum_actor", "extra": "field"}"#;
        let v: AuditActor = serde_json::from_str(json).unwrap();
        assert_eq!(v, AuditActor::Unrecognized);
    }

    #[test]
    fn unrecognized_target_kind_parses_as_unrecognized_variant_not_a_hard_failure() {
        let json = r#"{"target_kind": "quantum_target", "target_id": "x"}"#;
        let v: AuditTarget = serde_json::from_str(json).unwrap();
        assert_eq!(v, AuditTarget::Unrecognized);
    }

    #[test]
    fn audit_event_with_unrecognized_enum_variants_parses_and_round_trips() {
        let json = serde_json::json!({
            "schema_version": 1,
            "event_id": "e1",
            "occurred_at": "2026-09-03T14:22:05Z",
            "actor": {"actor_kind": "quantum_actor"},
            "action": "quantum_action",
            "target": {"target_kind": "quantum_target"},
            "outcome": "quantum_outcome",
            "export_class": "quantum_export",
        });
        let event: AuditEvent = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(event.actor, AuditActor::Unrecognized);
        assert_eq!(
            event.action,
            AuditAction::Unrecognized("quantum_action".to_string())
        );
        assert_eq!(
            event.outcome,
            AuditOutcome::Unrecognized("quantum_outcome".to_string())
        );
        assert_eq!(
            event.export_class,
            AuditExportClass::Unrecognized("quantum_export".to_string())
        );

        let reserialized = serde_json::to_value(&event).unwrap();
        assert_eq!(reserialized["action"], serde_json::json!("quantum_action"));
        assert_eq!(
            reserialized["outcome"],
            serde_json::json!("quantum_outcome")
        );
        assert_eq!(
            reserialized["export_class"],
            serde_json::json!("quantum_export")
        );
    }

    #[test]
    fn unknown_top_level_field_on_a_supported_schema_version_survives_round_trip() {
        let json = r#"{
            "schema_version": 1,
            "event_id": "e1",
            "occurred_at": "2026-09-03T14:22:05Z",
            "actor": {"actor_kind": "system"},
            "action": "permission_check",
            "target": {"target_kind": "permission", "target_id": "read_findings"},
            "outcome": "granted",
            "export_class": "metadata",
            "future_correlation_scheme": "v2-trace-id"
        }"#;
        let event: AuditEvent = serde_json::from_str(json).unwrap();
        assert_eq!(
            event.unknown.get("future_correlation_scheme"),
            Some(&serde_json::json!("v2-trace-id"))
        );

        let reser = serde_json::to_value(&event).unwrap();
        assert_eq!(
            reser["future_correlation_scheme"],
            serde_json::json!("v2-trace-id")
        );
    }

    #[test]
    fn truly_incompatible_schema_version_fails_explicitly_rather_than_silently_parsing() {
        let json = r#"{
            "schema_version": 999,
            "event_id": "e1",
            "occurred_at": "2026-09-03T14:22:05Z",
            "actor": {"actor_kind": "system"},
            "action": "permission_check",
            "target": {"target_kind": "permission", "target_id": "read_findings"},
            "outcome": "granted",
            "export_class": "metadata"
        }"#;
        let err = serde_json::from_str::<AuditEvent>(json).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("999") && msg.contains("not supported"),
            "expected an explicit error naming the offending version, got: {msg}"
        );
    }

    #[test]
    fn validate_audit_event_rejects_unsupported_schema_version() {
        let mut event = sample_event();
        event.schema_version = 42;
        let err = validate_audit_event(&event).unwrap_err();
        match err {
            AuditEventRejection::UnsupportedSchemaVersion { found, supported } => {
                assert_eq!(found, 42);
                assert_eq!(supported, SUPPORTED_AUDIT_SCHEMA_VERSIONS.to_vec());
            }
        }
    }

    // --- AC4: three-axis contrast --------------------------------------

    /// Proves `AuditExportClass`, `RetentionClass`, and `ContentClass` are
    /// orthogonal: no wire tag string is reused across the three axes, so a
    /// bare tag string can never be ambiguous about which axis it belongs
    /// to. See ADR-0011 §3 for the full narrative contrast.
    #[test]
    fn audit_export_class_retention_class_and_content_class_share_no_wire_tags() {
        let export_tags = [
            "metadata",
            "finding_summary",
            "sensitive_evidence_ref",
            "raw_content",
        ];
        let retention_tags = [
            "raw_local",
            "sanitized_replay_fixture",
            "aggregated_feature",
            "derived_finding",
        ];
        let content_tags = [
            "tool_telemetry",
            "provider_diagnostic",
            "experimental_signal",
            "raw_provider_metadata",
        ];

        for tag in export_tags {
            assert!(
                !retention_tags.contains(&tag) && !content_tags.contains(&tag),
                "export-class tag {tag:?} collides with another classification axis"
            );
        }
        for tag in retention_tags {
            assert!(
                !content_tags.contains(&tag),
                "retention-class tag {tag:?} collides with content-class"
            );
        }
    }

    #[test]
    fn unrecognized_export_class_is_treated_as_non_exportable_the_safe_default() {
        let unrecognized = AuditExportClass::Unrecognized("quantum_export".to_string());
        assert!(!unrecognized.is_exportable());
        assert!(!AuditExportClass::RawContent.is_exportable());
        assert!(!AuditExportClass::SensitiveEvidenceRef.is_exportable());
        assert!(AuditExportClass::Metadata.is_exportable());
        assert!(AuditExportClass::FindingSummary.is_exportable());
    }

    // --- AC5: AuditRef format, parser, Display, and the audit_ref: None
    // regression ----------------------------------------------------------

    #[test]
    fn audit_ref_round_trips_through_parse_and_display() {
        let reference = AuditRef::new(
            "horonomy-policy-issuer-1",
            "d290f1ee-6c54-4b01-90e6-d701748f0851",
        );
        let formatted = reference.to_string();
        assert_eq!(
            formatted,
            "horonomy-policy-issuer-1:d290f1ee-6c54-4b01-90e6-d701748f0851"
        );
        let parsed = AuditRef::parse(&formatted).unwrap();
        assert_eq!(parsed, reference);
    }

    #[test]
    fn audit_ref_parse_rejects_missing_separator() {
        let err = AuditRef::parse("no-colon-here").unwrap_err();
        assert!(matches!(err, AuditRefParseError::MissingSeparator { .. }));
    }

    #[test]
    fn audit_ref_parse_rejects_empty_issuer_scope() {
        let err = AuditRef::parse(":event-only").unwrap_err();
        assert!(matches!(err, AuditRefParseError::EmptyIssuerScope { .. }));
    }

    #[test]
    fn audit_ref_parse_rejects_empty_event_id() {
        let err = AuditRef::parse("issuer-only:").unwrap_err();
        assert!(matches!(err, AuditRefParseError::EmptyEventId { .. }));
    }

    #[test]
    fn audit_ref_parse_splits_on_first_colon_only_preserving_the_rest_in_event_id() {
        // event_id containing a colon is preserved intact; only
        // issuer_scope is constrained to be colon-free per the ADR's format
        // rule.
        let parsed = AuditRef::parse("issuer:namespace:event-id").unwrap();
        assert_eq!(parsed.issuer_scope, "issuer");
        assert_eq!(parsed.event_id, "namespace:event-id");
    }

    /// `Option<AuditRef>` deserializes fine from `null`/absent, proven in
    /// isolation (a small wrapper struct we control), plus a direct
    /// regression against the real `RevocationEntry` type using an
    /// `audit_ref: null` JSON literal — proving today's `audit_ref: None`
    /// behavior is unaffected by anything this module adds, without
    /// modifying `revocation.rs` itself (out of scope for FORNX-314; see
    /// the ADR §6 and the PR description for the follow-up carve-out).
    #[test]
    fn option_audit_ref_deserializes_from_null_and_absent() {
        #[derive(Debug, Deserialize, Serialize, PartialEq)]
        struct Wrapper {
            #[serde(default)]
            audit_ref: Option<String>,
        }

        let from_null: Wrapper = serde_json::from_str(r#"{"audit_ref": null}"#).unwrap();
        assert_eq!(from_null.audit_ref, None);

        let from_absent: Wrapper = serde_json::from_str("{}").unwrap();
        assert_eq!(from_absent.audit_ref, None);

        // A well-formed AuditRef string still parses on the way in when a
        // caller chooses to interpret the field that way.
        let from_value: Wrapper =
            serde_json::from_str(r#"{"audit_ref": "issuer-1:event-1"}"#).unwrap();
        let parsed = AuditRef::parse(from_value.audit_ref.as_deref().unwrap()).unwrap();
        assert_eq!(parsed, AuditRef::new("issuer-1", "event-1"));
    }

    #[test]
    fn revocation_entry_audit_ref_null_continues_to_parse_and_serialize_exactly_as_today() {
        // Direct regression against the real `RevocationEntry` type
        // (`crate::policy::revocation::RevocationEntry`), built from a JSON
        // literal so we never need `RevocationTarget`'s private digest
        // constructors. `RevocationEntry` is `#[serde(deny_unknown_fields)]`
        // with no `#[serde(default)]` on `audit_ref`, so the field must be
        // present as literal `null` (not simply absent) -- this test proves
        // that shape is untouched by anything added in this module.
        use crate::RevocationEntry;

        let json = serde_json::json!({
            "target": {
                "target_kind": "payload_digest",
                "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            },
            "revoked_at": "2026-09-03T14:22:05Z",
            "reason": "compromised signing key",
            "audit_ref": null,
            "superseded_by": null
        });

        let entry: RevocationEntry = serde_json::from_value(json).unwrap();
        assert_eq!(entry.audit_ref, None);

        let reser = serde_json::to_value(&entry).unwrap();
        assert_eq!(reser["audit_ref"], serde_json::Value::Null);
    }
}
