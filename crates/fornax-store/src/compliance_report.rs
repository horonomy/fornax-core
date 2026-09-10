//! Reproducible, evidence-backed local compliance report (FORNX-322).
//!
//! **This report never asserts anything it cannot demonstrate by querying
//! real state.** For any capability not actually present/enabled/configured
//! in the store this report is generated against, the corresponding section
//! renders an explicit "not evidenced in this deployment" line naming the
//! missing capability, rather than omitting the section or fabricating a
//! passing result — the same discipline
//! [`crate::retention::purge_evidence_payload_row`] already applies to a
//! single purge (it "does not fabricate a 'deletion succeeded' result
//! against data that was never tagged"), extended here to a whole report.
//!
//! There is no hardcoded pass/fail verdict string anywhere in this module.
//! Every field in [`ComplianceReportBody`] traces directly to a call into
//! [`crate::audit_ledger`], [`crate::audit_checkpoint`], or
//! [`crate::retention`] — a reader forms their own judgment from the real
//! counts/timestamps/verdicts reported, this module renders no opinion.
//!
//! # Digest and reproducibility
//!
//! [`ComplianceReportBody`] holds only deterministic content — no wall-clock
//! field. [`canonical_bytes`]/[`digest_of`] mirror
//! `fornax_types::policy::revision::canonical_bytes`/`digest_of`'s exact
//! discipline: `serde_json::to_vec` on the typed body (never a `Value`
//! round-trip, so field order is deterministic), then a `sha256:`-prefixed
//! hex digest. [`ComplianceReport::generated_at`] is a sibling field on the
//! outer, non-hashed wrapper — running [`Store::generate_compliance_report`]
//! twice against an unchanged store produces the identical
//! [`ComplianceReport::digest`] even though `generated_at` differs between
//! the two calls.
//!
//! # This report is itself audited
//!
//! [`Store::generate_compliance_report`] appends an
//! `AuditAction::ComplianceReportGenerated` event (FORNX-322) to the local
//! ledger, targeting the freshly computed digest
//! (`AuditTarget::ComplianceReport`) — so generating a report is itself
//! evidenced in the very ledger the report reads from.
//!
//! # No raw content
//!
//! Every field here is a count, a digest, a timestamp, or a named verdict —
//! never an embedded event/evidence payload. This report's own
//! `AuditEvent::export_class` is [`fornax_types::AuditExportClass::Metadata`],
//! matching that fact.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use fornax_types::{
    AuditAction, AuditActor, AuditEvent, AuditExportClass, AuditOutcome, AuditTarget,
    RetentionClass,
};

use crate::{Result, Store};

pub const COMPLIANCE_REPORT_SCHEMA_VERSION: u32 = 1;

/// Every [`RetentionClass`] this report evaluates, in a fixed, deterministic
/// order (matches `retention.rs`'s own AC1 table order) — never derived by
/// enumerating what happens to exist in the store, so the report's section
/// list is stable regardless of what data is present.
const REPORTED_RETENTION_CLASSES: &[RetentionClass] = &[
    RetentionClass::RawLocal,
    RetentionClass::SanitizedReplayFixture,
    RetentionClass::AggregatedFeature,
    RetentionClass::DerivedFinding,
];

/// This report's own rendering of [`crate::audit_ledger::ChainVerification`]
/// — a local copy rather than deriving `Serialize`/`Deserialize` on that
/// type directly, since `audit_ledger.rs` is otherwise untouched by this
/// ticket (see that module's own doc comment on the trust boundary it
/// alone owns).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum LedgerIntegrityStatus {
    Valid,
    Diverged {
        first_bad_seq: i64,
        /// `Debug`-rendered [`DivergenceKind`] (e.g. `"HashMismatch"`) — a
        /// real, queried value, never a hardcoded string.
        kind: String,
    },
}

impl From<&crate::audit_ledger::ChainVerification> for LedgerIntegrityStatus {
    fn from(v: &crate::audit_ledger::ChainVerification) -> Self {
        match v {
            crate::audit_ledger::ChainVerification::Valid => LedgerIntegrityStatus::Valid,
            crate::audit_ledger::ChainVerification::Diverged {
                first_bad_seq,
                kind,
            } => LedgerIntegrityStatus::Diverged {
                first_bad_seq: *first_bad_seq,
                kind: format!("{kind:?}"),
            },
        }
    }
}

/// Ledger integrity section: [`Store::verify_audit_chain`]'s result, event
/// count, and the ledger's real `seq`/`recorded_at` coverage window. An
/// empty ledger reports zero events and `None` for both ranges — never a
/// fabricated range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerIntegritySection {
    pub integrity: LedgerIntegrityStatus,
    pub event_count: u64,
    pub min_seq: Option<i64>,
    pub max_seq: Option<i64>,
    pub min_recorded_at: Option<String>,
    pub max_recorded_at: Option<String>,
}

/// Checkpoint anchoring section (FORNX-317). `NotEvidenced` is rendered,
/// never omitted, when [`Store::audit_checkpoint_receipts`] is empty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CheckpointAnchoringSection {
    /// Named per this ticket's governing principle: the missing capability
    /// is stated explicitly, not merely implied by an absent/zeroed field.
    NotEvidenced { detail: String },
    Evidenced {
        checkpoint_count: u64,
        latest_checkpoint_seq: u64,
        latest_issued_at: String,
    },
}

/// One [`RetentionClass`]'s configured duration vs. its real observed
/// coverage in this store (FORNX-319). `oldest_recorded_at` is `None`, not
/// a fabricated timestamp, when `record_count` is zero.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionClassObservation {
    pub retention_class: RetentionClass,
    pub configured_retention_seconds: u64,
    pub record_count: u64,
    pub oldest_recorded_at: Option<String>,
}

/// Retention section: every [`RetentionClass`] this binary knows about
/// (FORNX-106/FORNX-319 AC1's table), each with its configured duration
/// alongside this store's real observed coverage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionSection {
    pub classes: Vec<RetentionClassObservation>,
}

/// The deterministic, hashed content of a compliance report — no wall-clock
/// field. See this module's doc comment for the digest/reproducibility
/// discipline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceReportBody {
    pub schema_version: u32,
    pub ledger_integrity: LedgerIntegritySection,
    pub checkpoint_anchoring: CheckpointAnchoringSection,
    pub retention: RetentionSection,
}

/// `serde_json::to_vec` on the typed body — mirrors
/// `fornax_types::policy::revision::canonical_bytes`'s exact discipline:
/// field order must be deterministic and reproducible.
pub fn canonical_bytes(body: &ComplianceReportBody) -> Vec<u8> {
    serde_json::to_vec(body).expect("ComplianceReportBody always serializes")
}

/// `sha256:`-prefixed hex digest over [`canonical_bytes`], mirroring
/// `fornax_types::policy::revision::digest_of`.
pub fn digest_of(body: &ComplianceReportBody) -> String {
    let bytes = canonical_bytes(body);
    let hash = Sha256::digest(&bytes);
    let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256:{hex}")
}

/// A generated compliance report: the deterministic, digest-stamped `body`
/// plus a `generated_at` wall-clock timestamp that is NOT part of the
/// hashed content — two calls to [`Store::generate_compliance_report`]
/// against an unchanged store produce the same `digest` even though
/// `generated_at` differs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub body: ComplianceReportBody,
    pub digest: String,
    pub generated_at: String,
}

/// The `AuditAction::ComplianceReportGenerated` event
/// [`Store::generate_compliance_report`] appends, naming the freshly
/// computed digest as its target (FORNX-322).
fn compliance_report_generated_audit_event(digest: &str, now: DateTime<Utc>) -> AuditEvent {
    AuditEvent::new(
        uuid::Uuid::new_v4().to_string(),
        now.to_rfc3339(),
        AuditActor::System,
        AuditAction::ComplianceReportGenerated,
        AuditTarget::ComplianceReport {
            target_id: digest.to_string(),
        },
        AuditOutcome::Granted,
        AuditExportClass::Metadata,
    )
}

impl Store {
    /// Builds a [`ComplianceReportBody`] by querying this store's CURRENT
    /// state. Purely a read — no write, no audit event appended — so
    /// calling this repeatedly with no intervening write to the store
    /// always yields byte-identical output (proven by this module's
    /// `report_digest_is_reproducible_against_an_unchanged_store` test).
    /// [`Store::generate_compliance_report`] is the write-producing
    /// counterpart that calls this once and then audits having done so.
    pub async fn compliance_report_body(&self) -> Result<ComplianceReportBody> {
        let ledger_integrity = self.ledger_integrity_section().await?;
        let checkpoint_anchoring = self.checkpoint_anchoring_section().await?;
        let retention = self.retention_section().await?;

        Ok(ComplianceReportBody {
            schema_version: COMPLIANCE_REPORT_SCHEMA_VERSION,
            ledger_integrity,
            checkpoint_anchoring,
            retention,
        })
    }

    /// Generates a [`ComplianceReport`] against this store's CURRENT state
    /// and appends the `ComplianceReportGenerated` audit event recording
    /// that it did so. `now` is a parameter, never `Utc::now()` internally
    /// (mirrors `Store::append_audit_event`'s own discipline), so the
    /// audited event's own timestamp is deterministic in tests — this does
    /// NOT affect the report body's digest, since `now` never enters
    /// [`ComplianceReportBody`] at all (only the non-hashed
    /// `ComplianceReport::generated_at` wrapper field, and the audit event
    /// appended as a side effect, which is why calling THIS method twice in
    /// a row does NOT reproduce the same digest — each call's own audit
    /// append changes the ledger the next call reads. Reproducibility is a
    /// property of [`Store::compliance_report_body`] against an unchanged
    /// store, not of two full generate-and-audit round trips).
    pub async fn generate_compliance_report(&self, now: DateTime<Utc>) -> Result<ComplianceReport> {
        let body = self.compliance_report_body().await?;
        let digest = digest_of(&body);

        self.append_audit_event(&compliance_report_generated_audit_event(&digest, now), now)
            .await?;

        Ok(ComplianceReport {
            body,
            digest,
            generated_at: now.to_rfc3339(),
        })
    }

    async fn ledger_integrity_section(&self) -> Result<LedgerIntegritySection> {
        let verification = self.verify_audit_chain().await?;
        let events = self.audit_events().await?;

        let event_count = events.len() as u64;
        let min_seq = events.first().map(|e| e.seq);
        let max_seq = events.last().map(|e| e.seq);
        let min_recorded_at = events.first().map(|e| e.recorded_at.clone());
        let max_recorded_at = events.last().map(|e| e.recorded_at.clone());

        Ok(LedgerIntegritySection {
            integrity: LedgerIntegrityStatus::from(&verification),
            event_count,
            min_seq,
            max_seq,
            min_recorded_at,
            max_recorded_at,
        })
    }

    async fn checkpoint_anchoring_section(&self) -> Result<CheckpointAnchoringSection> {
        let receipts = self.audit_checkpoint_receipts().await?;
        if receipts.is_empty() {
            return Ok(CheckpointAnchoringSection::NotEvidenced {
                detail:
                    "not evidenced in this deployment: no audit checkpoints have been submitted"
                        .to_string(),
            });
        }
        let latest = self
            .latest_audit_checkpoint_receipt()
            .await?
            .expect("receipts is non-empty, so a latest receipt must exist");
        Ok(CheckpointAnchoringSection::Evidenced {
            checkpoint_count: receipts.len() as u64,
            latest_checkpoint_seq: latest.checkpoint_seq,
            latest_issued_at: latest.issued_at,
        })
    }

    async fn retention_section(&self) -> Result<RetentionSection> {
        let mut classes = Vec::with_capacity(REPORTED_RETENTION_CLASSES.len());
        for class in REPORTED_RETENTION_CLASSES {
            let (record_count, oldest_recorded_at) =
                self.retention_class_observation(class).await?;
            classes.push(RetentionClassObservation {
                retention_class: class.clone(),
                configured_retention_seconds: crate::retention::retention_duration_for(class)
                    .as_secs(),
                record_count,
                oldest_recorded_at,
            });
        }
        Ok(RetentionSection { classes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fornax_types::{AuditActor as EventActor, AuditExportClass as EventExportClass};
    use uuid::Uuid;

    fn tmp_db_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "fornax-store-compliance-report-test-{name}-{}.db",
            Uuid::new_v4()
        ))
    }

    fn now() -> DateTime<Utc> {
        "2026-09-03T00:00:00Z".parse().unwrap()
    }

    /// AC1: no hardcoded "compliant"/"pass" string anywhere in this module's
    /// source — a structural guarantee, mirroring
    /// `audit_ledger.rs`'s own source-inspection test style.
    #[test]
    fn no_hardcoded_compliant_or_pass_string_in_this_module() {
        let source = include_str!("compliance_report.rs");
        let production_source = source.split_once("#[cfg(test)]").unwrap().0;
        for forbidden in ["\"compliant\"", "\"pass\"", "\"Compliant\"", "\"Pass\""] {
            assert!(
                !production_source.contains(forbidden),
                "found forbidden hardcoded verdict string: {forbidden}"
            );
        }
    }

    /// AC2: a store with zero checkpoints reports checkpointing as
    /// explicitly not evidenced -- section present, no anchoring claim.
    #[tokio::test]
    async fn zero_checkpoints_reports_checkpoint_anchoring_as_not_evidenced() {
        let path = tmp_db_path("no-checkpoints");
        let store = Store::open(&path).await.expect("open db");

        let report = store
            .generate_compliance_report(now())
            .await
            .expect("generate report");

        assert_eq!(
            report.body.checkpoint_anchoring,
            CheckpointAnchoringSection::NotEvidenced {
                detail:
                    "not evidenced in this deployment: no audit checkpoints have been submitted"
                        .to_string(),
            }
        );

        std::fs::remove_file(&path).ok();
    }

    /// AC3: running the report twice against an unchanged store (no write
    /// in between) yields an identical digest, even when the two builds are
    /// separated by real wall-clock time and their own `generated_at`
    /// values would differ.
    #[tokio::test]
    async fn report_digest_is_reproducible_against_an_unchanged_store() {
        let path = tmp_db_path("reproducible-digest");
        let store = Store::open(&path).await.expect("open db");

        // Seed some ledger state so the report isn't trivially empty both
        // times (a real regression here could hide behind an all-empty
        // report).
        let event = AuditEvent::new(
            "seed-event",
            "2026-09-03T00:00:00Z",
            EventActor::Device {
                actor_id: "device-1".to_string(),
            },
            AuditAction::PermissionCheck,
            AuditTarget::Permission {
                target_id: "perm-1".to_string(),
            },
            AuditOutcome::Granted,
            EventExportClass::Metadata,
        );
        store
            .append_audit_event(&event, now())
            .await
            .expect("seed ledger");

        // `compliance_report_body` is a pure read with no side effect on
        // the store, so calling it twice in a row (with nothing written to
        // the store in between) is the real "unchanged store" case this AC
        // is about -- unlike `generate_compliance_report`, which itself
        // appends an audit event and so would legitimately see the ledger
        // grow between two successive calls.
        let first_body = store
            .compliance_report_body()
            .await
            .expect("first report body");
        let second_body = store
            .compliance_report_body()
            .await
            .expect("second report body");

        assert_eq!(
            first_body, second_body,
            "an unchanged store must produce byte-identical report content"
        );
        assert_eq!(
            digest_of(&first_body),
            digest_of(&second_body),
            "digest must be reproducible against an unchanged store"
        );

        // The digest computation must also be independent of wall-clock
        // time: wrapping the SAME body in two `ComplianceReport`s stamped
        // with different `generated_at` values must not change the digest,
        // since `generated_at` is a sibling field never fed into
        // `canonical_bytes`.
        let wrapped_now = ComplianceReport {
            body: first_body.clone(),
            digest: digest_of(&first_body),
            generated_at: now().to_rfc3339(),
        };
        let later = now() + chrono::Duration::hours(1);
        let wrapped_later = ComplianceReport {
            body: first_body,
            digest: digest_of(&second_body),
            generated_at: later.to_rfc3339(),
        };
        assert_ne!(wrapped_now.generated_at, wrapped_later.generated_at);
        assert_eq!(wrapped_now.digest, wrapped_later.digest);

        std::fs::remove_file(&path).ok();
    }

    /// AC4: generating a report appends an AuditEvent to the local ledger.
    #[tokio::test]
    async fn generating_a_report_appends_a_compliance_report_generated_audit_event() {
        let path = tmp_db_path("audits-itself");
        let store = Store::open(&path).await.expect("open db");

        let report = store
            .generate_compliance_report(now())
            .await
            .expect("generate report");

        let events = store.audit_events().await.expect("list audit events");
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event.action,
            AuditAction::ComplianceReportGenerated
        );
        assert_eq!(
            events[0].event.target,
            AuditTarget::ComplianceReport {
                target_id: report.digest.clone()
            }
        );
        assert_eq!(events[0].export_class, "metadata");

        let verification = store.verify_audit_chain().await.expect("verify chain");
        assert_eq!(verification, crate::audit_ledger::ChainVerification::Valid);

        std::fs::remove_file(&path).ok();
    }

    /// AC5: the report contains no `RawContent`-classed material -- this
    /// module's own audit event always uses `Metadata`, and none of
    /// `ComplianceReportBody`'s fields are event/evidence payloads.
    #[test]
    fn compliance_report_audit_event_is_never_raw_content_classed() {
        let event = compliance_report_generated_audit_event("sha256:deadbeef", now());
        assert_eq!(event.export_class, AuditExportClass::Metadata);
        assert_ne!(event.export_class, AuditExportClass::RawContent);
    }

    /// Retention section reports the real configured duration for every
    /// class this binary knows about, and (for a fresh store) zero records
    /// with no fabricated oldest-record timestamp for each.
    #[tokio::test]
    async fn retention_section_reports_every_known_class_with_real_durations() {
        let path = tmp_db_path("retention-section");
        let store = Store::open(&path).await.expect("open db");

        let report = store
            .generate_compliance_report(now())
            .await
            .expect("generate report");

        assert_eq!(report.body.retention.classes.len(), 4);
        for observation in &report.body.retention.classes {
            assert_eq!(
                observation.configured_retention_seconds,
                crate::retention::retention_duration_for(&observation.retention_class).as_secs()
            );
            assert_eq!(observation.record_count, 0);
            assert_eq!(observation.oldest_recorded_at, None);
        }

        std::fs::remove_file(&path).ok();
    }

    /// Retention section reports real, non-zero coverage once records exist
    /// for a class -- proving the "evidenced" path, not just the empty-store
    /// default, actually reflects real queried state.
    #[tokio::test]
    async fn retention_section_reports_real_coverage_once_records_exist() {
        use fornax_types::{DatasetLineageTag, RetentionClass, TenantRef};

        let path = tmp_db_path("retention-section-populated");
        let store = Store::open(&path).await.expect("open db");

        store
            .record_lineage_tag(
                "agent_events",
                "row-1",
                &DatasetLineageTag {
                    schema_version: 1,
                    retention_class: RetentionClass::RawLocal,
                    tenant_ref: TenantRef("tenant-x".to_string()),
                    source_record_ids: vec![],
                    recorded_at: "2026-01-01T00:00:00Z".to_string(),
                    deletion_requested_at: None,
                },
            )
            .await
            .expect("record lineage tag");

        let report = store
            .generate_compliance_report(now())
            .await
            .expect("generate report");

        let raw_local = report
            .body
            .retention
            .classes
            .iter()
            .find(|c| c.retention_class == RetentionClass::RawLocal)
            .expect("RawLocal section present");
        assert_eq!(raw_local.record_count, 1);
        assert_eq!(
            raw_local.oldest_recorded_at.as_deref(),
            Some("2026-01-01T00:00:00Z")
        );

        std::fs::remove_file(&path).ok();
    }

    /// Checkpoint anchoring reports "evidenced" with real counts/timestamps
    /// once a verified checkpoint receipt has actually been stored --
    /// mirroring `audit_checkpoint.rs`'s own real-verified-envelope
    /// integration test setup rather than a hand-built stand-in receipt.
    #[tokio::test]
    async fn checkpoint_anchoring_reports_evidenced_once_a_real_receipt_is_stored() {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine;
        use ed25519_dalek::{Signer, SigningKey};
        use fornax_types::policy::{
            BundleSignature, KeyId, SignatureAlgorithm, TrustedKey, TrustedVerificationKeys,
        };
        use fornax_types::{
            verify_audit_checkpoint, AuditCheckpointPayload, DeviceReportedChainStatus, LedgerHead,
            SignedAuditCheckpoint, AUDIT_CHECKPOINT_SCHEMA_VERSION,
            AUDIT_CHECKPOINT_SIGNING_DOMAIN,
        };

        let path = tmp_db_path("checkpoint-evidenced");
        let store = Store::open(&path).await.expect("open db");

        let seed_event = AuditEvent::new(
            "seed-event",
            "2026-09-03T00:00:00Z",
            EventActor::Device {
                actor_id: "device-1".to_string(),
            },
            AuditAction::PermissionCheck,
            AuditTarget::Permission {
                target_id: "perm-1".to_string(),
            },
            AuditOutcome::Granted,
            EventExportClass::Metadata,
        );
        let appended = store
            .append_audit_event(&seed_event, now())
            .await
            .expect("seed ledger");

        let key = SigningKey::from_bytes(&[7u8; 32]);
        let payload = AuditCheckpointPayload {
            checkpoint_schema_version: AUDIT_CHECKPOINT_SCHEMA_VERSION,
            issuer: "fornax-cloud:org-1".to_string(),
            device_id: "device-abc".to_string(),
            checkpoint_seq: 1,
            issued_at: "2026-09-03T00:00:05Z".to_string(),
            observed_at: "2026-09-03T00:00:00Z".to_string(),
            head: LedgerHead {
                ledger_seq: appended.seq,
                entry_hash: appended.entry_hash.clone(),
            },
            device_reported_chain_status: DeviceReportedChainStatus {
                status: "valid".to_string(),
                first_bad_ledger_seq: None,
                divergence_kind: None,
            },
            prev_checkpoint: None,
        };
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let mut signed_message = AUDIT_CHECKPOINT_SIGNING_DOMAIN.to_vec();
        signed_message.extend_from_slice(&payload_bytes);
        let signature = key.sign(&signed_message);
        let envelope = SignedAuditCheckpoint {
            checkpoint_schema_version: AUDIT_CHECKPOINT_SCHEMA_VERSION,
            payload_b64: B64.encode(&payload_bytes),
            signatures: vec![BundleSignature {
                key_id: KeyId("k1".to_string()),
                algorithm: SignatureAlgorithm::Ed25519,
                signature_b64: B64.encode(signature.to_bytes()),
            }],
        };
        let envelope_bytes = serde_json::to_vec(&envelope).unwrap();
        let trusted = TrustedVerificationKeys {
            schema_version: 1,
            keys: vec![TrustedKey {
                key_id: KeyId("k1".to_string()),
                algorithm: SignatureAlgorithm::Ed25519,
                public_key_b64: B64.encode(key.verifying_key().to_bytes()),
                not_before: None,
                not_after: None,
                comment: None,
            }],
        };
        let verified = verify_audit_checkpoint(&envelope_bytes, &trusted, now())
            .expect("hand-built checkpoint must verify");
        store
            .store_audit_checkpoint_receipt(&verified, &String::from_utf8(envelope_bytes).unwrap())
            .await
            .expect("store receipt");

        let report = store
            .generate_compliance_report(now())
            .await
            .expect("generate report");

        assert_eq!(
            report.body.checkpoint_anchoring,
            CheckpointAnchoringSection::Evidenced {
                checkpoint_count: 1,
                latest_checkpoint_seq: 1,
                latest_issued_at: "2026-09-03T00:00:05Z".to_string(),
            }
        );

        std::fs::remove_file(&path).ok();
    }
}
