//! Persistence for the egress profile, consents and allowlist (FORNX-464),
//! and the store-backed entry point every outbound path calls.
//!
//! [`Store::egress_state`] loads the persisted state; [`Store::decide_egress`]
//! runs [`fornax_types::egress::decide`] on it and treats *any* failure to
//! read or understand that state as a denial -- an unreadable egress policy
//! must never become an open one. Capture and verification never call into
//! here, so a denial can never block them.
//!
//! Every state change appends an audit event after it commits. Entering the
//! corporate profile revokes every live consent in the same transaction, and
//! leaving corporate requires an explicit confirmation.

use std::collections::BTreeSet;

use chrono::Utc;
use fornax_types::audit::{
    AuditAction, AuditActor, AuditEvent, AuditExportClass, AuditOutcome, AuditTarget,
};
use fornax_types::egress::{
    self, AllowlistEntry, Consent, Destination, EgressDenial, EgressPermit, EgressRequest,
    EgressState, Profile, Purpose,
};
use fornax_types::EgressContentClass;
use uuid::Uuid;

use crate::{Result, Store, StoreError};

/// Default consent lifetime when none is given.
pub const DEFAULT_CONSENT_DAYS: i64 = 365;

#[derive(sqlx::FromRow)]
struct ProfileRow {
    profile: String,
    generation: i64,
}

#[derive(sqlx::FromRow)]
struct ConsentRow {
    id: String,
    purpose: String,
    destination: String,
    data_classes: String,
    granted_at: String,
    expires_at: String,
    revoked_at: Option<String>,
    profile_generation: i64,
    authorization_ref: Option<String>,
}

#[derive(sqlx::FromRow)]
struct AllowRow {
    id: String,
    purpose: String,
    destination: String,
    removed_at: Option<String>,
}

fn invalid(msg: impl Into<String>) -> StoreError {
    StoreError::InvalidEgress(msg.into())
}

impl Store {
    /// Load the persisted egress state. A missing profile row is
    /// [`Profile::Unconfigured`]; any row that cannot be understood is an
    /// error (callers deny).
    pub async fn egress_state(&self) -> Result<EgressState> {
        let profile_row: Option<ProfileRow> =
            sqlx::query_as("SELECT profile, generation FROM egress_profile WHERE id = 1")
                .fetch_optional(&self.pool)
                .await?;
        let (profile, generation) = match profile_row {
            None => (Profile::Unconfigured, 0),
            Some(r) => (
                Profile::parse(&r.profile).ok_or_else(|| invalid("unknown profile"))?,
                r.generation,
            ),
        };

        let consent_rows: Vec<ConsentRow> = sqlx::query_as(
            "SELECT id, purpose, destination, data_classes, granted_at, expires_at, revoked_at,
                    profile_generation, authorization_ref
             FROM egress_consents",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut consents = Vec::with_capacity(consent_rows.len());
        for r in consent_rows {
            let classes: Vec<String> = serde_json::from_str(&r.data_classes)
                .map_err(|_| invalid("malformed consent data_classes"))?;
            consents.push(Consent {
                id: r.id,
                purpose: Purpose::parse(&r.purpose).ok_or_else(|| invalid("unknown purpose"))?,
                destination: r.destination,
                data_classes: classes.into_iter().collect(),
                granted_at: r.granted_at,
                expires_at: r.expires_at,
                revoked_at: r.revoked_at,
                profile_generation: r.profile_generation,
                authorization_ref: r.authorization_ref,
            });
        }

        let allow_rows: Vec<AllowRow> =
            sqlx::query_as("SELECT id, purpose, destination, removed_at FROM egress_allowlist")
                .fetch_all(&self.pool)
                .await?;
        let mut allowlist = Vec::with_capacity(allow_rows.len());
        for r in allow_rows {
            allowlist.push(AllowlistEntry {
                id: r.id,
                purpose: Purpose::parse(&r.purpose).ok_or_else(|| invalid("unknown purpose"))?,
                destination: r.destination,
                removed: r.removed_at.is_some(),
            });
        }

        Ok(EgressState {
            profile,
            generation,
            consents,
            allowlist,
        })
    }

    /// Decide whether `req` may leave the machine, from the persisted state.
    /// An unreadable state is a denial, never a pass.
    pub async fn decide_egress(
        &self,
        purpose: Purpose,
        url: &str,
        classes: &BTreeSet<EgressContentClass>,
        legacy_cloud_sync_gate_open: bool,
    ) -> std::result::Result<EgressPermit, EgressDenial> {
        let state = self
            .egress_state()
            .await
            .map_err(|_| EgressDenial::StateUnreadable)?;
        let now = Utc::now().to_rfc3339();
        egress::decide(
            &state,
            &EgressRequest {
                purpose,
                url,
                classes,
                legacy_cloud_sync_gate_open,
                now: &now,
            },
        )
    }

    /// Set the egress profile. Entering `corporate` revokes every live
    /// consent in the same transaction; leaving `corporate` requires
    /// `confirm_leave_corporate`. Every change bumps the generation, so
    /// consents granted earlier become stale.
    pub async fn set_egress_profile(
        &self,
        profile: Profile,
        source: &str,
        confirm_leave_corporate: bool,
    ) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let current: Option<ProfileRow> =
            sqlx::query_as("SELECT profile, generation FROM egress_profile WHERE id = 1")
                .fetch_optional(&mut *tx)
                .await?;
        let (current_profile, current_generation) = match current {
            None => (Profile::Unconfigured, 0),
            Some(r) => (
                Profile::parse(&r.profile).ok_or_else(|| invalid("unknown profile"))?,
                r.generation,
            ),
        };
        if current_profile == Profile::Corporate
            && profile != Profile::Corporate
            && !confirm_leave_corporate
        {
            return Err(invalid(
                "leaving the corporate profile needs --confirm-leave-corporate",
            ));
        }
        let generation = current_generation + 1;
        sqlx::query(
            "INSERT INTO egress_profile (id, profile, generation, changed_at, source)
             VALUES (1, ?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET profile = ?1, generation = ?2, changed_at = ?3, source = ?4",
        )
        .bind(profile.as_str())
        .bind(generation)
        .bind(&now)
        .bind(source)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO egress_profile_log (changed_at, profile, generation) VALUES (?1, ?2, ?3)",
        )
        .bind(&now)
        .bind(profile.as_str())
        .bind(generation)
        .execute(&mut *tx)
        .await?;
        let revoked = if profile == Profile::Corporate {
            sqlx::query(
                "UPDATE egress_consents SET revoked_at = ?1, revoked_reason = 'entered corporate profile'
                 WHERE revoked_at IS NULL",
            )
            .bind(&now)
            .execute(&mut *tx)
            .await?
            .rows_affected()
        } else {
            0
        };
        tx.commit().await?;

        self.audit_egress(
            AuditAction::EgressProfileChanged,
            format!("profile:{}:gen{generation}", profile.as_str()),
            source,
        )
        .await?;
        if revoked > 0 {
            self.audit_egress(
                AuditAction::EgressConsentRevoked,
                format!("all:{revoked}"),
                source,
            )
            .await?;
        }
        Ok(())
    }

    /// Record a consent. Refused unless it is grantable under the current
    /// profile: never under corporate except a semantic-judge authorization
    /// with a reference; never for the reserved uploader purpose; evidence
    /// purposes only for uploadable (metadata) classes.
    #[allow(clippy::too_many_arguments)]
    pub async fn grant_egress_consent(
        &self,
        purpose: Purpose,
        destination: &str,
        classes: &BTreeSet<EgressContentClass>,
        expires_in_days: i64,
        authorization_ref: Option<&str>,
        source: &str,
    ) -> Result<String> {
        let state = self.egress_state().await?;
        let dest = Destination::parse(destination).map_err(|d| invalid(d.code()))?;
        if purpose == Purpose::UploaderSpoolStream {
            return Err(invalid(
                "the uploader stream purpose is not available in v0.0.9",
            ));
        }
        if purpose == Purpose::PolicyFetch {
            return Err(invalid(
                "policy fetch needs an allowlist entry, not a consent",
            ));
        }
        match state.profile {
            Profile::Unconfigured => {
                return Err(invalid("choose a profile first (fornax egress profile set)"))
            }
            Profile::Corporate if purpose != Purpose::SemanticJudge => {
                return Err(invalid(
                    "the corporate profile is local-only: only a semantic-judge authorization can be recorded",
                ))
            }
            Profile::Corporate
                if authorization_ref.is_none_or(|r| r.trim().is_empty()) =>
            {
                return Err(invalid(
                    "a corporate semantic-judge authorization needs --authorization-ref",
                ))
            }
            _ => {}
        }
        if classes.is_empty() {
            return Err(invalid("at least one data class is required"));
        }
        if matches!(
            purpose,
            Purpose::EvidenceBatchUpload | Purpose::AuditCheckpoint
        ) && !classes.iter().all(egress::is_uploadable_class)
        {
            return Err(invalid(
                "only metadata classes (evidence_metadata, finding_verdicts, capability_declarations) may be uploaded",
            ));
        }
        if classes
            .iter()
            .any(|c| matches!(c, EgressContentClass::Unrecognized(_)))
        {
            return Err(invalid("unknown data class"));
        }
        if expires_in_days <= 0 {
            return Err(invalid("consent must expire in the future"));
        }

        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let expires = now + chrono::Duration::days(expires_in_days);
        let class_list: Vec<String> = classes.iter().map(egress::class_str).collect();
        sqlx::query(
            "INSERT INTO egress_consents
               (id, purpose, destination, data_classes, granted_at, expires_at,
                profile_generation, authorization_ref)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )
        .bind(&id)
        .bind(purpose.as_str())
        .bind(dest.canonical())
        .bind(serde_json::to_string(&class_list).map_err(|e| invalid(e.to_string()))?)
        .bind(now.to_rfc3339())
        .bind(expires.to_rfc3339())
        .bind(state.generation)
        .bind(authorization_ref)
        .execute(&self.pool)
        .await?;
        self.audit_egress(
            AuditAction::EgressConsentGranted,
            format!("consent:{id}"),
            source,
        )
        .await?;
        Ok(id)
    }

    /// Revoke one consent. Returns whether a live consent was revoked.
    pub async fn revoke_egress_consent(
        &self,
        id: &str,
        reason: &str,
        source: &str,
    ) -> Result<bool> {
        let n = sqlx::query(
            "UPDATE egress_consents SET revoked_at = ?2, revoked_reason = ?3
             WHERE id = ?1 AND revoked_at IS NULL",
        )
        .bind(id)
        .bind(Utc::now().to_rfc3339())
        .bind(reason)
        .execute(&self.pool)
        .await?
        .rows_affected();
        if n > 0 {
            self.audit_egress(
                AuditAction::EgressConsentRevoked,
                format!("consent:{id}"),
                source,
            )
            .await?;
        }
        Ok(n > 0)
    }

    /// Allowlist a destination for one purpose.
    pub async fn add_egress_allowlist(
        &self,
        purpose: Purpose,
        destination: &str,
        source: &str,
    ) -> Result<String> {
        if purpose == Purpose::UploaderSpoolStream {
            return Err(invalid(
                "the uploader stream purpose is not available in v0.0.9",
            ));
        }
        let dest = Destination::parse(destination).map_err(|d| invalid(d.code()))?;
        let id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO egress_allowlist (id, purpose, destination, added_at) VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(&id)
        .bind(purpose.as_str())
        .bind(dest.canonical())
        .bind(Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await?;
        self.audit_egress(
            AuditAction::EgressAllowlistChanged,
            format!("add:{id}"),
            source,
        )
        .await?;
        Ok(id)
    }

    /// Remove (soft-delete) an allowlist entry.
    pub async fn remove_egress_allowlist(&self, id: &str, source: &str) -> Result<bool> {
        let n = sqlx::query(
            "UPDATE egress_allowlist SET removed_at = ?2 WHERE id = ?1 AND removed_at IS NULL",
        )
        .bind(id)
        .bind(Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await?
        .rows_affected();
        if n > 0 {
            self.audit_egress(
                AuditAction::EgressAllowlistChanged,
                format!("remove:{id}"),
                source,
            )
            .await?;
        }
        Ok(n > 0)
    }

    /// Write the derived `egress-projection.json` the separate `fornax-cloud`
    /// uploader reads (contract v1). It is a view of the persisted state,
    /// never a source of truth: the uploader fails closed unless it finds
    /// `profile: personal` and a matching `uploader_spool_stream`
    /// authorization. That purpose is not grantable in v0.0.9, so
    /// `authorized` is always empty today and the uploader stays inert.
    pub async fn write_egress_projection(&self, path: &std::path::Path) -> Result<()> {
        use std::io::Write;
        let state = self.egress_state().await?;
        let authorized: Vec<serde_json::Value> = if state.profile == Profile::Personal {
            state
                .consents
                .iter()
                .filter(|c| {
                    c.purpose == Purpose::UploaderSpoolStream
                        && c.revoked_at.is_none()
                        && c.profile_generation == state.generation
                })
                .map(|c| {
                    serde_json::json!({
                        "purpose": "uploader_spool_stream",
                        "destination": c.destination,
                    })
                })
                .collect()
        } else {
            Vec::new()
        };
        let doc = serde_json::json!({
            "schema_version": 1,
            "profile": state.profile.as_str(),
            "generation": state.generation,
            "authorized": authorized,
        });
        let tmp = path.with_extension("json.tmp");
        {
            let mut f = std::fs::File::create(&tmp).map_err(|e| invalid(e.to_string()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                f.set_permissions(std::fs::Permissions::from_mode(0o600))
                    .map_err(|e| invalid(e.to_string()))?;
            }
            f.write_all(doc.to_string().as_bytes())
                .map_err(|e| invalid(e.to_string()))?;
            f.write_all(b"\n").map_err(|e| invalid(e.to_string()))?;
            f.sync_all().map_err(|e| invalid(e.to_string()))?;
        }
        std::fs::rename(&tmp, path).map_err(|e| invalid(e.to_string()))?;
        Ok(())
    }

    async fn audit_egress(&self, action: AuditAction, target: String, source: &str) -> Result<()> {
        self.append_audit_event(
            &AuditEvent::new(
                Uuid::new_v4().to_string(),
                Utc::now().to_rfc3339(),
                AuditActor::User {
                    actor_id: source.to_string(),
                },
                action,
                AuditTarget::EgressPolicy { target_id: target },
                AuditOutcome::Granted,
                AuditExportClass::Metadata,
            ),
            Utc::now(),
        )
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const URL: &str = "https://ingest.example.test/v1/ingest";
    const DEST: &str = "https://ingest.example.test/v1";

    async fn open() -> (Store, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!("fornax-egress-{}.db", Uuid::new_v4()));
        (Store::open(&path).await.expect("open db"), path)
    }

    fn meta() -> BTreeSet<EgressContentClass> {
        [EgressContentClass::EvidenceMetadata].into_iter().collect()
    }

    async fn decide_upload(
        store: &Store,
        gate: bool,
    ) -> std::result::Result<EgressPermit, EgressDenial> {
        store
            .decide_egress(Purpose::EvidenceBatchUpload, URL, &meta(), gate)
            .await
    }

    /// Set up a fully authorized personal install.
    async fn authorized_personal(store: &Store) -> String {
        store
            .set_egress_profile(Profile::Personal, "test", false)
            .await
            .unwrap();
        store
            .add_egress_allowlist(Purpose::EvidenceBatchUpload, DEST, "test")
            .await
            .unwrap();
        store
            .grant_egress_consent(
                Purpose::EvidenceBatchUpload,
                DEST,
                &meta(),
                30,
                None,
                "test",
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_fresh_database_is_unconfigured_and_denies_everything() {
        let (store, path) = open().await;
        assert_eq!(
            store.egress_state().await.unwrap().profile,
            Profile::Unconfigured
        );
        assert_eq!(
            decide_upload(&store, true).await.unwrap_err(),
            EgressDenial::Unconfigured
        );
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn personal_upload_needs_profile_allowlist_consent_and_the_kill_switch() {
        let (store, path) = open().await;
        let id = authorized_personal(&store).await;
        let permit = decide_upload(&store, true).await.unwrap();
        assert_eq!(permit.consent_id(), Some(id.as_str()));
        assert_eq!(
            decide_upload(&store, false).await.unwrap_err(),
            EgressDenial::KillSwitchOff
        );

        // Revocation takes effect on the very next decision.
        assert!(store
            .revoke_egress_consent(&id, "test", "test")
            .await
            .unwrap());
        assert_eq!(
            decide_upload(&store, true).await.unwrap_err(),
            EgressDenial::ConsentRevoked
        );
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn entering_corporate_revokes_every_consent_and_nothing_can_reopen_upload() {
        let (store, path) = open().await;
        authorized_personal(&store).await;
        assert!(decide_upload(&store, true).await.is_ok());

        store
            .set_egress_profile(Profile::Corporate, "test", false)
            .await
            .unwrap();
        let state = store.egress_state().await.unwrap();
        assert!(state.consents.iter().all(|c| c.revoked_at.is_some()));
        assert_eq!(
            decide_upload(&store, true).await.unwrap_err(),
            EgressDenial::CorporateLocalOnly
        );

        // No new evidence/checkpoint consent can be recorded under corporate.
        let err = store
            .grant_egress_consent(
                Purpose::EvidenceBatchUpload,
                DEST,
                &meta(),
                30,
                None,
                "test",
            )
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::InvalidEgress(_)), "{err}");
        // Even a stale allowlist entry cannot help.
        assert_eq!(
            decide_upload(&store, true).await.unwrap_err(),
            EgressDenial::CorporateLocalOnly
        );

        // Leaving corporate needs an explicit confirmation, and prior
        // consents stay revoked and stale.
        assert!(store
            .set_egress_profile(Profile::Personal, "test", false)
            .await
            .is_err());
        store
            .set_egress_profile(Profile::Personal, "test", true)
            .await
            .unwrap();
        assert!(decide_upload(&store, true).await.is_err());
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn a_profile_change_makes_earlier_consents_stale() {
        let (store, path) = open().await;
        authorized_personal(&store).await;
        // Re-selecting personal bumps the generation.
        store
            .set_egress_profile(Profile::Personal, "test", false)
            .await
            .unwrap();
        assert_eq!(
            decide_upload(&store, true).await.unwrap_err(),
            EgressDenial::ConsentStale
        );
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn grants_are_refused_when_they_could_never_be_honoured() {
        let (store, path) = open().await;
        // Unconfigured: choose a profile first.
        assert!(store
            .grant_egress_consent(Purpose::EvidenceBatchUpload, DEST, &meta(), 30, None, "t")
            .await
            .is_err());
        store
            .set_egress_profile(Profile::Personal, "test", false)
            .await
            .unwrap();
        let claim_text: BTreeSet<_> = [EgressContentClass::ClaimText].into_iter().collect();
        for (purpose, classes, days) in [
            (Purpose::EvidenceBatchUpload, claim_text.clone(), 30),
            (Purpose::UploaderSpoolStream, meta(), 30),
            (Purpose::PolicyFetch, meta(), 30),
            (Purpose::EvidenceBatchUpload, BTreeSet::new(), 30),
            (Purpose::EvidenceBatchUpload, meta(), 0),
        ] {
            assert!(
                store
                    .grant_egress_consent(purpose, DEST, &classes, days, None, "t")
                    .await
                    .is_err(),
                "{purpose:?} {classes:?} {days}"
            );
        }
        assert!(store
            .grant_egress_consent(
                Purpose::EvidenceBatchUpload,
                "http://insecure.example.test/x",
                &meta(),
                30,
                None,
                "t"
            )
            .await
            .is_err());
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn a_corporate_judge_authorization_needs_a_reference_and_does_not_license_upload() {
        let (store, path) = open().await;
        store
            .set_egress_profile(Profile::Corporate, "test", false)
            .await
            .unwrap();
        let gateway = "https://llm.corp.example.test/v1";
        let judge_classes: BTreeSet<_> = [
            EgressContentClass::ClaimText,
            EgressContentClass::RedactedEvidencePayload,
        ]
        .into_iter()
        .collect();
        assert!(store
            .grant_egress_consent(
                Purpose::SemanticJudge,
                gateway,
                &judge_classes,
                30,
                None,
                "t"
            )
            .await
            .is_err());
        store
            .add_egress_allowlist(Purpose::SemanticJudge, gateway, "t")
            .await
            .unwrap();
        store
            .grant_egress_consent(
                Purpose::SemanticJudge,
                gateway,
                &judge_classes,
                30,
                Some("CORP-DPA-2026-17"),
                "t",
            )
            .await
            .unwrap();
        assert!(store
            .decide_egress(
                Purpose::SemanticJudge,
                "https://llm.corp.example.test/v1/chat",
                &judge_classes,
                false
            )
            .await
            .is_ok());
        assert_eq!(
            store
                .decide_egress(Purpose::EvidenceBatchUpload, gateway, &meta(), true)
                .await
                .unwrap_err(),
            EgressDenial::CorporateLocalOnly
        );
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn unreadable_egress_state_is_a_denial_not_a_pass() {
        let (store, path) = open().await;
        authorized_personal(&store).await;
        assert!(decide_upload(&store, true).await.is_ok());
        // Corrupt the state the way tampering or a bad write would.
        sqlx::query("UPDATE egress_consents SET data_classes = 'not json'")
            .execute(&store.pool)
            .await
            .unwrap();
        assert_eq!(
            decide_upload(&store, true).await.unwrap_err(),
            EgressDenial::StateUnreadable
        );
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn every_state_change_is_audited_and_the_chain_stays_valid() {
        let (store, path) = open().await;
        let id = authorized_personal(&store).await;
        store
            .revoke_egress_consent(&id, "test", "test")
            .await
            .unwrap();
        store
            .set_egress_profile(Profile::Corporate, "test", false)
            .await
            .unwrap();
        let actions: Vec<_> = store
            .audit_events()
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.event.action)
            .collect();
        for expected in [
            AuditAction::EgressProfileChanged,
            AuditAction::EgressAllowlistChanged,
            AuditAction::EgressConsentGranted,
            AuditAction::EgressConsentRevoked,
        ] {
            assert!(actions.contains(&expected), "missing {expected:?}");
        }
        assert!(matches!(
            store.verify_audit_chain().await.unwrap(),
            crate::ChainVerification::Valid
        ));
        std::fs::remove_file(&path).ok();
    }
}
