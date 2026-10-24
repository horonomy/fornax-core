//! `fornax egress` (FORNX-464): the one place an operator chooses whether and
//! where Fornax data may leave this machine.
//!
//! Nothing is sent anywhere until a profile is chosen. `corporate` is
//! local-only and cannot be overridden by a consent, an allowlist entry, an
//! env var or a published policy; `personal` ships only metadata, only to an
//! allowlisted destination, only under a live, expiring consent. Reads and
//! writes `$FORNAX_HOME/fornax.db` directly (no daemon required); the daemon
//! re-reads the persisted state on every outbound attempt, so a change here
//! takes effect on the next request.
//!
//! Nothing here sends data: it records the profile, allowlist and consents
//! that the daemon's scheduled monthly upload (and `fornax upload run`) consult
//! before every request. `fornax export-spool` remains a manual, per-session
//! export.

use std::collections::BTreeSet;

use clap::Subcommand;
use fornax_types::egress::{self, Profile, Purpose};
use fornax_types::EgressContentClass;

#[derive(Subcommand)]
pub enum EgressAction {
    /// Show the profile, consents, allowlist and what is currently denied.
    Status,
    /// Choose the egress profile: `personal`, `corporate` or `unconfigured`.
    ///
    /// Entering `corporate` revokes every consent. Leaving it needs
    /// `--confirm-leave-corporate`. Every change makes earlier consents stale.
    ProfileSet {
        profile: String,
        #[arg(long)]
        confirm_leave_corporate: bool,
    },
    /// Record a consent: one purpose, one destination, named data classes,
    /// expiring. Evidence purposes accept metadata classes only.
    ConsentGrant {
        /// evidence_batch_upload | audit_checkpoint | semantic_judge
        #[arg(long)]
        purpose: String,
        /// Destination URL (https; http only for loopback). Path is a prefix.
        #[arg(long)]
        destination: String,
        /// Comma-separated: evidence_metadata, finding_verdicts,
        /// capability_declarations (and, for semantic_judge only,
        /// claim_text, redacted_evidence_payload).
        #[arg(long)]
        classes: String,
        #[arg(long, default_value_t = egress_default_days())]
        days: i64,
        /// Corporate processing authorization reference (required for a
        /// corporate semantic_judge gateway).
        #[arg(long)]
        authorization_ref: Option<String>,
    },
    /// Revoke a consent by id.
    ConsentRevoke {
        id: String,
        #[arg(long, default_value = "revoked by operator")]
        reason: String,
    },
    /// Allowlist a destination for one purpose.
    AllowAdd {
        /// evidence_batch_upload | audit_checkpoint | policy_fetch | semantic_judge
        #[arg(long)]
        purpose: String,
        destination: String,
    },
    /// Remove an allowlist entry by id.
    AllowRemove { id: String },
}

fn egress_default_days() -> i64 {
    fornax_store::egress::DEFAULT_CONSENT_DAYS
}

const SOURCE: &str = "cli";

fn parse_purpose(s: &str) -> anyhow::Result<Purpose> {
    Purpose::parse(s).ok_or_else(|| {
        anyhow::anyhow!(
            "unknown purpose '{s}' (evidence_batch_upload, audit_checkpoint, policy_fetch, semantic_judge)"
        )
    })
}

fn parse_classes(s: &str) -> anyhow::Result<BTreeSet<EgressContentClass>> {
    s.split(',')
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .map(|c| egress::parse_class(c).ok_or_else(|| anyhow::anyhow!("unknown data class '{c}'")))
        .collect()
}

pub async fn handle(action: EgressAction, fornax_home: &std::path::Path) -> anyhow::Result<()> {
    let store = fornax_store::Store::open(fornax_home.join("fornax.db")).await?;
    let projection = fornax_home.join("egress-projection.json");
    let mutated = !matches!(action, EgressAction::Status);

    match action {
        EgressAction::Status => print_status(&store).await?,
        EgressAction::ProfileSet {
            profile,
            confirm_leave_corporate,
        } => {
            let profile = Profile::parse(&profile)
                .ok_or_else(|| anyhow::anyhow!("unknown profile '{profile}'"))?;
            store
                .set_egress_profile(profile, SOURCE, confirm_leave_corporate)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("fornax egress: profile is now {}", profile.as_str());
            if profile == Profile::Corporate {
                println!("  corporate is local-only; every existing consent was revoked");
            }
        }
        EgressAction::ConsentGrant {
            purpose,
            destination,
            classes,
            days,
            authorization_ref,
        } => {
            let id = store
                .grant_egress_consent(
                    parse_purpose(&purpose)?,
                    &destination,
                    &parse_classes(&classes)?,
                    days,
                    authorization_ref.as_deref(),
                    SOURCE,
                )
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("fornax egress: recorded consent {id} (expires in {days} days)");
        }
        EgressAction::ConsentRevoke { id, reason } => {
            if store
                .revoke_egress_consent(&id, &reason, SOURCE)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?
            {
                println!("fornax egress: revoked consent {id}");
            } else {
                println!("fornax egress: no live consent {id}");
            }
        }
        EgressAction::AllowAdd {
            purpose,
            destination,
        } => {
            let id = store
                .add_egress_allowlist(parse_purpose(&purpose)?, &destination, SOURCE)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("fornax egress: allowlisted {destination} as {id}");
        }
        EgressAction::AllowRemove { id } => {
            if store
                .remove_egress_allowlist(&id, SOURCE)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?
            {
                println!("fornax egress: removed allowlist entry {id}");
            } else {
                println!("fornax egress: no live allowlist entry {id}");
            }
        }
    }

    if mutated {
        store
            .write_egress_projection(&projection)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    Ok(())
}

async fn print_status(store: &fornax_store::Store) -> anyhow::Result<()> {
    let state = store
        .egress_state()
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    println!(
        "profile: {} (generation {})",
        state.profile.as_str(),
        state.generation
    );
    match state.profile {
        Profile::Unconfigured => println!(
            "  no profile chosen: NOTHING leaves this machine (policy fetch only if allowlisted)"
        ),
        Profile::Corporate => println!(
            "  corporate is local-only: no evidence or checkpoint is uploaded and the monthly upload never \
             runs, whatever else is configured. Only an allowlisted policy fetch (no local data) \
             and an allowlisted semantic-judge gateway with a recorded corporate processing \
             authorization may make requests. A local setting, not organization-enforced policy"
        ),
        Profile::Personal => println!(
            "  personal: metadata only, only to an allowlisted destination, only under a live consent, \
             and only while FORNAX_CLOUD_SYNC_ENABLED=1"
        ),
    }
    println!("allowlist:");
    let mut any = false;
    for e in state.allowlist.iter().filter(|e| !e.removed) {
        any = true;
        println!("  {} {} {}", e.id, e.purpose.as_str(), e.destination);
    }
    if !any {
        println!("  (empty)");
    }
    println!("consents:");
    let mut any = false;
    for c in &state.consents {
        any = true;
        let standing = if c.revoked_at.is_some() {
            "revoked"
        } else if c.profile_generation != state.generation {
            "stale (profile changed since it was granted)"
        } else {
            "live"
        };
        println!(
            "  {} {} {} classes=[{}] expires {} -- {standing}",
            c.id,
            c.purpose.as_str(),
            c.destination,
            c.data_classes.iter().cloned().collect::<Vec<_>>().join(","),
            c.expires_at,
        );
    }
    if !any {
        println!("  (none)");
    }
    println!(
        "scheduled/monthly upload: the daemon sends each closed month automatically under a live \
         personal consent (see `fornax upload status`); never under corporate or unconfigured"
    );
    Ok(())
}
