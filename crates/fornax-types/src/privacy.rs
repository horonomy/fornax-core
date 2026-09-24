//! Cloud-egress policy gate (FORNX-33). No cloud sync code exists yet
//! (FORNX-41), but the policy primitive is introduced now, ahead of it, so
//! that ticket has no path to silently uploading anything: it must consult
//! this gate, which defaults to closed.
//!
//! [`longitudinal_reliability_collection_allowed`] (FORNX-106) is a second,
//! independent gate following the exact same shape — added here rather than
//! duplicated, since both gates answer the same kind of question ("has the
//! user explicitly opted in to something beyond ordinary local operation?").
//! It is deliberately a *different* gate from [`cloud_sync_allowed`]: cloud
//! sync is about data leaving the machine at all, while this one is about
//! whether *local* aggregation is allowed to reach across sessions to build
//! cross-session reliability statistics in the first place — a tenant could
//! reasonably permit one without the other.

/// Whether any Fornax-originated data may leave this machine. Defaults to
/// `false` — cloud sync is opt-in, never assumed. FORNX-41's uploader must
/// check this before any network call, not just at startup, so a user can
/// disable sync mid-session and have it take effect immediately.
pub fn cloud_sync_allowed() -> bool {
    std::env::var("FORNAX_CLOUD_SYNC_ENABLED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Whether raw, per-session local evidence may be aggregated across sessions
/// into longitudinal reliability statistics (FORNX-106 AC2: "protected local
/// raw evidence is not centralized merely to build reliability statistics").
/// Defaults to `false` — ordinary Fornax operation (collecting evidence for
/// *one* session's claims, replaying *one* frozen manifest) never needs this
/// flag and is unaffected by it either way; only a mechanism that reaches
/// across sessions to build a [`crate::ReliabilityContextKey`] cohort or a
/// derived [`crate::RetentionClass::AggregatedFeature`]/`DerivedFinding`
/// record must check this first.
pub fn longitudinal_reliability_collection_allowed() -> bool {
    std::env::var("FORNAX_LONGITUDINAL_COLLECTION_ENABLED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    // One test, not several: std::env::set_var is process-global and cargo
    // runs tests in parallel by default, so splitting these across tests
    // would race on the same env var.
    #[test]
    fn cloud_sync_gate_defaults_closed_and_requires_an_explicit_true_value() {
        std::env::remove_var("FORNAX_CLOUD_SYNC_ENABLED");
        assert!(!cloud_sync_allowed(), "must default to disabled when unset");

        std::env::set_var("FORNAX_CLOUD_SYNC_ENABLED", "1");
        assert!(cloud_sync_allowed());

        std::env::set_var("FORNAX_CLOUD_SYNC_ENABLED", "true");
        assert!(cloud_sync_allowed());

        std::env::set_var("FORNAX_CLOUD_SYNC_ENABLED", "yes");
        assert!(
            !cloud_sync_allowed(),
            "only '1'/'true' enable sync, not other truthy-looking strings"
        );

        std::env::remove_var("FORNAX_CLOUD_SYNC_ENABLED");
    }

    // One test, not several — same std::env::set_var race-avoidance reason
    // as `cloud_sync_gate_defaults_closed_and_requires_an_explicit_true_value`.
    #[test]
    fn longitudinal_collection_gate_defaults_closed_and_requires_an_explicit_true_value() {
        std::env::remove_var("FORNAX_LONGITUDINAL_COLLECTION_ENABLED");
        assert!(
            !longitudinal_reliability_collection_allowed(),
            "must default to disabled when unset (AC2: no centralization by default)"
        );

        std::env::set_var("FORNAX_LONGITUDINAL_COLLECTION_ENABLED", "1");
        assert!(longitudinal_reliability_collection_allowed());

        std::env::set_var("FORNAX_LONGITUDINAL_COLLECTION_ENABLED", "true");
        assert!(longitudinal_reliability_collection_allowed());

        std::env::set_var("FORNAX_LONGITUDINAL_COLLECTION_ENABLED", "yes");
        assert!(
            !longitudinal_reliability_collection_allowed(),
            "only '1'/'true' enable collection, not other truthy-looking strings"
        );

        std::env::remove_var("FORNAX_LONGITUDINAL_COLLECTION_ENABLED");
    }
}
