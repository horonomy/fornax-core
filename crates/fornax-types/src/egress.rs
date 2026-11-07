//! The single, fail-closed decision for every outbound network path
//! (FORNX-464).
//!
//! Before this module, "may this data leave the machine?" was answered
//! differently at each call site: one process-wide env var gated the audit
//! checkpoint push, the policy poll and the semantic judge had no egress gate
//! at all, and the separate uploader had only the env var. [`decide`] is the
//! one pure function all of them consult. It never performs IO and it denies
//! by default: an unconfigured install, a corporate install, a missing or
//! expired or revoked consent, a destination that is not on the allowlist,
//! and any content class that is not explicitly uploadable all end in an
//! [`EgressDenial`]. The only way to obtain an [`EgressPermit`] is a
//! successful [`decide`].
//!
//! Precedence, strongest first:
//! 1. **Corporate** never uploads evidence or checkpoints, whatever else is
//!    configured: no consent, allowlist entry, env var or published policy
//!    can override it. Its only outbound options are an allowlisted policy
//!    fetch (which carries no evidence) and an explicitly authorized
//!    semantic-judge gateway.
//! 2. **Unconfigured** (no profile has ever been chosen) behaves like
//!    corporate for evidence: nothing leaves.
//! 3. **Personal** may upload only under all of: a live consent for that
//!    exact purpose and destination, a matching allowlist entry, uploadable
//!    content classes, and the legacy `FORNAX_CLOUD_SYNC_ENABLED` kill
//!    switch. The env var can only tighten; it never grants.
//!
//! Loopback destinations (`127.0.0.1`, `::1`, `localhost`) do not leave the
//! machine, so a semantic judge on loopback needs no permit chain. They get
//! no such pass for evidence upload, checkpoints or policy fetch: those are
//! network paths by design and are tested through loopback mock servers.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::EgressContentClass;

/// Which egress profile this installation operates under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    /// No profile has ever been chosen. Fail closed.
    Unconfigured,
    /// Local-first dogfooding; batch upload only under consent.
    Personal,
    /// Local-only: no evidence or work data leaves the machine.
    Corporate,
}

impl Profile {
    pub fn as_str(self) -> &'static str {
        match self {
            Profile::Unconfigured => "unconfigured",
            Profile::Personal => "personal",
            Profile::Corporate => "corporate",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "unconfigured" => Some(Profile::Unconfigured),
            "personal" => Some(Profile::Personal),
            "corporate" => Some(Profile::Corporate),
            _ => None,
        }
    }
}

/// Why data is being sent. Consents and allowlist entries are per purpose: a
/// grant for one purpose never satisfies another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    /// Personal monthly/periodic metadata batch to the cloud.
    EvidenceBatchUpload,
    /// Signed audit-ledger checkpoint push.
    AuditCheckpoint,
    /// Fetching a published policy bundle. Carries no evidence.
    PolicyFetch,
    /// A semantic-judge model endpoint.
    SemanticJudge,
    /// The separate `fornax-cloud` uploader's spool stream. Reserved: not
    /// grantable in v0.0.9, so the uploader stays inert.
    UploaderSpoolStream,
}

impl Purpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Purpose::EvidenceBatchUpload => "evidence_batch_upload",
            Purpose::AuditCheckpoint => "audit_checkpoint",
            Purpose::PolicyFetch => "policy_fetch",
            Purpose::SemanticJudge => "semantic_judge",
            Purpose::UploaderSpoolStream => "uploader_spool_stream",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "evidence_batch_upload" => Some(Purpose::EvidenceBatchUpload),
            "audit_checkpoint" => Some(Purpose::AuditCheckpoint),
            "policy_fetch" => Some(Purpose::PolicyFetch),
            "semantic_judge" => Some(Purpose::SemanticJudge),
            "uploader_spool_stream" => Some(Purpose::UploaderSpoolStream),
            _ => None,
        }
    }

    /// Purposes that ship local evidence-derived data off the machine.
    fn ships_evidence(self) -> bool {
        matches!(
            self,
            Purpose::EvidenceBatchUpload | Purpose::AuditCheckpoint | Purpose::UploaderSpoolStream
        )
    }
}

/// The only content classes that may ever be uploaded (ADR-0012
/// `metadata_only`): ids, session id, provider, kinds, timestamps, verdict
/// enums, verifier names, hashes and counts. Claim text and redacted evidence
/// payloads are not uploadable.
pub fn is_uploadable_class(class: &EgressContentClass) -> bool {
    matches!(
        class,
        EgressContentClass::EvidenceMetadata
            | EgressContentClass::FindingVerdicts
            | EgressContentClass::CapabilityDeclarations
    )
}

/// Stable wire string for a content class (stored in consents).
pub fn class_str(class: &EgressContentClass) -> String {
    match class {
        EgressContentClass::FindingVerdicts => "finding_verdicts".into(),
        EgressContentClass::ClaimText => "claim_text".into(),
        EgressContentClass::EvidenceMetadata => "evidence_metadata".into(),
        EgressContentClass::RedactedEvidencePayload => "redacted_evidence_payload".into(),
        EgressContentClass::CapabilityDeclarations => "capability_declarations".into(),
        EgressContentClass::Unrecognized(s) => format!("unrecognized:{s}"),
    }
}

/// Inverse of [`class_str`]; an unknown string is `None` (never guessed).
pub fn parse_class(s: &str) -> Option<EgressContentClass> {
    match s {
        "finding_verdicts" => Some(EgressContentClass::FindingVerdicts),
        "claim_text" => Some(EgressContentClass::ClaimText),
        "evidence_metadata" => Some(EgressContentClass::EvidenceMetadata),
        "redacted_evidence_payload" => Some(EgressContentClass::RedactedEvidencePayload),
        "capability_declarations" => Some(EgressContentClass::CapabilityDeclarations),
        _ => None,
    }
}

/// A normalized destination: scheme, host, effective port and path prefix.
/// No userinfo, query or fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    /// Always starts with `/`; `/` matches every path.
    pub path_prefix: String,
}

pub fn is_loopback_host(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "::1" | "[::1]" | "localhost")
}

impl Destination {
    /// Parse a destination or request URL. Refuses anything that could smuggle
    /// a different effective host or carry data in the URL itself.
    pub fn parse(raw: &str) -> Result<Self, EgressDenial> {
        let url = url::Url::parse(raw).map_err(|_| EgressDenial::InvalidDestination)?;
        if !url.username().is_empty() || url.password().is_some() {
            return Err(EgressDenial::InvalidDestination);
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(EgressDenial::InvalidDestination);
        }
        let scheme = url.scheme().to_string();
        if scheme != "http" && scheme != "https" {
            return Err(EgressDenial::InvalidDestination);
        }
        let host = url
            .host_str()
            .filter(|h| !h.is_empty())
            .ok_or(EgressDenial::InvalidDestination)?
            .to_ascii_lowercase();
        let port = url
            .port_or_known_default()
            .ok_or(EgressDenial::InvalidDestination)?;
        // https everywhere; plain http only to a loopback literal.
        if scheme == "http" && !is_loopback_host(&host) {
            return Err(EgressDenial::InsecureDestination);
        }
        let mut path_prefix = url.path().to_string();
        if path_prefix.is_empty() {
            path_prefix = "/".into();
        }
        Ok(Destination {
            scheme,
            host,
            port,
            path_prefix,
        })
    }

    /// Canonical stored form, e.g. `https://ingest.example.test:443/v1`.
    pub fn canonical(&self) -> String {
        format!(
            "{}://{}:{}{}",
            self.scheme, self.host, self.port, self.path_prefix
        )
    }

    /// Whether a request to `request` falls under this destination: exact
    /// scheme, host and port, and a path that equals the prefix or continues
    /// it on a segment boundary (`/v1` matches `/v1` and `/v1/x`, not `/v10`).
    pub fn covers(&self, request: &Destination) -> bool {
        if self.scheme != request.scheme || self.host != request.host || self.port != request.port {
            return false;
        }
        if self.path_prefix == "/" {
            return true;
        }
        let prefix = self.path_prefix.trim_end_matches('/');
        request.path_prefix == prefix
            || request
                .path_prefix
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('/'))
    }
}

/// A recorded, scoped, expiring grant to send one purpose's data to one
/// destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Consent {
    pub id: String,
    pub purpose: Purpose,
    /// Canonical [`Destination`] string.
    pub destination: String,
    pub data_classes: BTreeSet<String>,
    pub granted_at: String,
    pub expires_at: String,
    pub revoked_at: Option<String>,
    /// The profile generation this was granted under; a later profile change
    /// bumps the generation and makes the consent stale.
    pub profile_generation: i64,
    /// Corporate processing authorization reference (required for a
    /// corporate semantic-judge gateway).
    pub authorization_ref: Option<String>,
}

/// An allowlisted destination for one purpose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowlistEntry {
    pub id: String,
    pub purpose: Purpose,
    /// Canonical [`Destination`] string.
    pub destination: String,
    pub removed: bool,
}

/// Everything [`decide`] needs, loaded from the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressState {
    pub profile: Profile,
    pub generation: i64,
    pub consents: Vec<Consent>,
    pub allowlist: Vec<AllowlistEntry>,
}

impl EgressState {
    /// The state of an install that has never configured egress.
    pub fn unconfigured() -> Self {
        EgressState {
            profile: Profile::Unconfigured,
            generation: 0,
            consents: Vec::new(),
            allowlist: Vec::new(),
        }
    }
}

/// What a caller asks to send, and where.
#[derive(Debug, Clone)]
pub struct EgressRequest<'a> {
    pub purpose: Purpose,
    pub url: &'a str,
    pub classes: &'a BTreeSet<EgressContentClass>,
    /// The legacy `FORNAX_CLOUD_SYNC_ENABLED` kill switch
    /// (`privacy::cloud_sync_allowed()`). Tighten-only: `false` denies
    /// evidence-shipping purposes, `true` grants nothing on its own.
    pub legacy_cloud_sync_gate_open: bool,
    /// RFC3339 "now", used for consent expiry.
    pub now: &'a str,
}

/// Why a send was refused. Stable, bounded reason codes: safe to log and to
/// show, never carries content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressDenial {
    InvalidDestination,
    InsecureDestination,
    /// The stored egress state could not be read or understood.
    StateUnreadable,
    /// No profile has been chosen.
    Unconfigured,
    /// The corporate profile forbids this purpose outright.
    CorporateLocalOnly,
    /// The legacy kill switch is off.
    KillSwitchOff,
    /// A content class that is never uploadable (or unknown) was requested.
    ContentClassNotUploadable,
    NoAllowlistEntry,
    NoConsent,
    ConsentExpired,
    ConsentRevoked,
    ConsentStale,
    ConsentDoesNotCoverClasses,
    /// Corporate semantic-judge gateway without an authorization reference.
    MissingAuthorizationRef,
    /// A purpose reserved for a later release.
    PurposeNotAvailable,
}

impl EgressDenial {
    pub fn code(self) -> &'static str {
        match self {
            EgressDenial::InvalidDestination => "invalid_destination",
            EgressDenial::InsecureDestination => "insecure_destination",
            EgressDenial::StateUnreadable => "state_unreadable",
            EgressDenial::Unconfigured => "unconfigured",
            EgressDenial::CorporateLocalOnly => "corporate_local_only",
            EgressDenial::KillSwitchOff => "kill_switch_off",
            EgressDenial::ContentClassNotUploadable => "content_class_not_uploadable",
            EgressDenial::NoAllowlistEntry => "no_allowlist_entry",
            EgressDenial::NoConsent => "no_consent",
            EgressDenial::ConsentExpired => "consent_expired",
            EgressDenial::ConsentRevoked => "consent_revoked",
            EgressDenial::ConsentStale => "consent_stale",
            EgressDenial::ConsentDoesNotCoverClasses => "consent_does_not_cover_classes",
            EgressDenial::MissingAuthorizationRef => "missing_authorization_ref",
            EgressDenial::PurposeNotAvailable => "purpose_not_available",
        }
    }
}

impl fmt::Display for EgressDenial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for EgressDenial {}

/// Proof that [`decide`] allowed one specific send. It cannot be constructed
/// outside this module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressPermit {
    purpose: Purpose,
    destination: String,
    consent_id: Option<String>,
}

impl EgressPermit {
    pub fn purpose(&self) -> Purpose {
        self.purpose
    }

    /// Canonical destination this permit was issued for.
    pub fn destination(&self) -> &str {
        &self.destination
    }

    /// The consent that authorized it, if one was required.
    pub fn consent_id(&self) -> Option<&str> {
        self.consent_id.as_deref()
    }

    /// Whether this permit authorizes a send to `url` for `purpose`. A caller
    /// holding a permit for one URL cannot reuse it for another.
    pub fn authorizes(&self, purpose: Purpose, url: &str) -> bool {
        self.purpose == purpose
            && Destination::parse(url)
                .map(|d| d.canonical() == self.destination)
                .unwrap_or(false)
    }
}

fn find_allowlist<'a>(
    state: &'a EgressState,
    purpose: Purpose,
    request: &Destination,
) -> Option<&'a AllowlistEntry> {
    state.allowlist.iter().find(|e| {
        !e.removed
            && e.purpose == purpose
            && Destination::parse(&e.destination)
                .map(|d| d.covers(request))
                .unwrap_or(false)
    })
}

fn find_consent<'a>(
    state: &'a EgressState,
    req: &EgressRequest<'_>,
    request: &Destination,
) -> Result<&'a Consent, EgressDenial> {
    let mut best: Result<&Consent, EgressDenial> = Err(EgressDenial::NoConsent);
    for consent in state
        .consents
        .iter()
        .filter(|c| c.purpose == req.purpose)
        .filter(|c| {
            Destination::parse(&c.destination)
                .map(|d| d.covers(request))
                .unwrap_or(false)
        })
    {
        // Strongest reason wins only if nothing usable exists.
        if consent.revoked_at.is_some() {
            best = best.or(Err(EgressDenial::ConsentRevoked));
            continue;
        }
        if consent.profile_generation != state.generation {
            best = best.or(Err(EgressDenial::ConsentStale));
            continue;
        }
        // RFC3339 UTC strings of equal shape compare chronologically; an
        // unparseable or non-UTC expiry is treated as expired (fail closed).
        if !is_before(req.now, &consent.expires_at) {
            best = best.or(Err(EgressDenial::ConsentExpired));
            continue;
        }
        let covers = req
            .classes
            .iter()
            .all(|class| consent.data_classes.contains(&class_str(class)));
        if !covers {
            best = best.or(Err(EgressDenial::ConsentDoesNotCoverClasses));
            continue;
        }
        return Ok(consent);
    }
    best
}

/// `a < b` for RFC3339 timestamps; any parse failure is `false`.
fn is_before(a: &str, b: &str) -> bool {
    match (
        chrono::DateTime::parse_from_rfc3339(a),
        chrono::DateTime::parse_from_rfc3339(b),
    ) {
        (Ok(a), Ok(b)) => a < b,
        _ => false,
    }
}

fn permit(purpose: Purpose, request: &Destination, consent: Option<&Consent>) -> EgressPermit {
    EgressPermit {
        purpose,
        destination: request.canonical(),
        consent_id: consent.map(|c| c.id.clone()),
    }
}

/// Decide whether `req` may leave the machine. Pure; denies by default.
pub fn decide(state: &EgressState, req: &EgressRequest<'_>) -> Result<EgressPermit, EgressDenial> {
    let request = Destination::parse(req.url)?;

    if req.purpose == Purpose::UploaderSpoolStream {
        // Reserved. The uploader reads a derived projection that never
        // authorizes this purpose in v0.0.9.
        return Err(EgressDenial::PurposeNotAvailable);
    }

    // A semantic judge on loopback never leaves the machine.
    if req.purpose == Purpose::SemanticJudge && is_loopback_host(&request.host) {
        return Ok(permit(req.purpose, &request, None));
    }

    // Unknown content classes are never sendable, whatever the purpose.
    if req
        .classes
        .iter()
        .any(|c| matches!(c, EgressContentClass::Unrecognized(_)))
    {
        return Err(EgressDenial::ContentClassNotUploadable);
    }

    match state.profile {
        Profile::Corporate => {
            if req.purpose.ships_evidence() {
                return Err(EgressDenial::CorporateLocalOnly);
            }
            if req.purpose == Purpose::PolicyFetch {
                find_allowlist(state, req.purpose, &request)
                    .ok_or(EgressDenial::NoAllowlistEntry)?;
                return Ok(permit(req.purpose, &request, None));
            }
            // SemanticJudge, non-loopback: only under a recorded corporate
            // processing authorization, on the allowlist.
            find_allowlist(state, req.purpose, &request).ok_or(EgressDenial::NoAllowlistEntry)?;
            let consent = find_consent(state, req, &request)?;
            if consent
                .authorization_ref
                .as_deref()
                .is_none_or(|r| r.trim().is_empty())
            {
                return Err(EgressDenial::MissingAuthorizationRef);
            }
            Ok(permit(req.purpose, &request, Some(consent)))
        }
        Profile::Unconfigured => {
            if req.purpose == Purpose::PolicyFetch {
                find_allowlist(state, req.purpose, &request)
                    .ok_or(EgressDenial::NoAllowlistEntry)?;
                return Ok(permit(req.purpose, &request, None));
            }
            Err(EgressDenial::Unconfigured)
        }
        Profile::Personal => {
            if req.purpose == Purpose::PolicyFetch {
                find_allowlist(state, req.purpose, &request)
                    .ok_or(EgressDenial::NoAllowlistEntry)?;
                return Ok(permit(req.purpose, &request, None));
            }
            if req.purpose.ships_evidence() {
                if !req.legacy_cloud_sync_gate_open {
                    return Err(EgressDenial::KillSwitchOff);
                }
                if !req.classes.iter().all(is_uploadable_class) {
                    return Err(EgressDenial::ContentClassNotUploadable);
                }
            }
            find_allowlist(state, req.purpose, &request).ok_or(EgressDenial::NoAllowlistEntry)?;
            let consent = find_consent(state, req, &request)?;
            Ok(permit(req.purpose, &request, Some(consent)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: &str = "2026-10-24T00:00:00Z";
    const LATER: &str = "2027-10-24T00:00:00Z";
    const EARLIER: &str = "2026-01-01T00:00:00Z";
    const URL: &str = "https://ingest.example.test/v1/ingest";

    fn classes(list: &[EgressContentClass]) -> BTreeSet<EgressContentClass> {
        list.iter().cloned().collect()
    }

    fn consent(purpose: Purpose, generation: i64) -> Consent {
        Consent {
            id: "c1".into(),
            purpose,
            destination: "https://ingest.example.test:443/v1".into(),
            data_classes: ["evidence_metadata", "finding_verdicts"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            granted_at: EARLIER.into(),
            expires_at: LATER.into(),
            revoked_at: None,
            profile_generation: generation,
            authorization_ref: None,
        }
    }

    fn allow(purpose: Purpose) -> AllowlistEntry {
        AllowlistEntry {
            id: "a1".into(),
            purpose,
            destination: "https://ingest.example.test:443/v1".into(),
            removed: false,
        }
    }

    fn personal(purpose: Purpose) -> EgressState {
        EgressState {
            profile: Profile::Personal,
            generation: 3,
            consents: vec![consent(purpose, 3)],
            allowlist: vec![allow(purpose)],
        }
    }

    fn req<'a>(
        purpose: Purpose,
        url: &'a str,
        c: &'a BTreeSet<EgressContentClass>,
        gate: bool,
    ) -> EgressRequest<'a> {
        EgressRequest {
            purpose,
            url,
            classes: c,
            legacy_cloud_sync_gate_open: gate,
            now: NOW,
        }
    }

    fn meta() -> BTreeSet<EgressContentClass> {
        classes(&[EgressContentClass::EvidenceMetadata])
    }

    #[test]
    fn personal_with_consent_allowlist_gate_and_metadata_is_the_only_allow_for_upload() {
        let state = personal(Purpose::EvidenceBatchUpload);
        let c = meta();
        let permit = decide(&state, &req(Purpose::EvidenceBatchUpload, URL, &c, true)).unwrap();
        assert_eq!(permit.consent_id(), Some("c1"));
        assert!(permit.authorizes(Purpose::EvidenceBatchUpload, URL));
        assert!(!permit.authorizes(Purpose::AuditCheckpoint, URL));
        assert!(!permit.authorizes(
            Purpose::EvidenceBatchUpload,
            "https://other.example.test/v1/ingest"
        ));
    }

    #[test]
    fn unconfigured_denies_all_evidence_purposes() {
        let c = meta();
        for purpose in [Purpose::EvidenceBatchUpload, Purpose::AuditCheckpoint] {
            assert_eq!(
                decide(&EgressState::unconfigured(), &req(purpose, URL, &c, true)).unwrap_err(),
                EgressDenial::Unconfigured
            );
        }
    }

    #[test]
    fn corporate_denies_evidence_even_with_consent_allowlist_and_gate() {
        let mut state = personal(Purpose::EvidenceBatchUpload);
        state.profile = Profile::Corporate;
        state.consents.push(consent(Purpose::AuditCheckpoint, 3));
        state.allowlist.push(allow(Purpose::AuditCheckpoint));
        let c = meta();
        for purpose in [
            Purpose::EvidenceBatchUpload,
            Purpose::AuditCheckpoint,
            Purpose::UploaderSpoolStream,
        ] {
            let denial = decide(&state, &req(purpose, URL, &c, true)).unwrap_err();
            assert!(
                matches!(
                    denial,
                    EgressDenial::CorporateLocalOnly | EgressDenial::PurposeNotAvailable
                ),
                "{purpose:?}: {denial}"
            );
        }
    }

    #[test]
    fn the_kill_switch_only_tightens() {
        let state = personal(Purpose::EvidenceBatchUpload);
        let c = meta();
        assert_eq!(
            decide(&state, &req(Purpose::EvidenceBatchUpload, URL, &c, false)).unwrap_err(),
            EgressDenial::KillSwitchOff
        );
        // Gate open without consent still denies.
        let mut no_consent = personal(Purpose::EvidenceBatchUpload);
        no_consent.consents.clear();
        assert_eq!(
            decide(
                &no_consent,
                &req(Purpose::EvidenceBatchUpload, URL, &c, true)
            )
            .unwrap_err(),
            EgressDenial::NoConsent
        );
    }

    #[test]
    fn expired_revoked_stale_and_uncovering_consents_deny() {
        let c = meta();
        let run = |mutate: &dyn Fn(&mut EgressState)| {
            let mut state = personal(Purpose::EvidenceBatchUpload);
            mutate(&mut state);
            decide(&state, &req(Purpose::EvidenceBatchUpload, URL, &c, true)).unwrap_err()
        };
        assert_eq!(
            run(&|s| s.consents[0].expires_at = EARLIER.into()),
            EgressDenial::ConsentExpired
        );
        assert_eq!(
            run(&|s| s.consents[0].expires_at = "not-a-date".into()),
            EgressDenial::ConsentExpired
        );
        assert_eq!(
            run(&|s| s.consents[0].revoked_at = Some(NOW.into())),
            EgressDenial::ConsentRevoked
        );
        assert_eq!(
            run(&|s| s.generation = 4),
            EgressDenial::ConsentStale,
            "a later profile change makes earlier consents stale"
        );
        assert_eq!(
            run(&|s| s.consents[0].data_classes.clear()),
            EgressDenial::ConsentDoesNotCoverClasses
        );
    }

    #[test]
    fn a_consent_for_one_purpose_never_satisfies_another() {
        let state = personal(Purpose::EvidenceBatchUpload);
        let c = meta();
        assert_eq!(
            decide(&state, &req(Purpose::AuditCheckpoint, URL, &c, true)).unwrap_err(),
            EgressDenial::NoAllowlistEntry
        );
    }

    #[test]
    fn claim_text_and_redacted_payloads_are_never_uploadable() {
        let mut state = personal(Purpose::EvidenceBatchUpload);
        state.consents[0].data_classes.insert("claim_text".into());
        state.consents[0]
            .data_classes
            .insert("redacted_evidence_payload".into());
        for class in [
            EgressContentClass::ClaimText,
            EgressContentClass::RedactedEvidencePayload,
            EgressContentClass::Unrecognized("raw_prompt".into()),
        ] {
            let c = classes(std::slice::from_ref(&class));
            assert_eq!(
                decide(&state, &req(Purpose::EvidenceBatchUpload, URL, &c, true)).unwrap_err(),
                EgressDenial::ContentClassNotUploadable,
                "{class:?}"
            );
        }
    }

    #[test]
    fn destinations_match_exactly_and_refuse_smuggling() {
        let state = personal(Purpose::EvidenceBatchUpload);
        let c = meta();
        let denied = |url: &str| {
            decide(&state, &req(Purpose::EvidenceBatchUpload, url, &c, true)).unwrap_err()
        };
        // Path boundary: /v10 is not under /v1.
        assert_eq!(
            denied("https://ingest.example.test/v10/ingest"),
            EgressDenial::NoAllowlistEntry
        );
        assert_eq!(
            denied("https://ingest.example.test:8443/v1/ingest"),
            EgressDenial::NoAllowlistEntry
        );
        assert_eq!(
            denied("https://evil.example.test/v1/ingest"),
            EgressDenial::NoAllowlistEntry
        );
        assert_eq!(
            denied("https://user:pw@ingest.example.test/v1/ingest"),
            EgressDenial::InvalidDestination
        );
        assert_eq!(
            denied("https://ingest.example.test/v1/ingest?x=1"),
            EgressDenial::InvalidDestination
        );
        assert_eq!(
            denied("http://ingest.example.test/v1/ingest"),
            EgressDenial::InsecureDestination
        );
        assert_eq!(
            denied("ftp://ingest.example.test/"),
            EgressDenial::InvalidDestination
        );
        assert_eq!(denied("not a url"), EgressDenial::InvalidDestination);
        // Host case is normalized, an exact match still passes.
        assert!(decide(
            &state,
            &req(
                Purpose::EvidenceBatchUpload,
                "https://INGEST.example.test/v1/ingest",
                &c,
                true
            )
        )
        .is_ok());
    }

    #[test]
    fn policy_fetch_needs_only_an_allowlist_entry_and_carries_no_evidence() {
        let c = BTreeSet::new();
        let mut state = EgressState::unconfigured();
        assert_eq!(
            decide(&state, &req(Purpose::PolicyFetch, URL, &c, false)).unwrap_err(),
            EgressDenial::NoAllowlistEntry
        );
        state.allowlist.push(allow(Purpose::PolicyFetch));
        assert!(decide(&state, &req(Purpose::PolicyFetch, URL, &c, false)).is_ok());
        state.profile = Profile::Corporate;
        assert!(decide(&state, &req(Purpose::PolicyFetch, URL, &c, false)).is_ok());
        state.allowlist[0].removed = true;
        assert_eq!(
            decide(&state, &req(Purpose::PolicyFetch, URL, &c, false)).unwrap_err(),
            EgressDenial::NoAllowlistEntry
        );
    }

    #[test]
    fn loopback_judge_is_always_allowed_but_loopback_evidence_upload_is_not() {
        let c = classes(&[
            EgressContentClass::ClaimText,
            EgressContentClass::RedactedEvidencePayload,
        ]);
        let judge = "http://localhost:11434/v1";
        for profile in [Profile::Unconfigured, Profile::Personal, Profile::Corporate] {
            let mut state = EgressState::unconfigured();
            state.profile = profile;
            assert!(
                decide(&state, &req(Purpose::SemanticJudge, judge, &c, false)).is_ok(),
                "{profile:?}"
            );
        }
        let m = meta();
        assert!(decide(
            &EgressState::unconfigured(),
            &req(
                Purpose::EvidenceBatchUpload,
                "http://127.0.0.1:9/x",
                &m,
                true
            )
        )
        .is_err());
    }

    #[test]
    fn a_non_loopback_judge_in_corporate_needs_an_authorization_reference() {
        let gateway = "https://llm.corp.example.test/v1";
        let c = classes(&[
            EgressContentClass::ClaimText,
            EgressContentClass::RedactedEvidencePayload,
        ]);
        let mut corp_consent = consent(Purpose::SemanticJudge, 7);
        corp_consent.destination = "https://llm.corp.example.test:443/v1".into();
        corp_consent.data_classes = ["claim_text", "redacted_evidence_payload"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let mut corp_allow = allow(Purpose::SemanticJudge);
        corp_allow.destination = "https://llm.corp.example.test:443/v1".into();
        let mut state = EgressState {
            profile: Profile::Corporate,
            generation: 7,
            consents: vec![corp_consent],
            allowlist: vec![corp_allow],
        };
        assert_eq!(
            decide(&state, &req(Purpose::SemanticJudge, gateway, &c, false)).unwrap_err(),
            EgressDenial::MissingAuthorizationRef
        );
        state.consents[0].authorization_ref = Some("CORP-DPA-2026-17".into());
        assert!(decide(&state, &req(Purpose::SemanticJudge, gateway, &c, false)).is_ok());
        // The same authorization never licenses evidence upload.
        let m = meta();
        assert_eq!(
            decide(
                &state,
                &req(Purpose::EvidenceBatchUpload, gateway, &m, true)
            )
            .unwrap_err(),
            EgressDenial::CorporateLocalOnly
        );
    }

    #[test]
    fn the_uploader_stream_purpose_is_reserved_and_never_authorized() {
        let state = personal(Purpose::UploaderSpoolStream);
        let c = meta();
        assert_eq!(
            decide(&state, &req(Purpose::UploaderSpoolStream, URL, &c, true)).unwrap_err(),
            EgressDenial::PurposeNotAvailable
        );
    }

    #[test]
    fn destination_covers_on_segment_boundaries_only() {
        let base = Destination::parse("https://h.example.test/v1").unwrap();
        for ok in ["https://h.example.test/v1", "https://h.example.test/v1/x/y"] {
            assert!(base.covers(&Destination::parse(ok).unwrap()), "{ok}");
        }
        for bad in [
            "https://h.example.test/v10",
            "https://h.example.test/",
            "https://h.example.test/v",
        ] {
            assert!(!base.covers(&Destination::parse(bad).unwrap()), "{bad}");
        }
        let root = Destination::parse("https://h.example.test").unwrap();
        assert!(root.covers(&Destination::parse("https://h.example.test/anything").unwrap()));
    }
}
