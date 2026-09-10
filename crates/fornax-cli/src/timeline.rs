//! `fornax timeline` (FORNX-321): reconstruct one finding's -- or one
//! session's -- full provenance from the local store alone: who (which
//! verifier) computed it, what evidence backed it (with per-item trust
//! class/provenance), the fused five-state verdict, this device's current
//! local policy state, and the local audit ledger.
//!
//! Reads `$FORNAX_HOME/fornax.db` directly (`fornax_store::Store`),
//! mirroring `fornax audit list`/`fornax audit verify`'s (FORNX-315)
//! precedent rather than the daemon's HTTP API -- see `main.rs`'s
//! `Commands::Audit` doc comment for the same rationale, which applies here
//! unchanged: this is local file state, not a daemon-mediated view, and the
//! whole point of an incident timeline is that it still works when the
//! daemon is down. No network client of any kind is reachable from this
//! module (see the offline test at the bottom of this file).
//!
//! # Scope boundary (read this before extending)
//!
//! 1. **The fused verdict is rendered verbatim, never re-derived.**
//!    `finding.verdict` is the tag `fornax-verify`'s fusion pipeline already
//!    computed and `Store::insert_finding` persisted (ADR-0001 D4: the
//!    five-state vocabulary -- `verified`/`unverified`/`contradicted`/
//!    `review`/`unavailable` -- is never collapsed to a boolean/score). This
//!    module does not call `fornax-verify` a second time; it prints exactly
//!    the string already on the `findings` row.
//! 2. **Per-evidence trust/provenance is rendered as-is, never reconstructed.**
//!    `Evidence::source` is either `None` (this record predates FORNX-157's
//!    sensor contract entirely) or `Some(EvidenceSource)`, whose
//!    `tamper_boundary` field independently defaults (via `#[serde(default)]`,
//!    see `sensor::TamperBoundary`'s `Default` impl) to the honest string
//!    `"unknown (record predates tamper-boundary tracking)"` for a record
//!    written before FORNX-159 added that field -- this module never
//!    synthesizes that string (or any other) from `trust_class`; it only
//!    reads the field. See `render_evidence_line`'s test coverage below.
//! 3. **Policy state is CURRENT, not point-in-time.** `Store::load_policy_cache`
//!    reports what this device's policy cache holds *right now* -- there is
//!    no column anywhere in this schema recording which policy revision was
//!    active when a given session ran, so this module cannot answer "what
//!    was in force when this finding was computed", only "what is in force
//!    on this device today". The rendered output says so explicitly rather
//!    than implying point-in-time correctness it cannot back up.
//! 4. **Audit-ledger events are NOT scoped to the session/finding.**
//!    `fornax_types::audit::AuditEvent` (mirroring fornax-cloud's ADR 0011
//!    schema exactly) carries no `session_id`/`claim_id`/`finding_id` field,
//!    and `AuditTargetKind` has no `finding`/`session` member -- the local
//!    audit ledger is an administrative trail (policy publish/rollback,
//!    permission checks), not a per-session record. There is therefore no
//!    real join key between a finding and an audit event, so this module
//!    does not fabricate one: it surfaces the full local ledger, labeled
//!    plainly as unscoped, for time-proximity correlation by a human --
//!    never claims a specific entry "belongs to" this session/finding.

use anyhow::{anyhow, bail};
use fornax_store::Store;
use std::collections::BTreeSet;
use uuid::Uuid;

/// `fornax timeline --finding <id>`: one finding's full local provenance.
pub async fn render_finding_timeline(store: &Store, finding_id: &str) -> anyhow::Result<String> {
    let finding = store
        .finding_by_id(finding_id)
        .await?
        .ok_or_else(|| anyhow!("no finding with id {finding_id}"))?;

    let evidence_ids: Vec<Uuid> = serde_json::from_str(&finding.evidence_ids)
        .map_err(|e| anyhow!("finding {finding_id}: corrupt evidence_ids: {e}"))?;
    let wanted: BTreeSet<Uuid> = evidence_ids.iter().copied().collect();

    let outcome = store.evidence_for_session(&finding.session_id).await?;
    // Preserve `finding.evidence_ids`' own order (the order the verifier
    // actually consulted them in), not whatever order the session-wide
    // query happens to return.
    let mut evidence_by_id: std::collections::HashMap<Uuid, &fornax_types::Evidence> = outcome
        .evidence
        .iter()
        .filter(|e| wanted.contains(&e.id))
        .map(|e| (e.id, e))
        .collect();

    let mut out = String::new();
    out.push_str(&format!("finding: {}\n", finding.id));
    out.push_str(&format!("  session:       {}\n", finding.session_id));
    out.push_str(&format!("  claim:         {}\n", finding.claim_id));
    out.push_str(&format!("  claim_text:    {}\n", finding.claim_text));
    out.push_str(&format!("  verifier:      {}\n", finding.verifier_name));
    // The fused five-state verdict, rendered exactly as persisted -- see
    // this module's doc comment, point 1.
    out.push_str(&format!("  verdict:       {}\n", finding.verdict));
    out.push_str(&format!("  rationale:     {}\n", finding.rationale));
    out.push_str(&format!("  computed_at:   {}\n", finding.computed_at));

    out.push_str(&format!("  evidence ({}):\n", evidence_ids.len()));
    for id in &evidence_ids {
        match evidence_by_id.remove(id) {
            Some(e) => out.push_str(&render_evidence_line(e)),
            None => out.push_str(&format!(
                "    - {id}: NOT FOUND in session {} (referenced by finding but no matching evidence row)\n",
                finding.session_id
            )),
        }
    }

    out.push_str(&render_policy_state_section(store).await?);
    out.push_str(&render_audit_ledger_section(store).await?);
    Ok(out)
}

/// `fornax timeline --session <id>`: every finding for one session, each
/// rendered the same way `render_finding_timeline` renders one finding
/// (minus the per-finding policy/audit sections, which are device-wide, not
/// per-finding, and are rendered exactly once at the end instead).
pub async fn render_session_timeline(store: &Store, session_id: &str) -> anyhow::Result<String> {
    let findings = store.findings_for_session(session_id).await?;
    if findings.is_empty() {
        bail!("no findings for session {session_id}");
    }

    let mut out = String::new();
    out.push_str(&format!(
        "session: {session_id} ({} finding{})\n",
        findings.len(),
        if findings.len() == 1 { "" } else { "s" }
    ));
    for finding in &findings {
        let evidence_ids: Vec<Uuid> = serde_json::from_str(&finding.evidence_ids)
            .map_err(|e| anyhow!("finding {}: corrupt evidence_ids: {e}", finding.id))?;
        let wanted: BTreeSet<Uuid> = evidence_ids.iter().copied().collect();
        let outcome = store.evidence_for_session(session_id).await?;
        let mut evidence_by_id: std::collections::HashMap<Uuid, &fornax_types::Evidence> = outcome
            .evidence
            .iter()
            .filter(|e| wanted.contains(&e.id))
            .map(|e| (e.id, e))
            .collect();

        out.push_str(&format!("\nfinding: {}\n", finding.id));
        out.push_str(&format!("  claim:         {}\n", finding.claim_id));
        out.push_str(&format!("  claim_text:    {}\n", finding.claim_text));
        out.push_str(&format!("  verifier:      {}\n", finding.verifier_name));
        out.push_str(&format!("  verdict:       {}\n", finding.verdict));
        out.push_str(&format!("  rationale:     {}\n", finding.rationale));
        out.push_str(&format!("  computed_at:   {}\n", finding.computed_at));
        out.push_str(&format!("  evidence ({}):\n", evidence_ids.len()));
        for id in &evidence_ids {
            match evidence_by_id.remove(id) {
                Some(e) => out.push_str(&render_evidence_line(e)),
                None => out.push_str(&format!(
                    "    - {id}: NOT FOUND in session {session_id} (referenced by finding but no matching evidence row)\n"
                )),
            }
        }
    }

    out.push_str(&render_policy_state_section(store).await?);
    out.push_str(&render_audit_ledger_section(store).await?);
    Ok(out)
}

/// One evidence item's line -- id, kind, provenance string, and (this
/// ticket's whole point) its trust class + tamper-boundary description,
/// rendered exactly as stored. Never re-derives either from the other; see
/// this module's doc comment, point 2.
fn render_evidence_line(e: &fornax_types::Evidence) -> String {
    match &e.source {
        Some(source) => format!(
            "    - {id} kind={kind:?} trust_class={trust:?} collection_method={method:?} \
             tamper_boundary={boundary:?} provenance={provenance}\n",
            id = e.id,
            kind = e.kind,
            trust = source.trust_class,
            method = source.collection_method,
            boundary = source.tamper_boundary.description,
            provenance = e.provenance,
        ),
        None => format!(
            "    - {id} kind={kind:?} trust_class=unknown (no provenance recorded -- \
             evidence predates FORNX-157's sensor contract) provenance={provenance}\n",
            id = e.id,
            kind = e.kind,
            provenance = e.provenance,
        ),
    }
}

/// See this module's doc comment, point 3 -- CURRENT device policy state
/// only, explicitly labeled as such.
async fn render_policy_state_section(store: &Store) -> anyhow::Result<String> {
    let loaded = store
        .load_policy_cache(None, chrono::Utc::now())
        .await
        .map_err(|e| anyhow!("reading local policy cache: {e}"))?;

    let mut out = String::new();
    out.push_str(
        "policy state (CURRENT device cache -- NOT point-in-time for this session/finding; \
         no session-to-policy-revision linkage is stored anywhere in this schema):\n",
    );
    match loaded.state.active {
        Some(generation) if !generation.members.is_empty() => {
            for member in &generation.members {
                out.push_str(&format!(
                    "  - policy_id={:?} revision={} revision_digest={} activated_at={}\n",
                    member.policy_id,
                    member.revision,
                    member.revision_digest,
                    member.first_activated_at
                ));
            }
        }
        _ => out.push_str("  (no active policy cache generation on this device)\n"),
    }
    Ok(out)
}

/// See this module's doc comment, point 4 -- the full local ledger,
/// unscoped, explicitly labeled as such.
async fn render_audit_ledger_section(store: &Store) -> anyhow::Result<String> {
    let events = store.audit_events().await?;
    let mut out = String::new();
    out.push_str(&format!(
        "local audit ledger (NOT scoped to this session/finding -- {} carries no session/finding \
         linkage; shown for time-proximity correlation only, {} event{} total):\n",
        "fornax_types::audit::AuditEvent",
        events.len(),
        if events.len() == 1 { "" } else { "s" }
    ));
    for entry in &events {
        out.push_str(&format!(
            "  - seq={} occurred_at={} action={:?} outcome={:?} target={:?}\n",
            entry.seq,
            entry.event.occurred_at,
            entry.event.action,
            entry.event.outcome,
            entry.event.target
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fornax_types::{
        audit::{AuditAction, AuditActor, AuditEvent, AuditExportClass, AuditOutcome, AuditTarget},
        AgentEvent, Claim, EventKind, Evidence, EvidenceKind, Finding, Provider, Verdict,
    };

    fn tmp_db_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "fornax-cli-timeline-test-{name}-{}.db",
            Uuid::new_v4()
        ))
    }

    async fn seeded_store_with_finding(
        path: &std::path::Path,
        evidence_source: Option<fornax_types::sensor::EvidenceSource>,
    ) -> (Store, Uuid, Uuid) {
        let store = Store::open(path).await.expect("open db");

        let event = AgentEvent {
            id: Uuid::new_v4(),
            session_id: "s-timeline".into(),
            provider: Provider::Codex,
            kind: EventKind::PostToolUse,
            observed_at: "2026-01-01T00:00:00Z".into(),
            tool_name: Some("exec_command".into()),
            tool_input: Some(serde_json::json!(["pytest"])),
            tool_response: Some(serde_json::json!({"exit_code": 0})),
            raw: serde_json::json!({"type": "exec_command_end"}),
        };
        store.insert_event(&event).await.expect("insert event");

        let evidence = Evidence {
            id: Uuid::new_v4(),
            session_id: "s-timeline".into(),
            source_event_id: event.id,
            kind: EvidenceKind::ExitCode,
            observed_at: "2026-01-01T00:00:01Z".into(),
            payload: serde_json::json!({"command": ["pytest"], "exit_code": 0}),
            provenance: "codex:rollout:exec_command_end".into(),
            source: evidence_source,
            extension: None,
            evidence_purged: false,
        };
        store
            .insert_evidence(&evidence)
            .await
            .expect("insert evidence");

        let claim = Claim {
            id: Uuid::new_v4(),
            session_id: "s-timeline".into(),
            source_event_id: event.id,
            text: "All tests passed.".into(),
            subject: "test_result".into(),
            claimed_at: "2026-01-01T00:00:02Z".into(),
        };
        store.insert_claim(&claim).await.expect("insert claim");

        let finding = Finding {
            id: Uuid::new_v4(),
            claim_id: claim.id,
            verdict: Verdict::Verified,
            evidence_ids: vec![evidence.id],
            verifier_name: "TestResultVerifier".into(),
            rationale: "exit_code == 0".into(),
            computed_at: "2026-01-01T00:00:03Z".into(),
        };
        store
            .insert_finding(&finding)
            .await
            .expect("insert finding");

        (store, finding.id, evidence.id)
    }

    // -------------------------------------------------------------------
    // AC1: evidence with trust class/provenance, verifier name, full
    // five-state verdict, and a documented policy digest.
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn finding_timeline_includes_verifier_verdict_and_evidence_trust_class() {
        let path = tmp_db_path("full-render");
        let source = fornax_types::sensor::EvidenceSource::now(
            "ExitCodeSensor",
            fornax_types::sensor::TrustClass::HostObserved,
            Some(Provider::Codex),
            fornax_types::sensor::CollectionMethod::ProcessObservation,
            None,
        );
        let (store, finding_id, _evidence_id) =
            seeded_store_with_finding(&path, Some(source)).await;

        let rendered = render_finding_timeline(&store, &finding_id.to_string())
            .await
            .expect("render finding timeline");

        assert!(rendered.contains("verifier:      TestResultVerifier"));
        // The full five-state tag, not a boolean/score.
        assert!(rendered.contains("verdict:       verified"));
        assert!(rendered.contains("trust_class=HostObserved"));
        assert!(rendered.contains("provenance=codex:rollout:exec_command_end"));
        assert!(rendered.contains("policy state (CURRENT device cache"));
        assert!(rendered.contains("local audit ledger (NOT scoped"));

        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn unknown_finding_id_is_a_clear_error_not_a_panic() {
        let path = tmp_db_path("missing-finding");
        let store = Store::open(&path).await.expect("open db");

        let err = render_finding_timeline(&store, &Uuid::new_v4().to_string())
            .await
            .expect_err("nonexistent finding must error");
        assert!(err.to_string().contains("no finding with id"));

        std::fs::remove_file(&path).ok();
    }

    // -------------------------------------------------------------------
    // AC2: a record predating tamper-boundary tracking renders the
    // existing honest "unknown" string verbatim -- never re-derived from
    // trust_class.
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn pre_tamper_boundary_record_renders_the_existing_honest_unknown_string_verbatim() {
        let path = tmp_db_path("pre-tamper-boundary");

        // An `EvidenceSource` with a real, known `trust_class` but written
        // before FORNX-159 added `tamper_boundary` -- simulated by
        // constructing the struct directly with `TamperBoundary::default()`
        // rather than `TamperBoundary::for_trust_class(...)`, exactly what
        // deserializing a pre-FORNX-159 JSON blob produces via
        // `#[serde(default)]`.
        let source = fornax_types::sensor::EvidenceSource {
            sensor_name: "ExitCodeSensor".into(),
            trust_class: fornax_types::sensor::TrustClass::HostObserved,
            collected_at: "2026-01-01T00:00:01Z".into(),
            provider: Some(Provider::Codex),
            collection_method: fornax_types::sensor::CollectionMethod::ProcessObservation,
            collector_version: None,
            freshness: fornax_types::sensor::Freshness::default(),
            tamper_boundary: fornax_types::sensor::TamperBoundary::default(),
            correlation_group: None,
            derived_from: Vec::new(),
        };
        let (store, finding_id, _evidence_id) =
            seeded_store_with_finding(&path, Some(source)).await;

        let rendered = render_finding_timeline(&store, &finding_id.to_string())
            .await
            .expect("render finding timeline");

        // The evidence's trust_class is known (HostObserved) -- proving the
        // "unknown" tamper-boundary string below is NOT derived from it.
        assert!(rendered.contains("trust_class=HostObserved"));
        assert!(rendered
            .contains("tamper_boundary=\"unknown (record predates tamper-boundary tracking)\""));

        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn evidence_with_no_provenance_at_all_is_distinguished_from_pre_tamper_boundary() {
        let path = tmp_db_path("no-provenance");
        let (store, finding_id, _evidence_id) = seeded_store_with_finding(&path, None).await;

        let rendered = render_finding_timeline(&store, &finding_id.to_string())
            .await
            .expect("render finding timeline");

        assert!(rendered.contains(
            "trust_class=unknown (no provenance recorded -- evidence predates FORNX-157's sensor contract)"
        ));
        // Must not be confused with the tamper-boundary-specific unknown
        // string, which only applies when `source` is `Some(..)`.
        assert!(!rendered.contains("record predates tamper-boundary tracking"));

        std::fs::remove_file(&path).ok();
    }

    // -------------------------------------------------------------------
    // AC3: works fully offline -- dependency-surface + successful
    // offline round-trip, mirroring `audit_ledger.rs`'s
    // `append_and_verify_run_fully_offline_with_no_network_client_dependency`.
    // -------------------------------------------------------------------

    #[test]
    fn timeline_module_source_never_calls_the_daemon_http_client_or_uds_socket() {
        // Unlike `fornax-store` (which has zero HTTP-client dependency at
        // the Cargo.toml level, so a manifest scan proves the point
        // directly), `fornax-cli` legitimately depends on an HTTP client
        // crate for other subcommands (`status`, `detail`, `capabilities`,
        // ...) that do go through the daemon's HTTP API. The
        // dependency-surface check for *this* module is therefore scoped to
        // this file's own production source text (everything above the
        // `#[cfg(test)]` marker, so this very assertion string can't
        // trivially match itself) rather than the whole crate's manifest:
        // that code must never reference the daemon's HTTP client, its
        // `fetch_json` helper, its `base_url` helper, or its Unix-socket
        // ingest channel -- every function above takes only `&Store`.
        let this_file = include_str!("timeline.rs");
        let production_code = this_file
            .split_once("#[cfg(test)]")
            .expect("this file has a #[cfg(test)] module")
            .0;
        let http_client_crate_name = ["re", "qwest"].concat();
        for forbidden in [
            http_client_crate_name.as_str(),
            "fetch_json",
            "base_url(",
            "UnixStream",
        ] {
            assert!(
                !production_code.contains(forbidden),
                "fornax timeline must never depend on the daemon's HTTP/UDS surface: found {forbidden:?}"
            );
        }
    }

    #[tokio::test]
    async fn finding_and_session_timeline_run_fully_offline_with_no_network_client_dependency() {
        let path = tmp_db_path("offline-finding");
        let source = fornax_types::sensor::EvidenceSource::now(
            "ExitCodeSensor",
            fornax_types::sensor::TrustClass::HostObserved,
            Some(Provider::Codex),
            fornax_types::sensor::CollectionMethod::ProcessObservation,
            None,
        );
        let (store, finding_id, _evidence_id) =
            seeded_store_with_finding(&path, Some(source)).await;

        // A real, local audit-ledger append -- proves the ledger section
        // reads real rows, still with no network involved.
        let event = AuditEvent::new(
            "event-timeline-test",
            "2026-01-01T00:00:04Z",
            AuditActor::System,
            AuditAction::PermissionCheck,
            AuditTarget::Permission {
                target_id: "read_finding".into(),
            },
            AuditOutcome::Granted,
            AuditExportClass::Metadata,
        );
        store
            .append_audit_event(&event, chrono::Utc::now())
            .await
            .expect("append audit event offline");

        let finding_rendered = render_finding_timeline(&store, &finding_id.to_string())
            .await
            .expect("render finding timeline offline");
        assert!(finding_rendered.contains("local audit ledger"));

        let session_rendered = render_session_timeline(&store, "s-timeline")
            .await
            .expect("render session timeline offline");
        assert!(session_rendered.contains("session: s-timeline (1 finding)"));

        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn session_with_no_findings_errors_clearly() {
        let path = tmp_db_path("empty-session");
        let store = Store::open(&path).await.expect("open db");

        let err = render_session_timeline(&store, "no-such-session")
            .await
            .expect_err("session with no findings must error");
        assert!(err.to_string().contains("no findings for session"));

        std::fs::remove_file(&path).ok();
    }
}
