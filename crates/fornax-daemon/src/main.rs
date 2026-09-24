//! Fornax local daemon (FORNX-25). One process: UDS event intake, immutable
//! storage, deterministic verification, and a localhost HTTP surface for the
//! status line, detail command, and dashboard (FORNX-30/31/32). No cloud
//! dependency on the critical path (D2, ADR 0001).

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use fornax_store::policy_cache::RevocationIngestOutcome;
use fornax_types::redact::{redact_json, redact_text};
use fornax_types::{
    compute_posture, verify_bundle, verify_revocation_list, ActivationOutcome, ActivationRejection,
    BoundRevision, CacheSlotKind, Finding, IngestMessage, PolicyCacheState, PolicyContent,
    PolicyDiagnostic, RuntimeCapabilities, TrustedVerificationKeys,
};
use fornax_verify::fusion::{project_graph, BaselineFusionPolicy, FusionInput, FusionPolicy};
use fornax_verify::{
    CommandExecutedVerifier, CommandSuccessVerifier, FileModifiedVerifier, GitOperationVerifier,
    TestResultVerifier, Verifier,
};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, RwLock};

mod policy_poll;

fn fornax_home() -> PathBuf {
    std::env::var("FORNAX_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| dirs_home().join(".fornax"))
}

fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

/// Single-instance guard (FORNX-12): a stale socket file left behind by an
/// unclean shutdown must not be confused with a second `fornaxd` already
/// live. Probe the existing path with a real connection attempt — a live
/// listener accepts it, a stale file refuses it — instead of unconditionally
/// deleting the path and silently stealing the socket out from under a
/// running daemon.
async fn ensure_single_instance(sock_path: &PathBuf) -> anyhow::Result<()> {
    if sock_path.exists() {
        match UnixStream::connect(sock_path).await {
            Ok(_) => {
                let home_dir = sock_path
                    .parent()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default();
                anyhow::bail!(
                    "fornaxd is already running: another daemon is live on {} — \
                     stop it first (e.g. `kill $(cat {home_dir}/fornaxd.pid)`) before starting a new one",
                    sock_path.display()
                );
            }
            Err(_) => {
                // Nothing is listening: a stale file from a previous unclean
                // shutdown (crash, kill -9, power loss). Safe to reclaim.
                tracing::warn!(
                    path = %sock_path.display(),
                    "removing stale socket file from a previous unclean shutdown"
                );
                std::fs::remove_file(sock_path)?;
            }
        }
    }
    Ok(())
}

/// Resolves to `()` once SIGTERM or SIGINT/Ctrl-C is received, for use with
/// `axum::serve(..).with_graceful_shutdown(..)` (FORNX-12: no signal handling
/// existed before this — the process could only be killed uncleanly).
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to install SIGTERM handler");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("received Ctrl-C, shutting down"),
        _ = terminate => tracing::info!("received SIGTERM, shutting down"),
    }
}

#[derive(Clone)]
struct AppState {
    store: fornax_store::Store,
    /// Per-session capabilities, announced once by the adapter. Also
    /// persisted to `store` (FORNX-62, `capabilities_for_session`) for
    /// `export-spool`/replay — kept here in-memory too so FORNX-53/55's
    /// live-session verdict computation never pays a DB round trip on the
    /// claim-verification hot path.
    caps: Arc<Mutex<HashMap<String, RuntimeCapabilities>>>,
    /// FORNX-281: each hook invocation is a fresh UDS connection handled by
    /// its own spawned task, with no ack from the daemon back to the hook —
    /// so nothing guarantees an earlier event (e.g. PostToolUse, carrying
    /// the exit-code Evidence a claim needs) finishes its DB write before a
    /// later message (e.g. Stop's Claim, which verifies against whatever
    /// Evidence already exists) starts processing on a different task. This
    /// is a single local daemon serving one user's sequential agent
    /// actions (ADR 0001) — not a system that needs concurrent throughput —
    /// so the correct fix is to make message *processing* strictly
    /// serialized in arrival order, not to make verification tolerant of
    /// partial evidence. Held for the full duration of `handle_message`.
    processing: Arc<Mutex<()>>,
    /// FORNX-119: never `None` if `resolve_trust_store` found and parsed a
    /// trust store at startup; static configuration, never re-read at
    /// runtime (trust roots do not rotate mid-process).
    trust: Arc<Option<TrustedVerificationKeys>>,
    /// FORNX-119: the daemon's live view of the local policy cache. Loaded
    /// once at startup (`Store::load_policy_cache`, before `axum::serve`)
    /// and refreshed after every successful `submit_policy_bundle` call
    /// from the UDS ingest path -- never abandoned on a policy failure
    /// (ADR-0001 D2).
    policy: Arc<RwLock<PolicyCacheSnapshot>>,
}

/// FORNX-311: the background policy poll task's most recent attempt.
/// In-memory only -- no persistence, no migration -- mirroring
/// `LastPolicyRejection`'s own precedent exactly.
#[derive(Clone)]
struct LastPolicyPoll {
    attempted_at: DateTime<Utc>,
    /// One of: "ok" | "disabled" | "unreachable" | "auth_failed" |
    /// "http_error" | "too_large" | "malformed" | "panicked".
    outcome: &'static str,
    /// Never contains the credential value or any URL query string.
    detail: String,
    bundles_received: usize,
    consecutive_failures: u32,
    next_attempt_at: DateTime<Utc>,
}

/// In-memory snapshot `GET /api/policy` reads. See
/// `docs/adr/0008-local-policy-cache-and-activation.md`.
#[derive(Clone)]
struct PolicyCacheSnapshot {
    state: PolicyCacheState,
    #[allow(dead_code)]
    // surfaced via `state`'s own generations; kept for future enforcement wiring.
    usable: Vec<BoundRevision>,
    loaded_slot: Option<CacheSlotKind>,
    diagnostics: Vec<PolicyDiagnostic>,
    /// In-memory only -- no persistence, no migration needed for it.
    last_rejection: Option<LastPolicyRejection>,
    /// FORNX-311: in-memory only -- no persistence, no migration needed.
    last_poll: Option<LastPolicyPoll>,
}

impl PolicyCacheSnapshot {
    fn empty() -> Self {
        Self {
            state: PolicyCacheState {
                schema_version: fornax_types::POLICY_CACHE_SCHEMA_VERSION,
                active: None,
                pending: None,
                last_known_good: None,
                high_water: std::collections::BTreeMap::new(),
                ever_configured: false,
                revocations: fornax_types::RevocationSet::default(),
            },
            usable: Vec::new(),
            loaded_slot: None,
            diagnostics: Vec::new(),
            last_rejection: None,
            last_poll: None,
        }
    }
}

#[derive(Clone)]
struct LastPolicyRejection {
    payload_digest: Option<String>,
    code: &'static str,
    message: String,
    remediation: String,
    at: DateTime<Utc>,
}

/// Short, stable snake_case label for one [`ActivationRejection`] variant --
/// surfaced on `GET /api/policy`'s `last_rejection.code`.
fn activation_rejection_code(r: &ActivationRejection) -> &'static str {
    match r {
        ActivationRejection::NotVerified(_) => "not_verified",
        ActivationRejection::SequenceNotAdvanced { .. } => "sequence_not_advanced",
        ActivationRejection::SequenceReused { .. } => "sequence_reused",
        ActivationRejection::IssuerMismatchForLineage { .. } => "issuer_mismatch_for_lineage",
        ActivationRejection::BindingsUnusable(_) => "bindings_unusable",
        ActivationRejection::Persistence { .. } => "persistence",
        ActivationRejection::Revoked { .. } => "revoked",
    }
}

fn remediation_for_rejection(r: &ActivationRejection) -> &'static str {
    match r {
        ActivationRejection::NotVerified(_) => {
            "re-export a bundle signed by a currently-trusted key, in-window and correctly formed"
        }
        ActivationRejection::SequenceNotAdvanced { .. }
        | ActivationRejection::SequenceReused { .. } => {
            "publish a new bundle with a sequence number strictly greater than the last one seen \
             for this issuer/policy_id"
        }
        ActivationRejection::IssuerMismatchForLineage { .. } => {
            "publish this policy_id's next revision from the same issuer that first claimed it, \
             or publish under a new policy_id"
        }
        ActivationRejection::BindingsUnusable(_) => {
            "remove pinned_fields from any binding targeted at TargetLevel::LocalUser"
        }
        ActivationRejection::Persistence { .. } => {
            "retry the import; if it persists, check disk space"
        }
        ActivationRejection::Revoked { .. } => {
            "this artifact must never be re-trusted; publish a fresh, unrevoked bundle instead"
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let home = fornax_home();
    std::fs::create_dir_all(&home)?;
    let db_path = home.join("fornax.db");
    let sock_path = home.join("fornax.sock");
    let pid_path = home.join("fornaxd.pid");
    ensure_single_instance(&sock_path).await?;
    // Written so an operator (or the single-instance guard's own error
    // message) can find this process's PID to stop it, e.g.
    // `kill $(cat "$FORNAX_HOME/fornaxd.pid")` (FORNX-12). There is no CLI
    // wrapper for this — a `fornax daemon stop` subcommand would need to
    // shell out to `kill`, which the zero-subprocess-spawn invariant
    // (asserted by `subprocess_surface_is_still_zero_in_production_code`)
    // forbids in production code. Best effort: a daemon that can't write
    // its own pid file still runs, it just can't be stopped this way.
    if let Err(e) = std::fs::write(&pid_path, std::process::id().to_string()) {
        tracing::warn!(error = %e, "failed to write pid file");
    }

    let store = fornax_store::Store::open(&db_path).await?;

    // FORNX-119: never abort startup on a policy failure (ADR-0001 D2).
    // Absent/malformed trust store or cache -> log and continue with a
    // degraded (possibly empty) policy snapshot.
    let (trusted, trust_diagnostics) = fornax_types::resolve_trust_store(&home);
    for d in &trust_diagnostics {
        tracing::warn!(code = ?d.code, message = %d.message, "policy trust store diagnostic");
    }
    let policy_snapshot = match store.load_policy_cache(trusted.as_ref(), Utc::now()).await {
        Ok(load) => {
            for d in &load.diagnostics {
                tracing::warn!(code = ?d.code, message = %d.message, "policy cache diagnostic");
            }
            PolicyCacheSnapshot {
                state: load.state,
                usable: load.usable,
                loaded_slot: load.loaded_slot,
                diagnostics: load.diagnostics,
                last_rejection: None,
                last_poll: None,
            }
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to load policy cache; continuing with an empty one");
            PolicyCacheSnapshot::empty()
        }
    };

    let state = AppState {
        store,
        caps: Arc::new(Mutex::new(HashMap::new())),
        processing: Arc::new(Mutex::new(())),
        trust: Arc::new(trusted),
        policy: Arc::new(RwLock::new(policy_snapshot)),
    };

    let uds_sock_path = sock_path.clone();
    let uds_state = state.clone();
    let uds_task = tokio::spawn(async move {
        if let Err(e) = run_uds_server(&uds_sock_path, uds_state).await {
            tracing::error!(error = %e, "UDS server exited");
        }
    });

    // FORNX-311: background policy bundle poll transport, alongside the UDS
    // ingest task. Disabled by default (no FORNAX_POLICY_POLL_URL) -- see
    // `policy_poll::resolve_poll_config`.
    let poll_task = policy_poll::spawn(state.clone(), home.clone());

    let app = Router::new()
        .route("/api/status", get(api_status))
        .route("/api/findings/recent", get(api_findings_recent))
        .route("/api/capabilities", get(api_capabilities))
        .route("/api/evidence-graph", get(api_evidence_graph))
        .route("/api/fusion", get(api_fusion))
        .route("/api/decision", get(api_decision))
        .route("/api/judge", get(api_judge))
        .route("/api/reliability", get(api_reliability))
        .route("/api/policy", get(api_policy))
        .route("/dashboard", get(dashboard))
        .with_state(state);

    let port: u16 = std::env::var("FORNAX_HTTP_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4317);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    tracing::info!(port, "fornax localhost dashboard listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    // FORNX-12: on a clean shutdown (SIGTERM/Ctrl-C), stop accepting new UDS
    // connections and reclaim both filesystem artifacts so the next start
    // doesn't have to distinguish "stale from a clean stop" from "stale from
    // a crash" — there's nothing left to distinguish.
    uds_task.abort();
    poll_task.abort();
    let _ = std::fs::remove_file(&sock_path);
    let _ = std::fs::remove_file(&pid_path);
    tracing::info!("fornaxd stopped");
    Ok(())
}

async fn run_uds_server(sock_path: &PathBuf, state: AppState) -> anyhow::Result<()> {
    let listener = UnixListener::bind(sock_path)?;
    tracing::info!(path = %sock_path.display(), "UDS ingest listening");
    loop {
        let (stream, _addr) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, state).await {
                tracing::warn!(error = %e, "ingest connection ended with error");
            }
        });
    }
}

async fn handle_connection(stream: UnixStream, state: AppState) -> anyhow::Result<()> {
    let mut lines = BufReader::new(stream).lines();
    let mut session_hint: Option<String> = None;

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let msg: IngestMessage = match serde_json::from_str(&line) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(error = %e, "dropping malformed ingest line");
                continue;
            }
        };
        if let Err(e) = handle_message(&state, msg, &mut session_hint).await {
            tracing::warn!(error = %e, "failed to process ingest message");
        }
    }
    Ok(())
}

async fn handle_message(
    state: &AppState,
    msg: IngestMessage,
    session_hint: &mut Option<String>,
) -> anyhow::Result<()> {
    // FORNX-281: serialize processing across every connection/task so a
    // later message's read of already-persisted state (e.g. a Claim
    // reading Evidence written by an earlier Event) can never race an
    // earlier message's still-in-flight write. See the `processing` field
    // doc comment for why this is the correct fix for a single local
    // daemon rather than making verification tolerant of partial evidence.
    let _serialize = state.processing.lock().await;
    match msg {
        IngestMessage::Capabilities(caps) => {
            // Capabilities may arrive before any Event sets `session_hint`
            // (e.g. Codex sends it right after `session_meta`, before the
            // first translatable event) — the adapter stamps the session id
            // into `notes` for exactly this case.
            let sid = caps
                .notes
                .get("session_id")
                .cloned()
                .or_else(|| session_hint.clone());
            if let Some(sid) = sid {
                *session_hint = Some(sid.clone());
                // The persisted store is correctly scoped to
                // `(session_id, provider)` (one row per announcing provider,
                // see `Store::upsert_capabilities`), but this in-memory cache
                // is a single slot per `session_id` — the one
                // `handle_message`'s `Claim` arm reads to gate verification.
                // FORNX-244: `sid` here is provider-controlled data (an
                // adapter reads it straight off the native payload, e.g.
                // opencode's `/input/sessionID`), so a malicious/buggy
                // provider payload could name another provider's live
                // session id and silently overwrite that session's
                // capability snapshot with its own — a real capability
                // *downgrade* (verbatim FORNX-244's Security Focus bullet)
                // that could suppress verification and hide evidence. Only
                // the announcing provider may overwrite its own session's
                // cached snapshot; a same-session announcement from a
                // different provider is dropped from the cache (the
                // correctly-scoped store row is still written) rather than
                // silently clobbering an unrelated provider's capabilities.
                state.store.upsert_capabilities(&sid, &caps).await?;
                let mut cache = state.caps.lock().await;
                let allow_cache_write = cache
                    .get(&sid)
                    .map(|existing| existing.provider == caps.provider)
                    .unwrap_or(true);
                if allow_cache_write {
                    cache.insert(sid, caps);
                } else {
                    tracing::warn!(
                        session_id = %sid,
                        incoming_provider = ?caps.provider,
                        "dropping cross-provider capabilities announcement for an \
                         already-cached session id (possible spoofed session_id)"
                    );
                }
            }
        }
        IngestMessage::Event(mut ev) => {
            *session_hint = Some(ev.session_id.clone());
            // Privacy boundary (FORNX-33): redact recognizable secrets from
            // raw tool output before it is ever persisted. Applied once,
            // here, not re-derived by every downstream reader.
            // FORNX-280: tool_input carries attacker/agent-controlled command
            // text exactly like tool_response and raw do (e.g. a secret typed
            // into a shell command) — it must go through the same boundary.
            ev.tool_input = ev.tool_input.as_ref().map(redact_json);
            ev.tool_response = ev.tool_response.as_ref().map(redact_json);
            ev.raw = redact_json(&ev.raw);
            state.store.insert_event(&ev).await?;
        }
        IngestMessage::Evidence(mut ev) => {
            *session_hint = Some(ev.session_id.clone());
            ev.payload = redact_json(&ev.payload);
            // FORNX-219/FORNX-244: `extension.fields` is deliberately
            // schemaless provider-specific JSON (the one escape-hatch field
            // in the canonical/extension split) and `extension.unknown`
            // preserves whatever a newer/different binary wrote verbatim —
            // both are exactly as capable of carrying sensitive free text as
            // `payload` above, and were never redacted before this fix.
            // `EvidenceSource` (`ev.source`) is not touched here: every one
            // of its fields is a short structured identifier/enum/timestamp
            // with no free-text content to redact.
            if let Some(ext) = ev.extension.as_mut() {
                ext.fields = redact_json(&ext.fields);
                ext.unknown =
                    match redact_json(&serde_json::Value::Object(std::mem::take(&mut ext.unknown)))
                    {
                        serde_json::Value::Object(map) => map,
                        _ => unreachable!("redact_json preserves the Object variant"),
                    };
            }
            state.store.insert_evidence(&ev).await?;
        }
        IngestMessage::PolicyBundle { envelope } => {
            handle_policy_bundle_ingest(state, envelope.into_bytes()).await;
        }
        IngestMessage::PolicyRevocation { envelope } => {
            handle_policy_revocation_ingest(state, envelope.into_bytes()).await;
        }
        IngestMessage::Claim(mut claim) => {
            *session_hint = Some(claim.session_id.clone());
            // FORNX-280: claim text is derived from agent/user transcript
            // content and had no redaction boundary at all — a secret
            // pasted into a prompt or echoed by the agent reached storage,
            // logs, and export-spool output unredacted. Apply the same
            // privacy boundary as Event/Evidence, once, before persistence.
            claim.text = redact_text(&claim.text);
            state.store.insert_claim(&claim).await?;

            let caps = state
                .caps
                .lock()
                .await
                .get(&claim.session_id)
                .cloned()
                .unwrap_or_else(default_unknown_caps);
            let evidence_read = state.store.evidence_for_session(&claim.session_id).await?;
            if !evidence_read.failed.is_empty() {
                tracing::warn!(
                    session_id = %claim.session_id,
                    failed = evidence_read.failed.len(),
                    total = evidence_read.evidence.len() + evidence_read.failed.len(),
                    "skipping evidence rows that failed to deserialize"
                );
            }
            let evidence = evidence_read.evidence;

            // FORNX-14: registry stays a flat Vec, per the ticket's own
            // maintainability requirement ("verifier registry/dispatch only
            // as complex as the first real verifier set requires") — five
            // verifiers dispatched by `applies_to` doesn't yet justify more.
            let verifiers: Vec<Box<dyn Verifier + Send + Sync>> = vec![
                Box::new(TestResultVerifier),
                Box::new(CommandExecutedVerifier),
                Box::new(CommandSuccessVerifier),
                Box::new(FileModifiedVerifier),
                Box::new(GitOperationVerifier),
            ];
            for verifier in verifiers.iter().filter(|v| v.applies_to(&claim)) {
                let finding = verifier.verify(&claim, &evidence, &caps);
                tracing::info!(verdict = ?finding.verdict, claim = %claim.text, "finding computed");
                state.store.insert_finding(&finding).await?;
            }
        }
    }
    Ok(())
}

/// Conservative default when an adapter hasn't announced capabilities yet —
/// never assume a signal is observable (D4/D7). Every class reads back
/// `Unknown` (ordinary absence, an empty `signals` list), which is
/// behaviorally identical to today's all-`false` bools at every verifier
/// gate — this fallback still never opens a gate it shouldn't.
///
/// FORNX-288 (found during FORNX-155's `RuntimeCapabilities` formalization,
/// disclosed there, fixed here): `provider` used to be hardcoded to `Codex`
/// regardless of which provider's session this actually is — a fabricated
/// provider identity for a session whose adapter simply hasn't spoken yet.
/// This now uses a real `Provider::Unknown` variant instead of guessing.
/// That variant is deliberately narrow-purpose: it is never written by
/// `Store::upsert_capabilities` (only a real announced `Capabilities`
/// message reaches that path) and never exported to `fornax-cloud`'s
/// separate, closed ingest enum, which doesn't know this variant — this
/// value only ever flows into `Verifier::verify`, and `Finding` carries no
/// provider field. A session→provider store lookup remains out of scope
/// here: it would put a DB round trip on the verify hot path the `caps`
/// in-memory cache exists specifically to avoid. Further provider plumbing
/// through the claim path, if ever needed, is FORNX-138 scope.
/// FORNX-119: submits a policy bundle envelope to the store and refreshes
/// `state.policy` accordingly. Never propagates an error up to
/// `handle_message`'s caller -- a malformed/unverifiable bundle is an
/// ordinary rejection outcome, not an ingest failure, and a genuine store
/// failure is logged, matching every other ingest arm's best-effort
/// posture.
async fn handle_policy_bundle_ingest(state: &AppState, envelope_bytes: Vec<u8>) {
    let Some(trusted) = state.trust.as_ref() else {
        tracing::warn!(
            "dropping policy bundle ingest message: no trust store configured \
             (set FORNAX_POLICY_TRUST_STORE or create <home>/policy-trust.json)"
        );
        return;
    };

    let now = Utc::now();
    let outcome = match state
        .store
        .submit_policy_bundle(&envelope_bytes, trusted, now)
        .await
    {
        Ok(outcome) => outcome,
        Err(e) => {
            tracing::error!(error = %e, "policy bundle submission failed");
            return;
        }
    };

    match outcome {
        ActivationOutcome::Activated { generation, .. }
        | ActivationOutcome::Confirmed { generation, .. } => {
            match state.store.load_policy_cache(Some(trusted), now).await {
                Ok(load) => {
                    let mut policy = state.policy.write().await;
                    policy.state = load.state;
                    policy.usable = load.usable;
                    policy.loaded_slot = load.loaded_slot;
                    policy.diagnostics = load.diagnostics;
                    policy.last_rejection = None;
                }
                Err(e) => {
                    tracing::error!(error = %e, "failed to reload policy cache after activation");
                }
            }
            tracing::info!(generation, "policy bundle activated/confirmed");
        }
        ActivationOutcome::Rejected {
            rejection,
            active_generation,
        } => {
            // Best-effort re-derivation of the candidate's payload_digest
            // for the diagnostic surface only -- verify_bundle has no side
            // effects, so re-running it here is safe and cheap (ingest is
            // not a hot path). `None` when verification itself failed
            // (there is no authenticated payload_digest to report).
            let payload_digest = verify_bundle(&envelope_bytes, trusted, now)
                .ok()
                .map(|v| v.payload_digest().to_string());
            tracing::warn!(
                code = activation_rejection_code(&rejection),
                active_generation,
                "policy bundle rejected: {rejection}"
            );
            let mut policy = state.policy.write().await;
            policy.last_rejection = Some(LastPolicyRejection {
                payload_digest,
                code: activation_rejection_code(&rejection),
                message: rejection.to_string(),
                remediation: remediation_for_rejection(&rejection).to_string(),
                at: now,
            });
        }
    }
}

/// FORNX-123: submits a policy revocation list envelope to the store and
/// refreshes `state.policy` accordingly. Mirrors
/// `handle_policy_bundle_ingest`'s best-effort posture exactly -- never
/// propagates an error up to `handle_message`'s caller, and refreshes the
/// in-memory snapshot after every successful apply/confirm so revocation
/// takes effect immediately in a running daemon rather than at next
/// restart.
async fn handle_policy_revocation_ingest(state: &AppState, envelope_bytes: Vec<u8>) {
    let Some(trusted) = state.trust.as_ref() else {
        tracing::warn!(
            "dropping policy revocation ingest message: no trust store configured \
             (set FORNAX_POLICY_TRUST_STORE or create <home>/policy-trust.json)"
        );
        return;
    };

    let now = Utc::now();
    let outcome = match state
        .store
        .submit_policy_revocation(&envelope_bytes, trusted, now)
        .await
    {
        Ok(outcome) => outcome,
        Err(e) => {
            tracing::error!(error = %e, "policy revocation submission failed");
            return;
        }
    };

    match outcome {
        RevocationIngestOutcome::Applied {
            issuer,
            sequence,
            new_entry_count,
            ..
        } => {
            match state.store.load_policy_cache(Some(trusted), now).await {
                Ok(load) => {
                    let mut policy = state.policy.write().await;
                    policy.state = load.state;
                    policy.usable = load.usable;
                    policy.loaded_slot = load.loaded_slot;
                    policy.diagnostics = load.diagnostics;
                }
                Err(e) => {
                    tracing::error!(error = %e, "failed to reload policy cache after revocation");
                }
            }
            tracing::info!(
                issuer,
                sequence,
                new_entry_count,
                "policy revocation list applied"
            );
        }
        RevocationIngestOutcome::AlreadyCurrent { issuer, sequence } => {
            tracing::info!(issuer, sequence, "policy revocation list already current");
        }
        RevocationIngestOutcome::Rejected { rejection } => {
            // Best-effort re-derivation of the candidate's payload_digest,
            // mirroring `handle_policy_bundle_ingest`'s own precedent --
            // `verify_revocation_list` has no side effects.
            let payload_digest = verify_revocation_list(&envelope_bytes, trusted, now)
                .ok()
                .map(|v| v.payload_digest().to_string());
            tracing::warn!(
                payload_digest,
                "policy revocation list rejected: {rejection}"
            );
        }
    }
}

/// `GET /api/policy` (FORNX-119): the local policy cache's status. Never
/// surfaces `PolicyRevisionBody`/`PolicyContent`, a display name, a binding
/// `TargetScope` identifier, or envelope bytes -- only identifiers,
/// digests, key ids, timestamps, tiers, flags, and this daemon's own
/// diagnostic strings. `basis` is always `"baseline"` in this ticket -- no
/// `DeviceContext` exists to resolve against yet (`RuntimeCapabilities` in
/// this codebase are per-session, not per-device).
async fn api_policy(State(state): State<AppState>) -> Json<serde_json::Value> {
    let snapshot = state.policy.read().await.clone();
    let baseline = PolicyContent::baseline();
    let members: Vec<fornax_types::CachedBundleRef> = snapshot
        .state
        .active
        .as_ref()
        .map(|g| g.members.clone())
        .unwrap_or_default();
    let pf = fornax_types::freshness(
        &members,
        snapshot.state.ever_configured,
        baseline.cache_max_age_seconds_by_risk,
        baseline.cache_offline_grace_seconds,
        Utc::now(),
    );
    let degraded = !matches!(snapshot.loaded_slot, Some(CacheSlotKind::Active))
        || !snapshot.diagnostics.is_empty();

    let last_rejection = snapshot.last_rejection.as_ref().map(|r| {
        serde_json::json!({
            "payload_digest": r.payload_digest,
            "code": r.code,
            "message": r.message,
            "remediation": r.remediation,
            "at": r.at,
        })
    });

    // FORNX-123: `posture` is separate from the pre-existing `degraded`
    // bool above -- `degraded` fires on ANY diagnostic (even a Warning) or
    // a mere LKG fallback; `posture` only degrades when `usable` is
    // actually empty, with an explicit precedence over which cause is
    // reported (see `compute_posture`'s own doc comment).
    let posture = compute_posture(
        snapshot.state.ever_configured,
        snapshot.usable.is_empty(),
        &snapshot.diagnostics,
    );

    // FORNX-311: `null` before the first poll cycle completes (or forever,
    // for an install with polling disabled/not configured).
    let last_poll = snapshot.last_poll.as_ref().map(|p| {
        serde_json::json!({
            "attempted_at": p.attempted_at,
            "outcome": p.outcome,
            "detail": p.detail,
            "bundles_received": p.bundles_received,
            "consecutive_failures": p.consecutive_failures,
            "next_attempt_at": p.next_attempt_at,
        })
    });

    Json(serde_json::json!({
        "schema_version": fornax_types::POLICY_CACHE_SCHEMA_VERSION,
        "configured": snapshot.state.ever_configured,
        "loaded_slot": snapshot.loaded_slot,
        "active": snapshot.state.active,
        "pending": serde_json::Value::Null,
        "last_known_good": snapshot.state.last_known_good,
        "freshness": {
            "basis": "baseline",
            "evaluated_at": pf.evaluated_at,
            "tier_by_risk": pf.tier_by_risk,
            "members": pf.members,
        },
        "revocations": {
            "entry_count": snapshot.state.revocations.revision_digests.len()
                + snapshot.state.revocations.payload_digests.len(),
            "unrecognized_entry_count": snapshot.state.revocations.unrecognized_entry_count,
            "max_sequence_by_issuer": snapshot.state.revocations.max_sequence_by_issuer,
        },
        "posture": posture,
        "degraded": degraded,
        "diagnostics": snapshot.diagnostics,
        "last_rejection": last_rejection,
        "last_poll": last_poll,
    }))
}

fn default_unknown_caps() -> RuntimeCapabilities {
    RuntimeCapabilities {
        schema_version: fornax_types::CAPABILITY_SCHEMA_VERSION,
        provider: fornax_types::Provider::Unknown,
        signals: vec![],
        notes: [(
            "reason".to_string(),
            "no capabilities announced by adapter yet".to_string(),
        )]
        .into(),
    }
}

async fn api_status(State(state): State<AppState>) -> Json<serde_json::Value> {
    match state.store.recent_findings(1).await {
        Ok(rows) if !rows.is_empty() => Json(serde_json::json!({ "latest": rows[0] })),
        Ok(_) => Json(serde_json::json!({ "latest": null })),
        Err(e) => Json(serde_json::json!({ "error": e.to_string() })),
    }
}

async fn api_findings_recent(State(state): State<AppState>) -> Json<serde_json::Value> {
    match state.store.recent_findings(50).await {
        Ok(rows) => Json(serde_json::json!({ "findings": rows })),
        Err(e) => Json(serde_json::json!({ "error": e.to_string() })),
    }
}

#[derive(serde::Deserialize)]
struct CapabilitiesQuery {
    session: String,
}

/// FORNX-85: exposes the persisted `RuntimeCapabilities` announcement(s) for
/// a session — the daemon-side half of the capability UX surface consumed by
/// `fornax capabilities <session>`. Reads `store.capabilities_for_session`
/// (one row per announcing provider, FORNX-62) rather than the in-memory
/// `state.caps` cache: the cache holds only the single most-recently-cached
/// provider per session id (see the `AppState::caps` field doc comment) and
/// exists to serve the claim-verification hot path, not to be a general
/// read API — a session with more than one announcing provider would be
/// silently under-reported by reading it here instead.
async fn api_capabilities(
    State(state): State<AppState>,
    Query(q): Query<CapabilitiesQuery>,
) -> Json<serde_json::Value> {
    match state.store.capabilities_for_session(&q.session).await {
        Ok(caps) if caps.is_empty() => Json(serde_json::json!({
            "session": q.session,
            "announced": false,
            "reason": "no capabilities announced yet by any adapter for this session",
            "capabilities": [],
        })),
        Ok(caps) => Json(serde_json::json!({
            "session": q.session,
            "announced": true,
            "capabilities": caps,
        })),
        Err(e) => Json(serde_json::json!({ "session": q.session, "error": e.to_string() })),
    }
}

#[derive(serde::Deserialize)]
struct EvidenceGraphQuery {
    claim: String,
    session: String,
}

/// FORNX-90: exposes `Store::evidence_graph_for_claim` (FORNX-89) as the
/// daemon-side half of the local Evidence Explorer — `fornax evidence-graph
/// <claim> <session>` reads this. This endpoint surfaces only `EvidenceLink`/
/// `MissingEvidence` rows — evidence ids and relation/availability metadata,
/// no evidence payload content at all (`EvidenceLink` doesn't carry one) —
/// so no redaction step applies on this path. A redaction-safe payload
/// drill-down (this ticket's AC also asks for one) is not built here; were
/// it added, it would need to read the already-redacted `Evidence` rows
/// (`handle_message` runs every `Evidence`/`Claim` through
/// `redact_json`/`redact_text` on ingest, see the `*_redacted_before_storage`
/// regression tests above), which would already satisfy that boundary
/// without any further redaction step of its own.
///
/// Distinguishes three cases, matching this ticket's core invariant that
/// "no evidence found" must never be silently conflated with "the claim
/// itself doesn't exist" or "evidence was expected but is missing":
/// - the claim id is not on record for this session at all -> `found: false`
/// - the claim exists but has zero links and zero missing-evidence notes
///   ("nobody has looked") -> `found: true`, empty `links`/`missing`
/// - the claim exists with links and/or missing notes -> `found: true`,
///   populated `links`/`missing`
///
/// Scoped by `(claim, session)` together, mirroring
/// `evidence_graph_for_claim`'s own authorization-boundary scoping — a
/// caller cannot probe another session's claim ids.
async fn api_evidence_graph(
    State(state): State<AppState>,
    Query(q): Query<EvidenceGraphQuery>,
) -> Json<serde_json::Value> {
    let claims = match state.store.claims_for_session(&q.session).await {
        Ok(claims) => claims,
        Err(e) => {
            return Json(
                serde_json::json!({ "claim": q.claim, "session": q.session, "error": e.to_string() }),
            )
        }
    };
    let claim_exists = claims.iter().any(|c| c.id.to_string() == q.claim);
    if !claim_exists {
        return Json(serde_json::json!({
            "claim": q.claim,
            "session": q.session,
            "found": false,
            "reason": "no claim with this id is on record for this session",
        }));
    }

    match state
        .store
        .evidence_graph_for_claim(&q.claim, &q.session)
        .await
    {
        Ok(graph) => Json(serde_json::json!({
            "claim": q.claim,
            "session": q.session,
            "found": true,
            "links": graph.links,
            "missing": graph.missing,
        })),
        Err(e) => Json(
            serde_json::json!({ "claim": q.claim, "session": q.session, "error": e.to_string() }),
        ),
    }
}

#[derive(serde::Deserialize)]
struct FusionQuery {
    claim: String,
    session: String,
}

/// Converts one `Store::findings_for_session` row into a real `Finding`, for
/// `fusion::project_graph`'s fallback path (see `api_fusion`). Store rows
/// serialize `verdict` as a bare snake_case tag and `evidence_ids` as a JSON
/// array string — the same shapes `Store`'s own (private) `tag`/`from_tag`
/// helpers produce, decoded here since neither is exported.
fn finding_row_to_finding(row: &fornax_store::FindingRow) -> anyhow::Result<Finding> {
    Ok(Finding {
        id: row.id.parse()?,
        claim_id: row.claim_id.parse()?,
        verdict: serde_json::from_value(serde_json::Value::String(row.verdict.clone()))?,
        evidence_ids: serde_json::from_str(&row.evidence_ids)?,
        verifier_name: row.verifier_name.clone(),
        rationale: row.rationale.clone(),
        computed_at: row.computed_at.clone(),
    })
}

/// Outcome of [`compute_fusion`] — the shared claim-lookup/graph-resolution/
/// fusion logic behind both `/api/fusion` (FORNX-304) and `/api/decision`
/// (FORNX-96), factored out so neither endpoint duplicates the other's
/// graph-loading/projection code (FORNX-96 implementation note).
enum FusionOutcome {
    /// No claim with this id is on record for this session.
    NotFound { reason: &'static str },
    /// A store/decode error occurred while resolving the claim's evidence.
    Error { message: String },
    /// A live `FusedFinding` was computed successfully. Boxed: this variant
    /// carries the claim/graph/evidence pool alongside `fused` (FORNX-94),
    /// which makes it much larger than `NotFound`/`Error` --
    /// `clippy::large_enum_variant` wants that size difference contained in
    /// one heap allocation rather than paid on every `FusionOutcome` value.
    Found(Box<FusionFound>),
}

/// Payload of [`FusionOutcome::Found`] (FORNX-94): the claim + resolved
/// graph/evidence pool that produced `fused` are retained so `/api/judge`
/// can build a `fornax_verify::judge::JudgeInput` without re-running the
/// claim-lookup/graph-resolution logic in [`compute_fusion`] a second time.
/// `/api/fusion`/`/api/decision` ignore `claim`/`graph`/`evidence_pool`,
/// same as before this ticket.
struct FusionFound {
    graph_source: &'static str,
    fused: fornax_verify::fusion::FusedFinding,
    claim: fornax_types::Claim,
    graph: fornax_types::EvidenceGraph,
    evidence_pool: Vec<fornax_types::Evidence>,
}

/// FORNX-304 (extended by FORNX-96 to be shared with `/api/decision`):
/// computes a live `FusedFinding` for one claim —
/// `fusion::BaselineFusionPolicy::fuse` run over FORNX-89's real evidence
/// graph, following the FORNX-90 `api_evidence_graph` precedent
/// (compute-on-demand, not persisted; no new `fornax-store` migration).
///
/// Prefers `Store::evidence_graph_for_claim`'s real, persisted graph; when
/// it comes back with zero links *and* zero missing-evidence notes (today's
/// actual production state — nothing on the live claim path writes graph
/// rows yet, per `fusion.rs`'s own module docs), falls back to
/// `fusion::project_graph()` over the claim's existing `Finding`(s) for this
/// session. The returned `graph_source` names which path was used.
///
/// `chrono::Utc::now()` is called exactly once, right here, to produce
/// `computed_at` — the one place in this feature the wall clock is read;
/// `fusion.rs` itself stays clock-free (FORNX-304 AC).
///
/// Scoped by `(claim, session)` together, mirroring `api_evidence_graph`'s
/// own authorization-boundary scoping.
async fn compute_fusion(state: &AppState, claim_id: &str, session: &str) -> FusionOutcome {
    let claims = match state.store.claims_for_session(session).await {
        Ok(claims) => claims,
        Err(e) => {
            return FusionOutcome::Error {
                message: e.to_string(),
            }
        }
    };
    let Some(claim) = claims.into_iter().find(|c| c.id.to_string() == claim_id) else {
        return FusionOutcome::NotFound {
            reason: "no claim with this id is on record for this session",
        };
    };

    let real_graph = match state
        .store
        .evidence_graph_for_claim(claim_id, session)
        .await
    {
        Ok(g) => g,
        Err(e) => {
            return FusionOutcome::Error {
                message: e.to_string(),
            }
        }
    };

    let (graph, graph_source) = if real_graph.links.is_empty() && real_graph.missing.is_empty() {
        let finding_rows = match state.store.findings_for_session(session).await {
            Ok(rows) => rows,
            Err(e) => {
                return FusionOutcome::Error {
                    message: e.to_string(),
                }
            }
        };
        let mut findings = Vec::new();
        for row in finding_rows.iter().filter(|r| r.claim_id == claim_id) {
            match finding_row_to_finding(row) {
                Ok(f) => findings.push(f),
                Err(e) => {
                    return FusionOutcome::Error {
                        message: format!("failed to decode finding {}: {e}", row.id),
                    }
                }
            }
        }
        (project_graph(&claim, &findings), "projected")
    } else {
        (real_graph, "graph")
    };

    let evidence_read = match state.store.evidence_for_session(session).await {
        Ok(outcome) => outcome,
        Err(e) => {
            return FusionOutcome::Error {
                message: e.to_string(),
            }
        }
    };

    let input = FusionInput {
        claim: &claim,
        graph: &graph,
        evidence: &evidence_read.evidence,
    };
    let computed_at = chrono::Utc::now().to_rfc3339();
    let fused = BaselineFusionPolicy.fuse(&input, &computed_at);

    FusionOutcome::Found(Box::new(FusionFound {
        graph_source,
        fused,
        claim,
        graph,
        evidence_pool: evidence_read.evidence,
    }))
}

async fn api_fusion(
    State(state): State<AppState>,
    Query(q): Query<FusionQuery>,
) -> Json<serde_json::Value> {
    match compute_fusion(&state, &q.claim, &q.session).await {
        FusionOutcome::Error { message } => {
            Json(serde_json::json!({ "claim": q.claim, "session": q.session, "error": message }))
        }
        FusionOutcome::NotFound { reason } => Json(serde_json::json!({
            "claim": q.claim,
            "session": q.session,
            "found": false,
            "reason": reason,
        })),
        FusionOutcome::Found(found) => Json(serde_json::json!({
            "claim": q.claim,
            "session": q.session,
            "found": true,
            "graph_source": found.graph_source,
            "fused": found.fused,
        })),
    }
}

#[derive(serde::Deserialize)]
struct DecisionQuery {
    claim: String,
    session: String,
    /// Risk class name (`strict`/`balanced`/`lenient`), defaults to
    /// `balanced` when omitted (FORNX-96 AC-adjacent contract: a caller who
    /// doesn't specify a risk class gets the class every hard safety floor
    /// in `fornax_verify::decision` is written against).
    #[serde(default)]
    risk: Option<String>,
}

fn parse_risk_class(s: Option<&str>) -> Result<fornax_verify::decision::RiskClass, String> {
    use fornax_verify::decision::RiskClass;
    match s.unwrap_or("balanced") {
        "strict" => Ok(RiskClass::Strict),
        "balanced" => Ok(RiskClass::Balanced),
        "lenient" => Ok(RiskClass::Lenient),
        other => Err(format!(
            "unknown risk class '{other}' -- expected one of strict, balanced, lenient"
        )),
    }
}

/// FORNX-96 (local half): `GET /api/decision?claim=&session=&risk=`.
/// Reuses `compute_fusion` (the same graph-loading/projection logic
/// `/api/fusion` uses) rather than duplicating it, then applies
/// `DefaultRiskPolicy` for the requested `RiskClass`. Always returns the
/// `Recommendation` alongside the full underlying `FusedFinding` in the
/// same response — never the recommendation alone — which is what "the
/// recommendation never replaces the underlying Finding/evidence graph"
/// means operationally at this layer.
async fn api_decision(
    State(state): State<AppState>,
    Query(q): Query<DecisionQuery>,
) -> Json<serde_json::Value> {
    use fornax_verify::decision::{DecisionPolicy, DefaultRiskPolicy};

    let risk = match parse_risk_class(q.risk.as_deref()) {
        Ok(r) => r,
        Err(message) => {
            return Json(
                serde_json::json!({ "claim": q.claim, "session": q.session, "error": message }),
            )
        }
    };

    match compute_fusion(&state, &q.claim, &q.session).await {
        FusionOutcome::Error { message } => {
            Json(serde_json::json!({ "claim": q.claim, "session": q.session, "error": message }))
        }
        FusionOutcome::NotFound { reason } => Json(serde_json::json!({
            "claim": q.claim,
            "session": q.session,
            "found": false,
            "reason": reason,
        })),
        FusionOutcome::Found(found) => {
            let recommendation = DefaultRiskPolicy.decide(&found.fused, risk);
            Json(serde_json::json!({
                "claim": q.claim,
                "session": q.session,
                "found": true,
                "graph_source": found.graph_source,
                "recommendation": recommendation,
                "fused": found.fused,
            }))
        }
    }
}

#[derive(serde::Deserialize)]
struct JudgeQuery {
    claim: String,
    session: String,
    /// Explicit opt-in to send unredacted evidence content to the judge
    /// (FORNX-94 AC: "raw protected evidence is not sent unless an
    /// explicit policy permits it"). Defaults to `false` when omitted.
    #[serde(default)]
    allow_raw_evidence: bool,
}

/// Maps a computed `Verdict` to the "does deterministic evidence support the
/// claim" boolean `JudgeOutput::with_disagreement_check` expects — `None`
/// for any verdict that isn't a clean yes/no (FORNX-94: disagreement is only
/// meaningful when there is an actual objective side to disagree with).
fn objective_supported_for_disagreement_check(verdict: fornax_types::Verdict) -> Option<bool> {
    match verdict {
        fornax_types::Verdict::Verified => Some(true),
        fornax_types::Verdict::Contradicted => Some(false),
        fornax_types::Verdict::Unverified
        | fornax_types::Verdict::Unavailable
        | fornax_types::Verdict::Review => None,
    }
}

/// FORNX-94: `GET /api/judge?claim=&session=&allow_raw_evidence=`. Reuses
/// `compute_fusion`'s claim-lookup/graph-resolution logic (same as
/// `/api/fusion`/`/api/decision`) to build a `JudgeInput`, then runs the
/// configured `LocalSelfHostedJudgeProvider` (`[semantic_judge]` in
/// `$FORNAX_HOME/config.toml`, disabled by default) via `spawn_blocking` —
/// the judge's HTTP client is sync (`fornax_verify::judge`'s module docs),
/// so it must not run directly on the async runtime thread.
///
/// Always returns the judge output alongside the full `FusedFinding` it was
/// computed from (same "never show one instead of the other" discipline as
/// `/api/decision`), plus a `disagreement` field surfaced explicitly rather
/// than the deterministic fusion result being silently overwritten. A judge
/// that is disabled/unreachable/timed out still returns `found: true` with
/// `judge.verdict: "unavailable"` — this is not treated as a daemon error,
/// since deterministic verification/fusion/decision must keep working
/// identically regardless of judge availability.
async fn api_judge(
    State(state): State<AppState>,
    Query(q): Query<JudgeQuery>,
) -> Json<serde_json::Value> {
    use fornax_verify::judge::{
        judge_output_to_evidence, JudgeInput, LocalSelfHostedJudgeProvider, SemanticJudgeConfig,
        SemanticJudgeProvider,
    };

    match compute_fusion(&state, &q.claim, &q.session).await {
        FusionOutcome::Error { message } => {
            Json(serde_json::json!({ "claim": q.claim, "session": q.session, "error": message }))
        }
        FusionOutcome::NotFound { reason } => Json(serde_json::json!({
            "claim": q.claim,
            "session": q.session,
            "found": false,
            "reason": reason,
        })),
        FusionOutcome::Found(found) => {
            let FusionFound {
                graph_source,
                fused,
                claim,
                graph,
                evidence_pool,
            } = *found;
            let input = JudgeInput::from_claim_and_graph(
                &claim,
                &graph,
                &evidence_pool,
                q.allow_raw_evidence,
            );
            let config = SemanticJudgeConfig::load_default();
            let objective = objective_supported_for_disagreement_check(fused.verdict);

            let judge_result = tokio::task::spawn_blocking(move || {
                let provider = LocalSelfHostedJudgeProvider::new(config);
                provider.judge(&input)
            })
            .await;

            let output = match judge_result {
                Ok(Ok(output)) => output.with_disagreement_check(objective),
                Ok(Err(e)) => {
                    return Json(serde_json::json!({
                        "claim": q.claim,
                        "session": q.session,
                        "error": e.to_string(),
                    }))
                }
                Err(e) => {
                    return Json(serde_json::json!({
                        "claim": q.claim,
                        "session": q.session,
                        "error": format!("judge task panicked: {e}"),
                    }))
                }
            };

            let derived_from_ids: Vec<uuid::Uuid> = graph
                .links
                .iter()
                .map(|l| l.evidence_id)
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect();
            let judge_evidence = judge_output_to_evidence(
                &output,
                &q.session,
                claim.source_event_id,
                derived_from_ids,
            );

            Json(serde_json::json!({
                "claim": q.claim,
                "session": q.session,
                "found": true,
                "graph_source": graph_source,
                "judge": output,
                "judge_evidence": judge_evidence,
                "fused": fused,
            }))
        }
    }
}

/// FORNX-105: `GET /api/reliability?session=&provider=&model_family=&model_version=&
/// adapter_version=&task_class=&toolset=&repository_class=&policy_version=&
/// verifier_version=&fusion_version=[&compare_model_version=&compare_adapter_version=]`.
///
/// This is the display/wiring layer over FORNX-103's context schema and
/// FORNX-104's statistics — it computes no new statistic itself. It:
///
/// - Refuses to even attempt aggregation when
///   `fornax_verify::reliability::ReliabilityAggregationConfig` (`[reliability]`
///   in `$FORNAX_HOME/config.toml`) has `historical_aggregation_enabled: false`
///   (the AC 5 opt-in gate) — returns `{"available": false, "reason": ...}`
///   before any context key is even built, a state kept structurally
///   distinct from "we looked and there isn't enough data" so a client can
///   never render "policy forbids this" as "insufficient support".
/// - Sources the `RuntimeCapabilities` half of the context key from the
///   session's own announced capabilities (`store.capabilities_for_session`,
///   the same lookup `/api/capabilities` uses) rather than a synthetic
///   value, so the fingerprint reflects what the session's runtime actually
///   declared. A session with no announced capabilities is its own
///   renderable fact (`"capabilities_announced": false`), not a silently
///   empty fingerprint.
/// - Builds a full `ReliabilityContextKey` via `fornax_types::aggregate_context`
///   from the request's explicit context dimensions — there is no path here
///   that accepts a bare provider/model and returns a number (FORNX-104's
///   own hard boundary).
/// - **No `ReliabilityObservation`s are persisted anywhere in this codebase
///   yet** (FORNX-104's module docs: writing real observations from the live
///   claim path is a distinct future ticket). `compute_reliability`/
///   `detect_drift` are therefore always invoked against an empty
///   observation set here — honestly reported by `sample_support` as
///   `insufficient_support` with `sample_count: 0`, never fabricated. This
///   endpoint's job is the rendering/wiring contract for when a real
///   observation store exists; `render_reliability`'s `Confident`/`Drifted`
///   rendering paths are exercised by synthetic JSON fixtures in
///   `fornax-cli`'s test module (mirroring `render_judge`'s own
///   `judge_fixture()` precedent), not by this live path today.
/// - When `compare_model_version`/`compare_adapter_version` is supplied,
///   additionally runs `detect_drift` between the primary context (baseline)
///   and the same context with those two dimensions swapped (comparison) —
///   the only two dimensions a drift check exists to let vary.
async fn api_reliability(
    State(state): State<AppState>,
    Query(q): Query<ReliabilityQuery>,
) -> Json<serde_json::Value> {
    use fornax_verify::reliability::ReliabilityAggregationConfig;

    let config = ReliabilityAggregationConfig::load_default();
    Json(reliability_response(&state, &q, config).await)
}

/// The testable core of [`api_reliability`], taking the privacy-gate config
/// as a plain parameter rather than reading `$FORNAX_HOME/config.toml`
/// itself — this crate's own `api_judge_returns_judge_output...` test
/// documents why daemon tests must not mutate that process-global,
/// machine-shared path; passing the config in directly makes the gate's
/// on/off behavior a deterministic, parallel-safe unit test instead.
async fn reliability_response(
    state: &AppState,
    q: &ReliabilityQuery,
    config: fornax_verify::reliability::ReliabilityAggregationConfig,
) -> serde_json::Value {
    use fornax_verify::reliability::{compute_reliability, detect_drift};

    if !config.historical_aggregation_enabled {
        return serde_json::json!({
            "session": q.session,
            "available": false,
            "reason": "historical reliability aggregation is disabled by local policy \
                       (set [reliability].historical_aggregation_enabled = true in \
                       $FORNAX_HOME/config.toml to opt in)",
        });
    }

    let requested_provider: fornax_types::Provider = match parse_context_tag(
        "provider",
        &q.provider,
    ) {
        Ok(p) => p,
        Err(message) => {
            return serde_json::json!({ "session": q.session, "available": true, "error": message })
        }
    };

    let caps = match state.store.capabilities_for_session(&q.session).await {
        Ok(caps) => caps,
        Err(e) => {
            return serde_json::json!({ "session": q.session, "available": true, "error": e.to_string() })
        }
    };
    // `capabilities_for_session` returns one row per announcing provider
    // (see its own doc comment: "a session with more than one announcing
    // provider would be silently under-reported" if read from the
    // single-slot in-memory cache instead). Selecting `.next()` here would
    // reintroduce exactly that failure at one remove: a session announced by
    // both `claude_code` and `codex`, queried with `--provider codex`, would
    // silently build a context key tagged `codex` but fingerprinted from
    // `claude_code`'s capabilities -- a wrong cohort in precisely the
    // dimension AC1/AC3 exist to make trustworthy. Match the row to the
    // provider the caller actually asked about instead.
    let Some(capabilities) = caps.into_iter().find(|c| c.provider == requested_provider) else {
        return serde_json::json!({
            "session": q.session,
            "available": true,
            "capabilities_announced": false,
            "reason": format!(
                "no capabilities announced for provider `{}` in this session -- \
                 a reliability context key cannot be built without one",
                q.provider
            ),
        });
    };

    let baseline_key = match build_reliability_context_key(q, capabilities.clone()) {
        Ok(key) => key,
        Err(message) => {
            return serde_json::json!({ "session": q.session, "available": true, "error": message })
        }
    };

    let observations: Vec<fornax_verify::reliability::ReliabilityObservation> = Vec::new();
    let policy_version = fornax_verify::reliability::RELIABILITY_POLICY_VERSION;

    match (&q.compare_model_version, &q.compare_adapter_version) {
        (None, None) => {
            let signal = compute_reliability(&baseline_key, &observations, policy_version);
            serde_json::json!({
                "session": q.session,
                "available": true,
                "capabilities_announced": true,
                "signal": signal,
            })
        }
        _ => {
            let comparison_key =
                fornax_types::aggregate_context(fornax_types::RawReliabilityContext {
                    provider: baseline_key.provider,
                    model_family: baseline_key.model_family.clone(),
                    model_version: q
                        .compare_model_version
                        .clone()
                        .unwrap_or_else(|| q.model_version.clone()),
                    adapter_version: q
                        .compare_adapter_version
                        .clone()
                        .unwrap_or_else(|| q.adapter_version.clone()),
                    task_class: baseline_key.task_class.clone(),
                    toolset: baseline_key.toolset.clone(),
                    repository: fornax_types::RawRepositoryContext {
                        identifying_hint: None,
                        class: baseline_key.repository_class.clone(),
                    },
                    policy_version: baseline_key.policy_version.clone(),
                    verifier_version: baseline_key.verifier_version.clone(),
                    fusion_version: baseline_key.fusion_version.clone(),
                    capabilities,
                });
            let assessment = detect_drift(
                &baseline_key,
                &observations,
                &comparison_key,
                &observations,
                policy_version,
            );
            serde_json::json!({
                "session": q.session,
                "available": true,
                "capabilities_announced": true,
                "drift_assessment": assessment,
            })
        }
    }
}

#[derive(serde::Deserialize)]
struct ReliabilityQuery {
    session: String,
    provider: String,
    model_family: String,
    model_version: String,
    adapter_version: String,
    task_class: String,
    /// Comma-separated `ToolClass` tags, e.g. `shell,file_edit`.
    toolset: String,
    repository_class: String,
    policy_version: String,
    verifier_version: String,
    fusion_version: String,
    /// Opt-in second dimension for a drift comparison (FORNX-105 AC:
    /// "drift after a runtime/model change is visible"). Supplying either
    /// of this pair runs `detect_drift` instead of a plain `compute_reliability`.
    #[serde(default)]
    compare_model_version: Option<String>,
    #[serde(default)]
    compare_adapter_version: Option<String>,
}

/// Parse one context-dimension query value into its closed (or
/// `Unrecognized`-tailed) enum type by round-tripping through its own wire
/// form -- every enum this module needs to parse
/// (`Provider`/`ModelFamily`/`TaskClass`/`ToolClass`/`RepositoryClass`) is
/// `#[serde(rename_all = "snake_case")]` and forward-compatible, so a plain
/// JSON string deserialization is the correct, already-existing parse path
/// rather than a hand-written match per enum.
fn parse_context_tag<T: for<'de> serde::Deserialize<'de>>(
    field: &str,
    value: &str,
) -> Result<T, String> {
    serde_json::from_value(serde_json::Value::String(value.to_string()))
        .map_err(|_| format!("invalid `{field}`: {value:?}"))
}

/// Build the primary (baseline) [`fornax_types::ReliabilityContextKey`] from
/// a [`ReliabilityQuery`] and the session's announced capabilities. The only
/// way to get a key is through [`fornax_types::aggregate_context`], which
/// (per FORNX-103) requires every dimension explicitly -- there is no path
/// here that could construct a key from `provider` alone.
fn build_reliability_context_key(
    q: &ReliabilityQuery,
    capabilities: RuntimeCapabilities,
) -> Result<fornax_types::ReliabilityContextKey, String> {
    use fornax_types::{
        aggregate_context, ModelFamily, RawReliabilityContext, RawRepositoryContext,
        RepositoryClass, TaskClass, ToolClass,
    };

    let provider: fornax_types::Provider = parse_context_tag("provider", &q.provider)?;
    let model_family: ModelFamily = parse_context_tag("model_family", &q.model_family)?;
    let task_class: TaskClass = parse_context_tag("task_class", &q.task_class)?;
    let repository_class: RepositoryClass =
        parse_context_tag("repository_class", &q.repository_class)?;
    let toolset: Vec<ToolClass> = q
        .toolset
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| parse_context_tag("toolset", s))
        .collect::<Result<Vec<ToolClass>, String>>()?;

    Ok(aggregate_context(RawReliabilityContext {
        provider,
        model_family,
        model_version: q.model_version.clone(),
        adapter_version: q.adapter_version.clone(),
        task_class,
        toolset,
        repository: RawRepositoryContext {
            identifying_hint: None,
            class: repository_class,
        },
        policy_version: q.policy_version.clone(),
        verifier_version: q.verifier_version.clone(),
        fusion_version: q.fusion_version.clone(),
        capabilities,
    }))
}

async fn dashboard(State(state): State<AppState>) -> axum::response::Html<String> {
    let rows = state.store.recent_findings(50).await.unwrap_or_default();
    let mut body = String::from(
        "<html><head><title>Fornax — local evidence dashboard</title>\
         <style>body{font-family:monospace;margin:2rem;background:#0b0e14;color:#d6dee8}\
         table{border-collapse:collapse;width:100%}td,th{padding:.4rem .6rem;border-bottom:1px solid #2a3140;text-align:left}\
         .verified{color:#4caf50}.contradicted{color:#e5534b}.unverified{color:#c9a227}.review{color:#4a9dd6}.unavailable{color:#7d8798}\
         </style></head><body><h2>🛡 Fornax — recent findings</h2><table>\
         <tr><th>Verdict</th><th>Claim</th><th>Verifier</th><th>Rationale</th><th>When</th></tr>",
    );
    for r in rows {
        body.push_str(&format!(
            "<tr><td class=\"{v}\">{v}</td><td>{claim}</td><td>{verifier}</td><td>{rationale}</td><td>{when}</td></tr>",
            v = html_escape(&r.verdict),
            claim = html_escape(&r.claim_text),
            verifier = html_escape(&r.verifier_name),
            rationale = html_escape(&r.rationale),
            when = html_escape(&r.computed_at),
        ));
    }
    body.push_str("</table></body></html>");
    axum::response::Html(body)
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use fornax_types::{AgentEvent, Claim, EventKind, Provider};
    use uuid::Uuid;

    async fn test_state() -> AppState {
        let db_path = std::env::temp_dir().join(format!("fornax-test-{}.db", Uuid::new_v4()));
        let store = fornax_store::Store::open(&db_path)
            .await
            .expect("open test store");
        AppState {
            store,
            caps: Arc::new(Mutex::new(HashMap::new())),
            processing: Arc::new(Mutex::new(())),
            trust: Arc::new(None),
            policy: Arc::new(RwLock::new(PolicyCacheSnapshot::empty())),
        }
    }

    /// FORNX-280 regression: a high-entropy secret in `tool_input` or claim
    /// text must never reach storage unredacted. Uses the same canary
    /// technique as the manual gap-closure repro: a random-hex marker shaped
    /// to trip `redact_json`/`redact_text`'s generic high-entropy detector,
    /// not a human-readable string a detector would legitimately ignore.
    #[tokio::test]
    async fn tool_input_and_claim_text_are_redacted_before_storage() {
        let state = test_state().await;
        let mut hint = None;
        let marker = format!("FORNAX-CANARY-{}-DO-NOT-LEAK", Uuid::new_v4().simple());
        let session_id = "fornx-280-regression".to_string();

        let event_id = Uuid::new_v4();
        let event = AgentEvent {
            id: event_id,
            session_id: session_id.clone(),
            provider: Provider::ClaudeCode,
            kind: EventKind::PreToolUse,
            observed_at: "2026-08-30T00:00:00Z".to_string(),
            tool_name: Some("Bash".to_string()),
            tool_input: Some(serde_json::json!({"command": format!("echo {marker}")})),
            tool_response: None,
            raw: serde_json::json!({}),
        };
        handle_message(&state, IngestMessage::Event(event), &mut hint)
            .await
            .expect("handle event");

        let claim = Claim {
            id: Uuid::new_v4(),
            session_id: session_id.clone(),
            source_event_id: event_id,
            text: format!("All tests passed. Session secret for audit: {marker}"),
            subject: "test_result".to_string(),
            claimed_at: "2026-08-30T00:00:00Z".to_string(),
        };
        handle_message(&state, IngestMessage::Claim(claim), &mut hint)
            .await
            .expect("handle claim");

        let stored_events = state
            .store
            .events_for_session(&session_id)
            .await
            .expect("read back events");
        let stored_input = stored_events[0]
            .tool_input
            .as_ref()
            .expect("tool_input present")
            .to_string();
        assert!(
            !stored_input.contains(&marker),
            "raw canary marker leaked into stored tool_input: {stored_input}"
        );
        assert!(
            stored_input.contains("REDACTED"),
            "expected a redacted placeholder in stored tool_input: {stored_input}"
        );

        let stored_claims = state
            .store
            .claims_for_session(&session_id)
            .await
            .expect("read back claims");
        assert!(
            !stored_claims[0].text.contains(&marker),
            "raw canary marker leaked into stored claim text: {}",
            stored_claims[0].text
        );
        assert!(
            stored_claims[0].text.contains("REDACTED"),
            "expected a redacted placeholder in stored claim text: {}",
            stored_claims[0].text
        );
    }

    /// FORNX-14 regression: a secret-shaped string reconstructed into a
    /// `FileDiff` evidence payload (e.g. by `ClaudeEditWriteDiffSensor` from
    /// an Edit's `old_string`/`new_string`) must go through the same
    /// redaction boundary as any other evidence payload before storage —
    /// proven directly against `IngestMessage::Evidence`, mirroring
    /// `tool_input_and_claim_text_are_redacted_before_storage` above.
    #[tokio::test]
    async fn file_diff_evidence_diff_is_redacted_before_storage() {
        let state = test_state().await;
        let mut hint = None;
        let marker = format!("FORNAX-CANARY-{}-DO-NOT-LEAK", Uuid::new_v4().simple());
        let session_id = "fornx-14-redaction-regression".to_string();

        let event_id = Uuid::new_v4();
        let event = AgentEvent {
            id: event_id,
            session_id: session_id.clone(),
            provider: Provider::ClaudeCode,
            kind: EventKind::PostToolUse,
            observed_at: "2026-08-31T00:00:00Z".to_string(),
            tool_name: Some("Edit".to_string()),
            tool_input: None,
            tool_response: None,
            raw: serde_json::json!({}),
        };
        handle_message(&state, IngestMessage::Event(event), &mut hint)
            .await
            .expect("handle event");

        let evidence = fornax_types::Evidence {
            id: Uuid::new_v4(),
            session_id: session_id.clone(),
            source_event_id: event_id,
            kind: fornax_types::EvidenceKind::FileDiff,
            observed_at: "2026-08-31T00:00:00Z".to_string(),
            payload: serde_json::json!({
                "path": "/repo/src/lib.rs",
                "diff": format!("-old\n+let secret = {marker}\n"),
            }),
            provenance: "claude_code:1.2.3:PostToolUse:Edit#heuristic:tool_input".to_string(),
            source: None,
            extension: None,
        };
        handle_message(&state, IngestMessage::Evidence(evidence), &mut hint)
            .await
            .expect("handle evidence");

        let stored = state
            .store
            .evidence_for_session(&session_id)
            .await
            .expect("read back evidence");
        let stored_diff = stored.evidence[0].payload["diff"]
            .as_str()
            .expect("diff field present")
            .to_string();
        assert!(
            !stored_diff.contains(&marker),
            "raw canary marker leaked into stored FileDiff evidence: {stored_diff}"
        );
        assert!(
            stored_diff.contains("REDACTED"),
            "expected a redacted placeholder in stored FileDiff evidence: {stored_diff}"
        );
    }

    /// FORNX-219: `ExtensionEnvelope.fields`/`.unknown` are the schemaless
    /// escape-hatch JSON added by FORNX-158 — a real, populated field for
    /// the first time via the opencode adapter (FORNX-161) — and were found
    /// to bypass the redaction boundary entirely while documenting the
    /// v0.0.3 release (`handle_message` only ever redacted `payload`).
    /// Proves both `fields` and `unknown` now go through the same boundary,
    /// mirroring `file_diff_evidence_diff_is_redacted_before_storage` above.
    #[tokio::test]
    async fn extension_fields_and_unknown_are_redacted_before_storage() {
        let state = test_state().await;
        let mut hint = None;
        let fields_marker = format!("FORNAX-CANARY-{}-FIELDS", Uuid::new_v4().simple());
        let unknown_marker = format!("FORNAX-CANARY-{}-UNKNOWN", Uuid::new_v4().simple());
        let session_id = "fornx-219-extension-redaction-regression".to_string();

        let event_id = Uuid::new_v4();
        let event = AgentEvent {
            id: event_id,
            session_id: session_id.clone(),
            provider: fornax_types::Provider::OpenCode,
            kind: EventKind::PostToolUse,
            observed_at: "2026-09-01T00:00:00Z".to_string(),
            tool_name: Some("bash".to_string()),
            tool_input: None,
            tool_response: None,
            raw: serde_json::json!({}),
        };
        handle_message(&state, IngestMessage::Event(event), &mut hint)
            .await
            .expect("handle event");

        let mut extension = fornax_types::ExtensionEnvelope::new(
            fornax_types::Provider::OpenCode,
            "1.18.25",
            fornax_types::ContentClass::ToolTelemetry,
            serde_json::json!({ "title": format!("secret={fields_marker}") }),
        );
        extension.unknown.insert(
            "future_field".to_string(),
            serde_json::json!(format!("secret={unknown_marker}")),
        );

        let evidence = fornax_types::Evidence {
            id: Uuid::new_v4(),
            session_id: session_id.clone(),
            source_event_id: event_id,
            kind: fornax_types::EvidenceKind::ProcessObservation,
            observed_at: "2026-09-01T00:00:00Z".to_string(),
            payload: serde_json::json!({}),
            provenance: "opencode:1.18.25:PostToolUse:bash#tool_response".to_string(),
            source: None,
            extension: Some(extension),
        };
        handle_message(&state, IngestMessage::Evidence(evidence), &mut hint)
            .await
            .expect("handle evidence");

        let stored = state
            .store
            .evidence_for_session(&session_id)
            .await
            .expect("read back evidence");
        let stored_extension = stored.evidence[0]
            .extension
            .as_ref()
            .expect("extension present");
        let stored_fields = stored_extension.fields.to_string();
        let stored_unknown = serde_json::to_string(&stored_extension.unknown).unwrap();

        assert!(
            !stored_fields.contains(&fields_marker),
            "raw canary marker leaked into stored extension.fields: {stored_fields}"
        );
        assert!(
            stored_fields.contains("REDACTED"),
            "expected a redacted placeholder in stored extension.fields: {stored_fields}"
        );
        assert!(
            !stored_unknown.contains(&unknown_marker),
            "raw canary marker leaked into stored extension.unknown: {stored_unknown}"
        );
        assert!(
            stored_unknown.contains("REDACTED"),
            "expected a redacted placeholder in stored extension.unknown: {stored_unknown}"
        );
    }

    /// FORNX-14 regression: a `ProcessObservation`/`vcs_operation` evidence
    /// payload must go through the same generic redaction boundary as any
    /// other evidence payload before storage — mirrors
    /// `file_diff_evidence_diff_is_redacted_before_storage` above. The
    /// canary is placed in `description` (a generic string field redact_json
    /// walks recursively), not in `observation.remote` — the sensor itself
    /// already sanitizes `remote` before this evidence is ever constructed
    /// (see `ClaudeGitOutcomeSensor::sanitize_remote`'s own dedicated
    /// regression coverage in `fornax-adapter-claude`), so `remote` is not a
    /// meaningful place to prove the *generic* redaction boundary here.
    #[tokio::test]
    async fn git_operation_evidence_is_redacted_before_storage() {
        let state = test_state().await;
        let mut hint = None;
        let marker = format!("FORNAX-CANARY-{}-DO-NOT-LEAK", Uuid::new_v4().simple());
        let session_id = "fornx-14-git-outcome-redaction-regression".to_string();

        let event_id = Uuid::new_v4();
        let event = AgentEvent {
            id: event_id,
            session_id: session_id.clone(),
            provider: Provider::ClaudeCode,
            kind: EventKind::PostToolUse,
            observed_at: "2026-08-31T00:00:00Z".to_string(),
            tool_name: Some("Bash".to_string()),
            tool_input: None,
            tool_response: None,
            raw: serde_json::json!({}),
        };
        handle_message(&state, IngestMessage::Event(event), &mut hint)
            .await
            .expect("handle event");

        let evidence = fornax_types::Evidence {
            id: Uuid::new_v4(),
            session_id: session_id.clone(),
            source_event_id: event_id,
            kind: fornax_types::EvidenceKind::ProcessObservation,
            observed_at: "2026-08-31T00:00:00Z".to_string(),
            payload: serde_json::json!({
                "description": format!("git commit created -- {marker}"),
                "observation": {
                    "observation_kind": "vcs_operation",
                    "operation": "commit",
                    "outcome": "created",
                    "commit_sha": "0e2fbd4",
                    "branch": "main"
                }
            }),
            provenance: "claude_code:1.2.3:PostToolUse:Bash#tool_response:git_commit".to_string(),
            source: None,
            extension: None,
        };
        handle_message(&state, IngestMessage::Evidence(evidence), &mut hint)
            .await
            .expect("handle evidence");

        let stored = state
            .store
            .evidence_for_session(&session_id)
            .await
            .expect("read back evidence");
        let stored_description = stored.evidence[0].payload["description"]
            .as_str()
            .expect("description field present")
            .to_string();
        assert!(
            !stored_description.contains(&marker),
            "raw canary marker leaked into stored ProcessObservation evidence: {stored_description}"
        );
        assert!(
            stored_description.contains("REDACTED"),
            "expected a redacted placeholder in stored ProcessObservation evidence: {stored_description}"
        );
    }

    /// FORNX-12 regression: no socket file at all is the ordinary first-boot
    /// case — must not error.
    #[tokio::test]
    async fn ensure_single_instance_allows_first_boot_with_no_socket() {
        let sock_path = std::env::temp_dir().join(format!("fornax-test-{}.sock", Uuid::new_v4()));
        assert!(!sock_path.exists());
        ensure_single_instance(&sock_path)
            .await
            .expect("no existing socket must never block startup");
    }

    /// FORNX-12 regression: a leftover socket *file* with nothing listening
    /// on it (the daemon's previous process crashed/was killed -9) must be
    /// reclaimed, not mistaken for a live instance.
    #[tokio::test]
    async fn ensure_single_instance_reclaims_a_stale_socket_file() {
        let sock_path = std::env::temp_dir().join(format!("fornax-test-{}.sock", Uuid::new_v4()));
        // A plain file at the socket path (not an actual bound socket) is
        // exactly what a crash leaves behind: the inode exists, nothing
        // accepts connections on it.
        std::fs::write(&sock_path, b"stale").expect("write stale socket file");

        ensure_single_instance(&sock_path)
            .await
            .expect("a stale socket file must be reclaimed, not treated as a live instance");
        assert!(
            !sock_path.exists(),
            "stale socket file should have been removed"
        );
    }

    /// FORNX-12 regression: a second daemon must refuse to start — loudly —
    /// rather than deleting the first daemon's live socket out from under it.
    #[tokio::test]
    async fn ensure_single_instance_refuses_when_another_daemon_is_live() {
        let sock_path = std::env::temp_dir().join(format!("fornax-test-{}.sock", Uuid::new_v4()));
        let listener = UnixListener::bind(&sock_path).expect("bind first instance's socket");
        // Keep the listener alive for the duration of the check by accepting
        // in the background; the guard only needs *something* live on the
        // other end of `connect`.
        let _accept_task = tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let result = ensure_single_instance(&sock_path).await;
        assert!(
            result.is_err(),
            "starting a second instance while one is live must be refused"
        );
        assert!(
            sock_path.exists(),
            "the first instance's live socket must not be deleted"
        );

        let _ = std::fs::remove_file(&sock_path);
    }

    /// FORNX-288 regression: a session that submits a Claim before any
    /// Capabilities announcement must fall back to a real `Provider::Unknown`
    /// value, not a fabricated guess at a specific provider.
    #[test]
    fn default_unknown_caps_uses_unknown_provider() {
        let caps = default_unknown_caps();
        assert_eq!(caps.provider, Provider::Unknown);
    }

    /// FORNX-17: `fornax status`/`fornax detail` (`/api/status` and
    /// `/api/findings/recent`) must surface a Codex session's finding —
    /// `Finding` carries no `provider` field, so no Codex-specific code
    /// exists in the daemon to test; this drives a real Codex session
    /// through the same `handle_message` pipeline the FORNX-280 Claude test
    /// above uses and checks both API surfaces produced the expected
    /// result. The parity claim with Claude Code is structural (same code
    /// path, same `Finding` shape), not something this one test
    /// demonstrates by comparison — it only exercises the Codex side. Also
    /// proves the CONTRADICTED rationale references the real evidence (exit
    /// code + provenance), satisfying the AC's "contradiction detail
    /// references the exact underlying evidence" for Codex specifically.
    #[tokio::test]
    async fn codex_session_finding_is_surfaced_by_status_and_detail() {
        use fornax_types::sensor::{CollectionMethod, EvidenceSource};
        use fornax_types::{
            CapabilitySignal, EventKind, Evidence, EvidenceKind, Provider, SignalAvailability,
            SignalClass, TrustClass,
        };

        let state = test_state().await;
        let mut hint = None;
        let session_id = "fornx-17-codex-session".to_string();

        // A minimal Codex capability announcement — just enough to open
        // `TestResultVerifier`'s `ToolTrace` gate (see its `verify` doc
        // comment) — not a full reproduction of
        // `fornax_adapter_codex::CodexAdapter::probe`'s real 7-signal
        // shape, which this crate deliberately doesn't depend on.
        let caps = RuntimeCapabilities {
            schema_version: fornax_types::CAPABILITY_SCHEMA_VERSION,
            provider: Provider::Codex,
            signals: vec![CapabilitySignal {
                class: SignalClass::ToolTrace,
                state: SignalAvailability::Available,
                detail: None,
            }],
            notes: [("session_id".to_string(), session_id.clone())].into(),
        };
        handle_message(&state, IngestMessage::Capabilities(caps), &mut hint)
            .await
            .expect("handle capabilities");

        // Evidence's `source_event_id` is a real foreign key — insert its
        // owning Event first, same as a real adapter would.
        let event_id = Uuid::new_v4();
        let event = AgentEvent {
            id: event_id,
            session_id: session_id.clone(),
            provider: Provider::Codex,
            kind: EventKind::PostToolUse,
            observed_at: "2026-08-31T00:00:00Z".to_string(),
            tool_name: Some("exec_command".to_string()),
            tool_input: Some(serde_json::json!({"command": "pytest -q"})),
            tool_response: Some(serde_json::json!({"exit_code": 1})),
            raw: serde_json::json!({}),
        };
        handle_message(&state, IngestMessage::Event(event), &mut hint)
            .await
            .expect("handle event");

        // Real FORNX-16 shape: a nonzero, non-heuristic exit code from a
        // failing `pytest -q` observed via `tools.shell_command`.
        let evidence = Evidence {
            id: Uuid::new_v4(),
            session_id: session_id.clone(),
            source_event_id: event_id,
            kind: EvidenceKind::ExitCode,
            observed_at: "2026-08-31T00:00:00Z".to_string(),
            payload: serde_json::json!({
                "command": "pytest -q",
                "exit_code": 1,
                "heuristic": false,
            }),
            provenance: "codex:0.0.1:rollout:custom_tool_call_output#exit_code_text".to_string(),
            source: Some(EvidenceSource::now(
                "codex_custom_tool_call_output_sensor_v1",
                TrustClass::AgentAdjacent,
                Some(Provider::Codex),
                CollectionMethod::FilePoll,
                Some("0.0.1".to_string()),
            )),
            extension: None,
        };
        handle_message(&state, IngestMessage::Evidence(evidence), &mut hint)
            .await
            .expect("handle evidence");

        // A false claim, same session.
        let claim = Claim {
            id: Uuid::new_v4(),
            session_id: session_id.clone(),
            source_event_id: event_id,
            text: "All tests passed.".to_string(),
            subject: "test_result".to_string(),
            claimed_at: "2026-08-31T00:00:00Z".to_string(),
        };
        handle_message(&state, IngestMessage::Claim(claim), &mut hint)
            .await
            .expect("handle claim");

        // Same surfaces `fornax status`/`fornax detail` call.
        let status = api_status(State(state.clone())).await;
        let latest = status
            .0
            .get("latest")
            .filter(|l| !l.is_null())
            .expect("api_status must surface the Codex session's finding");
        assert_eq!(
            latest.get("verdict").and_then(|v| v.as_str()),
            Some("contradicted")
        );

        let recent = api_findings_recent(State(state)).await;
        let findings = recent
            .0
            .get("findings")
            .and_then(|f| f.as_array())
            .expect("api_findings_recent must return an array");
        assert_eq!(findings.len(), 1);
        let rationale = findings[0]
            .get("rationale")
            .and_then(|s| s.as_str())
            .unwrap_or("");
        assert!(
            rationale.contains("exit_code=1"),
            "detail rationale must reference the real observed exit code: {rationale}"
        );
        assert!(
            rationale.contains("exit_code_text"),
            "detail rationale must reference the real Codex evidence provenance: {rationale}"
        );
    }

    /// FORNX-85: `/api/capabilities?session=<id>` must surface the exact
    /// signal/state pairs announced by a real capability probe, not a
    /// collapsed boolean summary — proves both the "announced" shape and
    /// that individual `SignalClass`/`SignalAvailability` values survive the
    /// full announce -> persist -> read round trip.
    #[tokio::test]
    async fn api_capabilities_surfaces_announced_signals_for_a_session() {
        use fornax_types::{CapabilitySignal, Provider, SignalAvailability, SignalClass};

        let state = test_state().await;
        let mut hint = None;
        let session_id = "fornx-85-capabilities-endpoint".to_string();

        let caps = RuntimeCapabilities {
            schema_version: fornax_types::CAPABILITY_SCHEMA_VERSION,
            provider: Provider::ClaudeCode,
            signals: vec![
                CapabilitySignal {
                    class: SignalClass::ToolInvocation,
                    state: SignalAvailability::Available,
                    detail: None,
                },
                CapabilitySignal {
                    class: SignalClass::RawReasoning,
                    state: SignalAvailability::Redacted,
                    detail: Some("thinking blocks withheld by privacy boundary".to_string()),
                },
                CapabilitySignal {
                    class: SignalClass::ProcessResult,
                    state: SignalAvailability::Unsupported,
                    detail: None,
                },
            ],
            notes: [("session_id".to_string(), session_id.clone())].into(),
        };
        handle_message(&state, IngestMessage::Capabilities(caps), &mut hint)
            .await
            .expect("handle capabilities");

        let query = Query(CapabilitiesQuery {
            session: session_id.clone(),
        });
        let resp = api_capabilities(State(state), query).await;
        assert_eq!(
            resp.0.get("announced").and_then(|b| b.as_bool()),
            Some(true)
        );
        let capabilities = resp.0["capabilities"]
            .as_array()
            .expect("capabilities must be an array");
        assert_eq!(capabilities.len(), 1);
        let signals = capabilities[0]["signals"]
            .as_array()
            .expect("signals must be an array");
        let tool_invocation = signals
            .iter()
            .find(|s| s["class"] == "tool_invocation")
            .expect("tool_invocation signal present");
        assert_eq!(tool_invocation["state"], "available");
        let raw_reasoning = signals
            .iter()
            .find(|s| s["class"] == "raw_reasoning")
            .expect("raw_reasoning signal present");
        assert_eq!(raw_reasoning["state"], "redacted");
        let process_result = signals
            .iter()
            .find(|s| s["class"] == "process_result")
            .expect("process_result signal present");
        assert_eq!(process_result["state"], "unsupported");
    }

    /// FORNX-85 regression: a session with no capability announcement on
    /// record must return a clear "not announced" shape distinct from an
    /// error — never a fabricated capability set (D4/D7: absence of a
    /// capability must never be silently treated as available).
    #[tokio::test]
    async fn api_capabilities_reports_not_announced_for_unknown_session() {
        let state = test_state().await;
        let query = Query(CapabilitiesQuery {
            session: "no-such-session".to_string(),
        });
        let resp = api_capabilities(State(state), query).await;
        assert_eq!(
            resp.0.get("announced").and_then(|b| b.as_bool()),
            Some(false)
        );
        assert!(resp.0["capabilities"]
            .as_array()
            .expect("capabilities must be an array")
            .is_empty());
        assert!(resp.0.get("reason").and_then(|s| s.as_str()).is_some());
    }

    /// FORNX-90: `/api/evidence-graph` must surface every linked-evidence
    /// relation and every missing-evidence note for a real claim, not a
    /// collapsed count — proves the full round trip through
    /// `evidence_graph_for_claim`.
    #[tokio::test]
    async fn api_evidence_graph_surfaces_links_and_missing_for_a_real_claim() {
        use fornax_types::{
            EvidenceLink, EvidenceRelation, MissingEvidence, SignalAvailability, SignalClass,
        };

        let state = test_state().await;
        let mut hint = None;
        let session_id = "fornx-90-evidence-graph-endpoint".to_string();

        let event_id = Uuid::new_v4();
        let event = AgentEvent {
            id: event_id,
            session_id: session_id.clone(),
            provider: Provider::ClaudeCode,
            kind: EventKind::PostToolUse,
            observed_at: "2026-09-01T00:00:00Z".to_string(),
            tool_name: Some("Bash".to_string()),
            tool_input: None,
            tool_response: None,
            raw: serde_json::json!({}),
        };
        handle_message(&state, IngestMessage::Event(event), &mut hint)
            .await
            .expect("handle event");

        let claim = Claim {
            id: Uuid::new_v4(),
            session_id: session_id.clone(),
            source_event_id: event_id,
            text: "all tests passed".to_string(),
            subject: "test_result".to_string(),
            claimed_at: "2026-09-01T00:00:00Z".to_string(),
        };
        handle_message(&state, IngestMessage::Claim(claim.clone()), &mut hint)
            .await
            .expect("handle claim");

        // `claim_evidence_links.evidence_id` is a foreign key into `evidence`
        // (0006_evidence_graph.sql) — a linked evidence id must reference a
        // real, already-stored `Evidence` row.
        let evidence_id = Uuid::new_v4();
        let evidence = fornax_types::Evidence {
            id: evidence_id,
            session_id: session_id.clone(),
            source_event_id: event_id,
            kind: fornax_types::EvidenceKind::ProcessObservation,
            observed_at: "2026-09-01T00:00:00Z".to_string(),
            payload: serde_json::json!({}),
            provenance: "claude_code:1.2.3:PostToolUse:Bash#tool_response".to_string(),
            source: None,
            extension: None,
        };
        handle_message(&state, IngestMessage::Evidence(evidence), &mut hint)
            .await
            .expect("handle evidence");

        state
            .store
            .insert_evidence_link(&EvidenceLink {
                id: Uuid::new_v4(),
                session_id: session_id.clone(),
                claim_id: claim.id,
                evidence_id,
                relation: EvidenceRelation::Contradicts,
                linked_at: "2026-09-01T00:00:01Z".to_string(),
            })
            .await
            .expect("insert evidence link");
        state
            .store
            .insert_missing_evidence(&MissingEvidence {
                id: Uuid::new_v4(),
                session_id: session_id.clone(),
                claim_id: claim.id,
                signal_class: SignalClass::ProcessResult,
                availability: SignalAvailability::Unavailable,
                detail: Some("no exit code sensor ran for this claim".to_string()),
                noted_at: "2026-09-01T00:00:02Z".to_string(),
            })
            .await
            .expect("insert missing evidence");

        let query = Query(EvidenceGraphQuery {
            claim: claim.id.to_string(),
            session: session_id,
        });
        let resp = api_evidence_graph(State(state), query).await;
        assert_eq!(resp.0.get("found").and_then(|b| b.as_bool()), Some(true));
        let links = resp.0["links"].as_array().expect("links must be an array");
        assert_eq!(links.len(), 1);
        assert_eq!(links[0]["relation"], "contradicts");
        let missing = resp.0["missing"]
            .as_array()
            .expect("missing must be an array");
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0]["signal_class"], "process_result");
        assert_eq!(missing[0]["availability"], "unavailable");
    }

    /// FORNX-90 regression: an unknown claim id must report `found: false`,
    /// never a fabricated empty graph — "the claim doesn't exist" must stay
    /// distinguishable from "the claim exists but nobody has looked".
    #[tokio::test]
    async fn api_evidence_graph_reports_not_found_for_unknown_claim() {
        let state = test_state().await;
        let query = Query(EvidenceGraphQuery {
            claim: Uuid::new_v4().to_string(),
            session: "no-such-session".to_string(),
        });
        let resp = api_evidence_graph(State(state), query).await;
        assert_eq!(resp.0.get("found").and_then(|b| b.as_bool()), Some(false));
        assert!(resp.0.get("reason").and_then(|s| s.as_str()).is_some());
    }

    /// FORNX-90 regression: a real claim with zero links and zero missing
    /// notes ("nobody has looked") must still report `found: true` with
    /// empty arrays — distinct from both the not-found case above and the
    /// looked-but-absent case covered by
    /// `api_evidence_graph_surfaces_links_and_missing_for_a_real_claim`.
    #[tokio::test]
    async fn api_evidence_graph_distinguishes_nobody_looked_from_not_found() {
        let state = test_state().await;
        let mut hint = None;
        let session_id = "fornx-90-nobody-looked".to_string();

        let event_id = Uuid::new_v4();
        let event = AgentEvent {
            id: event_id,
            session_id: session_id.clone(),
            provider: Provider::ClaudeCode,
            kind: EventKind::PostToolUse,
            observed_at: "2026-09-01T00:00:00Z".to_string(),
            tool_name: Some("Bash".to_string()),
            tool_input: None,
            tool_response: None,
            raw: serde_json::json!({}),
        };
        handle_message(&state, IngestMessage::Event(event), &mut hint)
            .await
            .expect("handle event");

        let claim = Claim {
            id: Uuid::new_v4(),
            session_id: session_id.clone(),
            source_event_id: event_id,
            text: "nobody has linked evidence to this claim yet".to_string(),
            subject: "test_result".to_string(),
            claimed_at: "2026-09-01T00:00:00Z".to_string(),
        };
        handle_message(&state, IngestMessage::Claim(claim.clone()), &mut hint)
            .await
            .expect("handle claim");

        let query = Query(EvidenceGraphQuery {
            claim: claim.id.to_string(),
            session: session_id,
        });
        let resp = api_evidence_graph(State(state), query).await;
        assert_eq!(resp.0.get("found").and_then(|b| b.as_bool()), Some(true));
        assert!(resp.0["links"]
            .as_array()
            .expect("links must be an array")
            .is_empty());
        assert!(resp.0["missing"]
            .as_array()
            .expect("missing must be an array")
            .is_empty());
    }

    /// FORNX-90 regression, direct read of the AC bullet "graph queries
    /// cannot cross tenant/session authorization boundaries": a claim that
    /// really exists in session A must report `found: false` — not A's
    /// graph — when queried under a different session id B, exactly like
    /// querying a claim id that doesn't exist anywhere.
    #[tokio::test]
    async fn api_evidence_graph_does_not_leak_a_claim_across_sessions() {
        use fornax_types::{EvidenceLink, EvidenceRelation};

        let state = test_state().await;
        let mut hint = None;
        let owning_session = "fornx-90-owning-session".to_string();
        let other_session = "fornx-90-other-session".to_string();

        let event_id = Uuid::new_v4();
        let event = AgentEvent {
            id: event_id,
            session_id: owning_session.clone(),
            provider: Provider::ClaudeCode,
            kind: EventKind::PostToolUse,
            observed_at: "2026-09-01T00:00:00Z".to_string(),
            tool_name: Some("Bash".to_string()),
            tool_input: None,
            tool_response: None,
            raw: serde_json::json!({}),
        };
        handle_message(&state, IngestMessage::Event(event), &mut hint)
            .await
            .expect("handle event");

        let claim = Claim {
            id: Uuid::new_v4(),
            session_id: owning_session.clone(),
            source_event_id: event_id,
            text: "belongs to the owning session only".to_string(),
            subject: "test_result".to_string(),
            claimed_at: "2026-09-01T00:00:00Z".to_string(),
        };
        handle_message(&state, IngestMessage::Claim(claim.clone()), &mut hint)
            .await
            .expect("handle claim");

        // `claim_evidence_links.evidence_id` is a foreign key into
        // `evidence` (0006_evidence_graph.sql) — needs a real stored row.
        let evidence_id = Uuid::new_v4();
        let evidence = fornax_types::Evidence {
            id: evidence_id,
            session_id: owning_session.clone(),
            source_event_id: event_id,
            kind: fornax_types::EvidenceKind::ProcessObservation,
            observed_at: "2026-09-01T00:00:00Z".to_string(),
            payload: serde_json::json!({}),
            provenance: "claude_code:1.2.3:PostToolUse:Bash#tool_response".to_string(),
            source: None,
            extension: None,
        };
        handle_message(&state, IngestMessage::Evidence(evidence), &mut hint)
            .await
            .expect("handle evidence");

        state
            .store
            .insert_evidence_link(&EvidenceLink {
                id: Uuid::new_v4(),
                session_id: owning_session.clone(),
                claim_id: claim.id,
                evidence_id,
                relation: EvidenceRelation::Supports,
                linked_at: "2026-09-01T00:00:01Z".to_string(),
            })
            .await
            .expect("insert evidence link");

        let cross_session_query = Query(EvidenceGraphQuery {
            claim: claim.id.to_string(),
            session: other_session,
        });
        let resp = api_evidence_graph(State(state.clone()), cross_session_query).await;
        assert_eq!(
            resp.0.get("found").and_then(|b| b.as_bool()),
            Some(false),
            "a real claim queried under a different session id must not leak as found"
        );

        // Sanity: the same claim id under its real session does resolve.
        let same_session_query = Query(EvidenceGraphQuery {
            claim: claim.id.to_string(),
            session: owning_session,
        });
        let resp2 = api_evidence_graph(State(state), same_session_query).await;
        assert_eq!(resp2.0.get("found").and_then(|b| b.as_bool()), Some(true));
    }

    /// FORNX-244 regression: `state.caps` is a single in-memory slot per
    /// `session_id`, but `session_id` here is provider-controlled data (an
    /// adapter reads it straight off the native payload). A malicious/buggy
    /// provider payload naming an already-active *other* provider's session
    /// id must not be able to silently overwrite that session's cached
    /// capability snapshot with its own — a real capability downgrade that
    /// could suppress verification (verbatim FORNX-244's "downgrade a real
    /// capability to hide evidence" Security Focus bullet).
    #[tokio::test]
    async fn cross_provider_capabilities_announcement_does_not_clobber_cached_session() {
        use fornax_types::{CapabilitySignal, Provider, SignalAvailability, SignalClass};

        let state = test_state().await;
        let mut hint = None;
        let session_id = "fornx-244-capability-downgrade-regression".to_string();

        let claude_caps = RuntimeCapabilities {
            schema_version: fornax_types::CAPABILITY_SCHEMA_VERSION,
            provider: Provider::ClaudeCode,
            signals: vec![CapabilitySignal {
                class: SignalClass::FinalResponse,
                state: SignalAvailability::Available,
                detail: None,
            }],
            notes: [("session_id".to_string(), session_id.clone())].into(),
        };
        handle_message(&state, IngestMessage::Capabilities(claude_caps), &mut hint)
            .await
            .expect("handle claude capabilities");

        // A spoofed/buggy announcement naming the same session id but a
        // different provider, declaring a strictly weaker capability set.
        let opencode_caps = RuntimeCapabilities {
            schema_version: fornax_types::CAPABILITY_SCHEMA_VERSION,
            provider: Provider::OpenCode,
            signals: vec![CapabilitySignal {
                class: SignalClass::FinalResponse,
                state: SignalAvailability::Unavailable,
                detail: None,
            }],
            notes: [("session_id".to_string(), session_id.clone())].into(),
        };
        handle_message(
            &state,
            IngestMessage::Capabilities(opencode_caps),
            &mut hint,
        )
        .await
        .expect("handle opencode capabilities");

        let cached = state
            .caps
            .lock()
            .await
            .get(&session_id)
            .cloned()
            .expect("session must still have a cached capability snapshot");
        assert_eq!(
            cached.provider,
            Provider::ClaudeCode,
            "a same-session announcement from a different provider must not overwrite the \
             original provider's cached capability snapshot"
        );
        assert_eq!(
            cached.state_of(&SignalClass::FinalResponse),
            SignalAvailability::Available,
            "the real provider's capability must not be silently downgraded by a \
             cross-provider announcement for the same session id"
        );
    }

    // --- FORNX-304: /api/fusion --------------------------------------------

    /// Inserts a real `AgentEvent` and returns its id — `claims.source_event_id`
    /// and `evidence.source_event_id` are both foreign keys into
    /// `agent_events` (0006_evidence_graph.sql), so fixtures for either must
    /// reference a row already stored via this, not a bare `Uuid::new_v4()`.
    async fn test_event(state: &AppState, session_id: &str) -> Uuid {
        let event = AgentEvent {
            id: Uuid::new_v4(),
            session_id: session_id.to_string(),
            provider: Provider::ClaudeCode,
            kind: EventKind::PostToolUse,
            observed_at: "2026-01-01T00:00:00Z".to_string(),
            tool_name: Some("Bash".to_string()),
            tool_input: None,
            tool_response: None,
            raw: serde_json::json!({}),
        };
        state
            .store
            .insert_event(&event)
            .await
            .expect("insert event");
        event.id
    }

    fn test_claim(session_id: &str, source_event_id: Uuid) -> Claim {
        Claim {
            id: Uuid::new_v4(),
            session_id: session_id.to_string(),
            source_event_id,
            text: "the command exited successfully".to_string(),
            subject: "command_succeeded".to_string(),
            claimed_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    fn test_evidence(session_id: &str, source_event_id: Uuid) -> fornax_types::Evidence {
        fornax_types::Evidence {
            id: Uuid::new_v4(),
            session_id: session_id.to_string(),
            source_event_id,
            kind: fornax_types::EvidenceKind::ExitCode,
            observed_at: "2026-01-01T00:00:00Z".to_string(),
            payload: serde_json::json!({}),
            provenance: "test".to_string(),
            source: None,
            extension: None,
        }
    }

    /// A claim with a real, persisted `claim_evidence_links` row must compute
    /// fusion straight from `Store::evidence_graph_for_claim` — the
    /// `project_graph` fallback must never fire when the real graph is
    /// already populated (FORNX-304 AC).
    #[tokio::test]
    async fn api_fusion_uses_the_real_graph_when_populated() {
        let state = test_state().await;
        let session_id = "fornx-304-real-graph";
        let event_id = test_event(&state, session_id).await;
        let claim = test_claim(session_id, event_id);
        let evidence = test_evidence(session_id, event_id);
        state
            .store
            .insert_claim(&claim)
            .await
            .expect("insert claim");
        state
            .store
            .insert_evidence(&evidence)
            .await
            .expect("insert evidence");
        let link = fornax_types::EvidenceLink {
            id: Uuid::new_v4(),
            session_id: session_id.to_string(),
            claim_id: claim.id,
            evidence_id: evidence.id,
            relation: fornax_types::EvidenceRelation::Supports,
            linked_at: "2026-01-01T00:00:00Z".to_string(),
        };
        state
            .store
            .insert_evidence_link(&link)
            .await
            .expect("insert evidence link");

        let response = api_fusion(
            State(state),
            Query(FusionQuery {
                claim: claim.id.to_string(),
                session: session_id.to_string(),
            }),
        )
        .await;
        let v = response.0;
        assert_eq!(v["found"], serde_json::json!(true));
        assert_eq!(v["graph_source"], serde_json::json!("graph"));
        let fused = &v["fused"];
        assert_eq!(fused["verdict"], serde_json::json!("verified"));
        assert_eq!(
            fused["counted_link_ids"],
            serde_json::json!([link.id.to_string()])
        );
    }

    /// A claim with a real `Finding` but nothing in the evidence-graph
    /// tables must fall back to `fusion::project_graph` over that finding
    /// (FORNX-304 AC: the projection fallback is today's actual production
    /// state, per `fusion.rs`'s own module docs).
    #[tokio::test]
    async fn api_fusion_projects_from_findings_when_the_real_graph_is_empty() {
        let state = test_state().await;
        let session_id = "fornx-304-projection-fallback";
        let event_id = test_event(&state, session_id).await;
        let claim = test_claim(session_id, event_id);
        let evidence = test_evidence(session_id, event_id);
        state
            .store
            .insert_claim(&claim)
            .await
            .expect("insert claim");
        state
            .store
            .insert_evidence(&evidence)
            .await
            .expect("insert evidence");
        let finding = Finding {
            id: Uuid::new_v4(),
            claim_id: claim.id,
            verdict: fornax_types::Verdict::Verified,
            evidence_ids: vec![evidence.id],
            verifier_name: "command_success_verifier_v1".to_string(),
            rationale: "exit code 0 observed".to_string(),
            computed_at: "2026-01-01T00:00:01Z".to_string(),
        };
        state
            .store
            .insert_finding(&finding)
            .await
            .expect("insert finding");

        // No claim_evidence_links / claim_missing_evidence rows exist for
        // this claim -- the real graph is empty, so this must fall back.
        let real_graph = state
            .store
            .evidence_graph_for_claim(&claim.id.to_string(), session_id)
            .await
            .expect("read real graph");
        assert!(real_graph.links.is_empty() && real_graph.missing.is_empty());

        let response = api_fusion(
            State(state),
            Query(FusionQuery {
                claim: claim.id.to_string(),
                session: session_id.to_string(),
            }),
        )
        .await;
        let v = response.0;
        assert_eq!(v["found"], serde_json::json!(true));
        assert_eq!(v["graph_source"], serde_json::json!("projected"));
        assert_eq!(v["fused"]["verdict"], serde_json::json!("verified"));
    }

    #[tokio::test]
    async fn api_fusion_reports_not_found_for_unknown_claim() {
        let state = test_state().await;
        let response = api_fusion(
            State(state),
            Query(FusionQuery {
                claim: Uuid::new_v4().to_string(),
                session: "fornx-304-unknown-claim".to_string(),
            }),
        )
        .await;
        let v = response.0;
        assert_eq!(v["found"], serde_json::json!(false));
    }

    // --- FORNX-96: /api/decision (local half) -------------------------------

    /// `/api/decision` always returns both the `Recommendation` and the
    /// full underlying `FusedFinding` in the same response -- FORNX-96 AC:
    /// "recommendation never replaces the underlying Finding/evidence
    /// graph". Uses the same real-graph fixture path as
    /// `api_fusion_uses_the_real_graph_when_populated`.
    #[tokio::test]
    async fn api_decision_returns_recommendation_and_full_fused_finding_together() {
        let state = test_state().await;
        let session_id = "fornx-96-decision-real-graph";
        let event_id = test_event(&state, session_id).await;
        let claim = test_claim(session_id, event_id);
        let evidence = test_evidence(session_id, event_id);
        state
            .store
            .insert_claim(&claim)
            .await
            .expect("insert claim");
        state
            .store
            .insert_evidence(&evidence)
            .await
            .expect("insert evidence");
        let link = fornax_types::EvidenceLink {
            id: Uuid::new_v4(),
            session_id: session_id.to_string(),
            claim_id: claim.id,
            evidence_id: evidence.id,
            relation: fornax_types::EvidenceRelation::Supports,
            linked_at: "2026-01-01T00:00:00Z".to_string(),
        };
        state
            .store
            .insert_evidence_link(&link)
            .await
            .expect("insert evidence link");

        let response = api_decision(
            State(state),
            Query(DecisionQuery {
                claim: claim.id.to_string(),
                session: session_id.to_string(),
                risk: None,
            }),
        )
        .await;
        let v = response.0;
        assert_eq!(v["found"], serde_json::json!(true));
        // The recommendation is present -- a single Supports link with no
        // recorded correlation group is Verified+Qualified (an
        // IndependenceUnverified caveat fires), so the hard AC safety floor
        // applies: never Proceed, at most Review.
        assert_eq!(v["fused"]["uncertainty"], serde_json::json!("qualified"));
        assert_eq!(v["recommendation"]["action"], serde_json::json!("review"));
        assert_eq!(
            v["recommendation"]["risk_class"],
            serde_json::json!("balanced")
        );
        assert_eq!(
            v["recommendation"]["policy_name"],
            serde_json::json!("default_risk_policy_v1")
        );
        // ...and the full FusedFinding is present alongside it, not instead
        // of it.
        assert_eq!(v["fused"]["verdict"], serde_json::json!("verified"));
        assert_eq!(
            v["fused"]["counted_link_ids"],
            serde_json::json!([link.id.to_string()])
        );
        // The recommendation points back at the claim, never embeds the
        // fusion rationale itself.
        assert_eq!(
            v["recommendation"]["claim_id"],
            serde_json::json!(claim.id.to_string())
        );
        assert!(v["recommendation"].get("rationale").is_none());
    }

    /// Omitting `risk` defaults to `balanced` -- confirmed above via
    /// `risk: None`; this test confirms an explicit `risk=strict` changes
    /// the action for the same underlying evidence (FORNX-96 AC: "same
    /// finding can yield different actions under explicit policy/risk
    /// contexts").
    #[tokio::test]
    async fn api_decision_risk_query_param_changes_the_recommended_action() {
        let state = test_state().await;
        let session_id = "fornx-96-decision-risk-param";
        let event_id = test_event(&state, session_id).await;
        let claim = test_claim(session_id, event_id);
        let evidence = test_evidence(session_id, event_id);
        state
            .store
            .insert_claim(&claim)
            .await
            .expect("insert claim");
        state
            .store
            .insert_evidence(&evidence)
            .await
            .expect("insert evidence");
        // A Contradicts link: Corroborated+Contradicted blocks under
        // Strict/Balanced but only reviews under Lenient.
        let link = fornax_types::EvidenceLink {
            id: Uuid::new_v4(),
            session_id: session_id.to_string(),
            claim_id: claim.id,
            evidence_id: evidence.id,
            relation: fornax_types::EvidenceRelation::Contradicts,
            linked_at: "2026-01-01T00:00:00Z".to_string(),
        };
        state
            .store
            .insert_evidence_link(&link)
            .await
            .expect("insert evidence link");

        let strict = api_decision(
            State(state.clone()),
            Query(DecisionQuery {
                claim: claim.id.to_string(),
                session: session_id.to_string(),
                risk: Some("strict".to_string()),
            }),
        )
        .await
        .0;
        let lenient = api_decision(
            State(state),
            Query(DecisionQuery {
                claim: claim.id.to_string(),
                session: session_id.to_string(),
                risk: Some("lenient".to_string()),
            }),
        )
        .await
        .0;

        assert_eq!(
            strict["fused"]["verdict"],
            serde_json::json!("contradicted")
        );
        assert_eq!(
            lenient["fused"]["verdict"],
            serde_json::json!("contradicted")
        );
        assert_eq!(
            strict["recommendation"]["action"],
            serde_json::json!("block")
        );
        assert_eq!(
            lenient["recommendation"]["action"],
            serde_json::json!("review")
        );
        assert_ne!(
            strict["recommendation"]["action"],
            lenient["recommendation"]["action"]
        );
    }

    #[tokio::test]
    async fn api_decision_reports_not_found_for_unknown_claim() {
        let state = test_state().await;
        let response = api_decision(
            State(state),
            Query(DecisionQuery {
                claim: Uuid::new_v4().to_string(),
                session: "fornx-96-decision-unknown-claim".to_string(),
                risk: None,
            }),
        )
        .await;
        let v = response.0;
        assert_eq!(v["found"], serde_json::json!(false));
        assert!(v.get("recommendation").is_none());
    }

    #[tokio::test]
    async fn api_decision_reports_error_for_unknown_risk_class() {
        let state = test_state().await;
        let response = api_decision(
            State(state),
            Query(DecisionQuery {
                claim: Uuid::new_v4().to_string(),
                session: "fornx-96-decision-bad-risk".to_string(),
                risk: Some("reckless".to_string()),
            }),
        )
        .await;
        let v = response.0;
        assert!(v.get("error").is_some());
    }

    // --- FORNX-94: /api/judge -------------------------------------------

    /// Deliberately does not assert `judge.verdict` is a specific value --
    /// whether the local judge is enabled depends on this test machine's
    /// `$FORNAX_HOME/config.toml`, which this test must not assume either
    /// way (and must not mutate, for the same "don't mutate process-global
    /// env vars shared with other tests" reason `sensor_config`'s own tests
    /// document). What every environment must produce identically: `found:
    /// true`, a `judge` object with a real verdict tag, and the SAME full
    /// `fused` FusedFinding alongside it -- never the judge output instead
    /// of the deterministic evidence trail.
    #[tokio::test]
    async fn api_judge_returns_judge_output_alongside_full_fused_finding() {
        let state = test_state().await;
        let session_id = "fornx-94-judge-real-graph";
        let event_id = test_event(&state, session_id).await;
        let claim = test_claim(session_id, event_id);
        let evidence = test_evidence(session_id, event_id);
        state
            .store
            .insert_claim(&claim)
            .await
            .expect("insert claim");
        state
            .store
            .insert_evidence(&evidence)
            .await
            .expect("insert evidence");
        let link = fornax_types::EvidenceLink {
            id: Uuid::new_v4(),
            session_id: session_id.to_string(),
            claim_id: claim.id,
            evidence_id: evidence.id,
            relation: fornax_types::EvidenceRelation::Supports,
            linked_at: "2026-01-01T00:00:00Z".to_string(),
        };
        state
            .store
            .insert_evidence_link(&link)
            .await
            .expect("insert evidence link");

        let response = api_judge(
            State(state),
            Query(JudgeQuery {
                claim: claim.id.to_string(),
                session: session_id.to_string(),
                allow_raw_evidence: false,
            }),
        )
        .await;
        let v = response.0;
        assert_eq!(v["found"], serde_json::json!(true));
        let verdict = v["judge"]["verdict"]
            .as_str()
            .expect("judge.verdict must be a string tag");
        assert!(
            ["supported", "contradicted", "inconclusive", "unavailable"].contains(&verdict),
            "unexpected judge verdict tag: {verdict}"
        );
        assert!(v["judge"]["model"].is_string());
        assert!(v["judge"]["endpoint"].is_string());
        assert!(v["judge"]["rationale"].is_string());
        // The full deterministic FusedFinding is present alongside the
        // judge output, never instead of it.
        assert_eq!(v["fused"]["verdict"], serde_json::json!("verified"));
        assert_eq!(
            v["fused"]["counted_link_ids"],
            serde_json::json!([link.id.to_string()])
        );
    }

    #[tokio::test]
    async fn api_judge_reports_not_found_for_unknown_claim() {
        let state = test_state().await;
        let response = api_judge(
            State(state),
            Query(JudgeQuery {
                claim: Uuid::new_v4().to_string(),
                session: "fornx-94-judge-unknown-claim".to_string(),
                allow_raw_evidence: false,
            }),
        )
        .await;
        let v = response.0;
        assert_eq!(v["found"], serde_json::json!(false));
        assert!(v.get("judge").is_none());
    }

    // --- FORNX-94: objective/disagreement mapping ------------------------

    #[test]
    fn objective_supported_maps_verified_and_contradicted_only() {
        assert_eq!(
            objective_supported_for_disagreement_check(fornax_types::Verdict::Verified),
            Some(true)
        );
        assert_eq!(
            objective_supported_for_disagreement_check(fornax_types::Verdict::Contradicted),
            Some(false)
        );
        for v in [
            fornax_types::Verdict::Unverified,
            fornax_types::Verdict::Unavailable,
            fornax_types::Verdict::Review,
        ] {
            assert_eq!(
                objective_supported_for_disagreement_check(v),
                None,
                "verdict={v:?} has no clean objective side to disagree against"
            );
        }
    }

    // --- FORNX-105: /api/reliability ---------------------------------------

    fn reliability_query(session: &str) -> ReliabilityQuery {
        ReliabilityQuery {
            session: session.to_string(),
            provider: "claude_code".to_string(),
            model_family: "claude".to_string(),
            model_version: "claude-sonnet-5".to_string(),
            adapter_version: "0.0.4".to_string(),
            task_class: "test_execution".to_string(),
            toolset: "shell,file_edit".to_string(),
            repository_class: "public_oss".to_string(),
            policy_version: "policy-v3".to_string(),
            verifier_version: "verifier-v2".to_string(),
            fusion_version: "fusion-v1".to_string(),
            compare_model_version: None,
            compare_adapter_version: None,
        }
    }

    async fn announce_reliability_caps(state: &AppState, session_id: &str) {
        announce_reliability_caps_for(state, session_id, fornax_types::Provider::ClaudeCode).await;
    }

    async fn announce_reliability_caps_for(
        state: &AppState,
        session_id: &str,
        provider: fornax_types::Provider,
    ) {
        use fornax_types::{CapabilitySignal, SignalAvailability, SignalClass};

        let caps = RuntimeCapabilities {
            schema_version: fornax_types::CAPABILITY_SCHEMA_VERSION,
            provider,
            signals: vec![CapabilitySignal {
                class: SignalClass::ToolTrace,
                state: SignalAvailability::Available,
                detail: None,
            }],
            notes: [("session_id".to_string(), session_id.to_string())].into(),
        };
        let mut hint = None;
        handle_message(state, IngestMessage::Capabilities(caps), &mut hint)
            .await
            .expect("handle capabilities");
    }

    fn aggregation_enabled() -> fornax_verify::reliability::ReliabilityAggregationConfig {
        fornax_verify::reliability::ReliabilityAggregationConfig {
            historical_aggregation_enabled: true,
        }
    }

    fn aggregation_disabled() -> fornax_verify::reliability::ReliabilityAggregationConfig {
        fornax_verify::reliability::ReliabilityAggregationConfig::default()
    }

    /// AC5: the privacy/opt-in gate defaults closed, and the closed state is
    /// reported *before* any capability lookup or context-key construction
    /// even happens -- `available: false`, never conflated with
    /// "insufficient support" (a distinct outcome tested below).
    #[tokio::test]
    async fn reliability_response_reports_unavailable_when_aggregation_disabled() {
        let state = test_state().await;
        let q = reliability_query("fornx-105-gate-closed");
        let v = reliability_response(&state, &q, aggregation_disabled()).await;
        assert_eq!(v["available"], serde_json::json!(false));
        assert!(v.get("signal").is_none());
        assert!(v.get("capabilities_announced").is_none());
    }

    /// A session with no announced capabilities cannot have a context key
    /// built at all -- this must render as its own fact, not a fabricated
    /// empty capability fingerprint, and never as "aggregation unavailable".
    #[tokio::test]
    async fn reliability_response_reports_no_capabilities_announced() {
        let state = test_state().await;
        let q = reliability_query("fornx-105-no-caps");
        let v = reliability_response(&state, &q, aggregation_enabled()).await;
        assert_eq!(v["available"], serde_json::json!(true));
        assert_eq!(v["capabilities_announced"], serde_json::json!(false));
        assert!(v.get("signal").is_none());
    }

    /// With aggregation enabled and capabilities announced, but no
    /// `ReliabilityObservation`s persisted anywhere yet (honest limitation,
    /// documented on `api_reliability`), the signal must read
    /// `insufficient_support` with `sample_count: 0` -- never a fabricated
    /// estimate.
    #[tokio::test]
    async fn reliability_response_computes_an_honest_insufficient_signal_with_no_observations() {
        let state = test_state().await;
        let session_id = "fornx-105-signal-empty-observations";
        announce_reliability_caps(&state, session_id).await;
        let q = reliability_query(session_id);
        let v = reliability_response(&state, &q, aggregation_enabled()).await;
        assert_eq!(v["available"], serde_json::json!(true));
        assert_eq!(v["capabilities_announced"], serde_json::json!(true));
        let signal = &v["signal"];
        assert_eq!(
            signal["sample_support"]["insufficient_support"]["sample_count"],
            serde_json::json!(0)
        );
        assert!(signal.get("reliability_estimate").is_none());
        // The full context key must be present so a client can render it.
        assert_eq!(signal["context_key"]["provider"], "claude_code");
        assert_eq!(signal["context_key"]["model_version"], "claude-sonnet-5");
    }

    /// Requesting a drift comparison runs `detect_drift` between the primary
    /// context and the same context with only model/adapter version swapped
    /// -- with no observations on either side, this must read
    /// `insufficient_data_for_comparison`, never a fabricated `Stable`/
    /// `Drifted` verdict.
    #[tokio::test]
    async fn reliability_response_drift_with_no_observations_is_insufficient_data() {
        let state = test_state().await;
        let session_id = "fornx-105-drift-empty-observations";
        announce_reliability_caps(&state, session_id).await;
        let mut q = reliability_query(session_id);
        q.compare_model_version = Some("claude-sonnet-4".to_string());
        let v = reliability_response(&state, &q, aggregation_enabled()).await;
        assert_eq!(v["available"], serde_json::json!(true));
        let assessment = &v["drift_assessment"];
        assert_eq!(
            assessment["drift_state"],
            serde_json::json!("insufficient_data_for_comparison")
        );
        assert_eq!(
            assessment["baseline_signal"]["context_key"]["model_version"],
            "claude-sonnet-5"
        );
        assert_eq!(
            assessment["comparison_signal"]["context_key"]["model_version"],
            "claude-sonnet-4"
        );
    }

    /// `Provider` is the one context dimension with no `Unrecognized`
    /// forward-compat tail (see `fornax_types::Provider`'s own doc comment),
    /// so an unparsable provider tag must be reported as an explicit error,
    /// never silently coerced or ignored.
    #[tokio::test]
    async fn reliability_response_reports_error_for_invalid_provider_tag() {
        let state = test_state().await;
        let session_id = "fornx-105-invalid-tag";
        announce_reliability_caps(&state, session_id).await;
        let mut q = reliability_query(session_id);
        q.provider = "not_a_real_provider".to_string();
        let v = reliability_response(&state, &q, aggregation_enabled()).await;
        // Still honestly reports availability before the parse failure.
        assert_eq!(v["available"], serde_json::json!(true));
        assert!(v.get("error").is_some());
        assert!(v.get("signal").is_none());
    }

    /// A session announced by more than one provider must select the
    /// capabilities row matching the *requested* provider, never just the
    /// first row `capabilities_for_session` happens to return (its own doc
    /// comment: rows are `ORDER BY provider ASC`, so `claude_code` always
    /// sorts before `codex`). Regression for a real bug caught in review:
    /// querying `--provider codex` on a session also announced by
    /// `claude_code` must never silently build a `codex`-tagged context key
    /// fingerprinted from Claude Code's capabilities.
    #[tokio::test]
    async fn reliability_response_selects_capabilities_matching_the_requested_provider() {
        let state = test_state().await;
        let session_id = "fornx-105-multi-provider-session";
        // Announce claude_code first (sorts first alphabetically) then codex.
        announce_reliability_caps_for(&state, session_id, fornax_types::Provider::ClaudeCode).await;
        announce_reliability_caps_for(&state, session_id, fornax_types::Provider::Codex).await;

        let mut q = reliability_query(session_id);
        q.provider = "codex".to_string();
        let v = reliability_response(&state, &q, aggregation_enabled()).await;

        assert_eq!(v["available"], serde_json::json!(true));
        assert_eq!(v["capabilities_announced"], serde_json::json!(true));
        assert_eq!(v["signal"]["context_key"]["provider"], "codex");
    }

    /// The mirror case: a session announced by a provider the query does
    /// *not* ask about must read "no capabilities announced for provider
    /// X", never fall back to whatever the first announced row happens to
    /// be.
    #[tokio::test]
    async fn reliability_response_reports_no_capabilities_for_the_requested_provider_specifically()
    {
        let state = test_state().await;
        let session_id = "fornx-105-wrong-provider-only";
        announce_reliability_caps_for(&state, session_id, fornax_types::Provider::ClaudeCode).await;

        let mut q = reliability_query(session_id);
        q.provider = "codex".to_string();
        let v = reliability_response(&state, &q, aggregation_enabled()).await;

        assert_eq!(v["available"], serde_json::json!(true));
        assert_eq!(v["capabilities_announced"], serde_json::json!(false));
        let reason = v["reason"].as_str().unwrap_or("");
        assert!(reason.contains("codex"), "reason was: {reason}");
    }

    // ========================================================================
    // FORNX-119 -- local policy cache: T78 (confidentiality allowlist), T79
    // (degraded-startup never panics).
    // ========================================================================

    fn policy_test_signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32])
    }

    fn policy_test_trust(
        key_id: &str,
        sk: &ed25519_dalek::SigningKey,
    ) -> fornax_types::TrustedVerificationKeys {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;
        fornax_types::TrustedVerificationKeys {
            schema_version: 1,
            keys: vec![fornax_types::policy::TrustedKey {
                key_id: fornax_types::KeyId(key_id.to_string()),
                algorithm: fornax_types::policy::SignatureAlgorithm::Ed25519,
                public_key_b64: STANDARD.encode(sk.verifying_key().to_bytes()),
                not_before: None,
                not_after: None,
                comment: None,
            }],
        }
    }

    /// Builds a signed envelope whose revision carries `display_name` and a
    /// `sensors.disabled` entry the caller supplies, so T78 can prove
    /// neither ever reaches `GET /api/policy`.
    fn build_policy_test_envelope(
        display_name: &str,
        disabled_sensor: &str,
        key_id: &str,
        sk: &ed25519_dalek::SigningKey,
    ) -> Vec<u8> {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;
        use ed25519_dalek::Signer;
        use fornax_types::policy::{
            BundlePayload, BundleProvenance, BundleSignature, PolicyBinding, PolicyDraft, PolicyId,
            SignatureAlgorithm, SignedPolicyBundle, TargetScope, TargetSelector,
        };
        use fornax_types::PolicyContent;

        let mut content = PolicyContent::default();
        let mut disabled = std::collections::BTreeSet::new();
        disabled.insert(disabled_sensor.to_string());
        content.sensors.disabled = Some(disabled);

        let draft = PolicyDraft {
            policy_id: PolicyId(Uuid::new_v4()),
            revision: 1,
            supersedes: None,
            display_name: display_name.to_string(),
            content,
            pinned_fields: std::collections::BTreeSet::new(),
        };
        let revision = draft
            .publish("2026-01-01T00:00:00Z".to_string())
            .expect("draft should publish");

        let binding = PolicyBinding {
            binding_id: Uuid::new_v4(),
            scope: TargetScope::Org {
                org_id: "org-1".to_string(),
            },
            selector: TargetSelector::default(),
            revision_ref: revision.reference(),
        };
        let payload = BundlePayload {
            bundle_schema_version: 1,
            bundle_id: Uuid::new_v4(),
            sequence: 1,
            issued_at: "2026-01-01T00:00:00Z".to_string(),
            not_before: "2026-01-01T00:00:00Z".to_string(),
            expires_at: "2027-01-01T00:00:00Z".to_string(),
            provenance: BundleProvenance {
                issuer: "issuer-a".to_string(),
                audit_ref: None,
                authorized_by: None,
            },
            revision,
            bindings: vec![binding],
        };
        let payload_bytes = serde_json::to_vec(&payload).unwrap();

        let mut signed_message = Vec::new();
        signed_message.extend_from_slice(fornax_types::policy::BUNDLE_SIGNING_DOMAIN);
        signed_message.extend_from_slice(&payload_bytes);
        let signature = sk.sign(&signed_message);

        let envelope = SignedPolicyBundle {
            bundle_schema_version: 1,
            payload_b64: STANDARD.encode(&payload_bytes),
            signatures: vec![BundleSignature {
                key_id: fornax_types::KeyId(key_id.to_string()),
                algorithm: SignatureAlgorithm::Ed25519,
                signature_b64: STANDARD.encode(signature.to_bytes()),
            }],
        };
        serde_json::to_vec(&envelope).unwrap()
    }

    fn assert_exact_keys(v: &serde_json::Value, expected: &[&str], where_: &str) {
        let obj = v
            .as_object()
            .unwrap_or_else(|| panic!("{where_} must be a JSON object"));
        let mut actual: Vec<&str> = obj.keys().map(String::as_str).collect();
        actual.sort_unstable();
        let mut expected_sorted: Vec<&str> = expected.to_vec();
        expected_sorted.sort_unstable();
        assert_eq!(actual, expected_sorted, "unexpected key set at {where_}");
    }

    /// T78: positive-allowlist confidentiality proof for `GET /api/policy`.
    /// Asserts the exact key set at every nesting level (not a denylist),
    /// and that neither a distinctive `display_name` nor a distinctive
    /// `sensors.disabled` entry appears anywhere in the serialized body.
    #[tokio::test]
    async fn t78_api_policy_never_leaks_display_name_or_sensor_names() {
        let mut state = test_state().await;
        let sk = policy_test_signing_key();
        let trust = policy_test_trust("k1", &sk);
        state.trust = Arc::new(Some(trust.clone()));

        let secret_display_name = "FORNX-T78-SECRET-DISPLAY-NAME-MUST-NOT-LEAK";
        let secret_sensor = "FORNX-T78-SECRET-SENSOR-MUST-NOT-LEAK";
        let envelope = build_policy_test_envelope(secret_display_name, secret_sensor, "k1", &sk);

        let outcome = state
            .store
            .submit_policy_bundle(&envelope, &trust, Utc::now())
            .await
            .expect("submit policy bundle");
        assert!(matches!(outcome, ActivationOutcome::Activated { .. }));

        let load = state
            .store
            .load_policy_cache(Some(&trust), Utc::now())
            .await
            .expect("load policy cache");
        {
            let mut policy = state.policy.write().await;
            policy.state = load.state;
            policy.usable = load.usable;
            policy.loaded_slot = load.loaded_slot;
            policy.diagnostics = load.diagnostics;
        }

        let response = api_policy(State(state.clone())).await;
        let body = response.0;
        let serialized = serde_json::to_string(&body).unwrap();

        assert!(
            !serialized.contains(secret_display_name),
            "display_name must never be surfaced on GET /api/policy"
        );
        assert!(
            !serialized.contains(secret_sensor),
            "a disabled sensor name must never be surfaced on GET /api/policy"
        );

        assert_exact_keys(
            &body,
            &[
                "schema_version",
                "configured",
                "loaded_slot",
                "active",
                "pending",
                "last_known_good",
                "freshness",
                "revocations",
                "posture",
                "degraded",
                "diagnostics",
                "last_rejection",
                "last_poll",
            ],
            "top level",
        );
        assert_eq!(body["pending"], serde_json::Value::Null);

        let active = &body["active"];
        assert_exact_keys(active, &["generation", "members", "written_at"], "active");
        let members = active["members"].as_array().unwrap();
        assert_eq!(members.len(), 1);
        assert_exact_keys(
            &members[0],
            &[
                "bundle_id",
                "issuer",
                "sequence",
                "policy_id",
                "revision",
                "revision_digest",
                "payload_digest",
                "verified_by",
                "not_before",
                "expires_at",
                "first_activated_at",
                "confirmed_at",
            ],
            "active.members[0]",
        );

        let freshness = &body["freshness"];
        assert_exact_keys(
            freshness,
            &["basis", "evaluated_at", "tier_by_risk", "members"],
            "freshness",
        );
        assert_eq!(freshness["basis"], serde_json::json!("baseline"));
        assert_exact_keys(
            &freshness["tier_by_risk"],
            &["low", "elevated", "high", "critical"],
            "freshness.tier_by_risk",
        );
        let freshness_members = freshness["members"].as_array().unwrap();
        assert_eq!(freshness_members.len(), 1);
        assert_exact_keys(
            &freshness_members[0],
            &[
                "bundle_id",
                "policy_id",
                "confirmed_at",
                "expires_at",
                "age_seconds",
                "tier_by_risk",
            ],
            "freshness.members[0]",
        );
    }

    /// T79: the daemon's policy surface must never panic or block startup
    /// when there is no trust store, no cache, or an unreadable trust store
    /// -- `configured` reads `false`, `GET /api/policy` still answers.
    #[tokio::test]
    async fn t79_degraded_policy_state_never_panics_and_reports_unconfigured() {
        // No trust store, no cache -- the exact state `test_state()`
        // already constructs (trust: None, empty PolicyCacheSnapshot).
        let state = test_state().await;
        let response = api_policy(State(state.clone())).await;
        let body = response.0;
        assert_eq!(body["configured"], serde_json::json!(false));
        assert_eq!(body["loaded_slot"], serde_json::Value::Null);
        assert_eq!(body["active"], serde_json::Value::Null);
        assert_eq!(body["last_known_good"], serde_json::Value::Null);

        // An unreadable/malformed trust store must resolve to `None` plus a
        // diagnostic, never a panic or an `Err` that aborts startup.
        let bad_home = std::env::temp_dir().join(format!("fornax-t79-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&bad_home).unwrap();
        std::fs::write(bad_home.join("policy-trust.json"), "not json").unwrap();
        let (trusted, diagnostics) = fornax_types::resolve_trust_store(&bad_home);
        assert!(trusted.is_none());
        assert!(!diagnostics.is_empty());
        let load = state
            .store
            .load_policy_cache(trusted.as_ref(), Utc::now())
            .await
            .expect("load_policy_cache must never fail for a missing trust store");
        assert!(load.usable.is_empty());
        std::fs::remove_dir_all(&bad_home).ok();
    }
}
