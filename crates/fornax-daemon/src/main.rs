//! Fornax local daemon (FORNX-25). One process: UDS event intake, immutable
//! storage, deterministic verification, and a localhost HTTP surface for the
//! status line, detail command, and dashboard (FORNX-30/31/32). No cloud
//! dependency on the critical path (D2, ADR 0001).

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use fornax_types::redact::{redact_json, redact_text};
use fornax_types::{IngestMessage, RuntimeCapabilities};
use fornax_verify::{
    CommandExecutedVerifier, CommandSuccessVerifier, FileModifiedVerifier, GitOperationVerifier,
    TestResultVerifier, Verifier,
};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;

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
    let state = AppState {
        store,
        caps: Arc::new(Mutex::new(HashMap::new())),
        processing: Arc::new(Mutex::new(())),
    };

    let uds_sock_path = sock_path.clone();
    let uds_state = state.clone();
    let uds_task = tokio::spawn(async move {
        if let Err(e) = run_uds_server(&uds_sock_path, uds_state).await {
            tracing::error!(error = %e, "UDS server exited");
        }
    });

    let app = Router::new()
        .route("/api/status", get(api_status))
        .route("/api/findings/recent", get(api_findings_recent))
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
}
