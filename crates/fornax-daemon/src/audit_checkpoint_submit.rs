//! Background audit checkpoint submission transport (FORNX-317, ADR-0012).
//!
//! **Push, not pull** -- unlike `policy_poll` (which pulls bundles/
//! revocations), this task periodically `POST`s this device's current
//! local audit-ledger head to `POST /v1/devices/me/audit-checkpoints` and
//! stores the cloud's countersigned response. See
//! `docs/adr/0012-audit-checkpoints.md` for the full wire contract this
//! module implements byte-for-byte.
//!
//! **Best-effort, never load-bearing for the local critical path (ADR-0001
//! D2).** A failed submission -- unreachable cloud, malformed response, a
//! response that fails [`fornax_types::verify_audit_checkpoint`] -- is
//! logged and the cycle ends; it must never block, delay, or fail local
//! evidence capture, and never panics past its own spawned task (mirroring
//! `policy_poll`'s panic-containment discipline).
//!
//! **Gated on [`fornax_types::privacy::cloud_sync_allowed`]** -- checkpoint
//! submission sends this device's ledger head to `fornax-cloud`, which is
//! exactly the kind of cloud egress that gate exists to control. Disabled
//! by default.
//!
//! **Empty ledger -> no submission** (ADR-0012 §2.2): a device with no
//! audit events has no head to attest, so this task simply skips the
//! cycle rather than posting.
//!
//! **`device_reported_chain_status` is derived from
//! `Store::verify_audit_chain` directly**, not from the (separate)
//! `Store::evaluate_all_checkpoint_receipts` §8.2 comparison against prior
//! receipts -- the wire field describes "is my own hash chain internally
//! self-consistent right now", which is exactly what
//! `ChainVerification` answers. A `evaluate_all_checkpoint_receipts`
//! finding of e.g. `AnchorRewritten` against a *prior* receipt is a
//! stronger, additional signal with no defined slot in this wire
//! vocabulary (ADR-0012 defines `divergence_kind` only for
//! `fornax_store::DivergenceKind`'s four variants) -- this task logs it at
//! `warn` but does not attempt to fold it into `device_reported_chain_status`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::Utc;
use fornax_types::{
    verify_audit_checkpoint, AuditCheckpointRequest, DeviceReportedChainStatus, LedgerHead,
};

use crate::AppState;

const CHECKPOINT_URL_ENV: &str = "FORNAX_AUDIT_CHECKPOINT_URL";
const CREDENTIAL_FILE_ENV: &str = "FORNAX_DEVICE_CREDENTIAL_FILE";
const INTERVAL_ENV: &str = "FORNAX_AUDIT_CHECKPOINT_INTERVAL_SECONDS";
const DEFAULT_CREDENTIAL_FILE_NAME: &str = "device-credential";
pub(crate) const DEFAULT_INTERVAL_SECONDS: u64 = 3600;
pub(crate) const MIN_INTERVAL_SECONDS: u64 = 60;
pub(crate) const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Never `Debug`/`Display`s its contents -- mirrors
/// `policy_poll::DeviceCredential`'s exact discipline.
struct DeviceCredential(String);

impl DeviceCredential {
    fn as_str(&self) -> &str {
        &self.0
    }
}

struct SubmitConfig {
    url: reqwest::Url,
    credential: DeviceCredential,
    interval: Duration,
}

/// Spawns the checkpoint submission supervisor task. Always returns a
/// `JoinHandle`, even when disabled, so `main()` can `.abort()` it
/// unconditionally at shutdown -- mirroring `policy_poll::spawn`.
pub(crate) fn spawn(state: AppState, home: PathBuf) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move { supervisor_loop(state, home).await })
}

async fn supervisor_loop(state: AppState, home: PathBuf) {
    // ADR-0012 §8.2: "Run this check on daemon start and before each new
    // checkpoint submission." Unconditional -- run even when submission
    // itself ends up disabled below, since a device can hold prior
    // receipts (from before cloud sync was disabled, or from a restore)
    // that are still worth re-checking against the current local ledger.
    evaluate_and_log_receipts(&state).await;

    let Some(config) = resolve_submit_config(&home) else {
        tracing::info!(
            "audit checkpoint submission disabled: {CHECKPOINT_URL_ENV} is not set or cloud \
             sync is not enabled (this is the expected state for most installs)"
        );
        return;
    };

    let http = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    let mut first_tick = true;
    loop {
        // First tick uses a short startup jitter (mirroring
        // `policy_poll::run_supervisor_inner`'s 0..=30s), not the full
        // interval -- so a fresh install/restart doesn't wait up to
        // `DEFAULT_INTERVAL_SECONDS` (1 hour) before its first submission.
        let wait = if first_tick {
            first_tick = false;
            Duration::from_secs(startup_jitter_seconds())
        } else {
            config.interval
        };
        tokio::time::sleep(wait).await;

        let cycle_state = state.clone();
        let cycle_http = http.clone();
        let cycle_url = config.url.clone();
        let cycle_credential = config.credential.as_str().to_string();

        // Panic containment: each attempt is its own spawned task, its
        // result discarded on join failure -- never propagated, mirroring
        // `policy_poll::run_supervisor_inner`.
        if let Err(_join_err) = tokio::spawn(async move {
            submit_one_cycle(&cycle_state, &cycle_http, &cycle_url, &cycle_credential).await;
        })
        .await
        {
            tracing::warn!("audit checkpoint submission cycle task panicked");
        }
    }
}

/// `0..=30` seconds -- see `policy_poll::startup_jitter_seconds`'s
/// identical rationale (avoid a fleet-restart thundering herd without a
/// `rand` dependency).
fn startup_jitter_seconds() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::from(d.subsec_nanos()) % 31)
        .unwrap_or(0)
}

/// ADR-0012 §8.2: runs the comparison for every stored receipt against the
/// CURRENT local chain, logging (never suppressing) any non-`Consistent`
/// finding. Never panics, never returns an error.
async fn evaluate_and_log_receipts(state: &AppState) {
    match state.store.evaluate_all_checkpoint_receipts().await {
        Ok(results) => {
            for (receipt, verdict) in results {
                if verdict != fornax_store::CheckpointConsistencyVerdict::Consistent {
                    tracing::warn!(
                        checkpoint_seq = receipt.checkpoint_seq,
                        head_ledger_seq = receipt.head_ledger_seq,
                        verdict = ?verdict,
                        "audit checkpoint: a previously-attested head is no longer consistent \
                         with the local ledger"
                    );
                }
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "audit checkpoint submission: failed to evaluate prior receipts");
        }
    }
}

/// One end-to-end submission attempt. Never panics, never returns an
/// error -- every failure is logged and swallowed, per this module's
/// best-effort discipline.
async fn submit_one_cycle(
    state: &AppState,
    http: &reqwest::Client,
    url: &reqwest::Url,
    credential: &str,
) {
    if !fornax_types::privacy::cloud_sync_allowed() {
        return;
    }

    let events = match state.store.audit_events().await {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(error = %e, "audit checkpoint submission: failed to read local ledger");
            return;
        }
    };
    // ADR-0012 §2.2: an empty ledger has no head to attest -- skip.
    let Some(tail) = events.last() else {
        return;
    };

    let chain = match state.store.verify_audit_chain().await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "audit checkpoint submission: failed to verify local chain");
            return;
        }
    };
    let device_reported_chain_status = match &chain {
        fornax_store::ChainVerification::Valid => DeviceReportedChainStatus {
            status: "valid".to_string(),
            first_bad_ledger_seq: None,
            divergence_kind: None,
        },
        fornax_store::ChainVerification::Diverged {
            first_bad_seq,
            kind,
        } => DeviceReportedChainStatus {
            status: "diverged".to_string(),
            first_bad_ledger_seq: Some(*first_bad_seq),
            divergence_kind: Some(divergence_kind_wire_str(*kind).to_string()),
        },
    };

    // ADR-0012 §8.2: run the comparison against prior receipts (again,
    // right before this new submission -- see `evaluate_and_log_receipts`'s
    // other call site at daemon start) and log (never suppress) any
    // non-`Consistent` finding -- see this module's top doc comment for
    // why it is not folded into the wire status above.
    evaluate_and_log_receipts(state).await;

    let next_checkpoint_seq = match state.store.latest_audit_checkpoint_receipt().await {
        Ok(Some(latest)) => latest.checkpoint_seq + 1,
        Ok(None) => 1,
        Err(e) => {
            tracing::warn!(error = %e, "audit checkpoint submission: failed to read prior receipt");
            return;
        }
    };

    let request = AuditCheckpointRequest {
        checkpoint_schema_version: fornax_types::AUDIT_CHECKPOINT_SCHEMA_VERSION,
        checkpoint_seq: next_checkpoint_seq,
        observed_at: rfc3339_z(Utc::now()),
        head: LedgerHead {
            ledger_seq: tail.seq,
            entry_hash: tail.entry_hash.clone(),
        },
        device_reported_chain_status,
    };

    let response = match http
        .post(url.clone())
        .bearer_auth(credential)
        .header(reqwest::header::ACCEPT, "application/json")
        .json(&request)
        .timeout(Duration::from_secs(20))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %classify_transport_error(&e), "audit checkpoint submission: request failed");
            return;
        }
    };

    if !response.status().is_success() {
        tracing::warn!(
            status = response.status().as_u16(),
            "audit checkpoint submission: non-2xx response"
        );
        return;
    }

    let mut response = response;
    let mut body: Vec<u8> = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                body.extend_from_slice(&chunk);
                if body.len() > MAX_RESPONSE_BYTES {
                    tracing::warn!("audit checkpoint submission: response exceeded size limit");
                    return;
                }
            }
            Ok(None) => break,
            Err(e) => {
                tracing::warn!(error = %classify_transport_error(&e), "audit checkpoint submission: failed reading response body");
                return;
            }
        }
    }

    let Some(trust) = state.trust.as_ref() else {
        tracing::warn!(
            "audit checkpoint submission: no trust store configured; cannot verify response"
        );
        return;
    };

    let verified = match verify_audit_checkpoint(&body, trust, Utc::now()) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "audit checkpoint submission: response failed verification");
            return;
        }
    };

    // §8.2: the response must echo what this device submitted.
    if verified.head().ledger_seq != tail.seq || verified.head().entry_hash != tail.entry_hash {
        tracing::warn!(
            "audit checkpoint submission: verified response's head does not match what this \
             device submitted; refusing to store it"
        );
        return;
    }

    // §3.2: "A device must check [device_id] equals its own." This device
    // has no independent config source for its own device_id (see this
    // module's flagged implementation gap), so the check is against the
    // FIRST receipt this device ever stored -- that bootstrap anchor's
    // `device_id` is what every later response must continue to match.
    // The very first receipt has nothing to check against and is accepted
    // unconditionally; every subsequent mismatch is refused and not stored.
    match state.store.first_audit_checkpoint_receipt().await {
        Ok(Some(anchor)) if anchor.device_id != verified.device_id() => {
            tracing::warn!(
                "audit checkpoint submission: verified response's device_id does not match \
                 this device's own bootstrap anchor; refusing to store it"
            );
            return;
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(error = %e, "audit checkpoint submission: failed to read bootstrap anchor receipt");
            return;
        }
    }

    let envelope_json = match String::from_utf8(body) {
        Ok(s) => s,
        Err(_) => {
            tracing::warn!(
                "audit checkpoint submission: verified response body was not valid UTF-8"
            );
            return;
        }
    };

    if let Err(e) = state
        .store
        .store_audit_checkpoint_receipt(&verified, &envelope_json)
        .await
    {
        tracing::warn!(error = %e, "audit checkpoint submission: failed to persist verified receipt");
    }
}

fn divergence_kind_wire_str(kind: fornax_store::DivergenceKind) -> &'static str {
    use fornax_store::DivergenceKind as K;
    use fornax_types::divergence_kind_wire as W;
    match kind {
        K::HashMismatch => W::HASH_MISMATCH,
        K::MissingSeq => W::MISSING_SEQ,
        K::TruncatedTail => W::TRUNCATED_TAIL,
        K::RelinkedPrevHash => W::RELINKED_PREV_HASH,
    }
}

/// ADR-0012 §4.2: "seconds precision, no fractional part, literal trailing
/// `Z`, never `+00:00`" -- `chrono`'s `to_rfc3339()` emits `+00:00`, which
/// is why this uses an explicit `strftime`-style format string instead.
fn rfc3339_z(dt: chrono::DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn classify_transport_error(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        "request timed out".to_string()
    } else if e.is_connect() {
        "connection failed".to_string()
    } else if e.is_decode() {
        "response decode error".to_string()
    } else if e.is_body() {
        "response body error".to_string()
    } else {
        "transport error".to_string()
    }
}

/// Mirrors `policy_poll::resolve_poll_config`'s discipline: reads env vars
/// once, requires both a valid URL and a readable credential file, and
/// additionally requires [`fornax_types::privacy::cloud_sync_allowed`].
fn resolve_submit_config(home: &Path) -> Option<SubmitConfig> {
    if !fornax_types::privacy::cloud_sync_allowed() {
        return None;
    }

    let raw_url = std::env::var(CHECKPOINT_URL_ENV).ok()?;
    if raw_url.trim().is_empty() {
        return None;
    }
    let url = reqwest::Url::parse(&raw_url).ok()?;
    let host_is_local = matches!(url.host_str(), Some("127.0.0.1") | Some("localhost"));
    if url.scheme() != "https" && !(url.scheme() == "http" && host_is_local) {
        tracing::warn!(
            scheme = %url.scheme(),
            "audit checkpoint submission disabled: {CHECKPOINT_URL_ENV} must use https://"
        );
        return None;
    }

    let credential_path = std::env::var(CREDENTIAL_FILE_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|_| home.join(DEFAULT_CREDENTIAL_FILE_NAME));
    let raw_credential = std::fs::read_to_string(&credential_path).ok()?;
    let credential_value = raw_credential
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    if credential_value.is_empty() {
        return None;
    }

    let mut interval_secs = std::env::var(INTERVAL_ENV)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_INTERVAL_SECONDS);
    if interval_secs < MIN_INTERVAL_SECONDS {
        interval_secs = MIN_INTERVAL_SECONDS;
    }

    Some(SubmitConfig {
        url,
        credential: DeviceCredential(credential_value),
        interval: Duration::from_secs(interval_secs),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t01_disabled_without_cloud_sync_enabled() {
        std::env::remove_var("FORNAX_CLOUD_SYNC_ENABLED");
        std::env::set_var(CHECKPOINT_URL_ENV, "https://cloud.example.com/checkpoints");
        let home =
            std::env::temp_dir().join(format!("fnx-checkpoint-cfg-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&home).unwrap();
        assert!(resolve_submit_config(&home).is_none());
        std::env::remove_var(CHECKPOINT_URL_ENV);
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn t02_divergence_kind_wire_mapping_matches_adr_0012_table() {
        assert_eq!(
            divergence_kind_wire_str(fornax_store::DivergenceKind::HashMismatch),
            "hash_mismatch"
        );
        assert_eq!(
            divergence_kind_wire_str(fornax_store::DivergenceKind::MissingSeq),
            "missing_ledger_seq"
        );
        assert_eq!(
            divergence_kind_wire_str(fornax_store::DivergenceKind::TruncatedTail),
            "truncated_tail"
        );
        assert_eq!(
            divergence_kind_wire_str(fornax_store::DivergenceKind::RelinkedPrevHash),
            "relinked_prev_hash"
        );
    }

    /// ADR-0012 §4.2: seconds precision, no fractional part, literal
    /// trailing `Z`, never `+00:00`. `to_rfc3339()` would emit `+00:00`;
    /// this pins the actual emitted shape against a fixed instant.
    #[test]
    fn t03_rfc3339_z_emits_the_exact_adr_0012_shape() {
        let dt: chrono::DateTime<Utc> = "2026-09-03T12:00:00.123456Z".parse().unwrap();
        assert_eq!(rfc3339_z(dt), "2026-09-03T12:00:00Z");
        assert!(!rfc3339_z(dt).contains('+'));
        assert!(!rfc3339_z(dt).contains('.'));
    }

    /// ADR-0012 §2.2: the request body's key order is normative. Confirms
    /// `AuditCheckpointRequest`'s `Serialize` impl (derived from its field
    /// declaration order) emits the exact key sequence the contract
    /// specifies, with every `Option` present as explicit `null` rather
    /// than omitted -- the request-emission half of the same discipline
    /// `fornax-types`' golden-vector test proves for the response payload.
    #[test]
    fn t04_request_serializes_keys_in_the_adr_0012_normative_order() {
        let request = AuditCheckpointRequest {
            checkpoint_schema_version: 1,
            checkpoint_seq: 1,
            observed_at: "2026-09-03T12:00:00Z".to_string(),
            head: LedgerHead {
                ledger_seq: 5,
                entry_hash:
                    "sha256:e967d0e31e6afd2a3a0f5bd805e39f85eb0eeb4e176e88e0e65d3c26a1cba464"
                        .to_string(),
            },
            device_reported_chain_status: DeviceReportedChainStatus {
                status: "valid".to_string(),
                first_bad_ledger_seq: None,
                divergence_kind: None,
            },
        };
        // `serde_json::Value`'s map is a `BTreeMap` (alphabetically
        // sorted) without the `preserve_order` feature, so key ORDER must
        // be checked against the serialized STRING, not a re-parsed
        // `Value` -- `to_value` would silently re-sort the keys and make
        // this assertion pass regardless of the struct's actual field
        // order.
        let json = serde_json::to_string(&request).unwrap();
        let positions: Vec<usize> = [
            "\"checkpoint_schema_version\"",
            "\"checkpoint_seq\"",
            "\"observed_at\"",
            "\"head\"",
            "\"device_reported_chain_status\"",
        ]
        .iter()
        .map(|key| {
            json.find(key)
                .unwrap_or_else(|| panic!("{key} missing from {json}"))
        })
        .collect();
        assert!(
            positions.windows(2).all(|w| w[0] < w[1]),
            "keys are not in ADR-0012 §2.2's normative order: {json}"
        );
        assert!(json.contains("\"first_bad_ledger_seq\":null"));
        assert!(json.contains("\"divergence_kind\":null"));
    }
}
