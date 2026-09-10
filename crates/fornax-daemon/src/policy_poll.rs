//! Background policy bundle poll transport (FORNX-311, epic FORNX-69).
//!
//! **Pull, not push.** A background task inside this daemon periodically
//! `GET`s a fornax-cloud endpoint and hands whatever it finds to the
//! ALREADY-EXISTING `handle_policy_bundle_ingest`/
//! `handle_policy_revocation_ingest` functions (FORNX-119/123) — exactly as
//! the UDS ingest path already does for `fornax policy import`. This module
//! adds **zero new trust logic**: `verify_bundle`, `evaluate_activation`,
//! `submit_policy_bundle`, `submit_policy_revocation`, and
//! `load_policy_cache` are all untouched. Its entire job is moving bytes
//! from an HTTP response to those functions.
//!
//! **No conditional fetch.** The full response is processed every cycle,
//! even when nothing has changed — re-submitting byte-identical bundle bytes
//! through `submit_policy_bundle` produces `ActivationDecision::Confirm`,
//! the only mechanism that advances `confirmed_at` and resets ADR-0008's
//! staleness clock. See `docs/adr/0010-policy-bundle-distribution.md` for
//! why a future conditional-fetch/304 optimization must not be introduced
//! without re-opening that gap.
//!
//! **Normative poll-cycle order** (mirrors `verify_bundle`/
//! `evaluate_activation`'s numbered-list doc convention):
//!
//! 1. If polling is disabled (no `FORNAX_POLICY_POLL_URL` or no valid,
//!    correctly-permissioned credential file) -> `Disabled`, no network
//!    contact, no error.
//! 2. Wait for the tick: at startup, jitter `0..=30s` (avoids a
//!    fleet-restart thundering herd); thereafter `interval *
//!    backoff_multiplier`.
//! 3. `GET <url>` with the bearer header, `Accept: application/json`,
//!    connect timeout 5s, total timeout 20s. Transport failure ->
//!    `Unreachable`, go to step 11.
//! 4. HTTP 401/403 -> `AuthFailed`. Any other non-2xx -> `HttpError`. Both
//!    -> step 11. Never retried within one cycle.
//! 5. Read the body bounded by [`MAX_RESPONSE_BYTES`], enforced WHILE
//!    STREAMING (`Response::chunk`, never `Content-Length`, which is
//!    attacker-influenced). Exceeding it -> `TooLarge`, step 11.
//! 6. Parse as [`PollResponseEnvelope`]. Parse failure -> `Malformed`, step
//!    11. Nothing inside is trusted yet.
//! 7. If `revocation` is present: bound-check its serialized length against
//!    `MAX_PAYLOAD_BYTES` before re-serializing/handing it on, then call
//!    `handle_policy_revocation_ingest`. This happens BEFORE any bundle in
//!    the same cycle — `evaluate_activation` already checks revocation
//!    first, so same-cycle ordering means a bundle carrying a
//!    just-revoked digest is rejected immediately.
//! 8. For each entry in `bundles`, in order, bounded by
//!    [`MAX_BUNDLES_PER_RESPONSE`] (truncate + warn beyond that), same
//!    length check, then call `handle_policy_bundle_ingest`. Each
//!    submission is independent — one rejection never aborts the loop.
//! 9. The response is submitted in FULL every cycle regardless of whether
//!    anything looks unchanged — no "skip if identical" optimization.
//! 10. Success (steps 3-9 completed without a transport/parse-level
//!     failure, regardless of individual per-bundle accept/reject
//!     outcomes): record `Ok`, reset `consecutive_failures` to 0 and
//!     `backoff_multiplier` to 1.
//! 11. Failure: increment `consecutive_failures`; set `backoff_multiplier =
//!     min(2^consecutive_failures, ceiling)` where `interval * ceiling <=
//!     3600` (cap total backoff interval at 1 hour). NEVER touch
//!     `state.policy`'s `state`/`usable`/`loaded_slot` fields on a
//!     transport-level failure — the existing cache stands exactly as
//!     FORNX-119 left it; only `last_poll` changes (and, additively, the
//!     [`fornax_types::DiagnosticCode::PolicyRefreshUnavailable`]
//!     diagnostic once `consecutive_failures >= 3` — see
//!     [`upsert_refresh_unavailable_diagnostic`]).
//! 12. Loop to step 2. Never exits except on task abort at daemon shutdown.
//!
//! **Concurrency.** This task does NOT acquire `AppState::processing`.
//! Bundle/revocation ingest touches entirely separate tables from
//! evidence/claim processing; `submit_policy_bundle`'s own `BEGIN
//! IMMEDIATE` transaction is the real serializer for policy-cache writes.
//! Holding the broader `processing` mutex here would put a background
//! network task ahead of a live hook request, against ADR-0001 D2's
//! spirit.
//!
//! **Panic containment.** Each poll-cycle attempt runs as its own spawned
//! task ([`supervisor_loop`]); a panic inside [`run_one_cycle`] surfaces as
//! an ordinary `JoinError`, recorded as the `"panicked"` outcome for that
//! cycle. The supervisor loop itself never panics, so the *next* tick
//! always runs.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use fornax_types::{DiagnosticCode, DiagnosticSeverity, PolicyContent, PolicyDiagnostic};
use serde::Deserialize;

use crate::{AppState, LastPolicyPoll};

/// Bounds the pre-authentication work a hostile/misbehaving cloud endpoint
/// can force onto this path — enforced while streaming, never trusting
/// `Content-Length`.
pub(crate) const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
/// Protects the daemon from an oversized response; the cloud side is
/// separately expected to already cap its own response.
pub(crate) const MAX_BUNDLES_PER_RESPONSE: usize = 32;
pub(crate) const DEFAULT_INTERVAL_SECONDS: u64 = 900;
pub(crate) const MIN_INTERVAL_SECONDS: u64 = 60;
/// `interval * backoff_multiplier` never exceeds this — the concrete,
/// named emergency-response bound under sustained poll failure.
pub(crate) const BACKOFF_CEILING_SECONDS: u64 = 3600;

const POLL_URL_ENV: &str = "FORNAX_POLICY_POLL_URL";
const CREDENTIAL_FILE_ENV: &str = "FORNAX_DEVICE_CREDENTIAL_FILE";
const INTERVAL_ENV: &str = "FORNAX_POLICY_POLL_INTERVAL_SECONDS";
const DEFAULT_CREDENTIAL_FILE_NAME: &str = "device-credential";
/// Test-only escape hatch (see [`run_one_cycle`]'s first line): gated
/// behind an explicit opt-in env var an operator would never set, so it can
/// never fire outside a deliberate test harness. Exists because
/// `fornax-daemon` has no library target — integration tests exercise the
/// compiled binary as a real subprocess (see `tests/`), so a panic must be
/// injectable from outside the process rather than via `#[cfg(test)]`.
const TEST_PANIC_ENV: &str = "FORNAX_POLICY_POLL_TEST_PANIC";

/// Never `Debug`/`Display`s its contents. The credential value must never
/// appear in a log line, an error message, an HTTP response, or any
/// diagnostic string, anywhere.
struct DeviceCredential(String);

impl DeviceCredential {
    fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for DeviceCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeviceCredential(<redacted>)")
    }
}

#[derive(Clone)]
struct PollConfig {
    url: reqwest::Url,
    credential: Arc<DeviceCredential>,
    interval: Duration,
}

impl std::fmt::Debug for PollConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PollConfig")
            .field("url", &self.url.as_str())
            .field("credential", &"<redacted>")
            .field("interval", &self.interval)
            .finish()
    }
}

/// The fornax-cloud poll-response envelope (see FORNX-311's wire contract).
/// Deliberately liberal about fields this binary doesn't yet use
/// (`schema_version`/`device_id`/`issuer`/`server_time` are parsed for
/// forward-compat shape only) and strict about the two fields it does use:
/// `bundles` stays raw `serde_json::Value`s (re-serialized to bytes and
/// handed to the existing ingest path, never eagerly typed as
/// `SignedPolicyBundle` here — that parsing is `verify_bundle`'s job, not
/// this module's) and `revocation` is nullable exactly as documented.
#[derive(Debug, Deserialize)]
struct PollResponseEnvelope {
    #[allow(dead_code)]
    schema_version: u32,
    #[allow(dead_code)]
    device_id: String,
    #[allow(dead_code)]
    issuer: String,
    #[allow(dead_code)]
    server_time: String,
    bundles: Vec<serde_json::Value>,
    revocation: Option<serde_json::Value>,
}

/// The result of one poll-cycle attempt, before the supervisor loop folds
/// it into `consecutive_failures`/`backoff_multiplier` and persists it as
/// [`LastPolicyPoll`].
struct CycleOutcomeResult {
    outcome: &'static str,
    detail: String,
    bundles_received: usize,
}

/// Spawns the poll supervisor task. Always returns a `JoinHandle` — even
/// when polling ends up disabled, so `main()` can `.abort()` it
/// unconditionally in the graceful-shutdown block, mirroring exactly how
/// the UDS ingest task handle is already aborted there.
pub(crate) fn spawn(state: AppState, home: PathBuf) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move { supervisor_loop(state, home).await })
}

/// Step 1: config resolution, then hands off to [`run_supervisor`] for
/// steps 2-12. Never panics itself — a panic inside one cycle is caught by
/// the per-cycle `JoinError` handled in `run_supervisor`, never propagated
/// past this function.
async fn supervisor_loop(state: AppState, home: PathBuf) {
    let Some(config) = resolve_poll_config(&home) else {
        record_disabled(&state).await;
        return;
    };
    run_supervisor(state, config).await;
}

/// Steps 2-12 (the tick loop), factored out of [`supervisor_loop`] so tests
/// can drive it with a directly-constructed [`PollConfig`] (a fast interval,
/// no 60s floor) instead of round-tripping through env vars and a real
/// credential file on disk. Thin wrapper over [`run_supervisor_inner`] with
/// the startup jitter enabled, as production always wants.
async fn run_supervisor(state: AppState, config: PollConfig) {
    run_supervisor_inner(state, config, true).await;
}

/// `skip_startup_jitter` exists ONLY so tests can drive many ticks
/// deterministically and quickly instead of waiting up to the real
/// `0..=30s` startup jitter on every single test — production code always
/// calls this via [`run_supervisor`] with jitter enabled.
async fn run_supervisor_inner(state: AppState, config: PollConfig, use_startup_jitter: bool) {
    let http = build_http_client();
    let mut consecutive_failures: u32 = 0;
    let mut backoff_multiplier: u32 = 1;
    let mut first_tick = true;

    loop {
        // Step 2: wait for the tick.
        let wait = if first_tick {
            first_tick = false;
            if use_startup_jitter {
                Duration::from_secs(startup_jitter_seconds())
            } else {
                Duration::ZERO
            }
        } else {
            config.interval.saturating_mul(backoff_multiplier)
        };
        tokio::time::sleep(wait).await;

        let attempted_at = Utc::now();
        let cycle_state = state.clone();
        let cycle_config = config.clone();
        let cycle_http = http.clone();

        // Panic containment: each attempt is its own spawned task, awaited
        // here. A panic surfaces as `Err(JoinError)`, never propagated.
        let outcome =
            match tokio::spawn(
                async move { run_one_cycle(cycle_state, cycle_config, cycle_http).await },
            )
            .await
            {
                Ok(result) => result,
                Err(_join_err) => CycleOutcomeResult {
                    outcome: "panicked",
                    detail: "poll cycle task panicked".to_string(),
                    bundles_received: 0,
                },
            };

        // Steps 10-11: fold into consecutive_failures/backoff_multiplier.
        if outcome.outcome == "ok" {
            consecutive_failures = 0;
            backoff_multiplier = 1;
        } else {
            consecutive_failures = consecutive_failures.saturating_add(1);
            backoff_multiplier = compute_backoff_multiplier(consecutive_failures, config.interval);
        }

        let next_wait = config.interval.saturating_mul(backoff_multiplier);
        let next_attempt_at =
            attempted_at + chrono::Duration::from_std(next_wait).unwrap_or(chrono::Duration::MAX);

        record_cycle(
            &state,
            LastPolicyPoll {
                attempted_at,
                outcome: outcome.outcome,
                detail: outcome.detail,
                bundles_received: outcome.bundles_received,
                consecutive_failures,
                next_attempt_at,
            },
        )
        .await;
    }
}

/// `backoff_multiplier = min(2^consecutive_failures, ceiling)` where
/// `interval * ceiling <= BACKOFF_CEILING_SECONDS`.
fn compute_backoff_multiplier(consecutive_failures: u32, interval: Duration) -> u32 {
    let interval_secs = interval.as_secs().max(1);
    let ceiling = (BACKOFF_CEILING_SECONDS / interval_secs).max(1) as u32;
    let pow = 2u32.saturating_pow(consecutive_failures.min(31));
    pow.min(ceiling)
}

/// `0..=30` seconds, without pulling in a `rand` dependency for one jitter
/// value — sub-second-precision process-start-time entropy is more than
/// sufficient for "avoid a fleet-restart thundering herd", which is the
/// only property this needs.
fn startup_jitter_seconds() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::from(d.subsec_nanos()) % 31)
        .unwrap_or(0)
}

fn build_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

/// Step 1: resolve whether polling is enabled at all, reading the three env
/// vars ONCE — never re-read for the lifetime of this task, matching the
/// trust store's own discipline (`resolve_trust_store`). Polling is enabled
/// only if BOTH a valid URL and a readable, correctly-permissioned
/// credential file are present. Logs once at `info` when disabled — this
/// must not read as an error in normal logs, since most installs won't have
/// this configured.
fn resolve_poll_config(home: &Path) -> Option<PollConfig> {
    let raw_url = match std::env::var(POLL_URL_ENV) {
        Ok(u) if !u.trim().is_empty() => u,
        _ => {
            tracing::info!(
                "policy poll transport disabled: {POLL_URL_ENV} is not set (this is the \
                 expected state for most installs)"
            );
            return None;
        }
    };

    let url = match reqwest::Url::parse(&raw_url) {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "policy poll transport disabled: {POLL_URL_ENV} is not a valid URL"
            );
            return None;
        }
    };

    let host_is_local = matches!(url.host_str(), Some("127.0.0.1") | Some("localhost"));
    if url.scheme() != "https" && !(url.scheme() == "http" && host_is_local) {
        tracing::warn!(
            scheme = %url.scheme(),
            "policy poll transport disabled: {POLL_URL_ENV} must use https:// (http:// is \
             only permitted for 127.0.0.1/localhost for local testing/dev)"
        );
        return None;
    }

    let credential_path = std::env::var(CREDENTIAL_FILE_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|_| home.join(DEFAULT_CREDENTIAL_FILE_NAME));

    if !credential_path.exists() {
        tracing::info!(
            path = %credential_path.display(),
            "policy poll transport disabled: no device credential file present"
        );
        return None;
    }

    if let Err(reason) = check_credential_file_permissions(&credential_path) {
        tracing::warn!("policy poll transport disabled: {reason}");
        return None;
    }

    let raw_credential = match std::fs::read_to_string(&credential_path) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                error = %e,
                path = %credential_path.display(),
                "policy poll transport disabled: failed to read device credential file"
            );
            return None;
        }
    };
    let credential_value = raw_credential
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    if credential_value.is_empty() {
        tracing::warn!(
            path = %credential_path.display(),
            "policy poll transport disabled: device credential file is empty"
        );
        return None;
    }

    let mut interval_secs = std::env::var(INTERVAL_ENV)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_INTERVAL_SECONDS);
    if interval_secs < MIN_INTERVAL_SECONDS {
        tracing::warn!(
            configured_seconds = interval_secs,
            floor_seconds = MIN_INTERVAL_SECONDS,
            "{INTERVAL_ENV} is below the floor; clamping"
        );
        interval_secs = MIN_INTERVAL_SECONDS;
    }
    let offline_grace_seconds = u64::from(PolicyContent::baseline().cache_offline_grace_seconds);
    if interval_secs > offline_grace_seconds {
        tracing::warn!(
            configured_seconds = interval_secs,
            offline_grace_seconds,
            "{INTERVAL_ENV} exceeds the policy's own offline_grace_seconds baseline"
        );
    }

    tracing::info!(
        scheme = %url.scheme(),
        host = %url.host_str().unwrap_or(""),
        path = %url.path(),
        interval_seconds = interval_secs,
        "policy poll transport enabled"
    );

    Some(PollConfig {
        url,
        credential: Arc::new(DeviceCredential(credential_value)),
        interval: Duration::from_secs(interval_secs),
    })
}

#[cfg(unix)]
fn check_credential_file_permissions(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path).map_err(|e| {
        format!(
            "could not stat device credential file {}: {e}",
            path.display()
        )
    })?;
    let mode = meta.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(format!(
            "device credential file {} is group/world-readable (mode {:o}); refusing to use it \
             (chmod 600 it)",
            path.display(),
            mode & 0o777
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_credential_file_permissions(_path: &Path) -> Result<(), String> {
    Ok(())
}

/// Steps 3-9 of one poll cycle. Owned parameters (not borrowed) so this can
/// be `tokio::spawn`ed by [`supervisor_loop`] for panic containment.
async fn run_one_cycle(
    state: AppState,
    config: PollConfig,
    http: reqwest::Client,
) -> CycleOutcomeResult {
    // Test-only panic injection -- see `TEST_PANIC_ENV`'s doc comment.
    if std::env::var(TEST_PANIC_ENV).as_deref() == Ok("1") {
        panic!("FORNX-311 test-injected panic (FORNAX_POLICY_POLL_TEST_PANIC=1)");
    }

    // Step 3: fetch.
    let request = http
        .get(config.url.clone())
        .bearer_auth(config.credential.as_str())
        .header(reqwest::header::ACCEPT, "application/json")
        .timeout(Duration::from_secs(20));
    let response = match request.send().await {
        Ok(r) => r,
        Err(e) => {
            return CycleOutcomeResult {
                outcome: "unreachable",
                detail: classify_transport_error(&e),
                bundles_received: 0,
            };
        }
    };

    // Step 4: status.
    let status = response.status();
    if status.as_u16() == 401 || status.as_u16() == 403 {
        return CycleOutcomeResult {
            outcome: "auth_failed",
            detail: format!("http status {}", status.as_u16()),
            bundles_received: 0,
        };
    }
    if !status.is_success() {
        return CycleOutcomeResult {
            outcome: "http_error",
            detail: format!("http status {}", status.as_u16()),
            bundles_received: 0,
        };
    }

    // Step 5: bounded streaming read -- `Response::chunk`, never trusting
    // `Content-Length`.
    let mut response = response;
    let mut body: Vec<u8> = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                body.extend_from_slice(&chunk);
                if body.len() > MAX_RESPONSE_BYTES {
                    return CycleOutcomeResult {
                        outcome: "too_large",
                        detail: format!("response body exceeded {MAX_RESPONSE_BYTES} bytes"),
                        bundles_received: 0,
                    };
                }
            }
            Ok(None) => break,
            Err(e) => {
                return CycleOutcomeResult {
                    outcome: "unreachable",
                    detail: classify_transport_error(&e),
                    bundles_received: 0,
                };
            }
        }
    }

    // Step 6: parse envelope. Nothing inside is trusted yet.
    let envelope: PollResponseEnvelope = match serde_json::from_slice(&body) {
        Ok(e) => e,
        Err(e) => {
            return CycleOutcomeResult {
                outcome: "malformed",
                detail: format!("response body did not parse as the poll-response envelope: {e}"),
                bundles_received: 0,
            };
        }
    };

    // Step 7: revocation BEFORE any bundle, same cycle.
    if let Some(revocation_value) = &envelope.revocation {
        match serde_json::to_vec(revocation_value) {
            Ok(bytes) if bytes.len() <= fornax_types::policy::MAX_PAYLOAD_BYTES => {
                crate::handle_policy_revocation_ingest(&state, bytes).await;
            }
            Ok(bytes) => {
                tracing::warn!(
                    len = bytes.len(),
                    max = fornax_types::policy::MAX_PAYLOAD_BYTES,
                    "policy poll: revocation entry exceeds the payload size limit, skipping"
                );
            }
            Err(e) => {
                tracing::warn!(error = %e, "policy poll: failed to re-serialize revocation entry, skipping");
            }
        }
    }

    // Step 8: bundles, bounded by MAX_BUNDLES_PER_RESPONSE, each submission
    // independent.
    let total = envelope.bundles.len();
    if total > MAX_BUNDLES_PER_RESPONSE {
        tracing::warn!(
            total,
            limit = MAX_BUNDLES_PER_RESPONSE,
            "policy poll: response carries more bundles than the per-cycle limit; truncating"
        );
    }
    let mut processed = 0usize;
    for bundle_value in envelope.bundles.iter().take(MAX_BUNDLES_PER_RESPONSE) {
        let bytes = match serde_json::to_vec(bundle_value) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, "policy poll: failed to re-serialize bundle entry, skipping");
                continue;
            }
        };
        if bytes.len() > fornax_types::policy::MAX_PAYLOAD_BYTES {
            tracing::warn!(
                len = bytes.len(),
                max = fornax_types::policy::MAX_PAYLOAD_BYTES,
                "policy poll: bundle entry exceeds the payload size limit, skipping"
            );
            continue;
        }
        // Step 9: submitted in full every cycle, regardless of whether it
        // looks unchanged -- see this module's top doc comment.
        crate::handle_policy_bundle_ingest(&state, bytes).await;
        processed += 1;
    }

    CycleOutcomeResult {
        outcome: "ok",
        detail: format!(
            "processed {processed} of {total} bundle(s); revocation_present={}",
            envelope.revocation.is_some()
        ),
        bundles_received: processed,
    }
}

/// Never includes the raw `reqwest::Error` `Display` output, which embeds
/// the request URL -- classified into a coarse, URL-free string instead.
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

async fn record_disabled(state: &AppState) {
    let mut policy = state.policy.write().await;
    let now = Utc::now();
    policy.last_poll = Some(LastPolicyPoll {
        attempted_at: now,
        outcome: "disabled",
        detail: "policy poll transport is not configured".to_string(),
        bundles_received: 0,
        consecutive_failures: 0,
        next_attempt_at: now,
    });
}

async fn record_cycle(state: &AppState, last_poll: LastPolicyPoll) {
    let mut policy = state.policy.write().await;
    let consecutive_failures = last_poll.consecutive_failures;
    policy.last_poll = Some(last_poll);
    upsert_refresh_unavailable_diagnostic(&mut policy.diagnostics, consecutive_failures);
}

/// Additive, idempotent: at most one [`DiagnosticCode::PolicyRefreshUnavailable`]
/// diagnostic is ever present, and every other diagnostic already in the
/// vector (e.g. from `load_policy_cache`) is left untouched. Cleared the
/// moment a cycle succeeds (`consecutive_failures` resets to 0), so a
/// recovered poller doesn't leave a stale warning behind.
fn upsert_refresh_unavailable_diagnostic(
    diagnostics: &mut Vec<PolicyDiagnostic>,
    consecutive_failures: u32,
) {
    diagnostics.retain(|d| d.code != DiagnosticCode::PolicyRefreshUnavailable);
    if consecutive_failures >= 3 {
        diagnostics.push(PolicyDiagnostic::new(
            DiagnosticCode::PolicyRefreshUnavailable,
            DiagnosticSeverity::Warning,
            format!(
                "the background policy poll transport has failed {consecutive_failures} \
                 consecutive cycles"
            ),
            format!(
                "check {POLL_URL_ENV} and {CREDENTIAL_FILE_ENV} are correctly configured, the \
                 endpoint is reachable, and the device credential is valid"
            ),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t01_backoff_multiplier_grows_then_caps_at_the_one_hour_ceiling() {
        let interval = Duration::from_secs(900); // ceiling = 3600/900 = 4
        assert_eq!(compute_backoff_multiplier(0, interval), 1);
        assert_eq!(compute_backoff_multiplier(1, interval), 2);
        assert_eq!(compute_backoff_multiplier(2, interval), 4);
        assert_eq!(compute_backoff_multiplier(3, interval), 4);
        assert_eq!(compute_backoff_multiplier(10, interval), 4);
        // interval * multiplier never exceeds the 1-hour ceiling.
        for failures in 0..20 {
            let m = compute_backoff_multiplier(failures, interval);
            assert!(interval.as_secs() * m as u64 <= BACKOFF_CEILING_SECONDS);
        }
    }

    #[test]
    fn t02_backoff_multiplier_with_a_small_interval_still_respects_the_ceiling() {
        let interval = Duration::from_secs(60); // ceiling = 3600/60 = 60
        assert_eq!(compute_backoff_multiplier(1, interval), 2);
        assert_eq!(compute_backoff_multiplier(5, interval), 32);
        assert_eq!(compute_backoff_multiplier(6, interval), 60); // min(64, 60)
        assert_eq!(compute_backoff_multiplier(20, interval), 60);
    }

    #[test]
    fn t03_upsert_refresh_unavailable_diagnostic_is_additive_and_idempotent() {
        let mut diagnostics = vec![PolicyDiagnostic::new(
            DiagnosticCode::TrustStoreUnavailable,
            DiagnosticSeverity::Warning,
            "unrelated",
            "unrelated",
        )];
        upsert_refresh_unavailable_diagnostic(&mut diagnostics, 2);
        assert_eq!(diagnostics.len(), 1, "below threshold: no diagnostic added");

        upsert_refresh_unavailable_diagnostic(&mut diagnostics, 3);
        assert_eq!(diagnostics.len(), 2);
        assert!(diagnostics
            .iter()
            .any(|d| d.code == DiagnosticCode::PolicyRefreshUnavailable));

        // Idempotent: calling again at a higher count never duplicates.
        upsert_refresh_unavailable_diagnostic(&mut diagnostics, 4);
        assert_eq!(diagnostics.len(), 2);

        // Recovery clears it, leaving the unrelated diagnostic untouched.
        upsert_refresh_unavailable_diagnostic(&mut diagnostics, 0);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, DiagnosticCode::TrustStoreUnavailable);
    }

    // -----------------------------------------------------------------
    // Test infrastructure: a hand-rolled TCP HTTP/1.1 mock server (no new
    // dependency), a real `fornax-store::Store` against a scratch SQLite
    // file, and a from-scratch signed-bundle/signed-revocation builder
    // using only public `fornax_types` API (this crate has no access to
    // `fornax-types`' own private test helpers).
    // -----------------------------------------------------------------

    use std::sync::Mutex as StdMutex;

    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    use fornax_types::policy::{
        BundlePayload, BundleProvenance, BundleSignature, SignatureAlgorithm, SignedPolicyBundle,
        TrustedKey, BUNDLE_SCHEMA_VERSION, BUNDLE_SIGNING_DOMAIN,
    };
    use fornax_types::{
        PolicyBinding, PolicyContent, PolicyDraft, PolicyId, RevocationEntry, RevocationPayload,
        RevocationTarget, SignedRevocationList, TargetScope, TargetSelector,
        TrustedVerificationKeys, REVOCATION_SCHEMA_VERSION, REVOCATION_SIGNING_DOMAIN,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::{Mutex as TokioMutex, RwLock as TokioRwLock};

    const TEST_CREDENTIAL: &str = "fornax-test-device-credential-do-not-leak";

    /// Serializes every test below that touches process-global state
    /// (`FORNAX_POLICY_POLL_*`/`FORNAX_DEVICE_CREDENTIAL_FILE` env vars, or
    /// `FORNAX_POLICY_POLL_TEST_PANIC`) -- `cargo test` runs tests in the
    /// same process on separate threads, so without this a panic-injection
    /// test setting `TEST_PANIC_ENV` could make an unrelated concurrently-
    /// running test's `run_one_cycle` call spuriously panic.
    static ENV_LOCK: TokioMutex<()> = TokioMutex::const_new(());

    /// Sets a process env var for the duration of this guard and always
    /// removes it on drop -- including on unwind from a failed assertion --
    /// so one failing test can never leak an env var into the next test
    /// sharing this process (see `ENV_LOCK`'s doc comment).
    struct EnvVarGuard(&'static str);

    impl EnvVarGuard {
        fn set(key: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
            std::env::set_var(key, value);
            Self(key)
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            std::env::remove_var(self.0);
        }
    }

    /// A minimal hand-rolled HTTP/1.1 server: reads one request's headers
    /// (ignores the body -- these are all `GET`s), calls the supplied
    /// responder for raw response bytes, writes them, closes the
    /// connection. Good enough to drive [`run_one_cycle`]/[`run_supervisor`]
    /// without adding a mock-HTTP-server dependency.
    type ResponderFn = Arc<StdMutex<Box<dyn FnMut() -> Vec<u8> + Send>>>;

    struct TestServer {
        port: u16,
        task: tokio::task::JoinHandle<()>,
    }

    impl TestServer {
        async fn start<F>(responder: F) -> Self
        where
            F: FnMut() -> Vec<u8> + Send + 'static,
        {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind ephemeral port");
            let port = listener.local_addr().expect("local_addr").port();
            let responder: ResponderFn = Arc::new(StdMutex::new(Box::new(responder)));
            let task = tokio::spawn(async move {
                loop {
                    let (mut socket, _) = match listener.accept().await {
                        Ok(x) => x,
                        Err(_) => continue,
                    };
                    let responder = responder.clone();
                    tokio::spawn(async move {
                        let mut buf: Vec<u8> = Vec::new();
                        let mut tmp = [0u8; 4096];
                        loop {
                            match socket.read(&mut tmp).await {
                                Ok(0) => return,
                                Ok(n) => {
                                    buf.extend_from_slice(&tmp[..n]);
                                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                        break;
                                    }
                                    if buf.len() > 64 * 1024 {
                                        break;
                                    }
                                }
                                Err(_) => return,
                            }
                        }
                        let response = { (responder.lock().unwrap())() };
                        let _ = socket.write_all(&response).await;
                        let _ = socket.shutdown().await;
                    });
                }
            });
            Self { port, task }
        }

        fn url(&self) -> reqwest::Url {
            reqwest::Url::parse(&format!("http://127.0.0.1:{}/poll", self.port)).unwrap()
        }
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    fn http_response(status: u16, body: &[u8]) -> Vec<u8> {
        let status_text = match status {
            200 => "OK",
            401 => "Unauthorized",
            403 => "Forbidden",
            500 => "Internal Server Error",
            _ => "Error",
        };
        let mut resp = format!(
            "HTTP/1.1 {status} {status_text}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        resp.extend_from_slice(body);
        resp
    }

    fn json_response(status: u16, value: &serde_json::Value) -> Vec<u8> {
        http_response(status, &serde_json::to_vec(value).unwrap())
    }

    fn empty_poll_response() -> serde_json::Value {
        serde_json::json!({
            "schema_version": 1,
            "device_id": "device-1",
            "issuer": "fornax-cloud:org-1",
            "server_time": "2026-01-01T00:00:00Z",
            "bundles": [],
            "revocation": null,
        })
    }

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn revision_digest_from_str(s: &str) -> fornax_types::RevisionDigest {
        serde_json::from_value(serde_json::Value::String(s.to_string()))
            .expect("RevisionDigest deserializes from its own wire shape")
    }

    fn build_trust_store(key_id: &str, signing_key: &SigningKey) -> TrustedVerificationKeys {
        TrustedVerificationKeys {
            schema_version: 1,
            keys: vec![TrustedKey {
                key_id: fornax_types::KeyId(key_id.to_string()),
                algorithm: SignatureAlgorithm::Ed25519,
                public_key_b64: B64.encode(signing_key.verifying_key().to_bytes()),
                not_before: None,
                not_after: None,
                comment: None,
            }],
        }
    }

    /// Builds one signed bundle envelope (as a `serde_json::Value`, exactly
    /// as it would appear in the poll response's `bundles` array) plus the
    /// revision digest it carries, using only public `fornax_types` API.
    fn build_bundle_envelope(
        key_id: &str,
        signing_key: &SigningKey,
        issuer: &str,
        sequence: u64,
        org_id: &str,
        policy_id: uuid::Uuid,
    ) -> (serde_json::Value, String) {
        let draft = PolicyDraft {
            policy_id: PolicyId(policy_id),
            revision: 1,
            supersedes: None,
            display_name: "test policy".to_string(),
            content: PolicyContent::default(),
            pinned_fields: std::collections::BTreeSet::new(),
        };
        let published = draft
            .publish("2026-01-01T00:00:00Z".to_string())
            .expect("publish");
        let revision_digest = published.digest().as_str().to_string();
        let binding = PolicyBinding {
            binding_id: uuid::Uuid::new_v4(),
            scope: TargetScope::Org {
                org_id: org_id.to_string(),
            },
            selector: TargetSelector::default(),
            revision_ref: published.reference(),
        };
        let payload = BundlePayload {
            bundle_schema_version: BUNDLE_SCHEMA_VERSION,
            bundle_id: uuid::Uuid::new_v4(),
            sequence,
            issued_at: "2026-01-01T00:00:00Z".to_string(),
            not_before: "2026-01-01T00:00:00Z".to_string(),
            expires_at: "2099-01-01T00:00:00Z".to_string(),
            provenance: BundleProvenance {
                issuer: issuer.to_string(),
                audit_ref: None,
                authorized_by: None,
            },
            revision: published,
            bindings: vec![binding],
        };
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let mut signed_message = BUNDLE_SIGNING_DOMAIN.to_vec();
        signed_message.extend_from_slice(&payload_bytes);
        let signature = signing_key.sign(&signed_message);
        let envelope = SignedPolicyBundle {
            bundle_schema_version: BUNDLE_SCHEMA_VERSION,
            payload_b64: B64.encode(&payload_bytes),
            signatures: vec![BundleSignature {
                key_id: fornax_types::KeyId(key_id.to_string()),
                algorithm: SignatureAlgorithm::Ed25519,
                signature_b64: B64.encode(signature.to_bytes()),
            }],
        };
        (serde_json::to_value(&envelope).unwrap(), revision_digest)
    }

    fn build_revocation_envelope(
        key_id: &str,
        signing_key: &SigningKey,
        issuer: &str,
        sequence: u64,
        revoked_revision_digest: &str,
    ) -> serde_json::Value {
        let payload = RevocationPayload {
            revocation_schema_version: REVOCATION_SCHEMA_VERSION,
            issuer: issuer.to_string(),
            sequence,
            issued_at: "2026-01-01T00:00:00Z".to_string(),
            entries: vec![RevocationEntry {
                target: RevocationTarget::RevisionDigest {
                    digest: revision_digest_from_str(revoked_revision_digest),
                },
                revoked_at: "2026-01-01T00:00:00Z".to_string(),
                reason: "test revocation".to_string(),
                audit_ref: None,
                superseded_by: None,
            }],
        };
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let mut signed_message = REVOCATION_SIGNING_DOMAIN.to_vec();
        signed_message.extend_from_slice(&payload_bytes);
        let signature = signing_key.sign(&signed_message);
        let envelope = SignedRevocationList {
            revocation_schema_version: REVOCATION_SCHEMA_VERSION,
            payload_b64: B64.encode(&payload_bytes),
            signatures: vec![BundleSignature {
                key_id: fornax_types::KeyId(key_id.to_string()),
                algorithm: SignatureAlgorithm::Ed25519,
                signature_b64: B64.encode(signature.to_bytes()),
            }],
        };
        serde_json::to_value(&envelope).unwrap()
    }

    struct TestFixture {
        state: AppState,
        dir: PathBuf,
    }

    impl Drop for TestFixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.dir).ok();
        }
    }

    async fn test_fixture(trust: Option<TrustedVerificationKeys>) -> TestFixture {
        let dir =
            std::env::temp_dir().join(format!("fnx-policy-poll-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        let store = fornax_store::Store::open(dir.join("fornax.db"))
            .await
            .expect("open store");
        let state = AppState {
            store,
            caps: Arc::new(TokioMutex::new(std::collections::HashMap::new())),
            processing: Arc::new(TokioMutex::new(())),
            trust: Arc::new(trust),
            policy: Arc::new(TokioRwLock::new(crate::PolicyCacheSnapshot::empty())),
        };
        TestFixture { state, dir }
    }

    fn test_config(url: reqwest::Url, interval: Duration) -> PollConfig {
        PollConfig {
            url,
            credential: Arc::new(DeviceCredential(TEST_CREDENTIAL.to_string())),
            interval,
        }
    }

    // -----------------------------------------------------------------
    // Scenario tests
    // -----------------------------------------------------------------

    /// THE most important test (see module docs' "No conditional fetch"
    /// section and `docs/adr/0010-policy-bundle-distribution.md`):
    /// submitting the identical bundle bytes a second cycle advances
    /// `confirmed_at` while `sequence`/generation stay unchanged.
    #[tokio::test]
    async fn t04_identical_resubmission_confirms_and_advances_confirmed_at() {
        let _guard = ENV_LOCK.lock().await;
        let key = signing_key(1);
        let trust = build_trust_store("k1", &key);
        let fixture = test_fixture(Some(trust)).await;
        let (bundle, _digest) =
            build_bundle_envelope("k1", &key, "cloud-1", 1, "org-1", uuid::Uuid::new_v4());

        let response = json_response(
            200,
            &serde_json::json!({
                "schema_version": 1,
                "device_id": "device-1",
                "issuer": "fornax-cloud:org-1",
                "server_time": "2026-01-01T00:00:00Z",
                "bundles": [bundle.clone()],
                "revocation": null,
            }),
        );
        let server = TestServer::start(move || response.clone()).await;
        let config = test_config(server.url(), Duration::from_secs(900));

        let outcome1 =
            run_one_cycle(fixture.state.clone(), config.clone(), build_http_client()).await;
        assert_eq!(outcome1.outcome, "ok");
        assert_eq!(outcome1.bundles_received, 1);

        let confirmed_at_1;
        let sequence_1;
        let generation_1;
        {
            let snapshot = fixture.state.policy.read().await;
            let active = snapshot.state.active.as_ref().expect("active generation");
            assert_eq!(active.members.len(), 1);
            confirmed_at_1 = active.members[0].confirmed_at;
            sequence_1 = active.members[0].sequence;
            generation_1 = active.generation;
        }

        tokio::time::sleep(Duration::from_millis(50)).await;

        let outcome2 = run_one_cycle(fixture.state.clone(), config, build_http_client()).await;
        assert_eq!(outcome2.outcome, "ok");
        assert_eq!(outcome2.bundles_received, 1);

        let snapshot = fixture.state.policy.read().await;
        let active = snapshot.state.active.as_ref().expect("active generation");
        assert_eq!(active.members.len(), 1);
        assert_eq!(
            active.members[0].sequence, sequence_1,
            "sequence must not change on a Confirm"
        );
        assert_eq!(
            active.generation, generation_1,
            "generation must not change on a Confirm"
        );
        assert!(
            active.members[0].confirmed_at > confirmed_at_1,
            "confirmed_at must advance on identical resubmission"
        );
    }

    #[test]
    fn t05_disabled_when_no_url_configured() {
        let _guard = ENV_LOCK.blocking_lock();
        std::env::remove_var(POLL_URL_ENV);
        let home = std::env::temp_dir().join(format!("fnx-poll-cfg-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&home).unwrap();
        assert!(resolve_poll_config(&home).is_none());
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn t06_disabled_when_credential_file_missing() {
        let _guard = ENV_LOCK.blocking_lock();
        let home = std::env::temp_dir().join(format!("fnx-poll-cfg-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&home).unwrap();
        std::env::set_var(POLL_URL_ENV, "https://policy.example.com/poll");
        std::env::remove_var(CREDENTIAL_FILE_ENV);
        assert!(resolve_poll_config(&home).is_none());
        std::env::remove_var(POLL_URL_ENV);
        std::fs::remove_dir_all(&home).ok();
    }

    #[cfg(unix)]
    #[test]
    fn t07_disabled_when_credential_file_is_group_readable() {
        let _guard = ENV_LOCK.blocking_lock();
        use std::os::unix::fs::PermissionsExt;
        let home = std::env::temp_dir().join(format!("fnx-poll-cfg-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&home).unwrap();
        let cred_path = home.join("device-credential");
        std::fs::write(&cred_path, TEST_CREDENTIAL).unwrap();
        std::fs::set_permissions(&cred_path, std::fs::Permissions::from_mode(0o640)).unwrap();

        std::env::set_var(POLL_URL_ENV, "https://policy.example.com/poll");
        std::env::set_var(CREDENTIAL_FILE_ENV, &cred_path);
        assert!(
            resolve_poll_config(&home).is_none(),
            "a group-readable credential file must refuse to enable polling"
        );
        std::env::remove_var(POLL_URL_ENV);
        std::env::remove_var(CREDENTIAL_FILE_ENV);
        std::fs::remove_dir_all(&home).ok();
    }

    #[cfg(unix)]
    #[test]
    fn t08_interval_is_clamped_to_the_floor_and_config_enables() {
        let _guard = ENV_LOCK.blocking_lock();
        use std::os::unix::fs::PermissionsExt;
        let home = std::env::temp_dir().join(format!("fnx-poll-cfg-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&home).unwrap();
        let cred_path = home.join("device-credential");
        std::fs::write(&cred_path, TEST_CREDENTIAL).unwrap();
        std::fs::set_permissions(&cred_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        std::env::set_var(POLL_URL_ENV, "https://policy.example.com/poll");
        std::env::set_var(CREDENTIAL_FILE_ENV, &cred_path);
        std::env::set_var(INTERVAL_ENV, "1");

        let config = resolve_poll_config(&home).expect("polling should be enabled");
        assert_eq!(config.interval, Duration::from_secs(MIN_INTERVAL_SECONDS));

        std::env::remove_var(POLL_URL_ENV);
        std::env::remove_var(CREDENTIAL_FILE_ENV);
        std::env::remove_var(INTERVAL_ENV);
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn t09_http_url_is_refused_for_a_non_local_host() {
        let _guard = ENV_LOCK.blocking_lock();
        std::env::remove_var(CREDENTIAL_FILE_ENV);
        let home = std::env::temp_dir().join(format!("fnx-poll-cfg-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&home).unwrap();
        std::env::set_var(POLL_URL_ENV, "http://policy.example.com/poll");
        assert!(
            resolve_poll_config(&home).is_none(),
            "http:// must be refused for a non-local host"
        );
        std::env::remove_var(POLL_URL_ENV);
        std::fs::remove_dir_all(&home).ok();
    }

    #[tokio::test]
    async fn t10_unreachable_when_connection_refused() {
        let _guard = ENV_LOCK.lock().await;
        let fixture = test_fixture(None).await;
        // A free port nothing is listening on.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let url = reqwest::Url::parse(&format!("http://127.0.0.1:{port}/poll")).unwrap();
        let config = test_config(url, Duration::from_secs(900));

        let outcome = run_one_cycle(fixture.state.clone(), config, build_http_client()).await;
        assert_eq!(outcome.outcome, "unreachable");
        assert!(!outcome.detail.contains(TEST_CREDENTIAL));
    }

    #[tokio::test]
    async fn t11_auth_failed_on_401() {
        let _guard = ENV_LOCK.lock().await;
        let fixture = test_fixture(None).await;
        let server = TestServer::start(|| http_response(401, b"{}")).await;
        let config = test_config(server.url(), Duration::from_secs(900));

        let outcome = run_one_cycle(fixture.state.clone(), config, build_http_client()).await;
        assert_eq!(outcome.outcome, "auth_failed");
        assert!(!outcome.detail.contains(TEST_CREDENTIAL));
    }

    #[tokio::test]
    async fn t12_http_error_on_500() {
        let _guard = ENV_LOCK.lock().await;
        let fixture = test_fixture(None).await;
        let server = TestServer::start(|| http_response(500, b"{}")).await;
        let config = test_config(server.url(), Duration::from_secs(900));

        let outcome = run_one_cycle(fixture.state.clone(), config, build_http_client()).await;
        assert_eq!(outcome.outcome, "http_error");
    }

    #[tokio::test]
    async fn t13_oversized_response_is_rejected_without_submission() {
        let _guard = ENV_LOCK.lock().await;
        let key = signing_key(2);
        let trust = build_trust_store("k1", &key);
        let fixture = test_fixture(Some(trust)).await;
        let oversized_body = vec![b'a'; MAX_RESPONSE_BYTES + 1024];
        let response = http_response(200, &oversized_body);
        let server = TestServer::start(move || response.clone()).await;
        let config = test_config(server.url(), Duration::from_secs(900));

        let outcome = run_one_cycle(fixture.state.clone(), config, build_http_client()).await;
        assert_eq!(outcome.outcome, "too_large");
        assert_eq!(outcome.bundles_received, 0);
        let snapshot = fixture.state.policy.read().await;
        assert!(snapshot.state.active.is_none());
    }

    #[tokio::test]
    async fn t14_malformed_json_is_rejected() {
        let _guard = ENV_LOCK.lock().await;
        let fixture = test_fixture(None).await;
        let response = http_response(200, b"{ not json, truncated");
        let server = TestServer::start(move || response.clone()).await;
        let config = test_config(server.url(), Duration::from_secs(900));

        let outcome = run_one_cycle(fixture.state.clone(), config, build_http_client()).await;
        assert_eq!(outcome.outcome, "malformed");
    }

    /// Revocation must be processed BEFORE the bundle in the same response,
    /// so a bundle whose revision digest was just revoked is rejected in
    /// the SAME cycle -- not merely "eventually".
    #[tokio::test]
    async fn t15_revocation_is_processed_before_bundle_in_the_same_cycle() {
        let _guard = ENV_LOCK.lock().await;
        let key = signing_key(3);
        let trust = build_trust_store("k1", &key);
        let fixture = test_fixture(Some(trust)).await;
        let (bundle, digest) =
            build_bundle_envelope("k1", &key, "cloud-1", 1, "org-1", uuid::Uuid::new_v4());
        let revocation = build_revocation_envelope("k1", &key, "cloud-1", 1, &digest);

        let response = json_response(
            200,
            &serde_json::json!({
                "schema_version": 1,
                "device_id": "device-1",
                "issuer": "fornax-cloud:org-1",
                "server_time": "2026-01-01T00:00:00Z",
                "bundles": [bundle],
                "revocation": revocation,
            }),
        );
        let server = TestServer::start(move || response.clone()).await;
        let config = test_config(server.url(), Duration::from_secs(900));

        let outcome = run_one_cycle(fixture.state.clone(), config, build_http_client()).await;
        assert_eq!(outcome.outcome, "ok");

        let snapshot = fixture.state.policy.read().await;
        assert!(
            snapshot.state.active.is_none(),
            "the bundle must never activate: its revision digest was revoked in the same cycle"
        );
        let rejection = snapshot
            .last_rejection
            .as_ref()
            .expect("a rejection should be recorded");
        assert_eq!(rejection.code, "revoked");
    }

    /// A hostile/stale bundle (sequence not advanced) is rejected via the
    /// existing `submit_policy_bundle` path; the active generation stands
    /// untouched and `last_rejection` is populated.
    #[tokio::test]
    async fn t16_stale_sequence_is_rejected_and_active_generation_is_untouched() {
        let _guard = ENV_LOCK.lock().await;
        let key = signing_key(4);
        let trust = build_trust_store("k1", &key);
        let fixture = test_fixture(Some(trust)).await;
        // Same policy_id for both calls -- otherwise each bundle names an
        // independent lineage and "stale" (same-lineage) sequence
        // comparison never has anything to compare against.
        let policy_id = uuid::Uuid::new_v4();
        let (fresh_bundle, _digest) =
            build_bundle_envelope("k1", &key, "cloud-1", 2, "org-1", policy_id);

        let ok_response = json_response(
            200,
            &serde_json::json!({
                "schema_version": 1,
                "device_id": "device-1",
                "issuer": "fornax-cloud:org-1",
                "server_time": "2026-01-01T00:00:00Z",
                "bundles": [fresh_bundle],
                "revocation": null,
            }),
        );
        let server = TestServer::start(move || ok_response.clone()).await;
        let config = test_config(server.url(), Duration::from_secs(900));
        let outcome = run_one_cycle(fixture.state.clone(), config, build_http_client()).await;
        assert_eq!(outcome.outcome, "ok");
        let generation_after_seq2 = fixture
            .state
            .policy
            .read()
            .await
            .state
            .active
            .as_ref()
            .unwrap()
            .generation;
        drop(server);

        // A second server returning a bundle with a LOWER sequence for the
        // same issuer/policy_id.
        let (stale_bundle, _digest2) =
            build_bundle_envelope("k1", &key, "cloud-1", 1, "org-1", policy_id);
        let stale_response = json_response(
            200,
            &serde_json::json!({
                "schema_version": 1,
                "device_id": "device-1",
                "issuer": "fornax-cloud:org-1",
                "server_time": "2026-01-01T00:00:00Z",
                "bundles": [stale_bundle],
                "revocation": null,
            }),
        );
        let server2 = TestServer::start(move || stale_response.clone()).await;
        let config2 = test_config(server2.url(), Duration::from_secs(900));
        let outcome2 = run_one_cycle(fixture.state.clone(), config2, build_http_client()).await;
        assert_eq!(
            outcome2.outcome, "ok",
            "the HTTP transport itself succeeded"
        );

        let snapshot = fixture.state.policy.read().await;
        assert_eq!(
            snapshot.state.active.as_ref().unwrap().generation,
            generation_after_seq2,
            "the existing generation must stand untouched"
        );
        assert_eq!(
            snapshot.last_rejection.as_ref().unwrap().code,
            "sequence_not_advanced"
        );
    }

    /// Injected panic inside one poll cycle: the supervisor records
    /// `"panicked"` for that cycle and the NEXT tick runs normally.
    #[tokio::test]
    async fn t17_panic_inside_a_cycle_is_contained_and_the_next_tick_recovers() {
        let _guard = ENV_LOCK.lock().await;
        let fixture = test_fixture(None).await;
        let response = empty_poll_response();
        let json = json_response(200, &response);
        let server = TestServer::start(move || json.clone()).await;
        let config = test_config(server.url(), Duration::from_millis(20));

        let panic_env = EnvVarGuard::set(TEST_PANIC_ENV, "1");
        let state_for_supervisor = fixture.state.clone();
        let handle =
            tokio::spawn(
                async move { run_supervisor_inner(state_for_supervisor, config, false).await },
            );

        // Wait for at least one "panicked" outcome.
        wait_for(Duration::from_secs(5), || {
            let state = fixture.state.clone();
            async move {
                state
                    .policy
                    .read()
                    .await
                    .last_poll
                    .as_ref()
                    .map(|p| p.outcome == "panicked")
                    .unwrap_or(false)
            }
        })
        .await;

        drop(panic_env);

        // Wait for a subsequent "ok" outcome, proving the next tick runs.
        wait_for(Duration::from_secs(5), || {
            let state = fixture.state.clone();
            async move {
                state
                    .policy
                    .read()
                    .await
                    .last_poll
                    .as_ref()
                    .map(|p| p.outcome == "ok")
                    .unwrap_or(false)
            }
        })
        .await;

        handle.abort();
    }

    /// Repeated 401s: backoff grows toward the 1-hour ceiling, the
    /// `PolicyRefreshUnavailable` diagnostic appears after the 3rd
    /// consecutive failure, and a subsequent success resets both
    /// `consecutive_failures` and the backoff multiplier.
    #[tokio::test]
    async fn t18_backoff_grows_then_diagnostic_appears_then_resets_on_success() {
        let _guard = ENV_LOCK.lock().await;
        let fixture = test_fixture(None).await;
        let fail_count = Arc::new(StdMutex::new(0u32));
        let fail_count_for_responder = fail_count.clone();
        let ok_body = json_response(200, &empty_poll_response());
        let responder = move || {
            let mut count = fail_count_for_responder.lock().unwrap();
            if *count < 3 {
                *count += 1;
                http_response(401, b"{}")
            } else {
                ok_body.clone()
            }
        };
        let server = TestServer::start(responder).await;
        let interval = Duration::from_millis(15);
        let config = test_config(server.url(), interval);

        let state_for_supervisor = fixture.state.clone();
        let handle =
            tokio::spawn(
                async move { run_supervisor_inner(state_for_supervisor, config, false).await },
            );

        // Wait until 3 consecutive failures have been recorded and the
        // diagnostic has appeared.
        wait_for(Duration::from_secs(10), || {
            let state = fixture.state.clone();
            async move {
                let snapshot = state.policy.read().await;
                snapshot
                    .last_poll
                    .as_ref()
                    .map(|p| p.outcome == "auth_failed" && p.consecutive_failures >= 3)
                    .unwrap_or(false)
                    && snapshot
                        .diagnostics
                        .iter()
                        .any(|d| d.code == DiagnosticCode::PolicyRefreshUnavailable)
            }
        })
        .await;

        {
            let snapshot = fixture.state.policy.read().await;
            let last = snapshot.last_poll.as_ref().unwrap();
            // interval * multiplier never exceeds the 1-hour ceiling.
            let ceiling = (BACKOFF_CEILING_SECONDS / interval.as_secs().max(1)).max(1);
            assert!(
                interval.as_secs()
                    * u64::from(compute_backoff_multiplier(
                        last.consecutive_failures,
                        interval
                    ))
                    <= interval.as_secs() * ceiling
            );
        }

        // Now let it succeed and observe the reset.
        wait_for(Duration::from_secs(10), || {
            let state = fixture.state.clone();
            async move {
                let snapshot = state.policy.read().await;
                snapshot
                    .last_poll
                    .as_ref()
                    .map(|p| p.outcome == "ok" && p.consecutive_failures == 0)
                    .unwrap_or(false)
                    && !snapshot
                        .diagnostics
                        .iter()
                        .any(|d| d.code == DiagnosticCode::PolicyRefreshUnavailable)
            }
        })
        .await;

        handle.abort();
    }

    /// Aborting the supervisor task mid-cycle (simulating SIGTERM) must not
    /// hang -- `JoinHandle::abort` plus a bounded join must complete
    /// quickly.
    #[tokio::test]
    async fn t19_graceful_abort_does_not_hang() {
        let _guard = ENV_LOCK.lock().await;
        let fixture = test_fixture(None).await;
        let response = json_response(200, &empty_poll_response());
        let server = TestServer::start(move || response.clone()).await;
        let config = test_config(server.url(), Duration::from_secs(900));

        let handle =
            tokio::spawn(async move { run_supervisor(fixture.state.clone(), config).await });
        handle.abort();
        let result = tokio::time::timeout(Duration::from_secs(5), handle).await;
        assert!(result.is_ok(), "abort must complete within the timeout");
    }

    /// The credential value must never appear in any `last_poll.detail`
    /// string, across success and every failure outcome exercised above.
    #[tokio::test]
    async fn t20_credential_never_appears_in_any_cycle_detail() {
        let _guard = ENV_LOCK.lock().await;
        let fixture = test_fixture(None).await;

        let unreachable_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let unreachable_port = unreachable_listener.local_addr().unwrap().port();
        drop(unreachable_listener);
        let unreachable_url =
            reqwest::Url::parse(&format!("http://127.0.0.1:{unreachable_port}/poll")).unwrap();

        let scenarios: Vec<(&str, reqwest::Url)> = vec![
            ("unreachable", unreachable_url),
            ("auth_failed", {
                let server = TestServer::start(|| http_response(401, b"{}")).await;
                let url = server.url();
                std::mem::forget(server);
                url
            }),
            ("too_large", {
                let body = vec![b'x'; MAX_RESPONSE_BYTES + 10];
                let response = http_response(200, &body);
                let server = TestServer::start(move || response.clone()).await;
                let url = server.url();
                std::mem::forget(server);
                url
            }),
            ("malformed", {
                let response = http_response(200, b"not json");
                let server = TestServer::start(move || response.clone()).await;
                let url = server.url();
                std::mem::forget(server);
                url
            }),
            ("ok", {
                let response = json_response(200, &empty_poll_response());
                let server = TestServer::start(move || response.clone()).await;
                let url = server.url();
                std::mem::forget(server);
                url
            }),
        ];

        for (expected_outcome, url) in scenarios {
            let config = test_config(url, Duration::from_secs(900));
            let outcome = run_one_cycle(fixture.state.clone(), config, build_http_client()).await;
            assert_eq!(outcome.outcome, expected_outcome);
            assert!(
                !outcome.detail.contains(TEST_CREDENTIAL),
                "credential leaked into detail for outcome {expected_outcome:?}: {}",
                outcome.detail
            );
        }
    }

    /// Bounded async poll helper, mirroring this crate's own integration
    /// test harnesses (`tests/adversarial_daemon_input.rs`) -- never a
    /// fixed sleep.
    async fn wait_for<F, Fut>(timeout: Duration, mut check: F)
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if check().await {
                return;
            }
            if tokio::time::Instant::now() > deadline {
                panic!("condition not met within {timeout:?}");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}
