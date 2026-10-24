//! The metadata-only upload sender (FORNX-464), shared by `fornax upload run`
//! and the daemon's automatic monthly schedule.
//!
//! It sends ids, kinds, providers, timestamps, verdict enums and bounded
//! labels from the staged outbox -- never raw evidence or claim text -- under
//! a live personal-profile consent, to the consented destination only, with
//! the persisted egress decision re-asked before every attempt. A sealed
//! batch's canonical bytes and hash are persisted before the first attempt, so
//! a retry is byte-identical and carries the same `Idempotency-Key`.

use std::time::Duration;

use fornax_store::upload::{current_window, SealedBatch, CANONICALIZATION};
use fornax_types::egress::Purpose;
use fornax_types::EgressContentClass;

const MAX_ATTEMPTS_PER_RUN: u32 = 4;
const DEVICE_ID_ENV: &str = "FORNX_DEVICE_ID";
const CREDENTIAL_FILE_ENV: &str = "FORNAX_DEVICE_CREDENTIAL_FILE";
const BACKOFF_ENV: &str = "FORNAX_UPLOAD_BACKOFF_MS";

enum Sent {
    Acknowledged,
    Poisoned,
    /// Retries for this run are exhausted; the batch stays sealed.
    Pending,
}

pub fn read_credential(home: &std::path::Path) -> anyhow::Result<String> {
    let path = std::env::var(CREDENTIAL_FILE_ENV)
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| home.join("device-credential"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path)
            .map_err(|e| anyhow::anyhow!("device credential {}: {e}", path.display()))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            anyhow::bail!(
                "device credential {} is group/world-readable (mode {:o}); chmod 600 it",
                path.display(),
                mode & 0o777
            );
        }
    }
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("device credential {}: {e}", path.display()))?;
    let value = raw.lines().next().unwrap_or("").trim().to_string();
    if value.is_empty() {
        anyhow::bail!("device credential {} is empty", path.display());
    }
    Ok(value)
}

pub async fn device_id(store: &fornax_store::Store) -> anyhow::Result<String> {
    if let Ok(id) = std::env::var(DEVICE_ID_ENV) {
        if !id.trim().is_empty() {
            return Ok(id.trim().to_string());
        }
    }
    if let Some(anchor) = store.first_audit_checkpoint_receipt().await? {
        return Ok(anchor.device_id);
    }
    anyhow::bail!("device id unknown: set {DEVICE_ID_ENV} (the id this device registered with)")
}

fn backoff(attempt: u32) -> Duration {
    let base: u64 = std::env::var(BACKOFF_ENV)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1000);
    Duration::from_millis(base.saturating_mul(1u64 << attempt.min(6)).min(30_000))
}

fn retry_after(resp: &reqwest::Response) -> Option<Duration> {
    resp.headers()
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .parse::<u64>()
        .ok()
        .map(|s| Duration::from_secs(s.min(30)))
}

/// Only one upload run may be sealing and sending at a time (the daemon's
/// schedule and an operator's `fornax upload run` share this).
struct UploadLock(std::path::PathBuf);

/// A lock older than this is from a crashed run and is taken over.
const LOCK_STALE_AFTER: Duration = Duration::from_secs(30 * 60);

impl UploadLock {
    fn acquire(home: &std::path::Path) -> anyhow::Result<Option<Self>> {
        use std::io::Write;
        let path = home.join("upload.lock");
        for _ in 0..2 {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut f) => {
                    let _ = writeln!(f, "{}", std::process::id());
                    return Ok(Some(Self(path)));
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    let age = std::fs::metadata(&path)
                        .and_then(|m| m.modified())
                        .ok()
                        .and_then(|t| t.elapsed().ok());
                    if age.is_some_and(|a| a > LOCK_STALE_AFTER) {
                        let _ = std::fs::remove_file(&path);
                        continue;
                    }
                    return Ok(None);
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(None)
    }
}

impl Drop for UploadLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// What one upload run did. The caller decides how to report it.
#[derive(Debug, Default)]
pub struct RunReport {
    pub staged: usize,
    pub expired_at_bound: usize,
    pub sent: usize,
    pub poisoned: usize,
    pub pending: usize,
    /// Batches left sealed because they target another consent's destination.
    pub skipped: Vec<String>,
}

/// Stage, seal and send pending batches under the live consent. Errors when
/// there is no live consent, no usable credential, or the receiver rejects the
/// credential; transient failures leave batches sealed and are reported as
/// `pending`.
pub async fn run_upload(
    store: &fornax_store::Store,
    home: &std::path::Path,
    window: Option<String>,
    max_batches: usize,
) -> anyhow::Result<RunReport> {
    let Some(_lock) = UploadLock::acquire(home)? else {
        anyhow::bail!("another upload run is in progress (home/upload.lock); nothing was sent");
    };
    let Some(consent) = store.live_upload_consent().await? else {
        anyhow::bail!(
            "no live consent for evidence_batch_upload under the personal profile: nothing is staged or sent \
             (see `fornax egress status`)"
        );
    };
    let staged = store.stage_upload_records().await?;

    let url = reqwest::Url::parse(&consent.destination)?;
    let classes: std::collections::BTreeSet<EgressContentClass> = [
        EgressContentClass::EvidenceMetadata,
        EgressContentClass::FindingVerdicts,
    ]
    .into_iter()
    .collect();
    let device = device_id(store).await?;
    let credential = read_credential(home)?;
    // No redirects: the consented destination must not be able to forward the
    // batch (and the device credential) elsewhere.
    let http = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("static reqwest client configuration is valid");

    let mut work: Vec<SealedBatch> = store.unfinished_upload_batches().await?;
    let mut sent = 0usize;
    let mut poisoned = 0usize;
    let mut pending = 0usize;
    let mut budget = max_batches;
    let mut skipped: Vec<String> = Vec::new();

    let windows: Vec<String> = match window {
        Some(w) => vec![w],
        None => {
            let open = current_window(chrono::Utc::now());
            store
                .pending_upload_windows()
                .await?
                .into_iter()
                .filter(|w| *w < open)
                .collect()
        }
    };

    'outer: loop {
        let batch = if let Some(b) = work.pop() {
            // A batch sealed for another destination (an older consent that
            // is still live) is never sent to this consent's URL: it stays
            // sealed until that consent ends or the operator reverts.
            if b.destination != consent.destination {
                skipped.push(b.batch_id.clone());
                continue;
            }
            b
        } else {
            let mut next = None;
            for w in &windows {
                if let Some(b) = store
                    .seal_upload_batch(w, &consent.id, &consent.destination)
                    .await?
                {
                    next = Some(b);
                    break;
                }
            }
            match next {
                Some(b) => b,
                None => break 'outer,
            }
        };
        if budget == 0 {
            // Sealed but not sent: it stays sealed for the next run.
            pending += 1;
            break;
        }
        budget -= 1;
        match send_batch(store, &http, &url, &classes, &device, &credential, &batch).await? {
            Sent::Acknowledged => sent += 1,
            // One permanent rejection stops the run: a systematic fault must
            // not walk through every remaining batch.
            Sent::Poisoned => {
                poisoned += 1;
                break;
            }
            Sent::Pending => {
                pending += 1;
                break;
            }
        }
    }

    Ok(RunReport {
        staged: staged.staged,
        expired_at_bound: staged.expired_at_bound,
        sent,
        poisoned,
        pending,
        skipped,
    })
}

/// Why a scheduled tick did or did not send.
#[derive(Debug)]
pub enum TickOutcome {
    /// The `FORNAX_CLOUD_SYNC_ENABLED` kill switch is off: nothing is staged,
    /// sealed or sent.
    Disabled,
    /// Another upload run holds the lock; this tick does nothing.
    Busy,
    /// No live personal-profile consent: nothing is staged or sent.
    NoConsent,
    /// Consent is live but no closed month or unfinished batch is due.
    NothingDue,
    /// Consent is live and work is due, but the device id or credential is
    /// not provisioned. Nothing is sent.
    NotConfigured(String),
    Ran(RunReport),
}

/// One pass of the automatic monthly upload. Strictly weaker than
/// [`run_upload`]: it does nothing unless a live consent exists (which already
/// implies the personal profile, a current profile generation and an
/// allowlisted destination), a closed month or unfinished batch is due, and
/// the device is provisioned. Corporate and unconfigured installs have no live
/// consent, so they can never schedule an upload. It only ever sends the
/// metadata-only outbox through the same egress-checked path as the CLI.
pub async fn scheduled_tick(
    store: &fornax_store::Store,
    home: &std::path::Path,
) -> anyhow::Result<TickOutcome> {
    if !fornax_types::privacy::cloud_sync_allowed() {
        return Ok(TickOutcome::Disabled);
    }
    if store.live_upload_consent().await?.is_none() {
        return Ok(TickOutcome::NoConsent);
    }
    let open = current_window(chrono::Utc::now());
    let closed_due = store
        .pending_upload_windows()
        .await?
        .into_iter()
        .any(|w| w < open);
    // New records are staged by the retention sweep and by `run_upload`; the
    // outbox may not yet hold a closed month, so stage before deciding.
    let staged_due = if closed_due {
        true
    } else {
        store.stage_upload_records().await?;
        store
            .pending_upload_windows()
            .await?
            .into_iter()
            .any(|w| w < open)
    };
    if !staged_due && store.unfinished_upload_batches().await?.is_empty() {
        return Ok(TickOutcome::NothingDue);
    }
    if let Err(e) = device_id(store).await {
        return Ok(TickOutcome::NotConfigured(e.to_string()));
    }
    if let Err(e) = read_credential(home) {
        return Ok(TickOutcome::NotConfigured(e.to_string()));
    }
    // `run_upload` takes the lock itself; losing the race is not an error.
    match run_upload(store, home, None, 8).await {
        Ok(report) => Ok(TickOutcome::Ran(report)),
        Err(e)
            if e.to_string()
                .starts_with("another upload run is in progress") =>
        {
            Ok(TickOutcome::Busy)
        }
        Err(e) => Err(e),
    }
}

async fn send_batch(
    store: &fornax_store::Store,
    http: &reqwest::Client,
    url: &reqwest::Url,
    classes: &std::collections::BTreeSet<EgressContentClass>,
    device: &str,
    credential: &str,
    batch: &SealedBatch,
) -> anyhow::Result<Sent> {
    let members: serde_json::Value = serde_json::from_str(&batch.members_json)?;
    let body = serde_json::json!({
        "schema_version": 1,
        "canonicalization": CANONICALIZATION,
        "device_id": device,
        "batch_id": batch.batch_id,
        "window_id": batch.window_id,
        "manifest_sha256": batch.manifest_sha256,
        "members": members,
    });

    for attempt in 0..MAX_ATTEMPTS_PER_RUN {
        // Re-ask the persisted decision on EVERY attempt: a revoked consent,
        // an allowlist removal or a switch to corporate stops the next send.
        let permit = store
            .decide_egress(
                Purpose::EvidenceBatchUpload,
                url.as_str(),
                classes,
                fornax_types::privacy::cloud_sync_allowed(),
            )
            .await
            .map_err(|d| anyhow::anyhow!("egress denied ({d}); nothing was sent"))?;
        anyhow::ensure!(
            permit.authorizes(Purpose::EvidenceBatchUpload, url.as_str()),
            "egress permit does not cover the upload URL"
        );

        let response = http
            .post(url.clone())
            .bearer_auth(credential)
            .header("Idempotency-Key", &batch.manifest_sha256)
            .json(&body)
            .send()
            .await;
        let (outcome, wait): (Result<(), String>, Option<Duration>) = match response {
            Ok(resp) => {
                let status = resp.status();
                let wait = retry_after(&resp);
                if status.is_success() {
                    store.record_upload_attempt(&batch.batch_id, None).await?;
                    store.acknowledge_upload_batch(&batch.batch_id).await?;
                    return Ok(Sent::Acknowledged);
                }
                // Redirects are never followed, a wrong path or an oversized request is
                // an operator/configuration fault, and a 409 means the receiver holds
                // a DIFFERENT manifest under this batch id (never an acknowledgement) that would hit every
                // batch alike: keep the data sealed and stop, never poison it.
                if status.is_redirection() || matches!(status.as_u16(), 404 | 405 | 409 | 413) {
                    let reason = if status.is_redirection() {
                        "redirect refused".to_string()
                    } else {
                        format!("http {}", status.as_u16())
                    };
                    store
                        .record_upload_attempt(&batch.batch_id, Some(&reason))
                        .await?;
                    anyhow::bail!(
                        "the receiver answered {reason}; check the allowlisted destination and receiver, then re-run (the batch stays sealed)"
                    );
                }
                if status.as_u16() == 401 || status.as_u16() == 403 {
                    // An operator-fixable credential problem: never poison
                    // data over it. Stop and keep the batch sealed.
                    store
                        .record_upload_attempt(&batch.batch_id, Some("credential rejected"))
                        .await?;
                    anyhow::bail!(
                        "the receiver rejected the device credential (HTTP {}); fix it and re-run",
                        status.as_u16()
                    );
                }
                if status.as_u16() == 408 || status.as_u16() == 429 || status.is_server_error() {
                    (Err(format!("http {}", status.as_u16())), wait)
                } else {
                    let reason = format!("http {}", status.as_u16());
                    store
                        .record_upload_attempt(&batch.batch_id, Some(&reason))
                        .await?;
                    store.poison_upload_batch(&batch.batch_id, &reason).await?;
                    return Ok(Sent::Poisoned);
                }
            }
            Err(e) => (
                Err(if e.is_timeout() {
                    "timeout".into()
                } else {
                    "transport error".into()
                }),
                None,
            ),
        };
        if let Err(reason) = outcome {
            store
                .record_upload_attempt(&batch.batch_id, Some(&reason))
                .await?;
            if attempt + 1 < MAX_ATTEMPTS_PER_RUN {
                tokio::time::sleep(wait.unwrap_or_else(|| backoff(attempt))).await;
            }
        }
    }
    Ok(Sent::Pending)
}
