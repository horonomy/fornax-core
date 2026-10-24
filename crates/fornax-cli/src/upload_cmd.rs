//! `fornax upload` (FORNX-464): the personal monthly metadata batch upload.
//!
//! Operator-invoked (no scheduler in this release): run it monthly, from cron
//! or launchd, for the previous closed month. It sends metadata only -- ids,
//! kinds, providers, timestamps, verdict enums, bounded labels -- from an
//! outbox staged ahead of the retention sweep, under a live personal-profile
//! consent, to the consented destination, and only while
//! `FORNAX_CLOUD_SYNC_ENABLED=1`.
//!
//! Every send attempt re-asks the persisted egress decision, so a revoked
//! consent or a switch to corporate stops the very next request. A sealed
//! batch's canonical bytes and hash are persisted before the first attempt:
//! a retry after a crash or a lost response is byte-identical and carries the
//! same `Idempotency-Key`, which the receiver dedups on.

use std::time::Duration;

use clap::Subcommand;
use fornax_store::upload::{current_window, SealedBatch, CANONICALIZATION};
use fornax_types::egress::Purpose;
use fornax_types::EgressContentClass;

#[derive(Subcommand)]
pub enum UploadAction {
    /// Show the outbox, batches and any recorded gaps. Local; any profile.
    Status,
    /// Show a few of the exact metadata members that would be uploaded.
    /// Local; any profile; sends nothing.
    Preview {
        /// Only this window (YYYY-MM).
        #[arg(long)]
        window: Option<String>,
    },
    /// Stage, seal and send pending batches for closed months (or `--window`).
    Run {
        /// Send this window (YYYY-MM) even if it is not yet closed.
        #[arg(long)]
        window: Option<String>,
        /// Upper bound on batches sent by one run.
        #[arg(long, default_value_t = 8)]
        max_batches: usize,
    },
}

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

pub async fn handle(action: UploadAction, fornax_home: &std::path::Path) -> anyhow::Result<()> {
    let store = fornax_store::Store::open(fornax_home.join("fornax.db")).await?;
    match action {
        UploadAction::Status => status(&store).await,
        UploadAction::Preview { window } => preview(&store, window.as_deref()).await,
        UploadAction::Run {
            window,
            max_batches,
        } => run(&store, fornax_home, window, max_batches).await,
    }
}

async fn status(store: &fornax_store::Store) -> anyhow::Result<()> {
    match store.live_upload_consent().await? {
        Some(c) => println!("consent: live ({}) -> {}", c.id, c.destination),
        None => println!(
            "consent: none live -- nothing is staged or sent (profile personal + `fornax egress consent-grant --purpose evidence_batch_upload` needed)"
        ),
    }
    println!("outbox (window, state, members):");
    let counts = store.upload_window_counts().await?;
    if counts.is_empty() {
        println!("  (empty)");
    }
    for c in counts {
        println!("  {} {} {}", c.window_id, c.state, c.n);
    }
    println!("batches:");
    let batches = store.upload_batch_counts().await?;
    if batches.is_empty() {
        println!("  (none)");
    }
    for (state, n) in batches {
        println!("  {state}: {n}");
    }
    let gaps = store.upload_gaps().await?;
    if !gaps.is_empty() {
        println!("GAPS (records that will never be uploaded):");
        for (window, reason, n, at) in gaps {
            println!("  {window} {reason} dropped={n} recorded={at}");
        }
    }
    println!("schedule: none -- run `fornax upload run` monthly (cron/launchd); there is no built-in scheduler in this release");
    Ok(())
}

async fn preview(store: &fornax_store::Store, window: Option<&str>) -> anyhow::Result<()> {
    let members = store.preview_pending_members(window, 3).await?;
    if members.is_empty() {
        println!("nothing staged. (`fornax upload run` stages eligible records first; nothing is staged without a live consent.)");
        return Ok(());
    }
    println!("pending metadata members, exactly as they would be uploaded (nothing sent):");
    for (kind, json) in members {
        println!("  {kind}: {json}");
    }
    Ok(())
}

fn read_credential(home: &std::path::Path) -> anyhow::Result<String> {
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

async fn device_id(store: &fornax_store::Store) -> anyhow::Result<String> {
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

async fn run(
    store: &fornax_store::Store,
    home: &std::path::Path,
    window: Option<String>,
    max_batches: usize,
) -> anyhow::Result<()> {
    let Some(consent) = store.live_upload_consent().await? else {
        anyhow::bail!(
            "no live consent for evidence_batch_upload under the personal profile: nothing is staged or sent \
             (see `fornax egress status`)"
        );
    };
    let staged = store.stage_upload_records().await?;
    println!(
        "staged {} new metadata member(s); {} expired at the outbox bound or with an ended consent",
        staged.staged, staged.expired_at_bound
    );

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
            Sent::Poisoned => poisoned += 1,
            Sent::Pending => {
                pending += 1;
                break;
            }
        }
    }

    println!("uploaded {sent} batch(es); {poisoned} rejected permanently; {pending} still pending");
    if pending > 0 {
        anyhow::bail!("upload incomplete: {pending} sealed batch(es) remain; re-run to resume (same bytes, same idempotency key)");
    }
    Ok(())
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
                if status.is_redirection() {
                    store
                        .record_upload_attempt(&batch.batch_id, Some("redirect refused"))
                        .await?;
                    store
                        .poison_upload_batch(&batch.batch_id, "redirect refused")
                        .await?;
                    return Ok(Sent::Poisoned);
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
