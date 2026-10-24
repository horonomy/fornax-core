//! `fornax upload` (FORNX-464): the personal monthly metadata batch upload.
//!
//! Operator-invoked here; the daemon also runs the same sender automatically
//! for each closed month while a live consent exists. It sends metadata only -- ids,
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

use clap::Subcommand;

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
    println!("schedule: automatic monthly upload by the daemon while a live consent exists; `fornax upload run` sends on demand");
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

async fn run(
    store: &fornax_store::Store,
    home: &std::path::Path,
    window: Option<String>,
    max_batches: usize,
) -> anyhow::Result<()> {
    let report = fornax_upload::run_upload(store, home, window, max_batches).await?;
    println!(
        "staged {} new metadata member(s); {} expired at the outbox bound or with an ended consent",
        report.staged, report.expired_at_bound
    );
    for batch in &report.skipped {
        println!(
            "skipping batch {batch}: sealed for a different destination than the live consent"
        );
    }
    println!(
        "uploaded {} batch(es); {} rejected permanently; {} still pending",
        report.sent, report.poisoned, report.pending
    );
    if report.pending > 0 {
        anyhow::bail!("upload incomplete: {} sealed batch(es) remain; re-run to resume (same bytes, same idempotency key)", report.pending);
    }
    Ok(())
}
