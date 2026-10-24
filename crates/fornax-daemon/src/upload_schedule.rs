//! Automatic monthly metadata upload (FORNX-464).
//!
//! A single background task that, once per interval, asks
//! [`fornax_upload::scheduled_tick`] whether anything is due. The tick is a
//! no-op unless a live personal-profile consent exists (which already implies
//! an allowlisted destination and a current profile generation), a closed
//! month or unfinished batch is due, and the device id and credential are
//! provisioned. A corporate or unconfigured install has no live consent, so
//! this task can never upload for it. What it sends is exactly what
//! `fornax upload run` sends: the metadata-only outbox, with the egress
//! decision re-asked before every request.

use std::path::PathBuf;
use std::time::Duration;

use fornax_upload::TickOutcome;

use crate::AppState;

const DEFAULT_INTERVAL_SECONDS: u64 = 3600;
const MIN_INTERVAL_SECONDS: u64 = 60;
const INTERVAL_ENV: &str = "FORNAX_UPLOAD_SCHEDULE_INTERVAL_SECONDS";

pub(crate) fn spawn(state: AppState, home: PathBuf) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move { supervisor_loop(state, home).await })
}

fn interval() -> Duration {
    let secs = std::env::var(INTERVAL_ENV)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_INTERVAL_SECONDS)
        .max(MIN_INTERVAL_SECONDS);
    Duration::from_secs(secs)
}

async fn supervisor_loop(state: AppState, home: PathBuf) {
    let every = interval();
    tracing::info!(
        interval_seconds = every.as_secs(),
        "monthly upload schedule task enabled (inert without a live consent)"
    );
    loop {
        tokio::time::sleep(every).await;
        let store = state.store.clone();
        let home = home.clone();
        // A panic in one tick must not end the schedule.
        let outcome =
            tokio::spawn(async move { fornax_upload::scheduled_tick(&store, &home).await }).await;
        match outcome {
            Ok(Ok(
                TickOutcome::NoConsent
                | TickOutcome::NothingDue
                | TickOutcome::Disabled
                | TickOutcome::Busy,
            )) => {}
            Ok(Ok(TickOutcome::NotConfigured(why))) => {
                tracing::warn!(reason = %why, "monthly upload is due but the device is not provisioned; nothing sent");
            }
            Ok(Ok(TickOutcome::Ran(report))) => {
                tracing::info!(
                    sent = report.sent,
                    poisoned = report.poisoned,
                    pending = report.pending,
                    "monthly upload tick finished"
                );
            }
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "monthly upload tick failed; will retry next interval");
            }
            Err(_) => tracing::warn!("monthly upload tick panicked; will retry next interval"),
        }
    }
}
