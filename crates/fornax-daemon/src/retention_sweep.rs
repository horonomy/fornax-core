//! Background retention-sweep task (FORNX-319, epic FORNX-20).
//!
//! Periodically drives `fornax_store::retention::Store::sweep_expired_records`
//! against this daemon's own store, following `policy_poll.rs`'s spawn/
//! supervisor-loop wiring pattern (FORNX-311) rather than inventing a new
//! shape: `spawn()` always returns a `JoinHandle` so `main()` can `.abort()`
//! it unconditionally at shutdown, and each cycle runs inside its own
//! `tokio::spawn` for panic containment (a panicking sweep cycle must never
//! take down the daemon or the next cycle).
//!
//! **This task does NOT acquire `AppState::processing`** — exactly
//! `policy_poll.rs`'s own reasoning applies here verbatim: the sweep only
//! ever touches `dataset_lineage_tags` plus, when a tag has expired, the
//! one row it names in `agent_events`/`claims`/`evidence`/`findings`. Each
//! sweep batch is its own small, bounded `BEGIN IMMEDIATE` transaction
//! (`Store::sweep_expired_records`'s own doc comment), so holding the
//! broader `processing` mutex here would put a background maintenance task
//! ahead of a live hook request, against ADR-0001 D2's spirit — the same
//! argument `policy_poll.rs` makes for not holding it either.
//!
//! One in-memory cursor is carried across cycles for the lifetime of this
//! task (never persisted — a restart simply starts a fresh full pass from
//! the beginning of `dataset_lineage_tags`, which is harmless: an
//! already-expired row is still expired next time it's examined). Within
//! one cycle, batches are drawn until either `more_remaining` is false (a
//! full pass completed) or [`MAX_BATCHES_PER_CYCLE`] is reached — bounding
//! how much work one wakeup can do, mirroring the per-call batch bound
//! `Store::sweep_expired_records` itself already enforces one layer down.
//!
//! **Store-size cap.** After each cycle, [`check_store_size_cap`] compares
//! the on-disk `fornax.db` file size against a configurable cap and logs a
//! warning (never fails the cycle) when it's exceeded — the sweep's own
//! purge/delete behavior is the actual mechanism that keeps the store
//! bounded over time; this check only surfaces when that isn't keeping up.
//!
//! **Audit-ledger retention window.** FORNX-315's `audit_events` table
//! (append-only, hash-chained — see `fornax_store::audit_ledger`) is
//! confirmed absent from [`fornax_store::retention::KNOWN_RECORD_TABLES`]
//! and is therefore never touched by this sweep at all — a lineage tag is
//! never recorded for it in the first place, so there is nothing for a
//! sweep pass to find. This is a deliberate policy statement, not an
//! oversight: an audit trail's value is in outliving the raw evidence it
//! once corroborated, so it needs a materially longer retention window
//! than [`fornax_store::retention::RAW_LOCAL_RETENTION`]/
//! [`fornax_store::retention::DERIVED_FINDING_RETENTION`] — likely "kept
//! indefinitely, or on its own much longer explicit schedule" — a decision
//! left to whichever future ticket defines the audit ledger's own
//! retention/rotation policy, not silently inherited from this module's
//! short-lived evidence/finding durations.

use std::path::PathBuf;
use std::time::Duration;

use chrono::Utc;
use fornax_store::retention::SweepReport;

use crate::AppState;

pub(crate) const DEFAULT_INTERVAL_SECONDS: u64 = 3600;
pub(crate) const MIN_INTERVAL_SECONDS: u64 = 60;
pub(crate) const DEFAULT_BATCH_SIZE: i64 = 500;
/// Bounds how many batches one wakeup drains, even if the table has more
/// expired rows than that — the remainder is picked up on the next tick
/// rather than one wakeup running indefinitely.
pub(crate) const MAX_BATCHES_PER_CYCLE: usize = 50;
/// FORNX-319 AC4's "documented bound on total ledger/store size". Chosen as
/// a generous default for a local single-user daemon; an operator with an
/// unusual workload can override it. Exceeding it only logs a warning today
/// — no enforcement action is taken automatically, since the sweep's own
/// time-based purge/delete is the real bounding mechanism and a hard
/// enforcement action (e.g. refusing new writes) is out of this ticket's
/// scope.
pub(crate) const DEFAULT_MAX_STORE_SIZE_BYTES: u64 = 500 * 1024 * 1024;

const INTERVAL_ENV: &str = "FORNAX_RETENTION_SWEEP_INTERVAL_SECONDS";
const BATCH_SIZE_ENV: &str = "FORNAX_RETENTION_SWEEP_BATCH_SIZE";
const MAX_STORE_SIZE_ENV: &str = "FORNAX_STORE_MAX_SIZE_BYTES";

#[derive(Clone, Copy)]
struct SweepConfig {
    interval: Duration,
    batch_size: i64,
    max_store_size_bytes: u64,
}

/// Spawns the retention-sweep supervisor task. Always returns a
/// `JoinHandle`, mirroring `policy_poll::spawn`, so `main()` can `.abort()`
/// it unconditionally during graceful shutdown regardless of configuration.
pub(crate) fn spawn(state: AppState, db_path: PathBuf) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move { supervisor_loop(state, db_path).await })
}

fn resolve_config() -> SweepConfig {
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

    let batch_size = std::env::var(BATCH_SIZE_ENV)
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_BATCH_SIZE);

    let max_store_size_bytes = std::env::var(MAX_STORE_SIZE_ENV)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_MAX_STORE_SIZE_BYTES);

    SweepConfig {
        interval: Duration::from_secs(interval_secs),
        batch_size,
        max_store_size_bytes,
    }
}

async fn supervisor_loop(state: AppState, db_path: PathBuf) {
    let config = resolve_config();
    tracing::info!(
        interval_seconds = config.interval.as_secs(),
        batch_size = config.batch_size,
        "retention sweep task enabled"
    );

    let mut cursor: Option<String> = None;

    loop {
        tokio::time::sleep(config.interval).await;

        let cycle_state = state.clone();
        let cycle_cursor = cursor.clone();
        let outcome =
            tokio::spawn(async move { run_one_cycle(cycle_state, cycle_cursor, config).await })
                .await;

        cursor = match outcome {
            Ok(next_cursor) => next_cursor,
            Err(_join_err) => {
                tracing::warn!(
                    "retention sweep cycle panicked; resuming from the same cursor next cycle"
                );
                cursor
            }
        };

        check_store_size_cap(&db_path, config.max_store_size_bytes);
    }
}

/// Drains up to [`MAX_BATCHES_PER_CYCLE`] bounded batches, or until a full
/// pass over `dataset_lineage_tags` completes (`more_remaining == false`),
/// whichever comes first. Returns the cursor to resume from next cycle
/// (`None` once a full pass completed).
async fn run_one_cycle(
    state: AppState,
    mut cursor: Option<String>,
    config: SweepConfig,
) -> Option<String> {
    let mut total = SweepReport::default();
    for _ in 0..MAX_BATCHES_PER_CYCLE {
        let report = match state
            .store
            .sweep_expired_records(Utc::now(), cursor.as_deref(), config.batch_size)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "retention sweep batch failed; resuming from the same cursor next cycle");
                return cursor;
            }
        };
        total.examined += report.examined;
        total.purged_evidence += report.purged_evidence;
        total.deleted_records += report.deleted_records;
        total.unknown_table_skipped += report.unknown_table_skipped;
        let more_remaining = report.more_remaining;
        cursor = report.next_cursor;
        if !more_remaining {
            break;
        }
    }

    if total.examined > 0 {
        tracing::info!(
            examined = total.examined,
            purged_evidence = total.purged_evidence,
            deleted_records = total.deleted_records,
            unknown_table_skipped = total.unknown_table_skipped,
            "retention sweep cycle complete"
        );
    }

    cursor
}

/// Logs a warning (never fails/panics) when the on-disk store file exceeds
/// `cap_bytes`. A missing/unreadable file is silently ignored — this is a
/// best-effort diagnostic, not a correctness mechanism.
fn check_store_size_cap(db_path: &std::path::Path, cap_bytes: u64) {
    let Ok(meta) = std::fs::metadata(db_path) else {
        return;
    };
    let size = meta.len();
    if size > cap_bytes {
        tracing::warn!(
            path = %db_path.display(),
            size_bytes = size,
            cap_bytes,
            "store file exceeds the configured size cap ({MAX_STORE_SIZE_ENV}); the retention \
             sweep's own time-based purge/delete is the real bounding mechanism — investigate \
             an unusually large backlog or an unusually long-lived session if this persists"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `cargo test` runs tests on separate threads within one process —
    /// `resolve_config` reads process-global env vars, so the three tests
    /// below must not interleave. Mirrors `policy_poll.rs`'s `ENV_LOCK`
    /// precedent.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn resolve_config_clamps_a_too_small_interval_to_the_floor() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var(INTERVAL_ENV, "1");
        let config = resolve_config();
        assert_eq!(config.interval, Duration::from_secs(MIN_INTERVAL_SECONDS));
        std::env::remove_var(INTERVAL_ENV);
    }

    #[test]
    fn resolve_config_uses_documented_defaults_when_unset() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var(INTERVAL_ENV);
        std::env::remove_var(BATCH_SIZE_ENV);
        std::env::remove_var(MAX_STORE_SIZE_ENV);
        let config = resolve_config();
        assert_eq!(
            config.interval,
            Duration::from_secs(DEFAULT_INTERVAL_SECONDS)
        );
        assert_eq!(config.batch_size, DEFAULT_BATCH_SIZE);
        assert_eq!(config.max_store_size_bytes, DEFAULT_MAX_STORE_SIZE_BYTES);
    }

    #[test]
    fn resolve_config_rejects_a_non_positive_batch_size_and_falls_back_to_the_default() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var(BATCH_SIZE_ENV, "0");
        let config = resolve_config();
        assert_eq!(config.batch_size, DEFAULT_BATCH_SIZE);
        std::env::remove_var(BATCH_SIZE_ENV);
    }

    #[test]
    fn check_store_size_cap_never_panics_on_a_missing_file() {
        check_store_size_cap(std::path::Path::new("/nonexistent/fornax.db"), 1024);
    }

    #[tokio::test]
    async fn run_one_cycle_drains_a_full_backlog_within_the_per_cycle_batch_cap() {
        let dir =
            std::env::temp_dir().join(format!("fnx-retention-sweep-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        let store = fornax_store::Store::open(dir.join("fornax.db"))
            .await
            .expect("open store");

        // A backlog smaller than MAX_BATCHES_PER_CYCLE * batch_size, so one
        // cycle should fully drain it and return cursor = None. Uses only
        // the public `Store::record_lineage_tag` API (this crate has no
        // access to `fornax_store::Store`'s private `pool` field).
        let old = (Utc::now() - chrono::Duration::days(400)).to_rfc3339();
        for i in 0..50 {
            let tag = fornax_types::DatasetLineageTag {
                schema_version: fornax_types::RELIABILITY_CONTEXT_SCHEMA_VERSION,
                retention_class: fornax_types::RetentionClass::RawLocal,
                tenant_ref: fornax_types::TenantRef("t".to_string()),
                source_record_ids: vec![],
                recorded_at: old.clone(),
                deletion_requested_at: None,
            };
            store
                .record_lineage_tag("retention_sweep_test_table", &format!("row-{i}"), &tag)
                .await
                .expect("hand-record a synthetic backlog tag");
        }

        let state = AppState {
            store,
            caps: std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
            processing: std::sync::Arc::new(tokio::sync::Mutex::new(())),
            trust: std::sync::Arc::new(None),
            policy: std::sync::Arc::new(tokio::sync::RwLock::new(
                crate::PolicyCacheSnapshot::empty(),
            )),
        };

        let config = SweepConfig {
            interval: Duration::from_secs(60),
            batch_size: 10,
            max_store_size_bytes: DEFAULT_MAX_STORE_SIZE_BYTES,
        };
        let cursor = run_one_cycle(state, None, config).await;
        assert_eq!(
            cursor, None,
            "a 50-row backlog with batch_size=10 fits within MAX_BATCHES_PER_CYCLE and should \
             fully drain in one cycle"
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
