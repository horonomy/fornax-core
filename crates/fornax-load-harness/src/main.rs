//! Local-sync capacity/soak harness (FORNX-211, first slice).
//!
//! Measures the SLI FORNX-210 §1 defines: event-arrival to durable-commit
//! latency against `fornax-store`, end to end through a real `fornax-daemon`
//! process over its real UDS ingest path — not `handle_message` called
//! in-process, which would prove nothing about the real OS-level path.
//!
//! Always targets an isolated `$FORNAX_HOME` (own socket, own sqlite file).
//! Never point `--fornax-home` at a real user daemon's home — this harness
//! sends synthetic events and will corrupt a real session history if it does.
//!
//! Scope: local-sync leg only. Ingest/processing/SaaS load paths (Cloud Run,
//! Pub/Sub) need their own harness against deployed infra and are explicitly
//! out of scope here (see FORNX-210's §2-4).

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use clap::Parser;
use fornax_store::Store;
use fornax_types::{AgentEvent, EventKind, IngestMessage, Provider};
use serde::Serialize;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(about = "Fornax local-sync capacity/soak harness (FORNX-211)")]
struct Args {
    /// Isolated $FORNAX_HOME of an already-running fornax-daemon test instance.
    /// Must not be a real user's daemon home.
    #[arg(long)]
    fornax_home: PathBuf,

    /// Load profile.
    #[arg(long, value_enum, default_value = "steady")]
    profile: Profile,

    /// Number of synthetic events to submit.
    #[arg(long, default_value_t = 500)]
    count: usize,

    /// For burst profile: events submitted concurrently per burst.
    #[arg(long, default_value_t = 50)]
    burst_size: usize,

    /// Max time to wait for a single event's durable commit before counting
    /// it as a budget-event (lost/late) rather than a measured latency.
    #[arg(long, default_value_t = 2000)]
    commit_timeout_ms: u64,

    /// Where to write the JSON result.
    #[arg(long)]
    out: PathBuf,
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum Profile {
    /// One event submitted at a time, waited for commit before the next.
    Steady,
    /// `burst_size` events submitted concurrently, repeated until `count`.
    Burst,
    /// Like steady, but intended for a long `count`/duration to catch
    /// leaks — same mechanics, different caller-chosen scale.
    Soak,
}

#[derive(Serialize)]
struct RunResult {
    profile: String,
    requested_count: usize,
    submitted: usize,
    committed: usize,
    budget_events_lost_or_late: usize,
    p50_ms: f64,
    p90_ms: f64,
    p99_ms: f64,
    max_ms: f64,
    throughput_events_per_sec: f64,
    wall_clock_ms: u128,
    db_bytes_before: u64,
    db_bytes_after: u64,
    wal_bytes_after: u64,
}

fn sock_path(home: &Path) -> PathBuf {
    home.join("fornax.sock")
}

fn db_path(home: &Path) -> PathBuf {
    home.join("fornax.db")
}

fn file_len(path: &Path) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

fn synthetic_event(session_id: &str) -> AgentEvent {
    AgentEvent {
        id: Uuid::new_v4(),
        session_id: session_id.to_string(),
        provider: Provider::ClaudeCode,
        kind: EventKind::PostToolUse,
        observed_at: chrono::Utc::now().to_rfc3339(),
        tool_name: Some("fornx211-synthetic-tool".to_string()),
        tool_input: Some(serde_json::json!({"synthetic": true})),
        tool_response: Some(serde_json::json!({"ok": true})),
        raw: serde_json::json!({
            "synthetic_harness": "fornax-load-harness",
            "ticket": "FORNX-211",
        }),
    }
}

/// Submits one event over a fresh UDS connection (matching real hook
/// behavior: one connection per invocation, not a shared long-lived pipe).
async fn submit_event(home: &Path, event: &AgentEvent) -> anyhow::Result<()> {
    let msg = IngestMessage::Event(event.clone());
    let line = serde_json::to_string(&msg)?;
    let mut stream = UnixStream::connect(sock_path(home)).await?;
    stream.write_all(line.as_bytes()).await?;
    stream.write_all(b"\n").await?;
    stream.shutdown().await?;
    Ok(())
}

/// Polls the store until `event_id` shows up in `session_id`'s events, or
/// `timeout` elapses. Returns the measured latency, or `None` on timeout —
/// a `None` is a real error-budget event (FORNX-210 §1), not a sample to
/// silently drop from the percentile math.
async fn wait_for_commit(
    store: &Store,
    session_id: &str,
    event_id: Uuid,
    submitted_at: Instant,
    timeout: Duration,
) -> Option<Duration> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(events) = store.events_for_session(session_id).await {
            if events.iter().any(|e| e.id == event_id) {
                return Some(submitted_at.elapsed());
            }
        }
        if Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

fn percentile(sorted_ms: &[f64], p: f64) -> f64 {
    if sorted_ms.is_empty() {
        return 0.0;
    }
    let idx = ((p / 100.0) * (sorted_ms.len() as f64 - 1.0)).round() as usize;
    sorted_ms[idx.min(sorted_ms.len() - 1)]
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    anyhow::ensure!(
        args.fornax_home.join("fornax.sock").exists() || sock_path(&args.fornax_home).exists(),
        "no UDS socket at {:?} — start an isolated fornax-daemon with this FORNAX_HOME first",
        args.fornax_home
    );

    let store = Store::open(db_path(&args.fornax_home)).await?;
    let db_bytes_before = file_len(&db_path(&args.fornax_home));

    let session_id = format!("fornx211-harness-{}", Uuid::new_v4().simple());
    let commit_timeout = Duration::from_millis(args.commit_timeout_ms);
    let wall_start = Instant::now();

    let mut latencies_ms: Vec<f64> = Vec::with_capacity(args.count);
    let mut submitted = 0usize;
    let mut committed = 0usize;
    let mut lost_or_late = 0usize;

    match args.profile {
        Profile::Steady | Profile::Soak => {
            for _ in 0..args.count {
                let event = synthetic_event(&session_id);
                let event_id = event.id;
                let t0 = Instant::now();
                if submit_event(&args.fornax_home, &event).await.is_err() {
                    lost_or_late += 1;
                    continue;
                }
                submitted += 1;
                match wait_for_commit(&store, &session_id, event_id, t0, commit_timeout).await {
                    Some(latency) => {
                        committed += 1;
                        latencies_ms.push(latency.as_secs_f64() * 1000.0);
                    }
                    None => lost_or_late += 1,
                }
            }
        }
        Profile::Burst => {
            let mut remaining = args.count;
            while remaining > 0 {
                let this_burst = remaining.min(args.burst_size);
                remaining -= this_burst;

                let mut handles = Vec::with_capacity(this_burst);
                for _ in 0..this_burst {
                    let event = synthetic_event(&session_id);
                    let home = args.fornax_home.clone();
                    let t0 = Instant::now();
                    handles.push(async move {
                        let event_id = event.id;
                        let ok = submit_event(&home, &event).await.is_ok();
                        (event_id, t0, ok)
                    });
                }
                let results = futures_join_all(handles).await;
                for (event_id, t0, ok) in results {
                    if !ok {
                        lost_or_late += 1;
                        continue;
                    }
                    submitted += 1;
                    match wait_for_commit(&store, &session_id, event_id, t0, commit_timeout).await {
                        Some(latency) => {
                            committed += 1;
                            latencies_ms.push(latency.as_secs_f64() * 1000.0);
                        }
                        None => lost_or_late += 1,
                    }
                }
            }
        }
    }

    let wall_clock_ms = wall_start.elapsed().as_millis();
    latencies_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let result = RunResult {
        profile: format!("{:?}", args.profile).to_lowercase(),
        requested_count: args.count,
        submitted,
        committed,
        budget_events_lost_or_late: lost_or_late,
        p50_ms: percentile(&latencies_ms, 50.0),
        p90_ms: percentile(&latencies_ms, 90.0),
        p99_ms: percentile(&latencies_ms, 99.0),
        max_ms: latencies_ms.last().copied().unwrap_or(0.0),
        throughput_events_per_sec: if wall_clock_ms > 0 {
            (submitted as f64) / (wall_clock_ms as f64 / 1000.0)
        } else {
            0.0
        },
        wall_clock_ms,
        db_bytes_before,
        db_bytes_after: file_len(&db_path(&args.fornax_home)),
        wal_bytes_after: file_len(&args.fornax_home.join("fornax.db-wal")),
    };

    std::fs::write(&args.out, serde_json::to_string_pretty(&result)?)?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

/// Minimal local stand-in for `futures::future::join_all` — avoids pulling
/// in the whole `futures` crate for one call site; every future here is
/// `Send + 'static` and already boxed-free, so a plain `Vec<JoinHandle>`
/// drive-to-completion loop is enough.
async fn futures_join_all<F, T>(futs: Vec<F>) -> Vec<T>
where
    F: std::future::Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let handles: Vec<_> = futs.into_iter().map(tokio::spawn).collect();
    let mut out = Vec::with_capacity(handles.len());
    for h in handles {
        out.push(h.await.expect("harness submit task panicked"));
    }
    out
}
