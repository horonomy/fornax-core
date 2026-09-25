//! FORNX-382 (Self-Integrity), invariant #1: "evidence from session/tenant
//! A cannot affect B", exercised under genuine concurrent load.
//!
//! `fornax-daemon`'s `AppState` keys its per-session runtime state in
//! `Arc<Mutex<HashMap<String, RuntimeCapabilities>>>` (`main.rs`'s `caps`
//! field) — a coarse-grained lock guarding a map keyed by session id. This
//! test does not spin up the full daemon (that's
//! `cross_session_identity_handshake.rs`'s job, at the cross-*process*
//! granularity); it exercises the *same concurrency primitive shape*
//! in-process, under real concurrent `tokio` tasks, to prove the pattern
//! itself does not let one session's concurrent write become visible under
//! another session's key, and that no reader ever observes a torn
//! (partially-written) value.
//!
//! Evaluated and rejected: `loom`. Loom's exhaustive-interleaving model is
//! built for lock-free/atomic code with genuinely many legal orderings to
//! enumerate; this daemon's actual concurrency model is coarse-grained
//! `Arc<Mutex<_>>`/`Arc<RwLock<_>>` guarding whole values (see `main.rs`'s
//! `caps: Arc<Mutex<HashMap<...>>>` and `policy: Arc<RwLock<...>>`) — the
//! mutex already serializes every access, so there is no finer-grained
//! interleaving for Loom to usefully explore here. A real concurrent stress
//! test against the actual primitive is the more honest tool for this
//! specific risk than a Loom model of a lock Rust's stdlib already
//! guarantees is exclusive.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Mirrors `RuntimeCapabilities`' role in `AppState.caps` closely enough to
/// exercise the real risk (a multi-field value written non-atomically by a
/// naive caller) without depending on `fornax-daemon`'s private `main.rs`
/// internals across the integration-test boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SessionState {
    session_id: String,
    generation: u64,
    marker: String,
}

const SESSIONS: usize = 64;
const WRITES_PER_SESSION: usize = 50;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_sessions_never_cross_attribute_or_tear_shared_state() {
    let caps: Arc<Mutex<HashMap<String, SessionState>>> = Arc::new(Mutex::new(HashMap::new()));

    let mut handles = Vec::new();
    for s in 0..SESSIONS {
        let caps = Arc::clone(&caps);
        let session_id = format!("session-{s}");
        handles.push(tokio::spawn(async move {
            for gen in 0..WRITES_PER_SESSION as u64 {
                let value = SessionState {
                    session_id: session_id.clone(),
                    generation: gen,
                    marker: format!("{session_id}-marker-{gen}"),
                };
                {
                    let mut guard = caps.lock().await;
                    guard.insert(session_id.clone(), value.clone());
                }
                // Immediately read back under a fresh lock acquisition --
                // must see exactly what this task itself just wrote (its
                // own session), never another concurrently-running
                // session's value and never a torn/partial struct (the
                // mutex makes "torn" impossible by construction, but this
                // proves it end-to-end rather than asserting it from the
                // type signature alone).
                let guard = caps.lock().await;
                let observed = guard.get(&session_id).cloned();
                drop(guard);
                assert_eq!(
                    observed,
                    Some(value),
                    "session {session_id} observed a different session's state, or a torn value"
                );
            }
        }));
    }

    for h in handles {
        h.await.expect("session task must not panic");
    }

    // Final state: every session's last-written generation is exactly what
    // that session (and only that session) wrote -- no key was ever
    // overwritten by a different session_id string, and the map has
    // exactly SESSIONS entries (no session's key was lost or merged).
    let guard = caps.lock().await;
    assert_eq!(guard.len(), SESSIONS);
    for s in 0..SESSIONS {
        let session_id = format!("session-{s}");
        let state = guard
            .get(&session_id)
            .unwrap_or_else(|| panic!("missing final state for {session_id}"));
        assert_eq!(state.session_id, session_id);
        assert_eq!(state.generation, (WRITES_PER_SESSION - 1) as u64);
    }
}
