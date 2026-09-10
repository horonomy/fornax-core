//! Latency budget and cancellation for probe execution (FORNX-346 AC5:
//! "acquisition respects cost/latency/resource budgets and is
//! cancellable").
//!
//! Every probe this crate implements ([`crate::probes::verify_artifact_hash`],
//! [`crate::probes::inspect_vcs_state`], [`crate::probes::inspect_vcs_state_for_root`])
//! is a synchronous, in-process, read-only operation with no external
//! resource held open across a call -- there is nothing to roll back if a
//! probe runs long. [`AcquisitionBudget::run`] therefore implements
//! cancellation the way it is actually meaningful for this shape of work:
//! the *caller* stops waiting once `max_latency` elapses and gets back an
//! honest [`AcquisitionOutcome::TimedOut`] instead of blocking forever,
//! even though Rust has no safe way to forcibly kill the still-running
//! probe thread. This is real, observable cancellation from the caller's
//! perspective -- an orphaned thread reading a file or querying `gix` can
//! never leave a half-done mutation, so there is no safety property lost
//! by letting it finish in the background and drop its result.
//!
//! `std::thread::spawn` here is an in-process OS thread, not a subprocess
//! -- distinct from, and not covered by,
//! `fornax-daemon/tests/adversarial_daemon_input.rs::
//! subprocess_surface_is_still_zero_in_production_code`'s external-process
//! spawn scan (see that test's own doc comment for the exact surface it
//! scans).

use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::outcome::AcquisitionOutcome;

/// Cost/latency budget applied to one probe execution. Latency is the only
/// dimension this crate can meaningfully bound today -- every probe is a
/// bounded local file/`gix` read, not a metered external API call, so
/// there is no separate dollar-cost or request-count budget to track (see
/// `docs/adr/0016-evidence-acquisition-boundary.md` for why `RerunTest`/
/// `QueryCiStatus`, the probes that *would* need one, remain out of
/// scope).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcquisitionBudget {
    pub max_latency: Duration,
}

/// A conservative default for a local file read / `gix` status query --
/// generous enough that a slow disk or a large working tree never
/// false-positives, tight enough that a genuinely hung probe (e.g. a
/// network filesystem gone unresponsive) is reported rather than blocking
/// a daemon request indefinitely.
pub const DEFAULT_MAX_LATENCY: Duration = Duration::from_secs(5);

impl Default for AcquisitionBudget {
    fn default() -> Self {
        Self {
            max_latency: DEFAULT_MAX_LATENCY,
        }
    }
}

impl AcquisitionBudget {
    pub fn new(max_latency: Duration) -> Self {
        Self { max_latency }
    }

    /// Runs `probe` on its own thread and waits at most `self.max_latency`
    /// for it to finish. Returns the probe's own outcome on time, or
    /// [`AcquisitionOutcome::TimedOut`] (never a fabricated `Acquired`/
    /// `Failed`) if the budget is exceeded.
    pub fn run<F>(&self, probe: F) -> AcquisitionOutcome
    where
        F: FnOnce() -> AcquisitionOutcome + Send + 'static,
    {
        let (tx, rx) = mpsc::channel();
        let start = Instant::now();
        // Result of `send` is deliberately ignored: if the receiver has
        // already timed out and dropped `rx`, there is nothing left to
        // deliver to, and that is not an error condition for the probe
        // thread itself.
        std::thread::spawn(move || {
            let _ = tx.send(probe());
        });
        match rx.recv_timeout(self.max_latency) {
            Ok(outcome) => outcome,
            Err(mpsc::RecvTimeoutError::Timeout) => AcquisitionOutcome::TimedOut {
                reason: format!(
                    "probe exceeded the {:?} acquisition latency budget",
                    self.max_latency
                ),
                elapsed_ms: start.elapsed().as_millis() as u64,
            },
            Err(mpsc::RecvTimeoutError::Disconnected) => AcquisitionOutcome::Failed {
                reason: "probe thread ended without producing an outcome".to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fornax_types::{Evidence, EvidenceKind};
    use uuid::Uuid;

    fn dummy_evidence() -> Evidence {
        Evidence {
            id: Uuid::new_v4(),
            session_id: "s1".to_string(),
            source_event_id: Uuid::new_v4(),
            kind: EvidenceKind::ProcessObservation,
            observed_at: "2026-01-01T00:00:00Z".to_string(),
            payload: serde_json::json!({}),
            provenance: "test".to_string(),
            source: None,
            extension: None,
            evidence_purged: false,
        }
    }

    #[test]
    fn a_fast_probe_completes_within_budget() {
        let budget = AcquisitionBudget::new(Duration::from_secs(1));
        let outcome = budget.run(|| AcquisitionOutcome::Acquired(Box::new(dummy_evidence())));
        assert!(matches!(outcome, AcquisitionOutcome::Acquired(_)));
    }

    #[test]
    fn a_slow_probe_is_reported_as_timed_out_not_silently_awaited() {
        let budget = AcquisitionBudget::new(Duration::from_millis(20));
        let outcome = budget.run(|| {
            std::thread::sleep(Duration::from_millis(500));
            AcquisitionOutcome::Acquired(Box::new(dummy_evidence()))
        });
        match outcome {
            AcquisitionOutcome::TimedOut { elapsed_ms, .. } => {
                assert!(elapsed_ms < 500, "must not have waited for the full probe");
            }
            other => panic!("expected TimedOut, got {other:?}"),
        }
    }

    #[test]
    fn default_budget_is_five_seconds() {
        assert_eq!(
            AcquisitionBudget::default().max_latency,
            Duration::from_secs(5)
        );
    }
}
