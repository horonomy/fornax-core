//! Daemon-managed Codex rollout capture (FORNX-468).
//!
//! Codex claims ("tests passed") and exit-code evidence exist only in the
//! rollout JSONL, so without this a new user gets no findings until they start
//! `fornax-hook-codex` by hand for every session. This task does that inside
//! the daemon.
//!
//! Opt-in: it does nothing unless `$FORNAX_HOME/codex-watch.json` exists
//! (written by `fornax install codex`, removed by uninstall), and it re-checks
//! on every scan so install/uninstall need no restart. Nothing is read from
//! the Codex directory without the marker.
//!
//! What is read is the same data the standalone tailer forwards (tool
//! commands and output, the final assistant message). Every message goes
//! through [`crate::process_line`], so ingest-boundary redaction and
//! quarantine apply exactly as for any other adapter.
//!
//! Only new activity is ingested, decided per file: a rollout created after
//! the watcher began is read from its start; one that already existed (a
//! `codex resume` of an old session, a file outside the 32-file window at
//! startup, anything written while capture was off) starts at its current end.
//! Before forwarding from a mid-file position the prefix is replayed through
//! the adapter with its output discarded, which restores the
//! native session id (FORNX-462: never invent one), format latch and pending
//! call pairing. One task handles files and lines strictly in order, so a
//! claim's own exit-code evidence is always stored before the claim is
//! checked; do not parallelise it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use fornax_adapter_codex::rollout_tail::{
    discover, last_newline_before, read_new_lines, read_prefix, resume_cursor, Start, TailCursor,
};
use fornax_adapter_codex::watch_marker::{self, Marker, MarkerError};
use fornax_adapter_codex::{stamped_capabilities, CodexAdapter};
use fornax_types::{AgentAdapter, IngestMessage, NormalizationOutcome};

use crate::AppState;

const CURSOR_FILE: &str = "codex-watch-cursors.json";

const SCAN_EVERY: Duration = Duration::from_secs(5);
const TAIL_EVERY: Duration = Duration::from_millis(500);
const FRESH_WINDOW: Duration = Duration::from_secs(24 * 3600);
const IDLE_AFTER: Duration = Duration::from_secs(30 * 60);
const MAX_FILES: usize = 32;
const MAX_LINE_BYTES: u64 = 8 * 1024 * 1024;
/// Largest prefix replayed to recover adapter state; beyond it only the first
/// line (`session_meta`) is replayed.
const WARM_REPLAY_CAP: u64 = 8 * 1024 * 1024;

struct Tracked {
    adapter: CodexAdapter,
    cursor: TailCursor,
    session_hint: Option<String>,
    caps_sent: bool,
    warned_no_session: bool,
    last_activity: Instant,
}

pub(crate) fn spawn(state: AppState, home: PathBuf) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move { watch_loop(state, home).await })
}

fn read_marker(home: &Path) -> Option<Marker> {
    match watch_marker::read(home) {
        Ok(m) => Some(m),
        Err(MarkerError::Missing) => None,
        Err(MarkerError::RelativeSessionsDir) => {
            tracing::warn!(
                "codex-watch.json sessions_dir must be absolute; codex capture stays off"
            );
            None
        }
        Err(e) => {
            tracing::warn!(error = ?e, "codex-watch.json is unreadable; codex capture stays off");
            None
        }
    }
}

fn load_cursors(home: &Path) -> BTreeMap<String, TailCursor> {
    match std::fs::read_to_string(home.join(CURSOR_FILE)) {
        Ok(raw) => serde_json::from_str(&raw).unwrap_or_else(|e| {
            tracing::warn!(error = %e, "codex-watch cursor file is corrupt; new files start at their end");
            BTreeMap::new()
        }),
        Err(_) => BTreeMap::new(),
    }
}

fn save_cursors(home: &Path, cursors: &BTreeMap<String, TailCursor>) {
    let Ok(raw) = serde_json::to_vec(cursors) else {
        return;
    };
    let tmp = home.join(format!("{CURSOR_FILE}.tmp"));
    if std::fs::write(&tmp, raw).is_ok() {
        let _ = std::fs::rename(&tmp, home.join(CURSOR_FILE));
    }
}

async fn watch_loop(state: AppState, home: PathBuf) {
    let mut tracked: BTreeMap<PathBuf, Tracked> = BTreeMap::new();
    // Files dropped for idleness, with the length they had; re-tracked only
    // once they grow, so an idle session is not replayed every 30 minutes.
    let mut idle: BTreeMap<PathBuf, u64> = BTreeMap::new();
    let mut cursors = load_cursors(&home);
    // What counts as history is decided per file: a rollout created before
    // this point (and not yet followed) starts at its end. Reset whenever
    // capture is switched off, so nothing written while it was off is read.
    let mut watching_since = SystemTime::now();
    let mut first_scan = true;
    let mut last_scan: Option<Instant> = None;
    let mut warned_missing_dir = false;
    loop {
        tokio::time::sleep(TAIL_EVERY).await;

        if last_scan.is_none_or(|t| t.elapsed() >= SCAN_EVERY) {
            last_scan = Some(Instant::now());
            let Some(marker) = read_marker(&home) else {
                if !tracked.is_empty() || !cursors.is_empty() {
                    tracked.clear();
                    idle.clear();
                    cursors.clear();
                    let _ = std::fs::remove_file(home.join(CURSOR_FILE));
                }
                watching_since = SystemTime::now();
                first_scan = true;
                continue;
            };
            if !marker.sessions_dir.is_dir() {
                if !warned_missing_dir {
                    tracing::warn!(dir = %marker.sessions_dir.display(), "codex sessions directory not found; retrying");
                    warned_missing_dir = true;
                }
                first_scan = false;
                continue;
            }
            warned_missing_dir = false;
            for path in discover(
                &marker.sessions_dir,
                SystemTime::now(),
                FRESH_WINDOW,
                MAX_FILES,
            ) {
                if tracked.contains_key(&path) {
                    continue;
                }
                let len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                if idle.get(&path) == Some(&len) {
                    continue;
                }
                idle.remove(&path);
                let saved = cursors.get(path.to_string_lossy().as_ref()).cloned();
                if let Some(t) = start_tracking(&path, saved, watching_since, first_scan) {
                    tracked.insert(path, t);
                }
            }
            first_scan = false;
            idle.retain(|p, _| p.exists());
            // A cursor for a file that is gone (rotated, deleted) is dead weight.
            let before = cursors.len();
            cursors.retain(|p, _| Path::new(p).exists());
            if cursors.len() != before {
                save_cursors(&home, &cursors);
            }
        }

        let mut changed = false;
        for (path, t) in tracked.iter_mut() {
            let Ok(read) = read_new_lines(path, Some(&t.cursor), Start::Beginning, MAX_LINE_BYTES)
            else {
                continue;
            };
            // Truncated or replaced: the file restarts at 0, so what the
            // adapter learned about the old one (session id, open calls) is stale.
            let restarted = read.cursor.ino != t.cursor.ino
                || read.cursor.dev != t.cursor.dev
                || read.cursor.offset < t.cursor.offset;
            if restarted {
                t.reset();
            }
            if read.cursor != t.cursor {
                changed = true;
            }
            if !read.lines.is_empty() {
                t.last_activity = Instant::now();
            }
            for line in &read.lines {
                forward_line(&state, t, line).await;
            }
            t.cursor = read.cursor;
            cursors.insert(path.to_string_lossy().into_owned(), t.cursor.clone());
        }
        let dropped: Vec<PathBuf> = tracked
            .iter()
            .filter(|(_, t)| t.last_activity.elapsed() >= IDLE_AFTER)
            .map(|(p, _)| p.clone())
            .collect();
        for p in dropped {
            if let Some(t) = tracked.remove(&p) {
                // Keyed by file length (not cursor offset, which trails a
                // half-written last line) so the re-add check can match.
                let len = std::fs::metadata(&p)
                    .map(|m| m.len())
                    .unwrap_or(t.cursor.offset);
                idle.insert(p, len);
            }
        }
        if changed {
            save_cursors(&home, &cursors);
        }
    }
}

/// Builds the per-file state, positioned at `saved`, or for a file seen for
/// the first time at its start (created since `watching_since`) or its end
/// (history), with adapter state recovered from the prefix.
fn start_tracking(
    path: &Path,
    saved: Option<TailCursor>,
    watching_since: SystemTime,
    first_scan: bool,
) -> Option<Tracked> {
    let len = std::fs::metadata(path).ok()?.len();
    let start = start_for(&saved, path, watching_since, first_scan);
    // Identity/truncation rules applied without consuming anything.
    let mut cursor = resume_cursor(path, saved.as_ref(), start).ok()?;
    let mut adapter = CodexAdapter::new();
    if cursor.offset > 0 {
        let upto = cursor.offset.min(len);
        match read_prefix(path, upto, WARM_REPLAY_CAP) {
            Ok(Some((lines, consumed))) => {
                replay_silently(&mut adapter, &lines);
                // Resume at the last complete line: a half-written one is
                // read once it is finished.
                cursor.offset = consumed;
            }
            Ok(None) => {
                if let Ok(head) = read_new_lines(path, None, Start::Beginning, MAX_LINE_BYTES) {
                    replay_silently(&mut adapter, &head.lines[..head.lines.len().min(1)]);
                }
                // Too large to replay: still resume on a line boundary.
                if saved.is_none() {
                    match last_newline_before(path, upto).ok()? {
                        // No line break in the window (one giant line): stay
                        // at the end and discard the rest of that line,
                        // rather than rewinding to 0 and backfilling.
                        0 => {
                            cursor.offset = upto;
                            cursor.skipping = true;
                        }
                        nl => cursor.offset = nl,
                    }
                }
                tracing::warn!(file = %path.display(), "codex rollout prefix too large to replay; only its session_meta line was");
            }
            Err(_) => return None,
        }
    }
    Some(Tracked {
        adapter,
        cursor,
        session_hint: None,
        caps_sent: false,
        warned_no_session: false,
        last_activity: Instant::now(),
    })
}

/// A file with a saved cursor resumes from it. Otherwise it is new activity
/// only if the file was created after the watcher began (falling back to "not
/// on the first scan" where the platform has no creation time).
fn start_for(
    saved: &Option<TailCursor>,
    path: &Path,
    watching_since: SystemTime,
    first_scan: bool,
) -> Start {
    if saved.is_some() {
        return Start::Beginning;
    }
    let created_after = std::fs::metadata(path)
        .and_then(|m| m.created())
        .map(|c| c >= watching_since)
        .unwrap_or(!first_scan);
    if created_after {
        Start::Beginning
    } else {
        Start::End
    }
}

impl Tracked {
    fn reset(&mut self) {
        self.adapter = CodexAdapter::new();
        self.session_hint = None;
        self.caps_sent = false;
        self.warned_no_session = false;
    }
}

fn replay_silently(adapter: &mut CodexAdapter, lines: &[String]) {
    for l in lines {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(l) {
            let _ = adapter.normalize("", &v);
        }
    }
}

async fn forward_line(state: &AppState, t: &mut Tracked, line: &str) {
    let Ok(entry) = serde_json::from_str::<serde_json::Value>(line) else {
        return;
    };
    let outcome = t.adapter.normalize("", &entry);
    let Some(sid) = t.adapter.known_session_id().map(str::to_string) else {
        if !t.warned_no_session {
            tracing::warn!("codex rollout has no native session id yet; not forwarding until session_meta supplies one");
            t.warned_no_session = true;
        }
        return;
    };
    if !t.caps_sent {
        let caps = stamped_capabilities(&t.adapter, &sid);
        send(state, t, &IngestMessage::Capabilities(caps)).await;
        t.caps_sent = true;
    }
    match outcome {
        NormalizationOutcome::Messages(msgs) => {
            for m in msgs {
                send(state, t, &m).await;
            }
        }
        NormalizationOutcome::Ignored { .. } => {}
        NormalizationOutcome::Unrecognized { discriminator } => {
            tracing::debug!(%discriminator, "unrecognized codex rollout line shape, skipping");
        }
    }
}

async fn send(state: &AppState, t: &mut Tracked, msg: &IngestMessage) {
    if let Ok(line) = serde_json::to_string(msg) {
        crate::process_line(state, &line, &mut t.session_hint).await;
    }
}
