//! Bounded, restart-safe reader for Codex rollout JSONL files (FORNX-468).
//!
//! Replaces the original tailer loop, which re-read the whole file every tick,
//! advanced its offset past a half-written last line (so a `task_complete`
//! written in two chunks was lost for good), stalled forever if the file
//! shrank, and treated a single invalid-UTF-8 byte as an empty file.
//!
//! IO only: no daemon, store or adapter types, so both the standalone tailer
//! and the daemon's watcher share one reader.

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Where to resume in one rollout file. `dev`/`ino` detect a replaced file; a
/// file shorter than `offset` is treated as truncated. Both restart at 0.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct TailCursor {
    pub dev: u64,
    pub ino: u64,
    pub offset: u64,
    /// Inside a line that exceeded the cap: drop bytes up to the next newline.
    #[serde(default)]
    pub skipping: bool,
}

/// Result of one read: complete, valid-UTF-8, non-empty lines in order, and
/// the cursor to persist once they have been handled.
#[derive(Debug, Default)]
pub struct TailRead {
    pub lines: Vec<String>,
    pub cursor: TailCursor,
    /// Lines dropped for being oversized or not valid UTF-8.
    pub skipped: usize,
}

/// Reads at most `max_line` bytes per call (one line may therefore be at most
/// `max_line - 1` bytes plus its newline; a longer one is skipped, not
/// buffered). A trailing line with no newline yet is left unconsumed.
///
/// `start` is where to begin when there is no usable `cursor`.
pub fn read_new_lines(
    path: &Path,
    cursor: Option<&TailCursor>,
    start: Start,
    max_line: u64,
) -> std::io::Result<TailRead> {
    let mut file = std::fs::File::open(path)?;
    let meta = file.metadata()?;
    let (dev, ino) = identity(&meta);
    let len = meta.len();

    let mut cur = resolve(cursor, start, dev, ino, len);

    let mut out = TailRead {
        cursor: cur.clone(),
        ..Default::default()
    };
    if cur.offset >= len {
        return Ok(out);
    }

    file.seek(SeekFrom::Start(cur.offset))?;
    let window = (len - cur.offset).min(max_line);
    let mut buf = Vec::with_capacity(window as usize);
    file.take(window).read_to_end(&mut buf)?;

    let mut pos = 0usize;
    if cur.skipping {
        match buf.iter().position(|b| *b == b'\n') {
            Some(i) => {
                pos = i + 1;
                cur.skipping = false;
            }
            None => {
                cur.offset += buf.len() as u64;
                out.cursor = cur;
                return Ok(out);
            }
        }
    }

    while let Some(rel) = buf[pos..].iter().position(|b| *b == b'\n') {
        let raw = &buf[pos..pos + rel];
        pos += rel + 1;
        match std::str::from_utf8(raw) {
            Ok(s) if s.trim().is_empty() => {}
            Ok(s) => out.lines.push(s.to_string()),
            Err(_) => out.skipped += 1,
        }
    }

    if pos == 0 && buf.len() as u64 >= max_line {
        // A full window with no newline: this line can never fit.
        out.skipped += 1;
        cur.skipping = true;
        cur.offset += buf.len() as u64;
    } else {
        cur.offset += pos as u64;
    }
    out.cursor = cur;
    Ok(out)
}

/// Complete lines of `path[..upto]`, and the offset just after the last
/// newline among them (a half-written trailing line is not consumed). `None`
/// when the prefix is larger than `cap`: the caller replays less instead of
/// buffering an unbounded history.
pub fn read_prefix(
    path: &Path,
    upto: u64,
    cap: u64,
) -> std::io::Result<Option<(Vec<String>, u64)>> {
    if upto > cap {
        return Ok(None);
    }
    let mut buf = Vec::with_capacity(upto as usize);
    std::fs::File::open(path)?
        .take(upto)
        .read_to_end(&mut buf)?;
    let end = buf.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
    let lines = buf[..end]
        .split(|b| *b == b'\n')
        .filter_map(|l| std::str::from_utf8(l).ok())
        .filter(|l| !l.trim().is_empty())
        .map(str::to_string)
        .collect();
    Ok(Some((lines, end as u64)))
}

/// Applies the identity/truncation rules: a usable `cursor` is kept; anything
/// else (first sight, replaced file, shrunk file) starts per `start`, except
/// that a file known to have changed identity restarts at 0.
fn resolve(cursor: Option<&TailCursor>, start: Start, dev: u64, ino: u64, len: u64) -> TailCursor {
    match cursor {
        Some(c) if c.dev == dev && c.ino == ino && c.offset <= len => c.clone(),
        Some(_) => TailCursor {
            dev,
            ino,
            ..Default::default()
        },
        None => TailCursor {
            dev,
            ino,
            offset: match start {
                Start::Beginning => 0,
                Start::End => len,
            },
            skipping: false,
        },
    }
}

/// Where reading would resume for `path`, without consuming anything.
pub fn resume_cursor(
    path: &Path,
    cursor: Option<&TailCursor>,
    start: Start,
) -> std::io::Result<TailCursor> {
    let meta = std::fs::metadata(path)?;
    let (dev, ino) = identity(&meta);
    Ok(resolve(cursor, start, dev, ino, meta.len()))
}

/// Where a never-seen file starts when no cursor exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Start {
    Beginning,
    End,
}

#[cfg(unix)]
fn identity(meta: &std::fs::Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    (meta.dev(), meta.ino())
}

#[cfg(not(unix))]
fn identity(_meta: &std::fs::Metadata) -> (u64, u64) {
    (0, 0)
}

/// `rollout-*.jsonl` files under `sessions_dir` modified within `window`,
/// most recent first, at most `max_files`. Depth is bounded because Codex
/// nests them as `YYYY/MM/DD/`.
pub fn discover(
    sessions_dir: &Path,
    now: SystemTime,
    window: Duration,
    max_files: usize,
) -> Vec<PathBuf> {
    const MAX_DEPTH: usize = 6;
    let mut found: Vec<(SystemTime, PathBuf)> = Vec::new();
    let mut stack = vec![(sessions_dir.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in rd.flatten() {
            let path = entry.path();
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_dir() {
                if depth < MAX_DEPTH {
                    stack.push((path, depth + 1));
                }
                continue;
            }
            let is_rollout = ft.is_file()
                && path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("rollout-") && n.ends_with(".jsonl"));
            if !is_rollout {
                continue;
            }
            let Ok(modified) = entry.metadata().and_then(|m| m.modified()) else {
                continue;
            };
            let fresh = now
                .duration_since(modified)
                .map(|age| age <= window)
                .unwrap_or(true);
            if fresh {
                found.push((modified, path));
            }
        }
    }
    found.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    found.truncate(max_files);
    found.into_iter().map(|(_, p)| p).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    struct Dir(PathBuf);
    impl Dir {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "fornax-rollout-tail-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&p).unwrap();
            Dir(p)
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn append(path: &Path, bytes: &[u8]) {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        f.write_all(bytes).unwrap();
    }

    const CAP: u64 = 1 << 20;

    #[test]
    fn partial_trailing_line_not_consumed_until_newline() {
        let d = Dir::new("partial");
        let f = d.0.join("rollout-a.jsonl");
        append(&f, b"{\"a\":1}\n{\"type\":\"task_comp");
        let r1 = read_new_lines(&f, None, Start::Beginning, CAP).unwrap();
        assert_eq!(r1.lines, vec!["{\"a\":1}"]);
        append(&f, b"lete\"}\n");
        let r2 = read_new_lines(&f, Some(&r1.cursor), Start::Beginning, CAP).unwrap();
        assert_eq!(r2.lines, vec!["{\"type\":\"task_complete\"}"]);
        let r3 = read_new_lines(&f, Some(&r2.cursor), Start::Beginning, CAP).unwrap();
        assert!(r3.lines.is_empty());
    }

    #[test]
    fn first_sight_at_end_skips_existing_history() {
        let d = Dir::new("end");
        let f = d.0.join("rollout-a.jsonl");
        append(&f, b"{\"old\":1}\n");
        let r1 = read_new_lines(&f, None, Start::End, CAP).unwrap();
        assert!(r1.lines.is_empty());
        append(&f, b"{\"new\":1}\n");
        let r2 = read_new_lines(&f, Some(&r1.cursor), Start::End, CAP).unwrap();
        assert_eq!(r2.lines, vec!["{\"new\":1}"]);
    }

    #[test]
    fn read_prefix_returns_complete_lines_and_their_end_offset() {
        let d = Dir::new("prefix");
        let f = d.0.join("rollout-a.jsonl");
        append(&f, b"{\"a\":1}\n{\"b\":2}\n{\"c\":");
        let len = std::fs::metadata(&f).unwrap().len();
        let (lines, end) = read_prefix(&f, len, CAP).unwrap().unwrap();
        assert_eq!(lines, vec!["{\"a\":1}", "{\"b\":2}"]);
        assert_eq!(end, 16);
        assert!(read_prefix(&f, len, 4).unwrap().is_none());
    }

    #[test]
    fn truncated_file_restarts_from_zero() {
        let d = Dir::new("trunc");
        let f = d.0.join("rollout-a.jsonl");
        append(&f, b"{\"a\":1}\n{\"b\":2}\n");
        let r1 = read_new_lines(&f, None, Start::Beginning, CAP).unwrap();
        assert_eq!(r1.lines.len(), 2);
        std::fs::write(&f, b"{\"c\":3}\n").unwrap();
        let r2 = read_new_lines(&f, Some(&r1.cursor), Start::Beginning, CAP).unwrap();
        assert_eq!(r2.lines, vec!["{\"c\":3}"]);
    }

    #[cfg(unix)]
    #[test]
    fn replaced_inode_restarts_from_zero() {
        let d = Dir::new("inode");
        let f = d.0.join("rollout-a.jsonl");
        append(&f, b"{\"a\":1}\n");
        let r1 = read_new_lines(&f, None, Start::Beginning, CAP).unwrap();
        // Replace with a different, equal-length file: same size, new inode.
        let tmp = d.0.join("swap");
        std::fs::write(&tmp, b"{\"z\":9}\n").unwrap();
        std::fs::rename(&tmp, &f).unwrap();
        let r2 = read_new_lines(&f, Some(&r1.cursor), Start::Beginning, CAP).unwrap();
        assert_eq!(r2.lines, vec!["{\"z\":9}"]);
    }

    #[test]
    fn invalid_utf8_line_skipped_not_whole_file() {
        let d = Dir::new("utf8");
        let f = d.0.join("rollout-a.jsonl");
        append(&f, b"{\"a\":1}\n\xff\xfe\n{\"b\":2}\n");
        let r = read_new_lines(&f, None, Start::Beginning, CAP).unwrap();
        assert_eq!(r.lines, vec!["{\"a\":1}", "{\"b\":2}"]);
        assert_eq!(r.skipped, 1);
    }

    #[test]
    fn oversized_line_skipped_bounded_memory() {
        let d = Dir::new("big");
        let f = d.0.join("rollout-a.jsonl");
        let mut big = vec![b'x'; 300];
        big.push(b'\n');
        append(&f, b"{\"a\":1}\n");
        append(&f, &big);
        append(&f, b"{\"b\":2}\n");
        let mut cursor: Option<TailCursor> = None;
        let mut lines = Vec::new();
        let mut skipped = 0;
        for _ in 0..40 {
            let r = read_new_lines(&f, cursor.as_ref(), Start::Beginning, 64).unwrap();
            lines.extend(r.lines);
            skipped += r.skipped;
            cursor = Some(r.cursor);
        }
        assert_eq!(lines, vec!["{\"a\":1}", "{\"b\":2}"]);
        assert!(skipped >= 1);
    }

    #[test]
    fn discover_only_rollout_jsonl_within_window() {
        let d = Dir::new("disc");
        let day = d.0.join("2026/10/25");
        std::fs::create_dir_all(&day).unwrap();
        append(&day.join("rollout-1.jsonl"), b"{}\n");
        append(&day.join("notes.jsonl"), b"{}\n");
        append(&day.join("rollout-2.txt"), b"x");
        let now = SystemTime::now();
        let got = discover(&d.0, now, Duration::from_secs(60), 10);
        assert_eq!(got, vec![day.join("rollout-1.jsonl")]);
        let later = now + Duration::from_secs(3600);
        assert!(discover(&d.0, later, Duration::from_secs(60), 10).is_empty());
    }

    #[test]
    fn discover_caps_max_files_most_recent_first() {
        let d = Dir::new("cap");
        for i in 0..3 {
            let p = d.0.join(format!("rollout-{i}.jsonl"));
            append(&p, b"{}\n");
            let t = SystemTime::now() - Duration::from_secs(100 - i * 10);
            std::fs::File::options()
                .write(true)
                .open(&p)
                .unwrap()
                .set_modified(t)
                .unwrap();
        }
        let got = discover(&d.0, SystemTime::now(), Duration::from_secs(3600), 2);
        assert_eq!(
            got,
            vec![d.0.join("rollout-2.jsonl"), d.0.join("rollout-1.jsonl")]
        );
    }

    #[test]
    fn warm_replay_restores_session_id_without_emitting() {
        use crate::CodexAdapter;
        use fornax_types::AgentAdapter;
        let d = Dir::new("warm");
        let f = d.0.join("rollout-a.jsonl");
        append(
            &f,
            b"{\"type\":\"session_meta\",\"payload\":{\"session_id\":\"11111111-2222-3333-4444-555555555555\",\"cli_version\":\"0.163.0\"}}\n",
        );
        let r = read_new_lines(&f, None, Start::Beginning, CAP).unwrap();
        let mut adapter = CodexAdapter::new();
        assert!(adapter.known_session_id().is_none());
        for l in &r.lines {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            let _ = adapter.normalize("", &v); // output discarded
        }
        assert_eq!(
            adapter.known_session_id(),
            Some("11111111-2222-3333-4444-555555555555")
        );
    }
}
