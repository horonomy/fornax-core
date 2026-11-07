//! The opt-in marker for the daemon's Codex rollout capture (FORNX-468), and the
//! one rule for when it is usable. The daemon decides whether to capture with
//! [`read`]; `fornax doctor` calls the same function so a diagnostic can never
//! say "on" for a marker the daemon would ignore.

use std::path::{Path, PathBuf};

pub const MARKER_FILE: &str = "codex-watch.json";

#[derive(Debug, PartialEq, Eq, serde::Deserialize)]
pub struct Marker {
    pub sessions_dir: PathBuf,
}

#[derive(Debug, PartialEq, Eq)]
pub enum MarkerError {
    /// No marker: capture is off.
    Missing,
    /// The file exists but cannot be read.
    Unreadable(String),
    /// Not the expected JSON.
    Invalid(String),
    /// `sessions_dir` is not absolute, so a daemon with another cwd would watch the wrong place.
    RelativeSessionsDir,
}

pub fn read(fornax_home: &Path) -> Result<Marker, MarkerError> {
    let raw = match std::fs::read_to_string(fornax_home.join(MARKER_FILE)) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(MarkerError::Missing),
        Err(e) => return Err(MarkerError::Unreadable(e.to_string())),
    };
    let marker: Marker =
        serde_json::from_str(&raw).map_err(|e| MarkerError::Invalid(e.to_string()))?;
    if marker.sessions_dir.is_absolute() {
        Ok(marker)
    } else {
        Err(MarkerError::RelativeSessionsDir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home(name: &str, body: Option<&str>) -> PathBuf {
        let d = std::env::temp_dir().join(format!("fnx-wm-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        if let Some(b) = body {
            std::fs::write(d.join(MARKER_FILE), b).unwrap();
        }
        d
    }

    #[test]
    fn only_an_absolute_sessions_dir_is_usable() {
        let ok = home("ok", Some(r#"{"sessions_dir":"/x/sessions"}"#));
        assert_eq!(
            read(&ok).unwrap().sessions_dir,
            PathBuf::from("/x/sessions")
        );
        let rel = home("rel", Some(r#"{"sessions_dir":"sessions"}"#));
        assert_eq!(read(&rel), Err(MarkerError::RelativeSessionsDir));
    }

    #[test]
    fn missing_and_invalid_are_distinct() {
        assert_eq!(read(&home("none", None)), Err(MarkerError::Missing));
        assert!(matches!(
            read(&home("bad", Some("{}"))),
            Err(MarkerError::Invalid(_))
        ));
        assert!(matches!(
            read(&home("junk", Some("not json"))),
            Err(MarkerError::Invalid(_))
        ));
    }
}
