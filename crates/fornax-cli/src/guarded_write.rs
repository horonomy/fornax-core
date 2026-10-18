//! Guarded replacement of a user-owned config file (FORNX-420).
//!
//! The target (e.g. `~/.claude/settings.json`) also holds state Fornax does
//! not own, so a writer must refuse rather than clobber: it checks the file
//! is unchanged since it was read, never writes through a planted path,
//! keeps the file's permissions, and makes the replacement durable.

use sha2::{Digest, Sha256};

/// What a file's bytes were when they were read; `None` means it did not
/// exist. Compared again immediately before a write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentDigest(Option<[u8; 32]>);

/// Digest of `path`'s current bytes, or the "absent" digest if it does not
/// exist. Any other read error is returned, never treated as "absent".
pub fn digest_of(path: &std::path::Path) -> std::io::Result<ContentDigest> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(ContentDigest(Some(Sha256::digest(&bytes).into()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ContentDigest(None)),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("fornax-guarded-{name}-{}", uuid::Uuid::new_v4()))
    }

    #[test]
    fn digest_distinguishes_absent_unchanged_and_changed_content() {
        let path = tmp_path("digest");
        let absent = digest_of(&path).expect("absent");
        std::fs::write(&path, "a").unwrap();
        let first = digest_of(&path).expect("first");
        assert_ne!(absent, first);
        assert_eq!(first, digest_of(&path).expect("again"));
        std::fs::write(&path, "b").unwrap();
        assert_ne!(first, digest_of(&path).expect("changed"));
        std::fs::remove_file(&path).ok();
    }
}
