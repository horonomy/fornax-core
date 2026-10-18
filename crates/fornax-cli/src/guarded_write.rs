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

/// The replacement keeps the existing file's permission bits, and is
/// owner-only when the file is new -- the file may hold credentials.
#[cfg(unix)]
fn target_mode(path: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o7777)
        .unwrap_or(0o600)
}

/// Replaces `path` with `contents` only if `path` still has the content
/// `expected` was taken from. A mismatch means someone else changed the file
/// since it was read; this refuses with no mutation at all instead of
/// overwriting their edit. (A change landing between this check and the
/// rename is not detectable without a lock; the window is a few syscalls.)
///
/// The replacement is staged in a uniquely named sibling opened with
/// `create_new`, so a planted file or symlink at any predictable name is
/// never a write target.
pub fn write_guarded(
    path: &std::path::Path,
    contents: &str,
    expected: &ContentDigest,
) -> anyhow::Result<()> {
    use std::io::Write;

    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{} has no parent directory", path.display()))?;
    std::fs::create_dir_all(parent)?;
    anyhow::ensure!(
        digest_of(path)? == *expected,
        "{} changed since it was read -- refusing to overwrite it; re-run to retry",
        path.display()
    );

    let tmp_path = parent.join(format!(".fornax-tmp-{}", uuid::Uuid::new_v4()));
    let staged = (|| -> anyhow::Result<()> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(target_mode(path));
        }
        let mut file = options.open(&tmp_path)?;
        // Re-assert on the open handle: `mode` above is masked by the umask,
        // and this must hold before any content is written.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(target_mode(path)))?;
        }
        file.write_all(contents.as_bytes())?;
        std::fs::rename(&tmp_path, path)?;
        Ok(())
    })();
    if staged.is_err() {
        std::fs::remove_file(&tmp_path).ok();
    }
    staged
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

    #[test]
    fn write_refuses_and_leaves_the_file_untouched_when_it_changed_since_read() {
        let path = tmp_path("stale");
        std::fs::write(&path, "original").unwrap();
        let read_earlier = digest_of(&path).unwrap();
        std::fs::write(&path, "edited by the user meanwhile").unwrap();
        let err = write_guarded(&path, "ours", &read_earlier).expect_err("must refuse");
        assert!(
            err.to_string().contains("changed since it was read"),
            "{err}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "edited by the user meanwhile"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn write_replaces_an_unchanged_file_and_leaves_no_staging_file() {
        let dir = tmp_path("dir");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("settings.json");
        std::fs::write(&path, "original").unwrap();
        let read = digest_of(&path).unwrap();
        write_guarded(&path, "ours", &read).expect("write");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "ours");
        let names: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("settings.json")]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn write_preserves_an_owner_only_mode_and_creates_new_files_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let mode_of =
            |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;

        let existing = tmp_path("mode-existing");
        std::fs::write(&existing, "x").unwrap();
        std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o600)).unwrap();
        write_guarded(&existing, "y", &digest_of(&existing).unwrap()).unwrap();
        assert_eq!(mode_of(&existing), 0o600);

        let fresh = tmp_path("mode-new");
        write_guarded(&fresh, "y", &digest_of(&fresh).unwrap()).unwrap();
        assert_eq!(mode_of(&fresh), 0o600);

        std::fs::remove_file(&existing).ok();
        std::fs::remove_file(&fresh).ok();
    }
}
