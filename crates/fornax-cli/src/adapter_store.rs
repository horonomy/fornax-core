//! External adapter registry index persistence and registration ceremony
//! (ADR-0023 D4/D5/D8, FORNX-428 S6).
//!
//! `$FORNAX_HOME/adapters/registry.json` is the single Fornax-owned index.
//! A manifest file merely present in the adapters directory is never read
//! on its own -- only entries listed in `registry.json` load, and the only
//! way to add one is [`register`].

use crate::adapter_manifest::{digest_of, parse_manifest_bytes, AdapterManifest};
use std::io::Read;
use std::path::{Path, PathBuf};

pub const REGISTRY_INDEX_FILE: &str = "registry.json";
/// `registry.json` size ceiling (ADR-0023 D7).
pub const MAX_INDEX_BYTES: usize = 1024 * 1024;
/// Entry count ceiling.
pub const MAX_ENTRIES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryEntry {
    pub id: String,
    pub manifest_file: String,
    pub digest: String,
    pub source_path: String,
    pub registered_at: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryIndex {
    #[serde(default = "default_index_schema_version")]
    pub schema_version: u32,
    #[serde(default)]
    pub entries: Vec<RegistryEntry>,
}

fn default_index_schema_version() -> u32 {
    1
}

/// Why a registry entry (or an attempted registration) did not load/apply.
/// Rejections are always named and surfaced -- never a silent skip
/// (ADR-0023 D8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection {
    pub id: String,
    pub reason: String,
}

/// A passive, fresh view of one external registration. This is display
/// data; it never grants dispatch or host-operation authority.
pub struct RegistrationInspection {
    pub entry: RegistryEntry,
    pub manifest: Option<AdapterManifest>,
    pub registry_schema_version: u32,
    pub load_state: &'static str,
    pub reason: Option<&'static str>,
}

fn rejected_registration(
    entry: RegistryEntry,
    registry_schema_version: u32,
    reason: &'static str,
) -> RegistrationInspection {
    RegistrationInspection {
        entry,
        manifest: None,
        registry_schema_version,
        load_state: "rejected",
        reason: Some(reason),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{reason}")]
pub struct InspectionFailure {
    pub reason: &'static str,
}

fn inspection_failure(reason: &'static str) -> InspectionFailure {
    InspectionFailure { reason }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct InspectionIndex {
    schema_version: u32,
    entries: Vec<RegistryEntry>,
}

// Hold the selected directory throughout inspection, so renaming or
// replacing its path cannot redirect the index or manifest reads.
struct InspectionDirectory {
    #[cfg(unix)]
    directory: std::fs::File,
}

#[cfg(unix)]
fn open_relative(
    directory: &std::fs::File,
    name: &str,
    flags: rustix::fs::OFlags,
) -> std::io::Result<std::fs::File> {
    rustix::fs::openat(directory, name, flags, rustix::fs::Mode::empty())
        .map(std::fs::File::from)
        .map_err(|error| {
            if error == rustix::io::Errno::LOOP {
                std::io::Error::from(std::io::ErrorKind::InvalidInput)
            } else {
                error.into()
            }
        })
}

impl InspectionDirectory {
    #[cfg(unix)]
    fn open(home: &Path) -> std::io::Result<Self> {
        use rustix::fs::{Mode, OFlags};
        // FORNAX_HOME is the caller-selected root, which may intentionally
        // be an alias. Its adapters child and both leaf files cannot be.
        let root = std::fs::File::from(rustix::fs::open(
            home,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let directory = open_relative(
            &root,
            "adapters",
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CLOEXEC,
        )?;
        Ok(Self { directory })
    }

    #[cfg(not(unix))]
    fn open(_home: &Path) -> std::io::Result<Self> {
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }

    #[cfg(unix)]
    fn read_bounded(&self, name: &str, max_bytes: usize) -> std::io::Result<Vec<u8>> {
        use std::os::unix::fs::MetadataExt;
        let file = open_relative(
            &self.directory,
            name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CLOEXEC,
        )?;
        let before = file.metadata()?;
        if !before.is_file() {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
        }
        let mut bytes = Vec::new();
        (&file).take(max_bytes as u64 + 1).read_to_end(&mut bytes)?;
        let after = file.metadata()?;
        if before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
        {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
        }
        Ok(bytes)
    }

    #[cfg(not(unix))]
    fn read_bounded(&self, _name: &str, _max_bytes: usize) -> std::io::Result<Vec<u8>> {
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }
}

/// Reads the existing index afresh and validates exactly one selected
/// owned copy. It never follows `source_path` or opens the declared target.
pub fn inspect_registration(
    fornax_home: &Path,
    id: &str,
) -> Result<RegistrationInspection, InspectionFailure> {
    if id.len() > 64 {
        return Err(inspection_failure("unknown_adapter_id"));
    }
    let directory = match InspectionDirectory::open(fornax_home) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(inspection_failure("unknown_adapter_id"));
        }
        Err(error) if error.kind() == std::io::ErrorKind::Unsupported => {
            return Err(inspection_failure("inspection_platform_unsupported"));
        }
        Err(_) => return Err(inspection_failure("registry_index_unreadable")),
    };
    let index_bytes = match directory.read_bounded(REGISTRY_INDEX_FILE, MAX_INDEX_BYTES) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(inspection_failure("unknown_adapter_id"));
        }
        Err(_) => return Err(inspection_failure("registry_index_unreadable")),
    };
    if index_bytes.len() > MAX_INDEX_BYTES {
        return Err(inspection_failure("registry_index_oversized"));
    }
    let index: InspectionIndex = serde_json::from_slice(&index_bytes)
        .map_err(|_| inspection_failure("registry_index_malformed"))?;
    if !matches!(index.schema_version, 0 | 1) {
        return Err(inspection_failure("registry_index_unsupported_version"));
    }
    let registry_schema_version = index.schema_version;
    if index.entries.len() > MAX_ENTRIES {
        return Err(inspection_failure("registry_index_too_many_entries"));
    }

    let mut selected = index.entries.iter().filter(|entry| entry.id == id);
    let Some(entry) = selected.next() else {
        return Err(inspection_failure("unknown_adapter_id"));
    };
    if selected.next().is_some() {
        return Err(inspection_failure("duplicate_registration_id"));
    }
    let entry = entry.clone();
    if crate::adapter_manifest::validate_id(&entry.id).is_err() {
        return Ok(rejected_registration(
            entry,
            registry_schema_version,
            "invalid_registration_id",
        ));
    }
    let expected_file = format!("{}.manifest.json", entry.id);
    if entry.manifest_file != expected_file {
        return Ok(rejected_registration(
            entry,
            registry_schema_version,
            "invalid_owned_filename",
        ));
    }

    let bytes =
        match directory.read_bounded(&expected_file, crate::adapter_manifest::MAX_MANIFEST_BYTES) {
            Ok(bytes) => bytes,
            Err(error) => {
                let reason = match error.kind() {
                    std::io::ErrorKind::InvalidInput => "invalid_owned_file_type",
                    std::io::ErrorKind::InvalidData => "owned_manifest_changed",
                    _ => "owned_manifest_unavailable",
                };
                return Ok(rejected_registration(
                    entry,
                    registry_schema_version,
                    reason,
                ));
            }
        };
    if bytes.len() > crate::adapter_manifest::MAX_MANIFEST_BYTES {
        return Ok(rejected_registration(
            entry,
            registry_schema_version,
            "owned_manifest_oversized",
        ));
    }
    if digest_of(&bytes) != entry.digest {
        return Ok(rejected_registration(
            entry,
            registry_schema_version,
            "digest_mismatch",
        ));
    }
    let manifest = match parse_manifest_bytes(&bytes, &crate::dirs_home()) {
        Ok(manifest) => manifest,
        Err(error) => {
            let reason = if error
                .downcast_ref::<crate::adapter_manifest::ManifestError>()
                .is_some_and(|e| {
                    matches!(
                        e,
                        crate::adapter_manifest::ManifestError::UnsupportedSchemaVersion { .. }
                    )
                }) {
                "unsupported_manifest_version"
            } else {
                "malformed_manifest"
            };
            return Ok(rejected_registration(
                entry,
                registry_schema_version,
                reason,
            ));
        }
    };
    if manifest.id != entry.id {
        return Ok(rejected_registration(
            entry,
            registry_schema_version,
            "manifest_id_mismatch",
        ));
    }

    Ok(RegistrationInspection {
        registry_schema_version,
        load_state: if entry.enabled {
            "enabled_valid"
        } else {
            "disabled"
        },
        entry,
        manifest: Some(manifest),
        reason: None,
    })
}

fn adapters_dir(fornax_home: &Path) -> PathBuf {
    fornax_home.join("adapters")
}

/// FORNX-428 S6 (ticket text, "Refuse manifests from world-writable
/// paths"): refuses to register a manifest whose source file, or whose
/// containing directory, is writable by users other than its owner. A
/// manifest the registering user doesn't exclusively control could be
/// swapped out by another local account between review and confirm even
/// with the digest pin in place (the pin only proves the bytes didn't
/// change across the two invocations, not that nobody else could have
/// written them in the first place) -- checked before the source is ever
/// read. Unix-only; a no-op on platforms with no POSIX permission bits.
fn refuse_if_world_writable(source: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let is_group_or_world_writable = |p: &Path| -> anyhow::Result<bool> {
            let mode = std::fs::symlink_metadata(p)
                .map_err(|e| anyhow::anyhow!("failed to stat {}: {e}", p.display()))?
                .permissions()
                .mode();
            Ok(mode & 0o022 != 0)
        };

        if is_group_or_world_writable(source)? {
            anyhow::bail!(
                "refusing to register {}: it is group- or world-writable",
                source.display()
            );
        }
        let parent = source
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        if is_group_or_world_writable(parent)? {
            anyhow::bail!(
                "refusing to register {}: its containing directory {} is group- or \
                 world-writable",
                source.display(),
                parent.display()
            );
        }
    }
    Ok(())
}

fn index_path(fornax_home: &Path) -> PathBuf {
    adapters_dir(fornax_home).join(REGISTRY_INDEX_FILE)
}

/// Reads and parses `registry.json`. A missing directory/file is "no
/// external adapters registered yet" -- `Ok(RegistryIndex::default())`,
/// never an error, and this function never creates anything.
fn load_index(fornax_home: &Path) -> anyhow::Result<RegistryIndex> {
    let path = index_path(fornax_home);
    if !path.exists() {
        return Ok(RegistryIndex::default());
    }
    let bytes = std::fs::read(&path)?;
    if bytes.len() > MAX_INDEX_BYTES {
        anyhow::bail!(
            "{} exceeds the {MAX_INDEX_BYTES}-byte size limit ({} bytes)",
            path.display(),
            bytes.len()
        );
    }
    let index: RegistryIndex = serde_json::from_slice(&bytes)?;
    Ok(index)
}

/// Atomically overwrites `registry.json` (write-to-temp then rename),
/// creating `$FORNAX_HOME/adapters/` (mode 0700 on unix) if it does not
/// already exist. Only called by [`register`]/[`set_enabled`]/[`remove`] --
/// never by a read path.
fn save_index(fornax_home: &Path, index: &RegistryIndex) -> anyhow::Result<()> {
    let dir = adapters_dir(fornax_home);
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let path = index_path(fornax_home);
    let mut json = serde_json::to_string_pretty(index)?;
    json.push('\n');
    let tmp_path = dir.join("registry.json.fornax-tmp");
    std::fs::write(&tmp_path, &json)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp_path, &path)?;
    Ok(())
}

/// Result of a registration attempt that completed review but was not
/// (yet) confirmed, or was confirmed and registered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterOutcome {
    /// Review step: manifest parsed and validated; this is the digest the
    /// caller must pass back as `--confirm-digest` to actually register.
    Reviewed {
        manifest: Box<AdapterManifest>,
        digest: String,
    },
    /// Confirm step succeeded: the adapter is now in `registry.json`.
    Registered { id: String },
}

/// `fornax adapter register --manifest <path> [--confirm-digest <d>]`
/// (ADR-0023 D5). Reads `source`'s bytes exactly once; digest, parse, and
/// (on confirm) the owned copy are all derived from that one buffer.
pub fn register(
    fornax_home: &Path,
    source: &Path,
    confirm_digest: Option<&str>,
) -> anyhow::Result<RegisterOutcome> {
    refuse_if_world_writable(source)?;
    let bytes = std::fs::read(source)
        .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", source.display()))?;
    let digest = digest_of(&bytes);
    let manifest = parse_manifest_bytes(&bytes, &crate::dirs_home())?;

    let Some(confirm) = confirm_digest else {
        return Ok(RegisterOutcome::Reviewed {
            manifest: Box::new(manifest),
            digest,
        });
    };
    if confirm != digest {
        anyhow::bail!(
            "manifest changed since review (reviewed {confirm}, now {digest}) -- nothing registered"
        );
    }

    let mut index = load_index(fornax_home)?;
    if index.entries.iter().any(|e| e.id == manifest.id) {
        anyhow::bail!("an adapter with id {:?} is already registered", manifest.id);
    }
    if crate::adapter_registry::built_in_ids().any(|id| id == manifest.id) {
        anyhow::bail!(
            "id {:?} collides with a built-in adapter -- choose a different id",
            manifest.id
        );
    }
    if index.entries.len() >= MAX_ENTRIES {
        anyhow::bail!("registry already holds the maximum of {MAX_ENTRIES} entries");
    }

    let dir = adapters_dir(fornax_home);
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let manifest_file = format!("{}.manifest.json", manifest.id);
    let owned_path = dir.join(&manifest_file);
    std::fs::write(&owned_path, &bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&owned_path, std::fs::Permissions::from_mode(0o600))?;
    }

    index.entries.push(RegistryEntry {
        id: manifest.id.clone(),
        manifest_file,
        digest,
        source_path: source.display().to_string(),
        registered_at: chrono::Utc::now().to_rfc3339(),
        enabled: true,
    });
    save_index(fornax_home, &index)?;

    Ok(RegisterOutcome::Registered { id: manifest.id })
}

pub fn set_enabled(fornax_home: &Path, id: &str, enabled: bool) -> anyhow::Result<()> {
    let mut index = load_index(fornax_home)?;
    let entry = index
        .entries
        .iter_mut()
        .find(|e| e.id == id)
        .ok_or_else(|| anyhow::anyhow!("no registered adapter with id {id:?}"))?;
    entry.enabled = enabled;
    save_index(fornax_home, &index)
}

pub fn remove(fornax_home: &Path, id: &str) -> anyhow::Result<()> {
    let mut index = load_index(fornax_home)?;
    let pos = index
        .entries
        .iter()
        .position(|e| e.id == id)
        .ok_or_else(|| anyhow::anyhow!("no registered adapter with id {id:?}"))?;
    let entry = index.entries.remove(pos);
    save_index(fornax_home, &index)?;
    let owned_path = adapters_dir(fornax_home).join(&entry.manifest_file);
    std::fs::remove_file(&owned_path).ok();
    Ok(())
}

/// Loads every enabled external adapter from `$FORNAX_HOME/adapters/`,
/// re-verifying each owned manifest copy's digest against its pin
/// (ADR-0023 D5 load-time verification) and rejecting (never silently
/// skipping) anything malformed, digest-mismatched, missing, or
/// id-colliding with a built-in (ADR-0023 D8). Never creates the
/// directory; a missing directory is simply zero entries.
pub fn load_external(
    fornax_home: &Path,
) -> (
    Vec<crate::adapter_external::ExternalAdapter>,
    Vec<Rejection>,
) {
    let mut loaded = Vec::new();
    let mut rejections = Vec::new();

    let index = match load_index(fornax_home) {
        Ok(idx) => idx,
        Err(e) => {
            rejections.push(Rejection {
                id: "<registry.json>".to_string(),
                reason: format!("malformed registry index: {e}"),
            });
            return (loaded, rejections);
        }
    };

    // Must use `built_in_ids()`, never `registry()`/`resolve()` -- this
    // function runs inside `registry()`'s own lazy-init closure (see
    // `adapter_registry::loaded`), and calling back into `registry()` from
    // here would reenter its `OnceLock` mid-initialization, which deadlocks.
    let builtin_ids: std::collections::HashSet<&str> =
        crate::adapter_registry::built_in_ids().collect();

    for entry in index.entries {
        if !entry.enabled {
            continue;
        }
        if builtin_ids.contains(entry.id.as_str()) {
            rejections.push(Rejection {
                id: entry.id,
                reason: "id collides with built-in adapter".to_string(),
            });
            continue;
        }
        let owned_path = adapters_dir(fornax_home).join(&entry.manifest_file);
        let bytes = match std::fs::read(&owned_path) {
            Ok(b) => b,
            Err(_) => {
                rejections.push(Rejection {
                    id: entry.id,
                    reason: "unavailable -- owned manifest copy is missing or unreadable"
                        .to_string(),
                });
                continue;
            }
        };
        let actual_digest = digest_of(&bytes);
        if actual_digest != entry.digest {
            rejections.push(Rejection {
                id: entry.id,
                reason: "digest mismatch".to_string(),
            });
            continue;
        }
        match parse_manifest_bytes(&bytes, &crate::dirs_home()) {
            Ok(manifest) if manifest.id == entry.id => {
                loaded.push(crate::adapter_external::ExternalAdapter::new(manifest));
            }
            Ok(manifest) => {
                rejections.push(Rejection {
                    id: entry.id,
                    reason: format!(
                        "registry entry id does not match manifest id {:?}",
                        manifest.id
                    ),
                });
            }
            Err(e) => {
                rejections.push(Rejection {
                    id: entry.id,
                    reason: format!("malformed manifest: {e}"),
                });
            }
        }
    }

    (loaded, rejections)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter_registry::AdapterPlugin;

    /// A fresh, uniquely-named scratch directory under the OS temp dir --
    /// avoids a `tempfile` dependency by following this repo's own e2e-test
    /// convention (`std::env::temp_dir()` + `uuid::Uuid::new_v4()`).
    /// Intentionally not auto-cleaned on drop: left behind on panic, same
    /// as the existing e2e tests' `.ok()`-swallowed `remove_dir_all`.
    fn scratch_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fornax-adapter-store-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_manifest(dir: &Path, id: &str) -> PathBuf {
        let path = dir.join(format!("{id}.src.json"));
        let body = serde_json::json!({
            "schema_version": 1,
            "id": id,
            "display_name": "Fixture",
            "summary": "fixture adapter for tests",
            "min_fornax_version": "0.0.1",
            "provenance": "https://example.com/fixture",
            "capabilities": ["plan", "install", "uninstall"],
            "target": { "format": "json", "path": format!("~/.{id}/settings.json") },
            "operations": [{
                "kind": "ensure_marked_array_element",
                "pointer": "/hooks/PostToolUse",
                "marker_key": "command",
                "marker_value": format!("fornax-hook-{id}"),
                "element": { "type": "command", "command": format!("fornax-hook-{id}") }
            }]
        });
        std::fs::write(&path, serde_json::to_vec_pretty(&body).unwrap()).unwrap();
        path
    }

    #[cfg(unix)]
    #[test]
    fn register_refuses_a_world_writable_manifest_source() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = scratch_dir();
        let fornax_home = tmp.join("fornax-home");
        let src = write_manifest(&tmp, "fixture-ww");
        std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o666)).unwrap();

        let err = register(&fornax_home, &src, None).unwrap_err();
        assert!(err.to_string().contains("world-writable"));
        assert!(!adapters_dir(&fornax_home).exists());
    }

    #[cfg(unix)]
    #[test]
    fn register_refuses_a_manifest_in_a_world_writable_directory() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = scratch_dir();
        let fornax_home = tmp.join("fornax-home");
        let src = write_manifest(&tmp, "fixture-wwd");
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o777)).unwrap();

        let err = register(&fornax_home, &src, None).unwrap_err();
        assert!(err.to_string().contains("world-writable"));
        assert!(!adapters_dir(&fornax_home).exists());

        // Restore so the scratch dir can still be cleaned up / reused by
        // later tests sharing the OS temp root.
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn register_without_confirm_digest_writes_nothing_and_exits_nonzero() {
        let tmp = scratch_dir();
        let fornax_home = tmp.join("fornax-home");
        let src = write_manifest(&tmp, "fixture-a");

        let outcome = register(&fornax_home, &src, None).unwrap();
        assert!(matches!(outcome, RegisterOutcome::Reviewed { .. }));
        assert!(!adapters_dir(&fornax_home).exists());
    }

    #[test]
    fn register_with_stale_confirm_digest_refuses_and_writes_nothing() {
        let tmp = scratch_dir();
        let fornax_home = tmp.join("fornax-home");
        let src = write_manifest(&tmp, "fixture-b");

        let err = register(&fornax_home, &src, Some("sha256:wrong")).unwrap_err();
        assert!(err.to_string().contains("changed since review"));
        assert!(!adapters_dir(&fornax_home).exists());
    }

    #[test]
    fn register_then_load_external_resolves_through_registry_seam() {
        let tmp = scratch_dir();
        let fornax_home = tmp.join("fornax-home");
        let src = write_manifest(&tmp, "fixture-c");

        let digest = match register(&fornax_home, &src, None).unwrap() {
            RegisterOutcome::Reviewed { digest, .. } => digest,
            other => panic!("expected Reviewed, got {other:?}"),
        };
        let outcome = register(&fornax_home, &src, Some(&digest)).unwrap();
        assert_eq!(
            outcome,
            RegisterOutcome::Registered {
                id: "fixture-c".to_string()
            }
        );

        let (loaded, rejections) = load_external(&fornax_home);
        assert!(rejections.is_empty(), "{rejections:?}");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id(), "fixture-c");
    }

    #[test]
    fn register_rejects_duplicate_id_of_existing_entry() {
        let tmp = scratch_dir();
        let fornax_home = tmp.join("fornax-home");
        let src = write_manifest(&tmp, "fixture-d");
        let digest = match register(&fornax_home, &src, None).unwrap() {
            RegisterOutcome::Reviewed { digest, .. } => digest,
            other => panic!("expected Reviewed, got {other:?}"),
        };
        register(&fornax_home, &src, Some(&digest)).unwrap();

        let err = register(&fornax_home, &src, Some(&digest)).unwrap_err();
        assert!(err.to_string().contains("already registered"));
    }

    #[test]
    fn register_rejects_id_colliding_with_builtin() {
        let tmp = scratch_dir();
        let fornax_home = tmp.join("fornax-home");
        let src = write_manifest(&tmp, "codex");
        let digest = match register(&fornax_home, &src, None).unwrap() {
            RegisterOutcome::Reviewed { digest, .. } => digest,
            other => panic!("expected Reviewed, got {other:?}"),
        };
        let err = register(&fornax_home, &src, Some(&digest)).unwrap_err();
        assert!(err.to_string().contains("collides with a built-in"));
    }

    #[test]
    fn load_external_on_missing_directory_returns_empty_and_creates_nothing() {
        let tmp = scratch_dir();
        let fornax_home = tmp.join("fornax-home");
        let (loaded, rejections) = load_external(&fornax_home);
        assert!(loaded.is_empty());
        assert!(rejections.is_empty());
        assert!(!fornax_home.exists());
    }

    #[test]
    fn digest_mismatch_on_owned_copy_rejects_the_entry() {
        let tmp = scratch_dir();
        let fornax_home = tmp.join("fornax-home");
        let src = write_manifest(&tmp, "fixture-e");
        let digest = match register(&fornax_home, &src, None).unwrap() {
            RegisterOutcome::Reviewed { digest, .. } => digest,
            other => panic!("expected Reviewed, got {other:?}"),
        };
        register(&fornax_home, &src, Some(&digest)).unwrap();

        // Tamper with the owned copy directly.
        let owned = adapters_dir(&fornax_home).join("fixture-e.manifest.json");
        let mut body: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&owned).unwrap()).unwrap();
        body["summary"] = serde_json::json!("tampered");
        std::fs::write(&owned, serde_json::to_vec(&body).unwrap()).unwrap();

        let (loaded, rejections) = load_external(&fornax_home);
        assert!(loaded.is_empty());
        assert_eq!(rejections.len(), 1);
        assert_eq!(rejections[0].reason, "digest mismatch");
    }

    #[test]
    fn missing_owned_manifest_copy_rejects_the_entry() {
        let tmp = scratch_dir();
        let fornax_home = tmp.join("fornax-home");
        let src = write_manifest(&tmp, "fixture-f");
        let digest = match register(&fornax_home, &src, None).unwrap() {
            RegisterOutcome::Reviewed { digest, .. } => digest,
            other => panic!("expected Reviewed, got {other:?}"),
        };
        register(&fornax_home, &src, Some(&digest)).unwrap();
        std::fs::remove_file(adapters_dir(&fornax_home).join("fixture-f.manifest.json")).unwrap();

        let (loaded, rejections) = load_external(&fornax_home);
        assert!(loaded.is_empty());
        assert!(rejections[0].reason.contains("unavailable"));
    }

    #[test]
    fn malformed_registry_index_rejects_all_entries_without_panicking() {
        let tmp = scratch_dir();
        let fornax_home = tmp.join("fornax-home");
        std::fs::create_dir_all(adapters_dir(&fornax_home)).unwrap();
        std::fs::write(index_path(&fornax_home), b"{not valid json").unwrap();

        let (loaded, rejections) = load_external(&fornax_home);
        assert!(loaded.is_empty());
        assert_eq!(rejections.len(), 1);
    }

    #[test]
    fn disable_then_load_excludes_entry_but_info_still_reports_it() {
        let tmp = scratch_dir();
        let fornax_home = tmp.join("fornax-home");
        let src = write_manifest(&tmp, "fixture-g");
        let digest = match register(&fornax_home, &src, None).unwrap() {
            RegisterOutcome::Reviewed { digest, .. } => digest,
            other => panic!("expected Reviewed, got {other:?}"),
        };
        register(&fornax_home, &src, Some(&digest)).unwrap();

        set_enabled(&fornax_home, "fixture-g", false).unwrap();
        let (loaded, rejections) = load_external(&fornax_home);
        assert!(loaded.is_empty());
        assert!(
            rejections.is_empty(),
            "disabled is not a rejection, just excluded"
        );

        let index = load_index(&fornax_home).unwrap();
        assert!(!index.entries[0].enabled);
    }

    #[test]
    fn remove_deletes_entry_and_owned_copy_and_leaves_others_intact() {
        let tmp = scratch_dir();
        let fornax_home = tmp.join("fornax-home");
        let src1 = write_manifest(&tmp, "fixture-h1");
        let src2 = write_manifest(&tmp, "fixture-h2");
        for src in [&src1, &src2] {
            let digest = match register(&fornax_home, src, None).unwrap() {
                RegisterOutcome::Reviewed { digest, .. } => digest,
                other => panic!("expected Reviewed, got {other:?}"),
            };
            register(&fornax_home, src, Some(&digest)).unwrap();
        }

        remove(&fornax_home, "fixture-h1").unwrap();
        assert!(!adapters_dir(&fornax_home)
            .join("fixture-h1.manifest.json")
            .exists());
        assert!(adapters_dir(&fornax_home)
            .join("fixture-h2.manifest.json")
            .exists());

        let (loaded, _) = load_external(&fornax_home);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id(), "fixture-h2");
    }
}

#[cfg(all(test, unix))]
mod inspection_directory_tests {
    use super::InspectionDirectory;

    #[test]
    fn replacing_adapter_directory_cannot_redirect_held_reads() {
        let root = std::env::temp_dir().join(format!(
            "fornax-inspection-directory-{}",
            uuid::Uuid::new_v4()
        ));
        let home = root.join("home");
        let adapters = home.join("adapters");
        let outside = root.join("outside");
        std::fs::create_dir_all(&adapters).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(adapters.join("registry.json"), b"owned").unwrap();
        std::fs::write(outside.join("registry.json"), b"outside-canary").unwrap();
        let held = InspectionDirectory::open(&home).unwrap();
        std::fs::rename(&adapters, root.join("original-adapters")).unwrap();
        std::os::unix::fs::symlink(&outside, &adapters).unwrap();
        assert_eq!(held.read_bounded("registry.json", 64).unwrap(), b"owned");
        assert!(InspectionDirectory::open(&home).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
