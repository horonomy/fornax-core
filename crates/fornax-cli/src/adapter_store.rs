//! CLI registration ceremony and configuration binding for the owner registry.
//!
//! The existing store module owns index decoding and every mutation. This
//! caller validates configuration semantics; host descriptors remain passive.

use crate::adapter_manifest::{digest_of, parse_manifest_bytes, AdapterManifest};
use fornax_store::adapter_registry::{self as owner, RegistrationKind, RegistryErrorCode};
use fornax_types::{decode_host_adapter_manifest, HostAdapterManifest};
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryEntry {
    pub id: String,
    pub manifest_file: String,
    pub digest: String,
    pub source_path: String,
    pub registered_at: String,
    pub enabled: bool,
    pub kind: RegistrationKind,
}

impl From<&owner::RegistryEntry> for RegistryEntry {
    fn from(entry: &owner::RegistryEntry) -> Self {
        Self {
            id: entry.id().to_owned(),
            manifest_file: entry.manifest_file().to_owned(),
            digest: entry.digest().to_owned(),
            source_path: entry.source_path().to_owned(),
            registered_at: entry.registered_at().to_owned(),
            enabled: entry.enabled(),
            kind: entry.kind(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection {
    pub id: String,
    pub reason: String,
}

pub struct RegistrationInspection {
    pub entry: RegistryEntry,
    pub manifest: Option<AdapterManifest>,
    pub host_manifest: Option<HostAdapterManifest>,
    pub registry_schema_version: Option<u32>,
    pub load_state: &'static str,
    pub reason: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{reason}")]
pub struct InspectionFailure {
    pub reason: &'static str,
}

fn inspection_reason(error: &owner::RegistryError) -> &'static str {
    match error.code() {
        RegistryErrorCode::UnsupportedVersion => "registry_index_unsupported_version",
        RegistryErrorCode::Malformed => "registry_index_malformed",
        RegistryErrorCode::IndexOversized => "registry_index_oversized",
        RegistryErrorCode::RegistryFull => "registry_index_too_many_entries",
        RegistryErrorCode::DuplicateId => "duplicate_registration_id",
        RegistryErrorCode::InvalidRecord => "invalid_registration_record",
        RegistryErrorCode::BuiltinCollision => "builtin_collision",
        RegistryErrorCode::DescriptorMismatch => "digest_mismatch",
        RegistryErrorCode::InvalidDescriptor => "malformed_manifest",
        RegistryErrorCode::DescriptorUnavailable => "owned_manifest_unavailable",
        RegistryErrorCode::DescriptorUnsafeFileType => "invalid_owned_file_type",
        RegistryErrorCode::DescriptorOversized => "owned_manifest_oversized",
        RegistryErrorCode::DescriptorChanged => "owned_manifest_changed",
        RegistryErrorCode::DescriptorCapacity => error.code_str(),
        RegistryErrorCode::Unavailable => "registry_index_unreadable",
        _ => "registry_index_unreadable",
    }
}

pub fn inspect_registration(
    home: &Path,
    id: &str,
) -> Result<RegistrationInspection, InspectionFailure> {
    if id.len() > 64 {
        return Err(InspectionFailure {
            reason: "unknown_adapter_id",
        });
    }
    let snapshot = owner::read_registry(home).map_err(|error| InspectionFailure {
        reason: match error.code() {
            RegistryErrorCode::Unavailable => "registry_index_unreadable",
            _ => inspection_reason(&error),
        },
    })?;
    let record = snapshot
        .entries()
        .iter()
        .find(|entry| entry.id() == id)
        .ok_or(InspectionFailure {
            reason: "unknown_adapter_id",
        })?;
    let mut view = RegistrationInspection {
        entry: record.into(),
        manifest: None,
        host_manifest: None,
        registry_schema_version: snapshot.stored_schema_version(),
        load_state: if record.enabled() {
            "enabled_valid"
        } else {
            "disabled"
        },
        reason: None,
    };
    match record.kind() {
        RegistrationKind::ConfigV1 => match owner::lookup_config_descriptor(home, id) {
            Ok(descriptor) if descriptor.entry() != record => {
                view.load_state = "rejected";
                view.reason = Some("registration_changed");
            }
            Ok(descriptor) => {
                match parse_manifest_bytes(descriptor.raw_bytes(), &crate::dirs_home()) {
                    Ok(manifest) => view.manifest = Some(manifest),
                    Err(_) => {
                        view.load_state = "rejected";
                        view.reason = Some("malformed_manifest");
                    }
                }
            }
            Err(error) => {
                view.load_state = "rejected";
                view.reason = Some(inspection_reason(&error));
            }
        },
        RegistrationKind::HostAdapterV1 => match owner::lookup_host_descriptor(home, id) {
            Ok(descriptor) if descriptor.entry() != record => {
                view.load_state = "rejected";
                view.reason = Some("registration_changed");
            }
            Ok(descriptor) => {
                // Retain the exact validated buffer without converting arbitrary
                // numeric schema declarations through serde_json::Value.
                view.host_manifest = Some(
                    decode_host_adapter_manifest(descriptor.manifest().as_manifest_bytes())
                        .map_err(|_| InspectionFailure {
                            reason: "malformed_manifest",
                        })?,
                );
            }
            Err(error) => {
                view.load_state = "rejected";
                view.reason = Some(inspection_reason(&error));
            }
        },
    }
    Ok(view)
}

/// Bounded declaration-only projection; configuration_schema is intentionally
/// omitted, so exact arbitrary numeric declarations never round through Value.
pub fn host_declaration_view(manifest: &HostAdapterManifest) -> anyhow::Result<serde_json::Value> {
    let fields: std::collections::BTreeMap<String, Box<serde_json::value::RawValue>> =
        serde_json::from_str(manifest.as_raw_json().get())?;
    let mut result = serde_json::Map::new();
    for key in [
        "manifest_kind",
        "manifest_version",
        "adapter_id",
        "adapter_version",
        "protocol_versions",
        "contract_version_range",
        "roles",
        "capabilities",
        "host_version_constraints",
        "launch",
        "runtime_files",
        "input_limits",
        "needs",
    ] {
        if let Some(value) = fields.get(key) {
            result.insert(key.to_owned(), serde_json::from_str(value.get())?);
        }
    }
    result.insert("configuration_schema".to_owned(), serde_json::Value::Null);
    result.insert(
        "projection".to_owned(),
        serde_json::json!("partial_configuration_schema_omitted"),
    );
    // This schema-bounded array has at most32 small integers. Retain all
    // versions so a late v1 declaration cannot become false incompatibility.
    let protocols = result.get("protocol_versions").cloned();
    let mut truncated = false;
    let mut result = bounded_declarations(serde_json::Value::Object(result), &mut truncated);
    if let Some(protocols) = protocols {
        result["protocol_versions"] = protocols;
    }
    result["declarations_truncated"] = serde_json::json!(truncated);
    Ok(result)
}

fn bounded_declarations(value: serde_json::Value, truncated: &mut bool) -> serde_json::Value {
    match value {
        serde_json::Value::String(value) => {
            let mut chars = value.chars();
            let rendered: String = chars.by_ref().take(512).collect();
            *truncated |= chars.next().is_some();
            serde_json::Value::String(rendered)
        }
        serde_json::Value::Array(values) => {
            *truncated |= values.len() > 16;
            serde_json::Value::Array(
                values
                    .into_iter()
                    .take(16)
                    .map(|value| bounded_declarations(value, truncated))
                    .collect(),
            )
        }
        serde_json::Value::Object(fields) => serde_json::Value::Object(
            fields
                .into_iter()
                .map(|(key, value)| (key, bounded_declarations(value, truncated)))
                .collect(),
        ),
        value => value,
    }
}

#[cfg(test)]
fn adapters_dir(home: &Path) -> PathBuf {
    home.join("adapters")
}
#[cfg(test)]
fn index_path(home: &Path) -> PathBuf {
    adapters_dir(home).join(owner::REGISTRY_INDEX_FILE)
}

#[derive(Debug)]
pub enum RegisterOutcome {
    Reviewed {
        manifest: Box<AdapterManifest>,
        digest: String,
    },
    HostReviewed {
        manifest: HostAdapterManifest,
        digest: String,
        registry_upgrade: bool,
    },
    Registered {
        id: String,
    },
    HostRegistered {
        id: String,
    },
}

/// Read a source once from held directory authority, refusing mutable shared
/// paths and special files before allocation. The reviewed bytes supply the pin.
fn read_source(source: &Path) -> anyhow::Result<Vec<u8>> {
    #[cfg(unix)]
    {
        use rustix::fs::{Mode, OFlags};
        use std::io::Read;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let parent = source
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let name = source
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("manifest source has no filename"))?;
        let directory = std::fs::File::from(rustix::fs::open(
            parent,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        if directory.metadata()?.permissions().mode() & 0o022 != 0 {
            anyhow::bail!("manifest containing directory is group- or world-writable");
        }
        let file = std::fs::File::from(rustix::fs::openat(
            &directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let before = file.metadata()?;
        if !before.is_file() {
            anyhow::bail!("manifest source is not a regular file");
        }
        if before.permissions().mode() & 0o022 != 0 {
            anyhow::bail!("manifest source is group- or world-writable");
        }
        let max = fornax_types::MAX_HOST_ADAPTER_MANIFEST_BYTES;
        if before.len() > max as u64 {
            return Err(fornax_types::HostManifestRejection::InputTooLarge.into());
        }
        let mut bytes = Vec::new();
        (&file).take(max as u64 + 1).read_to_end(&mut bytes)?;
        let after = file.metadata()?;
        if bytes.len() > max {
            return Err(fornax_types::HostManifestRejection::InputTooLarge.into());
        }
        if before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
        {
            anyhow::bail!("manifest source changed while reading");
        }
        Ok(bytes)
    }
    #[cfg(not(unix))]
    {
        let _ = source;
        anyhow::bail!("registration_platform_unsupported")
    }
}

pub fn register(
    home: &Path,
    source: &Path,
    confirm: Option<&str>,
) -> anyhow::Result<RegisterOutcome> {
    let bytes = read_source(source)?;
    let digest = digest_of(&bytes);
    // Borrow root fields so the discriminator is read without rounding any
    // configuration schema numbers or re-reading the source file.
    let root: std::collections::BTreeMap<String, Box<serde_json::value::RawValue>> =
        serde_json::from_slice(&bytes)?;
    let host = match root.get("manifest_kind") {
        None => None,
        Some(marker)
            if serde_json::from_str::<String>(marker.get()).ok().as_deref()
                == Some("host-adapter") =>
        {
            Some(decode_host_adapter_manifest(&bytes)?)
        }
        Some(_) => anyhow::bail!("unsupported_manifest_kind"),
    };
    let config = if host.is_none() {
        Some(parse_manifest_bytes(&bytes, &crate::dirs_home())?)
    } else {
        None
    };
    if let Some(confirm) = confirm {
        if confirm != digest {
            anyhow::bail!("manifest changed since review -- nothing registered");
        }
        let source_path = source.display().to_string();
        let registered_at = chrono::Utc::now().to_rfc3339();
        if let Some(manifest) = host {
            let entry = owner::register_host_descriptor(
                home,
                &source_path,
                &registered_at,
                manifest.as_manifest_bytes(),
            )?;
            Ok(RegisterOutcome::HostRegistered {
                id: entry.id().to_owned(),
            })
        } else {
            let manifest = config.expect("configuration discriminator selected validated config");
            let entry = owner::register_config(
                home,
                owner::ConfigRegistration {
                    id: &manifest.id,
                    source_path: &source_path,
                    registered_at: &registered_at,
                    raw_bytes: &bytes,
                },
            )?;
            Ok(RegisterOutcome::Registered {
                id: entry.id().to_owned(),
            })
        }
    } else if let Some(manifest) = host {
        let snapshot = owner::read_registry(home)?;
        Ok(RegisterOutcome::HostReviewed {
            manifest,
            digest,
            registry_upgrade: snapshot.effective_schema_version() < 2,
        })
    } else {
        Ok(RegisterOutcome::Reviewed {
            manifest: Box::new(config.expect("configuration selected")),
            digest,
        })
    }
}

pub fn set_enabled(home: &Path, id: &str, enabled: bool) -> anyhow::Result<()> {
    Ok(owner::set_registration_enabled(home, id, enabled)?)
}
pub fn remove(home: &Path, id: &str) -> anyhow::Result<()> {
    Ok(owner::remove_registration(home, id)?)
}

pub fn load_external(
    home: &Path,
) -> (
    Vec<crate::adapter_external::ExternalAdapter>,
    Vec<Rejection>,
) {
    let mut loaded = Vec::new();
    let mut rejections = Vec::new();
    let snapshot = match owner::read_registry(home) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            rejections.push(Rejection {
                id: "<registry.json>".to_owned(),
                reason: format!("malformed registry index: {}", error.code_str()),
            });
            return (loaded, rejections);
        }
    };
    for entry in snapshot.entries() {
        if entry.kind() != RegistrationKind::ConfigV1 || !entry.enabled() {
            continue;
        }
        match owner::lookup_config_descriptor(home, entry.id()) {
            Ok(descriptor) => {
                match parse_manifest_bytes(descriptor.raw_bytes(), &crate::dirs_home()) {
                    Ok(manifest) => {
                        loaded.push(crate::adapter_external::ExternalAdapter::new(manifest))
                    }
                    Err(_) => rejections.push(Rejection {
                        id: entry.id().to_owned(),
                        reason: "malformed manifest".to_owned(),
                    }),
                }
            }
            Err(error) => rejections.push(Rejection {
                id: entry.id().to_owned(),
                reason: if error.code() == RegistryErrorCode::DescriptorMismatch {
                    "digest mismatch".to_owned()
                } else {
                    format!("unavailable -- {}", error.code_str())
                },
            }),
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
        assert!(matches!(outcome, RegisterOutcome::Registered { id } if id == "fixture-c"));

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
        assert_eq!(
            err.downcast_ref::<owner::RegistryError>().unwrap().code(),
            RegistryErrorCode::DuplicateId
        );
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
        assert_eq!(
            err.downcast_ref::<owner::RegistryError>().unwrap().code(),
            RegistryErrorCode::BuiltinCollision
        );
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

        let index = owner::read_registry(&fornax_home).unwrap();
        assert!(!index.entries()[0].enabled());
    }

    #[test]
    fn remove_retains_owned_copy_but_removes_index_entry_and_leaves_others_intact() {
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

        // Strict Retention (HORO-1745): the index entry is removed, but the
        // owned copy is never unlinked -- see `adapter_registry::remove_owned`.
        let error = remove(&fornax_home, "fixture-h1").unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<owner::RegistryError>()
                .map(owner::RegistryError::code),
            Some(RegistryErrorCode::CleanupFailed)
        );
        assert!(adapters_dir(&fornax_home)
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
