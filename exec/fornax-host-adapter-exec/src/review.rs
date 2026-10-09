//! Read-only review of a registered host-adapter manifest: field extraction,
//! version-compatibility reasoning, and implementation-digest measurement.
//!
//! Nothing in this module opens a file for anything other than hashing it,
//! and nothing spawns a process. The measurements here are diagnostics, not
//! proof of execution safety -- re-hashing a path moments before a
//! hypothetical spawn still cannot prove which bytes a later `exec()` would
//! actually run against a non-root writer running as the same user (the
//! founder-recorded fail-closed decision, 2026-10-09). This module exists to
//! let an operator *inspect* a registered adapter, never to clear it to run.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use fornax_store::adapter_registry::RegisteredHostDescriptor;
use sha2::{Digest, Sha256};

/// Transport versions this build understands. Kept as a const slice (not a
/// single constant) so the intersection logic reads the same way it will
/// once a second version is ever added.
pub const SUPPORTED_PROTOCOL_VERSIONS: &[u32] = &[1];
/// Host SPI/data contract versions this build understands.
pub const SUPPORTED_CONTRACT_VERSIONS: &[u32] = &[1];

/// Per-file measurement capacity -- independent of, and in addition to, the
/// manifest's own declared `input_limits.max_bytes` (which bounds *runtime*
/// stdin, not this review's own file reads).
pub const MAX_RUNTIME_FILES: usize = 128;
pub const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;

/// Independently re-extracted manifest fields this crate actually needs.
/// Deliberately not a blind `serde_json::from_value::<Manifest>` into a
/// type that mirrors the pinned schema exactly -- this crate re-validates
/// the shapes it depends on itself (defense in depth for a trust-boundary
/// adjacent tool), rather than trusting `fornax-types`' own validation to
/// have been run against the exact bytes this process is looking at.
#[derive(Debug, Clone)]
pub struct ManifestFields {
    pub adapter_id: String,
    pub adapter_version: String,
    pub protocol_versions: Vec<u32>,
    pub contract_minimum: u32,
    pub contract_maximum: u32,
    pub roles: Vec<String>,
    pub capabilities: Vec<String>,
    pub executable: String,
    pub argv: Vec<String>,
    pub runtime_files: Vec<RuntimeFileField>,
    pub input_max_bytes: u64,
    pub needs_environment: Vec<String>,
    pub needs_read_paths: Vec<String>,
    pub needs_write_paths: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RuntimeFileField {
    pub path: String,
    pub kind: String,
    pub declared_digest: String,
}

#[derive(Debug, thiserror::Error)]
pub enum FieldExtractionError {
    #[error("manifest field '{0}' missing or the wrong shape")]
    MalformedField(&'static str),
}

/// Extracts the fields this crate needs from the manifest's raw JSON,
/// erroring (never panicking, never defaulting silently) on anything
/// missing or the wrong shape.
pub fn extract_fields(
    manifest: &fornax_types::HostAdapterManifest,
) -> Result<ManifestFields, FieldExtractionError> {
    let raw: serde_json::Value = serde_json::from_str(manifest.as_raw_json().get())
        .map_err(|_| FieldExtractionError::MalformedField("<root>"))?;

    let str_field = |key: &'static str| -> Result<String, FieldExtractionError> {
        raw.get(key)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or(FieldExtractionError::MalformedField(key))
    };
    let str_array = |parent: &serde_json::Value,
                     key: &'static str|
     -> Result<Vec<String>, FieldExtractionError> {
        parent
            .get(key)
            .and_then(serde_json::Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .ok_or(FieldExtractionError::MalformedField(key))
    };
    let u32_array = |key: &'static str| -> Result<Vec<u32>, FieldExtractionError> {
        raw.get(key)
            .and_then(serde_json::Value::as_array)
            .ok_or(FieldExtractionError::MalformedField(key))?
            .iter()
            .map(|v| {
                v.as_u64()
                    .and_then(|n| u32::try_from(n).ok())
                    .ok_or(FieldExtractionError::MalformedField(key))
            })
            .collect()
    };

    let adapter_id = str_field("adapter_id")?;
    let adapter_version = str_field("adapter_version")?;
    let protocol_versions = u32_array("protocol_versions")?;

    let contract_version_range =
        raw.get("contract_version_range")
            .ok_or(FieldExtractionError::MalformedField(
                "contract_version_range",
            ))?;
    let contract_minimum = contract_version_range
        .get("minimum")
        .and_then(serde_json::Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .ok_or(FieldExtractionError::MalformedField(
            "contract_version_range.minimum",
        ))?;
    let contract_maximum = contract_version_range
        .get("maximum")
        .and_then(serde_json::Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .ok_or(FieldExtractionError::MalformedField(
            "contract_version_range.maximum",
        ))?;

    let roles = str_array(&raw, "roles")?;
    let capabilities = str_array(&raw, "capabilities")?;

    let launch = raw
        .get("launch")
        .ok_or(FieldExtractionError::MalformedField("launch"))?;
    let executable = str_field_of(launch, "executable")?;
    let argv = str_array(launch, "argv")?;

    let runtime_files_raw = raw
        .get("runtime_files")
        .and_then(serde_json::Value::as_array)
        .ok_or(FieldExtractionError::MalformedField("runtime_files"))?;
    if runtime_files_raw.len() > MAX_RUNTIME_FILES {
        return Err(FieldExtractionError::MalformedField("runtime_files"));
    }
    let mut runtime_files = Vec::with_capacity(runtime_files_raw.len());
    for entry in runtime_files_raw {
        runtime_files.push(RuntimeFileField {
            path: str_field_of(entry, "path")?,
            kind: str_field_of(entry, "kind")?,
            declared_digest: str_field_of(entry, "digest")?,
        });
    }

    let input_limits = raw
        .get("input_limits")
        .ok_or(FieldExtractionError::MalformedField("input_limits"))?;
    let input_max_bytes = input_limits
        .get("max_bytes")
        .and_then(serde_json::Value::as_u64)
        .ok_or(FieldExtractionError::MalformedField(
            "input_limits.max_bytes",
        ))?;

    let needs = raw
        .get("needs")
        .ok_or(FieldExtractionError::MalformedField("needs"))?;
    let needs_environment = str_array(needs, "environment")?;
    let needs_read_paths = str_array(needs, "read_paths")?;
    let needs_write_paths = str_array(needs, "write_paths")?;

    Ok(ManifestFields {
        adapter_id,
        adapter_version,
        protocol_versions,
        contract_minimum,
        contract_maximum,
        roles,
        capabilities,
        executable,
        argv,
        runtime_files,
        input_max_bytes,
        needs_environment,
        needs_read_paths,
        needs_write_paths,
    })
}

fn str_field_of(
    value: &serde_json::Value,
    key: &'static str,
) -> Result<String, FieldExtractionError> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or(FieldExtractionError::MalformedField(key))
}

/// Outcome of intersecting this build's supported versions against the
/// manifest's declared ones. Mirrors the shared contract's own refusal
/// reason codes exactly (`protocol_version_incompatible` /
/// `host_contract_version_incompatible`) so this tool's output means the
/// same thing the real runner's would.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionCompatibility {
    Compatible {
        protocol_version: u32,
        contract_version: u32,
    },
    ProtocolIncompatible,
    ContractIncompatible,
}

pub fn negotiate_versions(fields: &ManifestFields) -> VersionCompatibility {
    let protocol_version = fields
        .protocol_versions
        .iter()
        .copied()
        .filter(|v| SUPPORTED_PROTOCOL_VERSIONS.contains(v))
        .max();
    let Some(protocol_version) = protocol_version else {
        return VersionCompatibility::ProtocolIncompatible;
    };
    let contract_version = SUPPORTED_CONTRACT_VERSIONS
        .iter()
        .copied()
        .filter(|v| *v >= fields.contract_minimum && *v <= fields.contract_maximum)
        .max();
    let Some(contract_version) = contract_version else {
        return VersionCompatibility::ContractIncompatible;
    };
    VersionCompatibility::Compatible {
        protocol_version,
        contract_version,
    }
}

/// One measured runtime file: what's on disk right now, compared against
/// what the manifest declared. `matches_declared` is a drift signal only --
/// see this module's own doc comment for why a match here is not proof of
/// anything at a later, hypothetical spawn time.
#[derive(Debug, Clone)]
pub struct MeasuredFile {
    pub path: String,
    pub kind: String,
    pub declared_digest: String,
    pub measured_digest: Option<String>,
    pub matches_declared: bool,
}

/// Measures the executable and every declared runtime file, bounded by
/// [`MAX_RUNTIME_FILES`]/[`MAX_FILE_BYTES`]/[`MAX_TOTAL_BYTES`]. A file that
/// can't be opened or read is reported with `measured_digest: None`, never
/// silently skipped and never treated as a match. If the total-bytes
/// capacity is exceeded partway through, measurement stops there and the
/// second element of the returned tuple is `true` -- the caller must
/// surface that visibly (never silently drop it), since an unmeasured file
/// is exactly the kind of gap this review exists to never hide.
pub fn measure_runtime_files(fields: &ManifestFields) -> (Vec<MeasuredFile>, bool) {
    // `extract_fields` already rejects more than `MAX_RUNTIME_FILES` entries
    // before this ever runs; this is a second, independent check so this
    // function stays correct even if called with a `ManifestFields` built
    // some other way.
    if fields.runtime_files.len() > MAX_RUNTIME_FILES {
        return (Vec::new(), true);
    }
    let mut total: u64 = 0;
    let mut out = Vec::with_capacity(fields.runtime_files.len());
    for file in &fields.runtime_files {
        let measured = hash_file_bounded(Path::new(&file.path), MAX_FILE_BYTES);
        let measured_digest = match measured {
            Ok((digest, bytes)) => {
                total = total.saturating_add(bytes);
                if total > MAX_TOTAL_BYTES {
                    return (out, true);
                }
                Some(digest)
            }
            Err(_) => None,
        };
        let matches_declared = measured_digest.as_deref() == Some(file.declared_digest.as_str());
        out.push(MeasuredFile {
            path: file.path.clone(),
            kind: file.kind.clone(),
            declared_digest: file.declared_digest.clone(),
            measured_digest,
            matches_declared,
        });
    }
    (out, false)
}

/// Hashes the executable itself (not a declared `runtime_files` entry --
/// the manifest's `launch.executable` is separate from its dependency list).
pub fn hash_executable(fields: &ManifestFields) -> Option<String> {
    hash_file_bounded(Path::new(&fields.executable), MAX_FILE_BYTES)
        .ok()
        .map(|(digest, _)| digest)
}

fn hash_file_bounded(path: &Path, max_bytes: u64) -> std::io::Result<(String, u64)> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let read = file.read(&mut buf)?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        if total > max_bytes {
            return Err(std::io::Error::other(
                "file exceeds the local measurement capacity",
            ));
        }
        hasher.update(&buf[..read]);
    }
    let encoded: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok((format!("sha256:{encoded}"), total))
}

/// The `fornax-host-impl-v1` implementation digest: a single value that
/// commits to the executable's real path and bytes, the literal argv, and
/// every declared runtime file's path/kind/bytes. Two manifests that
/// declare the same `launch`/`runtime_files` but whose on-disk bytes differ
/// produce different digests; two differently-ordered-but-identical
/// `runtime_files` declarations produce the *same* digest (file entries are
/// sorted by path before hashing; argv order is preserved, since argv order
/// is semantically meaningful).
///
/// Wire format (all integers big-endian `u32`; byte-string fields are
/// length-prefixed by a `u32` length then the raw bytes; the two kinds of
/// raw hash below are fixed-size 32-byte digests written without a prefix,
/// since their length is already fixed by position):
///
/// ```text
/// b"fornax-host-impl-v1"
/// u32 len(executable_path) ++ executable_path bytes
/// 32 raw bytes: SHA-256(executable)
/// u32 argv.len()
/// for each argv[i] in order: u32 len(argv[i]) ++ argv[i] bytes
/// u32 runtime_files.len()
/// for each runtime file, sorted by path bytes ascending:
///     1 byte kind (0x01 = entrypoint, 0x02 = dependency, 0x00 = unknown)
///     u32 len(path) ++ path bytes
///     32 raw bytes: SHA-256(file)
/// ```
pub fn implementation_digest(
    fields: &ManifestFields,
    executable_sha256: &[u8; 32],
    measured: &[MeasuredFile],
) -> Option<String> {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"fornax-host-impl-v1");
    push_len_prefixed(&mut buf, fields.executable.as_bytes());
    buf.extend_from_slice(executable_sha256);
    buf.extend_from_slice(&(fields.argv.len() as u32).to_be_bytes());
    for arg in &fields.argv {
        push_len_prefixed(&mut buf, arg.as_bytes());
    }
    buf.extend_from_slice(&(measured.len() as u32).to_be_bytes());

    let mut sorted: Vec<&MeasuredFile> = measured.iter().collect();
    sorted.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    for file in sorted {
        let kind_byte = match file.kind.as_str() {
            "entrypoint" => 0x01u8,
            "dependency" => 0x02u8,
            _ => 0x00u8,
        };
        buf.push(kind_byte);
        push_len_prefixed(&mut buf, file.path.as_bytes());
        let raw = decode_sha256_hex(file.measured_digest.as_deref()?)?;
        buf.extend_from_slice(&raw);
    }

    let digest = Sha256::digest(&buf);
    let encoded: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    Some(format!("sha256:{encoded}"))
}

fn push_len_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn decode_sha256_hex(value: &str) -> Option<[u8; 32]> {
    let hex = value.strip_prefix("sha256:")?;
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).ok()?;
        out[i] = u8::from_str_radix(s, 16).ok()?;
    }
    Some(out)
}

/// The full review of a registered descriptor -- everything a `doctor` call
/// reports, before the unconditional refusal.
pub struct Review {
    pub entry_enabled: bool,
    pub fields: ManifestFields,
    pub version: VersionCompatibility,
    pub environment_grant_declared: bool,
    pub executable_measured_digest: Option<String>,
    pub runtime_files: Vec<MeasuredFile>,
    /// `true` if measurement stopped early because `MAX_TOTAL_BYTES` (or,
    /// defensively, `MAX_RUNTIME_FILES`) was exceeded -- `runtime_files` is
    /// then a *partial* list, and this must stay visible in every report,
    /// never silently absorbed into an otherwise-clean-looking review.
    pub measurement_capacity_exceeded: bool,
    pub implementation_digest: Option<String>,
}

pub fn build_review(descriptor: &RegisteredHostDescriptor) -> Result<Review, FieldExtractionError> {
    let fields = extract_fields(descriptor.manifest())?;
    let version = negotiate_versions(&fields);
    let environment_grant_declared = !fields.needs_environment.is_empty();
    let (runtime_files, measurement_capacity_exceeded) = measure_runtime_files(&fields);
    let executable_measured_digest = hash_executable(&fields);
    let implementation_digest = if measurement_capacity_exceeded {
        None
    } else {
        executable_measured_digest
            .as_deref()
            .and_then(decode_sha256_hex)
            .and_then(|raw| implementation_digest(&fields, &raw, &runtime_files))
    };
    Ok(Review {
        entry_enabled: descriptor.entry().enabled(),
        fields,
        version,
        environment_grant_declared,
        executable_measured_digest,
        runtime_files,
        measurement_capacity_exceeded,
        implementation_digest,
    })
}

/// Drift summary used by the human-readable report -- counts, not raw
/// paths, so this never needs its own redaction pass beyond what's already
/// in `Review`.
pub fn drift_counts(review: &Review) -> BTreeMap<&'static str, usize> {
    let mut counts = BTreeMap::new();
    let matched = review
        .runtime_files
        .iter()
        .filter(|f| f.matches_declared)
        .count();
    let mismatched = review.runtime_files.len() - matched;
    counts.insert("matched", matched);
    counts.insert("mismatched_or_unreadable", mismatched);
    counts
}
