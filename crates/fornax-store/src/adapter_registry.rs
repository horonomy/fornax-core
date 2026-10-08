//! Passive, version-aware owner for the shared adapter registry.
//!
//! This module owns the existing `adapters/registry.json` namespace. Reads
//! never initialize the evidence database and never create files. Host
//! records retain descriptor bytes only; this module has no execution or
//! implementation-trust authority.

use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::io::{Read, Write};
use std::path::Path;
#[cfg(unix)]
use std::time::{Duration, Instant};

pub const REGISTRY_INDEX_FILE: &str = "registry.json";
pub const MAX_INDEX_BYTES: usize = 1024 * 1024;
pub const MAX_ENTRIES: usize = 64;
/// Local capacity ceiling for bounded owned executable-manifest reads.
pub const MAX_OWNED_BYTES: usize = fornax_types::MAX_HOST_ADAPTER_MANIFEST_BYTES;
/// Existing configuration-manifest v1 ceiling, retained for its legacy kind.
pub const MAX_CONFIG_MANIFEST_BYTES: usize = 64 * 1024;
pub const REGISTRY_KIND_V2: &str = "fornax-adapter-registry-v2";

#[cfg(unix)]
const LOCK_FILE: &str = "registry.lock";
#[cfg(unix)]
const LOCK_WAIT: Duration = Duration::from_secs(2);
#[cfg(unix)]
const LOCK_POLL: Duration = Duration::from_millis(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RegistrationKind {
    ConfigV1,
    HostAdapterV1,
}

impl RegistrationKind {
    fn filename(self, id: &str) -> String {
        match self {
            Self::ConfigV1 => format!("{id}.manifest.json"),
            Self::HostAdapterV1 => format!("{id}.host-adapter.json"),
        }
    }
}

/// An immutable validated registration row. Fields are exposed by getters
/// so callers cannot use this type to publish arbitrary index contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryEntry {
    id: String,
    manifest_file: String,
    digest: String,
    source_path: String,
    registered_at: String,
    enabled: bool,
    kind: RegistrationKind,
}

impl RegistryEntry {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn manifest_file(&self) -> &str {
        &self.manifest_file
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
    pub fn source_path(&self) -> &str {
        &self.source_path
    }
    pub fn registered_at(&self) -> &str {
        &self.registered_at
    }
    pub fn enabled(&self) -> bool {
        self.enabled
    }
    pub fn kind(&self) -> RegistrationKind {
        self.kind
    }
}

/// The exact declared historical root version (`None` means the field was
/// omitted), its effective compatibility version, and an immutable view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrySnapshot {
    stored_schema_version: Option<u32>,
    effective_schema_version: u32,
    entries: Vec<RegistryEntry>,
}

impl RegistrySnapshot {
    pub fn stored_schema_version(&self) -> Option<u32> {
        self.stored_schema_version
    }
    pub fn effective_schema_version(&self) -> u32 {
        self.effective_schema_version
    }
    pub fn entries(&self) -> &[RegistryEntry] {
        &self.entries
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryErrorCode {
    Unavailable,
    IndexOversized,
    Malformed,
    UnsupportedVersion,
    InvalidRecord,
    DuplicateId,
    BuiltinCollision,
    RegistryFull,
    RegistryBusy,
    RegistryChanged,
    RegistrationMissing,
    WrongKind,
    Disabled,
    RegistrationEnabled,
    DescriptorUnavailable,
    DescriptorUnsafeFileType,
    DescriptorOversized,
    DescriptorChanged,
    DescriptorMismatch,
    InvalidDescriptor,
    DescriptorCapacity,
    ExecutionBoundaryUnavailable,
    CleanupFailed,
    CommittedUnverified,
    Io,
    /// A file already exists at this id's exact owned-destination filename,
    /// and a new registration cannot create its own owned copy there.
    /// Distinct from `InvalidRecord`: the new registration's own bytes are
    /// not malformed. `create_owned` cannot tell whether the occupying file
    /// is a prior removal's retained orphan (Strict Retention, HORO-1745)
    /// or something placed there outside the registry entirely -- both
    /// reach this same refusal, since neither is this registration's to
    /// overwrite.
    OwnedDestinationOccupied,
}

impl RegistryErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "registry_unavailable",
            Self::IndexOversized => "registry_index_oversized",
            Self::Malformed => "registry_malformed",
            Self::UnsupportedVersion => "registry_version_unsupported",
            Self::InvalidRecord => "registration_malformed",
            Self::DuplicateId => "duplicate_id",
            Self::BuiltinCollision => "builtin_collision",
            Self::RegistryFull => "registry_full",
            Self::RegistryBusy => "registry_busy",
            Self::RegistryChanged => "registry_changed",
            Self::RegistrationMissing => "registration_missing",
            Self::WrongKind => "wrong_registration_kind",
            Self::Disabled => "registration_disabled",
            Self::RegistrationEnabled => "registration_enabled",
            Self::DescriptorUnavailable => "descriptor_unavailable",
            Self::DescriptorUnsafeFileType => "invalid_owned_file_type",
            Self::DescriptorOversized => "owned_manifest_oversized",
            Self::DescriptorChanged => "owned_manifest_changed",
            Self::DescriptorMismatch => "descriptor_mismatch",
            Self::InvalidDescriptor => "descriptor_malformed",
            Self::DescriptorCapacity => "descriptor_capacity_exceeded",
            Self::ExecutionBoundaryUnavailable => "execution_boundary_unavailable",
            Self::CleanupFailed => "cleanup_failed",
            Self::CommittedUnverified => "registration_committed_unverified",
            Self::Io => "registry_io",
            Self::OwnedDestinationOccupied => "owned_destination_occupied",
        }
    }
}

impl std::fmt::Display for RegistryErrorCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{code}: {detail}")]
pub struct RegistryError {
    code: RegistryErrorCode,
    detail: &'static str,
    #[source]
    manifest_rejection: Option<fornax_types::HostManifestRejection>,
    index_published: bool,
}

impl RegistryError {
    fn new(code: RegistryErrorCode, detail: &'static str) -> Self {
        Self {
            code,
            detail,
            manifest_rejection: None,
            index_published: false,
        }
    }
    fn published(code: RegistryErrorCode, detail: &'static str) -> Self {
        Self {
            code,
            detail,
            manifest_rejection: None,
            index_published: true,
        }
    }
    pub fn code(&self) -> RegistryErrorCode {
        self.code
    }
    pub fn code_str(&self) -> &'static str {
        self.manifest_rejection
            .map(fornax_types::HostManifestRejection::reason_code)
            .unwrap_or(self.code.as_str())
    }
    /// Whether the index rename commit point was crossed before this error.
    pub fn index_published(&self) -> bool {
        self.index_published
    }
}

fn fail(code: RegistryErrorCode, detail: &'static str) -> RegistryError {
    RegistryError::new(code, detail)
}
fn fail_published(code: RegistryErrorCode, detail: &'static str) -> RegistryError {
    RegistryError::published(code, detail)
}

fn manifest_rejection(error: fornax_types::HostManifestRejection) -> RegistryError {
    let mut rejection = fail(
        if error.is_local_capacity() {
            RegistryErrorCode::DescriptorCapacity
        } else {
            RegistryErrorCode::InvalidDescriptor
        },
        error.reason_code(),
    );
    rejection.manifest_rejection = Some(error);
    rejection
}

/// A configuration registration request. The CLI must run its existing
/// complete configuration-manifest validator before calling this storage
/// boundary; the owner independently checks bounded bytes, raw identity,
/// legacy ID grammar, collisions, and the indexed digest.
#[derive(Debug, Clone)]
pub struct ConfigRegistration<'a> {
    pub id: &'a str,
    pub source_path: &'a str,
    pub registered_at: &'a str,
    pub raw_bytes: &'a [u8],
}

pub struct RegisteredHostDescriptor {
    entry: RegistryEntry,
    manifest: fornax_types::HostAdapterManifest,
}

impl RegisteredHostDescriptor {
    pub fn entry(&self) -> &RegistryEntry {
        &self.entry
    }
    pub fn manifest(&self) -> &fornax_types::HostAdapterManifest {
        &self.manifest
    }
}

/// A digest-pinned immutable configuration manifest buffer. Full config
/// semantics remain with the established CLI validator.
pub struct RegisteredConfigDescriptor {
    entry: RegistryEntry,
    raw_bytes: Vec<u8>,
}

impl RegisteredConfigDescriptor {
    pub fn entry(&self) -> &RegistryEntry {
        &self.entry
    }
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw_bytes
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct V2RootRef<'a> {
    schema_version: u32,
    registry_kind: &'static str,
    entries: &'a [WireEntry],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireEntry {
    id: String,
    manifest_file: String,
    digest: String,
    source_path: String,
    registered_at: String,
    enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    kind: Option<RegistrationKind>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyRoot {
    #[serde(default)]
    schema_version: Option<u32>,
    entries: Vec<LegacyEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyEntry {
    id: String,
    manifest_file: String,
    digest: String,
    source_path: String,
    registered_at: String,
    enabled: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct V2Root {
    schema_version: u32,
    registry_kind: String,
    entries: Vec<WireEntry>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct LegacyRootRef<'a> {
    schema_version: u32,
    entries: &'a [WireEntry],
}

/// serde_json's ordinary `Value` visitor accepts duplicate object keys.
/// The registry wire format is authoritative, so reject ambiguity while
/// decoding rather than choosing one occurrence.
struct UniqueValue(serde_json::Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(UniqueValueVisitor)
    }
}

struct UniqueValueVisitor;

impl<'de> Visitor<'de> for UniqueValueVisitor {
    type Value = UniqueValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueValue(value.into()))
    }
    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueValue(value.into()))
    }
    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueValue(value.into()))
    }
    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
        serde_json::Number::from_f64(value)
            .map(|number| UniqueValue(number.into()))
            .ok_or_else(|| E::custom("non-finite number"))
    }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(UniqueValue(value.into()))
    }
    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueValue(value.into()))
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(serde_json::Value::Null))
    }
    fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        self.visit_unit()
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = seq.next_element::<UniqueValue>()? {
            values.push(value.0);
        }
        Ok(UniqueValue(values.into()))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut values = serde_json::Map::new();
        while let Some((key, value)) = map.next_entry::<String, UniqueValue>()? {
            if values.contains_key(&key) {
                return Err(serde::de::Error::custom("duplicate object key"));
            }
            values.insert(key, value.0);
        }
        Ok(UniqueValue(values.into()))
    }
}

#[derive(Clone)]
struct IndexState {
    stored_version: Option<u32>,
    effective_version: u32,
    v2: bool,
    entries: Vec<WireEntry>,
}

#[derive(Clone, PartialEq, Eq)]
struct IndexRevision(Option<Vec<u8>>);

#[cfg(unix)]
#[derive(Clone, Copy)]
struct CreatedIdentity {
    device: u64,
    inode: u64,
}
#[cfg(not(unix))]
#[derive(Clone, Copy)]
struct CreatedIdentity;

impl IndexState {
    fn empty() -> Self {
        Self {
            stored_version: None,
            effective_version: 1,
            v2: false,
            entries: Vec::new(),
        }
    }
    fn encode(&self) -> Result<Vec<u8>, RegistryError> {
        let mut bytes = if self.v2 {
            serde_json::to_vec_pretty(&V2RootRef {
                schema_version: 2,
                registry_kind: REGISTRY_KIND_V2,
                entries: &self.entries,
            })
        } else {
            serde_json::to_vec_pretty(&LegacyRootRef {
                schema_version: self.effective_version,
                entries: &self.entries,
            })
        }
        .map_err(|_| fail(RegistryErrorCode::Malformed, "index serialization failed"))?;
        bytes.push(b'\n');
        if bytes.len() > MAX_INDEX_BYTES {
            return Err(fail(
                RegistryErrorCode::RegistryFull,
                "index byte limit exceeded",
            ));
        }
        Ok(bytes)
    }
}

/// Reads a passive snapshot from the sole registry file. Missing home,
/// adapters directory, or index means a fresh empty legacy view; no path is
/// created and SQLite/runtime state is never initialized.
pub fn read_registry(home: &Path) -> Result<RegistrySnapshot, RegistryError> {
    let Some(directory) = InspectionDirectory::open_existing(home)? else {
        return Ok(snapshot(IndexState::empty()));
    };
    match directory.read_bounded(REGISTRY_INDEX_FILE, MAX_INDEX_BYTES) {
        Ok(bytes) => decode_index(&bytes).map(snapshot),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(snapshot(IndexState::empty()))
        }
        Err(error) if error.kind() == std::io::ErrorKind::FileTooLarge => Err(fail(
            RegistryErrorCode::IndexOversized,
            "index byte capacity exceeded",
        )),
        Err(_) => Err(fail(
            RegistryErrorCode::Unavailable,
            "index unavailable or unsafe",
        )),
    }
}

fn snapshot(state: IndexState) -> RegistrySnapshot {
    RegistrySnapshot {
        stored_schema_version: state.stored_version,
        effective_schema_version: state.effective_version,
        entries: state
            .entries
            .into_iter()
            .map(|entry| RegistryEntry {
                id: entry.id,
                manifest_file: entry.manifest_file,
                digest: entry.digest,
                source_path: entry.source_path,
                registered_at: entry.registered_at,
                enabled: entry.enabled,
                kind: entry.kind.unwrap_or(RegistrationKind::ConfigV1),
            })
            .collect(),
    }
}

fn decode_index(bytes: &[u8]) -> Result<IndexState, RegistryError> {
    if bytes.len() > MAX_INDEX_BYTES {
        return Err(fail(
            RegistryErrorCode::Malformed,
            "index byte limit exceeded",
        ));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = UniqueValue::deserialize(&mut deserializer)
        .map_err(|_| fail(RegistryErrorCode::Malformed, "index JSON malformed"))?
        .0;
    deserializer
        .end()
        .map_err(|_| fail(RegistryErrorCode::Malformed, "index JSON trailing data"))?;
    if let Some(version) = value.get("schema_version") {
        if version
            .as_u64()
            .is_none_or(|version| version > u32::MAX as u64)
        {
            return Err(fail(
                RegistryErrorCode::Malformed,
                "registry version field malformed",
            ));
        }
    }
    let version = value
        .get("schema_version")
        .and_then(serde_json::Value::as_u64);
    let state = match version {
        None => {
            let root: LegacyRoot = serde_json::from_value(value)
                .map_err(|_| fail(RegistryErrorCode::Malformed, "legacy index shape malformed"))?;
            let effective = root.schema_version.unwrap_or(1);
            if effective > 1 {
                return Err(fail(
                    RegistryErrorCode::UnsupportedVersion,
                    "unsupported registry version",
                ));
            }
            let entries = root
                .entries
                .into_iter()
                .map(|e| WireEntry {
                    id: e.id,
                    manifest_file: e.manifest_file,
                    digest: e.digest,
                    source_path: e.source_path,
                    registered_at: e.registered_at,
                    enabled: e.enabled,
                    kind: None,
                })
                .collect();
            IndexState {
                stored_version: root.schema_version,
                effective_version: effective,
                v2: false,
                entries,
            }
        }
        Some(0 | 1) => {
            let root: LegacyRoot = serde_json::from_value(value)
                .map_err(|_| fail(RegistryErrorCode::Malformed, "legacy index shape malformed"))?;
            let effective = root.schema_version.unwrap_or(1);
            let entries = root
                .entries
                .into_iter()
                .map(|e| WireEntry {
                    id: e.id,
                    manifest_file: e.manifest_file,
                    digest: e.digest,
                    source_path: e.source_path,
                    registered_at: e.registered_at,
                    enabled: e.enabled,
                    kind: None,
                })
                .collect();
            IndexState {
                stored_version: root.schema_version,
                effective_version: effective,
                v2: false,
                entries,
            }
        }
        Some(2) => {
            let root: V2Root = serde_json::from_value(value)
                .map_err(|_| fail(RegistryErrorCode::Malformed, "v2 index shape malformed"))?;
            if root.schema_version != 2
                || root.registry_kind != REGISTRY_KIND_V2
                || root.entries.iter().any(|entry| entry.kind.is_none())
            {
                return Err(fail(
                    RegistryErrorCode::Malformed,
                    "v2 marker or record kind invalid",
                ));
            }
            IndexState {
                stored_version: Some(2),
                effective_version: 2,
                v2: true,
                entries: root.entries,
            }
        }
        Some(_) => {
            return Err(fail(
                RegistryErrorCode::UnsupportedVersion,
                "unsupported registry version",
            ))
        }
    };
    validate_state(&state)?;
    Ok(state)
}

fn validate_state(state: &IndexState) -> Result<(), RegistryError> {
    if state.entries.len() > MAX_ENTRIES {
        return Err(fail(
            RegistryErrorCode::RegistryFull,
            "entry count limit exceeded",
        ));
    }
    let mut ids = HashSet::new();
    for entry in &state.entries {
        if !ids.insert(entry.id.as_str()) {
            return Err(fail(
                RegistryErrorCode::DuplicateId,
                "duplicate registration id",
            ));
        }
        let kind = entry.kind.unwrap_or(RegistrationKind::ConfigV1);
        if !valid_id(&entry.id, kind)
            || entry.manifest_file != kind.filename(&entry.id)
            || !valid_digest(&entry.digest)
        {
            return Err(fail(
                RegistryErrorCode::InvalidRecord,
                "registration fields invalid",
            ));
        }
        if builtin_ids().contains(&entry.id.as_str()) {
            return Err(fail(
                RegistryErrorCode::BuiltinCollision,
                "built-in id collision",
            ));
        }
    }
    Ok(())
}

fn valid_id(id: &str, kind: RegistrationKind) -> bool {
    if kind == RegistrationKind::ConfigV1 {
        let bytes = id.as_bytes();
        (3..=64).contains(&bytes.len())
            && bytes
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
            && bytes
                .first()
                .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            && bytes
                .last()
                .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    } else {
        (1..=64).contains(&id.len())
            && id.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
            && id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    }
}

fn valid_digest(digest: &str) -> bool {
    digest.strip_prefix("sha256:").is_some_and(|h| {
        h.len() == 64
            && h.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
fn digest(bytes: &[u8]) -> String {
    let hash = Sha256::digest(bytes);
    let encoded: String = hash.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("sha256:{encoded}")
}
/// Canonical built-in reservation table shared by owner validation and the CLI.
pub const BUILTIN_ADAPTER_IDS: &[&str] = &["claude-code", "codex"];
pub fn builtin_adapter_ids() -> &'static [&'static str] {
    BUILTIN_ADAPTER_IDS
}
fn builtin_ids() -> &'static [&'static str] {
    BUILTIN_ADAPTER_IDS
}

/// Resolves a registered host descriptor from its pinned owned copy. State
/// such as disabled or future-only declarations remains inspectable.
pub fn lookup_host_descriptor(
    home: &Path,
    id: &str,
) -> Result<RegisteredHostDescriptor, RegistryError> {
    let (entry, bytes) =
        read_pinned_descriptor(home, id, RegistrationKind::HostAdapterV1, MAX_OWNED_BYTES)?;
    let manifest =
        fornax_types::decode_host_adapter_manifest(&bytes).map_err(manifest_rejection)?;
    if manifest.id() != id {
        return Err(fail(
            RegistryErrorCode::DescriptorMismatch,
            "owned descriptor id mismatch",
        ));
    }
    Ok(RegisteredHostDescriptor { entry, manifest })
}

pub fn lookup_config_descriptor(
    home: &Path,
    id: &str,
) -> Result<RegisteredConfigDescriptor, RegistryError> {
    let (entry, raw_bytes) = read_pinned_descriptor(
        home,
        id,
        RegistrationKind::ConfigV1,
        MAX_CONFIG_MANIFEST_BYTES,
    )?;
    let mut deserializer = serde_json::Deserializer::from_slice(&raw_bytes);
    let raw = UniqueValue::deserialize(&mut deserializer)
        .map_err(|_| {
            fail(
                RegistryErrorCode::InvalidDescriptor,
                "owned configuration manifest malformed",
            )
        })?
        .0;
    deserializer.end().map_err(|_| {
        fail(
            RegistryErrorCode::InvalidDescriptor,
            "owned configuration manifest malformed",
        )
    })?;
    if raw.get("manifest_kind").is_some()
        || raw
            .get("schema_version")
            .and_then(serde_json::Value::as_u64)
            != Some(1)
        || raw.get("id").and_then(serde_json::Value::as_str) != Some(id)
    {
        return Err(fail(
            RegistryErrorCode::DescriptorMismatch,
            "owned configuration identity mismatch",
        ));
    }
    Ok(RegisteredConfigDescriptor { entry, raw_bytes })
}

fn read_pinned_descriptor(
    home: &Path,
    id: &str,
    expected: RegistrationKind,
    max_bytes: usize,
) -> Result<(RegistryEntry, Vec<u8>), RegistryError> {
    let directory = InspectionDirectory::open_existing(home)?.ok_or_else(|| {
        fail(
            RegistryErrorCode::RegistrationMissing,
            "registration not found",
        )
    })?;
    let state = directory.read_state()?;
    let wire = state
        .entries
        .iter()
        .find(|entry| entry.id == id)
        .ok_or_else(|| {
            fail(
                RegistryErrorCode::RegistrationMissing,
                "registration not found",
            )
        })?
        .clone();
    let entry = public_entry(wire);
    if entry.kind != expected {
        return Err(fail(
            RegistryErrorCode::WrongKind,
            "registration kind does not match lookup",
        ));
    }
    let bytes = directory
        .read_bounded(entry.manifest_file(), max_bytes)
        .map_err(|error| {
            fail(
                match error.kind() {
                    std::io::ErrorKind::InvalidInput => RegistryErrorCode::DescriptorUnsafeFileType,
                    std::io::ErrorKind::FileTooLarge => RegistryErrorCode::DescriptorOversized,
                    std::io::ErrorKind::InvalidData => RegistryErrorCode::DescriptorChanged,
                    _ => RegistryErrorCode::DescriptorUnavailable,
                },
                "owned descriptor unavailable or unsafe",
            )
        })?;
    if digest(&bytes) != entry.digest {
        return Err(fail(
            RegistryErrorCode::DescriptorMismatch,
            "owned descriptor digest mismatch",
        ));
    }
    let after = directory.read_state()?;
    if !after
        .entries
        .iter()
        .any(|row| public_entry(row.clone()) == entry)
    {
        return Err(fail(
            RegistryErrorCode::DescriptorMismatch,
            "registration changed during lookup",
        ));
    }
    Ok((entry, bytes))
}

/// Publishes a validated configuration manifest into the legacy index. This
/// remains schema v0/v1 and preserves historical configuration behavior.
pub fn register_config(
    home: &Path,
    registration: ConfigRegistration<'_>,
) -> Result<RegistryEntry, RegistryError> {
    if registration.raw_bytes.len() > MAX_CONFIG_MANIFEST_BYTES
        || !valid_id(registration.id, RegistrationKind::ConfigV1)
    {
        return Err(fail(
            RegistryErrorCode::InvalidRecord,
            "configuration registration invalid",
        ));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(registration.raw_bytes);
    let raw = UniqueValue::deserialize(&mut deserializer)
        .map_err(|_| {
            fail(
                RegistryErrorCode::InvalidRecord,
                "configuration manifest malformed",
            )
        })?
        .0;
    deserializer.end().map_err(|_| {
        fail(
            RegistryErrorCode::InvalidRecord,
            "configuration manifest malformed",
        )
    })?;
    if raw.get("manifest_kind").is_some()
        || raw
            .get("schema_version")
            .and_then(serde_json::Value::as_u64)
            != Some(1)
        || raw.get("id").and_then(serde_json::Value::as_str) != Some(registration.id)
    {
        return Err(fail(
            RegistryErrorCode::InvalidRecord,
            "configuration manifest identity invalid",
        ));
    }
    let row = WireEntry {
        id: registration.id.to_owned(),
        manifest_file: RegistrationKind::ConfigV1.filename(registration.id),
        digest: digest(registration.raw_bytes),
        source_path: registration.source_path.to_owned(),
        registered_at: registration.registered_at.to_owned(),
        enabled: true,
        kind: None,
    };
    register_bytes(home, row.clone(), registration.raw_bytes, false)?;
    Ok(public_entry(row))
}

/// Validates exact raw bytes through the shared pure host-manifest validator
/// and publishes an initially disabled descriptor in v2.
pub fn register_host_descriptor(
    home: &Path,
    source_path: &str,
    registered_at: &str,
    raw_bytes: &[u8],
) -> Result<RegistryEntry, RegistryError> {
    register_host_descriptor_with_publish(
        home,
        source_path,
        registered_at,
        raw_bytes,
        |directory, state, revision| directory.publish(state, revision),
    )
}

fn register_host_descriptor_with_publish(
    home: &Path,
    source_path: &str,
    registered_at: &str,
    raw_bytes: &[u8],
    publish: impl FnOnce(&InspectionDirectory, &IndexState, &IndexRevision) -> Result<(), RegistryError>,
) -> Result<RegistryEntry, RegistryError> {
    let manifest =
        fornax_types::decode_host_adapter_manifest(raw_bytes).map_err(manifest_rejection)?;
    let id = manifest.id();
    if !valid_id(id, RegistrationKind::HostAdapterV1) {
        return Err(fail(
            RegistryErrorCode::InvalidDescriptor,
            "descriptor identity invalid",
        ));
    }
    let validated_bytes = manifest.as_manifest_bytes();
    let entry = WireEntry {
        id: id.to_owned(),
        manifest_file: RegistrationKind::HostAdapterV1.filename(id),
        digest: digest(validated_bytes),
        source_path: source_path.to_owned(),
        registered_at: registered_at.to_owned(),
        enabled: false,
        kind: Some(RegistrationKind::HostAdapterV1),
    };
    register_bytes_with_publish(home, entry.clone(), validated_bytes, true, publish)?;
    Ok(public_entry(entry))
}

fn public_entry(entry: WireEntry) -> RegistryEntry {
    RegistryEntry {
        id: entry.id,
        manifest_file: entry.manifest_file,
        digest: entry.digest,
        source_path: entry.source_path,
        registered_at: entry.registered_at,
        enabled: entry.enabled,
        kind: entry.kind.unwrap_or(RegistrationKind::ConfigV1),
    }
}

fn register_bytes(
    home: &Path,
    entry: WireEntry,
    bytes: &[u8],
    upgrade: bool,
) -> Result<(), RegistryError> {
    register_bytes_with_publish(home, entry, bytes, upgrade, |directory, state, revision| {
        directory.publish(state, revision)
    })
}

fn register_bytes_with_publish(
    home: &Path,
    entry: WireEntry,
    bytes: &[u8],
    upgrade: bool,
    publish: impl FnOnce(&InspectionDirectory, &IndexState, &IndexRevision) -> Result<(), RegistryError>,
) -> Result<(), RegistryError> {
    let directory = InspectionDirectory::open_for_mutation(home)?;
    let _lock = directory.lock()?;
    let (mut state, revision) = directory.read_state_with_revision()?;
    if state.entries.iter().any(|old| old.id == entry.id) {
        return Err(fail(
            RegistryErrorCode::DuplicateId,
            "registration id already exists",
        ));
    }
    if builtin_ids().contains(&entry.id.as_str()) {
        return Err(fail(
            RegistryErrorCode::BuiltinCollision,
            "built-in id collision",
        ));
    }
    if state.entries.len() >= MAX_ENTRIES {
        return Err(fail(
            RegistryErrorCode::RegistryFull,
            "entry count limit exceeded",
        ));
    }
    if upgrade && !state.v2 {
        state.v2 = true;
        state.stored_version = Some(2);
        state.effective_version = 2;
        for old in &mut state.entries {
            if old.kind.is_none() {
                old.kind = Some(RegistrationKind::ConfigV1);
            }
        }
    }
    let mut entry = entry;
    if state.v2 && entry.kind.is_none() {
        entry.kind = Some(RegistrationKind::ConfigV1);
    }
    let final_name = entry.manifest_file.clone();
    let owned_created = directory.create_owned(&final_name, bytes)?;
    state.entries.push(entry);
    if let Err(error) = publish(&directory, &state, &revision) {
        if !error.index_published() {
            // Strict Retention (HORO-1745): `remove_owned` never deletes, so
            // this is an attempt at identity verification only, not a
            // cleanup this function can rely on. The orphaned invocation-
            // owned copy is retained at `final_name`; the original
            // publication error -- not a generic cleanup code -- remains
            // the fact that matters to the caller. A later registration of
            // the same id will refuse at `create_owned` (`EEXIST`) rather
            // than silently reuse or overwrite the retained file.
            let _ = directory.remove_owned(&final_name, owned_created);
        }
        return Err(error);
    }
    Ok(())
}

fn set_enabled(home: &Path, id: &str, enabled: bool) -> Result<(), RegistryError> {
    let directory = InspectionDirectory::open_for_mutation(home)?;
    let _lock = directory.lock()?;
    let (mut state, revision) = directory.read_state_with_revision()?;
    let row = state
        .entries
        .iter_mut()
        .find(|entry| entry.id == id)
        .ok_or_else(|| {
            fail(
                RegistryErrorCode::RegistrationMissing,
                "registration not found",
            )
        })?;
    if row.kind == Some(RegistrationKind::HostAdapterV1) && enabled {
        return Err(fail(
            RegistryErrorCode::ExecutionBoundaryUnavailable,
            "host execution boundary unavailable",
        ));
    }
    row.enabled = enabled;
    directory.publish(&state, &revision)
}

fn remove(home: &Path, id: &str) -> Result<(), RegistryError> {
    let directory = InspectionDirectory::open_for_mutation(home)?;
    let _lock = directory.lock()?;
    let (mut state, revision) = directory.read_state_with_revision()?;
    let index = state
        .entries
        .iter()
        .position(|entry| entry.id == id)
        .ok_or_else(|| {
            fail(
                RegistryErrorCode::RegistrationMissing,
                "registration not found",
            )
        })?;
    if state.entries[index].kind == Some(RegistrationKind::HostAdapterV1)
        && state.entries[index].enabled
    {
        return Err(fail(
            RegistryErrorCode::RegistrationEnabled,
            "host registration must be disabled before removal",
        ));
    }
    let removed = state.entries.remove(index);
    let owned_identity = directory.identity_if_regular(&removed.manifest_file);
    directory.publish(&state, &revision)?;
    match owned_identity {
        Ok(Some(identity)) => directory
            .remove_owned(&removed.manifest_file, identity)
            .map_err(|_| {
                fail_published(
                    RegistryErrorCode::CleanupFailed,
                    "registration removed but owned copy cleanup failed",
                )
            }),
        Ok(None) => Ok(()),
        Err(()) => Err(fail_published(
            RegistryErrorCode::CleanupFailed,
            "registration removed but owned copy could not be safely cleaned",
        )),
    }
}

#[cfg(unix)]
struct RegistryLock {
    _file: File,
}
#[cfg(not(unix))]
struct RegistryLock;

#[cfg(unix)]
struct InspectionDirectory {
    directory: File,
}

#[cfg(not(unix))]
struct InspectionDirectory;

#[cfg(unix)]
impl InspectionDirectory {
    fn open_existing(home: &Path) -> Result<Option<Self>, RegistryError> {
        let root = match rustix::fs::open(
            home,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        ) {
            Ok(root) => File::from(root),
            Err(error) if error == rustix::io::Errno::NOENT => return Ok(None),
            Err(_) => {
                return Err(fail(
                    RegistryErrorCode::Unavailable,
                    "home directory unavailable",
                ))
            }
        };
        match rustix::fs::openat(
            &root,
            "adapters",
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        ) {
            Ok(fd) => Ok(Some(Self {
                directory: File::from(fd),
            })),
            Err(error) if error == rustix::io::Errno::NOENT => Ok(None),
            Err(_) => Err(fail(
                RegistryErrorCode::Unavailable,
                "adapters directory unavailable or unsafe",
            )),
        }
    }
    fn open_for_mutation(home: &Path) -> Result<Self, RegistryError> {
        std::fs::create_dir_all(home).map_err(|_| {
            fail(
                RegistryErrorCode::Unavailable,
                "home directory creation failed",
            )
        })?;
        let root = File::from(
            rustix::fs::open(
                home,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NONBLOCK
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|_| fail(RegistryErrorCode::Unavailable, "home directory unavailable"))?,
        );
        let fd = match rustix::fs::openat(
            &root,
            "adapters",
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(error) if error == rustix::io::Errno::NOENT => {
                match rustix::fs::mkdirat(
                    &root,
                    "adapters",
                    rustix::fs::Mode::from_bits_truncate(0o700),
                ) {
                    Ok(()) => (),
                    Err(error) if error == rustix::io::Errno::EXIST => (),
                    Err(_) => {
                        return Err(fail(
                            RegistryErrorCode::Unavailable,
                            "adapters directory creation failed",
                        ))
                    }
                }
                rustix::fs::openat(
                    &root,
                    "adapters",
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::DIRECTORY
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::NONBLOCK
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )
                .map_err(|_| {
                    fail(
                        RegistryErrorCode::Unavailable,
                        "adapters directory creation failed",
                    )
                })?
            }
            Err(_) => {
                return Err(fail(
                    RegistryErrorCode::Unavailable,
                    "adapters directory unsafe",
                ))
            }
        };
        Ok(Self {
            directory: File::from(fd),
        })
    }
    fn read_bounded(&self, name: &str, max: usize) -> std::io::Result<Vec<u8>> {
        use std::os::unix::fs::MetadataExt;
        let file = File::from(
            rustix::fs::openat(
                &self.directory,
                name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::NONBLOCK
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|error| {
                if error == rustix::io::Errno::LOOP {
                    std::io::Error::from(std::io::ErrorKind::InvalidInput)
                } else {
                    std::io::Error::from(error)
                }
            })?,
        );
        let before = file.metadata()?;
        if !before.is_file() {
            return Err(std::io::ErrorKind::InvalidInput.into());
        }
        if before.len() > max as u64 {
            return Err(std::io::ErrorKind::FileTooLarge.into());
        }
        let mut bytes = Vec::with_capacity(before.len() as usize);
        (&file).take(max as u64 + 1).read_to_end(&mut bytes)?;
        let after = file.metadata()?;
        if before.len() != after.len()
            || before.ino() != after.ino()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
        {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
        }
        if bytes.len() > max {
            return Err(std::io::ErrorKind::FileTooLarge.into());
        }
        Ok(bytes)
    }
    fn read_index_bytes(&self) -> Result<Option<Vec<u8>>, RegistryError> {
        match self.read_bounded(REGISTRY_INDEX_FILE, MAX_INDEX_BYTES) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) if e.kind() == std::io::ErrorKind::FileTooLarge => Err(fail(
                RegistryErrorCode::IndexOversized,
                "index byte capacity exceeded",
            )),
            Err(_) => Err(fail(
                RegistryErrorCode::Malformed,
                "registry index unavailable or unsafe",
            )),
        }
    }
    fn read_state_with_revision(&self) -> Result<(IndexState, IndexRevision), RegistryError> {
        let bytes = self.read_index_bytes()?;
        let state = bytes
            .as_deref()
            .map(decode_index)
            .transpose()?
            .unwrap_or_else(IndexState::empty);
        Ok((state, IndexRevision(bytes)))
    }
    fn read_state(&self) -> Result<IndexState, RegistryError> {
        self.read_state_with_revision().map(|(state, _)| state)
    }
    fn lock(&self) -> Result<RegistryLock, RegistryError> {
        use rustix::fs::{fstat, FileType, FlockOperation, Mode, OFlags};
        let fd = rustix::fs::openat(
            &self.directory,
            LOCK_FILE,
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(|_| {
            fail(
                RegistryErrorCode::Unavailable,
                "registry lock unsafe or unavailable",
            )
        })?;
        let file = File::from(fd);
        if FileType::from_raw_mode(
            fstat(&file)
                .map_err(|_| fail(RegistryErrorCode::Unavailable, "registry lock unavailable"))?
                .st_mode,
        ) != FileType::RegularFile
        {
            return Err(fail(
                RegistryErrorCode::Unavailable,
                "registry lock is not regular",
            ));
        }
        let deadline = Instant::now() + LOCK_WAIT;
        loop {
            match rustix::fs::flock(&file, FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => return Ok(RegistryLock { _file: file }),
                Err(error)
                    if error == rustix::io::Errno::AGAIN
                        || error == rustix::io::Errno::WOULDBLOCK =>
                {
                    if Instant::now() >= deadline {
                        return Err(fail(RegistryErrorCode::RegistryBusy, "registry is busy"));
                    }
                    std::thread::sleep(LOCK_POLL);
                }
                Err(_) => return Err(fail(RegistryErrorCode::Unavailable, "registry lock failed")),
            }
        }
    }
    fn create_owned(&self, name: &str, bytes: &[u8]) -> Result<CreatedIdentity, RegistryError> {
        use rustix::fs::{Mode, OFlags};
        let mut file = File::from(
            rustix::fs::openat(
                &self.directory,
                name,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_bits_truncate(0o600),
            )
            .map_err(|e| {
                if e == rustix::io::Errno::EXIST {
                    // This is not a malformed registration -- the new bytes
                    // are fine. Something already occupies this exact
                    // destination name; most often a prior removal's
                    // retained owned file (Strict Retention, HORO-1745,
                    // never deleted by design), but this call site cannot
                    // tell that apart from a file placed there outside the
                    // registry. Either way it must be cleared by hand
                    // before this id can be registered again.
                    fail(
                        RegistryErrorCode::OwnedDestinationOccupied,
                        "a file already occupies this id's owned destination",
                    )
                } else {
                    fail(RegistryErrorCode::Io, "owned file creation failed")
                }
            })?,
        );
        let metadata = file.metadata().map_err(|_| {
            fail(
                RegistryErrorCode::CleanupFailed,
                "owned copy created but its identity could not be verified",
            )
        })?;
        let identity = CreatedIdentity {
            device: std::os::unix::fs::MetadataExt::dev(&metadata),
            inode: std::os::unix::fs::MetadataExt::ino(&metadata),
        };
        if file
            .write_all(bytes)
            .and_then(|()| file.sync_all())
            .is_err()
        {
            // Strict Retention (HORO-1745): the half-written copy is
            // retained at `name`, not deleted; see `remove_owned`'s doc
            // comment. The write failure, not a generic cleanup code,
            // remains the fact that matters to the caller.
            let _ = self.remove_owned(name, identity);
            return Err(fail(RegistryErrorCode::Io, "owned file write failed"));
        }
        Ok(identity)
    }
    /// Verifies `name` is still the exact invocation-owned inode, then
    /// retains it rather than deleting it (HORO-1745: Strict Retention,
    /// owner-accepted 2026-10-08).
    ///
    /// `fstat`-verify-identity cannot be followed by a race-free pathname
    /// `unlinkat`: POSIX has no atomic "unlink this exact already-open inode
    /// by name" primitive, so a same-user noncooperating writer can replace
    /// the file in the window between the identity check and any subsequent
    /// unlink, causing deletion of a different inode than the one verified.
    /// Narrowing the check (shorter window, extra retries, a directory-
    /// replacement guard) only shrinks the window; it cannot close it, and a
    /// cooperating-writer assumption is exactly the assumption this finding
    /// showed is not load-bearing here.
    ///
    /// The accepted policy is to never take that risk: this function always
    /// returns `Err(())`, whether or not the identity check above succeeds,
    /// so every caller takes its existing "could not be safely cleaned" /
    /// `CleanupFailed` path. An invocation-owned staging or descriptor file
    /// this function would otherwise have deleted is left on disk, inert and
    /// unreferenced by the index once the index mutation itself has
    /// committed. The accepted cost is that a removed id's filename is not
    /// released until something else clears the orphan: re-registering the
    /// same id will refuse at `create_owned` (`EEXIST`) rather than silently
    /// reusing or overwriting it.
    fn remove_owned(&self, name: &str, created: CreatedIdentity) -> Result<(), ()> {
        use std::os::unix::fs::MetadataExt;
        let file = File::from(
            rustix::fs::openat(
                &self.directory,
                name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::NONBLOCK
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|_| ())?,
        );
        let metadata = file.metadata().map_err(|_| ())?;
        if metadata.dev() != created.device || metadata.ino() != created.inode {
            // Not the invocation-owned inode at all -- retained for the same
            // reason as the verified-identity case below, via the same
            // outcome.
            return Err(());
        }
        // Identity verified; still never deleted. See the doc comment above.
        Err(())
    }
    fn identity_if_regular(&self, name: &str) -> Result<Option<CreatedIdentity>, ()> {
        use rustix::fs::{fstat, FileType, Mode, OFlags};
        use std::os::unix::fs::MetadataExt;
        let file = match rustix::fs::openat(
            &self.directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => File::from(fd),
            Err(error) if error == rustix::io::Errno::NOENT => return Ok(None),
            Err(_) => return Err(()),
        };
        let stat = fstat(&file).map_err(|_| ())?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
            return Err(());
        }
        let metadata = file.metadata().map_err(|_| ())?;
        Ok(Some(CreatedIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        }))
    }
    fn publish(&self, state: &IndexState, expected: &IndexRevision) -> Result<(), RegistryError> {
        self.publish_with_hook(state, expected, || {}, || true)
    }
    fn publish_with_hook<F: FnOnce(), G: FnOnce() -> bool>(
        &self,
        state: &IndexState,
        expected: &IndexRevision,
        before_revision_check: F,
        after_rename: G,
    ) -> Result<(), RegistryError> {
        let bytes = state.encode()?;
        let staging = format!("registry.json.tmp-{}", uuid::Uuid::new_v4());
        let mut file = File::from(
            rustix::fs::openat(
                &self.directory,
                &staging,
                rustix::fs::OFlags::WRONLY
                    | rustix::fs::OFlags::CREATE
                    | rustix::fs::OFlags::EXCL
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::from_bits_truncate(0o600),
            )
            .map_err(|_| fail(RegistryErrorCode::Io, "index staging creation failed"))?,
        );
        let metadata = file.metadata().map_err(|_| {
            fail(
                RegistryErrorCode::CleanupFailed,
                "index staging created but its identity could not be verified",
            )
        })?;
        let identity = CreatedIdentity {
            device: std::os::unix::fs::MetadataExt::dev(&metadata),
            inode: std::os::unix::fs::MetadataExt::ino(&metadata),
        };
        // Strict Retention (HORO-1745): every `remove_owned` call on the
        // random-uuid-named staging file below is identity verification
        // only, never deletion -- see its doc comment. The staging name is
        // single-use and never looked up again, so a retained one is
        // harmless disk litter, not a re-registration hazard; it must never
        // be allowed to mask the real pre-commit error (write/revision/
        // rename failure) behind a generic cleanup code.
        if file
            .write_all(&bytes)
            .and_then(|()| file.sync_all())
            .is_err()
        {
            let _ = self.remove_owned(&staging, identity);
            return Err(fail(RegistryErrorCode::Io, "index staging write failed"));
        }
        before_revision_check();
        let current = match self.read_index_bytes() {
            Ok(current) => current,
            Err(error) => {
                let _ = self.remove_owned(&staging, identity);
                return Err(error);
            }
        };
        if &IndexRevision(current) != expected {
            let _ = self.remove_owned(&staging, identity);
            return Err(fail(
                RegistryErrorCode::RegistryChanged,
                "registry changed before publication",
            ));
        }
        if rustix::fs::renameat(
            &self.directory,
            &staging,
            &self.directory,
            REGISTRY_INDEX_FILE,
        )
        .is_err()
        {
            let _ = self.remove_owned(&staging, identity);
            return Err(fail(RegistryErrorCode::Io, "index publication failed"));
        }
        if !after_rename() {
            return Err(fail_published(
                RegistryErrorCode::CommittedUnverified,
                "index committed but verification failed",
            ));
        }
        if rustix::fs::fsync(&self.directory).is_err() {
            return Err(fail_published(
                RegistryErrorCode::CommittedUnverified,
                "index committed but directory sync failed",
            ));
        }
        match self
            .read_bounded(REGISTRY_INDEX_FILE, MAX_INDEX_BYTES)
            .and_then(|observed| {
                decode_index(&observed)
                    .map(|_| observed)
                    .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))
            }) {
            Ok(observed) if observed == bytes => Ok(()),
            _ => Err(fail_published(
                RegistryErrorCode::CommittedUnverified,
                "index committed but verification failed",
            )),
        }
    }
}

#[cfg(not(unix))]
impl InspectionDirectory {
    fn open_existing(_home: &Path) -> Result<Option<Self>, RegistryError> {
        Err(fail(
            RegistryErrorCode::Unavailable,
            "safe registry reads unsupported on this platform",
        ))
    }
    fn open_for_mutation(_home: &Path) -> Result<Self, RegistryError> {
        Err(fail(
            RegistryErrorCode::Unavailable,
            "registry mutation unsupported on this platform",
        ))
    }
    fn read_bounded(&self, _name: &str, _max: usize) -> std::io::Result<Vec<u8>> {
        Err(std::io::ErrorKind::Unsupported.into())
    }
    fn read_state(&self) -> Result<IndexState, RegistryError> {
        Err(fail(RegistryErrorCode::Unavailable, "registry unavailable"))
    }
    fn read_state_with_revision(&self) -> Result<(IndexState, IndexRevision), RegistryError> {
        Err(fail(RegistryErrorCode::Unavailable, "registry unavailable"))
    }
    fn lock(&self) -> Result<RegistryLock, RegistryError> {
        Err(fail(
            RegistryErrorCode::Unavailable,
            "registry lock unsupported",
        ))
    }
    fn create_owned(&self, _name: &str, _bytes: &[u8]) -> Result<CreatedIdentity, RegistryError> {
        Err(fail(RegistryErrorCode::Unavailable, "registry unsupported"))
    }
    fn remove_owned(&self, _name: &str, _created: CreatedIdentity) -> Result<(), ()> {
        Err(())
    }
    fn identity_if_regular(&self, _name: &str) -> Result<Option<CreatedIdentity>, ()> {
        Err(())
    }
    fn publish(&self, _state: &IndexState, _expected: &IndexRevision) -> Result<(), RegistryError> {
        Err(fail(RegistryErrorCode::Unavailable, "registry unsupported"))
    }
}

/// Owner mutation API. Host enable is refused until an execution owner exists.
pub fn set_registration_enabled(home: &Path, id: &str, enabled: bool) -> Result<(), RegistryError> {
    set_enabled(home, id, enabled)
}
pub fn remove_registration(home: &Path, id: &str) -> Result<(), RegistryError> {
    remove(home, id)
}

#[cfg(all(test, unix))]
mod owner_publication_tests {
    use super::*;

    #[test]
    fn prepublication_revision_drift_preserves_external_index_and_retains_stage() {
        let home =
            std::env::temp_dir().join(format!("fornax-registry-drift-{}", uuid::Uuid::new_v4()));
        let dir = home.join("adapters");
        std::fs::create_dir_all(&dir).unwrap();
        let index = dir.join(REGISTRY_INDEX_FILE);
        let original = br#"{"schema_version":1,"entries":[]}"#;
        let external = br#"{"schema_version":1,"entries":[],"external_change":true}"#;
        std::fs::write(&index, original).unwrap();
        let held = InspectionDirectory::open_existing(&home).unwrap().unwrap();
        let (state, revision) = held.read_state_with_revision().unwrap();

        let error = held
            .publish_with_hook(
                &state,
                &revision,
                || std::fs::write(&index, external).unwrap(),
                || true,
            )
            .unwrap_err();
        assert_eq!(error.code(), RegistryErrorCode::RegistryChanged);
        assert!(!error.index_published());
        assert_eq!(std::fs::read(&index).unwrap(), external);
        let names = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(
            names.len(),
            2,
            "the invocation-owned staging file is retained, not deleted (HORO-1745 Strict Retention)"
        );
        assert!(names.contains(&REGISTRY_INDEX_FILE.into()));
        std::fs::remove_dir_all(home).ok();
    }

    #[test]
    fn postrename_verification_failure_reports_committed_index() {
        let home = std::env::temp_dir().join(format!(
            "fornax-registry-committed-{}",
            uuid::Uuid::new_v4()
        ));
        let dir = home.join("adapters");
        std::fs::create_dir_all(&dir).unwrap();
        let index = dir.join(REGISTRY_INDEX_FILE);
        let original = br#"{"schema_version":1,"entries":[]}"#;
        std::fs::write(&index, original).unwrap();
        let held = InspectionDirectory::open_existing(&home).unwrap().unwrap();
        let (state, revision) = held.read_state_with_revision().unwrap();

        let error = held
            .publish_with_hook(&state, &revision, || {}, || false)
            .unwrap_err();
        assert_eq!(error.code(), RegistryErrorCode::CommittedUnverified);
        assert!(error.index_published());
        let published: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&index).unwrap()).unwrap();
        assert_eq!(published["schema_version"], 1);
        std::fs::remove_dir_all(home).ok();
    }

    #[test]
    fn complete_host_registration_retains_published_descriptor_after_verification_failure() {
        let home = std::env::temp_dir().join(format!(
            "fornax-registration-fault-{}",
            uuid::Uuid::new_v4()
        ));
        let raw = serde_json::to_vec(&serde_json::json!({
            "manifest_kind":"host-adapter", "manifest_version":1,
            "adapter_id":"published_fixture", "adapter_version":"1.0.0",
            "protocol_versions":[1], "contract_version_range":{"minimum":1,"maximum":1},
            "roles":["IdentitySource"], "capabilities":["identity.agent"],
            "host_version_constraints":[{"provider":"synthetic_host","minimum":null,"maximum":null}],
            "configuration_schema":{"type":"object","properties":{},"additionalProperties":false},
            "launch":{"executable":"/nonexistent/synthetic-owner-fault","argv":[]},
            "runtime_files":[], "input_limits":{"max_bytes":1048576},
            "needs":{"environment":[],"read_paths":[],"write_paths":[]}
        })).unwrap();
        let error = register_host_descriptor_with_publish(
            &home,
            "synthetic-source",
            "fixture",
            &raw,
            |directory, state, revision| {
                directory.publish_with_hook(state, revision, || {}, || false)
            },
        )
        .unwrap_err();
        assert_eq!(error.code(), RegistryErrorCode::CommittedUnverified);
        assert!(error.index_published());
        let snapshot = read_registry(&home).unwrap();
        assert_eq!(snapshot.entries().len(), 1);
        assert_eq!(snapshot.effective_schema_version(), 2);
        let retained = lookup_host_descriptor(&home, "published_fixture").unwrap();
        assert!(!retained.entry().enabled());
        assert_eq!(retained.manifest().as_manifest_bytes(), raw);
        assert_eq!(
            std::fs::read(home.join("adapters/published_fixture.host-adapter.json")).unwrap(),
            raw
        );
        let before = std::fs::read(home.join("adapters/registry.json")).unwrap();
        let retry =
            register_host_descriptor(&home, "synthetic-source", "fixture", &raw).unwrap_err();
        assert_eq!(retry.code(), RegistryErrorCode::DuplicateId);
        assert!(!retry.index_published());
        assert_eq!(
            std::fs::read(home.join("adapters/registry.json")).unwrap(),
            before
        );
        std::fs::remove_dir_all(home).ok();
    }
}
