//! External adapter manifest schema (ADR-0023, FORNX-428 S6).
//!
//! A manifest is a declarative, data-only description of one marker-based
//! config mutation. There is deliberately no field naming an executable,
//! entrypoint, or command to run -- an unknown field (including one named
//! `executable`/`entrypoint`/`command`/`script`) is a parse failure, not a
//! silently-ignored key, because every struct here is
//! `#[serde(deny_unknown_fields)]`.

use std::path::PathBuf;

/// Manifest schema versions this build understands. Gated the same way
/// `fornax-types::audit`'s `SUPPORTED_AUDIT_SCHEMA_VERSIONS` is: an
/// unsupported version is a specific, named rejection, not a confusing
/// field-level parse error.
pub const SUPPORTED_MANIFEST_SCHEMA_VERSIONS: &[u32] = &[1];

/// Manifest file size ceiling (ADR-0023 D7).
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;
/// Operation count ceiling per manifest.
pub const MAX_OPERATIONS: usize = 16;
/// JSON pointer length ceiling, in bytes.
pub const MAX_POINTER_BYTES: usize = 256;
/// JSON pointer depth ceiling, in `/`-separated segments.
pub const MAX_POINTER_DEPTH: usize = 16;
/// Serialized `element` size ceiling.
pub const MAX_ELEMENT_BYTES: usize = 4 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    Plan,
    Install,
    Uninstall,
}

impl Capability {
    pub fn as_str(self) -> &'static str {
        match self {
            Capability::Plan => "plan",
            Capability::Install => "install",
            Capability::Uninstall => "uninstall",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum TargetFormat {
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub format: TargetFormat,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    EnsureMarkedArrayElement {
        pointer: String,
        marker_key: String,
        marker_value: String,
        element: serde_json::Value,
    },
}

/// The wire shape serde deserializes directly -- validated and converted
/// into [`AdapterManifest`] by `TryFrom`, mirroring
/// `fornax-types::audit::AuditEventWire`'s established pattern in this repo.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterManifestWire {
    pub schema_version: u32,
    pub id: String,
    pub display_name: String,
    pub summary: String,
    pub min_fornax_version: String,
    pub provenance: String,
    pub capabilities: Vec<Capability>,
    pub target: Target,
    pub operations: Vec<Operation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterManifest {
    pub id: String,
    pub display_name: String,
    pub summary: String,
    pub min_fornax_version: (u64, u64, u64),
    pub provenance: String,
    pub capabilities: Vec<Capability>,
    pub target_format: TargetFormat,
    /// Already validated and resolved to an absolute, `$HOME`-contained
    /// path (ADR-0023 D6). Never the raw manifest string.
    pub target_path: PathBuf,
    pub operations: Vec<Operation>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManifestError {
    #[error("unsupported manifest schema_version {got} (this build supports {supported:?})")]
    UnsupportedSchemaVersion { got: u32, supported: Vec<u32> },
    #[error("manifest exceeds the {MAX_MANIFEST_BYTES}-byte size limit ({got} bytes)")]
    TooLarge { got: usize },
    #[error(
        "invalid adapter id {id:?}: must be 3-64 ASCII lowercase alphanumeric/hyphen \
         characters, starting and ending with an alphanumeric character"
    )]
    InvalidId { id: String },
    #[error("display_name must be 1-64 characters with no control characters")]
    InvalidDisplayName,
    #[error("summary must be 1-200 characters with no control characters")]
    InvalidSummary,
    #[error("provenance must be 1-256 characters with no control characters")]
    InvalidProvenance,
    #[error("min_fornax_version {0:?} must be of the form MAJOR.MINOR.PATCH (plain integers)")]
    InvalidVersion(String),
    #[error(
        "this build of fornax ({running}) is older than the adapter's \
         min_fornax_version ({required})"
    )]
    FornaxTooOld { running: String, required: String },
    #[error("capabilities must declare at least one of plan/install/uninstall")]
    EmptyCapabilities,
    #[error("duplicate capability {0:?} declared more than once")]
    DuplicateCapability(&'static str),
    #[error(
        "capabilities declare {0:?} but operations is empty -- install/uninstall need at \
         least one operation"
    )]
    MissingOperationsForCapability(&'static str),
    #[error("operations must declare at least 1 and at most {MAX_OPERATIONS} entries")]
    OperationCountOutOfBounds,
    #[error("duplicate operation targeting pointer {0:?} with the same marker")]
    DuplicateOperation(String),
    #[error("operation pointer {pointer:?} exceeds the {MAX_POINTER_BYTES}-byte length limit")]
    PointerTooLong { pointer: String },
    #[error("operation pointer {pointer:?} exceeds the {MAX_POINTER_DEPTH}-segment depth limit")]
    PointerTooDeep { pointer: String },
    #[error("operation pointer {0:?} is not a valid RFC 6901 JSON pointer (must start with '/')")]
    InvalidPointer(String),
    #[error("operation element exceeds the {MAX_ELEMENT_BYTES}-byte size limit")]
    ElementTooLarge,
    #[error(
        "operation element at key {marker_key:?} is {actual:?}, but marker_value is {expected:?} \
         -- an adapter must be able to find and remove exactly what it installs"
    )]
    MarkerMismatch {
        marker_key: String,
        expected: String,
        actual: String,
    },
    #[error("target.path must not be empty")]
    EmptyTargetPath,
    #[error(
        "target.path {0:?} uses unsupported tilde syntax -- only a single leading '~/' is allowed"
    )]
    UnsupportedTilde(String),
    #[error("target.path {0:?} must resolve under the current user's home directory")]
    PathEscapesHome(String),
    #[error("target.path {0:?} must not contain a '..' component")]
    PathTraversal(String),
    #[error(
        "target.path {path:?} has extension {ext:?}, which does not match target.format {format:?}"
    )]
    PathExtensionMismatch {
        path: String,
        ext: String,
        format: &'static str,
    },
}

fn validate_id(id: &str) -> Result<(), ManifestError> {
    let len_ok = (3..=64).contains(&id.len());
    let charset_ok = id
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    let ends_ok = id
        .bytes()
        .next()
        .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && id
            .bytes()
            .last()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    if len_ok && charset_ok && ends_ok {
        Ok(())
    } else {
        Err(ManifestError::InvalidId { id: id.to_string() })
    }
}

fn no_control_chars(s: &str) -> bool {
    !s.chars().any(|c| c.is_control())
}

fn parse_version_triple(s: &str) -> Result<(u64, u64, u64), ManifestError> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 3 {
        return Err(ManifestError::InvalidVersion(s.to_string()));
    }
    let mut nums = [0u64; 3];
    for (i, part) in parts.iter().enumerate() {
        nums[i] = part
            .parse::<u64>()
            .map_err(|_| ManifestError::InvalidVersion(s.to_string()))?;
    }
    Ok((nums[0], nums[1], nums[2]))
}

/// This build's own version, parsed the same way, for the compatibility
/// check against a manifest's `min_fornax_version`.
pub fn running_fornax_version() -> (u64, u64, u64) {
    parse_version_triple(env!("CARGO_PKG_VERSION"))
        .expect("CARGO_PKG_VERSION is always MAJOR.MINOR.PATCH")
}

fn validate_pointer(pointer: &str) -> Result<(), ManifestError> {
    if pointer.len() > MAX_POINTER_BYTES {
        return Err(ManifestError::PointerTooLong {
            pointer: pointer.to_string(),
        });
    }
    if !pointer.is_empty() && !pointer.starts_with('/') {
        return Err(ManifestError::InvalidPointer(pointer.to_string()));
    }
    let depth = pointer.matches('/').count();
    if depth > MAX_POINTER_DEPTH {
        return Err(ManifestError::PointerTooDeep {
            pointer: pointer.to_string(),
        });
    }
    Ok(())
}

/// ADR-0023 D6: resolves and validates `target.path` into an absolute,
/// `$HOME`-contained path with no traversal, matching `target.format`'s
/// extension. `home` is injected so tests never depend on the real `$HOME`.
pub fn resolve_target_path(
    raw: &str,
    format: TargetFormat,
    home: &std::path::Path,
) -> Result<PathBuf, ManifestError> {
    if raw.is_empty() {
        return Err(ManifestError::EmptyTargetPath);
    }
    if raw.contains("..") {
        return Err(ManifestError::PathTraversal(raw.to_string()));
    }
    // Exactly one accepted form: a leading "~/", joined under `home`. Any
    // other tilde form ("~" alone, "~user") is rejected by name; anything
    // else at all -- a bare absolute path (e.g. "/etc/passwd.json"), a
    // bare relative path, anything -- is rejected as escaping home. A raw
    // absolute path must NEVER be silently re-rooted under `home` by
    // stripping its leading '/' (that would turn "/etc/passwd.json" into
    // an accepted in-home path, defeating this entire containment check).
    let rest = match raw.strip_prefix("~/") {
        Some(stripped) => stripped,
        None if raw == "~" || raw.starts_with('~') => {
            return Err(ManifestError::UnsupportedTilde(raw.to_string()));
        }
        None => return Err(ManifestError::PathEscapesHome(raw.to_string())),
    };

    let candidate = home.join(rest);
    let normalized = normalize_lexically(&candidate);
    let normalized_home = normalize_lexically(home);
    if !normalized.starts_with(&normalized_home) || normalized == normalized_home {
        return Err(ManifestError::PathEscapesHome(raw.to_string()));
    }

    let expected_ext = match format {
        TargetFormat::Json => "json",
    };
    let ext = normalized
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    if ext != expected_ext {
        return Err(ManifestError::PathExtensionMismatch {
            path: raw.to_string(),
            ext: ext.to_string(),
            format: match format {
                TargetFormat::Json => "json",
            },
        });
    }

    Ok(normalized)
}

/// Lexical (no filesystem access) `.`/`..`-free normalization. Callers have
/// already rejected any literal ".." component in the raw manifest string;
/// this only collapses what `PathBuf::join` leaves behind (e.g. nothing in
/// practice today, but kept explicit and total rather than assumed).
fn normalize_lexically(path: &std::path::Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other),
        }
    }
    out
}

impl TryFrom<AdapterManifestWire> for AdapterManifest {
    type Error = ManifestError;

    fn try_from(w: AdapterManifestWire) -> Result<Self, Self::Error> {
        Self::validate_and_build(w, &crate::dirs_home())
    }
}

impl AdapterManifest {
    /// Testable entry point taking an injected home directory -- the real
    /// `TryFrom` always calls this with `crate::dirs_home()`.
    pub fn validate_and_build(
        w: AdapterManifestWire,
        home: &std::path::Path,
    ) -> Result<Self, ManifestError> {
        if !SUPPORTED_MANIFEST_SCHEMA_VERSIONS.contains(&w.schema_version) {
            return Err(ManifestError::UnsupportedSchemaVersion {
                got: w.schema_version,
                supported: SUPPORTED_MANIFEST_SCHEMA_VERSIONS.to_vec(),
            });
        }
        validate_id(&w.id)?;
        if w.display_name.is_empty()
            || w.display_name.len() > 64
            || !no_control_chars(&w.display_name)
        {
            return Err(ManifestError::InvalidDisplayName);
        }
        if w.summary.is_empty() || w.summary.len() > 200 || !no_control_chars(&w.summary) {
            return Err(ManifestError::InvalidSummary);
        }
        if w.provenance.is_empty() || w.provenance.len() > 256 || !no_control_chars(&w.provenance) {
            return Err(ManifestError::InvalidProvenance);
        }

        let min_version = parse_version_triple(&w.min_fornax_version)?;
        let running = running_fornax_version();
        if running < min_version {
            return Err(ManifestError::FornaxTooOld {
                running: env!("CARGO_PKG_VERSION").to_string(),
                required: w.min_fornax_version.clone(),
            });
        }

        if w.capabilities.is_empty() {
            return Err(ManifestError::EmptyCapabilities);
        }
        let mut seen_caps = std::collections::HashSet::new();
        for cap in &w.capabilities {
            if !seen_caps.insert(*cap) {
                return Err(ManifestError::DuplicateCapability(cap.as_str()));
            }
        }
        let needs_ops = w.capabilities.contains(&Capability::Install)
            || w.capabilities.contains(&Capability::Uninstall);
        if needs_ops && w.operations.is_empty() {
            let which = if w.capabilities.contains(&Capability::Install) {
                "install"
            } else {
                "uninstall"
            };
            return Err(ManifestError::MissingOperationsForCapability(which));
        }

        if w.operations.is_empty() || w.operations.len() > MAX_OPERATIONS {
            return Err(ManifestError::OperationCountOutOfBounds);
        }
        let mut seen_ops = std::collections::HashSet::new();
        for op in &w.operations {
            let Operation::EnsureMarkedArrayElement {
                pointer,
                marker_key,
                marker_value,
                element,
            } = op;
            validate_pointer(pointer)?;
            let key = format!("{pointer}\u{0}{marker_key}\u{0}{marker_value}");
            if !seen_ops.insert(key) {
                return Err(ManifestError::DuplicateOperation(pointer.clone()));
            }
            let serialized = serde_json::to_vec(element).unwrap_or_default();
            if serialized.len() > MAX_ELEMENT_BYTES {
                return Err(ManifestError::ElementTooLarge);
            }
            let actual = element.get(marker_key).and_then(|v| v.as_str());
            if actual != Some(marker_value.as_str()) {
                return Err(ManifestError::MarkerMismatch {
                    marker_key: marker_key.clone(),
                    expected: marker_value.clone(),
                    actual: actual.unwrap_or("<missing>").to_string(),
                });
            }
        }

        let target_path = resolve_target_path(&w.target.path, w.target.format, home)?;

        Ok(AdapterManifest {
            id: w.id,
            display_name: w.display_name,
            summary: w.summary,
            min_fornax_version: min_version,
            provenance: w.provenance,
            capabilities: w.capabilities,
            target_format: w.target.format,
            target_path,
            operations: w.operations,
        })
    }
}

/// `sha256:<64 lowercase hex>` over raw bytes -- the exact bytes shown to
/// the user during review, never a canonicalized re-serialization (ADR-0023
/// D5).
pub fn digest_of(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let hash = hasher.finalize();
    let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256:{hex}")
}

/// Parses manifest bytes end to end: size bound, JSON parse, schema/field
/// validation, target-path containment -- everything that can be checked
/// without touching the target file.
pub fn parse_manifest_bytes(
    bytes: &[u8],
    home: &std::path::Path,
) -> anyhow::Result<AdapterManifest> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(ManifestError::TooLarge { got: bytes.len() }.into());
    }
    let wire: AdapterManifestWire = serde_json::from_slice(bytes)?;
    Ok(AdapterManifest::validate_and_build(wire, home)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home() -> PathBuf {
        PathBuf::from("/Users/fixture-home")
    }

    fn valid_wire() -> AdapterManifestWire {
        AdapterManifestWire {
            schema_version: 1,
            id: "acme-agent".to_string(),
            display_name: "Acme Agent".to_string(),
            summary: "Wires the Fornax hook into Acme Agent's settings.json.".to_string(),
            min_fornax_version: "0.0.1".to_string(),
            provenance: "https://example.com/acme-agent".to_string(),
            capabilities: vec![Capability::Plan, Capability::Install, Capability::Uninstall],
            target: Target {
                format: TargetFormat::Json,
                path: "~/.acme/settings.json".to_string(),
            },
            operations: vec![Operation::EnsureMarkedArrayElement {
                pointer: "/hooks/PostToolUse".to_string(),
                marker_key: "command".to_string(),
                marker_value: "fornax-hook-acme".to_string(),
                element: serde_json::json!({"type": "command", "command": "fornax-hook-acme"}),
            }],
        }
    }

    #[test]
    fn valid_manifest_builds_successfully() {
        let m = AdapterManifest::validate_and_build(valid_wire(), &home()).expect("valid");
        assert_eq!(m.id, "acme-agent");
        assert_eq!(m.target_path, home().join(".acme/settings.json"));
    }

    #[test]
    fn unsupported_schema_version_is_a_named_rejection() {
        let mut w = valid_wire();
        w.schema_version = 99;
        let err = AdapterManifest::validate_and_build(w, &home()).unwrap_err();
        assert!(matches!(
            err,
            ManifestError::UnsupportedSchemaVersion { got: 99, .. }
        ));
    }

    #[test]
    fn unknown_manifest_field_is_a_parse_failure_naming_the_field() {
        let mut v: serde_json::Value = serde_json::to_value(valid_wire()).unwrap();
        v.as_object_mut()
            .unwrap()
            .insert("token".to_string(), serde_json::json!("super-secret"));
        let err = serde_json::from_value::<AdapterManifestWire>(v).unwrap_err();
        assert!(err.to_string().contains("token"));
    }

    #[test]
    fn manifest_with_executable_or_entrypoint_field_fails_to_parse() {
        for bad_field in ["executable", "entrypoint", "command", "script"] {
            let mut v: serde_json::Value = serde_json::to_value(valid_wire()).unwrap();
            v.as_object_mut()
                .unwrap()
                .insert(bad_field.to_string(), serde_json::json!("/bin/sh"));
            let err = serde_json::from_value::<AdapterManifestWire>(v).unwrap_err();
            assert!(
                err.to_string().contains(bad_field),
                "expected rejection naming {bad_field}: {err}"
            );
        }
    }

    #[test]
    fn invalid_id_charset_including_uppercase_and_unicode_is_rejected() {
        for bad_id in ["Acme-Agent", "acmé-agent", "-leading-hyphen", "ab", ""] {
            let mut w = valid_wire();
            w.id = bad_id.to_string();
            let err = AdapterManifest::validate_and_build(w, &home()).unwrap_err();
            assert!(
                matches!(err, ManifestError::InvalidId { .. }),
                "{bad_id:?} -> {err:?}"
            );
        }
    }

    #[test]
    fn target_path_with_dotdot_is_rejected() {
        let mut w = valid_wire();
        w.target.path = "~/.acme/../../../etc/x.json".to_string();
        let err = AdapterManifest::validate_and_build(w, &home()).unwrap_err();
        assert!(matches!(err, ManifestError::PathTraversal(_)));
    }

    #[test]
    fn target_path_outside_home_is_rejected() {
        for bad_path in ["/etc/passwd.json", "/tmp/x.json"] {
            let mut w = valid_wire();
            w.target.path = bad_path.to_string();
            let err = AdapterManifest::validate_and_build(w, &home()).unwrap_err();
            assert!(
                matches!(err, ManifestError::PathEscapesHome(_)),
                "{bad_path} -> {err:?}"
            );
        }
    }

    #[test]
    fn target_path_with_wrong_extension_is_rejected() {
        let mut w = valid_wire();
        w.target.path = "~/.acme/settings.toml".to_string();
        let err = AdapterManifest::validate_and_build(w, &home()).unwrap_err();
        assert!(matches!(err, ManifestError::PathExtensionMismatch { .. }));
    }

    #[test]
    fn target_path_with_tilde_user_is_rejected() {
        let mut w = valid_wire();
        w.target.path = "~otheruser/.acme/settings.json".to_string();
        let err = AdapterManifest::validate_and_build(w, &home()).unwrap_err();
        assert!(matches!(err, ManifestError::UnsupportedTilde(_)));
    }

    #[test]
    fn target_path_with_env_var_is_not_interpolated() {
        let mut w = valid_wire();
        w.target.path = "~/.acme/$HOME/settings.json".to_string();
        // No interpolation occurs -- the literal "$HOME" segment is just a
        // directory name under the real home, which is fine; this asserts
        // it does NOT escape home via env expansion (it still must end in
        // .json and stay under home, which it does).
        let m = AdapterManifest::validate_and_build(w, &home()).expect("literal, not expanded");
        assert!(m.target_path.starts_with(home()));
        assert!(m.target_path.to_string_lossy().contains("$HOME"));
    }

    #[test]
    fn min_fornax_version_above_this_build_is_a_named_rejection() {
        let mut w = valid_wire();
        w.min_fornax_version = "999.0.0".to_string();
        let err = AdapterManifest::validate_and_build(w, &home()).unwrap_err();
        assert!(matches!(err, ManifestError::FornaxTooOld { .. }));
    }

    #[test]
    fn element_whose_marker_key_disagrees_with_marker_value_is_rejected() {
        let mut w = valid_wire();
        w.operations = vec![Operation::EnsureMarkedArrayElement {
            pointer: "/hooks/PostToolUse".to_string(),
            marker_key: "command".to_string(),
            marker_value: "fornax-hook-acme".to_string(),
            element: serde_json::json!({"type": "command", "command": "something-else"}),
        }];
        let err = AdapterManifest::validate_and_build(w, &home()).unwrap_err();
        assert!(matches!(err, ManifestError::MarkerMismatch { .. }));
    }

    #[test]
    fn oversized_manifest_and_too_many_operations_and_too_deep_pointer_are_rejected() {
        let huge = vec![b'x'; MAX_MANIFEST_BYTES + 1];
        let err = parse_manifest_bytes(&huge, &home()).unwrap_err();
        assert!(err.to_string().contains(&MAX_MANIFEST_BYTES.to_string()));

        let mut w = valid_wire();
        w.operations = (0..MAX_OPERATIONS + 1)
            .map(|i| Operation::EnsureMarkedArrayElement {
                pointer: format!("/hooks/Event{i}"),
                marker_key: "command".to_string(),
                marker_value: "m".to_string(),
                element: serde_json::json!({"command": "m"}),
            })
            .collect();
        let err = AdapterManifest::validate_and_build(w, &home()).unwrap_err();
        assert!(matches!(err, ManifestError::OperationCountOutOfBounds));

        let mut w2 = valid_wire();
        let deep_pointer = "/a".repeat(MAX_POINTER_DEPTH + 1);
        w2.operations = vec![Operation::EnsureMarkedArrayElement {
            pointer: deep_pointer,
            marker_key: "command".to_string(),
            marker_value: "m".to_string(),
            element: serde_json::json!({"command": "m"}),
        }];
        let err = AdapterManifest::validate_and_build(w2, &home()).unwrap_err();
        assert!(matches!(err, ManifestError::PointerTooDeep { .. }));
    }

    #[test]
    fn digest_is_stable_sha256_over_raw_bytes() {
        let a = digest_of(b"hello");
        let b = digest_of(b"hello");
        let c = digest_of(b"hello!");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.starts_with("sha256:"));
        assert_eq!(a.len(), "sha256:".len() + 64);
    }

    /// AC#10's "timeout" row, discharged with proof rather than silence:
    /// the wire struct has no field whose name suggests an execution
    /// surface, cross-referencing the repo-wide FORNX-238 invariant that no
    /// production code under `crates/` spawns a subprocess at all.
    #[test]
    fn timeout_case_is_not_applicable_manifest_has_no_execution_surface() {
        let v = serde_json::to_value(valid_wire()).unwrap();
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(|s| s.as_str()).collect();
        for forbidden in [
            "executable",
            "entrypoint",
            "command",
            "script",
            "args",
            "env",
        ] {
            assert!(
                !keys.contains(&forbidden),
                "manifest wire schema must never gain an execution-shaped field: {forbidden}"
            );
        }
    }
}
