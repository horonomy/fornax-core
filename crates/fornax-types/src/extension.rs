//! Versioned provider-extension envelope for evidence (FORNX-158, parent
//! epic FORNX-138).
//!
//! FORNX-155/156/157 gave core three things: a versioned capability
//! taxonomy, a thin adapter boundary, and a structured sensor/provenance
//! contract. None of them gave provider-specific evidence a home that isn't
//! either "invent a new canonical `EvidenceKind`" (too slow — a canonical
//! field is a cross-provider commitment, see `docs/adr/0005-schema-evolution.md`'s
//! promotion criteria) or "stuff it into `Evidence::payload` untyped forever"
//! (the schemaless-event-lake outcome this ticket's AC explicitly forbids).
//!
//! [`ExtensionEnvelope`] is that home: a versioned, provider/adapter-tagged,
//! content-classified wrapper around a `fields: serde_json::Value` bucket,
//! attached to [`crate::Evidence::extension`]. It is an **escape hatch**, not
//! the default path — canonical `EvidenceKind`/payload shapes
//! (`crate::validate_canonical_payload`) remain how broadly-shared evidence
//! is represented; the envelope exists only for evidence that doesn't
//! warrant a canonical field yet.
//!
//! # Not a laundering path for unrecognized native payloads
//!
//! `AgentAdapter::normalize`'s `NormalizationOutcome::Unrecognized` (FORNX-156,
//! `crates/fornax-types/src/adapter.rs`) deliberately carries only a
//! `discriminator` type tag, never the native payload body — forwarding
//! unvetted provider JSON into any downstream shape, envelope included, is
//! exactly the "uncontrolled provider-native payload leakage" that contract
//! forbids. An `ExtensionEnvelope` is built only for a native shape a sensor
//! **recognizes and deliberately chooses** to carry provider-specifically
//! (e.g. a real future `ClaudeThinkingBlockSensor` that recognizes Claude's
//! extended-thinking block shape and decides it's not yet worth a canonical
//! `EvidenceKind`), never as a generic catch-all for "adapter didn't
//! recognize this."
//!
//! # Forward/backward compatibility model
//!
//! Two independent tolerance mechanisms, matching FORNX-155's precedent
//! (`crate::SignalAvailability::Unrecognized`) rather than inventing a new
//! one:
//!
//! - **Unknown *fields* within a compatible `schema_version`**: tolerated
//!   and *preserved*, not silently dropped. [`ExtensionEnvelope`] carries a
//!   `#[serde(flatten)]` catch-all map for any top-level JSON key this
//!   binary's struct doesn't name explicitly; a reader that deserializes and
//!   re-serializes an envelope from a newer binary reproduces those fields
//!   byte-for-byte rather than deleting what it doesn't understand.
//! - **An incompatible `schema_version`**: an explicit, loud deserialization
//!   failure — see [`SUPPORTED_EXTENSION_SCHEMA_VERSIONS`]. This is the one
//!   place in the extension surface where "fail loudly" is correct, in
//!   direct contrast to the unknown-field case above: an unrecognized
//!   *field* is forward-compatible noise; an unrecognized *version* means
//!   this binary has no idea what invariants the payload actually satisfies,
//!   and silently accepting it risks corrupt/misinterpreted data rather than
//!   just missing an optional detail.
//!
//! No arbitrary code or plugin execution is ever triggered by envelope
//! content: `fields`/`unknown` are inert JSON data, read only by whatever
//! typed consumer later chooses to interpret a specific `content_class` —
//! this module does no dispatch on their contents.

use serde::{Deserialize, Serialize};

use crate::Provider;

/// The `schema_version` values this binary knows how to interpret. Anything
/// outside this set is a "truly incompatible" version per FORNX-158's AC —
/// deserialization fails explicitly (see [`ExtensionEnvelopeWire`]'s
/// `TryFrom` impl) rather than silently accepting a payload whose shape
/// invariants this binary cannot vouch for.
///
/// Deliberately a plain allow-list, not a packed major/minor integer: a
/// minor/patch-style distinction has no job left once unknown *fields*
/// within a version are already tolerated-and-preserved (see the module
/// docs) — "an additive change within a version" is exactly "same
/// `schema_version`, extra unknown keys," so there is nothing left for a
/// minor counter to express. Bump by adding a new version here (and to
/// `EXTENSION_SCHEMA_VERSION` if it becomes the new default) only when a
/// change is not additive-safe — e.g. a field's *meaning* or type changes
/// under the same name. See `docs/adr/0005-schema-evolution.md`'s
/// deprecation/migration rules for the full policy and when an old version
/// is finally dropped from this list.
pub const SUPPORTED_EXTENSION_SCHEMA_VERSIONS: &[u32] = &[1, 2];

/// The `schema_version` a newly-constructed [`ExtensionEnvelope`] should
/// stamp. Distinct from [`SUPPORTED_EXTENSION_SCHEMA_VERSIONS`] (the read
/// side accepts more than the write side emits) exactly as
/// `crate::CAPABILITY_SCHEMA_VERSION` does for `RuntimeCapabilities`.
pub const EXTENSION_SCHEMA_VERSION: u32 = 2;

/// What kind of provider-specific content this envelope carries. One
/// variant per broad category observed/anticipated so far; a category this
/// binary doesn't recognize round-trips via `Unrecognized` rather than
/// failing — a new `content_class` value is forward-compatible noise, not a
/// version-incompatibility (see the module docs for that distinction).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentClass {
    /// Provider-native telemetry about a tool invocation that doesn't fit
    /// any canonical `EvidenceKind` (e.g. a provider-specific timing/cache
    /// breakdown attached to a tool call).
    ToolTelemetry,
    /// Provider-emitted diagnostic/debug information not itself evidence of
    /// task outcome (e.g. a rate-limit warning, a deprecation notice).
    ProviderDiagnostic,
    /// A signal being trialed for a specific provider/adapter version,
    /// before there is enough cross-provider evidence to promote it to a
    /// canonical field (see `docs/adr/0005-schema-evolution.md`'s promotion
    /// criteria).
    ExperimentalSignal,
    /// A raw, largely-opaque provider metadata blob kept for
    /// replay/debugging, with no interpretation attempted yet.
    RawProviderMetadata,
    /// Forward-compatibility catch-all for a future content class this
    /// binary doesn't know about yet. Must stay last — see
    /// [`crate::SignalAvailability::Unrecognized`] for the same pattern.
    #[serde(untagged)]
    Unrecognized(String),
}

/// A versioned, provider/adapter-tagged wrapper for evidence that is
/// specific to one provider/runtime and doesn't yet warrant a canonical
/// `EvidenceKind`/typed payload. See the module docs for the full
/// compatibility model and the boundary with `NormalizationOutcome::Unrecognized`.
///
/// Deserialization is asymmetric with serialization, matching
/// `RuntimeCapabilities`'s precedent: this type always *serializes* its full
/// named-field shape plus any preserved unknown fields, but *deserializes*
/// through [`ExtensionEnvelopeWire`] so an incompatible `schema_version` can
/// be rejected with a specific error before construction, rather than after.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "ExtensionEnvelopeWire")]
pub struct ExtensionEnvelope {
    /// Version of this envelope's own shape (not the provider's runtime
    /// version — that's `adapter_version`/a `CapabilitySignal::detail`
    /// string). Must be a member of [`SUPPORTED_EXTENSION_SCHEMA_VERSIONS`]
    /// to deserialize at all.
    pub schema_version: u32,
    pub provider: Provider,
    /// The producing `AgentAdapter` implementation's own version
    /// (`AgentAdapter::adapter_version`), independent of `schema_version`.
    pub adapter_version: String,
    pub content_class: ContentClass,
    /// Provider-specific content, structured however the producing sensor
    /// sees fit. Deliberately untyped — this is the one field in the whole
    /// canonical/extension split allowed to be schemaless JSON, and only
    /// because that's the extension envelope's entire purpose (see the
    /// module docs' "escape hatch, not the default path" framing).
    pub fields: serde_json::Value,
    /// Any top-level JSON key present on the wire that this binary's struct
    /// does not name above — preserved verbatim so a tolerant reader that
    /// re-serializes an envelope from a newer binary does not silently
    /// delete what it doesn't understand. Empty for an envelope constructed
    /// by this binary's own `new`.
    #[serde(flatten)]
    pub unknown: serde_json::Map<String, serde_json::Value>,
}

impl ExtensionEnvelope {
    /// Construct a fresh envelope stamped with the current
    /// [`EXTENSION_SCHEMA_VERSION`] and no unknown fields.
    pub fn new(
        provider: Provider,
        adapter_version: impl Into<String>,
        content_class: ContentClass,
        fields: serde_json::Value,
    ) -> Self {
        Self {
            schema_version: EXTENSION_SCHEMA_VERSION,
            provider,
            adapter_version: adapter_version.into(),
            content_class,
            fields,
            unknown: serde_json::Map::new(),
        }
    }
}

/// Wire shape accepted on deserialization. Structurally identical to
/// [`ExtensionEnvelope`]; exists only so [`TryFrom`] can gate on
/// `schema_version` before the domain type is ever constructed. See the
/// module docs for why an incompatible version is a hard failure while an
/// unknown field is not.
#[derive(Debug, Deserialize)]
struct ExtensionEnvelopeWire {
    schema_version: u32,
    provider: Provider,
    adapter_version: String,
    content_class: ContentClass,
    fields: serde_json::Value,
    #[serde(flatten)]
    unknown: serde_json::Map<String, serde_json::Value>,
}

impl TryFrom<ExtensionEnvelopeWire> for ExtensionEnvelope {
    type Error = String;

    fn try_from(w: ExtensionEnvelopeWire) -> Result<Self, Self::Error> {
        if !SUPPORTED_EXTENSION_SCHEMA_VERSIONS.contains(&w.schema_version) {
            return Err(format!(
                "incompatible ExtensionEnvelope schema_version {}: this binary supports {:?}",
                w.schema_version, SUPPORTED_EXTENSION_SCHEMA_VERSIONS
            ));
        }
        Ok(ExtensionEnvelope {
            schema_version: w.schema_version,
            provider: w.provider,
            adapter_version: w.adapter_version,
            content_class: w.content_class,
            fields: w.fields,
            unknown: w.unknown,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope() -> ExtensionEnvelope {
        ExtensionEnvelope::new(
            Provider::ClaudeCode,
            "claude-adapter-0.3.0",
            ContentClass::ToolTelemetry,
            serde_json::json!({"cache_read_tokens": 128}),
        )
    }

    // --- ContentClass forward-compat round-trip (FORNX-155 precedent) ----

    #[test]
    fn unrecognized_content_class_round_trips_the_original_string() {
        let json = r#""quantum_signal""#;
        let v: ContentClass = serde_json::from_str(json).unwrap();
        assert_eq!(v, ContentClass::Unrecognized("quantum_signal".to_string()));
        let back = serde_json::to_string(&v).unwrap();
        assert_eq!(back, json);
    }

    // --- Required test: round-trip preserving unknown fields -------------
    // (compatible version; test #1)

    #[test]
    fn unknown_top_level_field_on_a_compatible_version_survives_round_trip() {
        let json = r#"{
            "schema_version": 1,
            "provider": "codex",
            "adapter_version": "codex-adapter-0.1.0",
            "content_class": "raw_provider_metadata",
            "fields": {"blob": "opaque"},
            "retention_hint_days": 30
        }"#;
        let env: ExtensionEnvelope = serde_json::from_str(json).unwrap();
        assert_eq!(env.schema_version, 1);
        assert_eq!(
            env.unknown.get("retention_hint_days"),
            Some(&serde_json::json!(30))
        );

        // Re-serialize: the unrecognized field must still be present, not
        // silently dropped (preserve-and-ignore, not delete-on-read).
        let reser = serde_json::to_value(&env).unwrap();
        assert_eq!(reser["retention_hint_days"], serde_json::json!(30));
        assert_eq!(reser["fields"]["blob"], serde_json::json!("opaque"));
    }

    // --- Required test: explicit hard failure on incompatible version ----
    // (test #2, distinct from the tolerate-unknown-fields test above)

    #[test]
    fn truly_incompatible_schema_version_fails_explicitly_rather_than_silently_parsing() {
        let json = r#"{
            "schema_version": 999,
            "provider": "codex",
            "adapter_version": "codex-adapter-0.1.0",
            "content_class": "tool_telemetry",
            "fields": {}
        }"#;
        let err = serde_json::from_str::<ExtensionEnvelope>(json).unwrap_err();
        assert!(
            err.to_string().contains("incompatible"),
            "expected an explicit incompatibility error, got: {err}"
        );
    }

    // --- Required test: two-historical-version compatibility fixtures ----
    // (test #3) — v1 is the initial envelope shape; v2 (current) adds no
    // named field over v1, so the only difference a real future v2 would
    // introduce is exercised here as an additional field arriving on the
    // wire, proving both the old and new shapes still read correctly under
    // the same type.

    #[test]
    fn historical_v1_envelope_fixture_still_reads_correctly() {
        let v1_json = r#"{
            "schema_version": 1,
            "provider": "claude_code",
            "adapter_version": "claude-adapter-0.1.0",
            "content_class": "tool_telemetry",
            "fields": {"cache_read_tokens": 42}
        }"#;
        let env: ExtensionEnvelope = serde_json::from_str(v1_json).unwrap();
        assert_eq!(env.schema_version, 1);
        assert_eq!(env.content_class, ContentClass::ToolTelemetry);
        assert_eq!(env.fields["cache_read_tokens"], serde_json::json!(42));
        assert!(env.unknown.is_empty());
    }

    #[test]
    fn historical_v2_envelope_fixture_reads_correctly_and_is_the_current_default() {
        let v2_json = r#"{
            "schema_version": 2,
            "provider": "claude_code",
            "adapter_version": "claude-adapter-0.3.0",
            "content_class": "experimental_signal",
            "fields": {"trial_signal": true}
        }"#;
        let env: ExtensionEnvelope = serde_json::from_str(v2_json).unwrap();
        assert_eq!(env.schema_version, 2);
        assert_eq!(env.schema_version, EXTENSION_SCHEMA_VERSION);
        assert_eq!(env.content_class, ContentClass::ExperimentalSignal);
    }

    #[test]
    fn both_historical_versions_are_members_of_the_supported_set() {
        assert!(SUPPORTED_EXTENSION_SCHEMA_VERSIONS.contains(&1));
        assert!(SUPPORTED_EXTENSION_SCHEMA_VERSIONS.contains(&2));
    }

    // --- new()/round-trip sanity ------------------------------------------

    #[test]
    fn new_envelope_round_trips_losslessly() {
        let env = envelope();
        let json = serde_json::to_string(&env).unwrap();
        let back: ExtensionEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(env, back);
    }
}
