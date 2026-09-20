//! Golden-fixture loading (FORNX-160, extending FORNX-156's conformance
//! harness into the full golden-fixture kit the parent epic's AC asks for).
//!
//! A fixture is a versioned, provider-tagged JSON file capturing one real
//! (or deliberately synthetic, for a breaking-change probe) provider-native
//! event shape — see `fixtures/README.md` for the exact file schema and the
//! sanitization rule every fixture must satisfy. `load_fixtures` is the only
//! way to read them, and it refuses to load anything not marked
//! `sanitized: true`.

use fornax_types::Provider;
use serde::Deserialize;

/// Versioned provenance for one [`GoldenFixture`]. See `fixtures/README.md`
/// field-by-field for what each of these means and when
/// `historical_schema_drift_ticket` may legitimately be set.
#[derive(Debug, Clone, Deserialize)]
pub struct FixtureMetadata {
    pub provider: Provider,
    pub provider_runtime_version: String,
    pub description: String,
    pub sanitized: bool,
    #[serde(default)]
    pub historical_schema_drift_ticket: Option<String>,
}

/// Wire shape of a fixture JSON file. Kept separate from [`GoldenFixture`]
/// only so `load_fixtures` can attach the file-derived `name` field, which
/// has no JSON representation of its own.
#[derive(Debug, Clone, Deserialize)]
struct GoldenFixtureFile {
    provider: Provider,
    provider_runtime_version: String,
    description: String,
    sanitized: bool,
    #[serde(default)]
    historical_schema_drift_ticket: Option<String>,
    native_events: Vec<serde_json::Value>,
}

/// A loaded golden fixture: its provenance metadata plus one or more native
/// provider payloads to replay in order against a single adapter instance
/// (see [`crate::replay_fixture`]). More than one entry in `native_events`
/// means the fixture exercises a stateful sequence (e.g. Codex's
/// `custom_tool_call`/`custom_tool_call_output` call-id pairing).
#[derive(Debug, Clone)]
pub struct GoldenFixture {
    /// The fixture file's name (its filename without the `.json`
    /// extension), used only for test failure messages/reporting.
    pub name: String,
    pub metadata: FixtureMetadata,
    pub native_events: Vec<serde_json::Value>,
}

/// Loads every `*.json` fixture file from `fixtures/<subdir>` (`"claude"` or
/// `"codex"`), relative to this crate's own manifest directory — resolved
/// via `CARGO_MANIFEST_DIR` so this works regardless of the test runner's
/// current working directory.
///
/// Panics on a malformed fixture file, or one that does not declare
/// `sanitized: true` — a fixture that cannot prove it was sanitized must
/// never load silently into a test run (see `fixtures/README.md`).
pub fn load_fixtures(subdir: &str) -> Vec<GoldenFixture> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(subdir);
    let entries = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("failed to read fixture dir {}: {e}", dir.display()));

    let mut fixtures: Vec<GoldenFixture> = entries
        .filter_map(|entry| {
            let path = entry.expect("fixture dir entry").path();
            (path.extension().and_then(|e| e.to_str()) == Some("json")).then_some(path)
        })
        .map(|path| {
            let name = path
                .file_stem()
                .expect("fixture file must have a name")
                .to_string_lossy()
                .to_string();
            let content = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("failed to read fixture {}: {e}", path.display()));
            let file: GoldenFixtureFile = serde_json::from_str(&content)
                .unwrap_or_else(|e| panic!("failed to parse fixture {}: {e}", path.display()));
            assert!(
                file.sanitized,
                "fixture {} does not declare sanitized: true — refusing to load",
                path.display()
            );
            GoldenFixture {
                name,
                metadata: FixtureMetadata {
                    provider: file.provider,
                    provider_runtime_version: file.provider_runtime_version,
                    description: file.description,
                    sanitized: file.sanitized,
                    historical_schema_drift_ticket: file.historical_schema_drift_ticket,
                },
                native_events: file.native_events,
            }
        })
        .collect();

    fixtures.sort_by(|a, b| a.name.cmp(&b.name));
    fixtures
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_claude_fixture_loads_and_is_sanitized() {
        let fixtures = load_fixtures("claude");
        assert!(!fixtures.is_empty(), "expected at least one Claude fixture");
        for f in &fixtures {
            assert!(f.metadata.sanitized);
            assert_eq!(f.metadata.provider, Provider::ClaudeCode);
            assert!(!f.native_events.is_empty());
        }
    }

    #[test]
    fn every_codex_fixture_loads_and_is_sanitized() {
        let fixtures = load_fixtures("codex");
        assert!(!fixtures.is_empty(), "expected at least one Codex fixture");
        for f in &fixtures {
            assert!(f.metadata.sanitized);
            assert_eq!(f.metadata.provider, Provider::Codex);
            assert!(!f.native_events.is_empty());
        }
    }

    #[test]
    fn every_opencode_fixture_loads_and_is_sanitized() {
        let fixtures = load_fixtures("opencode");
        assert!(
            !fixtures.is_empty(),
            "expected at least one opencode fixture"
        );
        for f in &fixtures {
            assert!(f.metadata.sanitized);
            assert_eq!(f.metadata.provider, Provider::OpenCode);
            assert!(!f.native_events.is_empty());
        }
    }

    #[test]
    fn exactly_one_codex_fixture_is_tagged_as_the_fornx_55_regression() {
        let fixtures = load_fixtures("codex");
        let drift: Vec<_> = fixtures
            .iter()
            .filter(|f| f.metadata.historical_schema_drift_ticket.as_deref() == Some("FORNX-55"))
            .collect();
        assert_eq!(
            drift.len(),
            1,
            "expected exactly one fixture tagged as the FORNX-55 historical schema-drift regression"
        );
    }
}
