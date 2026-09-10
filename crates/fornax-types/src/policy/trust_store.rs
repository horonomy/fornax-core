//! Trust-root resolution for [`super::bundle::verify_bundle`] (FORNX-119).
//!
//! FORNX-118 built signature verification but left "where do the trusted
//! keys come from" unanswered — without this module, nothing can ever
//! activate. Precedence: `FORNAX_POLICY_TRUST_STORE` env var (a path) ->
//! `<home>/policy-trust.json` -> none.
//!
//! No compiled-in default key exists — this is a public OSS repo, and no
//! production signing key belongs committed to it. An absent or malformed
//! trust store is never a startup failure (ADR-0001 D2) — it produces
//! `None` plus a `TrustStoreUnavailable` diagnostic, and the daemon
//! continues with an empty/degraded policy cache.

use std::path::Path;

use super::bundle::TrustedVerificationKeys;
use super::diagnostics::{DiagnosticCode, DiagnosticSeverity, PolicyDiagnostic};

pub const POLICY_TRUST_STORE_ENV_VAR: &str = "FORNAX_POLICY_TRUST_STORE";
pub const POLICY_TRUST_STORE_FILE: &str = "policy-trust.json";

fn unavailable_diagnostic(detail: impl Into<String>) -> PolicyDiagnostic {
    PolicyDiagnostic::new(
        DiagnosticCode::TrustStoreUnavailable,
        DiagnosticSeverity::Warning,
        detail.into(),
        "provide a valid trust store via FORNAX_POLICY_TRUST_STORE or <home>/policy-trust.json \
         to allow policy bundle activation",
    )
}

/// Never fails startup (D2). Precedence: `FORNAX_POLICY_TRUST_STORE` env var
/// -> `<home>/policy-trust.json` -> `None`.
pub fn resolve_trust_store(
    home: &Path,
) -> (Option<TrustedVerificationKeys>, Vec<PolicyDiagnostic>) {
    let mut diagnostics = Vec::new();

    if let Ok(path) = std::env::var(POLICY_TRUST_STORE_ENV_VAR) {
        return match load_from_path(Path::new(&path)) {
            Ok(keys) => (Some(keys), diagnostics),
            Err(detail) => {
                diagnostics.push(unavailable_diagnostic(format!(
                    "{POLICY_TRUST_STORE_ENV_VAR}={path:?} could not be loaded: {detail}"
                )));
                (None, diagnostics)
            }
        };
    }

    let default_path = home.join(POLICY_TRUST_STORE_FILE);
    if default_path.exists() {
        return match load_from_path(&default_path) {
            Ok(keys) => (Some(keys), diagnostics),
            Err(detail) => {
                diagnostics.push(unavailable_diagnostic(format!(
                    "{} could not be loaded: {detail}",
                    default_path.display()
                )));
                (None, diagnostics)
            }
        };
    }

    diagnostics.push(unavailable_diagnostic(format!(
        "no trust store configured: set {POLICY_TRUST_STORE_ENV_VAR} or create {}",
        default_path.display()
    )));
    (None, diagnostics)
}

fn load_from_path(path: &Path) -> Result<TrustedVerificationKeys, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    TrustedVerificationKeys::load(&raw).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fornax-trust-store-test-{name}-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn no_env_var_no_file_yields_none_and_a_diagnostic() {
        std::env::remove_var(POLICY_TRUST_STORE_ENV_VAR);
        let home = tmp_dir("none");
        let (keys, diagnostics) = resolve_trust_store(&home);
        assert!(keys.is_none());
        assert!(diagnostics
            .iter()
            .any(|d| d.code == DiagnosticCode::TrustStoreUnavailable));
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn malformed_default_file_yields_none_and_a_diagnostic_never_a_panic() {
        std::env::remove_var(POLICY_TRUST_STORE_ENV_VAR);
        let home = tmp_dir("malformed");
        std::fs::write(home.join(POLICY_TRUST_STORE_FILE), "not json").unwrap();
        let (keys, diagnostics) = resolve_trust_store(&home);
        assert!(keys.is_none());
        assert!(diagnostics
            .iter()
            .any(|d| d.code == DiagnosticCode::TrustStoreUnavailable));
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn valid_default_file_is_loaded() {
        std::env::remove_var(POLICY_TRUST_STORE_ENV_VAR);
        let home = tmp_dir("valid");
        let raw = serde_json::json!({
            "schema_version": 1,
            "keys": [{
                "key_id": "k1",
                "algorithm": "ed25519",
                "public_key_b64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "not_before": null,
                "not_after": null,
                "comment": null
            }]
        })
        .to_string();
        std::fs::write(home.join(POLICY_TRUST_STORE_FILE), raw).unwrap();
        let (keys, _diagnostics) = resolve_trust_store(&home);
        assert!(keys.is_some());
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn env_var_takes_precedence_over_default_file() {
        let home = tmp_dir("precedence-home");
        // A malformed default file that would fail if ever read.
        std::fs::write(home.join(POLICY_TRUST_STORE_FILE), "not json").unwrap();

        let override_dir = tmp_dir("precedence-override");
        let override_path = override_dir.join("trust.json");
        let raw = serde_json::json!({
            "schema_version": 1,
            "keys": [{
                "key_id": "k1",
                "algorithm": "ed25519",
                "public_key_b64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "not_before": null,
                "not_after": null,
                "comment": null
            }]
        })
        .to_string();
        std::fs::write(&override_path, raw).unwrap();

        std::env::set_var(POLICY_TRUST_STORE_ENV_VAR, &override_path);
        let (keys, _diagnostics) = resolve_trust_store(&home);
        assert!(
            keys.is_some(),
            "env var path must be used, not the malformed default file"
        );
        std::env::remove_var(POLICY_TRUST_STORE_ENV_VAR);

        std::fs::remove_dir_all(&home).ok();
        std::fs::remove_dir_all(&override_dir).ok();
    }
}
