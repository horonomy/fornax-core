//! Domain 2: shadow-run a proposed SQL migration against a throwaway,
//! file-backed SQLite database created fresh inside this run's own staging
//! subdirectory — never a shared or production database (AC7).
//!
//! SQLite is chosen for this domain specifically because it needs zero
//! external process, network, or credential: the "digital twin" for this
//! domain is nothing more than a temp file this run creates and the same
//! staging-root cleanup [`crate::orphan::sweep_orphaned_staging_dirs`]
//! already reclaims for an abandoned [`crate::staging::StagedWorktree`]. See
//! this module's [`EnvironmentFidelity`] for the explicit, disclosed gap
//! this leaves relative to a real production database engine (AC4) —
//! passing a shadow migration here proves schema mechanics against
//! representative seed data, not full production-engine behavior.

use std::path::{Path, PathBuf};

use rusqlite::Connection;

use crate::executor::Cancellation;
use crate::shadow::{
    contains_forbidden_parameter_key, is_local_only_target, EnvironmentFidelity, ShadowDomain,
    ShadowOutcome, ShadowResult,
};

/// One proposed migration: `setup_sql` creates the pre-migration schema,
/// `seed_sql` populates it with representative rows (this is what makes
/// AC3's fragility detection possible — a constraint violation surfaces
/// only against real rows, never against an empty table), and
/// `migration_sql` is the change under test.
#[derive(Debug, Clone)]
pub struct MigrationProposal {
    /// **Validated, not dispatched on.** This runner always creates its own
    /// throwaway SQLite file at `staging_dir/shadow.sqlite3` regardless of
    /// this field's value — it never opens `connection_target` itself. The
    /// field exists purely as the caller's declared intent, checked against
    /// [`is_local_only_target`] before anything runs: a caller naming a
    /// real, non-local target (e.g. a real production DSN, by mistake or by
    /// a malicious proposal) is refused up front, rather than silently
    /// ignored in a way that could be mistaken for "verified against the
    /// real target". A future runner that genuinely supports multiple
    /// backends would need to make this field authoritative; this one does
    /// not, and says so here rather than leaving it ambiguous.
    pub connection_target: String,
    pub setup_sql: Vec<String>,
    pub seed_sql: Vec<String>,
    pub migration_sql: String,
}

fn fidelity() -> EnvironmentFidelity {
    EnvironmentFidelity {
        domain: ShadowDomain::SqliteMigration,
        covers: vec!["schema_mechanics".to_string()],
        unmodeled: vec![
            "SQLite is not the production database engine (fornax-cloud runs Postgres)".to_string(),
            "no production-scale data volume or concurrent-writer load is replicated".to_string(),
        ],
    }
}

/// Runs one [`MigrationProposal`] against a fresh SQLite database file
/// created inside `staging_dir` — a subdirectory the caller places under the
/// same [`crate::staging::staging_root`] every [`crate::staging::StagedWorktree`]
/// uses, so an abandoned shadow database is reclaimed by the same orphan
/// sweep, not a second cleanup mechanism.
pub fn run_migration_shadow(
    staging_dir: &Path,
    proposal: &MigrationProposal,
    params: &serde_json::Map<String, serde_json::Value>,
    cancellation: &Cancellation,
) -> ShadowResult {
    if cancellation.is_cancelled() {
        return aborted("cancelled before the shadow database was created");
    }
    if contains_forbidden_parameter_key(params) {
        return refused("proposal parameters contain a credential-shaped key");
    }
    if !is_local_only_target(&proposal.connection_target) {
        return refused(&format!(
            "connection target '{}' is not a local-only target; refused before any connection attempt",
            proposal.connection_target
        ));
    }

    if let Err(e) = std::fs::create_dir_all(staging_dir) {
        return failed(&format!("failed to create shadow staging dir: {e}"));
    }
    let db_path: PathBuf = staging_dir.join("shadow.sqlite3");

    let conn = match Connection::open(&db_path) {
        Ok(c) => c,
        Err(e) => return failed(&format!("failed to open shadow database: {e}")),
    };

    if cancellation.is_cancelled() {
        return aborted("cancelled before setup SQL ran");
    }

    for stmt in &proposal.setup_sql {
        if let Err(e) = conn.execute_batch(stmt) {
            return failed(&format!("setup SQL failed against shadow database: {e}"));
        }
    }
    for stmt in &proposal.seed_sql {
        if let Err(e) = conn.execute_batch(stmt) {
            return failed(&format!("seed SQL failed against shadow database: {e}"));
        }
    }

    let baseline_schema = match schema_snapshot(&conn) {
        Ok(s) => s,
        Err(e) => return failed(&format!("failed to snapshot baseline schema: {e}")),
    };

    if cancellation.is_cancelled() {
        return aborted("cancelled before the migration was applied");
    }

    if let Err(e) = conn.execute_batch(&proposal.migration_sql) {
        // A real fragility (AC3): the migration failed against
        // representative seeded data, exactly the class of failure passive
        // review of the migration's own SQL text cannot reliably predict.
        return ShadowResult {
            proposed_action: proposal.migration_sql.clone(),
            fidelity: fidelity(),
            outcome: ShadowOutcome::Failed {
                reason: format!("migration failed against shadow database: {e}"),
            },
            related_claim_ref: None,
        };
    }

    let after_schema = match schema_snapshot(&conn) {
        Ok(s) => s,
        Err(e) => return failed(&format!("failed to snapshot post-migration schema: {e}")),
    };

    let outcome = if after_schema == baseline_schema {
        ShadowOutcome::Diverged {
            observed: after_schema,
            expected: "schema to change".to_string(),
        }
    } else {
        ShadowOutcome::Matched {
            observed: after_schema,
        }
    };

    ShadowResult {
        proposed_action: proposal.migration_sql.clone(),
        fidelity: fidelity(),
        outcome,
        related_claim_ref: None,
    }
}

fn schema_snapshot(conn: &Connection) -> rusqlite::Result<String> {
    let mut stmt = conn.prepare(
        "SELECT name, sql FROM sqlite_master WHERE type IN ('table','index') ORDER BY name",
    )?;
    let rows = stmt.query_map([], |row| {
        let name: String = row.get(0)?;
        let sql: Option<String> = row.get(1)?;
        Ok(format!("{name}: {}", sql.unwrap_or_default()))
    })?;
    let mut parts = Vec::new();
    for r in rows {
        parts.push(r?);
    }
    Ok(parts.join("\n"))
}

fn refused(reason: &str) -> ShadowResult {
    ShadowResult {
        proposed_action: String::new(),
        fidelity: fidelity(),
        outcome: ShadowOutcome::Refused {
            reason: reason.to_string(),
        },
        related_claim_ref: None,
    }
}

fn failed(reason: &str) -> ShadowResult {
    ShadowResult {
        proposed_action: String::new(),
        fidelity: fidelity(),
        outcome: ShadowOutcome::Failed {
            reason: reason.to_string(),
        },
        related_claim_ref: None,
    }
}

fn aborted(reason: &str) -> ShadowResult {
    ShadowResult {
        proposed_action: String::new(),
        fidelity: fidelity(),
        outcome: ShadowOutcome::Aborted {
            reason: reason.to_string(),
        },
        related_claim_ref: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "fornax-shadow-db-test-{label}-{}",
            uuid::Uuid::new_v4()
        ))
    }

    fn no_params() -> serde_json::Map<String, serde_json::Value> {
        serde_json::Map::new()
    }

    #[test]
    fn a_clean_migration_reports_matched_and_changes_the_schema() {
        let dir = temp_dir("clean-migration");
        let proposal = MigrationProposal {
            connection_target: ":memory:".to_string(),
            setup_sql: vec!["CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT);".to_string()],
            seed_sql: vec!["INSERT INTO users (name) VALUES ('alice'), ('bob');".to_string()],
            migration_sql: "ALTER TABLE users ADD COLUMN email TEXT;".to_string(),
        };

        let result = run_migration_shadow(&dir, &proposal, &no_params(), &Cancellation::new());
        assert!(
            matches!(result.outcome, ShadowOutcome::Matched { .. }),
            "{:?}",
            result.outcome
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// AC3: a real fragility detected only by executing the migration
    /// against representative seeded data -- a UNIQUE constraint that the
    /// migration's own SQL text gives no hint would fail, since the
    /// violation depends entirely on pre-existing duplicate rows.
    #[test]
    fn a_unique_constraint_migration_fails_against_seeded_duplicate_data() {
        let dir = temp_dir("unique-violation");
        let proposal = MigrationProposal {
            connection_target: ":memory:".to_string(),
            setup_sql: vec![
                "CREATE TABLE accounts (id INTEGER PRIMARY KEY, email TEXT);".to_string(),
            ],
            // Two rows share the same email -- innocuous under the current
            // schema, but a real problem the instant a UNIQUE index is
            // added.
            seed_sql: vec![
                "INSERT INTO accounts (email) VALUES ('dup@example.com'), ('dup@example.com');"
                    .to_string(),
            ],
            migration_sql: "CREATE UNIQUE INDEX accounts_email_unique ON accounts(email);"
                .to_string(),
        };

        let result = run_migration_shadow(&dir, &proposal, &no_params(), &Cancellation::new());
        assert!(
            matches!(result.outcome, ShadowOutcome::Failed { .. }),
            "expected the migration to fail against duplicate seeded data, got {:?}",
            result.outcome
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_migration_that_changes_nothing_reports_diverged() {
        let dir = temp_dir("no-op-migration");
        let proposal = MigrationProposal {
            connection_target: ":memory:".to_string(),
            setup_sql: vec!["CREATE TABLE t (id INTEGER PRIMARY KEY);".to_string()],
            seed_sql: vec![],
            migration_sql: "SELECT 1;".to_string(),
        };

        let result = run_migration_shadow(&dir, &proposal, &no_params(), &Cancellation::new());
        assert!(
            matches!(result.outcome, ShadowOutcome::Diverged { .. }),
            "{:?}",
            result.outcome
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// AC5/AC7 negative control: a network-shaped connection target is
    /// refused before any connection is attempted.
    #[test]
    fn a_network_shaped_target_is_refused_before_any_connection_attempt() {
        let dir = temp_dir("network-refused");
        let proposal = MigrationProposal {
            connection_target: "postgres://real-production-host/db".to_string(),
            setup_sql: vec![],
            seed_sql: vec![],
            migration_sql: "SELECT 1;".to_string(),
        };

        let result = run_migration_shadow(&dir, &proposal, &no_params(), &Cancellation::new());
        assert!(matches!(result.outcome, ShadowOutcome::Refused { .. }));
        // Nothing was created at all -- the refusal happens before the
        // staging directory is even provisioned.
        assert!(!dir.exists());
    }

    /// AC5/AC7 negative control: a credential-shaped parameter key is
    /// refused before any database is opened.
    #[test]
    fn a_credential_shaped_parameter_key_is_refused_before_opening_the_database() {
        let dir = temp_dir("credential-refused");
        let mut params = serde_json::Map::new();
        params.insert("db_password".to_string(), serde_json::json!("shhh"));
        let proposal = MigrationProposal {
            connection_target: ":memory:".to_string(),
            setup_sql: vec![],
            seed_sql: vec![],
            migration_sql: "SELECT 1;".to_string(),
        };

        let result = run_migration_shadow(&dir, &proposal, &params, &Cancellation::new());
        assert!(matches!(result.outcome, ShadowOutcome::Refused { .. }));
        assert!(!dir.exists());
    }

    /// AC6: pre-cancelled runs abort before touching the filesystem at all.
    #[test]
    fn a_pre_cancelled_run_aborts_before_creating_the_database() {
        let dir = temp_dir("cancelled");
        let cancellation = Cancellation::new();
        cancellation.cancel();
        let proposal = MigrationProposal {
            connection_target: ":memory:".to_string(),
            setup_sql: vec![],
            seed_sql: vec![],
            migration_sql: "SELECT 1;".to_string(),
        };

        let result = run_migration_shadow(&dir, &proposal, &no_params(), &cancellation);
        assert!(matches!(result.outcome, ShadowOutcome::Aborted { .. }));
        assert!(!dir.exists());
    }

    /// AC6/orphan recovery: a shadow database directory this module creates
    /// lives under the same staging root [`crate::orphan::sweep_orphaned_staging_dirs`]
    /// already scans, so an abandoned one is reclaimed by the existing
    /// sweep without a second cleanup mechanism.
    #[test]
    fn an_abandoned_shadow_database_directory_is_reclaimed_by_the_existing_orphan_sweep() {
        let staging_root = temp_dir("staging-root-for-orphan-test");
        let run_dir = staging_root.join("fornax-shadow-db-run");
        let proposal = MigrationProposal {
            connection_target: ":memory:".to_string(),
            setup_sql: vec!["CREATE TABLE t (id INTEGER PRIMARY KEY);".to_string()],
            seed_sql: vec![],
            migration_sql: "ALTER TABLE t ADD COLUMN v TEXT;".to_string(),
        };
        let result = run_migration_shadow(&run_dir, &proposal, &no_params(), &Cancellation::new());
        assert!(matches!(result.outcome, ShadowOutcome::Matched { .. }));
        assert!(
            run_dir.exists(),
            "the run's own directory must exist after a completed run"
        );

        let removed =
            crate::orphan::sweep_orphaned_staging_dirs(&staging_root, std::time::Duration::ZERO)
                .unwrap();
        assert_eq!(removed, vec![run_dir.clone()]);
        assert!(!run_dir.exists());

        std::fs::remove_dir_all(&staging_root).ok();
    }
}
