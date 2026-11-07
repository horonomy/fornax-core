//! Execution identity envelope (HORO-1597/1598, FORNX-466).
//!
//! Fornax's implementation of the shared Horonom execution identity contract
//! (`horonomy/.github` `governance/product/execution-identity-contract.md`).
//! The Host-owned Python reference (`scripts/execution_identity.py`,
//! `scripts/execution_identity_normalize.py`) and the conformance vectors
//! (`tests/fixtures/execution-identity-conformance-vectors.json`) define the
//! behaviour; this module mirrors them and `tests/execution_identity_conformance.rs`
//! runs every vector against it.
//!
//! Rules that matter downstream:
//! - Provider-native ids are opaque and copied verbatim. An absent, empty,
//!   whitespace-only or non-string native id is *unknown*, never coerced and
//!   never replaced by a placeholder.
//! - A cache key never widens: if a scope lacks identity, [`ExecutionIdentity::cache_key`]
//!   returns `None` rather than a broader scope's key.
//! - `host_id` is always present, so the narrowest attributable scope is
//!   never inferred as [`Scope::Host`] from a missing session.
//! - `cwd`, `transcript_path`, `prompt_id` and process ids are deliberately
//!   ignored as identity.

use std::fmt;

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

/// Envelope version a capturer declares and a reader accepts.
pub const ENVELOPE_VERSION: u64 = 1;

/// Why an envelope or one of its fields was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityError(pub String);

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for IdentityError {}

fn refuse<T>(reason: impl Into<String>) -> Result<T, IdentityError> {
    Err(IdentityError(reason.into()))
}

/// The smallest truthful dimension that owns one datum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Host,
    Session,
    Agent,
    TurnTask,
    ProjectWorktree,
    Unknown,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Host => "host",
            Scope::Session => "session",
            Scope::Agent => "agent",
            Scope::TurnTask => "turn_task",
            Scope::ProjectWorktree => "project_worktree",
            Scope::Unknown => "unknown",
        }
    }
}

/// Whether an agent's parent relationship is proven, absent or unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineageStatus {
    Root,
    Child,
    Unknown,
}

impl LineageStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            LineageStatus::Root => "root",
            LineageStatus::Child => "child",
            LineageStatus::Unknown => "unknown",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "root" => Some(LineageStatus::Root),
            "child" => Some(LineageStatus::Child),
            "unknown" => Some(LineageStatus::Unknown),
            _ => None,
        }
    }
}

/// `^[a-z][a-z0-9_-]{0,31}$` -- bounded, lowercase, no path/shell characters.
pub fn is_valid_tool_provider(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > 32 || !bytes[0].is_ascii_lowercase() {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_' || *b == b'-')
}

/// One instant's execution identity envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionIdentity {
    pub observed_at: String,
    pub host_id: String,
    pub tool_provider: String,
    pub tool_instance_id: Option<String>,
    pub provider_session_id: Option<String>,
    pub agent_id: Option<String>,
    pub turn_id: Option<String>,
    pub lineage_status: LineageStatus,
    pub parent_agent_id: Option<String>,
    pub session_lineage_id: Option<String>,
    pub event_id: Option<String>,
    pub repo_id: Option<String>,
    pub worktree_id: Option<String>,
}

const OPTIONAL_FIELDS: [&str; 9] = [
    "tool_instance_id",
    "provider_session_id",
    "agent_id",
    "turn_id",
    "parent_agent_id",
    "session_lineage_id",
    "event_id",
    "repo_id",
    "worktree_id",
];

/// `%Y-%m-%dT%H:%M:%S.<1-6 digits>Z`, UTC. Returns the canonical
/// millisecond-truncated form used on the wire.
fn canonical_observed_at(raw: &str) -> Result<String, IdentityError> {
    let Some(body) = raw.strip_suffix('Z') else {
        return refuse("observed_at must be UTC (trailing Z)");
    };
    let Some((whole, frac)) = body.split_once('.') else {
        return refuse("observed_at needs fractional seconds");
    };
    if frac.is_empty() || frac.len() > 6 || !frac.bytes().all(|b| b.is_ascii_digit()) {
        return refuse("observed_at fractional seconds must be 1-6 digits");
    }
    if chrono::NaiveDateTime::parse_from_str(whole, "%Y-%m-%dT%H:%M:%S").is_err() {
        return refuse("observed_at is not %Y-%m-%dT%H:%M:%S.fZ");
    }
    // Pad to 6 digits (microseconds), then truncate to milliseconds.
    let padded = format!("{frac:0<6}");
    Ok(format!("{whole}.{}Z", &padded[..3]))
}

fn optional_string(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Option<String>, IdentityError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => refuse(format!("{key} must be a string")),
    }
}

impl ExecutionIdentity {
    /// Parse a wire document. Unknown top-level fields are ignored; an
    /// unknown `envelope_version`, `lineage_status` or malformed field is
    /// refused rather than guessed.
    pub fn from_wire(document: &Value) -> Result<Self, IdentityError> {
        let Some(object) = document.as_object() else {
            return refuse("envelope must be an object");
        };
        // Strict about type: a version emitted as "1" or true is a capturer
        // bug and must not be coerced.
        match object.get("envelope_version") {
            Some(v) if v.as_u64() == Some(ENVELOPE_VERSION) => {}
            other => return refuse(format!("unsupported envelope_version: {other:?}")),
        }
        let lineage_status = match object.get("lineage_status") {
            None | Some(Value::Null) => LineageStatus::Unknown,
            Some(Value::String(s)) => match LineageStatus::parse(s) {
                Some(l) => l,
                None => return refuse(format!("unrecognised lineage_status: {s:?}")),
            },
            Some(_) => return refuse("lineage_status must be a string"),
        };
        let observed_at = match object.get("observed_at") {
            Some(Value::String(s)) => canonical_observed_at(s)?,
            _ => return refuse("observed_at is required"),
        };
        let host_id = match object.get("host_id") {
            Some(Value::String(s)) if !s.is_empty() => s.clone(),
            _ => return refuse("host_id is required and must be a non-empty string"),
        };
        let tool_provider = match object.get("tool_provider") {
            Some(Value::String(s)) if is_valid_tool_provider(s) => s.clone(),
            other => return refuse(format!("invalid tool_provider: {other:?}")),
        };
        let identity = ExecutionIdentity {
            observed_at,
            host_id,
            tool_provider,
            tool_instance_id: optional_string(object, "tool_instance_id")?,
            provider_session_id: optional_string(object, "provider_session_id")?,
            agent_id: optional_string(object, "agent_id")?,
            turn_id: optional_string(object, "turn_id")?,
            lineage_status,
            parent_agent_id: optional_string(object, "parent_agent_id")?,
            session_lineage_id: optional_string(object, "session_lineage_id")?,
            event_id: optional_string(object, "event_id")?,
            repo_id: optional_string(object, "repo_id")?,
            worktree_id: optional_string(object, "worktree_id")?,
        };
        match (identity.lineage_status, identity.parent_agent_id.as_deref()) {
            (LineageStatus::Child, None | Some("")) => {
                return refuse("lineage_status=child requires a non-empty parent_agent_id");
            }
            (LineageStatus::Child, Some(_)) => {}
            (_, Some(_)) => {
                return refuse("parent_agent_id must be absent unless lineage_status=child")
            }
            (_, None) => {}
        }
        Ok(identity)
    }

    /// Serialize to the wire shape (absent optionals omitted).
    pub fn to_wire(&self) -> Value {
        let mut out = Map::new();
        out.insert("envelope_version".into(), json!(ENVELOPE_VERSION));
        out.insert("observed_at".into(), json!(self.observed_at));
        out.insert("host_id".into(), json!(self.host_id));
        out.insert("tool_provider".into(), json!(self.tool_provider));
        out.insert("lineage_status".into(), json!(self.lineage_status.as_str()));
        for name in OPTIONAL_FIELDS {
            if let Some(value) = self.optional(name) {
                out.insert(name.into(), json!(value));
            }
        }
        Value::Object(out)
    }

    fn optional(&self, name: &str) -> Option<&str> {
        match name {
            "tool_instance_id" => self.tool_instance_id.as_deref(),
            "provider_session_id" => self.provider_session_id.as_deref(),
            "agent_id" => self.agent_id.as_deref(),
            "turn_id" => self.turn_id.as_deref(),
            "parent_agent_id" => self.parent_agent_id.as_deref(),
            "session_lineage_id" => self.session_lineage_id.as_deref(),
            "event_id" => self.event_id.as_deref(),
            "repo_id" => self.repo_id.as_deref(),
            "worktree_id" => self.worktree_id.as_deref(),
            _ => None,
        }
    }

    /// The minimal identity tuple `scope`'s data is keyed on, or `None` when
    /// the envelope lacks identity for it. Never falls back to a broader
    /// scope's key. An empty string counts as missing.
    pub fn cache_key(&self, scope: Scope) -> Option<Vec<String>> {
        let present = |v: &Option<String>| v.clone().filter(|s| !s.is_empty());
        let session = present(&self.provider_session_id);
        let agent = present(&self.agent_id);
        let turn = present(&self.turn_id);
        let base = |extra: &[&String]| {
            let mut key = vec![self.host_id.clone(), self.tool_provider.clone()];
            key.extend(extra.iter().map(|s| (*s).clone()));
            key
        };
        match scope {
            Scope::Host => Some(vec![self.host_id.clone()]),
            Scope::Session => session.as_ref().map(|s| base(&[s])),
            Scope::Agent => match (&session, &agent) {
                (Some(s), Some(a)) => Some(base(&[s, a])),
                _ => None,
            },
            Scope::TurnTask => match (&session, &agent, &turn) {
                (Some(s), Some(a), Some(t)) => Some(base(&[s, a, t])),
                _ => None,
            },
            Scope::ProjectWorktree => present(&self.worktree_id)
                .or_else(|| present(&self.repo_id))
                .map(|id| vec![id]),
            Scope::Unknown => None,
        }
    }

    /// The narrowest scope this identity can key a datum on, else `Unknown`.
    /// Never `Host`: a missing session must not become a confident host-wide
    /// claim.
    pub fn narrowest_attributable_scope(&self) -> Scope {
        [Scope::TurnTask, Scope::Agent, Scope::Session]
            .into_iter()
            .find(|scope| self.cache_key(*scope).is_some())
            .unwrap_or(Scope::Unknown)
    }

    /// `dimension:` + the first 8 hex of `sha256("dimension:value")`. A
    /// display/log token only -- never for correlation or cache keys.
    pub fn display_id(&self, dimension: &str) -> Result<String, IdentityError> {
        let raw = match dimension {
            "host_id" => Some(self.host_id.as_str()),
            "tool_provider" => Some(self.tool_provider.as_str()),
            other => self.optional(other),
        };
        let Some(raw) = raw.filter(|s| !s.is_empty()) else {
            return refuse(format!("{dimension} has no value to redact"));
        };
        let digest = Sha256::digest(format!("{dimension}:{raw}").as_bytes());
        Ok(format!("{dimension}:{}", &hex::encode(digest)[..8]))
    }

    /// Whether two envelopes describe the same identity position. Two `None`s
    /// never match ("unknown for both" is not "the same"); at least one
    /// field must be concretely and identically populated on both sides and
    /// no concretely populated field may differ.
    pub fn correlates_with(&self, other: &ExecutionIdentity) -> bool {
        let fields: [(&str, Option<&str>, Option<&str>); 8] = [
            ("host_id", Some(&self.host_id), Some(&other.host_id)),
            (
                "tool_provider",
                Some(&self.tool_provider),
                Some(&other.tool_provider),
            ),
            (
                "tool_instance_id",
                self.optional("tool_instance_id"),
                other.optional("tool_instance_id"),
            ),
            (
                "provider_session_id",
                self.optional("provider_session_id"),
                other.optional("provider_session_id"),
            ),
            (
                "agent_id",
                self.optional("agent_id"),
                other.optional("agent_id"),
            ),
            (
                "turn_id",
                self.optional("turn_id"),
                other.optional("turn_id"),
            ),
            (
                "parent_agent_id",
                self.optional("parent_agent_id"),
                other.optional("parent_agent_id"),
            ),
            (
                "session_lineage_id",
                self.optional("session_lineage_id"),
                other.optional("session_lineage_id"),
            ),
        ];
        let mut any_concrete_match = false;
        for (_, left, right) in fields {
            let (Some(left), Some(right)) = (left, right) else {
                continue;
            };
            if left != right {
                return false;
            }
            any_concrete_match = true;
        }
        any_concrete_match
    }
}

/// The provider-native identity fields read out of one hook payload.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NativeIdentity {
    pub provider_session_id: Option<String>,
    pub agent_id: Option<String>,
    pub turn_id: Option<String>,
}

/// The provider's own value for `key`, verbatim, or `None`: a non-object
/// payload, a missing key, a non-string, or an empty/whitespace-only string
/// is *unknown*, never coerced.
fn native(payload: &Value, key: &str) -> Option<String> {
    match payload.as_object()?.get(key)? {
        Value::String(s) if !s.trim().is_empty() => Some(s.clone()),
        _ => None,
    }
}

/// Read the native identity out of a raw hook payload for `tool_provider`
/// (`claude_code`, `codex`). Any other provider is *unattributed* -- no field
/// is read, so none can be invented.
///
/// Claude Code: `session_id`; `agent_id` only on a Task subagent's events
/// (with the parent's `session_id`); no `turn_id` (its `prompt_id` is a
/// prompt-cycle id, not a turn identity). Codex: `session_id`, `turn_id` and
/// (subagent events only) `agent_id`.
pub fn native_identity(tool_provider: &str, payload: &Value) -> NativeIdentity {
    match tool_provider {
        "claude_code" => NativeIdentity {
            provider_session_id: native(payload, "session_id"),
            agent_id: native(payload, "agent_id"),
            turn_id: None,
        },
        "codex" => NativeIdentity {
            provider_session_id: native(payload, "session_id"),
            agent_id: native(payload, "agent_id"),
            turn_id: native(payload, "turn_id"),
        },
        _ => NativeIdentity::default(),
    }
}

/// The provider's own subagent label (`agent_type`), a display attribute and
/// not an identity. Only Claude Code and Codex hooks are read.
pub fn native_agent_type(tool_provider: &str, payload: &Value) -> Option<String> {
    match tool_provider {
        "claude_code" | "codex" => native(payload, "agent_type"),
        _ => None,
    }
}

impl NativeIdentity {
    /// Wrap into a full envelope for `host_id`/`observed_at`. Lineage is
    /// always `unknown`: no provider hook exposes a parent link.
    pub fn into_envelope(
        self,
        tool_provider: &str,
        host_id: &str,
        observed_at: &str,
    ) -> Result<ExecutionIdentity, IdentityError> {
        let document = json!({
            "envelope_version": ENVELOPE_VERSION,
            "observed_at": observed_at,
            "host_id": host_id,
            "tool_provider": tool_provider,
            "lineage_status": "unknown",
        });
        let mut identity = ExecutionIdentity::from_wire(&document)?;
        identity.provider_session_id = self.provider_session_id;
        identity.agent_id = self.agent_id;
        identity.turn_id = self.turn_id;
        Ok(identity)
    }
}
