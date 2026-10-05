//! Bounded decoder for the pinned CanonicalHostEvent v1 contract.
//!
//! Contract source: `horonomy/.github` revision
//! `714e1b04b94dfbd8f85db095c5ba451ea2342f37`,
//! `governance/product/host-adapter/v1/schemas/canonical-host-event.schema.json`
//! (SHA-256 `38ff7b5426781b10e7743c4909609d285b12f4080901f5263ca0c54aa42ac94a`).

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Number, Value};
use std::collections::BTreeMap;
use std::fmt;

pub const CANONICAL_HOST_EVENT_SCHEMA_VERSION: u32 = 1;
pub const MAX_HOST_EVENT_BYTES: usize = 1_048_576;
pub const MAX_HOST_EVENT_NESTING: usize = 64;
pub const CANONICAL_HOST_EVENT_SCHEMA_SHA256: &str =
    "38ff7b5426781b10e7743c4909609d285b12f4080901f5263ca0c54aa42ac94a";

/// # Validated construction boundary
///
/// ```compile_fail
/// use fornax_types::host_event::CanonicalHostEvent;
/// fn corrupt(event: &mut CanonicalHostEvent) {
///     event.observed_at = "2026-10-05T01:02:03Z".to_owned();
/// }
/// ```

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HostEventRejection {
    #[error("host event exceeds the input size limit")]
    InputTooLarge,
    #[error("host event contains excessive nesting")]
    ExcessiveNesting,
    #[error("host event contains duplicate object keys")]
    DuplicateKey,
    #[error("host event is not valid JSON")]
    InvalidJson,
    #[error("host event violates canonical event v1")]
    ContractViolation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostSourceKind {
    Hook,
    Rollout,
    Statusline,
    Cli,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostScope {
    Host,
    Session,
    Agent,
    TurnTask,
    ProjectWorktree,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostEventKind {
    Lifecycle,
    ToolBefore,
    ToolAfter,
    ToolFailure,
    Usage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostEventQuality {
    Literal,
    Reconstructed,
    Heuristic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostLineageStatus {
    Root,
    Child,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostActionKind {
    ShellCommand,
    FileMutation,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperandCompleteness {
    Complete,
    Partial,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostFieldAvailability {
    Observed,
    Unavailable,
    Redacted,
    NotProvided,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostFileOperation {
    Create,
    Update,
    Delete,
    Move,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CanonicalHostEvent {
    event_id: String,
    observed_at: String,
    adapter_id: String,
    adapter_version: String,
    host_version: Option<String>,
    source: HostEventSource,
    capability_snapshot_id: String,
    identity: HostEventIdentity,
    scope: HostScope,
    kind: HostEventKind,
    facts: HostEventFacts,
    quality: HostEventQuality,
    field_provenance: BTreeMap<String, String>,
}

impl CanonicalHostEvent {
    pub fn event_id(&self) -> &str {
        &self.event_id
    }
    pub fn observed_at(&self) -> &str {
        &self.observed_at
    }
    pub fn adapter_id(&self) -> &str {
        &self.adapter_id
    }
    pub fn adapter_version(&self) -> &str {
        &self.adapter_version
    }
    pub fn host_version(&self) -> Option<&str> {
        self.host_version.as_deref()
    }
    pub fn source(&self) -> &HostEventSource {
        &self.source
    }
    pub fn capability_snapshot_id(&self) -> &str {
        &self.capability_snapshot_id
    }
    pub fn identity(&self) -> &HostEventIdentity {
        &self.identity
    }
    pub fn scope(&self) -> HostScope {
        self.scope
    }
    pub fn kind(&self) -> HostEventKind {
        self.kind
    }
    pub fn facts(&self) -> &HostEventFacts {
        &self.facts
    }
    pub fn quality(&self) -> HostEventQuality {
        self.quality
    }
    pub fn field_provenance(&self) -> &BTreeMap<String, String> {
        &self.field_provenance
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostEventSource {
    pub kind: HostSourceKind,
    pub native_event_name: String,
    pub native_schema_ref: Option<String>,
    pub native_event_id: Option<String>,
    pub replay_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HostEventIdentity {
    pub observed_at: String,
    pub host_id: String,
    pub tool_provider: String,
    pub lineage_status: HostLineageStatus,
    pub tool_instance_id: Option<String>,
    pub provider_session_id: Option<String>,
    pub agent_id: Option<String>,
    pub turn_id: Option<String>,
    pub parent_agent_id: Option<String>,
    pub session_lineage_id: Option<String>,
    pub event_id: Option<String>,
    pub repo_id: Option<String>,
    pub worktree_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum HostEventFacts {
    Lifecycle(LifecycleFacts),
    Tool(ToolFacts),
    Usage(UsageFacts),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleFacts {
    pub event_type: String,
    pub native_lifecycle_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ToolFacts {
    pub tool_name: String,
    pub native_call_id: Option<String>,
    pub action_kind: Option<HostActionKind>,
    pub operand_completeness: Option<OperandCompleteness>,
    pub operands: Option<ToolOperands>,
    pub operands_availability: Option<HostFieldAvailability>,
    pub working_directory: Option<String>,
    pub result_availability: Option<HostFieldAvailability>,
    pub result: Option<Value>,
    pub failure_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolOperands {
    ShellCommand(String),
    Files(Vec<FileMutationOperand>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMutationOperand {
    pub operation: HostFileOperation,
    pub path: String,
    pub destination_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct UsageFacts {
    pub measure: String,
    pub amount: Number,
    pub unit: String,
    pub aggregation: String,
    pub observation_scope: HostScope,
    pub model: Option<String>,
}

/// Parse and validate one bounded CanonicalHostEvent v1 JSON document.
///
/// Diagnostics intentionally contain only a bounded rejection category;
/// they never include commands, results, prompts, paths, or native bodies.
pub fn decode_host_event(bytes: &[u8]) -> Result<CanonicalHostEvent, HostEventRejection> {
    if bytes.len() > MAX_HOST_EVENT_BYTES {
        return Err(HostEventRejection::InputTooLarge);
    }
    if exceeds_nesting_limit(bytes) {
        return Err(HostEventRejection::ExcessiveNesting);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let parsed = StrictValue::deserialize(&mut deserializer).map_err(|error| {
        if error.to_string().contains("fornax_duplicate_object_key") {
            HostEventRejection::DuplicateKey
        } else {
            HostEventRejection::InvalidJson
        }
    })?;
    deserializer
        .end()
        .map_err(|_| HostEventRejection::InvalidJson)?;
    validate_event(parsed.0)
}

fn exceeds_nesting_limit(bytes: &[u8]) -> bool {
    let (mut depth, mut in_string, mut escaped) = (0usize, false, false);
    for byte in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                in_string = false;
            }
        } else if *byte == b'"' {
            in_string = true;
        } else if *byte == b'{' || *byte == b'[' {
            depth += 1;
            if depth > MAX_HOST_EVENT_NESTING {
                return true;
            }
        } else if *byte == b'}' || *byte == b']' {
            depth = depth.saturating_sub(1);
        }
    }
    false
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value with unique object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(StrictValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictValue>()? {
            values.push(value.0);
        }
        Ok(StrictValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("fornax_duplicate_object_key"));
            }
            let value = object.next_value::<StrictValue>()?;
            values.insert(key, value.0);
        }
        Ok(StrictValue(Value::Object(values)))
    }
}

fn validate_event(value: Value) -> Result<CanonicalHostEvent, HostEventRejection> {
    let mut root = object(value)?;
    check_keys(
        &root,
        &[
            "schema_version",
            "event_id",
            "observed_at",
            "adapter_id",
            "adapter_version",
            "host_version",
            "source",
            "capability_snapshot_id",
            "identity",
            "scope",
            "kind",
            "facts",
            "quality",
            "field_provenance",
        ],
    )?;
    if !is_json_number_one(root.get("schema_version")) {
        return contract();
    }
    let event_id = take_string(&mut root, "event_id", true)?.expect("required");
    let observed_at = take_string(&mut root, "observed_at", true)?.expect("required");
    validate_timestamp(&observed_at)?;
    let adapter_id = take_string(&mut root, "adapter_id", true)?.expect("required");
    if !valid_adapter_id(&adapter_id) {
        return contract();
    }
    let adapter_version = take_string(&mut root, "adapter_version", true)?.expect("required");
    let host_version = take_string(&mut root, "host_version", false)?;
    let source = validate_source(
        root.remove("source")
            .ok_or(HostEventRejection::ContractViolation)?,
    )?;
    let capability_snapshot_id =
        take_string(&mut root, "capability_snapshot_id", true)?.expect("required");
    let identity = validate_identity(
        root.remove("identity")
            .ok_or(HostEventRejection::ContractViolation)?,
    )?;
    let scope = parse_scope(&take_required_string(&mut root, "scope")?)?;
    let kind = parse_event_kind(&take_required_string(&mut root, "kind")?)?;
    let facts = validate_facts(
        kind,
        root.remove("facts")
            .ok_or(HostEventRejection::ContractViolation)?,
    )?;
    let quality = parse_quality(&take_required_string(&mut root, "quality")?)?;
    let field_provenance = validate_field_provenance(
        root.remove("field_provenance")
            .ok_or(HostEventRejection::ContractViolation)?,
    )?;
    Ok(CanonicalHostEvent {
        event_id,
        observed_at,
        adapter_id,
        adapter_version,
        host_version,
        source,
        capability_snapshot_id,
        identity,
        scope,
        kind,
        facts,
        quality,
        field_provenance,
    })
}

fn validate_source(value: Value) -> Result<HostEventSource, HostEventRejection> {
    let mut object = object(value)?;
    check_keys(
        &object,
        &[
            "kind",
            "native_event_name",
            "native_schema_ref",
            "native_event_id",
            "replay_key",
        ],
    )?;
    let kind = match take_required_string(&mut object, "kind")?.as_str() {
        "hook" => HostSourceKind::Hook,
        "rollout" => HostSourceKind::Rollout,
        "statusline" => HostSourceKind::Statusline,
        "cli" => HostSourceKind::Cli,
        "other" => HostSourceKind::Other,
        _ => return contract(),
    };
    let native_event_name = take_string(&mut object, "native_event_name", true)?.expect("required");
    Ok(HostEventSource {
        kind,
        native_event_name,
        native_schema_ref: take_string(&mut object, "native_schema_ref", false)?,
        native_event_id: take_string(&mut object, "native_event_id", false)?,
        replay_key: take_string(&mut object, "replay_key", false)?,
    })
}

fn validate_identity(value: Value) -> Result<HostEventIdentity, HostEventRejection> {
    let mut object = object(value)?;
    if !object.contains_key("envelope_version")
        || !is_json_number_one(object.get("envelope_version"))
    {
        return contract();
    }
    let observed_at = take_string(&mut object, "observed_at", true)?.expect("required");
    validate_timestamp(&observed_at)?;
    let host_id = take_string(&mut object, "host_id", true)?.expect("required");
    let tool_provider = take_string(&mut object, "tool_provider", true)?.expect("required");
    if !valid_provider_tag(&tool_provider) {
        return contract();
    }
    let lineage_status = match take_required_string(&mut object, "lineage_status")?.as_str() {
        "root" => HostLineageStatus::Root,
        "child" => HostLineageStatus::Child,
        "unknown" => HostLineageStatus::Unknown,
        _ => return contract(),
    };
    let tool_instance_id = take_string(&mut object, "tool_instance_id", false)?;
    let provider_session_id = take_string(&mut object, "provider_session_id", false)?;
    let agent_id = take_string(&mut object, "agent_id", false)?;
    let turn_id = take_string(&mut object, "turn_id", false)?;
    let parent_agent_id = take_string(&mut object, "parent_agent_id", false)?;
    let session_lineage_id = take_string(&mut object, "session_lineage_id", false)?;
    let event_id = take_string(&mut object, "event_id", false)?;
    let repo_id = take_string(&mut object, "repo_id", false)?;
    let worktree_id = take_string(&mut object, "worktree_id", false)?;
    match lineage_status {
        HostLineageStatus::Child if parent_agent_id.as_deref().is_none_or(str::is_empty) => {
            return contract();
        }
        HostLineageStatus::Root | HostLineageStatus::Unknown if parent_agent_id.is_some() => {
            return contract();
        }
        _ => {}
    }
    Ok(HostEventIdentity {
        observed_at,
        host_id,
        tool_provider,
        lineage_status,
        tool_instance_id,
        provider_session_id,
        agent_id,
        turn_id,
        parent_agent_id,
        session_lineage_id,
        event_id,
        repo_id,
        worktree_id,
    })
}

fn validate_facts(kind: HostEventKind, value: Value) -> Result<HostEventFacts, HostEventRejection> {
    let mut facts = object(value)?;
    match kind {
        HostEventKind::Lifecycle => {
            check_keys(&facts, &["event_type", "native_lifecycle_id"])?;
            let event_type = take_required_string(&mut facts, "event_type")?;
            if !matches!(
                event_type.as_str(),
                "session_start"
                    | "session_end"
                    | "turn_start"
                    | "turn_end"
                    | "subagent_start"
                    | "subagent_end"
                    | "interrupt"
                    | "compact"
            ) {
                return contract();
            }
            Ok(HostEventFacts::Lifecycle(LifecycleFacts {
                event_type,
                native_lifecycle_id: take_string(&mut facts, "native_lifecycle_id", false)?,
            }))
        }
        HostEventKind::ToolBefore | HostEventKind::ToolAfter | HostEventKind::ToolFailure => {
            validate_tool_facts(facts).map(HostEventFacts::Tool)
        }
        HostEventKind::Usage => validate_usage_facts(facts).map(HostEventFacts::Usage),
    }
}

fn validate_tool_facts(mut facts: Map<String, Value>) -> Result<ToolFacts, HostEventRejection> {
    check_keys(
        &facts,
        &[
            "tool_name",
            "native_call_id",
            "action_kind",
            "operand_completeness",
            "operands",
            "operands_availability",
            "working_directory",
            "result_availability",
            "result",
            "failure_code",
        ],
    )?;
    let tool_name = take_string(&mut facts, "tool_name", true)?.expect("required");
    let action_kind = take_enum(&mut facts, "action_kind", |value| match value {
        "shell_command" => Some(HostActionKind::ShellCommand),
        "file_mutation" => Some(HostActionKind::FileMutation),
        "unknown" => Some(HostActionKind::Unknown),
        _ => None,
    })?;
    let operand_completeness =
        take_enum(&mut facts, "operand_completeness", |value| match value {
            "complete" => Some(OperandCompleteness::Complete),
            "partial" => Some(OperandCompleteness::Partial),
            "unknown" => Some(OperandCompleteness::Unknown),
            _ => None,
        })?;
    let operands = facts
        .remove("operands")
        .map(validate_operands)
        .transpose()?;
    let operands_availability = take_enum(&mut facts, "operands_availability", parse_availability)?;
    let result_availability = take_enum(&mut facts, "result_availability", parse_availability)?;
    let result = facts.remove("result");
    let native_call_id = take_string(&mut facts, "native_call_id", false)?;
    let working_directory = take_string(&mut facts, "working_directory", false)?;
    if working_directory.as_ref().is_some_and(String::is_empty) {
        return contract();
    }
    let failure_code = take_string(&mut facts, "failure_code", false)?;
    if operand_completeness == Some(OperandCompleteness::Complete)
        && (!matches!(
            action_kind,
            Some(HostActionKind::ShellCommand | HostActionKind::FileMutation)
        ) || operands.is_none()
            || operands_availability != Some(HostFieldAvailability::Observed))
    {
        return contract();
    }
    match (&action_kind, &operands) {
        (Some(HostActionKind::ShellCommand), Some(ToolOperands::Files(_)))
        | (Some(HostActionKind::FileMutation), Some(ToolOperands::ShellCommand(_))) => {
            return contract();
        }
        (Some(HostActionKind::Unknown), _)
            if operand_completeness == Some(OperandCompleteness::Complete)
                || operands.is_some() =>
        {
            return contract();
        }
        _ => {}
    }
    Ok(ToolFacts {
        tool_name,
        native_call_id,
        action_kind,
        operand_completeness,
        operands,
        operands_availability,
        working_directory,
        result_availability,
        result,
        failure_code,
    })
}

fn validate_operands(value: Value) -> Result<ToolOperands, HostEventRejection> {
    let mut operands = object(value)?;
    if operands.contains_key("command") {
        check_keys(&operands, &["command"])?;
        let command = take_string(&mut operands, "command", true)?.expect("required");
        if command.is_empty() {
            return contract();
        }
        return Ok(ToolOperands::ShellCommand(command));
    }
    check_keys(&operands, &["files"])?;
    let Some(Value::Array(files)) = operands.remove("files") else {
        return contract();
    };
    if files.is_empty() {
        return contract();
    }
    let files = files
        .into_iter()
        .map(validate_file_operand)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ToolOperands::Files(files))
}

fn validate_file_operand(value: Value) -> Result<FileMutationOperand, HostEventRejection> {
    let mut object = object(value)?;
    check_keys(&object, &["operation", "path", "destination_path"])?;
    let operation = match take_required_string(&mut object, "operation")?.as_str() {
        "create" => HostFileOperation::Create,
        "update" => HostFileOperation::Update,
        "delete" => HostFileOperation::Delete,
        "move" => HostFileOperation::Move,
        _ => return contract(),
    };
    let path = take_string(&mut object, "path", true)?.expect("required");
    if path.is_empty() {
        return contract();
    }
    let destination_path = take_string(&mut object, "destination_path", false)?;
    if destination_path.as_ref().is_some_and(String::is_empty)
        || (operation == HostFileOperation::Move && destination_path.is_none())
        || (operation != HostFileOperation::Move && destination_path.is_some())
    {
        return contract();
    }
    Ok(FileMutationOperand {
        operation,
        path,
        destination_path,
    })
}

fn validate_usage_facts(mut facts: Map<String, Value>) -> Result<UsageFacts, HostEventRejection> {
    check_keys(
        &facts,
        &[
            "measure",
            "amount",
            "unit",
            "aggregation",
            "observation_scope",
            "model",
        ],
    )?;
    let measure = take_nonempty_string(&mut facts, "measure")?;
    let Some(Value::Number(amount)) = facts.remove("amount") else {
        return contract();
    };
    if amount
        .as_f64()
        .is_none_or(|number| !number.is_finite() || number < 0.0)
    {
        return contract();
    }
    let unit = take_nonempty_string(&mut facts, "unit")?;
    let aggregation = take_required_string(&mut facts, "aggregation")?;
    if !matches!(aggregation.as_str(), "delta" | "cumulative") {
        return contract();
    }
    let observation_scope = parse_scope(&take_required_string(&mut facts, "observation_scope")?)?;
    let model = take_string(&mut facts, "model", false)?;
    Ok(UsageFacts {
        measure,
        amount,
        unit,
        aggregation,
        observation_scope,
        model,
    })
}

fn validate_field_provenance(value: Value) -> Result<BTreeMap<String, String>, HostEventRejection> {
    let object = object(value)?;
    object
        .into_iter()
        .map(|(key, value)| {
            let Value::String(value) = value else {
                return contract();
            };
            if value.is_empty() {
                return contract();
            }
            Ok((key, value))
        })
        .collect()
}

fn object(value: Value) -> Result<Map<String, Value>, HostEventRejection> {
    match value {
        Value::Object(object) => Ok(object),
        _ => contract(),
    }
}

fn check_keys(object: &Map<String, Value>, allowed: &[&str]) -> Result<(), HostEventRejection> {
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        contract()
    } else {
        Ok(())
    }
}

fn take_string(
    object: &mut Map<String, Value>,
    key: &str,
    required: bool,
) -> Result<Option<String>, HostEventRejection> {
    match object.remove(key) {
        Some(Value::String(value)) if !required || !value.is_empty() => Ok(Some(value)),
        Some(_) => contract(),
        None if required => contract(),
        None => Ok(None),
    }
}

fn take_required_string(
    object: &mut Map<String, Value>,
    key: &str,
) -> Result<String, HostEventRejection> {
    take_string(object, key, true).map(|value| value.expect("required"))
}

fn take_nonempty_string(
    object: &mut Map<String, Value>,
    key: &str,
) -> Result<String, HostEventRejection> {
    take_required_string(object, key)
}

fn take_enum<T>(
    object: &mut Map<String, Value>,
    key: &str,
    parse: impl FnOnce(&str) -> Option<T>,
) -> Result<Option<T>, HostEventRejection> {
    let Some(value) = take_string(object, key, false)? else {
        return Ok(None);
    };
    parse(&value)
        .map(Some)
        .ok_or(HostEventRejection::ContractViolation)
}

fn parse_availability(value: &str) -> Option<HostFieldAvailability> {
    match value {
        "observed" => Some(HostFieldAvailability::Observed),
        "unavailable" => Some(HostFieldAvailability::Unavailable),
        "redacted" => Some(HostFieldAvailability::Redacted),
        "not_provided" => Some(HostFieldAvailability::NotProvided),
        _ => None,
    }
}

fn parse_scope(value: &str) -> Result<HostScope, HostEventRejection> {
    match value {
        "host" => Ok(HostScope::Host),
        "session" => Ok(HostScope::Session),
        "agent" => Ok(HostScope::Agent),
        "turn_task" => Ok(HostScope::TurnTask),
        "project_worktree" => Ok(HostScope::ProjectWorktree),
        "unknown" => Ok(HostScope::Unknown),
        _ => contract(),
    }
}

fn parse_event_kind(value: &str) -> Result<HostEventKind, HostEventRejection> {
    match value {
        "lifecycle" => Ok(HostEventKind::Lifecycle),
        "tool_before" => Ok(HostEventKind::ToolBefore),
        "tool_after" => Ok(HostEventKind::ToolAfter),
        "tool_failure" => Ok(HostEventKind::ToolFailure),
        "usage" => Ok(HostEventKind::Usage),
        _ => contract(),
    }
}

fn parse_quality(value: &str) -> Result<HostEventQuality, HostEventRejection> {
    match value {
        "literal" => Ok(HostEventQuality::Literal),
        "reconstructed" => Ok(HostEventQuality::Reconstructed),
        "heuristic" => Ok(HostEventQuality::Heuristic),
        _ => contract(),
    }
}

fn validate_timestamp(value: &str) -> Result<(), HostEventRejection> {
    if !value.ends_with('Z') || chrono::DateTime::parse_from_rfc3339(value).is_err() {
        contract()
    } else {
        Ok(())
    }
}

fn valid_adapter_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_lowercase()
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_' || *byte == b'-'
        })
}

fn valid_provider_tag(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 32
        && bytes[0].is_ascii_lowercase()
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_' || *byte == b'-'
        })
}

fn contract<T>() -> Result<T, HostEventRejection> {
    Err(HostEventRejection::ContractViolation)
}

fn is_json_number_one(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Number(number)) if number.as_f64() == Some(1.0))
}
