//! Pure local projection from canonical host observations to the existing
//! Claude Bash result sensor. This module does not activate an ingress.

use fornax_types::host_event::{
    CanonicalHostEvent, HostEventFacts, HostEventKind, HostEventQuality, HostFieldAvailability,
    HostSourceKind, OperandCompleteness, ToolOperands,
};
use fornax_types::{
    AgentEvent, EventKind, Provider, RuntimeCapabilities, SensorDisableConfig, SignalAvailability,
};
use serde_json::json;
use std::collections::HashMap;
use uuid::Uuid;

use crate::{collect_claude_bash_exit_code, ADAPTER_VERSION};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostBindingGapReason {
    ProviderBindingUnavailable,
    SessionIdentityUnavailable,
    EventBindingUnavailable,
    SourceBindingUnavailable,
    SourceQualityUnavailable,
    OperandsUnavailable,
    ResultUnavailable,
    ResultShapeUnavailable,
    ExitCodeUnavailable,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HostObservationProvenance {
    /// Retains canonical identifiers, source-native IDs, typed identity
    /// (including absent optional fields), scope, snapshot, quality and
    /// field provenance without putting a fabricated hook in `AgentEvent.raw`.
    pub canonical_event: CanonicalHostEvent,
}

#[derive(Debug, Clone)]
pub struct BoundHostObservation {
    pub event: AgentEvent,
    pub evidence: Vec<fornax_types::Evidence>,
    pub provenance: HostObservationProvenance,
    pub sensor_state: SignalAvailability,
    pub sensor_detail: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HostBindingGap {
    pub reason: HostBindingGapReason,
    pub provenance: HostObservationProvenance,
}

#[derive(Debug, Clone)]
pub enum HostBindingOutcome {
    Bound(Box<BoundHostObservation>),
    Gap(Box<HostBindingGap>),
}

/// Bind one schema-valid canonical event to the current Claude Bash sensor.
///
/// Adapter identity and capability snapshot values remain correlation claims;
/// this function does not establish registration, trust, or active capability.
pub fn bind_host_event(
    canonical: &CanonicalHostEvent,
    disabled: &SensorDisableConfig,
) -> HostBindingOutcome {
    let provenance = HostObservationProvenance {
        canonical_event: canonical.clone(),
    };
    if canonical.identity().tool_provider != "claude_code" {
        return gap(HostBindingGapReason::ProviderBindingUnavailable, provenance);
    }
    let Some(session_id) = canonical
        .identity()
        .provider_session_id
        .as_ref()
        .filter(|session_id| !session_id.is_empty())
    else {
        return gap(HostBindingGapReason::SessionIdentityUnavailable, provenance);
    };
    if canonical.kind() != HostEventKind::ToolAfter {
        return gap(HostBindingGapReason::EventBindingUnavailable, provenance);
    }
    if canonical.source().kind != HostSourceKind::Hook
        || canonical.source().native_event_name != "PostToolUse"
    {
        return gap(HostBindingGapReason::SourceBindingUnavailable, provenance);
    }
    if canonical.quality() != HostEventQuality::Literal {
        return gap(HostBindingGapReason::SourceQualityUnavailable, provenance);
    }
    let HostEventFacts::Tool(facts) = canonical.facts() else {
        return gap(HostBindingGapReason::EventBindingUnavailable, provenance);
    };
    if facts.tool_name != "Bash" {
        return gap(HostBindingGapReason::EventBindingUnavailable, provenance);
    }
    if facts.result_availability != Some(HostFieldAvailability::Observed) || facts.result.is_none()
    {
        return gap(HostBindingGapReason::ResultUnavailable, provenance);
    }
    if !recognized_native_result(facts.result.as_ref().expect("checked above")) {
        return gap(HostBindingGapReason::ResultShapeUnavailable, provenance);
    }
    let (
        Some(OperandCompleteness::Complete),
        Some(HostFieldAvailability::Observed),
        Some(ToolOperands::ShellCommand(command)),
    ) = (
        facts.operand_completeness,
        facts.operands_availability,
        facts.operands.as_ref(),
    )
    else {
        return gap(HostBindingGapReason::OperandsUnavailable, provenance);
    };
    let event = AgentEvent {
        id: Uuid::new_v4(),
        session_id: session_id.clone(),
        provider: Provider::ClaudeCode,
        kind: EventKind::PostToolUse,
        observed_at: canonical.observed_at().to_owned(),
        tool_name: Some("Bash".to_string()),
        tool_input: Some(json!({"command": command})),
        tool_response: facts.result.clone(),
        raw: serde_json::Value::Null,
    };
    let capabilities = RuntimeCapabilities {
        schema_version: fornax_types::CAPABILITY_SCHEMA_VERSION,
        provider: Provider::ClaudeCode,
        signals: Vec::new(),
        notes: HashMap::new(),
    };
    let outcome = collect_claude_bash_exit_code(&event, ADAPTER_VERSION, &capabilities, disabled);
    if outcome.state != SignalAvailability::Disabled && outcome.evidence.is_empty() {
        return gap(HostBindingGapReason::ExitCodeUnavailable, provenance);
    }
    HostBindingOutcome::Bound(Box::new(BoundHostObservation {
        event,
        evidence: outcome.evidence,
        provenance,
        sensor_state: outcome.state,
        sensor_detail: outcome.detail,
    }))
}

fn gap(reason: HostBindingGapReason, provenance: HostObservationProvenance) -> HostBindingOutcome {
    HostBindingOutcome::Gap(Box::new(HostBindingGap { reason, provenance }))
}

fn recognized_native_result(value: &serde_json::Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    let mut recognized = false;
    for key in ["stdout", "stderr"] {
        if let Some(value) = object.get(key) {
            if !value.is_string() {
                return false;
            }
            recognized = true;
        }
    }
    for key in ["interrupted", "isImage", "noOutputExpected"] {
        if let Some(value) = object.get(key) {
            if !value.is_boolean() {
                return false;
            }
            recognized = true;
        }
    }
    for key in ["exit_code", "exitCode", "returncode", "status"] {
        if let Some(value) = object.get(key) {
            if value.as_i64().is_none() {
                return false;
            }
            recognized = true;
        }
    }
    recognized
}
