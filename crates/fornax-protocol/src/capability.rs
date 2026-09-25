//! Protocol capability negotiation (FORNX-391 scope: "unsupported
//! evidence/contract semantics remain explicit").
//!
//! A [`ProtocolEnvelope`](crate::envelope::ProtocolEnvelope) declares which
//! optional semantics its payload actually relies on. A consumer that does
//! not implement one of those semantics can detect the gap explicitly via
//! [`missing_capabilities`] instead of silently misinterpreting a field it
//! does not understand (or, worse, silently ignoring a semantic distinction
//! that changes what the payload means).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// One optional semantic a payload may rely on. Closed enum: adding a
/// variant is itself a protocol change governed by
/// `docs/protocol/agent-evidence-protocol.md`'s compatibility policy (AC7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// The payload's independence/dependency reasoning relies on
    /// [`fornax_receipt::multi_agent::MultiAgentSignal`] (FORNX-385) --
    /// a consumer that predates that vocabulary would otherwise
    /// mis-attribute a cross-agent dependency finding.
    MultiAgentSignals,
    /// The payload references an
    /// [`fornax_receipt::incident::IncidentRecord`] (FORNX-389).
    IncidentLinkage,
    /// The payload's satisfaction/decision reasoning depends on a non-default
    /// [`fornax_verify::calibration::CalibrationState`] (FORNX-348) beyond
    /// plain absence of calibration.
    CalibrationState,
}

/// The capabilities in `required` that are not present in `supported` --
/// empty means the consumer can fully interpret the envelope's declared
/// semantics. Never returns an ambiguous "maybe": either a capability is
/// declared supported or it is not.
pub fn missing_capabilities(
    required: &BTreeSet<Capability>,
    supported: &BTreeSet<Capability>,
) -> BTreeSet<Capability> {
    required.difference(supported).copied().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_missing_capabilities_when_everything_required_is_supported() {
        let required = BTreeSet::from([Capability::MultiAgentSignals]);
        let supported =
            BTreeSet::from([Capability::MultiAgentSignals, Capability::IncidentLinkage]);
        assert!(missing_capabilities(&required, &supported).is_empty());
    }

    #[test]
    fn an_unsupported_required_capability_is_reported_explicitly() {
        let required = BTreeSet::from([Capability::CalibrationState]);
        let supported = BTreeSet::from([Capability::MultiAgentSignals]);
        assert_eq!(
            missing_capabilities(&required, &supported),
            BTreeSet::from([Capability::CalibrationState])
        );
    }

    #[test]
    fn empty_requirements_are_always_satisfiable() {
        let required = BTreeSet::new();
        let supported = BTreeSet::new();
        assert!(missing_capabilities(&required, &supported).is_empty());
    }
}
