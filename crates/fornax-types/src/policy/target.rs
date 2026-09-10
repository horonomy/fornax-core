//! Policy targeting, kept separate from content (FORNX-116).
//!
//! `PolicyBinding` carries no policy content and `PolicyContent` carries no
//! targeting. A future canary/staged-rollout ticket adds state to the
//! *binding* side without touching a single content type.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::diagnostics::{
    DiagnosticCode, DiagnosticSeverity, PolicyDiagnostic, PolicyValidationReport,
};
use super::revision::{PolicyRevisionRef, PublishedPolicyRevision};
use crate::{Provider, RuntimeCapabilities, SignalClass};

/// Precedence order: derive order == most-general to most-specific.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetLevel {
    Org,
    Team,
    Project,
    Device,
    LocalUser,
}

/// Coarse OS family for a [`TargetSelector`]. Owned by this ticket (not an
/// existing `fornax-types` enum), so it carries the standard forward-compat
/// `Unrecognized` tail and derives `Ord` for use in a `BTreeSet`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsFamily {
    MacOs,
    Linux,
    Windows,
    #[serde(untagged)]
    Unrecognized(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "level", rename_all = "snake_case", deny_unknown_fields)]
pub enum TargetScope {
    Org { org_id: String },
    Team { org_id: String, team_id: String },
    Project { org_id: String, project_id: String },
    Device { device_id: String },
    LocalUser,
}

impl TargetScope {
    pub fn level(&self) -> TargetLevel {
        match self {
            TargetScope::Org { .. } => TargetLevel::Org,
            TargetScope::Team { .. } => TargetLevel::Team,
            TargetScope::Project { .. } => TargetLevel::Project,
            TargetScope::Device { .. } => TargetLevel::Device,
            TargetScope::LocalUser => TargetLevel::LocalUser,
        }
    }

    fn matches(&self, ctx: &DeviceContext) -> bool {
        match self {
            TargetScope::Org { org_id } => ctx.org_id.as_deref() == Some(org_id.as_str()),
            TargetScope::Team { org_id, team_id } => {
                ctx.org_id.as_deref() == Some(org_id.as_str()) && ctx.team_ids.contains(team_id)
            }
            TargetScope::Project { org_id, project_id } => {
                ctx.org_id.as_deref() == Some(org_id.as_str())
                    && ctx.project_ids.contains(project_id)
            }
            TargetScope::Device { device_id } => &ctx.device_id == device_id,
            TargetScope::LocalUser => true,
        }
    }
}

/// Closed selectors, not predicates. Every field `None` means "matches
/// everything." Evaluated purely against a local [`DeviceContext`] — never
/// a network call (ADR-0001 D2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct TargetSelector {
    /// `Vec`, not a set: `crate::Provider` derives no `Ord` and this
    /// selector is never part of the signed revision body's canonical
    /// bytes, so no canonicalization is required — matching is a plain
    /// membership check.
    pub providers: Option<Vec<Provider>>,
    pub os_families: Option<BTreeSet<OsFamily>>,
    /// Every listed class must be `SignalAvailability::Available` locally.
    /// `Vec` for the same reason as `providers` (`crate::SignalClass` has no
    /// `Ord`/`Hash` — see `content::SensorScope::required_signals`).
    pub requires_signals: Option<Vec<SignalClass>>,
}

impl TargetSelector {
    /// `binding_id` is only used to attribute a `SelectorNotUnderstood`/
    /// `RequiredSignalUnavailable` diagnostic to the right binding.
    fn matches(
        &self,
        ctx: &DeviceContext,
        binding_id: Uuid,
        diagnostics: &mut Vec<PolicyDiagnostic>,
    ) -> bool {
        if let Some(providers) = &self.providers {
            if !providers.contains(&ctx.provider) {
                return false;
            }
        }

        let mut selector_not_understood = false;

        if let Some(os_families) = &self.os_families {
            if os_families
                .iter()
                .any(|o| matches!(o, OsFamily::Unrecognized(_)))
            {
                selector_not_understood = true;
            } else if !os_families.contains(&ctx.os_family) {
                return false;
            }
        }

        if let Some(signals) = &self.requires_signals {
            if signals
                .iter()
                .any(|s| matches!(s, SignalClass::Unrecognized(_)))
            {
                selector_not_understood = true;
            } else {
                for class in signals {
                    if !ctx.capabilities.is_observable(class) {
                        diagnostics.push(
                            PolicyDiagnostic::new(
                                DiagnosticCode::RequiredSignalUnavailable,
                                DiagnosticSeverity::Warning,
                                format!(
                                    "binding requires signal {class:?}, which this device does not report as available"
                                ),
                                "publish a binding whose requires_signals matches what this device can observe, or drop the requirement",
                            )
                            .with_bindings(vec![binding_id]),
                        );
                        return false;
                    }
                }
            }
        }

        if selector_not_understood {
            diagnostics.push(
                PolicyDiagnostic::new(
                    DiagnosticCode::SelectorNotUnderstood,
                    DiagnosticSeverity::Warning,
                    "selector names a value this binary does not recognize; applying the binding rather than silently dropping it",
                    "upgrade this binary to a version that understands the newer selector value",
                )
                .with_bindings(vec![binding_id]),
            );
        }

        true
    }
}

/// Wire/storage form. Holds a reference to a revision, never the content
/// itself — this is the content-vs-targeting separation this module's docs
/// describe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyBinding {
    pub binding_id: Uuid,
    pub scope: TargetScope,
    #[serde(default)]
    pub selector: TargetSelector,
    pub revision_ref: PolicyRevisionRef,
}

impl PolicyBinding {
    pub(crate) fn matches(
        &self,
        ctx: &DeviceContext,
        diagnostics: &mut Vec<PolicyDiagnostic>,
    ) -> bool {
        self.scope.matches(ctx) && self.selector.matches(ctx, self.binding_id, diagnostics)
    }
}

/// Resolve-time join of a binding with the revision bytes the local cache
/// already holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundRevision {
    binding: PolicyBinding,
    revision: PublishedPolicyRevision,
}

impl BoundRevision {
    /// Verifies `binding.revision_ref.digest == revision.digest()` and that
    /// a pin isn't declared at `TargetLevel::LocalUser` (a no-op there —
    /// nothing is more specific).
    pub fn new(
        binding: PolicyBinding,
        revision: PublishedPolicyRevision,
    ) -> Result<Self, PolicyValidationReport> {
        if &binding.revision_ref.digest != revision.digest() {
            return Err(PolicyValidationReport {
                diagnostics: vec![PolicyDiagnostic::new(
                    DiagnosticCode::DigestMismatch,
                    DiagnosticSeverity::Error,
                    "binding.revision_ref.digest does not match the joined revision's digest",
                    "re-fetch the revision the binding actually references, or update the binding",
                )
                .with_bindings(vec![binding.binding_id])],
            });
        }

        if binding.scope.level() == TargetLevel::LocalUser
            && !revision.body().pinned_fields.is_empty()
        {
            return Err(PolicyValidationReport {
                diagnostics: vec![PolicyDiagnostic::new(
                    DiagnosticCode::PinAtLocalUserLayer,
                    DiagnosticSeverity::Error,
                    "a pin at TargetLevel::LocalUser is a no-op -- nothing is more specific than this level",
                    "remove pinned_fields from a revision bound at LocalUser scope",
                )
                .with_bindings(vec![binding.binding_id])],
            });
        }

        Ok(Self { binding, revision })
    }

    pub fn binding(&self) -> &PolicyBinding {
        &self.binding
    }

    pub fn revision(&self) -> &PublishedPolicyRevision {
        &self.revision
    }
}

/// Everything `resolve()` needs to know about the local device, evaluated
/// purely locally (ADR-0001 D2) — never a network call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceContext {
    pub org_id: Option<String>,
    pub team_ids: BTreeSet<String>,
    pub project_ids: BTreeSet<String>,
    pub device_id: String,
    pub provider: Provider,
    pub capabilities: RuntimeCapabilities,
    pub os_family: OsFamily,
}
