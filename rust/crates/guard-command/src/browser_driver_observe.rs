//! R-QUIET-4: observe before tighten for contributed driver profile mappings (BP-T173).
//!
//! A new or changed contributed driver profile can map a tool to a louder class than Guard
//! reaches without it. When that mapping runs in `observe`, the decision stays what Guard decides
//! without the mapping and the louder action is kept as `observed_policy_action`, the field a
//! Watch receipt already carries for a call Guard would have stopped. A mapping in `enforce`
//! decides the call.
//!
//! Observe never lowers anything. First-party profiles are always enforced, whatever a control
//! layer says, and the floor (first-party floors and the native sensitive-surface screens) holds
//! under either effect: Guard never decides below it, and the observed action never reads below
//! it either. A mapping that is not louder than Guard's own decision has nothing to observe and
//! applies as written, still above the floor.

use guard_contracts::BrowserDriverTrustClassV1;
use serde::{Deserialize, Serialize};

use crate::browser_driver_compile::CompiledBrowserDriverV1;
use crate::effect_decision::GuardAction;
use crate::extension_control::ControlLayerKind;

/// The reason code on a decision whose louder mapping was only observed.
pub const BROWSER_MAPPING_OBSERVED: &str = "browser.driver_mapping_observed";

/// How a contributed profile's mapping takes part in the decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BrowserMappingEffect {
    /// The decision is unchanged and a louder mapping is recorded as a would-have-stopped action.
    Observe,
    /// The mapping decides the call.
    Enforce,
}

/// One control-layer entry setting a profile's mapping effect, keyed by the profile id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserMappingEffectControl {
    pub layer: ControlLayerKind,
    pub driver_id: String,
    pub effect: BrowserMappingEffect,
}

/// The effect for one profile under `controls`. A first-party profile is always enforced. A
/// contributed profile is observed only when some layer asks for `observe` and no layer asks for
/// `enforce`, so a layer can always put the stricter effect back.
pub fn browser_mapping_effect(
    driver: &CompiledBrowserDriverV1,
    controls: &[BrowserMappingEffectControl],
) -> BrowserMappingEffect {
    if driver.trust_class != BrowserDriverTrustClassV1::Contributed {
        return BrowserMappingEffect::Enforce;
    }
    let mut observe = false;
    for control in controls
        .iter()
        .filter(|control| control.driver_id == driver.id)
    {
        match control.effect {
            BrowserMappingEffect::Enforce => return BrowserMappingEffect::Enforce,
            BrowserMappingEffect::Observe => observe = true,
        }
    }
    if observe {
        BrowserMappingEffect::Observe
    } else {
        BrowserMappingEffect::Enforce
    }
}

/// What Guard decides for one call, with and without the contributed mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrowserMappingDecisionInput {
    /// The least the call gets from first-party floors and the native sensitive-surface screens.
    pub floor: GuardAction,
    /// Guard's decision when the contributed mapping is left out.
    pub without_mapping: GuardAction,
    /// Guard's decision when the contributed mapping takes part.
    pub with_mapping: GuardAction,
    pub effect: BrowserMappingEffect,
}

/// The decision and, when a louder mapping was only observed, the action it would have taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct BrowserMappingDecision {
    pub policy_action: GuardAction,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_policy_action: Option<GuardAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<&'static str>,
}

pub fn browser_mapping_decision(input: BrowserMappingDecisionInput) -> BrowserMappingDecision {
    let held = |action: GuardAction| louder(action, input.floor);
    let mapped = held(input.with_mapping);
    let unmapped = held(input.without_mapping);
    if input.effect == BrowserMappingEffect::Observe && mapped.severity() > unmapped.severity() {
        return BrowserMappingDecision {
            policy_action: unmapped,
            observed_policy_action: Some(mapped),
            reason_code: Some(BROWSER_MAPPING_OBSERVED),
        };
    }
    BrowserMappingDecision {
        policy_action: mapped,
        observed_policy_action: None,
        reason_code: None,
    }
}

fn louder(left: GuardAction, right: GuardAction) -> GuardAction {
    if right.severity() > left.severity() {
        right
    } else {
        left
    }
}

#[cfg(test)]
#[path = "browser_driver_observe_tests.rs"]
mod tests;
