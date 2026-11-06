//! The configuration fields a risk-action resolution reads.
//!
//! Python used to resolve the action for a risk class and send the verdict
//! with the request. The resident owns every verdict, so it is sent the
//! configuration instead and resolves the class itself. These are exactly the
//! fields `resolve_risk_action` and its posture/security-level defaults read,
//! projected from the loaded `GuardConfig` without being interpreted.
//!
//! The maps are sent as they were loaded. `harness_risk_actions` is keyed the
//! way the caller's harness name is spelled, and `harness_postures` by the
//! canonical harness id, because that is how the resolver reads each of them.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// `GuardConfig` projected to the fields a risk-action resolution reads.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RiskActionConfigV1 {
    /// `security_level` — the defaults used when no posture applies.
    pub security_level: String,
    /// `protection_posture` — the defaults used when it is explicit.
    pub protection_posture: String,
    /// `protection_posture_explicit`.
    pub protection_posture_explicit: bool,
    /// `managed_locked_settings`; a locked `security_level` keeps the posture
    /// defaults out.
    #[serde(default)]
    pub managed_locked_settings: Vec<String>,
    /// `risk_actions` — the configured action per risk class.
    #[serde(default)]
    pub risk_actions: BTreeMap<String, String>,
    /// `harness_risk_actions` — the same, per harness.
    #[serde(default)]
    pub harness_risk_actions: BTreeMap<String, BTreeMap<String, String>>,
    /// `harness_postures` — read for the per-harness Extra careful floor.
    #[serde(default)]
    pub harness_postures: BTreeMap<String, String>,
}
