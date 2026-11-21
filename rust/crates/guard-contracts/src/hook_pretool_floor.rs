//! `HookDecide` `pretool_floor` — wire contract for the PreToolUse floor.
//!
//! A PreToolUse hook floors its verdict at the minimum action the resident's
//! pre-tool review returned for the command. The transport sends the review's
//! `minimum_action` and `reason_code`; whether they floor the verdict, and at
//! which action, is the resident's answer. No pre-tool review at all is a
//! resident outage the transport reports as one, never a floor it picks.

use serde::{Deserialize, Serialize};

/// Advertised when the resident answers `pretool_floor`, the PreToolUse
/// floor; a resident that predates it rejects the query.
pub const HOOK_DECISION_PRETOOL_FLOOR_FEATURE: &str = "hook-decision-pretool-floor-v1";

/// The resident pre-tool review's answer for the command.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PretoolFloorInputsV1 {
    /// The review's `minimum_action`, a canonical Guard action.
    pub minimum_action: String,
    /// The review's `reason_code`; never empty.
    pub reason_code: String,
}

/// The floor the hook verdict is held at.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PretoolFloorV1 {
    /// A canonical Guard action, or `None` when the review does not floor the
    /// verdict (a contextual review the hook settles from its own facts).
    pub floor: Option<String>,
}
