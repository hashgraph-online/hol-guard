//! The configuration fields a per-harness posture resolution reads.
//!
//! The machine-wide posture is the baseline and a harness may carry its own
//! override. Python used to rank the two and derive the mode and security
//! level the override implies; the runtime owns that now, so it is sent the
//! loaded fields instead of a resolved posture.
//!
//! `harness_postures` is keyed by the canonical harness id, which is how the
//! loader stores it and how a caller's harness name is normalized before the
//! lookup.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// `GuardConfig` projected to the fields a posture resolution reads.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HarnessPostureConfigV1 {
    /// `protection_posture` — the machine-wide baseline.
    pub protection_posture: String,
    /// `mode` — an observing install reads as Watch whatever its posture says.
    pub mode: String,
    /// `security_level` — what a Watch override leaves the level at.
    pub security_level: String,
    /// `harness_postures` — the configured override per harness.
    #[serde(default)]
    pub harness_postures: BTreeMap<String, String>,
}
