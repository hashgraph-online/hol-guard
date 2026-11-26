//! Which compiled browser driver profiles take part in matching.
//!
//! First-party profiles are on unless a control layer turns them off. A contributed profile is
//! inert until a local administrator enables it on this device. A signed cloud layer can turn a
//! profile off but can never turn a contributed one on, the same rule contributed MCP server
//! entries follow. Any layer's `disabled` wins over any `enabled`.
//!
//! A this-device custom MCP grant for the server still decides the call: a profile describes a
//! driver, it does not replace a decision the user made on this device.

use guard_contracts::BrowserDriverTrustClassV1;

use crate::browser_driver_compile::CompiledBrowserDriverV1;
use crate::extension_control::{ControlLayerKind, ControlState};

/// One control-layer entry for a browser driver profile, keyed by the profile id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserDriverControl {
    pub layer: ControlLayerKind,
    pub driver_id: String,
    pub state: ControlState,
}

/// Whether one profile takes part in matching under `controls`.
pub fn browser_driver_enabled(
    driver: &CompiledBrowserDriverV1,
    controls: &[BrowserDriverControl],
) -> bool {
    let mut local_enable = false;
    for control in controls
        .iter()
        .filter(|control| control.driver_id == driver.id)
    {
        match (control.state, control.layer) {
            (ControlState::Disabled, _) => return false,
            (ControlState::Enabled, ControlLayerKind::LocalAdmin) => local_enable = true,
            (ControlState::Enabled, ControlLayerKind::SignedCloud) => {}
        }
    }
    match driver.trust_class {
        BrowserDriverTrustClassV1::FirstParty => true,
        BrowserDriverTrustClassV1::Contributed => local_enable,
        BrowserDriverTrustClassV1::Unprofiled => false,
    }
}

/// The profiles that take part in matching, in table order.
pub fn enabled_browser_drivers(
    drivers: &[CompiledBrowserDriverV1],
    controls: &[BrowserDriverControl],
) -> Vec<CompiledBrowserDriverV1> {
    drivers
        .iter()
        .filter(|driver| browser_driver_enabled(driver, controls))
        .cloned()
        .collect()
}

/// Who decides a matched browser call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserDecisionSource {
    /// A this-device custom MCP grant for the server decides; the profile only labels the card.
    DeviceCustomGrant,
    /// The profile's projection feeds Guard's browser review.
    DriverProfile,
}

/// A this-device custom MCP grant wins over any driver profile.
pub fn browser_decision_source(has_device_custom_mcp_grant: bool) -> BrowserDecisionSource {
    if has_device_custom_mcp_grant {
        BrowserDecisionSource::DeviceCustomGrant
    } else {
        BrowserDecisionSource::DriverProfile
    }
}

#[cfg(test)]
#[path = "browser_driver_enablement_tests.rs"]
mod tests;
