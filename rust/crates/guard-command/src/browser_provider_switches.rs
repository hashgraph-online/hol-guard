//! Rollback switches for browser protection and provider integrations.
//!
//! - `HOL_GUARD_BROWSER_PROTECTION=legacy` keeps browser classification on the tables and grants
//!   that shipped before driver profiles. Any other value, or no value, selects the current path.
//! - `HOL_GUARD_PROVIDER_INTEGRATIONS=off` (also `0`, `false`, `disabled`) makes every provider
//!   integration route answer `provider_capability_unavailable` and turns the provider decide step
//!   into a no-op, so no provider evidence can reach a decision.
//!
//! Both follow `HOL_GUARD_DISCOVERY=off`: values are trimmed and compared without case, and the
//! switch is read when it is consulted, so an operator can roll back without a rebuild.

use guard_contracts::{
    ProviderIntegrationErrorV1, BROWSER_PROTECTION_ENV, PROVIDER_INTEGRATIONS_ENV,
};

/// Which browser classification path a decision uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserProtectionMode {
    /// Driver profiles, verbs and grants.
    Current,
    /// The tables and grants that shipped before driver profiles.
    Legacy,
}

/// Parse a `HOL_GUARD_BROWSER_PROTECTION` value. Only `legacy` selects the legacy path, so an
/// unknown or misspelled value never turns protection off.
pub fn browser_protection_mode_from(value: Option<&str>) -> BrowserProtectionMode {
    match value
        .map(|text| text.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("legacy") => BrowserProtectionMode::Legacy,
        _ => BrowserProtectionMode::Current,
    }
}

/// The browser classification path selected by the environment.
pub fn browser_protection_mode() -> BrowserProtectionMode {
    browser_protection_mode_from(std::env::var(BROWSER_PROTECTION_ENV).ok().as_deref())
}

/// Parse a `HOL_GUARD_PROVIDER_INTEGRATIONS` value with the discovery switch's disabled values.
pub fn provider_integrations_enabled_from(value: Option<&str>) -> bool {
    !matches!(
        value
            .map(|text| text.trim().to_ascii_lowercase())
            .as_deref(),
        Some("0" | "off" | "false" | "disabled")
    )
}

/// Whether provider integrations are on in this environment.
pub fn provider_integrations_enabled() -> bool {
    provider_integrations_enabled_from(std::env::var(PROVIDER_INTEGRATIONS_ENV).ok().as_deref())
}

/// Gate for every provider integration route, given the switch value.
pub fn provider_route_gate_from(value: Option<&str>) -> Result<(), ProviderIntegrationErrorV1> {
    if provider_integrations_enabled_from(value) {
        Ok(())
    } else {
        Err(ProviderIntegrationErrorV1::ProviderCapabilityUnavailable)
    }
}

/// Gate for every provider integration route in this environment. A route that gets `Err` answers
/// with the error's code and does no other work.
pub fn provider_route_gate() -> Result<(), ProviderIntegrationErrorV1> {
    provider_route_gate_from(std::env::var(PROVIDER_INTEGRATIONS_ENV).ok().as_deref())
}

/// Run the provider decide step only when integrations are on. When the switch is off the step is a
/// no-op: `step` is not called and the decision gets no provider evidence.
pub fn provider_decide_step_from<T>(value: Option<&str>, step: impl FnOnce() -> Vec<T>) -> Vec<T> {
    if provider_integrations_enabled_from(value) {
        step()
    } else {
        Vec::new()
    }
}

/// [`provider_decide_step_from`] with the switch read from the environment.
pub fn provider_decide_step<T>(step: impl FnOnce() -> Vec<T>) -> Vec<T> {
    provider_decide_step_from(
        std::env::var(PROVIDER_INTEGRATIONS_ENV).ok().as_deref(),
        step,
    )
}

#[cfg(test)]
#[path = "browser_provider_switches_tests.rs"]
mod tests;
