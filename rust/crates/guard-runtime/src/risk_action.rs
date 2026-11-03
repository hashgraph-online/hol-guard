//! Resolve the configured action of a risk class from a sent configuration.
//!
//! `config.resolve_risk_action` is already ported against the `GuardConfig`
//! mirror in `guard_command::local_supply_chain`. Callers that send the
//! configuration rather than a loaded config hydrate the mirror here, so one
//! resolver answers for all of them and no caller resolves a risk class of
//! its own.

use guard_command::local_supply_chain::{resolve_risk_action, GuardConfig};
use guard_contracts::RiskActionConfigV1;

/// The mirror the sent configuration describes.
///
/// `guard_home` is where a config was read from rather than a policy field,
/// and the resolver never reads it, so it is left unset. `extra` carries
/// fields this resolution does not read and is left empty for the same reason.
fn mirror(config: &RiskActionConfigV1) -> GuardConfig {
    GuardConfig {
        security_level: config.security_level.clone(),
        protection_posture: config.protection_posture.clone(),
        protection_posture_explicit: config.protection_posture_explicit,
        managed_locked_settings: config.managed_locked_settings.clone(),
        risk_actions: Some(config.risk_actions.clone()),
        harness_risk_actions: Some(config.harness_risk_actions.clone()),
        harness_postures: Some(config.harness_postures.clone()),
        managed_policy_status: String::new(),
        managed_policy_hash: None,
        guard_home: None,
        extra: serde_json::Map::new(),
    }
}

/// The configured action of `risk_class`, or `None` when nothing configures
/// it and no default names it.
pub(crate) fn configured_risk_action(
    config: &RiskActionConfigV1,
    risk_class: &str,
    harness: Option<&str>,
) -> Option<String> {
    resolve_risk_action(&mirror(config), Some(risk_class), harness)
}

#[cfg(test)]
#[path = "risk_action_tests.rs"]
mod tests;
