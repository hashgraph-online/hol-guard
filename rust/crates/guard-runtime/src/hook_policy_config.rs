//! Native configured-policy action of one hook artifact.
//!
//! Python projects the guard config and per-artifact facts; this module owns
//! the verdict: global/harness risk actions, posture confidence stops, the
//! explicit catalog-permission allow, guard default actions, and the
//! artifact/publisher/harness override and command floor. It mirrors the
//! former Python `_runtime_artifact_policy_action` branch for branch and
//! records which risk classes the posture auto-stopped so Python can emit the
//! protection events.

use guard_command::local_supply_chain::{
    posture_risk_actions, security_level_risk_actions, VALID_RISK_ACTION_KEYS,
};
use guard_contracts::{
    normalize_guard_action, GuardAction, PolicyArtifactFactsV1, PolicyConfigFactsV1,
};
use serde_json::{json, Value};

use crate::hook_artifact_compose_op::stricter;

const DATA_FLOW_RISK: &str = "data_flow_exfiltration";

fn norm(action: &str, fallback: GuardAction) -> GuardAction {
    normalize_guard_action(&Value::String(action.to_owned()), fallback)
}

fn typed(action: &str) -> Option<GuardAction> {
    GuardAction::from_canonical(action)
}

fn configured_harness_action(config: &PolicyConfigFactsV1, risk_class: &str) -> Option<String> {
    config
        .harness_risk_actions
        .get(&config.harness)?
        .get(risk_class)
        .cloned()
}

fn configured_risk_action(config: &PolicyConfigFactsV1, risk_class: &str) -> Option<String> {
    configured_harness_action(config, risk_class)
        .or_else(|| config.risk_actions.get(risk_class).cloned())
}

fn default_risk_action(config: &PolicyConfigFactsV1, risk_class: &str) -> Option<String> {
    let posture = (config.protection_posture_explicit && !config.managed_locks_level)
        .then(|| posture_risk_actions(&config.protection_posture))
        .flatten();
    posture
        .unwrap_or_else(|| security_level_risk_actions(&config.security_level))
        .get(risk_class)
        .cloned()
}

fn resolve_risk_action(config: &PolicyConfigFactsV1, risk_class: &str) -> Option<String> {
    if !VALID_RISK_ACTION_KEYS.contains(&risk_class) {
        return None;
    }
    let resolved = configured_risk_action(config, risk_class)
        .or_else(|| default_risk_action(config, risk_class));
    if config.harness_posture_override.as_deref() != Some("extra_careful") {
        return resolved;
    }
    // A per-harness Extra careful override only ever strengthens.
    let floor =
        posture_risk_actions("extra_careful").and_then(|rows| rows.get(risk_class).cloned());
    match (resolved, floor) {
        (Some(base), Some(floor)) => Some(
            stricter(
                norm(&base, GuardAction::Block),
                norm(&floor, GuardAction::Block),
            )
            .as_str()
            .to_owned(),
        ),
        (base, floor) => base.or(floor),
    }
}

/// Whether the explicit posture turns this risk class into a terminal stop.
fn posture_stops(
    config: &PolicyConfigFactsV1,
    risk_class: &str,
    art: Option<&PolicyArtifactFactsV1>,
    strong: bool,
) -> bool {
    if !matches!(
        config.protection_posture.as_str(),
        "protected" | "extra_careful"
    ) {
        return false;
    }
    if matches!(risk_class, "credential_exfiltration" | DATA_FLOW_RISK) && strong {
        return true;
    }
    if !config.protection_posture_explicit {
        return false;
    }
    let Some(art) = art else {
        return matches!(risk_class, "guard_bypass" | "encoded_exfiltration");
    };
    matches!(risk_class, "guard_bypass" | "encoded_exfiltration")
        || (risk_class == "prompt_injection" && art.hard_block && strong)
        || (risk_class == "persistence" && art.writes_launch_agent)
        || (risk_class == "malicious_skill" && art.skill_is_known_bad)
}

/// The configured data-flow action, strengthened to a stop on strong evidence.
pub(crate) fn data_flow_configured_action(
    config: &PolicyConfigFactsV1,
    strong: bool,
) -> Option<GuardAction> {
    let action = resolve_risk_action(config, DATA_FLOW_RISK)?;
    if posture_stops(config, DATA_FLOW_RISK, None, strong) {
        return Some(GuardAction::Block);
    }
    typed(&action)
}

fn apply_explicit(
    config: &PolicyConfigFactsV1,
    art: &PolicyArtifactFactsV1,
    risk_class: &str,
    action: &str,
    events: &mut Vec<Value>,
) -> GuardAction {
    let resolved = typed(action).unwrap_or(GuardAction::RequireReapproval);
    if !posture_stops(config, risk_class, Some(art), art.confidence_strong) {
        return resolved;
    }
    if resolved != GuardAction::Block {
        events.push(json!({"risk_class": risk_class, "confidence": art.confidence_text}));
    }
    GuardAction::Block
}

/// The configured policy action of one artifact; appends auto-stop events.
pub(crate) fn artifact_policy_action(
    config: &PolicyConfigFactsV1,
    art: &PolicyArtifactFactsV1,
    events: &mut Vec<Value>,
) -> GuardAction {
    if art.hard_block {
        return GuardAction::Block;
    }
    let floor = art
        .command_action_floor
        .as_deref()
        .map(|item| norm(item, GuardAction::Review));
    // Artifact/publisher/harness settings are more specific than the global
    // default. An explicitly enabled catalog permission already accepted the
    // command's cataloged risks, so global risk actions must not re-raise them.
    let current = match &art.configured_override {
        Some(item) => norm(item, GuardAction::Review),
        None if art.explicit_permission_allow => GuardAction::Allow,
        None => norm(&config.default_action, GuardAction::Review),
    };
    let with_config = |action: GuardAction| {
        let floor = if action == GuardAction::SandboxRequired && art.pytest_restricted_sandbox {
            None
        } else {
            floor
        };
        [Some(current), floor]
            .into_iter()
            .flatten()
            .fold(action, stricter)
    };
    let classes = &art.risk_classes;
    if art.explicit_permission_allow {
        let applied: Vec<GuardAction> = classes
            .iter()
            .filter_map(|class| {
                let action = configured_harness_action(config, class)?;
                Some(apply_explicit(config, art, class, &action, events))
            })
            .collect();
        let base = applied
            .into_iter()
            .reduce(stricter)
            .unwrap_or_else(|| floor.unwrap_or(GuardAction::Allow));
        return with_config(base);
    }
    let mut resolve_all = |configured_first: bool| -> Option<GuardAction> {
        let applied: Vec<GuardAction> = classes
            .iter()
            .filter_map(|class| {
                let configured = configured_first
                    .then(|| configured_risk_action(config, class))
                    .flatten();
                let action = configured.or_else(|| resolve_risk_action(config, class))?;
                typed(&action)?;
                Some(apply_explicit(config, art, class, &action, events))
            })
            .collect();
        applied.into_iter().reduce(stricter)
    };
    if classes
        .iter()
        .any(|class| configured_risk_action(config, class).is_some())
    {
        if let Some(resolved) = resolve_all(true) {
            return with_config(resolved);
        }
    }
    let default = art
        .guard_default_action
        .as_deref()
        .map(|item| norm(item, GuardAction::RequireReapproval));
    // The shell local-script detector establishes an approval floor, not a
    // terminal execution block; other independent risks still resolve normally.
    if default == Some(GuardAction::RequireReapproval)
        && art.shell_local_script_review
        && classes.iter().all(|class| class == "execution")
    {
        return with_config(GuardAction::RequireReapproval);
    }
    if default == Some(GuardAction::SandboxRequired) && art.pytest_restricted_sandbox {
        return with_config(GuardAction::SandboxRequired);
    }
    match (resolve_all(false), default) {
        (Some(resolved), Some(default)) => with_config(stricter(resolved, default)),
        (Some(resolved), None) => with_config(resolved),
        (None, Some(default)) => with_config(default),
        (None, None) => with_config(GuardAction::RequireReapproval),
    }
}
