//! Validation of one incoming settings value (`_coerce_editable_setting`).

use guard_command::local_supply_chain::VALID_RISK_ACTION_KEYS;

use crate::guard_config_harness::canonical_harness_id;
use crate::guard_config_update_value::{py_json_eq_int, py_json_repr, py_strip, set, Table, Tv};
use crate::package_authority_config::VALID_SECURITY_LEVELS;
use crate::pyjson::PyVal;

const GUARD_ACTIONS: [&str; 6] = [
    "allow",
    "warn",
    "review",
    "require-reapproval",
    "sandbox-required",
    "block",
];
const MAX_APPROVAL_WAIT_TIMEOUT_SECONDS: i64 = 600;

pub(crate) fn invalid(message: &str) -> String {
    message.to_owned()
}

/// `normalize_protection_posture` on a stored or incoming string.
pub(crate) fn normalize_posture(value: Option<&str>) -> Option<&'static str> {
    let normalized = py_strip(value?).replace('-', "_").to_lowercase();
    ["protected", "extra_careful", "watch"]
        .into_iter()
        .find(|posture| *posture == normalized)
}

fn bounded_int(value: &PyVal, maximum: i64) -> Option<i64> {
    match value {
        PyVal::Int(text) => text
            .parse::<i64>()
            .ok()
            .filter(|number| (0..=maximum).contains(number)),
        _ => None,
    }
}

fn str_in(value: &PyVal, allowed: &[&str]) -> Option<String> {
    value
        .as_str()
        .filter(|text| allowed.contains(text))
        .map(str::to_owned)
}

fn coerce_risk_actions(value: &PyVal) -> Result<Tv, String> {
    let PyVal::Dict(entries) = value else {
        return Err(invalid("Risk actions must be a table."));
    };
    let mut actions = Table::new();
    for (key, action) in entries {
        if !VALID_RISK_ACTION_KEYS.contains(&key.as_str()) {
            return Err(invalid("Invalid Guard risk action."));
        }
        let action =
            str_in(action, &GUARD_ACTIONS).ok_or_else(|| invalid("Invalid Guard risk action."))?;
        set(&mut actions, key, Tv::Str(action));
    }
    Ok(Tv::Table(actions))
}

fn coerce_harness_risk_actions(value: &PyVal) -> Result<Tv, String> {
    let PyVal::Dict(entries) = value else {
        return Err(invalid("Harness risk actions must be a table."));
    };
    let mut harnesses = Table::new();
    for (harness, actions) in entries {
        if py_strip(harness).is_empty() {
            return Err(invalid("Invalid Guard harness."));
        }
        set(&mut harnesses, harness, coerce_risk_actions(actions)?);
    }
    Ok(Tv::Table(harnesses))
}

fn one_of(value: &PyVal, allowed: &[&str], message: &str) -> Result<Tv, String> {
    str_in(value, allowed)
        .map(Tv::Str)
        .ok_or_else(|| invalid(message))
}

fn flag(value: &PyVal, message: &str) -> Result<Tv, String> {
    match value {
        PyVal::Bool(flag) => Ok(Tv::Bool(*flag)),
        _ => Err(invalid(message)),
    }
}

fn int(value: &PyVal, maximum: i64, message: &str) -> Result<Tv, String> {
    bounded_int(value, maximum)
        .map(Tv::Int)
        .ok_or_else(|| invalid(message))
}

/// `_coerce_editable_setting`.
pub(crate) fn coerce_editable(key: &str, value: &PyVal) -> Result<Tv, String> {
    match key {
        "presentation_mode" => one_of(
            value,
            &["everyday", "technical"],
            "Presentation mode must be everyday or technical.",
        ),
        "presentation_mode_explicit" => {
            flag(value, "presentation_mode_explicit must be true or false.")
        }
        "presentation_schema_version" if py_json_eq_int(value, 1) => Ok(Tv::Int(1)),
        "presentation_schema_version" => Err(invalid("Unsupported presentation schema version.")),
        "mode" => one_of(
            value,
            &["observe", "prompt", "enforce"],
            "Invalid Guard mode.",
        ),
        "protection_posture" => normalize_posture(value.as_str())
            .map(|posture| Tv::Str(posture.to_owned()))
            .ok_or_else(|| invalid("Invalid Guard protection posture.")),
        "protection_posture_explicit" => {
            flag(value, "protection_posture_explicit must be true or false.")
        }
        "watch_auto_revert_hours" => int(
            value,
            168,
            "Watch auto-revert hours must be between 0 and 168.",
        ),
        "security_level" => one_of(
            value,
            &VALID_SECURITY_LEVELS,
            "Invalid Guard security level.",
        ),
        "risk_actions" => coerce_risk_actions(value),
        "harness_risk_actions" => coerce_harness_risk_actions(value),
        _ if key.ends_with("_action") => one_of(value, &GUARD_ACTIONS, "Invalid Guard action."),
        "approval_surface_policy" => {
            let policies = [
                "attention-aware",
                "auto-open-once",
                "native-only",
                "approval-center",
            ];
            match str_in(value, &policies) {
                Some(policy) if policy == "auto-open-once" => {
                    Ok(Tv::Str("attention-aware".to_owned()))
                }
                Some(policy) => Ok(Tv::Str(policy)),
                None => Err(invalid("Invalid approval surface policy.")),
            }
        }
        "blocked_request_mode" => one_of(
            value,
            &["safe-alternative", "ask"],
            "Choose safe-alternative or ask for blocked requests.",
        ),
        "approval_browser_delay_seconds" => int(
            value,
            300,
            "Browser attention delay must be between 0 and 300 seconds.",
        ),
        "approval_browser_immediate_severity" => one_of(
            value,
            &["info", "low", "medium", "high", "critical"],
            "Invalid immediate browser attention severity.",
        ),
        "approval_wait_timeout_seconds" => {
            let maximum = MAX_APPROVAL_WAIT_TIMEOUT_SECONDS;
            let message = format!("Approval wait timeout must be between 0 and {maximum} seconds.");
            int(value, maximum, &message)
        }
        "desktop_notifications" | "telemetry" | "sync" | "billing" => {
            flag(value, &format!("{key} must be true or false."))
        }
        "update_channel" => one_of(
            value,
            &["stable", "alpha"],
            "Update channel must be stable or alpha.",
        ),
        "receipt_redaction_level" => str_in(value, &["full", "partial", "none"])
            .map(Tv::Str)
            .ok_or_else(|| format!("Invalid receipt redaction level: {}", py_json_repr(value))),
        _ => Err(format!("Unsupported Guard setting: {key}")),
    }
}

/// `coerce_harness_posture_patch`: `None`/`"inherit"` clears one harness.
pub(crate) fn coerce_harness_patch(
    value: &PyVal,
) -> Result<Vec<(&'static str, Option<&'static str>)>, String> {
    let PyVal::Dict(entries) = value else {
        return Err(invalid("Harness postures must be a table."));
    };
    let mut patch: Vec<(&'static str, Option<&'static str>)> = Vec::new();
    for (key, raw) in entries {
        let harness = canonical_harness_id(py_strip(key))
            .ok_or_else(|| invalid("Unknown Guard harness for protection posture."))?;
        let inherit = match raw {
            PyVal::Null => true,
            PyVal::Str(text) => py_strip(text).to_lowercase() == "inherit",
            _ => false,
        };
        let posture = if inherit {
            None
        } else {
            Some(
                normalize_posture(raw.as_str())
                    .ok_or_else(|| invalid("Invalid Guard protection posture."))?,
            )
        };
        match patch.iter_mut().find(|(name, _)| *name == harness) {
            Some(slot) => slot.1 = posture,
            None => patch.push((harness, posture)),
        }
    }
    Ok(patch)
}
