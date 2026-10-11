//! Loaded-value coercion for the effective Guard configuration.
//!
//! Mirrors the `_coerce_loaded_*` helpers of `guard/config.py`. A malformed
//! stored value never errors: it falls back to the documented default.

use std::collections::BTreeMap;

use guard_command::action_lattice::normalize_guard_action;
use guard_command::effect_decision::GuardAction;
use serde_json::{Map, Value};

use crate::package_authority_config::coerce_risk_action_map;

/// A TOML integer. Floats and booleans are never integers.
fn plain_int(value: Option<&Value>) -> Option<i64> {
    value?.as_i64()
}

pub(crate) fn non_negative_int(value: Option<&Value>, fallback: i64) -> i64 {
    plain_int(value).filter(|v| *v >= 0).unwrap_or(fallback)
}

pub(crate) fn bounded_int(value: Option<&Value>, default: i64, maximum: i64) -> i64 {
    plain_int(value)
        .filter(|v| (0..=maximum).contains(v))
        .unwrap_or(default)
}

pub(crate) fn bounded_positive_int(value: Option<&Value>, default: i64, maximum: i64) -> i64 {
    plain_int(value)
        .filter(|v| (1..=maximum).contains(v))
        .unwrap_or(default)
}

pub(crate) fn optional_bounded_positive_int(value: Option<&Value>, maximum: i64) -> Option<i64> {
    plain_int(value).filter(|v| (1..=maximum).contains(v))
}

pub(crate) fn positive_int(value: Option<&Value>, fallback: i64) -> i64 {
    plain_int(value).filter(|v| *v > 0).unwrap_or(fallback)
}

/// `_coerce_loaded_bool`: only a real boolean counts; anything else is false.
pub(crate) fn loaded_bool(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Bool(true)))
}

/// Python `bool(value)` for the legacy `telemetry`/`sync`/`billing` flags.
pub(crate) fn python_truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(Value::Number(number)) => number
            .as_i64()
            .map_or_else(|| number.as_f64().is_some_and(|f| f != 0.0), |i| i != 0),
        Some(Value::String(text)) => !text.is_empty(),
        Some(Value::Array(items)) => !items.is_empty(),
        Some(Value::Object(map)) => !map.is_empty(),
    }
}

fn string_in<'a>(value: Option<&'a Value>, allowed: &[&str]) -> Option<&'a str> {
    value
        .and_then(Value::as_str)
        .filter(|text| allowed.contains(text))
}

pub(crate) fn update_channel(value: Option<&Value>) -> &'static str {
    match string_in(value, &["stable", "alpha"]) {
        Some("alpha") => "alpha",
        _ => "stable",
    }
}

pub(crate) fn sandbox_analysis(value: Option<&Value>) -> &'static str {
    match string_in(value, &["off", "suspicious", "strict"]) {
        Some("suspicious") => "suspicious",
        Some("strict") => "strict",
        _ => "off",
    }
}

pub(crate) fn receipt_redaction_level(value: Option<&Value>) -> &'static str {
    match string_in(value, &["full", "partial", "none"]) {
        Some("partial") => "partial",
        Some("none") => "none",
        _ => "full",
    }
}

pub(crate) fn approval_surface_policy(value: Option<&Value>) -> &'static str {
    match string_in(value, &["native-only"]) {
        Some(_) => "native-only",
        None => "attention-aware",
    }
}

pub(crate) fn approval_browser_severity(value: Option<&Value>) -> &'static str {
    match string_in(value, &["info", "low", "medium", "high", "critical"]) {
        Some("info") => "info",
        Some("low") => "low",
        Some("medium") => "medium",
        Some("high") => "high",
        _ => "critical",
    }
}

pub(crate) fn loaded_mode(value: Option<&Value>, fallback: &'static str) -> &'static str {
    match string_in(value, &["observe", "prompt", "enforce"]) {
        Some("observe") => "observe",
        Some("prompt") => "prompt",
        Some("enforce") => "enforce",
        _ => fallback,
    }
}

pub(crate) fn blocked_request_mode(value: Option<&Value>) -> &'static str {
    if value.and_then(Value::as_str) == Some("ask") {
        "ask"
    } else {
        "safe-alternative"
    }
}

/// `_coerce_loaded_guard_action_or_default`: an absent value takes the
/// default, a malformed one fails closed to `require-reapproval`.
pub(crate) fn action_or_default(value: Option<&Value>, fallback: GuardAction) -> GuardAction {
    match value {
        None => fallback,
        Some(present) => normalize_guard_action(present, GuardAction::RequireReapproval),
    }
}

/// `_coerce_loaded_string_tuple`.
pub(crate) fn string_list(value: Option<&Value>) -> Vec<String> {
    let Some(Value::Array(items)) = value else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(Value::as_str)
        .filter(|item| !item.trim().is_empty())
        .map(str::to_owned)
        .collect()
}

/// `_coerce_action_map`: every string key keeps a normalized action.
pub(crate) fn action_map(value: Option<&Value>) -> BTreeMap<String, String> {
    let Some(Value::Object(map)) = value else {
        return BTreeMap::new();
    };
    map.iter()
        .map(|(key, entry)| {
            let raw = match entry {
                Value::Object(table) => table
                    .get("action")
                    .or_else(|| table.get("default_action"))
                    .unwrap_or(entry),
                other => other,
            };
            let action = normalize_guard_action(raw, GuardAction::RequireReapproval);
            (key.clone(), action.as_str().to_owned())
        })
        .collect()
}

pub(crate) fn risk_action_map(value: Option<&Value>) -> BTreeMap<String, String> {
    coerce_risk_action_map(value)
}

/// `coerce_persisted_presentation_mode`.
pub(crate) struct Presentation {
    pub(crate) value: &'static str,
    pub(crate) explicit: bool,
    pub(crate) source: &'static str,
    pub(crate) diagnostic: Option<String>,
}

fn is_schema_version_one(value: Option<&Value>) -> bool {
    match value {
        None => true,
        Some(Value::Bool(flag)) => *flag,
        Some(Value::Number(number)) => number
            .as_i64()
            .map_or_else(|| number.as_f64() == Some(1.0), |i| i == 1),
        Some(_) => false,
    }
}

fn presentation_fallback(diagnostic: Option<&str>) -> Presentation {
    Presentation {
        value: "everyday",
        explicit: false,
        source: "default",
        diagnostic: diagnostic.map(str::to_owned),
    }
}

pub(crate) fn presentation(
    value: Option<&Value>,
    explicit: Option<&Value>,
    schema_version: Option<&Value>,
) -> Presentation {
    let is_explicit = matches!(explicit, Some(Value::Bool(true)));
    if !is_schema_version_one(schema_version) {
        return presentation_fallback(Some(
            "unsupported_presentation_schema_fell_back_to_everyday",
        ));
    }
    let text = value.and_then(Value::as_str);
    match text {
        Some(mode @ ("everyday" | "technical")) => Presentation {
            value: if mode == "technical" {
                "technical"
            } else {
                "everyday"
            },
            explicit: is_explicit,
            source: if is_explicit {
                "local-explicit"
            } else {
                "default"
            },
            diagnostic: None,
        },
        Some(legacy @ ("simple" | "advanced" | "developer")) => Presentation {
            value: if legacy == "simple" {
                "everyday"
            } else {
                "technical"
            },
            explicit: true,
            source: "migrated",
            diagnostic: Some(format!("migrated_legacy_{legacy}_presentation_mode")),
        },
        _ if value.is_none() || text == Some("") => presentation_fallback(None),
        _ => presentation_fallback(Some("unknown_presentation_mode_fell_back_to_everyday")),
    }
}

/// Resolve the first present legacy presentation key, in Python's order.
pub(crate) fn legacy_presentation_value(merged: &Map<String, Value>) -> Option<&Value> {
    [
        "presentation_mode",
        "presentation_density",
        "display_density",
        "density",
    ]
    .iter()
    .find_map(|key| merged.get(*key))
}
