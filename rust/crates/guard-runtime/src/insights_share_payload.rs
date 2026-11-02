//! `insights_share_payload` runner-authority kind: the shareable Guard
//! insights card the dashboard publishes to Guard Cloud. Ported from
//! `insights_share.build_insights_share_payload`.
//!
//! Python reads the receipt analytics and the overview counters from the
//! store, then ships:
//!
//! - `analytics`, the `receipt_analytics` object;
//! - `include_top_artifacts` and `show_display_name`, the share choices;
//! - `display_name`, the name to show, or `null`;
//! - `overview_stats`, the `pending`/`apps`/`recorded` counters, or `null`;
//! - `generated_at`, the share's timestamp, so this kind stays a pure
//!   function of its arguments.
//!
//! The answer is `{"payload": ...}`, the body Python posts. Counters follow
//! Python's `coerce_int`; percentages round half to even like `round()`.
//! Text fields read a non-empty string and fall back to their default for any
//! other value; the native store only ever writes strings there.

use serde_json::{json, Map, Value};

use crate::daemon_lifecycle_text::{py_strip, python_int};
use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const HEATMAP_DAYS: usize = 90;
const MINI_HEATMAP_DAYS: usize = 5;
const HARNESS_BREAKDOWN_ROWS: usize = 4;
const TOP_ARTIFACT_ROWS: usize = 3;
const LABEL_CHARS: usize = 120;
const UNKNOWN_APP: &str = "Unknown app";

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let analytics = args
        .get("analytics")
        .and_then(Value::as_object)
        .ok_or(ERR_INVALID)?;
    let flag = |key: &str| args.get(key).and_then(Value::as_bool).ok_or(ERR_INVALID);
    let include_top_artifacts = flag("include_top_artifacts")?;
    let show_display_name = flag("show_display_name")?;
    let display_name = match args.get("display_name") {
        Some(Value::Null) => None,
        Some(Value::String(name)) => Some(name.as_str()),
        _ => return Err(ERR_INVALID),
    };
    let overview_stats = match args.get("overview_stats") {
        Some(Value::Null) => None,
        Some(Value::Object(stats)) => Some(stats),
        _ => return Err(ERR_INVALID),
    };
    let generated_at = args
        .get("generated_at")
        .and_then(Value::as_str)
        .ok_or(ERR_INVALID)?;
    Ok(json!({
        "payload": payload(
            analytics,
            include_top_artifacts,
            show_display_name.then_some(display_name).flatten(),
            overview_stats,
            generated_at,
        ),
    }))
}

fn payload(
    analytics: &Map<String, Value>,
    include_top_artifacts: bool,
    display_name: Option<&str>,
    overview_stats: Option<&Map<String, Value>>,
    generated_at: &str,
) -> Value {
    let total = coerce_int(analytics.get("total"));
    let blocked = coerce_int(analytics.get("blocked"));
    let harness_rows = object_rows(analytics.get("by_harness"));
    let top_harness = harness_label(text_or(
        harness_rows.first().and_then(|row| row.get("harness")),
        UNKNOWN_APP,
    ));
    let harness_breakdown: Vec<Value> = harness_rows
        .iter()
        .take(HARNESS_BREAKDOWN_ROWS)
        .map(|row| {
            let count = coerce_int(row.get("total"));
            json!({
                "harness": harness_label(text_or(row.get("harness"), UNKNOWN_APP)),
                "count": count,
                "sharePct": percent(count, total),
            })
        })
        .collect();
    let daily_rows = object_rows(analytics.get("daily_activity"));
    let peak_day_total = coerce_int(analytics.get("peak_day_total"));
    let heatmap_peak = daily_rows
        .iter()
        .map(|row| coerce_int(row.get("total")))
        .max()
        .unwrap_or(peak_day_total);
    let heatmap_cells = heatmap(&daily_rows, HEATMAP_DAYS, heatmap_peak);
    let mini_heatmap_cells = heatmap(&daily_rows, MINI_HEATMAP_DAYS, heatmap_peak);
    let stat = |key: &str| overview_stats.map_or(0, |stats| coerce_int(stats.get(key)));
    let shown_name = display_name.filter(|name| !name.is_empty());
    let mut payload = json!({
        "version": 1,
        "generatedAt": generated_at,
        "source": "local_daemon",
        "period": {
            "label": "all_time",
            "activityDays": nonzero_or_default(daily_rows.len()),
        },
        "headline": {
            "totalActions": total,
            "activeDayStreak": coerce_int(analytics.get("active_day_streak")),
            "peakDayTotal": peak_day_total,
            "blockedCount": blocked,
            "stopRatePct": percent(blocked, total),
            "topHarness": top_harness,
        },
        "harnessBreakdown": harness_breakdown,
        "heatmap": {
            "days": nonzero_or_default(heatmap_cells.len()),
            "cells": heatmap_cells,
        },
        "showDisplayName": shown_name.is_some(),
        "overviewStats": {
            "pending": stat("pending"),
            "apps": stat("apps"),
            "recorded": stat("recorded"),
        },
    });
    let fields = payload.as_object_mut().expect("payload is an object");
    if !mini_heatmap_cells.is_empty() {
        fields.insert(
            "miniHeatmap".to_owned(),
            json!({ "days": mini_heatmap_cells.len(), "cells": mini_heatmap_cells }),
        );
    }
    if let Some(name) = shown_name {
        fields.insert(
            "displayName".to_owned(),
            Value::String(truncate(py_strip(name))),
        );
    }
    if include_top_artifacts {
        let top_artifacts: Vec<Value> = object_rows(analytics.get("top_artifacts"))
            .iter()
            .take(TOP_ARTIFACT_ROWS)
            .map(|row| {
                json!({
                    "label": truncate(text_or(row.get("name"), "Protected action")),
                    "count": coerce_int(row.get("total")),
                })
            })
            .collect();
        fields.insert("topArtifacts".to_owned(), Value::Array(top_artifacts));
    }
    payload
}

/// The object rows of a list field; any other value has none.
fn object_rows(value: Option<&Value>) -> Vec<&Map<String, Value>> {
    value
        .and_then(Value::as_array)
        .map(|rows| rows.iter().filter_map(Value::as_object).collect())
        .unwrap_or_default()
}

/// One cell per dated row among the last `days` rows.
fn heatmap(rows: &[&Map<String, Value>], days: usize, peak: i64) -> Vec<Value> {
    rows[rows.len().saturating_sub(days)..]
        .iter()
        .filter_map(|row| {
            let date_key = text_or(row.get("date_key"), "");
            if date_key.is_empty() {
                return None;
            }
            let level = heatmap_level(coerce_int(row.get("total")), peak);
            Some(json!({ "date": date_key, "level": level }))
        })
        .collect()
}

fn heatmap_level(total: i64, peak: i64) -> u8 {
    if total <= 0 || peak <= 0 {
        return 0;
    }
    let ratio = total as f64 / peak as f64;
    if ratio >= 0.85 {
        4
    } else if ratio >= 0.6 {
        3
    } else if ratio >= 0.35 {
        2
    } else {
        1
    }
}

/// `round((part / whole) * 100)`, or `0` without a whole.
fn percent(part: i64, whole: i64) -> i64 {
    if whole <= 0 {
        return 0;
    }
    ((part as f64 / whole as f64) * 100.0).round_ties_even() as i64
}

fn nonzero_or_default(count: usize) -> usize {
    if count == 0 {
        HEATMAP_DAYS
    } else {
        count
    }
}

fn text_or<'a>(value: Option<&'a Value>, default: &'a str) -> &'a str {
    value
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .unwrap_or(default)
}

fn truncate(text: &str) -> String {
    text.chars().take(LABEL_CHARS).collect()
}

/// The display name of a harness slug. A blank slug is `Unknown app`; an
/// unlisted one is title-cased with hyphens read as spaces.
fn harness_label(harness: &str) -> String {
    let normalized = py_strip(harness).to_lowercase();
    if normalized.is_empty() {
        return UNKNOWN_APP.to_owned();
    }
    let known = match normalized.as_str() {
        "codex" => "Codex",
        "claude-code" => "Claude Code",
        "cursor" => "Cursor",
        "copilot" => "Copilot",
        "gemini-cli" => "Gemini CLI",
        "hermes" => "Hermes",
        "opencode" => "OpenCode",
        "pi" => "Pi",
        "omp" => "Oh My Pi",
        "windsurf" => "Windsurf",
        _ => return title_case(&normalized.replace('-', " ")),
    };
    known.to_owned()
}

/// `str.title()`: a cased character after a cased one is lowered, any other
/// is raised.
fn title_case(text: &str) -> String {
    let mut titled = String::with_capacity(text.len());
    let mut previous_cased = false;
    for character in text.chars() {
        if previous_cased {
            titled.extend(character.to_lowercase());
        } else {
            titled.extend(character.to_uppercase());
        }
        previous_cased = character.is_lowercase() || character.is_uppercase();
    }
    titled
}

/// `value_coercion.coerce_int`: booleans and integers as themselves, finite
/// floats truncated, decimal text parsed, anything else `0`.
fn coerce_int(value: Option<&Value>) -> i64 {
    match value {
        Some(Value::Bool(flag)) => i64::from(*flag),
        Some(Value::Number(number)) => number
            .as_i64()
            .or_else(|| number.as_u64().map(|_| i64::MAX))
            .or_else(|| {
                number
                    .as_f64()
                    .filter(|float| float.is_finite())
                    .map(|float| float.trunc() as i64)
            })
            .unwrap_or(0),
        Some(Value::String(text)) => python_int(text).unwrap_or(0),
        _ => 0,
    }
}

#[cfg(test)]
#[path = "insights_share_payload_tests.rs"]
mod tests;
