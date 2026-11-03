//! The client and AI-tool sections of `fleet-posture/v1`.
//!
//! Python reads the facts that need the store, the adapters or the config:
//! the stored auto-update state, each tool's setup diagnostics, coverage,
//! latest receipt time, pause state and posture override. This module turns
//! them into the contract's sections (see docs/guard/fleet-posture.md).

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{json, Map, Value};

use crate::cloud_request_text::py_truthy;
use crate::runner_authority_op::ERR_INVALID;

use super::selection::{iso, normalized_timestamp, timestamp};

/// `STALE_AFTER`: activity older than a week makes a protected tool stale.
const STALE_AFTER_MICROS: i64 = 7 * 24 * 60 * 60 * 1_000_000;
const MAX_BLIND_SPOTS: usize = 8;
const MAX_BLIND_SPOT_LENGTH: usize = 80;
const MAX_VERSION_LENGTH: usize = 32;

static VERSION_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[A-Za-z.+-][0-9A-Za-z.+-]*)?$")
        .expect("version pattern compiles")
});
static PRERELEASE_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)[0-9](a|b|rc|dev|alpha|beta)[0-9]*").expect("prerelease pattern compiles")
});

/// `clip`: the first `limit` characters.
fn clip(text: &str, limit: usize) -> String {
    text.chars().take(limit).collect()
}

fn is_true(value: Option<&Value>) -> bool {
    value == Some(&Value::Bool(true))
}

fn truthy(value: Option<&Value>) -> bool {
    value.is_some_and(py_truthy)
}

/// Python's `value == 0`, which `False` and `0.0` also satisfy.
fn equals_zero(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Bool(flag)) => !flag,
        Some(Value::Number(number)) => number.as_f64() == Some(0.0),
        _ => false,
    }
}

fn object(value: Option<&Value>) -> Option<&Map<String, Value>> {
    value.and_then(Value::as_object)
}

/// `_auto_update_state`: the reported auto-update section and the release
/// channel the last check stored.
fn auto_update(raw: Option<&Value>) -> (Value, Option<&str>) {
    let empty = Map::new();
    let state = object(raw).unwrap_or(&empty);
    let status = object(state.get("last_status")).unwrap_or(&empty);
    let last_checked = normalized_timestamp(state.get("last_check_at"));
    let result = if !status.is_empty() {
        let last_update_at = timestamp(state.get("last_update_at"));
        let checked_at = timestamp(state.get("last_check_at"));
        // An update is only attempted when the check found one and nothing blocked it.
        let attempted = is_true(status.get("update_available"))
            && truthy(status.get("auto_updatable"))
            && !truthy(status.get("blocked_reason"));
        let ran_this_cycle = matches!(
            (last_update_at, checked_at),
            (Some(updated), Some(checked)) if updated >= checked
        );
        let exited_cleanly = equals_zero(state.get("last_update_exit_code"));
        if attempted && ran_this_cycle && exited_cleanly {
            Some("updated")
        } else if attempted
            && ((ran_this_cycle && !exited_cleanly)
                || (!ran_this_cycle && is_true(state.get("last_update_error"))))
        {
            Some("failed")
        } else if is_true(status.get("update_available")) {
            Some("update_available")
        } else {
            Some("up_to_date")
        }
    } else if is_true(state.get("last_check_error")) || is_true(state.get("last_update_error")) {
        Some("failed")
    } else {
        None
    };
    let section = json!({
        "enabled": !status.is_empty() && truthy(status.get("auto_updatable")),
        "lastCheckedAt": last_checked,
        "lastResult": result,
    });
    let channel = status
        .get("release_channel")
        .and_then(Value::as_str)
        .filter(|channel| matches!(*channel, "stable" | "alpha"));
    (section, channel)
}

/// `client_section` from the running version, the runtime and the stored
/// auto-update state.
pub(super) fn client_section(client: &Value) -> Result<Value, &'static str> {
    let client = client.as_object().ok_or(ERR_INVALID)?;
    let version = client
        .get("version")
        .and_then(Value::as_str)
        .ok_or(ERR_INVALID)?;
    let (auto_update, stored_channel) = auto_update(client.get("autoUpdateState"));
    let channel = stored_channel.unwrap_or(if PRERELEASE_PATTERN.is_match(version) {
        "alpha"
    } else {
        "stable"
    });
    let reported = if VERSION_PATTERN.is_match(version) {
        version
    } else {
        "0.0.0"
    };
    let runtime = match client.get("runtime").and_then(Value::as_str) {
        Some(runtime @ ("python" | "native")) => runtime,
        _ => "python",
    };
    Ok(json!({
        "version": clip(reported, MAX_VERSION_LENGTH),
        "channel": channel,
        "runtime": runtime,
        "autoUpdate": auto_update,
    }))
}

/// `derive_protection_state`: one tool's protection state.
fn protection_state(
    setup_status: &str,
    has_config_paths: bool,
    paused: bool,
    last_activity: Option<i64>,
    now: i64,
) -> &'static str {
    match setup_status {
        "not_found" if has_config_paths => "needs_setup",
        "not_found" => "not_detected",
        // Adapters report `partial` for a tool that is installed but not managed by Guard.
        "partial" => "needs_setup",
        "broken" => "broken",
        _ if paused => "paused",
        // A freshly protected tool has no receipts yet; only old activity is stale.
        _ if last_activity.is_some_and(|last| now - last > STALE_AFTER_MICROS) => "stale",
        _ => "protected",
    }
}

/// `_posture_override`: Guard's per-app posture in the contract's override
/// vocabulary. The "watch" posture records but never blocks, which is
/// protection off; `observe` is reserved and never emitted.
fn posture_override(tool: &Map<String, Value>) -> Value {
    if !is_true(tool.get("configured")) {
        return Value::Null;
    }
    Value::from(match tool.get("override") {
        None | Some(Value::Null) => "default",
        Some(Value::String(posture)) if posture == "watch" => "off",
        Some(_) => "enforce",
    })
}

fn blind_spots(coverage: &Map<String, Value>) -> Vec<String> {
    coverage
        .get("blindSpots")
        .and_then(Value::as_array)
        .map(|spots| {
            spots
                .iter()
                .filter_map(Value::as_str)
                .take(MAX_BLIND_SPOTS)
                .map(|spot| clip(spot, MAX_BLIND_SPOT_LENGTH))
                .collect()
        })
        .unwrap_or_default()
}

/// `tool_row`: one AI tool's row from its collected facts.
fn tool_row(
    tool: &Map<String, Value>,
    now: i64,
    detail: bool,
) -> Result<(String, Map<String, Value>), &'static str> {
    let harness = tool
        .get("harness")
        .and_then(Value::as_str)
        .ok_or(ERR_INVALID)?;
    let setup_status = tool
        .get("setupStatus")
        .and_then(Value::as_str)
        .ok_or(ERR_INVALID)?;
    let empty = Map::new();
    let coverage = object(tool.get("coverage")).unwrap_or(&empty);
    let last_activity = timestamp(tool.get("lastActivityAt"));
    let state = protection_state(
        setup_status,
        is_true(tool.get("hasConfigPaths")),
        is_true(tool.get("paused")),
        last_activity,
        now,
    );
    let row = json!({
        "harness": harness,
        "toolVersion": tool.get("toolVersion").filter(|version| version.is_string()),
        "setupStatus": setup_status,
        "protectionState": state,
        "hooks": {
            "nativeHooks": truthy(coverage.get("nativeHooks")),
            "browserFallback": truthy(coverage.get("browserFallback")),
            "mcpProxy": truthy(coverage.get("mcpProxy")),
            "promptHooks": truthy(coverage.get("promptHooks")),
        },
        "blindSpots": if detail { blind_spots(coverage) } else { Vec::new() },
        "postureOverride": posture_override(tool),
        "lastActivityAt": last_activity.and_then(iso),
    });
    let Value::Object(row) = row else {
        return Err(ERR_INVALID);
    };
    Ok((harness.to_owned(), row))
}

/// The tool rows to report: a tool that is not detected is reported only
/// once it disappears, so the last report named it in another state.
pub(super) fn reported_tools(
    tools: &[Value],
    last: Option<&Map<String, Value>>,
    now: i64,
    detail: bool,
) -> Result<Vec<(String, Map<String, Value>)>, &'static str> {
    let previous = object(last.and_then(|last| last.get("tools")));
    let mut rows = Vec::new();
    for tool in tools {
        let (harness, row) = tool_row(tool.as_object().ok_or(ERR_INVALID)?, now, detail)?;
        let reported_before = previous
            .and_then(|previous| previous.get(&harness))
            .is_some_and(|state| !state.is_null() && state != "not_detected");
        if row["protectionState"] == "not_detected" && !reported_before {
            continue;
        }
        rows.push((harness, row));
    }
    Ok(rows)
}

#[cfg(test)]
#[path = "fleet_posture_tools_tests.rs"]
mod tests;
