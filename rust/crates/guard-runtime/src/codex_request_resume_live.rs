//! Whether a Codex hook is still waiting on the browser decision.
//!
//! This is the retired Python `_live_hook_wait_is_active`,
//! `_pretool_bridge_wait_is_active` and `codex_live_hook_wait_deadline` of
//! `codex_resume.py`. A saved decision is handed to the hook itself only while
//! the hook's process is the one that was recorded and its deadline has not
//! passed. The caller's clock is the `now` of the call.

use std::path::{Path, PathBuf};

use rusqlite::Connection;
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::cloud_request_text::py_truthy;
use crate::codex_hook_bridge::MAX_APPROVAL_WAIT_SECONDS;
use crate::codex_hook_identity::process_identity_matches;
use crate::codex_live_wait_build::managed_policy_source;
use crate::codex_request_resume_op::{defer, Call};
use crate::codex_request_resume_store as store;
use crate::guard_config_load::approval_wait_timeout_seconds_under;
use crate::guard_store_db::StoreResult;
use crate::guard_store_json::{
    add_micros_aware_isoformat, aware_epoch_micros, epoch_micros, py_str, py_strip,
};
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const WAITS_KEY: &str = "codex_hook_waits_for_browser_approval";
const PROCESS_KEY: &str = "codex_browser_wait_process";
const DEADLINE_KEYS: [&str; 2] = ["codex_browser_wait_deadline_at", "browser_wait_deadline_at"];
const EVENT_KEYS: [&str; 2] = ["hook_event_name", "event"];
const PRETOOL: &str = "PreToolUse";
const WAITING: &str = "waiting_on_approval";
const DEFAULT_WAIT_SECONDS: i64 = 120;
/// The bridge waits this much past the configured budget, less the 2 seconds
/// it gives back.
const BRIDGE_ALLOWANCE_SECONDS: i64 = 5 - 2;
const MICROS: i64 = 1_000_000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetArgs {
    operation: Option<Map<String, Value>>,
    metadata: Map<String, Value>,
}

/// Project the live-hook facts used by continuation offers without changing
/// operation or approval state.
pub(crate) fn dispatch_target(args: &Value, guard_home: &str) -> KindResult {
    let TargetArgs {
        operation,
        metadata,
    } = TargetArgs::deserialize(args).map_err(|_| ERR_INVALID)?;
    let declared = browser_wait_declared(&metadata);
    let waiting = operation.filter(|op| op.get("status").and_then(Value::as_str) == Some(WAITING));
    let live = (declared || waiting.is_some()) && process_is_live(&metadata);
    let wait_deadline = waiting
        .filter(|_| live)
        .as_ref()
        .and_then(|op| deadline_source(op, &metadata, Path::new(guard_home)))
        .and_then(|(text, micros)| add_micros_aware_isoformat(text, micros));
    Ok(json!({
        "process_unavailable": declared && !live,
        "wait_deadline": wait_deadline,
    }))
}

/// `defer_request_resume_to_live_hook`'s precondition: the approval's Codex
/// operation is waiting on a hook that is live at `call.now`.
fn hook_is_waiting(
    connection: &Connection,
    call: &Call<'_>,
    guard_home: &Path,
) -> StoreResult<bool> {
    let Some(operation) = store::operation(connection, call.request_id)? else {
        return Ok(false);
    };
    if py_str(&operation["harness"]).as_deref() != Some("codex")
        || py_str(&operation["status"]).as_deref() != Some(WAITING)
    {
        return Ok(false);
    }
    let Some(metadata) = operation["metadata"].as_object() else {
        return Ok(false);
    };
    let now = epoch_micros(call.now);
    if live_hook_wait_is_active(metadata, now) {
        return Ok(true);
    }
    Ok(event_name(metadata) == PRETOOL
        && pretool_bridge_wait_is_active(&operation, metadata, now, guard_home))
}

/// `defer_request_resume_to_live_hook`: hands the decision to the Codex hook
/// that is still waiting for it, or records nothing when none is.
pub(crate) fn defer_live(
    connection: &Connection,
    call: &Call<'_>,
    action: &str,
    guard_home: &Path,
) -> StoreResult<Option<Value>> {
    if !hook_is_waiting(connection, call, guard_home)? {
        return Ok(None);
    }
    defer(connection, call, action)
}

/// `_live_hook_wait_is_active`: the explicit deadline of a hook that waits for
/// the browser, and has not passed.
fn live_hook_wait_is_active(metadata: &Map<String, Value>, now: Option<i128>) -> bool {
    if !browser_wait_declared(metadata) || !process_is_live(metadata) {
        return false;
    }
    let deadline = first_string(metadata, &DEADLINE_KEYS).and_then(epoch_micros);
    matches!((now, deadline), (Some(now), Some(deadline)) if now <= deadline)
}

/// `_pretool_bridge_wait_is_active`.
fn pretool_bridge_wait_is_active(
    operation: &Value,
    metadata: &Map<String, Value>,
    now: Option<i128>,
    guard_home: &Path,
) -> bool {
    // The operation is read as a PreToolUse wait even when it names no event.
    let mut metadata = metadata.clone();
    if !metadata.get(EVENT_KEYS[0]).is_some_and(py_truthy) {
        metadata.insert(EVENT_KEYS[0].to_owned(), Value::from(PRETOOL));
    }
    let deadline = live_hook_wait_deadline(operation, &metadata, guard_home);
    matches!((now, deadline), (Some(now), Some(deadline)) if now <= deadline)
}

/// `codex_live_hook_wait_deadline` of a waiting operation, in microseconds
/// since the epoch.
fn live_hook_wait_deadline(
    operation: &Value,
    metadata: &Map<String, Value>,
    guard_home: &Path,
) -> Option<i128> {
    if !process_is_live(metadata) {
        return None;
    }
    let (text, micros) = deadline_source(operation.as_object()?, metadata, guard_home)?;
    aware_epoch_micros(text).map(|instant| instant + i128::from(micros))
}

fn deadline_source<'a>(
    operation: &'a Map<String, Value>,
    metadata: &'a Map<String, Value>,
    guard_home: &Path,
) -> Option<(&'a str, i64)> {
    if browser_wait_declared(metadata) {
        if let Some(explicit) = trimmed_string(metadata, &DEADLINE_KEYS) {
            if aware_epoch_micros(explicit).is_some() {
                return Some((explicit, 0));
            }
        }
    }
    if trimmed_string(metadata, &EVENT_KEYS) != Some(PRETOOL) {
        return None;
    }
    let started_at = trimmed_string(operation, &["updated_at", "created_at"])?;
    aware_epoch_micros(started_at)?;
    let workspace = trimmed_string(metadata, &["workspace"]).map(PathBuf::from);
    let configured = approval_wait_timeout_seconds_under(
        guard_home,
        workspace.as_deref(),
        &managed_policy_source(),
    )
    .map(|seconds| seconds.clamp(0, MAX_APPROVAL_WAIT_SECONDS))
    .unwrap_or(DEFAULT_WAIT_SECONDS);
    let hold = (configured + BRIDGE_ALLOWANCE_SECONDS).max(1);
    Some((started_at, hold * MICROS))
}

fn browser_wait_declared(metadata: &Map<String, Value>) -> bool {
    metadata.get(WAITS_KEY) == Some(&Value::Bool(true))
}

fn process_is_live(metadata: &Map<String, Value>) -> bool {
    process_identity_matches(metadata.get(PROCESS_KEY).unwrap_or(&Value::Null))
}

/// `str(metadata.get("hook_event_name") or metadata.get("event") or "")`.
fn event_name(metadata: &Map<String, Value>) -> String {
    EVENT_KEYS
        .iter()
        .filter_map(|key| metadata.get(*key))
        .find(|value| py_truthy(value))
        .and_then(py_str)
        .unwrap_or_default()
}

/// `_first_string` of `codex_resume.py`: the first non-blank string, unstripped.
fn first_string<'a>(mapping: &'a Map<String, Value>, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|key| {
        mapping
            .get(*key)
            .and_then(Value::as_str)
            .filter(|text| !py_strip(text).is_empty())
    })
}

/// `_first_string` of `codex_live_hook_target.py`: the first non-blank
/// string, stripped.
fn trimmed_string<'a>(mapping: &'a Map<String, Value>, keys: &[&str]) -> Option<&'a str> {
    first_string(mapping, keys).map(py_strip)
}

#[cfg(test)]
#[path = "codex_request_resume_live_tests.rs"]
mod tests;
