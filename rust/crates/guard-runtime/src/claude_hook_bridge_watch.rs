//! Watch posture for the native Claude hook bridge.
//!
//! Watch observes and records; it never blocks. When the bridge cannot get a
//! usable answer from the daemon, the action it would otherwise deny is let
//! through instead, and the failure is written to the Guard home so it is not
//! silent. An enforcing harness keeps the deny: nothing here runs for it.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use crate::approval_gate_state::iso_from_epoch;
use crate::claude_hook_bridge_render::HookEvent;
use crate::guard_config_harness::{effective_map, global_effective, loaded_postures};
use crate::guard_config_load::load_under;
use crate::hook_env_stamp::json_string;
use crate::managed_policy_floor::effective_managed_policy;
use crate::managed_policy_load::{load_managed_policy, ManagedPolicySource};

const HARNESS: &str = "claude-code";
const REASON_CODE: &str = "watch_native_review_unavailable";
const FAILURE_LOG: &str = "logs/hook-bridge-watch-failures.jsonl";
/// The log stops growing here; a failure past it is still let through.
const FAILURE_LOG_LIMIT: u64 = 1 << 20;
const PASSTHROUGH_KEY: &str = "guard_permission_passthrough";

/// Whether the loaded configuration puts Claude Code in Watch. A harness
/// override wins over the machine-wide posture in both directions, and an
/// unreadable value never reads as Watch.
fn config_is_watch(config: &Value) -> bool {
    let field = |key: &str| config.get(key).and_then(Value::as_str).unwrap_or("");
    let baseline = global_effective(field("protection_posture"), field("mode")).to_owned();
    let postures = loaded_postures(config.get("harness_postures"));
    effective_map(&baseline, &postures)
        .get(HARNESS)
        .is_some_and(|posture| posture == "watch")
}

fn harness_is_watch(guard_home: &Path) -> bool {
    let policy = effective_managed_policy(&load_managed_policy(&ManagedPolicySource::native()));
    load_under(guard_home, None, policy.as_ref()).is_ok_and(|config| config_is_watch(&config))
}

/// The response that lets the action through in place of a failure deny, or
/// `None` when the failure keeps its deny: another posture, or an event the
/// bridge does not deny.
pub(crate) fn fail_open(
    guard_home: Option<&Path>,
    event: &HookEvent,
    reason: &str,
) -> Option<String> {
    let permission = event.is_permission();
    if !permission && event.name != "PreToolUse" {
        return None;
    }
    let guard_home = guard_home?;
    if !harness_is_watch(guard_home) {
        return None;
    }
    record(guard_home, event, reason);
    let message = format!(
        "HOL Guard is in Watch mode: native review could not complete ({reason}), so this action was allowed and the failure was recorded."
    );
    let message = json_string(&message, true, false);
    let name = json_string(&event.name, true, false);
    Some(if permission {
        // Watch grants nothing here; Claude's own dialog decides.
        format!(
            "{{\"{PASSTHROUGH_KEY}\":true,\"reason_code\":\"{REASON_CODE}\",\"hookSpecificOutput\":{{\"hookEventName\":{name}}}}}"
        )
    } else {
        format!(
            "{{\"continue\":true,\"policy_action\":\"warn\",\"reason_code\":\"{REASON_CODE}\",\"hookSpecificOutput\":{{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"allow\",\"permissionDecisionReason\":{message}}}}}"
        )
    })
}

/// Appends one line for a failure Watch let through. Best effort: a Guard
/// home that cannot be written to never turns the allow back into a deny.
fn record(guard_home: &Path, event: &HookEvent, reason: &str) {
    let path = guard_home.join(FAILURE_LOG);
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if fs::metadata(&path).is_ok_and(|meta| meta.len() >= FAILURE_LOG_LIMIT) {
        return;
    }
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |elapsed| elapsed.as_secs_f64());
    let line = json!({
        "timestamp": iso_from_epoch(seconds),
        "event": "hook_bridge_watch_fail_open",
        "harness": HARNESS,
        "hook_event": event.name,
        "reason_code": REASON_CODE,
        "reason": reason,
    });
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    if let Ok(mut file) = options.open(&path) {
        let _ = writeln!(file, "{line}");
    }
}

#[cfg(all(test, unix))]
#[path = "claude_hook_bridge_watch_tests.rs"]
mod tests;
