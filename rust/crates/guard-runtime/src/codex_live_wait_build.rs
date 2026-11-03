//! A waiting Codex hook's live wait, built by the resident that queues it.
//!
//! The hook names its bridge process and its outer wait budget. The resident
//! proves that process is still live, bounds the wait by the effective
//! `approval_wait_timeout_seconds`, and writes the operation metadata and the
//! frozen `suspended-response` snapshot the review's queue write links.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use crate::codex_hook_bridge::MAX_APPROVAL_WAIT_SECONDS;
use crate::codex_hook_identity::process_identity_matches;
use crate::guard_config_load::approval_wait_timeout_seconds_under;
use crate::guard_store_json::add_seconds_utc_isoformat;
use crate::guard_store_outbox_identity::{correlation_id, validated_continuation_snapshot};
use crate::managed_policy_load::ManagedPolicySource;

/// The queue write's argument naming the waiting hook's raw facts.
pub(crate) const FACTS_KEY: &str = "codex_live_wait_facts";
/// Set in place of the link when the facts name no live, bounded wait.
pub(crate) const NOT_LIVE_KEY: &str = "codex_live_wait_not_live";

/// The queue write's arguments with `codex_live_wait_facts` turned
/// into the `codex_live_wait` link and the request's `continuation_snapshot`.
///
/// A bridge that is not a live process with a bounded budget is dropped, its
/// request is queued as a manual retry and the reply's `live_wait` says
/// `not_live`. `None` when the call
/// carries no facts. This runs before the store opens its write: the process
/// check can spawn `ps` and the config read touches the filesystem.
pub(crate) fn prepare(
    method: &str,
    args: &Map<String, Value>,
    guard_home: &Path,
) -> Option<Map<String, Value>> {
    if !matches!(
        method,
        "add_approval_request" | "add_native_review_approval_request"
    ) {
        return None;
    }
    let facts = args.get(FACTS_KEY)?;
    let mut prepared = args.clone();
    prepared.remove(FACTS_KEY);
    prepared.remove("codex_live_wait");
    let built = build(facts, args, guard_home);
    match (built, prepared.get_mut("request")) {
        (Some((link, snapshot)), Some(Value::Object(request))) => {
            request.insert("continuation_snapshot".to_owned(), snapshot);
            prepared.insert("codex_live_wait".to_owned(), link);
        }
        (_, request) => {
            // Only a wait the resident built may make the request resumable.
            if let Some(Value::Object(request)) = request {
                request.remove("continuation_snapshot");
            }
            prepared.insert(NOT_LIVE_KEY.to_owned(), Value::Bool(true));
        }
    }
    Some(prepared)
}

fn build(facts: &Value, args: &Map<String, Value>, guard_home: &Path) -> Option<(Value, Value)> {
    let request = args.get("request")?.as_object()?;
    if request.get("harness").and_then(Value::as_str) != Some("codex") {
        return None;
    }
    let request_id = request.get("request_id")?.as_str()?;
    let now = args.get("now")?.as_str()?;
    let outer = facts
        .get("timeout_seconds")?
        .as_i64()
        .filter(|seconds| (1..=MAX_APPROVAL_WAIT_SECONDS).contains(seconds))?;
    let workspace = match facts.get("workspace") {
        None | Some(Value::Null) => None,
        Some(Value::String(workspace)) => Some(workspace.as_str()),
        Some(_) => return None,
    };
    let process = facts.get("process")?;
    if !process_identity_matches(process) {
        return None;
    }
    let configured = approval_wait_timeout_seconds_under(
        guard_home,
        workspace.map(PathBuf::from).as_deref(),
        &managed_policy_source(),
    )
    .ok()?;
    let wait_seconds = configured.clamp(0, MAX_APPROVAL_WAIT_SECONDS).min(outer);
    if wait_seconds <= 0 {
        return None;
    }
    let started_at = add_seconds_utc_isoformat(now, 0)?;
    let deadline_at = add_seconds_utc_isoformat(now, wait_seconds.checked_mul(1_000_000)?)?;
    let mut metadata = json!({
        "codex_hook_waits_for_browser_approval": true,
        "codex_browser_wait_started_at": started_at,
        "codex_browser_wait_deadline_at": deadline_at,
        "codex_browser_wait_timeout_seconds": wait_seconds,
        "codex_browser_wait_process": process,
        "hook_event_name": "PreToolUse",
    });
    if let Some(workspace) = workspace {
        metadata["workspace"] = Value::from(workspace);
    }
    // The capability the offer rules grant a live Codex hook whose deadline
    // is still ahead: the original hook stays attached until the deadline.
    let snapshot = validated_continuation_snapshot(&json!({
        "capability": "suspended-response",
        "correlationId": correlation_id(request_id)?,
        "hookAttached": true,
        "opaqueTargetId": null,
        "waitDeadline": deadline_at,
    }))?;
    let link = json!({
        "metadata_json": serde_json::to_string(&metadata).ok()?,
        "workspace": workspace,
    });
    Some((link, Value::Object(snapshot)))
}

/// This machine's managed policy. Tests read an unmanaged machine root, so
/// the host's own policy never changes their waits.
#[cfg(not(test))]
pub(crate) fn managed_policy_source() -> ManagedPolicySource {
    ManagedPolicySource::native()
}

#[cfg(test)]
pub(crate) fn managed_policy_source() -> ManagedPolicySource {
    ManagedPolicySource {
        system: crate::managed_policy_load::MachineSystem::Other,
        policy_path: None,
        write_cache: false,
        machine_root: Some(std::env::temp_dir().join("hol-guard-live-wait-unmanaged-machine")),
        registry: crate::managed_policy_registry::RegistryAuthority::Native,
    }
}

#[cfg(test)]
#[path = "codex_live_wait_build_tests.rs"]
mod tests;
