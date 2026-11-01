//! Exact-command review rules at the hook edge.
//!
//! A Guard Cloud rule that asks a person before one exact shell command is
//! saved as an artifact-scoped `review` decision under the command's
//! exact-command ids, the same ids a saved block uses. Native evaluation never
//! reads those rows, so without this step an allowed command ran with the
//! rule applied and acknowledged. The edge raises such a command to review
//! before it builds the receipt and review evidence, so the ordinary review
//! (Allow once, Always allow, saved exact-action reuse) answers it.

use std::path::Path;

use guard_contracts::{GuardHookEnvelopeV2, PreToolActionTypeV1, PreToolResultV1};
use rusqlite::{params, Connection};

use crate::local_store_read::{
    open_read_only_cached, pre_tool_command, table_exists, STORE_FILE_NAME,
};
use crate::policy_enforcement::{ActionFloor, AdmittedPolicySnapshot};

const POLICY_REVIEW: &str = "policy_exact_command_review";
const SAVED_REVIEW: &str = "saved_exact_command_review";
/// Sources a Guard Cloud policy writes its decisions under.
const CLOUD_SOURCES: &[&str] = &[
    "cloud-sync",
    "team-policy",
    "policy-bundle",
    "policy-bundle-canonical",
    "cloud-signed-memory",
];

/// Whether `reason_code` is this step's review. It names a saved rule, so it
/// holds the hook verdict at review before execution.
pub(crate) fn is_review_finding(reason_code: &str) -> bool {
    reason_code == POLICY_REVIEW || reason_code == SAVED_REVIEW
}

/// [`apply`] for a hook envelope: the rules are read from its Guard home.
pub(crate) fn apply_to_envelope(
    envelope: &GuardHookEnvelopeV2,
    policy_snapshot: Option<&AdmittedPolicySnapshot>,
    result: PreToolResultV1,
) -> PreToolResultV1 {
    // Watch records what Guard would do and never pauses a call.
    let observe = policy_snapshot.is_some_and(|snapshot| snapshot.mode == "observe");
    if envelope.recording_only || observe {
        return result;
    }
    let Some(command) = envelope.raw_payload.as_object().and_then(pre_tool_command) else {
        return result;
    };
    apply(
        Path::new(&envelope.source.guard_home),
        command,
        now_micros(),
        result,
    )
}

/// Raises an allowed shell `PreToolUse` to review when a saved review rule
/// names `command` exactly. A store it cannot read leaves the result as is:
/// this step only adds a review, and the daemon still applies saved blocks.
pub(crate) fn apply(
    guard_home: &Path,
    command: &str,
    now_micros: Option<i64>,
    result: PreToolResultV1,
) -> PreToolResultV1 {
    if result.action.event != "PreToolUse"
        || !is_shell_action(&result.action.action_type)
        || !matches!(result.minimum_action.as_str(), "allow" | "warn")
    {
        return result;
    }
    let Some(source) = matching_rule(guard_home, &result.action.harness, command, now_micros)
    else {
        return result;
    };
    raise(result, &source)
}

fn is_shell_action(action_type: &PreToolActionTypeV1) -> bool {
    matches!(
        action_type,
        PreToolActionTypeV1::Command
            | PreToolActionTypeV1::Package
            | PreToolActionTypeV1::ProcessService
            | PreToolActionTypeV1::Network
    )
}

/// The source of a live review rule for `harness` or every harness that
/// names one of `command`'s exact-command ids.
fn matching_rule(
    guard_home: &Path,
    harness: &str,
    command: &str,
    now_micros: Option<i64>,
) -> Option<String> {
    let connection = open_read_only_cached(&guard_home.join(STORE_FILE_NAME)).ok()??;
    if !table_exists(&connection, "policy_decisions").ok()? {
        return None;
    }
    let candidates = crate::memory_pattern::verdict(&crate::memory_pattern::MemoryRequest {
        command: Some(command),
        artifact_type: Some("shell_command"),
        artifact_id: None,
        artifact_name: None,
        harness: None,
    });
    candidates
        .exact_artifact_ids
        .iter()
        .find_map(|id| live_rule(&connection, harness, id, now_micros))
}

fn live_rule(
    connection: &Connection,
    harness: &str,
    artifact_id: &str,
    now_micros: Option<i64>,
) -> Option<String> {
    let mut statement = connection
        .prepare_cached(
            "select coalesce(source, ''), expires_at from policy_decisions \
             where harness in (?1, '*') and scope = 'artifact' and action = 'review' \
             and artifact_id = ?2",
        )
        .ok()?;
    let mut rows = statement.query(params![harness, artifact_id]).ok()?;
    while let Ok(Some(row)) = rows.next() {
        let (Ok(source), Ok(expires_at)) = (row.get::<_, String>(0), row.get::<_, Option<String>>(1))
        else {
            continue;
        };
        if !expired(expires_at.as_deref(), now_micros) {
            return Some(source);
        }
    }
    None
}

/// Whether a rule's expiry has passed. An expiry Guard cannot read keeps the
/// rule: honoring it only asks before the command runs.
fn expired(expires_at: Option<&str>, now_micros: Option<i64>) -> bool {
    let (Some(expires_at), Some(now)) = (expires_at.filter(|text| !text.is_empty()), now_micros)
    else {
        return false;
    };
    let normalized = match expires_at.strip_suffix('Z') {
        Some(stripped) => format!("{stripped}+00:00"),
        None => expires_at.to_owned(),
    };
    guard_contracts::utc_timestamp_micros(&normalized).is_some_and(|at| at <= now)
}

fn raise(mut result: PreToolResultV1, source: &str) -> PreToolResultV1 {
    let (reason_code, reason) = if CLOUD_SOURCES.contains(&source) {
        (
            POLICY_REVIEW,
            "Your Guard Cloud policy asks a person to approve this exact command before it runs.",
        )
    } else {
        (
            SAVED_REVIEW,
            "A saved Guard rule asks a person to approve this exact command before it runs.",
        )
    };
    if ActionFloor::parse(&result.policy_action).is_none_or(|policy| policy < ActionFloor::Review)
    {
        result.policy_action = "review".into();
    }
    result.minimum_action = "review".into();
    result.decision = "deny".into();
    result.explicitly_benign = false;
    result.reason_code = reason_code.into();
    result.reason = reason.into();
    result
}

fn now_micros() -> Option<i64> {
    let micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_micros();
    i64::try_from(micros).ok()
}

#[cfg(test)]
#[path = "edge_exact_command_review_tests.rs"]
mod tests;
