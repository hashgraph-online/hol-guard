//! Exact-command review rules at the hook edge.
//!
//! A Guard Cloud rule that asks a person before one exact shell command is
//! saved as an artifact-scoped `review` decision under the command's
//! exact-command ids, the same ids a saved block uses. Native evaluation never
//! reads those rows, so without this step an allowed command ran with the
//! rule applied and acknowledged. The edge raises such a command to review
//! before it builds the receipt and review evidence, so the ordinary review
//! (Allow once, Always allow, saved exact-action reuse) answers it. A rule
//! limited to one folder is saved workspace-scoped and applies in that folder.

use std::path::Path;

use guard_contracts::{GuardHookEnvelopeV2, PreToolActionTypeV1, PreToolResultV1};
use rusqlite::{params, Connection};
use serde_json::Value;

use crate::local_store_read::{
    open_read_only_cached, pre_tool_command, table_exists, STORE_FILE_NAME,
};
use crate::policy_decision_lookup_op::{normalized_workspace_path, workspace_policy_key};
use crate::policy_enforcement::{ActionFloor, AdmittedPolicySnapshot};

const POLICY_REVIEW: &str = "policy_exact_command_review";
const SAVED_REVIEW: &str = "saved_exact_command_review";
const UNREADABLE_REVIEW: &str = "exact_command_rules_unreadable";
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
    [POLICY_REVIEW, SAVED_REVIEW, UNREADABLE_REVIEW].contains(&reason_code)
}

/// The command and folder a hook runs in, as the rules are matched against.
pub(crate) struct Call<'a> {
    /// The command text, read the way native evaluation reads it and as the
    /// payload spells it; a rule naming either one applies.
    pub(crate) commands: Vec<&'a str>,
    /// The folder the hook runs in, for rules limited to one folder.
    pub(crate) workspace: Option<&'a str>,
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
    let payload = &envelope.raw_payload;
    let extracted = guard_command::pretool::generic::extract_untrusted_command_context(payload)
        .ok()
        .and_then(|context| context.command);
    let mut commands: Vec<&str> = extracted
        .as_deref()
        .into_iter()
        .chain(payload.as_object().and_then(pre_tool_command))
        .collect();
    commands.dedup();
    if commands.is_empty() {
        return result;
    }
    let workspace = envelope
        .source
        .cwd
        .as_deref()
        .or_else(|| payload.get("cwd").and_then(Value::as_str));
    let call = Call {
        commands,
        workspace,
    };
    apply(
        Path::new(&envelope.source.guard_home),
        &call,
        now_micros(),
        result,
    )
}

/// Raises an allowed shell `PreToolUse` to review when a saved review rule
/// names the call's command exactly. A store that exists but cannot be read
/// may hold such a rule, so the call is raised to review then too.
pub(crate) fn apply(
    guard_home: &Path,
    call: &Call<'_>,
    now_micros: Option<i64>,
    result: PreToolResultV1,
) -> PreToolResultV1 {
    if result.action.event != "PreToolUse"
        || !is_shell_action(&result.action.action_type)
        || !matches!(result.minimum_action.as_str(), "allow" | "warn")
    {
        return result;
    }
    match matching_rule(guard_home, &result.action.harness, call, now_micros) {
        Ok(None) => result,
        Ok(Some(source)) => raise(result, rule_reason(&source)),
        Err(Unreadable) => raise(
            result,
            (
                UNREADABLE_REVIEW,
                "Guard could not read its saved rules, so it asks before this command runs.",
            ),
        ),
    }
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

/// The store exists but a read of it failed.
struct Unreadable;

/// The source of a live review rule for `harness` or every harness that
/// names one of the call's exact-command ids, everywhere or in its folder. A
/// missing store or table holds no rule.
fn matching_rule(
    guard_home: &Path,
    harness: &str,
    call: &Call<'_>,
    now_micros: Option<i64>,
) -> Result<Option<String>, Unreadable> {
    let Some(connection) =
        open_read_only_cached(&guard_home.join(STORE_FILE_NAME)).map_err(|_| Unreadable)?
    else {
        return Ok(None);
    };
    if !table_exists(&connection, "policy_decisions").map_err(|_| Unreadable)? {
        return Ok(None);
    }
    let places = call
        .workspace
        .filter(|place| !place.trim().is_empty())
        .map(|place| {
            (
                workspace_policy_key(Some(place)),
                normalized_workspace_path(place),
            )
        });
    let (key, path) = places.map_or((None, None), |(key, path)| (key, Some(path)));
    for command in call.commands.iter().copied() {
        let candidates = crate::memory_pattern::verdict(&crate::memory_pattern::MemoryRequest {
            command: Some(command),
            artifact_type: Some("shell_command"),
            artifact_id: None,
            artifact_name: None,
            harness: None,
        });
        for id in &candidates.exact_artifact_ids {
            let place = (key.as_deref(), path.as_deref());
            if let Some(source) = live_rule(&connection, harness, id, place, now_micros)? {
                return Ok(Some(source));
            }
        }
    }
    Ok(None)
}

fn live_rule(
    connection: &Connection,
    harness: &str,
    artifact_id: &str,
    (key, path): (Option<&str>, Option<&str>),
    now_micros: Option<i64>,
) -> Result<Option<String>, Unreadable> {
    let mut statement = connection
        .prepare_cached(
            "select coalesce(source, ''), expires_at from policy_decisions \
             where harness in (?1, '*') and action = 'review' and artifact_id = ?2 \
             and (scope = 'artifact' or (scope = 'workspace' and workspace in (?3, ?4)))",
        )
        .map_err(|_| Unreadable)?;
    let mut rows = statement
        .query(params![harness, artifact_id, key, path])
        .map_err(|_| Unreadable)?;
    while let Some(row) = rows.next().map_err(|_| Unreadable)? {
        let source = row.get::<_, Option<String>>(0).map_err(|_| Unreadable)?;
        let expires_at = row.get::<_, Option<String>>(1).map_err(|_| Unreadable)?;
        if !expired(expires_at.as_deref(), now_micros) {
            return Ok(Some(source.unwrap_or_default()));
        }
    }
    Ok(None)
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

fn rule_reason(source: &str) -> (&'static str, &'static str) {
    if CLOUD_SOURCES.contains(&source) {
        (
            POLICY_REVIEW,
            "Your Guard Cloud policy asks a person to approve this exact command before it runs.",
        )
    } else {
        (
            SAVED_REVIEW,
            "A saved Guard rule asks a person to approve this exact command before it runs.",
        )
    }
}

fn raise(mut result: PreToolResultV1, (reason_code, reason): (&str, &str)) -> PreToolResultV1 {
    if ActionFloor::parse(&result.policy_action).is_none_or(|policy| policy < ActionFloor::Review) {
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
