//! Exact-command review and block rules at the hook edge.
//!
//! A Guard Cloud rule that asks a person before one exact shell command is
//! saved as an artifact-scoped `review` decision under the command's
//! exact-command ids, the same ids a saved block uses. Native evaluation never
//! reads those rows, so without this step an allowed command ran with the
//! rule applied and acknowledged. The edge raises such a command to review
//! before it builds the receipt and review evidence, so the ordinary review
//! (Allow once, Always allow, saved exact-action reuse) answers it. A rule
//! limited to one folder is saved workspace-scoped and applies in that folder.
//!
//! The ids are hashes of the rule's text, so a rule also has to match the
//! other ways a shell spells the same program and arguments (see
//! [`crate::edge_exact_command_spelling`]). A block that matched only its own
//! text let `  npm publish`, `CI=1 npm publish` or `(npm publish)` run after
//! an approval. A block found under any spelling denies the call outright.
//!
//! A Guard Cloud rule may also name a command risk group ("ask before any
//! permanent delete"). It is saved under `risk-group:<group>` and applies to
//! every command whose steps fall in that group
//! ([`crate::command_risk_groups`]), the same groups Guard Cloud shows on the
//! request. Such a rule only asks or blocks; it never allows a command.

use std::collections::HashMap;
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
const UNREAD_LINE_REVIEW: &str = "exact_command_line_unreadable";
const POLICY_BLOCK: &str = "policy_exact_command_block";
const SAVED_BLOCK: &str = "saved_exact_command_block";
const GROUP_REVIEW: &str = "policy_risk_group_review";
const GROUP_BLOCK: &str = "policy_risk_group_block";
/// The id prefix a command risk-group rule is saved under.
const GROUP_PREFIX: &str = "risk-group:";
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
    [
        POLICY_REVIEW,
        SAVED_REVIEW,
        UNREADABLE_REVIEW,
        UNREAD_LINE_REVIEW,
        GROUP_REVIEW,
    ]
    .contains(&reason_code)
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

/// Denies a shell `PreToolUse` when a saved block rule names its command
/// under any spelling, raises an allowed one to review when a saved review
/// rule does, and settles a review a Guard Cloud allow rule names exactly
/// ([`crate::edge_exact_command_allow`]). A store that exists but cannot be
/// read may hold a block or review rule, so an allowed call is raised to
/// review then too.
pub(crate) fn apply(
    guard_home: &Path,
    call: &Call<'_>,
    now_micros: Option<i64>,
    result: PreToolResultV1,
) -> PreToolResultV1 {
    apply_with(
        guard_home,
        call,
        now_micros,
        result,
        crate::edge_exact_command_allow::cached_identities,
    )
}

/// [`apply`] with the source of the signed bundle's decision identities, which
/// a Guard Cloud allow rule is checked against.
pub(crate) fn apply_with(
    guard_home: &Path,
    call: &Call<'_>,
    now_micros: Option<i64>,
    result: PreToolResultV1,
    identities: crate::edge_exact_command_allow::BundleIdentities,
) -> PreToolResultV1 {
    apply_with_sources(
        guard_home,
        call,
        now_micros,
        result,
        identities,
        crate::edge_command_pattern_allow::cached_patterns,
    )
}

/// [`apply_with`] with the source of the signed bundle's command-pattern
/// Allow rules too.
pub(crate) fn apply_with_sources(
    guard_home: &Path,
    call: &Call<'_>,
    now_micros: Option<i64>,
    result: PreToolResultV1,
    identities: crate::edge_exact_command_allow::BundleIdentities,
    patterns: crate::edge_command_pattern_allow::BundlePatterns,
) -> PreToolResultV1 {
    if result.action.event != "PreToolUse" || !is_shell_action(&result.action.action_type) {
        return result;
    }
    let Some(minimum) = ActionFloor::parse(&result.minimum_action) else {
        return result;
    };
    if minimum >= ActionFloor::Block {
        return result;
    }
    let reviewable = minimum <= ActionFloor::Warn;
    // A missing store holds no rule.
    let connection = match open_read_only_cached(&guard_home.join(STORE_FILE_NAME)) {
        Ok(Some(connection)) => connection,
        Ok(None) => return result,
        Err(_) => return unreadable(result, reviewable),
    };
    // One read snapshot for the block and review rules, the allow rule and the
    // signed bundle behind it, so a policy sync that commits between the reads
    // cannot pair a newly signed allow with the rules from before it.
    let Ok(_snapshot) = connection.unchecked_transaction() else {
        return unreadable(result, reviewable);
    };
    match matching_rules(&connection, &result.action.harness, call, now_micros) {
        Ok(Rules {
            block: Some(hit),
            ..
        }) => block(result, block_reason(&hit)),
        Ok(Rules {
            review: Some(hit),
            ..
        }) if reviewable => raise(result, rule_reason(&hit)),
        Ok(Rules {
            incomplete: true, ..
        }) if reviewable => raise(
            result,
            (
                UNREAD_LINE_REVIEW,
                "Guard could not read every step of this command against your saved rules, so it asks before it runs.",
            ),
        ),
        // No block or review rule names the command under any spelling, and
        // every step was read, so a Guard Cloud allow on its exact text, or a
        // pattern Allow every spelling matches, may settle the review.
        Ok(Rules {
            review: None,
            incomplete: false,
            ..
        }) => crate::edge_command_pattern_allow::apply(
            &connection,
            &call.commands,
            call.workspace,
            now_micros,
            crate::edge_exact_command_allow::apply(
                &connection,
                &call.commands,
                now_micros,
                result,
                identities,
            ),
            patterns,
        ),
        Ok(_) => result,
        Err(Unreadable) => unreadable(result, reviewable),
    }
}

/// A store that exists but cannot be read may hold a block or review rule, so
/// an allowed call is raised to review.
fn unreadable(result: PreToolResultV1, reviewable: bool) -> PreToolResultV1 {
    if !reviewable {
        return result;
    }
    raise(
        result,
        (
            UNREADABLE_REVIEW,
            "Guard could not read its saved rules, so it asks before this command runs.",
        ),
    )
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

/// The rule that named a command: its source and, for a risk-group rule, the
/// group the command falls in.
struct Hit {
    source: String,
    group: Option<&'static str>,
}

/// The first live block and review rules.
#[derive(Default)]
struct Rules {
    block: Option<Hit>,
    review: Option<Hit>,
    /// Part of the line could not be read, so a rule may name a step that
    /// was not looked up.
    incomplete: bool,
}

/// The live block and review rules for `harness` or every harness that name
/// one of the exact-command ids of the call's commands, under any spelling,
/// everywhere or in its folder. A missing table holds no rule.
fn matching_rules(
    connection: &Connection,
    harness: &str,
    call: &Call<'_>,
    now_micros: Option<i64>,
) -> Result<Rules, Unreadable> {
    let mut rules = Rules::default();
    if !table_exists(connection, "policy_decisions").map_err(|_| Unreadable)?
        || !holds_command_rules(connection)?
    {
        return Ok(rules);
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
    let place = (key.as_deref(), path.as_deref());
    let live = live_rules(connection, harness, place, now_micros)?;
    if live.is_empty() {
        return Ok(rules);
    }
    let mut texts: Vec<String> = call
        .commands
        .iter()
        .map(|text| (*text).to_owned())
        .collect();
    for command in &call.commands {
        let spelled = crate::edge_exact_command_spelling::spellings(command);
        rules.incomplete |= !spelled.complete;
        texts.extend(spelled.texts);
    }
    for text in &texts {
        let candidates = crate::memory_pattern::verdict(&crate::memory_pattern::MemoryRequest {
            command: Some(text),
            artifact_type: Some("shell_command"),
            artifact_id: None,
            artifact_name: None,
            harness: None,
        });
        for id in &candidates.exact_artifact_ids {
            match live.get(id.as_str()) {
                Some(LiveRule {
                    block: true,
                    source,
                }) => {
                    rules.block = Some(Hit {
                        source: source.clone(),
                        group: None,
                    });
                    return Ok(rules);
                }
                Some(LiveRule { source, .. }) if rules.review.is_none() => {
                    rules.review = Some(Hit {
                        source: source.clone(),
                        group: None,
                    });
                }
                _ => {}
            }
        }
    }
    // A risk-group rule names every command in its group, read from the
    // command as written and from each other way it is spelled.
    let mut group_review = None;
    for text in &texts {
        for group in crate::command_risk_groups::command_risk_groups(text) {
            match live.get(format!("{GROUP_PREFIX}{group}").as_str()) {
                Some(LiveRule {
                    block: true,
                    source,
                }) => {
                    rules.block = Some(Hit {
                        source: source.clone(),
                        group: Some(group),
                    });
                    return Ok(rules);
                }
                Some(LiveRule { source, .. }) if group_review.is_none() => {
                    group_review = Some(Hit {
                        source: source.clone(),
                        group: Some(group),
                    });
                }
                _ => {}
            }
        }
    }
    if rules.review.is_none() {
        rules.review = group_review;
    }
    Ok(rules)
}

/// Whether any block or review rule is saved, so a store without one skips
/// the spellings.
fn holds_command_rules(connection: &Connection) -> Result<bool, Unreadable> {
    connection
        .prepare_cached(
            "select exists(select 1 from policy_decisions where action in ('block', 'review'))",
        )
        .and_then(|mut statement| statement.query_row([], |row| row.get::<_, bool>(0)))
        .map_err(|_| Unreadable)
}

/// The strongest live rule saved under one exact-command id.
struct LiveRule {
    block: bool,
    source: String,
}

/// Every live block and review rule for `harness` or every harness, by
/// exact-command id. They are read once so each spelling is a map lookup.
fn live_rules(
    connection: &Connection,
    harness: &str,
    (key, path): (Option<&str>, Option<&str>),
    now_micros: Option<i64>,
) -> Result<HashMap<String, LiveRule>, Unreadable> {
    let mut statement = connection
        .prepare_cached(
            "select artifact_id, action, coalesce(source, ''), expires_at from policy_decisions \
             where harness in (?1, '*') and action in ('block', 'review') \
             and ((artifact_id like 'memory:exact-%' and scope = 'artifact') \
               or (artifact_id like 'risk-group:%' and scope in ('harness', 'global')) \
               or ((artifact_id like 'memory:exact-%' or artifact_id like 'risk-group:%') \
                 and scope = 'workspace' and workspace in (?2, ?3)))",
        )
        .map_err(|_| Unreadable)?;
    let mut rows = statement
        .query(params![harness, key, path])
        .map_err(|_| Unreadable)?;
    let mut live: HashMap<String, LiveRule> = HashMap::new();
    while let Some(row) = rows.next().map_err(|_| Unreadable)? {
        let id = row.get::<_, String>(0).map_err(|_| Unreadable)?;
        let action = row.get::<_, String>(1).map_err(|_| Unreadable)?;
        let source = row.get::<_, Option<String>>(2).map_err(|_| Unreadable)?;
        let expires_at = row.get::<_, Option<String>>(3).map_err(|_| Unreadable)?;
        if expired(expires_at.as_deref(), now_micros) {
            continue;
        }
        let block = action == "block";
        match live.get(&id) {
            Some(saved) if saved.block || !block => {}
            _ => {
                live.insert(
                    id,
                    LiveRule {
                        block,
                        source: source.unwrap_or_default(),
                    },
                );
            }
        }
    }
    Ok(live)
}

/// Whether a rule's expiry has passed. An expiry Guard cannot read keeps the
/// rule: honoring it only asks before the command runs.
pub(crate) fn expired(expires_at: Option<&str>, now_micros: Option<i64>) -> bool {
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

fn rule_reason(hit: &Hit) -> (&'static str, &'static str) {
    if let Some(group) = hit.group {
        return (GROUP_REVIEW, group_review_reason(group));
    }
    if CLOUD_SOURCES.contains(&hit.source.as_str()) {
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

fn block_reason(hit: &Hit) -> (&'static str, &'static str) {
    if let Some(group) = hit.group {
        return (GROUP_BLOCK, group_block_reason(group));
    }
    if CLOUD_SOURCES.contains(&hit.source.as_str()) {
        (
            POLICY_BLOCK,
            "Your Guard Cloud policy blocks this command, however it is spelled.",
        )
    } else {
        (
            SAVED_BLOCK,
            "You chose to always block this command in HOL Guard, however it is spelled.",
        )
    }
}

/// Why a risk-group rule holds a command, in the group's own words.
fn group_review_reason(group: &str) -> &'static str {
    match group {
        "deletes" => "Your Guard policy asks a person before commands that delete files or data.",
        "bulk_changes" => "Your Guard policy asks a person before commands that change many things at once.",
        "sending_and_sharing" => "Your Guard policy asks a person before commands that send or share data.",
        "secrets" => "Your Guard policy asks a person before commands that read or move secrets.",
        "code_and_deploys" => "Your Guard policy asks a person before commands that push code or deploy.",
        "packages_and_scripts" => "Your Guard policy asks a person before commands that install packages or run downloaded scripts.",
        _ => "Your Guard policy asks a person before commands like this one.",
    }
}

/// Why a risk-group rule stops a command, in the group's own words.
fn group_block_reason(group: &str) -> &'static str {
    match group {
        "deletes" => "Your Guard policy blocks commands that delete files or data.",
        "bulk_changes" => "Your Guard policy blocks commands that change many things at once.",
        "sending_and_sharing" => "Your Guard policy blocks commands that send or share data.",
        "secrets" => "Your Guard policy blocks commands that read or move secrets.",
        "code_and_deploys" => "Your Guard policy blocks commands that push code or deploy.",
        "packages_and_scripts" => {
            "Your Guard policy blocks commands that install packages or run downloaded scripts."
        }
        _ => "Your Guard policy blocks commands like this one.",
    }
}

/// A block is final: no approval runs a command a saved rule blocks.
fn block(mut result: PreToolResultV1, (reason_code, reason): (&str, &str)) -> PreToolResultV1 {
    result.policy_action = "block".into();
    result.minimum_action = "block".into();
    result.decision = "deny".into();
    result.explicitly_benign = false;
    result.reason_code = reason_code.into();
    result.reason = reason.into();
    result
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

#[cfg(test)]
#[path = "edge_exact_command_block_tests.rs"]
mod block_tests;

#[cfg(test)]
#[path = "edge_risk_group_rule_tests.rs"]
mod risk_group_tests;
