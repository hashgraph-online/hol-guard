//! The daemon's custom extension block for an allowed `PreToolUse`, once the
//! launch identity and its grant are known.
//!
//! Ports the decision and response steps of `native_local_cli_block_response`
//! (`hook_native_local_cli.py`), `decide_local_cli_grant`
//! (`local_cli_grant_decision.py`) and `match_command_id`
//! (`runtime/local_cli_commands.py`). Recorded parity vectors
//! (`scripts/record_local_cli_block_vectors.py`) pin every step.

use std::collections::BTreeSet;

use guard_command::hook_responses::{pre_tool, recording_only_pre_tool, Object};
use guard_contracts::{
    LocalCliIdentitySourceV1, LocalCliIdentityV1, PackageJsonScriptsV1, UnlistedCliV1,
    HOOK_RENDER_MAX_BYTES,
};
use serde_json::{json, Value};

const ROOT_COMMAND_ID: &str = "root";
pub(super) const OTHER_COMMAND_ID: &str = "other";
const MAX_DEPTH: usize = 4;
const MANAGERS: [&str; 4] = ["npm", "pnpm", "yarn", "bun"];
const KINDS: [&str; 2] = ["script", "executable"];
const BLOCKED_REASON_CODE: &str = "local_cli_extension_blocked";
const UNVERIFIED_REASON_CODE: &str = "local_cli_extension_unverified";
const UNVERIFIED_REASON: &str =
    "Guard could not check this command against your custom extension rules.";
/// The keys of a grant answer, as `_decode_payload` requires them.
const ANSWER_KEYS: [&str; 3] = ["state", "cli_id", "identity_hash"];
const WATCH_REASON: &str = "Watch recorded this action without stopping it.";
/// The worst-case growth of a verdict on the daemon's render wire, where
/// every byte may become a six-byte escape, plus room for the envelope.
const RENDER_ESCAPE_FACTOR: usize = 6;
const RENDER_ENVELOPE_BYTES: usize = 1_024;

/// The command id the daemon sends with the grant read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum CommandSelector {
    /// Resolved as the daemon resolves it; `None` when the CLI has no catalog.
    Known(Option<String>),
    /// The daemon resolves it from its own shell model, which is not ported.
    Unresolved,
}

/// `_resolved_command_id`: no catalog sends no id; otherwise the invocation's
/// tokens select a catalog command. `tokens` are the package script tokens,
/// and `None` when the command runs no package script.
pub(super) fn command_selector(
    catalog: &BTreeSet<String>,
    tokens: Option<&[String]>,
) -> CommandSelector {
    if catalog.is_empty() {
        return CommandSelector::Known(None);
    }
    match tokens {
        Some(tokens) => CommandSelector::Known(Some(match_command_id(tokens, catalog))),
        None => CommandSelector::Unresolved,
    }
}

/// `match_command_id`: the longest token prefix that names a catalog command.
pub(crate) fn match_command_id(tokens: &[String], catalog: &BTreeSet<String>) -> String {
    if tokens.is_empty() {
        return ROOT_COMMAND_ID.to_owned();
    }
    for length in (1..=tokens.len().min(MAX_DEPTH)).rev() {
        let candidate = tokens[..length].join(".");
        if catalog.contains(&candidate) {
            return candidate;
        }
    }
    OTHER_COMMAND_ID.to_owned()
}

/// What the daemon does with an allowed `PreToolUse` once it read the grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Verdict {
    /// No grant, or an allow: the edge response stands.
    Unchanged,
    /// A block naming the CLI.
    Blocked(String),
    /// No trustworthy grant answer: the daemon blocks as unverified.
    Unverified,
}

/// `decide_local_cli_grant` after the resident's grant answer: an answer for
/// another identity, or none at all, is unverified.
pub(super) fn grant_verdict(launch: &Launch, answer: Option<&Value>) -> Verdict {
    let Some(answer) = answer.and_then(Value::as_object) else {
        return Verdict::Unverified;
    };
    if answer.len() != ANSWER_KEYS.len()
        || !ANSWER_KEYS.iter().all(|key| answer.contains_key(*key))
        || answer["cli_id"].as_str() != Some(launch.cli_id.as_str())
        || answer["identity_hash"].as_str() != Some(launch.identity_hash.as_str())
    {
        return Verdict::Unverified;
    }
    match answer["state"].as_str() {
        Some("blocked") => Verdict::Blocked(launch.name.clone()),
        Some("allowed" | "none") => Verdict::Unchanged,
        _ => Verdict::Unverified,
    }
}

/// The launch identity the daemon reads a grant for.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Launch {
    pub(super) cli_id: String,
    pub(super) name: String,
    pub(super) identity_hash: String,
    pub(super) source: LocalCliIdentitySourceV1,
    /// The package script tokens, when the command runs a package script.
    pub(super) tokens: Option<Vec<String>>,
}

/// The daemon's identity steps over the resident's two answers: the package
/// script identity, else the first unlisted CLI. `Err` is any answer the
/// daemon rejects as malformed, which it blocks as unverified.
pub(super) fn launch(
    package: Option<PackageJsonScriptsV1>,
    unlisted: impl FnOnce() -> Result<Vec<UnlistedCliV1>, ()>,
) -> Result<Option<Launch>, ()> {
    if package.as_ref().is_some_and(|found| !valid_package(found)) {
        return Err(());
    }
    let tokens = package.as_ref().map(|found| found.command_tokens.clone());
    if let Some(found) = package {
        if let Some(identity) = found.identity {
            return Ok(Some(Launch {
                cli_id: identity.cli_id,
                name: identity.name,
                identity_hash: identity.identity_hash,
                source: found.source,
                tokens,
            }));
        }
    }
    let records = unlisted()?;
    if !records.iter().all(valid_unlisted) {
        return Err(());
    }
    Ok(records.into_iter().next().map(|record| Launch {
        cli_id: record.cli_id,
        name: record.name,
        identity_hash: record.identity_hash,
        source: record.identity_source,
        tokens,
    }))
}

/// `_parse_native_scripts`' checks on the resident's package answer.
pub(crate) fn valid_package(found: &PackageJsonScriptsV1) -> bool {
    let source_valid = matches!(
        &found.source,
        LocalCliIdentitySourceV1::PackageJson { content_sha256, .. } if sha256_hex(content_sha256)
    );
    source_valid
        && MANAGERS.contains(&found.runner.as_str())
        && found.identity.as_ref().is_none_or(valid_identity)
}

/// `_valid_unlisted_cli`'s checks on one unlisted CLI record.
pub(crate) fn valid_unlisted(record: &UnlistedCliV1) -> bool {
    valid_identity(&LocalCliIdentityV1 {
        cli_id: record.cli_id.clone(),
        name: record.name.clone(),
        kind: record.kind.clone(),
        identity_hash: record.identity_hash.clone(),
    })
}

/// `valid_local_cli_identity`.
fn valid_identity(identity: &LocalCliIdentityV1) -> bool {
    KINDS.contains(&identity.kind.as_str())
        && sha256_hex(&identity.identity_hash)
        && valid_cli_id(&identity.cli_id)
}

fn sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// `^local-cli\.[a-z0-9]+(?:-[a-z0-9]+){0,8}$`.
fn valid_cli_id(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("local-cli.") else {
        return false;
    };
    let parts: Vec<&str> = rest.split('-').collect();
    parts.len() <= 9
        && parts.iter().all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
}

/// `_saved_block_response`'s verdict: the edge result as a terminal block.
pub(super) fn block_verdict(result: &Object, reason_code: &str, reason: &str) -> Object {
    let mut blocked = result.clone();
    for (key, value) in [
        ("decision", "deny"),
        ("minimum_action", "block"),
        ("policy_action", "block"),
        ("reason_code", reason_code),
        ("reason", reason),
    ] {
        blocked.insert(key.to_owned(), json!(value));
    }
    blocked
}

pub(super) fn blocked_reason(name: &str) -> String {
    format!("Your custom extension rules block this {name} command.")
}

/// The harness response the daemon returns for a custom block: the rendered
/// block marked as a blocked reuse, or in Watch the recording-only continue.
/// `None` when the daemon's render request could exceed its size limit, so
/// its fixed fallback would answer instead.
pub(super) fn block_response(
    harness: &str,
    result: &Object,
    name: &str,
    recording_only: bool,
) -> Option<Value> {
    rendered_block(
        harness,
        result,
        BLOCKED_REASON_CODE,
        &blocked_reason(name),
        recording_only,
    )
}

/// `block_response` for a launch whose grant the daemon could not check:
/// `native_local_cli_block_response` blocks it as unverified while some custom
/// block rule exists, and Watch records it as the custom block.
pub(super) fn unverified_response(
    harness: &str,
    result: &Object,
    recording_only: bool,
) -> Option<Value> {
    rendered_block(
        harness,
        result,
        UNVERIFIED_REASON_CODE,
        UNVERIFIED_REASON,
        recording_only,
    )
}

fn rendered_block(
    harness: &str,
    result: &Object,
    reason_code: &str,
    reason: &str,
    recording_only: bool,
) -> Option<Value> {
    if recording_only {
        return Some(Value::Object(recording_only_pre_tool(
            harness,
            BLOCKED_REASON_CODE,
            WATCH_REASON,
        )));
    }
    let verdict = block_verdict(result, reason_code, reason);
    let encoded = serde_json::to_vec(&verdict).ok()?.len() + harness.len();
    if encoded * RENDER_ESCAPE_FACTOR + RENDER_ENVELOPE_BYTES > HOOK_RENDER_MAX_BYTES {
        return None;
    }
    let mut response = pre_tool(harness, &verdict);
    response.insert("approval_reuse_status".to_owned(), json!("blocked"));
    Some(Value::Object(response))
}

#[cfg(test)]
#[path = "hook_direct_local_cli_block_tests.rs"]
mod tests;
