//! The action summary a Pulse request shows in the YID app.
//!
//! The summary comes from Guard's own stored approval request, looked up by
//! the `approval-request:<id>` subject the approval is already bound to, never
//! from the caller. A caller therefore cannot make the phone describe a
//! different action from the one the grant is issued for.
//!
//! A bulk approval is bound to `approval-request-batch:<uuid5>`, a hash of its
//! request ids. The caller names the ids; they are used only when they hash
//! to that exact subject, and every one of them must be in the store. The
//! phone then sees how many actions the scan approves, their programs,
//! agents and request kinds, and the highest risk level.
//!
//! Only reduced values leave the machine:
//! - the harness, mapped to its display name
//! - the request kind, mapped from a closed list
//! - Guard's risk level (high, medium or low)
//! - Guard's risk headline, through the same secret filter used for Guard Cloud
//! - the names of the programs being run, without flags, arguments, paths or
//!   environment values, and only when the Guard Cloud secret filter leaves
//!   them unchanged
//! - the decision the grant is bound to (allow or block, and its scope),
//!   mapped from closed lists
//! - for a single action, and only while the user lets the YID app show it
//!   (`pulse_show_command`, on by default), the command itself after the
//!   Guard Cloud secret filter, with user folders shown as `~`
//!   (`approval_gate_pulse_command`). A batch never shows commands.
//!
//! Anything Guard cannot read or reduce is left out rather than guessed.

#![forbid(unsafe_code)]

use std::path::Path;

use guard_command::cloud_scrub::cloud_scrub_text;
use guard_command::command_model::parse_shell_command;
use guard_yanez_pulse::terms::ActionSummary;
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;

use crate::approval_gate_pulse_command::command_preview;
use crate::local_store_read::{open_read_only, STORE_FILE_NAME};

const REQUEST_SUBJECT_PREFIX: &str = "approval-request:";
const BATCH_SUBJECT_PREFIX: &str = "approval-request-batch:";
/// Python's `uuid.NAMESPACE_URL`, which names the batch subject.
const NAMESPACE_URL: [u8; 16] = [
    0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8,
];
/// Largest batch the bulk approval accepts.
const MAX_BATCH_IDS: usize = 1024;
/// Most programs listed for one command; a longer pipeline ends with "…".
const MAX_PROGRAMS: usize = 4;

/// The stored fields the summary reads.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct StoredRequest {
    pub harness: Option<String>,
    pub artifact_type: Option<String>,
    pub risk_headline: Option<String>,
    pub risk_summary: Option<String>,
    pub policy_action: Option<String>,
    pub command: Option<String>,
}

/// Whether the summary includes the command, and the home folder to show as
/// `~` when it does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CommandRow<'a> {
    Hidden,
    Shown { home: Option<&'a str> },
}

/// The summary for one Pulse request, without the command. See
/// `summary_with_command`.
pub(crate) fn summary_for(
    guard_home: &Path,
    purpose: &str,
    action: Option<&str>,
    scope: Option<&str>,
    subject: Option<&str>,
    batch_ids: &[String],
) -> ActionSummary {
    summary_with_command(
        guard_home,
        purpose,
        action,
        scope,
        subject,
        batch_ids,
        CommandRow::Hidden,
    )
}

/// The summary for one Pulse request. Empty for every purpose other than
/// queued approval requests. The decision row comes from the `action` and
/// `scope` the grant is bound to, so it is shown even when the stored
/// request cannot be read. The command is added only for a single request
/// and only when `command` is `Shown`.
pub(crate) fn summary_with_command(
    guard_home: &Path,
    purpose: &str,
    action: Option<&str>,
    scope: Option<&str>,
    subject: Option<&str>,
    batch_ids: &[String],
    command: CommandRow<'_>,
) -> ActionSummary {
    if purpose != "approval_decision" {
        return ActionSummary::default();
    }
    let decision = decision_label(action, scope);
    let summary = if let Some(hash) = subject.and_then(|s| s.strip_prefix(BATCH_SUBJECT_PREFIX)) {
        read_batch(guard_home, hash, batch_ids)
            .map(|rows| summarize_batch(&rows))
            .unwrap_or_default()
    } else if let Some(request_id) = subject.and_then(|s| s.strip_prefix(REQUEST_SUBJECT_PREFIX)) {
        read_request(guard_home, request_id)
            .map(|stored| ActionSummary {
                command: match command {
                    CommandRow::Shown { home } => stored
                        .command
                        .as_deref()
                        .and_then(|text| command_preview(text, home)),
                    CommandRow::Hidden => None,
                },
                ..summarize(&stored)
            })
            .unwrap_or_default()
    } else {
        ActionSummary::default()
    };
    ActionSummary {
        decision,
        ..summary
    }
}

/// The decision a grant is bound to, as the YID app shows it: "Allow" or
/// "Block", then what it covers. An unknown action shows nothing; an
/// unknown scope shows the action alone.
pub(crate) fn decision_label(action: Option<&str>, scope: Option<&str>) -> Option<String> {
    let verb = match action? {
        "allow" => "Allow",
        "block" => "Block",
        _ => return None,
    };
    let covers = match scope.unwrap_or_default() {
        "artifact" => Some("this item"),
        "workspace" => Some("everything in this workspace"),
        "publisher" => Some("everything from this publisher"),
        "harness" => Some("everything this agent runs"),
        "global" => Some("everywhere"),
        _ => None,
    };
    Some(match covers {
        Some(covers) => format!("{verb}, {covers}"),
        None => verb.to_owned(),
    })
}

/// `uuid.uuid5(uuid.NAMESPACE_URL, "\0".join(sorted(ids))).hex`, as the bulk
/// approval names its subject.
pub(crate) fn batch_hash(ids: &[String]) -> String {
    use sha1::{Digest, Sha1};
    let mut sorted: Vec<&str> = ids.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    let mut hasher = Sha1::new();
    hasher.update(NAMESPACE_URL);
    hasher.update(sorted.join("\0").as_bytes());
    let mut bytes: [u8; 16] = hasher.finalize()[..16].try_into().expect("16 bytes");
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    hex::encode(bytes)
}

fn read_batch(guard_home: &Path, hash: &str, ids: &[String]) -> Option<Vec<StoredRequest>> {
    if ids.len() < 2 || ids.len() > MAX_BATCH_IDS || batch_hash(ids) != hash {
        return None;
    }
    let connection = open_read_only(&guard_home.join(STORE_FILE_NAME)).ok()??;
    read_batch_from(&connection, ids)
}

/// Every id must be stored; one missing row means no summary at all.
pub(crate) fn read_batch_from(
    connection: &Connection,
    ids: &[String],
) -> Option<Vec<StoredRequest>> {
    ids.iter()
        .map(|id| read_request_from(connection, id))
        .collect()
}

/// One summary for several requests: the count, the distinct programs,
/// agents and request kinds, the highest risk level, and the reason only when
/// every request gives the same one.
pub(crate) fn summarize_batch(rows: &[StoredRequest]) -> ActionSummary {
    let singles: Vec<ActionSummary> = rows.iter().map(summarize).collect();
    let distinct = |pick: fn(&ActionSummary) -> Option<&String>| -> Option<String> {
        let mut seen: Vec<&str> = Vec::new();
        for value in singles.iter().filter_map(pick) {
            if !seen.contains(&value.as_str()) {
                seen.push(value);
            }
        }
        if seen.is_empty() {
            return None;
        }
        let shown = seen.len().min(MAX_PROGRAMS);
        let mut joined = seen[..shown].join(", ");
        if seen.len() > shown {
            joined.push_str(&format!(" and {} more", seen.len() - shown));
        }
        Some(joined)
    };
    let rank = |level: &str| match level {
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    };
    let risk_level = singles
        .iter()
        .filter_map(|s| s.risk_level.clone())
        .max_by_key(|level| rank(level));
    let first_reason = singles.first().and_then(|s| s.reason.clone());
    let reason = first_reason.filter(|r| singles.iter().all(|s| s.reason.as_ref() == Some(r)));
    ActionSummary {
        agent: distinct(|s| s.agent.as_ref()),
        request_type: distinct(|s| s.request_type.as_ref()),
        risk_level,
        reason,
        programs: distinct(|s| s.programs.as_ref()),
        action_count: Some(rows.len()),
        decision: None,
        command: None,
    }
}

fn read_request(guard_home: &Path, request_id: &str) -> Option<StoredRequest> {
    let connection = open_read_only(&guard_home.join(STORE_FILE_NAME)).ok()??;
    read_request_from(&connection, request_id)
}

pub(crate) fn read_request_from(
    connection: &Connection,
    request_id: &str,
) -> Option<StoredRequest> {
    connection
        .query_row(
            "select harness, artifact_type, risk_headline, risk_summary, policy_action, \
             raw_command_text, action_envelope_json from approval_requests where request_id = ?1",
            params![request_id],
            |row| {
                let text = |index: usize| row.get::<_, Option<String>>(index);
                let envelope_command = text(6)?
                    .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
                    .and_then(|envelope| {
                        envelope
                            .get("command")
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    });
                Ok(StoredRequest {
                    harness: text(0)?,
                    artifact_type: text(1)?,
                    risk_headline: text(2)?,
                    risk_summary: text(3)?,
                    policy_action: text(4)?,
                    command: text(5)?
                        .filter(|c| !c.trim().is_empty())
                        .or(envelope_command),
                })
            },
        )
        .optional()
        .ok()
        .flatten()
}

pub(crate) fn summarize(stored: &StoredRequest) -> ActionSummary {
    ActionSummary {
        agent: stored.harness.as_deref().and_then(agent_name),
        request_type: stored.artifact_type.as_deref().and_then(request_type),
        risk_level: risk_level(stored).map(str::to_owned),
        reason: stored
            .risk_headline
            .as_deref()
            .map(cloud_scrub_text)
            .filter(|text| !text.trim().is_empty()),
        programs: stored.command.as_deref().and_then(program_names),
        action_count: None,
        decision: None,
        command: None,
    }
}

/// Display name for a harness id. Unknown ids are shown only when they are a
/// plain identifier, so no free text reaches Pulse through this field.
fn agent_name(harness: &str) -> Option<String> {
    let known = match harness {
        "codex" => "Codex",
        "claude-code" => "Claude Code",
        "copilot" => "Copilot",
        "cursor" => "Cursor",
        "opencode" => "OpenCode",
        "gemini" => "Gemini",
        "grok" => "Grok",
        "cline" => "Cline",
        "pi" => "Pi",
        _ => {
            let plain = !harness.is_empty()
                && harness.len() <= 40
                && harness
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
            return plain.then(|| harness.to_owned());
        }
    };
    Some(known.to_owned())
}

/// Guard's request kinds, as the YID app shows them. Other kinds are left out.
fn request_type(artifact_type: &str) -> Option<String> {
    let label = match artifact_type {
        "tool_action_request" | "tool_call" => "Tool call",
        "package_request" => "Package install",
        "mcp_server" => "MCP server",
        "skill" => "Skill",
        "prompt_request" => "Prompt",
        "harness_host" => "Agent launch",
        _ => return None,
    };
    Some(label.to_owned())
}

/// Guard's risk level, as `review_contracts._risk_category` derives it for
/// Guard Cloud: the first of headline, summary and policy action that names a
/// level decides it. `None` when none does.
fn risk_level(stored: &StoredRequest) -> Option<&'static str> {
    for value in [
        &stored.risk_headline,
        &stored.risk_summary,
        &stored.policy_action,
    ] {
        let lowered = value.as_deref().unwrap_or_default().to_lowercase();
        if ["critical", "high", "block", "destructive"]
            .iter()
            .any(|token| lowered.contains(token))
        {
            return Some("high");
        }
        if ["medium", "review", "reapproval"]
            .iter()
            .any(|token| lowered.contains(token))
        {
            return Some("medium");
        }
        if ["low", "allow"].iter().any(|token| lowered.contains(token)) {
            return Some("low");
        }
    }
    None
}

/// Program names in a shell command: each part becomes its wrappers and
/// program, by file name only, joined with " | " after a pipe and "; "
/// otherwise. Flags, arguments, redirects and environment values never appear.
pub(crate) fn program_names(command: &str) -> Option<String> {
    if command.trim().is_empty() {
        return None;
    }
    let model = parse_shell_command(
        command,
        None,
        None,
        "posix",
        "shell_string",
        "guard-shell",
        true,
    );
    let mut joined = String::new();
    let mut count = 0usize;
    for segment in &model.segments {
        let names: Vec<String> = segment
            .wrapper_chain
            .iter()
            .map(String::as_str)
            .chain(segment.executable.as_deref())
            .filter_map(file_name)
            .collect();
        if names.is_empty() {
            continue;
        }
        let separator = if segment.pipeline_index > 0 {
            " | "
        } else {
            "; "
        };
        if count == MAX_PROGRAMS {
            joined.push_str(separator);
            joined.push('…');
            break;
        }
        if count > 0 {
            joined.push_str(separator);
        }
        joined.push_str(&names.join(" "));
        count += 1;
    }
    (count > 0).then_some(joined)
}

/// The last path component of a program token, if it is a plain name that
/// the Guard Cloud secret filter leaves unchanged. A name the filter would
/// redact is left out entirely, not sent in its redacted form.
fn file_name(token: &str) -> Option<String> {
    let name = Path::new(token).file_name()?.to_str()?;
    let plain = !name.is_empty()
        && name.len() <= 64
        && !name.contains('=')
        && name.chars().all(|c| !c.is_whitespace() && !c.is_control());
    (plain && cloud_scrub_text(name) == name).then(|| name.to_owned())
}

#[cfg(test)]
#[path = "approval_gate_pulse_summary_tests.rs"]
mod tests;
