//! `protect_guidance` runner-authority kind: what a paused package install
//! tells the person or agent that ran it. Ported from
//! `cli/protect_inline_approval.py` (`pending_protect_request_ids`,
//! `protect_command_text`, `_terminal_safe`, `_reason`, `_prompt_text`,
//! `approval_step_lines`, `human_protect_guidance` and `_approval_link`) and
//! `cli/render.py` (`_protect_guidance_lines`).
//!
//! Python ships the protect response's members named in [`KEYS`] (`null`
//! when absent), whether the run came from an AI harness (`from_agent`) and
//! whether the prompt title is bold (`emphasis`), and answers:
//!
//! - `request_ids`, the approval requests the run queued;
//! - `prompt`, the inline terminal prompt;
//! - `title` and `guidance`, the guidance panel. A person gets the commands
//!   that approve the install; an agent gets the harness guidance, which says
//!   to wait and not retry.
//!
//! The caller still owns the terminal: it checks that one is attached, reads
//! the answer and records the approval.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{json, Map, Value};

use crate::approval_queue_identity_op::is_truthy;
use crate::daemon_lifecycle_text::py_strip;
use crate::guard_store_json::py_str;
use crate::hermes_printable::is_printable;
use crate::local_cli_identify::shlex_quote;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const KEYS: [&str; 8] = [
    "_ephemeral_signed_approval_url",
    "approval_request_ids",
    "approval_resume",
    "primary_approval_url",
    "request",
    "supply_chain",
    "supply_chain_evaluation",
    "verdict",
];
const PROMPT_TITLE: &str = "HOL Guard paused this install before it ran.";
const PROMPT_CHOICES: [&str; 6] = [
    "",
    "  y  Allow once",
    "  a  Always allow this exact install (Guard asks again if the package changes)",
    "  n  Keep it blocked",
    "",
    "Allow this install? [y/a/N] ",
];
/// `str.isspace` characters end a link as Python's `\s` does.
static URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"https?://[^\s\x1c-\x1f<>"'`]+"#).expect("approval link pattern")
});

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let fields = args.as_object().ok_or(ERR_INVALID)?;
    if fields.len() != 3 {
        return Err(ERR_INVALID);
    }
    let payload = fields
        .get("payload")
        .and_then(Value::as_object)
        .ok_or(ERR_INVALID)?;
    if payload.len() != KEYS.len() || !KEYS.iter().all(|key| payload.contains_key(*key)) {
        return Err(ERR_INVALID);
    }
    let from_agent = fields
        .get("from_agent")
        .and_then(Value::as_bool)
        .ok_or(ERR_INVALID)?;
    let emphasis = fields
        .get("emphasis")
        .and_then(Value::as_bool)
        .ok_or(ERR_INVALID)?;
    let steps = if from_agent {
        Vec::new()
    } else {
        approval_step_lines(payload)
    };
    let agent_guidance = guidance_lines(payload);
    let (title, guidance) = if steps.is_empty() {
        ("Guard guidance", agent_guidance)
    } else {
        let link = approval_link(&agent_guidance);
        let mut lines: Vec<String> = Vec::new();
        if !link.is_empty() {
            lines.push(format!("Approve in the browser: {link}"));
        }
        lines.extend(steps);
        ("Approve this install", lines)
    };
    Ok(json!({
        "request_ids": request_ids(payload),
        "prompt": prompt_text(payload, emphasis),
        "title": title,
        "guidance": guidance,
    }))
}

/// `pending_protect_request_ids`: the queued ids, in either approval mode.
fn request_ids(payload: &Map<String, Value>) -> Vec<String> {
    if let Some(Value::Array(queued)) = payload.get("approval_request_ids") {
        let ids: Vec<String> = queued
            .iter()
            .filter_map(Value::as_str)
            .filter(|id| !id.is_empty())
            .map(str::to_owned)
            .collect();
        if !ids.is_empty() {
            return ids;
        }
    }
    payload
        .get("approval_resume")
        .and_then(|resume| resume.get("request_id"))
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .map(|id| vec![id.to_owned()])
        .unwrap_or_default()
}

/// `_terminal_safe`: control characters from request text show as `?` so
/// they cannot restyle the prompt.
fn terminal_safe(text: &str) -> String {
    text.chars()
        .map(|character| {
            if is_printable(character) {
                character
            } else {
                '?'
            }
        })
        .collect()
}

/// `os.path.basename`.
fn os_basename(path: &str) -> &str {
    #[cfg(windows)]
    let path = {
        let bytes = path.as_bytes();
        if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
            &path[2..]
        } else {
            path
        }
    };
    path.rsplit(|character| character == '/' || (cfg!(windows) && character == '\\'))
        .next()
        .unwrap_or_default()
}

/// `protect_command_text`: the install as a person would type it again,
/// quoted for a POSIX shell. The manager is named by its basename: an
/// external-archive shim sends the resolved real manager's path, and typing
/// that would skip the shim.
fn command_text(payload: &Map<String, Value>) -> String {
    match payload
        .get("request")
        .and_then(|request| request.get("command"))
    {
        Some(Value::String(command)) => terminal_safe(py_strip(command)),
        Some(Value::Array(parts)) => {
            let mut argv: Vec<&str> = parts.iter().filter_map(Value::as_str).collect();
            let Some(first) = argv.first_mut() else {
                return String::new();
            };
            let name = os_basename(*first);
            if !name.is_empty() {
                *first = name;
            }
            let quoted: Vec<String> = argv.iter().map(|part| shlex_quote(part)).collect();
            terminal_safe(&quoted.join(" "))
        }
        _ => String::new(),
    }
}

/// `_prompt_text`.
fn prompt_text(payload: &Map<String, Value>, emphasis: bool) -> String {
    let title = if emphasis {
        format!("\u{1b}[1m{PROMPT_TITLE}\u{1b}[0m")
    } else {
        PROMPT_TITLE.to_owned()
    };
    let mut lines = vec![String::new(), title];
    let command = command_text(payload);
    if !command.is_empty() {
        lines.push(format!("  {command}"));
    }
    if let Some(reason) = payload
        .get("verdict")
        .and_then(|verdict| verdict.get("reason"))
        .and_then(Value::as_str)
    {
        let reason = terminal_safe(py_strip(reason));
        if !reason.is_empty() {
            lines.push(format!("  {reason}"));
        }
    }
    lines.extend(PROMPT_CHOICES.iter().map(|line| (*line).to_owned()));
    lines.join("\n")
}

/// `approval_step_lines`: commands that approve a paused install later, for
/// output nobody could answer inline.
fn approval_step_lines(payload: &Map<String, Value>) -> Vec<String> {
    let ids = request_ids(payload);
    let [request_id] = ids.as_slice() else {
        return Vec::new();
    };
    let action = payload
        .get("verdict")
        .and_then(|verdict| verdict.get("action"))
        .and_then(Value::as_str);
    if !matches!(action, Some("review" | "require-reapproval")) {
        return Vec::new();
    }
    let mut lines = vec![
        format!("Approve once:   hol-guard approvals approve {request_id}"),
        format!("Always allow:   hol-guard approvals approve {request_id} --remember"),
        "Or decide in the approval center: hol-guard approvals".to_owned(),
    ];
    let command = command_text(payload);
    if !command.is_empty() {
        lines.push(format!("Then run it again: {command}"));
    }
    if let Some(Value::Object(supply_chain)) = payload.get("supply_chain") {
        let connected = supply_chain
            .get("bundle")
            .and_then(Value::as_object)
            .and_then(|bundle| bundle.get("workspace_id"))
            .is_some_and(is_truthy);
        if !connected {
            lines.push(
                "Sign in to Guard Cloud for package intelligence and phone approvals: hol-guard connect"
                    .to_owned(),
            );
        }
    }
    lines
}

/// `str(value or "").strip()`.
fn text_or_empty(value: Option<&Value>) -> String {
    value
        .filter(|value| is_truthy(value))
        .and_then(py_str)
        .map(|text| py_strip(&text).to_owned())
        .unwrap_or_default()
}

/// `_protect_guidance_lines`: the harness guidance from the supply-chain
/// evaluation's user copy, and the page that approves the install.
fn guidance_lines(payload: &Map<String, Value>) -> Vec<String> {
    let empty = Map::new();
    let user_copy = payload
        .get("supply_chain_evaluation")
        .and_then(Value::as_object)
        .and_then(|evaluation| evaluation.get("user_copy"))
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let mut lines: Vec<String> = Vec::new();
    let harness_message = text_or_empty(user_copy.get("harness_message"));
    if !harness_message.is_empty() {
        lines.push(harness_message.clone());
    }
    let next_step = text_or_empty(user_copy.get("next_step"));
    if !next_step.is_empty() && !harness_message.contains(&next_step) {
        lines.push(format!("Next step: {next_step}"));
    }
    let primary = payload.get("primary_approval_url");
    let dashboard_url = match payload.get("_ephemeral_signed_approval_url") {
        Some(Value::String(signed)) if !py_strip(signed).is_empty() => py_strip(signed).to_owned(),
        _ if user_copy.get("dashboard_url") == Some(&Value::Null)
            && !primary.is_some_and(is_truthy) =>
        {
            String::new()
        }
        _ => text_or_empty(
            primary
                .filter(|url| is_truthy(url))
                .or_else(|| user_copy.get("dashboard_url")),
        ),
    };
    if !dashboard_url.is_empty() && !lines.iter().any(|line| line.contains(&dashboard_url)) {
        lines.push(format!("Review: {dashboard_url}"));
    }
    lines
}

/// `_approval_link`: the approval page from the agent guidance, preferring
/// its explicit review link.
fn approval_link(guidance: &[String]) -> String {
    let (reviews, others): (Vec<&String>, Vec<&String>) = guidance
        .iter()
        .partition(|line| line.starts_with("Review: "));
    reviews
        .into_iter()
        .chain(others)
        .find_map(|line| URL.find(line))
        .map(|found| {
            found
                .as_str()
                .trim_end_matches(['.', ',', ';', ':', ')', ']'])
                .to_owned()
        })
        .unwrap_or_default()
}

#[cfg(test)]
#[path = "protect_guidance_tests.rs"]
mod tests;
