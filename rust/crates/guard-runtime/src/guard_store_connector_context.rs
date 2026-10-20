//! Connector setup context on a local-CLI observation.
//!
//! One method, `record_connector_setup_context`, writes the six nullable
//! context columns Python's schema owns. It is the only writer, and it never
//! trusts its caller's text: every field is scrubbed and capped here, so a
//! secret, a URL credential or an argv operand that slipped into review
//! wording is not stored. The method touches no grant and no capability.

use std::sync::LazyLock;

use regex::{Captures, Regex};
use rusqlite::Connection;
use serde_json::Value;

use crate::guard_store_args::Args;
use crate::guard_store_db::{exec, value_error, StoreResult};
use crate::guard_store_local_cli::parse_utc;
use crate::guard_store_observed_mcp::is_local_cli_id;

/// What can block a connector first. Anything else is refused.
pub(crate) const FIRST_BLOCKED_CAUSES: [&str; 5] = [
    "exec_outside_roots",
    "connect_loopback",
    "read_home_state",
    "write_home_state",
    "unrecognised_tool",
];
/// Longest stored review wording, in characters.
pub(crate) const MAX_SUMMARY_CHARS: usize = 240;
/// Longest stored harness or workspace label, in characters.
pub(crate) const MAX_LABEL_CHARS: usize = 80;
/// Longest accepted raw field, in bytes, before any scrubbing runs.
pub(crate) const MAX_RAW_FIELD_BYTES: usize = 4096;
/// Longest accepted identity hash, in bytes.
pub(crate) const MAX_IDENTITY_HASH_BYTES: usize = 128;
const MAX_TIMESTAMP_BYTES: usize = 64;

static URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"[A-Za-z][A-Za-z0-9+.\-]*://[^\s`'"<>]+"#).expect("static URL pattern")
});

/// Whether `value` is one of the known first-blocked causes.
pub(crate) fn is_first_blocked_cause(value: &str) -> bool {
    FIRST_BLOCKED_CAUSES.contains(&value)
}

/// `scheme://host/path` for every URL in `text`: no credentials, no query, no
/// fragment. Remote identity is the scheme, host and path.
fn strip_url_detail(text: &str) -> String {
    URL.replace_all(text, |captures: &Captures| {
        let url = &captures[0];
        let Some((scheme, rest)) = url.split_once("://") else {
            return url.to_owned();
        };
        let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(authority_end);
        let host = authority.rsplit('@').next().unwrap_or(authority);
        let path_end = tail.find(['?', '#']).unwrap_or(tail.len());
        format!("{scheme}://{host}{}", &tail[..path_end])
    })
    .into_owned()
}

/// Review wording made safe to keep: URLs reduced to their identity, secrets
/// redacted, control characters and whitespace collapsed, length capped.
/// `None` when nothing is left. URLs go first so a credential or query is
/// gone before any redaction rewrites the text around it.
pub(crate) fn scrub_context_text(raw: &str, cap: usize) -> Option<String> {
    let stripped = strip_url_detail(raw);
    let redacted = guard_command::redacted_command_tokens::redact_text(&stripped).text;
    let redacted = guard_command::cloud_scrub::redact_sensitive_text(&redacted);
    let spaced = redacted
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>();
    let collapsed = spaced
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(cap)
        .collect::<String>();
    let trimmed = collapsed.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

fn scrubbed(value: Option<&str>, cap: usize) -> StoreResult<Value> {
    match value {
        None => Ok(Value::Null),
        Some(raw) if raw.len() > MAX_RAW_FIELD_BYTES => value_error("context text too long"),
        Some(raw) => Ok(scrub_context_text(raw, cap).map_or(Value::Null, Value::from)),
    }
}

/// Records the context of one observed connector and returns how many rows
/// changed (`0` when no observation matches the id and identity), or `null`
/// when the call carries nothing to write. The first cause sticks: it is set
/// only while the observation has none. The review wording and labels replace
/// what was kept, and an absent field leaves its column as it was.
pub(crate) fn record_context(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let cli_id = args.str("cli_id")?;
    if !is_local_cli_id(cli_id) {
        return value_error("invalid local CLI id");
    }
    let identity_hash = args.str("identity_hash")?;
    if identity_hash.is_empty()
        || identity_hash.len() > MAX_IDENTITY_HASH_BYTES
        || !identity_hash
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric())
    {
        return value_error("invalid identity hash");
    }
    let cause = match args.opt_str("first_blocked_cause")? {
        None => Value::Null,
        Some(cause) if is_first_blocked_cause(cause) => Value::from(cause),
        Some(_) => return value_error("invalid first blocked cause"),
    };
    let observed_at = args.str("observed_at")?.trim();
    if observed_at.len() > MAX_TIMESTAMP_BYTES || parse_utc(&Value::from(observed_at)).is_none() {
        return value_error("invalid context time");
    }
    let fields = [
        scrubbed(args.opt_str("trigger_summary")?, MAX_SUMMARY_CHARS)?,
        scrubbed(args.opt_str("why_now")?, MAX_SUMMARY_CHARS)?,
        scrubbed(args.opt_str("harness")?, MAX_LABEL_CHARS)?,
        scrubbed(args.opt_str("workspace_label")?, MAX_LABEL_CHARS)?,
    ];
    if cause.is_null() && fields.iter().all(Value::is_null) {
        return Ok(Value::Null);
    }
    let [summary, why_now, harness, workspace] = fields;
    let changed = exec(
        connection,
        "update local_cli_observation set \
             first_blocked_cause = coalesce(first_blocked_cause, ?), \
             last_trigger_summary = coalesce(?, last_trigger_summary), \
             last_why_now = coalesce(?, last_why_now), \
             last_harness = coalesce(?, last_harness), \
             last_workspace_label = coalesce(?, last_workspace_label), \
             last_context_at = ? \
         where cli_id = ? and identity_hash = ?",
        &[
            cause,
            summary,
            why_now,
            harness,
            workspace,
            Value::from(observed_at),
            Value::from(cli_id),
            Value::from(identity_hash),
        ],
    )?;
    Ok(Value::from(changed))
}

#[cfg(test)]
#[path = "guard_store_connector_context_tests.rs"]
mod tests;
