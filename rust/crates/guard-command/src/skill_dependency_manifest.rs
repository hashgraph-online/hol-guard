//! A skill's declared tool dependencies, and the advisory requirements they
//! draw against the local CLI authority a caller observed.
//!
//! Two halves of the same contract. [`parse_dependencies`] reads the
//! `hol-guard.dependencies` manifest a skill's frontmatter declares and says
//! whether it is absent, declared or invalid; [`preflight`] resolves each
//! declared tool against the saved connections and says what a live runtime
//! check would still have to establish. Neither grants anything: a
//! `saved-allow` requirement still carries
//! `live-runtime-check-still-required`, and the document always reports that
//! the permissions are not granted.
//!
//! The saved rows arrive as they were stored, so the comparisons here are the
//! ones the store's own values answer rather than ones a caller made first.

use serde_json::{json, Map, Value};

use crate::strict_json::parse_unique_json;
use crate::target_identities::py_truthy;

/// Largest declaration the manifest reader will look at, in UTF-8 bytes.
const MAX_MANIFEST_BYTES: usize = 8192;
/// Largest number of tools one skill may declare.
const MAX_TOOLS: usize = 50;
/// The only manifest schema this reader accepts.
const MANIFEST_SCHEMA: &str = "guard.skill-dependencies.v1";
/// Every declaration Guard reads comes from the skill's own frontmatter.
const DEPENDENCY_SOURCE: &str = "guard-extension";

/// `^local-cli\.[a-z0-9]+(?:-[a-z0-9]+){0,8}$`.
pub fn is_local_cli_id(value: &str) -> bool {
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

/// `[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}\Z`.
fn is_tool_name(value: &str) -> bool {
    let mut rest = value.bytes();
    let Some(first) = rest.next() else {
        return false;
    };
    first.is_ascii_alphanumeric()
        && value.len() <= 256
        && rest
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-'))
}

fn declaration(status: &str, tools: Vec<Value>) -> Value {
    json!({"source": DEPENDENCY_SOURCE, "status": status, "tools": tools})
}

fn keys_are(object: &Map<String, Value>, expected: [&str; 2]) -> bool {
    object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key))
}

/// Read the `hol-guard.dependencies` declaration.
///
/// `present` is whether the frontmatter carried the key with a non-null
/// value, and `text` the declaration when it is text Guard could carry. A key
/// that is there but unreadable has no manifest in it, so it reads as invalid
/// rather than absent: a declaration Guard cannot read must never resolve as
/// a skill that declared nothing.
pub fn parse_dependencies(present: bool, text: Option<&str>) -> Value {
    if !present {
        return declaration("absent", Vec::new());
    }
    let invalid = || declaration("invalid", Vec::new());
    let Some(text) = text else {
        return invalid();
    };
    if text.len() > MAX_MANIFEST_BYTES {
        return invalid();
    }
    let Ok(Value::Object(manifest)) = parse_unique_json(text) else {
        return invalid();
    };
    if !keys_are(&manifest, ["schema_version", "tools"])
        || manifest["schema_version"] != MANIFEST_SCHEMA
    {
        return invalid();
    }
    let Some(declared) = manifest["tools"].as_array() else {
        return invalid();
    };
    if declared.len() > MAX_TOOLS {
        return invalid();
    }
    let mut tools = Vec::with_capacity(declared.len());
    let mut seen: Vec<(&str, &str)> = Vec::with_capacity(declared.len());
    for tool in declared {
        let Some(entry) = tool.as_object() else {
            return invalid();
        };
        if !keys_are(entry, ["connection_id", "tool_name"]) {
            return invalid();
        }
        let (Some(connection), Some(name)) =
            (entry["connection_id"].as_str(), entry["tool_name"].as_str())
        else {
            return invalid();
        };
        if !is_local_cli_id(connection) || !is_tool_name(name) || seen.contains(&(connection, name))
        {
            return invalid();
        }
        seen.push((connection, name));
        tools.push(json!({"connection_id": connection, "tool_name": name}));
    }
    declaration("declared", tools)
}

fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
    value.get(key).unwrap_or(&Value::Null)
}

fn is(value: &Value, text: &str) -> bool {
    value.as_str() == Some(text)
}

/// The saved command a connection holds for this tool name.
///
/// A connection that carries no command list, or one that is not a list, has
/// observed nothing; within a list, the first entry whose `usage` equals the
/// requested name wins, and an entry that is not an object is not an
/// observation at all.
fn saved_command<'a>(connection: &'a Value, name: &Value) -> Option<&'a Value> {
    field(connection, "commands")
        .as_array()?
        .iter()
        .find(|entry| entry.is_object() && field(entry, "usage") == name)
}

/// Resolve every declared tool against the saved connections.
///
/// `dependencies` is the declaration document, and `connections` the saved
/// rows at `authority_revision`. `requires_action_review` is the Composio
/// contract's own answer for a tool name: a provider action is reviewed even
/// where the saved state would otherwise have been enough, because the
/// account behind it was never established here.
pub fn preflight(
    dependencies: &Value,
    connections: &[Value],
    authority_revision: i64,
    requires_action_review: &dyn Fn(&str) -> bool,
) -> Value {
    let declared = field(dependencies, "tools");
    let requests = declared.as_array().map(Vec::as_slice).unwrap_or_default();
    let mut requirements = Vec::with_capacity(requests.len());
    for request in requests {
        if !request.is_object() {
            continue;
        }
        let connection_id = field(request, "connection_id");
        let name = field(request, "tool_name");
        // A later row for the same id supersedes an earlier one.
        let connection = connections
            .iter()
            .rev()
            .find(|row| field(row, "cli_id") == connection_id);
        let mut state = "unresolved";
        let mut reason = "connection-not-observed";
        let mut identity = &Value::Null;
        if let Some(row) = connection {
            identity = field(row, "identity_hash");
            let command = saved_command(row, name);
            let saved_state = command.map(|entry| field(entry, "state"));
            if py_truthy(field(row, "stale")) {
                reason = "connection-changed";
            } else if is(field(row, "state"), "blocked")
                || saved_state.is_some_and(|value| is(value, "block"))
            {
                state = "deny";
                reason = "saved-deny";
            } else if command.is_none() {
                reason = "tool-not-observed";
            } else if name.as_str().is_some_and(requires_action_review) {
                state = "ask";
                reason = "provider-account-and-action-unverified";
            } else if is(field(row, "state"), "allowed")
                && saved_state.is_some_and(|value| is(value, "allow"))
            {
                state = "saved-allow";
                reason = "live-runtime-check-still-required";
            } else {
                state = "ask";
                reason = "permission-review-needed";
            }
        }
        requirements.push(json!({
            "connection_id": connection_id,
            "tool_name": name,
            "identity_hash": identity,
            "state": state,
            "reason": reason,
        }));
    }
    let status = dependencies
        .get("status")
        .cloned()
        .unwrap_or_else(|| Value::from("absent"));
    json!({
        "schema_version": "guard.workflow-preflight.v1",
        "dependency_source": DEPENDENCY_SOURCE,
        "dependency_status": status,
        "authority_revision": authority_revision,
        "requirements": requirements,
        // Advisory only: a requirement never stands in for the runtime check
        // the call itself still has to pass.
        "requirements_complete": false,
        "permissions_granted": false,
        "runtime_checks_required": true,
    })
}

#[cfg(test)]
#[path = "skill_dependency_manifest_tests.rs"]
mod tests;
