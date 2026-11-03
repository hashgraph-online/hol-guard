//! `local_cli_change_request` runner-authority kind: the request checks the
//! daemon's custom-extension preview and apply routes run before they read the
//! store or ask for approval.
//!
//! `{"payload": {...}}` carries only the request keys these checks read, and a
//! key the request left out stays absent: an absent `provider_actions` means
//! none, while an explicit `null` is refused. The answer holds one entry per
//! check, each `{"value": ...}` or `{"error": code}`, so the daemon can raise
//! them in the order its routes always have:
//!
//! - `mutation`: `{"cli_id", "identity_hash", "name", "kind", "state",
//!   "example_label", "interpreter_name"}`, with the name and label already cut
//!   to the lengths the store keeps.
//! - `provider_updates`: `[[tool_slug, state, revision], ...]`.
//! - `command_states`: `[[command_id, state], ...]` in request order. A later
//!   repeat of a command id overrides the earlier one, as a dict built from the
//!   pairs does.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use guard_contracts::python_strip;
use regex::Regex;
use serde_json::{json, Map, Value};

use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const MAX_PROVIDER_ACTIONS: usize = 100;
/// `MAX_LOCAL_CLI_COMMANDS`: one hundred listed commands and the Other row.
const MAX_LOCAL_CLI_COMMANDS: usize = 101;
const MAX_COMMAND_DEPTH: usize = 4;
const NAME_LIMIT: usize = 120;
const EXAMPLE_LABEL_LIMIT: usize = 160;
const INVALID_PROVIDER_ACTIONS: &str = "invalid_provider_actions";

static CLI_ID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^local-cli\.[a-z0-9]+(?:-[a-z0-9]+){0,8}$").expect("local CLI id pattern")
});
static TOOL_SLUG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$").expect("provider tool slug pattern")
});
static COMMAND_NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z][A-Za-z0-9_-]{0,40}$").expect("local CLI command name pattern")
});
static OPTION_NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:--[A-Za-z0-9][A-Za-z0-9_-]{0,39}|-[A-Za-z0-9])$")
        .expect("local CLI option name pattern")
});

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let payload = args_object(args)?
        .get("payload")
        .and_then(Value::as_object)
        .ok_or(ERR_INVALID)?;
    Ok(json!({
        "mutation": answer(mutation(payload)),
        "provider_updates": answer(provider_updates(payload)),
        "command_states": answer(command_states(payload)),
    }))
}

fn answer(checked: Result<Value, String>) -> Value {
    match checked {
        Ok(value) => json!({ "value": value }),
        Err(code) => json!({ "error": code }),
    }
}

/// A present, non-blank string, stripped as Python's `str.strip()` does.
fn required_string<'a>(payload: &'a Map<String, Value>, key: &str) -> Result<&'a str, String> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .map(python_strip)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("missing_{key}"))
}

/// An absent or `null` value is no value; anything but a string is refused.
fn optional_string<'a>(
    payload: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a str>, String> {
    match payload.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value)),
        Some(_) => Err(format!("invalid_{key}")),
    }
}

/// The first `limit` characters, as a Python slice counts them.
fn leading_chars(text: &str, limit: usize) -> &str {
    text.char_indices()
        .nth(limit)
        .map_or(text, |(end, _)| &text[..end])
}

fn mutation(payload: &Map<String, Value>) -> Result<Value, String> {
    let cli_id = required_string(payload, "cli_id")?;
    let identity_hash = required_string(payload, "identity_hash")?;
    let name = required_string(payload, "name")?;
    let kind = required_string(payload, "kind")?;
    let state = required_string(payload, "state")?;
    if !CLI_ID.is_match(cli_id) {
        return Err("invalid_cli_id".to_owned());
    }
    if identity_hash.len() != 64
        || !identity_hash
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err("invalid_identity_hash".to_owned());
    }
    if !matches!(kind, "executable" | "script") {
        return Err("invalid_cli_kind".to_owned());
    }
    if !matches!(state, "allowed" | "blocked" | "unset") {
        return Err("invalid_cli_state".to_owned());
    }
    let example_label =
        optional_string(payload, "example_label")?.filter(|label| !label.is_empty());
    let interpreter_name = optional_string(payload, "interpreter_name")?;
    Ok(json!({
        "cli_id": cli_id,
        "identity_hash": identity_hash,
        "name": leading_chars(name, NAME_LIMIT),
        "kind": kind,
        "state": state,
        "example_label": leading_chars(example_label.unwrap_or(name), EXAMPLE_LABEL_LIMIT),
        "interpreter_name": interpreter_name,
    }))
}

fn provider_update(entry: &Value) -> Option<(&str, &str, u64)> {
    let entry = entry.as_object()?;
    if entry.len() != 3 {
        return None;
    }
    let slug = entry
        .get("tool_slug")?
        .as_str()
        .filter(|slug| TOOL_SLUG.is_match(slug))?;
    let state = entry
        .get("state")?
        .as_str()
        .filter(|state| matches!(*state, "review" | "block"))?;
    // `as_u64` refuses booleans, fractions and negatives, as `type(...) is int` does.
    let revision = entry
        .get("revision")?
        .as_u64()
        .filter(|revision| *revision >= 1)?;
    Some((slug, state, revision))
}

fn provider_updates(payload: &Map<String, Value>) -> Result<Value, String> {
    let entries = match payload.get("provider_actions") {
        None => return Ok(json!([])),
        Some(Value::Array(entries)) if entries.len() <= MAX_PROVIDER_ACTIONS => entries,
        Some(_) => return Err(INVALID_PROVIDER_ACTIONS.to_owned()),
    };
    let mut slugs = BTreeSet::new();
    let mut updates = Vec::with_capacity(entries.len());
    for entry in entries {
        let (slug, state, revision) =
            provider_update(entry).ok_or_else(|| INVALID_PROVIDER_ACTIONS.to_owned())?;
        slugs.insert(slug);
        updates.push(json!([slug, state, revision]));
    }
    if slugs.len() != updates.len() {
        return Err(INVALID_PROVIDER_ACTIONS.to_owned());
    }
    Ok(Value::Array(updates))
}

/// A dotted command path, or one option a help text or script named.
fn is_command_id(value: &str) -> bool {
    if matches!(value, "root" | "other") || OPTION_NAME.is_match(value) {
        return true;
    }
    let parts: Vec<&str> = value.split('.').collect();
    parts.len() <= MAX_COMMAND_DEPTH && parts.iter().all(|part| COMMAND_NAME.is_match(part))
}

fn command_states(payload: &Map<String, Value>) -> Result<Value, String> {
    let entries = match payload.get("commands") {
        None | Some(Value::Null) => return Ok(json!([])),
        Some(Value::Array(entries)) if entries.len() <= MAX_LOCAL_CLI_COMMANDS => entries,
        Some(_) => return Err("invalid_commands".to_owned()),
    };
    let mut states = Vec::with_capacity(entries.len());
    for entry in entries {
        let entry = entry
            .as_object()
            .ok_or_else(|| "invalid_commands".to_owned())?;
        let command_id = entry
            .get("command_id")
            .and_then(Value::as_str)
            .filter(|command_id| is_command_id(command_id))
            .ok_or_else(|| "invalid_command_id".to_owned())?;
        let state = entry
            .get("state")
            .and_then(Value::as_str)
            .filter(|state| matches!(*state, "inherit" | "allow" | "review" | "block"))
            .ok_or_else(|| "invalid_command_state".to_owned())?;
        states.push(json!([command_id, state]));
    }
    Ok(Value::Array(states))
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::dispatch;

    const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn checked(payload: Value) -> Value {
        dispatch(&json!({ "payload": payload })).expect("checked request")
    }

    fn mutation() -> Value {
        json!({"cli_id": " local-cli.my-tool ", "identity_hash": HASH, "name": "my-tool", "kind": "script", "state": "allowed"})
    }

    #[test]
    fn a_valid_mutation_is_stripped_and_labelled_with_its_name() {
        let answer = checked(mutation());
        assert_eq!(
            answer["mutation"]["value"],
            json!({"cli_id": "local-cli.my-tool", "identity_hash": HASH, "name": "my-tool", "kind": "script",
                   "state": "allowed", "example_label": "my-tool", "interpreter_name": null})
        );
        assert_eq!(answer["provider_updates"], json!({"value": []}));
        assert_eq!(answer["command_states"], json!({"value": []}));
    }

    #[test]
    fn mutation_errors_follow_the_route_order() {
        let mut payload = mutation();
        payload["name"] = json!("\u{1c} ");
        payload["cli_id"] = json!("bad");
        assert_eq!(
            checked(payload.clone())["mutation"],
            json!({"error": "missing_name"})
        );
        payload["name"] = json!("ok");
        assert_eq!(
            checked(payload.clone())["mutation"],
            json!({"error": "invalid_cli_id"})
        );
        payload["cli_id"] = json!("local-cli.ok");
        payload["kind"] = json!("binary");
        assert_eq!(
            checked(payload.clone())["mutation"],
            json!({"error": "invalid_cli_kind"})
        );
        payload["kind"] = json!("executable");
        payload["example_label"] = json!(3);
        assert_eq!(
            checked(payload)["mutation"],
            json!({"error": "invalid_example_label"})
        );
    }

    #[test]
    fn long_names_are_cut_by_character() {
        let mut payload = mutation();
        payload["name"] = json!("é".repeat(130));
        let value = &checked(payload)["mutation"]["value"];
        assert_eq!(
            value["name"].as_str().map(|name| name.chars().count()),
            Some(120)
        );
        assert_eq!(
            value["example_label"]
                .as_str()
                .map(|label| label.chars().count()),
            Some(130)
        );
    }

    #[test]
    fn provider_actions_refuse_null_duplicates_and_non_integer_revisions() {
        let entry = json!({"tool_slug": "SLACK_SEND", "state": "block", "revision": 1});
        let ok = checked(json!({"provider_actions": [entry]}));
        assert_eq!(
            ok["provider_updates"],
            json!({"value": [["SLACK_SEND", "block", 1]]})
        );
        for refused in [
            json!(null),
            json!([entry, entry]),
            json!([{"tool_slug": "SLACK_SEND", "state": "allow", "revision": 1}]),
            json!([{"tool_slug": "SLACK_SEND", "state": "block", "revision": true}]),
            json!([{"tool_slug": "SLACK_SEND", "state": "block", "revision": 1.0}]),
            json!([{"tool_slug": "SLACK_SEND", "state": "block", "revision": 1, "extra": 0}]),
        ] {
            let answer = checked(json!({ "provider_actions": refused }));
            assert_eq!(
                answer["provider_updates"],
                json!({"error": "invalid_provider_actions"})
            );
        }
    }

    #[test]
    fn command_states_keep_request_order_and_check_each_entry() {
        let answer = checked(json!({"commands": [
            {"command_id": "deploy.prod", "state": "block"},
            {"command_id": "--force", "state": "review"},
            {"command_id": "other", "state": "inherit"},
        ]}));
        assert_eq!(
            answer["command_states"],
            json!({"value": [["deploy.prod", "block"], ["--force", "review"], ["other", "inherit"]]})
        );
        let deep = checked(json!({"commands": [{"command_id": "a.b.c.d.e", "state": "block"}]}));
        assert_eq!(
            deep["command_states"],
            json!({"error": "invalid_command_id"})
        );
        let state = checked(json!({"commands": [{"command_id": "a", "state": "deny"}]}));
        assert_eq!(
            state["command_states"],
            json!({"error": "invalid_command_state"})
        );
        let shape = checked(json!({"commands": ["a"]}));
        assert_eq!(
            shape["command_states"],
            json!({"error": "invalid_commands"})
        );
    }
}
