//! `runner_authority` kind `copilot_hook_config`: which Copilot hook entries
//! Guard wrote, the shell spellings of Guard's hook command, and the
//! workspace hook file Guard rewrites (`_merge_hook_entries`,
//! `_remove_hook_entries`, `_managed_hook_payload` and `_hook_shell_commands`
//! in `guard/adapters/copilot.py` before they moved here).
//!
//! Python keeps the file I/O, Guard's hook argv and the interpreter probe.
//! Ownership reads the same predicate as `copilot-hook-commands --stdin`.
//! serde_json does not keep object order, so answers name entries by index
//! into the caller's own lists and user JSON is never rebuilt here.
//!
//! One `plan` request carries every hooks object an install or uninstall
//! touches, so Python asks once, before it writes anything.

use std::collections::BTreeSet;

use serde_json::{json, Map, Value};

use super::copilot_hook_commands::is_managed;
use super::local_cli_identify::shlex_quote;
use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};

/// The hook events Guard installs into, in the order Python assigns them.
const MANAGED_EVENTS: [&str; 5] = [
    "userPromptSubmitted",
    "preToolUse",
    "postToolUse",
    "permissionRequest",
    "permissionRequestV2",
];
/// The entry keys that hold a hook command.
const COMMAND_KEYS: [&str; 3] = ["command", "bash", "powershell"];
/// Python asked about commands in batches of this many JSON bytes and never
/// sent a longer one, so such a command was never Guard's.
const MAX_COMMAND_JSON_BYTES: usize = 512 * 1024;

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let map = args_object(args)?;
    if map.get("op").and_then(Value::as_str) != Some("plan")
        || map.len() != 4
        || !["interpreter", "script", "jobs"]
            .iter()
            .all(|key| map.contains_key(*key))
    {
        return Err(ERR_INVALID);
    }
    let interpreter = optional_text(&map["interpreter"])?;
    let script = optional_text(&map["script"])?;
    let bridge = interpreter.zip(script);
    let jobs = map["jobs"].as_array().ok_or(ERR_INVALID)?;
    let plans = jobs
        .iter()
        .map(|job| plan(job, bridge))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(json!({ "jobs": plans }))
}

fn optional_text(value: &Value) -> Result<Option<&str>, &'static str> {
    match value {
        Value::Null => Ok(None),
        Value::String(text) => Ok(Some(text.as_str())),
        _ => Err(ERR_INVALID),
    }
}

/// Guard's current hook command in both shells, and the isolated bridge
/// Guard installs at the current Guard home.
struct Guard<'a> {
    bash: String,
    powershell: String,
    bridge: Option<(&'a str, &'a str)>,
}

impl Guard<'_> {
    /// `_is_managed_hook_entry`: an object entry whose shell pair is Guard's
    /// current one, or any of whose commands Guard wrote.
    fn owns(&self, entry: &Value) -> bool {
        let Some(object) = entry.as_object() else {
            return false;
        };
        let text = |key: &str| object.get(key).and_then(Value::as_str);
        if text("bash") == Some(self.bash.as_str())
            && text("powershell") == Some(self.powershell.as_str())
        {
            return true;
        }
        COMMAND_KEYS
            .iter()
            .filter_map(|key| text(key))
            .any(|command| {
                command == self.bash || command == self.powershell || self.wrote(command)
            })
    }

    /// `is_managed` for a command Python would have asked about.
    fn wrote(&self, command: &str) -> bool {
        serde_json::to_string(command).is_ok_and(|text| text.len() < MAX_COMMAND_JSON_BYTES)
            && is_managed(command, self.bridge)
    }

    /// The indices of the entries Guard does not own; none for a missing or
    /// non-list event.
    fn kept(&self, entries: Option<&Value>) -> Vec<usize> {
        entries
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .enumerate()
            .filter(|(_, entry)| !self.owns(entry))
            .map(|(index, _)| index)
            .collect()
    }

    /// `[event, kept]` for every managed event of one hooks object.
    fn events(&self, hooks: Option<&Map<String, Value>>) -> Value {
        let events: Vec<Value> = MANAGED_EVENTS
            .iter()
            .map(|event| {
                let entries = hooks.and_then(|hooks| hooks.get(*event));
                json!([event, self.kept(entries)])
            })
            .collect();
        Value::Array(events)
    }
}

/// One hooks object: `{"parts", "hooks"}` for the config's inline hooks, or
/// `{"parts", "payload", "keys"}` for the workspace hook file, whose answer
/// also says how Python normalizes it.
fn plan(job: &Value, bridge: Option<(&str, &str)>) -> KindResult {
    let job = job.as_object().ok_or(ERR_INVALID)?;
    let parts = job
        .get("parts")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?
        .iter()
        .map(|part| part.as_str().ok_or(ERR_INVALID))
        .collect::<Result<Vec<_>, _>>()?;
    let guard = Guard {
        bash: shlex_join(&parts),
        powershell: list2cmdline(&parts),
        bridge,
    };
    let mut answer = Map::new();
    match (
        job.len(),
        job.get("hooks"),
        job.get("payload"),
        job.get("keys"),
    ) {
        (2, Some(hooks), None, None) => {
            let hooks = hooks.as_object().ok_or(ERR_INVALID)?;
            answer.insert("events".to_owned(), guard.events(Some(hooks)));
        }
        (3, None, Some(payload), Some(keys)) => {
            let payload = payload.as_object().ok_or(ERR_INVALID)?;
            let keys = ordered_keys(payload, keys)?;
            let nested = payload.get("hooks").and_then(Value::as_object);
            let lists = match nested {
                Some(_) => Value::Null,
                None => json!(top_level_lists(payload, &keys)),
            };
            answer.insert("events".to_owned(), guard.events(nested));
            answer.insert(
                "version".to_owned(),
                json!(is_py_int(payload.get("version"))),
            );
            answer.insert("hooks".to_owned(), lists);
        }
        _ => return Err(ERR_INVALID),
    }
    answer.insert("bash".to_owned(), Value::String(guard.bash));
    answer.insert("powershell".to_owned(), Value::String(guard.powershell));
    Ok(Value::Object(answer))
}

/// `keys` as the exact key order of `object`.
fn ordered_keys<'a>(
    object: &Map<String, Value>,
    keys: &'a Value,
) -> Result<Vec<&'a str>, &'static str> {
    let keys = keys
        .as_array()
        .ok_or(ERR_INVALID)?
        .iter()
        .map(|key| key.as_str().ok_or(ERR_INVALID))
        .collect::<Result<Vec<_>, _>>()?;
    let distinct: BTreeSet<&str> = keys.iter().copied().collect();
    if distinct.len() != keys.len()
        || keys.len() != object.len()
        || !keys.iter().all(|key| object.contains_key(*key))
    {
        return Err(ERR_INVALID);
    }
    Ok(keys)
}

/// Without a nested `hooks` object, `_managed_hook_payload` keeps the
/// top-level lists other than `version` and the managed events.
fn top_level_lists(payload: &Map<String, Value>, keys: &[&str]) -> Vec<usize> {
    keys.iter()
        .enumerate()
        .filter(|(_, key)| {
            **key != "version" && !MANAGED_EVENTS.contains(*key) && payload[**key].is_array()
        })
        .map(|(index, _)| index)
        .collect()
}

/// Python's `isinstance(version, int)` for a JSON value (`bool` included).
fn is_py_int(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Bool(_)) => true,
        Some(Value::Number(number)) => !number.to_string().contains(['.', 'e', 'E']),
        _ => false,
    }
}

/// `shlex.join(parts)`.
pub(crate) fn shlex_join(parts: &[&str]) -> String {
    parts
        .iter()
        .map(|part| shlex_quote(part))
        .collect::<Vec<_>>()
        .join(" ")
}

/// `subprocess.list2cmdline(parts)`: the MS C runtime quoting rules.
pub(crate) fn list2cmdline(parts: &[&str]) -> String {
    let mut result = String::new();
    for (position, part) in parts.iter().enumerate() {
        if position > 0 {
            result.push(' ');
        }
        let quoted = part.is_empty() || part.contains([' ', '\t']);
        if quoted {
            result.push('"');
        }
        let mut backslashes = 0;
        for character in part.chars() {
            match character {
                '\\' => backslashes += 1,
                '"' => {
                    result.push_str(&"\\".repeat(backslashes * 2));
                    backslashes = 0;
                    result.push_str("\\\"");
                }
                other => {
                    result.push_str(&"\\".repeat(backslashes));
                    backslashes = 0;
                    result.push(other);
                }
            }
        }
        result.push_str(&"\\".repeat(backslashes));
        if quoted {
            result.push_str(&"\\".repeat(backslashes));
            result.push('"');
        }
    }
    result
}
