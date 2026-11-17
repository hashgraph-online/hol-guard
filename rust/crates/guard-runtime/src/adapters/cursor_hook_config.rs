//! `runner_authority` kind `cursor_hook_config`: which Cursor hook entries and
//! commands Guard owns, and the merge that installs Guard's managed hooks.
//!
//! Python keeps the file I/O, the live-script path checks (symlinks, files on
//! disk), the preToolUse matcher regex and the command rendering. Every op is
//! lexical over the JSON it is given. serde_json does not keep object order, so
//! requests carry key order explicitly and answers name entries by index into
//! the caller's own lists; user JSON is never rebuilt here.
//!
//! Every request carries `windows` (the host hook syntax) and `long_paths`
//! (8.3 short names Python resolved). Every answer carries `short_tokens`, the
//! short names met while splitting, so Python can resolve new ones and ask again.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Map, Value};

use super::cursor_hook_command::{py_space, Syntax};
use super::cursor_hook_rebind::{self, REBIND_KEYS};
use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};

pub(crate) const SUPPORTED_EVENTS: &[&str] = &[
    "beforeShellExecution",
    "beforeMCPExecution",
    "afterShellExecution",
    "afterMCPExecution",
    "beforeReadFile",
    "afterFileEdit",
    "beforeTabFileRead",
    "afterTabFileEdit",
    "stop",
    "beforeSubmitPrompt",
    "afterAgentResponse",
    "afterAgentThought",
    "sessionStart",
    "sessionEnd",
    "preCompact",
    "subagentStart",
    "subagentStop",
    "preToolUse",
    "postToolUse",
    "postToolUseFailure",
    "workspaceOpen",
];
const BLOCKING_EVENTS: &[&str] = &[
    "beforeShellExecution",
    "beforeMCPExecution",
    "beforeReadFile",
    "preToolUse",
];
const MANAGED_DOCSTRING: &str =
    "\"\"\"Managed by HOL Guard. Re-run `hol-guard install cursor` after moving Guard home.\"\"\"";
const SHARED_KEYS: &[&str] = &["op", "windows", "long_paths"];

type Pairs<'a> = Option<Vec<(&'a str, &'a Value)>>;

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let map = args_object(args)?;
    let op = map.get("op").and_then(Value::as_str).ok_or(ERR_INVALID)?;
    let keys: &[&str] = match op {
        "command" => &["command"],
        "entries" => &["entries", "command"],
        "commands" | "intercept" => &["hooks"],
        "install" => &["payload", "top_keys", "hooks_keys", "managed", "script"],
        "script" | "ephemeral" => &["source"],
        "rebind" => REBIND_KEYS,
        _ => return Err(ERR_INVALID),
    };
    if map.len() != SHARED_KEYS.len() + keys.len()
        || !SHARED_KEYS
            .iter()
            .chain(keys)
            .all(|key| map.contains_key(*key))
    {
        return Err(ERR_INVALID);
    }
    let windows = map["windows"].as_bool().ok_or(ERR_INVALID)?;
    let mut syntax = Syntax::new(windows, long_paths(&map["long_paths"])?);
    let mut answer = match op {
        "command" => command(&mut syntax, &map["command"]),
        "entries" => entries(&mut syntax, &map["entries"], text(&map["command"])?),
        "commands" => commands(&mut syntax, &pairs(&map["hooks"])?),
        "intercept" => intercept(&mut syntax, &pairs(&map["hooks"])?),
        "install" => install(&mut syntax, map)?,
        "ephemeral" => cursor_hook_rebind::ephemeral(&syntax, text(&map["source"])?),
        "rebind" => cursor_hook_rebind::rebind(&mut syntax, map)?,
        _ => script(text(&map["source"])?),
    };
    answer["short_tokens"] = json!(syntax.short_tokens());
    Ok(answer)
}

fn text(value: &Value) -> Result<&str, &'static str> {
    value.as_str().ok_or(ERR_INVALID)
}

fn long_paths(value: &Value) -> Result<BTreeMap<String, String>, &'static str> {
    let map = value.as_object().ok_or(ERR_INVALID)?;
    map.iter()
        .map(|(short, long)| Ok((short.clone(), text(long)?.to_string())))
        .collect()
}

/// `[[name, value], ...]` in the caller's order, or `None` for `null`.
fn pairs(value: &Value) -> Result<Pairs<'_>, &'static str> {
    if value.is_null() {
        return Ok(None);
    }
    let list = value.as_array().ok_or(ERR_INVALID)?;
    let pairs = list
        .iter()
        .map(|pair| match pair.as_array().map(Vec::as_slice) {
            Some([Value::String(name), value]) => Ok((name.as_str(), value)),
            _ => Err(ERR_INVALID),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Some(pairs))
}

/// `_is_managed_hook_entry`.
fn is_managed_entry(syntax: &mut Syntax, entry: &Value, command: &str) -> bool {
    match entry.get("command") {
        Some(Value::String(text)) => text == command || syntax.is_managed_command(text),
        _ => false,
    }
}

fn command(syntax: &mut Syntax, value: &Value) -> Value {
    let Some(command) = value.as_str() else {
        return json!({"managed": false, "structured": false, "script": null});
    };
    json!({
        "managed": syntax.is_managed_command(command),
        "structured": syntax.is_structured(command),
        "script": syntax.live_script(command),
    })
}

fn entries(syntax: &mut Syntax, value: &Value, command: &str) -> Value {
    let managed: Vec<bool> = value
        .as_array()
        .map(|list| {
            list.iter()
                .map(|entry| is_managed_entry(syntax, entry, command))
                .collect()
        })
        .unwrap_or_default();
    json!({ "managed": managed })
}

/// Structured Guard commands with a script token, deduplicated in order.
/// Python keeps those whose script passes its path checks.
fn commands(syntax: &mut Syntax, hooks: &Pairs<'_>) -> Value {
    let mut seen = BTreeSet::new();
    let mut found = Vec::new();
    for (_, entries) in hooks.iter().flatten() {
        for entry in entries.as_array().into_iter().flatten() {
            let Some(command) = entry.get("command").and_then(Value::as_str) else {
                continue;
            };
            if seen.contains(command)
                || entry.get("enabled") == Some(&Value::Bool(false))
                || entry.get("disabled") == Some(&Value::Bool(true))
                || !syntax.is_structured(command)
            {
                continue;
            }
            let Some(script) = syntax.live_script(command) else {
                continue;
            };
            seen.insert(command);
            let frozen = syntax.boots_frozen(command);
            found.push(json!({"command": command, "script": script, "frozen": frozen}));
        }
    }
    json!({ "commands": found })
}

/// Per blocking event, the `[index, script]` entries Python checks on disk;
/// `null` when Cursor would ignore the file or a blocking event is not a list.
fn intercept(syntax: &mut Syntax, hooks: &Pairs<'_>) -> Value {
    let unrouted = json!({ "events": null });
    let Some(hooks) = hooks else {
        return unrouted;
    };
    if hooks
        .iter()
        .any(|(name, _)| !SUPPORTED_EVENTS.contains(name))
    {
        return unrouted;
    }
    let mut events = Vec::new();
    for event in BLOCKING_EVENTS {
        let found = hooks.iter().find(|(name, _)| name == event);
        let Some(entries) = found.and_then(|(_, value)| value.as_array()) else {
            return unrouted;
        };
        let mut candidates = Vec::new();
        for (index, entry) in entries.iter().enumerate() {
            let Some(command) = entry.get("command").and_then(Value::as_str) else {
                continue;
            };
            if command.trim_matches(py_space).is_empty() {
                continue;
            }
            if let Some(script) = syntax.live_script(command) {
                candidates.push(json!([index, script]));
            }
        }
        events.push(json!([event, candidates]));
    }
    json!({ "events": events })
}

fn script(source: &str) -> Value {
    json!({ "managed": is_managed_script(source) })
}

/// `_is_managed_hook_script`.
pub(crate) fn is_managed_script(source: &str) -> bool {
    source.contains(MANAGED_DOCSTRING)
        && source.contains("\nGUARD_CLI =")
        && source.contains("\nGUARD_RECOVERY_COMMAND =")
}

/// One event of the installed hooks object.
struct Slot<'a> {
    event: &'a str,
    entries: &'a [Value],
    /// Indices kept from `entries`; `None` keeps a non-list value as it is.
    kept: Option<Vec<usize>>,
    guard: bool,
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
        .map(text)
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

fn slot<'a>(event: &'a str, value: &'a Value) -> Slot<'a> {
    let entries = value.as_array().map_or(&[][..], Vec::as_slice);
    let kept = value.as_array().map(|list| (0..list.len()).collect());
    Slot {
        event,
        entries,
        kept,
        guard: false,
    }
}

/// The hooks object `_managed_hooks_payload` reads: the nested `hooks` object,
/// else every top-level list except `version`.
fn source_slots(map: &Map<String, Value>) -> Result<Vec<Slot<'_>>, &'static str> {
    let payload = map["payload"].as_object().ok_or(ERR_INVALID)?;
    let top_keys = ordered_keys(payload, &map["top_keys"])?;
    if let Some(nested) = payload.get("hooks").and_then(Value::as_object) {
        let keys = ordered_keys(nested, &map["hooks_keys"])?;
        return Ok(keys
            .into_iter()
            .map(|key| slot(key, &nested[key]))
            .collect());
    }
    if !map["hooks_keys"].is_null() {
        return Err(ERR_INVALID);
    }
    Ok(top_keys
        .into_iter()
        .filter(|key| *key != "version" && payload[*key].is_array())
        .map(|key| slot(key, &payload[key]))
        .collect())
}

fn managed_commands(value: &Value) -> Result<Vec<(&str, &str)>, &'static str> {
    let managed = value
        .as_array()
        .ok_or(ERR_INVALID)?
        .iter()
        .map(|pair| match pair.as_array().map(Vec::as_slice) {
            Some([Value::String(event), Value::String(command)]) => {
                Ok((event.as_str(), command.as_str()))
            }
            _ => Err(ERR_INVALID),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let events: BTreeSet<&str> = managed.iter().map(|(event, _)| *event).collect();
    if events.len() != managed.len() || !events.iter().all(|event| SUPPORTED_EVENTS.contains(event))
    {
        return Err(ERR_INVALID);
    }
    Ok(managed)
}

fn strip(syntax: &mut Syntax, slot: &Slot<'_>, command: &str) -> Vec<usize> {
    let entries = slot.entries;
    slot.kept
        .iter()
        .flatten()
        .copied()
        .filter(|index| !is_managed_entry(syntax, &entries[*index], command))
        .collect()
}

fn unsupported(slots: &[Slot<'_>]) -> Vec<String> {
    let mut events: Vec<String> = slots
        .iter()
        .filter(|slot| !SUPPORTED_EVENTS.contains(&slot.event))
        .map(|slot| slot.event.to_string())
        .collect();
    events.sort();
    events
}

/// Python's `isinstance(version, int)` for a JSON value (`bool` included).
fn kept_version(version: Option<&Value>) -> Value {
    match version {
        Some(Value::Bool(flag)) => Value::Bool(*flag),
        Some(Value::Number(number)) if !number.to_string().contains(['.', 'e', 'E']) => {
            Value::Number(number.clone())
        }
        _ => json!(1),
    }
}

/// Merge Guard's entries into each managed event, then drop Guard entries
/// under events Cursor rejects. Another tool's entry under such an event
/// still makes Cursor ignore every hook, so install stops with their names.
fn install(syntax: &mut Syntax, map: &Map<String, Value>) -> KindResult {
    let mut slots = source_slots(map)?;
    let script = text(&map["script"])?;
    for (event, command) in managed_commands(&map["managed"])? {
        match slots.iter().position(|slot| slot.event == event) {
            Some(index) => {
                let kept = strip(syntax, &slots[index], command);
                slots[index].kept = Some(kept);
                slots[index].guard = true;
            }
            None => slots.push(Slot {
                event,
                entries: &[],
                kept: Some(Vec::new()),
                guard: true,
            }),
        }
    }
    for event in unsupported(&slots) {
        let Some(index) = slots.iter().position(|slot| slot.event == event) else {
            continue;
        };
        let remaining = strip(syntax, &slots[index], script);
        if remaining.is_empty() {
            slots.remove(index);
        } else {
            slots[index].kept = Some(remaining);
        }
    }
    let left = unsupported(&slots);
    if !left.is_empty() {
        return Ok(json!({
            "error": format!(
                "guard_cursor_hook_unsupported_events:{}: Cursor ignores hooks.json while it names these events; remove or rename them, then reinstall.",
                left.join(",")
            )
        }));
    }
    let payload = map["payload"].as_object().ok_or(ERR_INVALID)?;
    let hooks: Vec<Value> = slots
        .iter()
        .map(|slot| json!([slot.event, slot.kept, slot.guard]))
        .collect();
    Ok(json!({ "version": kept_version(payload.get("version")), "hooks": hooks }))
}
