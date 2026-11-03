//! `runner_authority` kind `harness_settings_file`: the Devin `config.json`
//! and Muse `settings.json` rewrite of `DevinHarnessAdapter` and
//! `MuseHarnessAdapter` install and uninstall, over the hook plan of
//! `harness_hook_settings`.
//!
//! Python keeps the file reads, the path checks, the modes, the launcher shim,
//! the bridge command and the writes. It sends the captured bytes as base64
//! (`content`, `null` for no file) and gets back whole texts rendered like
//! `json.dumps(indent=2)` plus a newline, with every user object and its key
//! order kept:
//!
//! - `install` answers `{"text", "state", "notes"}` (the new settings, the
//!   install state and the manifest notes) or `{"refusal"}`, the message for a
//!   file Guard will not rewrite;
//! - `uninstall` (with `present`, whether a file is there even when it could
//!   not be read) answers `{"text", "notes"}`, `text` being `null` when the
//!   file stays as it is.
//!
//! Devin's file is JSONC: Guard refuses to rewrite one carrying comments or
//! trailing commas. Muse's is strict JSON and must carry `schema_version`.

use std::cell::Cell;

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Map, Value};

use super::devin_jsonc::{self, Parsed};
use super::harness_hook_settings::{
    install_events, pruned_events, timing_seconds, Group, Harness, Step,
};
use super::pyjson::{parse_mapping_lone_surrogates, JsonFailure, PyVal, SurrogateMapped};
use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};
use super::zcode_hook_settings::{lookup, remove_key, set_key, Dict};
use super::zcode_hook_surface::render_file;

const DEVIN_PRESERVED: &str =
    "User permissions, read_config_from, MCP servers, and any pre-existing hooks were preserved";
const MUSE_PRESERVED: &str =
    "User model, skills, MCP servers, and any pre-existing hooks were preserved";

/// How the captured settings read.
enum Read {
    /// The object and whether the parse mapped a lone surrogate escape.
    Payload(Dict, bool),
    /// Unreadable, or not UTF-8.
    Unreadable,
    /// Not JSON (Muse), or not a JSONC object (Devin).
    Unparsed,
    /// Devin JSONC with comments or trailing commas.
    Commented,
    /// Muse JSON that is not an object.
    NotObject,
}

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let map = args_object(args)?;
    let harness = Harness::parse(map.get("harness"))?;
    let op = map.get("op").and_then(Value::as_str).ok_or(ERR_INVALID)?;
    let mut keys = vec!["op", "harness", "content"];
    match op {
        "install" => keys.extend(["config_path", "command", harness.timing_key()]),
        "uninstall" => keys.push("present"),
        _ => return Err(ERR_INVALID),
    }
    if map.len() != keys.len() || !keys.iter().all(|key| map.contains_key(*key)) {
        return Err(ERR_INVALID);
    }
    if op == "install" {
        install(harness, map)
    } else {
        uninstall(harness, map)
    }
}

fn install(harness: Harness, map: &Map<String, Value>) -> KindResult {
    let groups = harness.groups(timing_seconds(&map[harness.timing_key()])?)?;
    let command = map["command"].as_str().ok_or(ERR_INVALID)?;
    let config_path = map["config_path"].as_str().ok_or(ERR_INVALID)?;
    let (mut payload, lone) = match content(&map["content"])? {
        None => (Dict::new(), false),
        Some(bytes) => match read(harness, bytes)? {
            Read::Payload(payload, lone) => (payload, lone),
            refused => return Ok(json!({ "refusal": install_refusal(harness, &refused) })),
        },
    };
    // A missing or `null` hooks value plans like an empty one.
    let hooks = match lookup(&payload, "hooks") {
        None | Some(PyVal::Null) => Dict::new(),
        Some(PyVal::Dict(hooks)) => hooks.clone(),
        Some(_) => return Ok(json!({ "refusal": hooks_not_object(harness) })),
    };
    let (shape, keys) = plan_input(&hooks);
    let events = match install_events(harness, &groups, &shape, &keys) {
        Ok(events) => events,
        Err(event) => {
            let refusal = format!(
                "Muse settings have a non-list hooks.{event} value; Guard will not rewrite it. \
                 Fix the file, then rerun hol-guard install muse."
            );
            return Ok(json!({ "refusal": refusal }));
        }
    };
    let mut rebuilt = Dict::new();
    for (event, steps, guard) in events {
        let own = lookup(&hooks, event);
        let value = match steps {
            None => own.cloned().ok_or(ERR_INVALID)?,
            Some(steps) => {
                let handler = guard.map(|group| guard_handler(command, group));
                rebuild(list_items(own), &steps, handler.as_ref())?
            }
        };
        rebuilt.push((event.to_owned(), value));
    }
    let state_key = match harness {
        Harness::Devin => "managed_config_path",
        Harness::Muse => {
            // Muse refuses a settings file without schema_version; a file
            // Guard creates (or repairs) must carry it.
            if lookup(&payload, "schema_version").is_none() {
                payload.push(("schema_version".to_owned(), PyVal::Int("1".to_owned())));
            }
            "managed_settings_path"
        }
    };
    set_key(&mut payload, "hooks", PyVal::Dict(rebuilt));
    let state = vec![(state_key.to_owned(), PyVal::Str(config_path.to_owned()))];
    Ok(json!({
        "text": render_file(payload, lone)?,
        "state": render_file(state, false)?,
        "notes": install_notes(harness),
    }))
}

fn uninstall(harness: Harness, map: &Map<String, Value>) -> KindResult {
    let present = map["present"].as_bool().ok_or(ERR_INVALID)?;
    let read = match (content(&map["content"])?, present) {
        (Some(bytes), true) => read(harness, bytes)?,
        (None, true) => Read::Unreadable,
        (None, false) => Read::Payload(Dict::new(), false),
        (Some(_), false) => return Err(ERR_INVALID),
    };
    let unreadable = match harness {
        Harness::Devin => "Devin config could not be parsed; Guard left the file untouched.",
        Harness::Muse => "Muse settings could not be parsed; Guard left the file untouched.",
    };
    let (text, notes) = match read {
        // A JSONC or unparseable file is never rewritten: pruning would
        // silently strip the user's comments or data.
        Read::Unreadable | Read::Unparsed => (None, vec![unreadable]),
        Read::Commented => (
            None,
            vec![
                "Devin config is JSONC (comments or trailing commas); Guard left its managed hook \
                 entries in place rather than rewriting the file. Remove the entries under the \
                 hooks key manually.",
            ],
        ),
        Read::NotObject => (None, removed_notes(harness)),
        Read::Payload(mut payload, lone) => match lookup(&payload, "hooks") {
            Some(PyVal::Dict(hooks)) => {
                let pruned = prune_hooks(harness, hooks)?;
                if pruned.is_empty() {
                    remove_key(&mut payload, "hooks");
                } else {
                    set_key(&mut payload, "hooks", PyVal::Dict(pruned));
                }
                match render_file(payload, lone) {
                    Ok(text) => (Some(text), removed_notes(harness)),
                    // A lone surrogate escape has no Rust string form to write
                    // back; the file is left as it is so the rest of the
                    // uninstall still runs.
                    Err(_) if lone => (None, vec![unwritable(harness)]),
                    Err(error) => return Err(error),
                }
            }
            _ => (None, removed_notes(harness)),
        },
    };
    Ok(json!({ "text": text, "notes": notes }))
}

/// The captured bytes, `None` for no file.
fn content(value: &Value) -> Result<Option<Vec<u8>>, &'static str> {
    match value {
        Value::Null => Ok(None),
        Value::String(text) => STANDARD.decode(text).map(Some).map_err(|_| ERR_INVALID),
        _ => Err(ERR_INVALID),
    }
}

/// Devin's `parse_devin_jsonc` or Muse's `json.loads`, over UTF-8 text. Input
/// CPython raises on instead of parsing is refused.
fn read(harness: Harness, bytes: Vec<u8>) -> Result<Read, &'static str> {
    let Ok(text) = String::from_utf8(bytes) else {
        return Ok(Read::Unreadable);
    };
    match harness {
        Harness::Devin => {
            let mapped = Cell::new(false);
            let parsed = devin_jsonc::parse_with(&text, |text| {
                parse_mapping_lone_surrogates(text).map(|parse| {
                    mapped.set(mapped.get() || parse.mapped);
                    parse.value
                })
            })?;
            Ok(match parsed {
                Parsed {
                    parse_failed: true, ..
                } => Read::Unparsed,
                Parsed {
                    had_comments: true, ..
                } => Read::Commented,
                Parsed {
                    payload: PyVal::Dict(entries),
                    ..
                } => Read::Payload(entries, mapped.get()),
                Parsed { .. } => Read::Unparsed,
            })
        }
        Harness::Muse => match parse_mapping_lone_surrogates(&text) {
            Ok(SurrogateMapped {
                value: PyVal::Dict(entries),
                mapped,
                ..
            }) => Ok(Read::Payload(entries, mapped)),
            Ok(_) => Ok(Read::NotObject),
            Err(JsonFailure::Syntax) => Ok(Read::Unparsed),
            Err(_) => Err(ERR_INVALID),
        },
    }
}

fn install_refusal(harness: Harness, read: &Read) -> &'static str {
    match (harness, read) {
        (Harness::Devin, Read::Commented) => {
            "Devin config at ~/.config/devin/config.json contains comments or trailing commas; \
             Guard will not rewrite it. Remove the comments or move them to another file, then \
             rerun hol-guard install devin."
        }
        (Harness::Devin, Read::Unreadable) => {
            "Devin config could not be parsed as a JSON object; Guard will not rewrite it."
        }
        (Harness::Devin, _) => {
            "Devin config at ~/.config/devin/config.json could not be parsed as a JSON object; \
             Guard will not rewrite it. Fix the file, then rerun hol-guard install devin."
        }
        (Harness::Muse, Read::NotObject) => {
            "Muse settings must be a JSON object before installation."
        }
        (Harness::Muse, _) => {
            "Muse settings at ~/.config/muse/settings.json could not be parsed as a JSON object; \
             Guard will not rewrite it. Fix the file, then rerun hol-guard install muse."
        }
    }
}

fn hooks_not_object(harness: Harness) -> &'static str {
    match harness {
        Harness::Devin => "Devin config has a non-object hooks value; Guard will not rewrite it.",
        Harness::Muse => "Muse settings have a non-object hooks value; Guard will not rewrite it.",
    }
}

fn install_notes(harness: Harness) -> Vec<&'static str> {
    match harness {
        Harness::Devin => vec![
            "Guard hook entries added to ~/.config/devin/config.json under the hooks section",
            DEVIN_PRESERVED,
        ],
        Harness::Muse => vec![
            "Guard hook entries added to ~/.config/muse/settings.json under the hooks section",
            MUSE_PRESERVED,
            "Approving a blocked Muse tool call resumes that exact call inside the pending hook",
        ],
    }
}

fn unwritable(harness: Harness) -> &'static str {
    match harness {
        Harness::Devin => {
            "Devin config holds a lone surrogate escape Guard cannot write back; Guard left its \
             managed hook entries in place. Remove the entries under the hooks key manually."
        }
        Harness::Muse => {
            "Muse settings hold a lone surrogate escape Guard cannot write back; Guard left its \
             managed hook entries in place. Remove the entries under the hooks key manually."
        }
    }
}

fn removed_notes(harness: Harness) -> Vec<&'static str> {
    match harness {
        Harness::Devin => vec![
            "Guard-managed hook entries removed from ~/.config/devin/config.json",
            DEVIN_PRESERVED,
        ],
        Harness::Muse => vec![
            "Guard-managed hook entries removed from ~/.config/muse/settings.json",
            MUSE_PRESERVED,
        ],
    }
}

/// A shape-only copy for the planner, which reads value kinds, strings and
/// list lengths only: every number becomes 0, so a non-finite float still has
/// a JSON form.
fn shape_of(value: &PyVal) -> Value {
    match value {
        PyVal::Null => Value::Null,
        PyVal::Bool(flag) => Value::Bool(*flag),
        PyVal::Int(_) | PyVal::Float(_) => Value::from(0),
        PyVal::Str(text) => Value::String(text.clone()),
        PyVal::List(items) => Value::Array(items.iter().map(shape_of).collect()),
        PyVal::Dict(entries) => Value::Object(
            entries
                .iter()
                .map(|(key, item)| (key.clone(), shape_of(item)))
                .collect(),
        ),
    }
}

/// The planner's view of `hooks` and its key order.
fn plan_input(hooks: &[(String, PyVal)]) -> (Map<String, Value>, Vec<&str>) {
    let shape = hooks
        .iter()
        .map(|(key, value)| (key.clone(), shape_of(value)))
        .collect();
    let keys = hooks.iter().map(|(key, _)| key.as_str()).collect();
    (shape, keys)
}

fn list_items(value: Option<&PyVal>) -> &[PyVal] {
    match value {
        Some(PyVal::List(items)) => items.as_slice(),
        _ => &[],
    }
}

/// Guard's handler running `command`.
fn guard_handler(command: &str, group: Group) -> PyVal {
    let mut handler = vec![
        ("type".to_owned(), PyVal::Str("command".to_owned())),
        ("command".to_owned(), PyVal::Str(command.to_owned())),
        ("timeout".to_owned(), PyVal::Int(group.timeout.to_string())),
    ];
    if let Some(status) = group.status {
        handler.push(("statusMessage".to_owned(), PyVal::Str(status.to_owned())));
    }
    PyVal::Dict(handler)
}

/// One list plan over the caller's own entries; `None` items are Guard's
/// handler. A copied entry keeps its keys and their order, its `hooks` set in
/// place.
fn rebuild(
    entries: &[PyVal],
    steps: &[Step],
    handler: Option<&PyVal>,
) -> Result<PyVal, &'static str> {
    let mut rebuilt = Vec::with_capacity(steps.len());
    for step in steps {
        rebuilt.push(match step {
            Step::Keep(index) => entries.get(*index).cloned().ok_or(ERR_INVALID)?,
            Step::Copy(index, items) => {
                let Some(PyVal::Dict(entry)) = entries.get(*index) else {
                    return Err(ERR_INVALID);
                };
                let nested = list_items(lookup(entry, "hooks"));
                let hooks = items
                    .iter()
                    .map(|item| match item {
                        Some(position) => nested.get(*position).cloned().ok_or(ERR_INVALID),
                        None => handler.cloned().ok_or(ERR_INVALID),
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let mut copy = entry.clone();
                set_key(&mut copy, "hooks", PyVal::List(hooks));
                PyVal::Dict(copy)
            }
            Step::Group(matcher) => {
                let handler = handler.cloned().ok_or(ERR_INVALID)?;
                let mut group = vec![("hooks".to_owned(), PyVal::List(vec![handler]))];
                if let Some(matcher) = matcher {
                    group.push(("matcher".to_owned(), PyVal::Str(matcher.clone())));
                }
                PyVal::Dict(group)
            }
        });
    }
    Ok(PyVal::List(rebuilt))
}

/// `hooks` without Guard's handlers; events left without entries are dropped.
fn prune_hooks(harness: Harness, hooks: &[(String, PyVal)]) -> Result<Dict, &'static str> {
    let (shape, keys) = plan_input(hooks);
    pruned_events(harness, &shape, &keys)
        .into_iter()
        .map(|(event, steps)| -> Result<(String, PyVal), &'static str> {
            let own = lookup(hooks, event);
            let value = match steps {
                None => own.cloned().ok_or(ERR_INVALID)?,
                Some(steps) => rebuild(list_items(own), &steps, None)?,
            };
            Ok((event.to_owned(), value))
        })
        .collect()
}

#[cfg(test)]
#[path = "harness_settings_file_tests.rs"]
mod tests;
