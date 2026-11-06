//! Guard's Claude hook entries as index plans over the caller's own lists.
//!
//! A port of `prune_guard_hook_entries`, `merge_hook_group` and
//! `handler_identity` from `adapters/claude_hook_config.py`. Results never
//! rebuild user JSON: each entry of a result names an entry of the caller's
//! list, a copy of one with some of its own handlers (and Guard's), or a new
//! Guard group, so Python keeps the user's objects and their key order.

use serde_json::{json, Map, Value};

use crate::approval_queue_identity_op::py_str;
use crate::claude_session_start_contract::{handler_argv, is_guard_handler, HookGroupsContract};
use crate::guard_store_json::py_strip;

/// The answer code for an unhashable handler type, where the Python helpers
/// raised `TypeError`.
pub(crate) const ERR_UNHASHABLE: &str = "claude_hook_handler_type_unhashable";

/// A handler type Python could not hash.
#[derive(Debug)]
pub(crate) struct Unhashable;

/// One handler of a copied entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Item {
    /// The copied entry's own handler at this index.
    Own(usize),
    /// Guard's handler.
    Guard,
}

/// One entry of a result list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Entry {
    /// The caller's entry at this index, unchanged.
    Keep(usize),
    /// `dict(entry)` of the caller's entry with these `hooks`.
    Copy(usize, Vec<Item>),
    /// `guard_hook_group(matcher, handler)`.
    Group(Option<String>),
}

fn guard(contract: &HookGroupsContract, handler: &Value) -> Result<bool, Unhashable> {
    is_guard_handler(contract, handler).map_err(|()| Unhashable)
}

/// Every entry of `entries`, unchanged.
pub(crate) fn kept(entries: &[Value]) -> Vec<Entry> {
    (0..entries.len()).map(Entry::Keep).collect()
}

/// `prune_guard_hook_entries`: drop Guard entries and Guard handlers, and
/// entries left without a handler. Non-object entries stay.
pub(crate) fn prune(
    contract: &HookGroupsContract,
    entries: &[Value],
) -> Result<Vec<Entry>, Unhashable> {
    let mut remaining = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let Some(object) = entry.as_object() else {
            remaining.push(Entry::Keep(index));
            continue;
        };
        if guard(contract, entry)? {
            continue;
        }
        let Some(handlers) = object.get("hooks").and_then(Value::as_array) else {
            remaining.push(Entry::Keep(index));
            continue;
        };
        let mut items = Vec::new();
        for (position, handler) in handlers.iter().enumerate() {
            if !guard(contract, handler)? {
                items.push(Item::Own(position));
            }
        }
        if !items.is_empty() {
            remaining.push(Entry::Copy(index, items));
        }
    }
    Ok(remaining)
}

/// `matcher.strip()` when that leaves text, else `None`.
fn matcher_key(matcher: Option<&Value>) -> Option<String> {
    let text = py_strip(matcher?.as_str()?);
    (!text.is_empty()).then(|| text.to_owned())
}

/// `merge_hook_group`: object entries only; Guard's handler replaces the
/// handlers with its identity in the first entry whose matcher key matches,
/// else joins that entry, else arrives as a new group.
pub(crate) fn merge(
    entries: &[Value],
    plan: Vec<Entry>,
    matcher: Option<&Value>,
    handler: &Map<String, Value>,
) -> Vec<Entry> {
    let expected = identity(handler);
    let mut merged: Vec<Entry> = plan
        .into_iter()
        .filter(|entry| !matches!(entry, Entry::Keep(index) if !entries[*index].is_object()))
        .collect();
    let key = matcher_key(matcher);
    for slot in 0..merged.len() {
        let index = match &merged[slot] {
            Entry::Group(group_key) if *group_key != key => continue,
            Entry::Group(_) => None,
            Entry::Keep(index) | Entry::Copy(index, _) => Some(*index),
        };
        // A Guard group holds only this handler, so it is already current.
        let Some(index) = index else {
            return merged;
        };
        let entry = &entries[index];
        if matcher_key(entry.get("matcher")) != key {
            continue;
        }
        let own = entry.get("hooks").and_then(Value::as_array);
        let mut items = match &merged[slot] {
            Entry::Copy(_, items) => items.clone(),
            _ => (0..own.map_or(0, Vec::len)).map(Item::Own).collect(),
        };
        if items.iter().any(|item| is_expected(own, *item, &expected)) {
            for item in &mut items {
                if is_expected(own, *item, &expected) {
                    *item = Item::Guard;
                }
            }
        } else {
            items.push(Item::Guard);
        }
        merged[slot] = Entry::Copy(index, items);
        return merged;
    }
    merged.push(Entry::Group(key));
    merged
}

/// A handler object with Guard's identity; Guard's own handler always has it.
fn is_expected(own: Option<&Vec<Value>>, item: Item, expected: &[String]) -> bool {
    match item {
        Item::Guard => true,
        Item::Own(position) => own
            .and_then(|handlers| handlers.get(position))
            .and_then(Value::as_object)
            .is_some_and(|handler| identity(handler) == expected),
    }
}

/// The plan as JSON: an index keeps that entry, `{"entry", "hooks"}` copies
/// it with those handlers (`null` is Guard's), `{"matcher"}` is a new group.
pub(crate) fn plan_json(plan: &[Entry]) -> Value {
    let entries = plan.iter().map(|entry| match entry {
        Entry::Keep(index) => json!(index),
        Entry::Copy(index, items) => {
            let hooks: Vec<Value> = items
                .iter()
                .map(|item| match item {
                    Item::Own(position) => json!(position),
                    Item::Guard => Value::Null,
                })
                .collect();
            json!({"entry": index, "hooks": hooks})
        }
        Entry::Group(matcher) => json!({ "matcher": matcher }),
    });
    Value::Array(entries.collect())
}

/// `handler_identity`: the `http` URL, the exec argv, or the shell command.
pub(crate) fn identity(handler: &Map<String, Value>) -> Vec<String> {
    let text = |key: &str| handler.get(key).map_or_else(String::new, py_text);
    let kind = text("type");
    if kind == "http" {
        return vec![kind, text("url")];
    }
    if let Some(argv) = handler_argv(handler) {
        let mut identity = vec![kind, "exec".to_owned()];
        identity.extend(argv.into_iter().map(str::to_owned));
        return identity;
    }
    let shell = match handler.get("shell") {
        Some(Value::String(shell)) if !shell.is_empty() => shell.as_str(),
        _ => "default",
    };
    vec![kind, format!("shell:{shell}"), text("command")]
}

/// Python `str(value)` for a decoded JSON value.
fn py_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => py_repr(other),
    }
}

/// Python `repr(value)`. Objects follow this decoder's key order, not the
/// document's, which only a list- or object-valued handler field can show.
fn py_repr(value: &Value) -> String {
    match value {
        Value::String(text) => py_repr_str(text),
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(py_repr).collect();
            format!("[{}]", parts.join(", "))
        }
        Value::Object(map) => {
            let parts: Vec<String> = map
                .iter()
                .map(|(key, item)| format!("{}: {}", py_repr_str(key), py_repr(item)))
                .collect();
            format!("{{{}}}", parts.join(", "))
        }
        // JSON carries no infinities, so every scalar has a `str`.
        Value::Number(_) | Value::Null | Value::Bool(_) => py_str(value).unwrap_or_default(),
    }
}

fn py_repr_str(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::from(quote);
    for character in text.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            other if other == quote => {
                out.push('\\');
                out.push(other);
            }
            other
                if u32::from(other) < 0x20
                    || (0x7f..=0xa0).contains(&u32::from(other))
                    || other == '\u{ad}' =>
            {
                out.push_str(&format!("\\x{:02x}", u32::from(other)));
            }
            other => out.push(other),
        }
    }
    out.push(quote);
    out
}
