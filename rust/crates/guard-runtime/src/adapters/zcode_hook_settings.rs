//! `runner_authority` kind `zcode_hook_settings`: Guard's hook groups in a
//! ZCode `hooks` settings mapping (`config.json` and the CLI's
//! `setting.json`), ported from `ZCodeHarnessAdapter` in `adapters/zcode.py`.
//!
//! Python keeps the file I/O, the install state, the handler rendering and
//! the `enabled` flag writes. It sends the `hooks` mapping as JSON text so its
//! key order survives, and every list in the answer names entries of the
//! caller's own lists, so user objects and their key order are never rebuilt:
//!
//! - `["events", i]` / `["hooks", i]`: entry `i` of `hooks.events[name]` or of
//!   the legacy flat `hooks[name]`, unchanged;
//! - `{"copy": <ref>, "hooks": [j, "guard", ...]}`: `dict(entry)` holding
//!   those of its own handlers and Guard's handler for the event;
//! - `{"group": <matcher or null>}`: a new group holding Guard's handler.
//!
//! `install` answers the legacy flat keys to drop and the `hooks.events`
//! lists to assign, in assignment order; `uninstall` answers every event list
//! after pruning (`null` drops it). Both answer the saved pre-install
//! `enabled` record, or `null` when the live flag still applies.

use std::collections::HashSet;

use serde_json::{json, Map, Value};

use super::context_digest::python_strip;
use super::pyjson::{self, PyVal};
use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};
use super::zcode_artifacts::{hook_event_groups, is_managed, HOOK_EVENT_NAMES};

const EVENTS_KEY: &str = "events";
const PRETOOL: &str = "PreToolUse";
const PROMPT: &str = "UserPromptSubmit";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Source {
    /// `hooks.events[name]`.
    Events,
    /// The legacy flat `hooks[name]`.
    Hooks,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Handler {
    /// The copied entry's own handler at this index.
    Own(usize),
    /// Guard's handler for the event.
    Guard,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Entry {
    Keep(Source, usize),
    Copy(Source, usize, Vec<Handler>),
    Group(Option<String>),
}

type Ref = (Source, usize);
type Assigned = Vec<(String, Vec<Entry>)>;
type EventPlan = (String, Option<Vec<Entry>>);
type EventPlans = Vec<EventPlan>;

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let map = args_object(args)?;
    let op = map.get("op").and_then(Value::as_str).ok_or(ERR_INVALID)?;
    let keys: &[&str] = match op {
        "install" => &[
            "hooks",
            "path",
            "history",
            "managed_config_path",
            "matchers",
        ],
        "uninstall" => &["hooks", "path", "history", "managed_config_path"],
        _ => return Err(ERR_INVALID),
    };
    if map.len() != keys.len() + 1 || !keys.iter().all(|key| map.contains_key(*key)) {
        return Err(ERR_INVALID);
    }
    let text = map["hooks"].as_str().ok_or(ERR_INVALID)?;
    let hooks = pyjson::parse(text).map_err(|_| ERR_INVALID)?;
    if hooks.as_dict().is_none() {
        return Err(ERR_INVALID);
    }
    let path = map["path"].as_str().ok_or(ERR_INVALID)?;
    let enabled = recorded_enabled(&hooks, path, &map["history"], &map["managed_config_path"]);
    if op == "uninstall" {
        let (events, flat) = uninstall(&hooks);
        return Ok(json!({
            "enabled": enabled,
            "events": plans_json(&events),
            "hooks": plans_json(&flat),
        }));
    }
    let matchers = map["matchers"]
        .as_array()
        .ok_or(ERR_INVALID)?
        .iter()
        .map(|matcher| matcher.as_str().ok_or(ERR_INVALID))
        .collect::<Result<Vec<_>, _>>()?;
    let (drop, events) = install(&hooks, &matchers);
    let has_handlers = hook_event_groups(&hooks)
        .iter()
        .any(|(_, entries)| !entries.is_empty());
    let events: Vec<Value> = events
        .iter()
        .map(|(name, plan)| json!([name, plan_json(plan)]))
        .collect();
    Ok(json!({
        "enabled": enabled,
        "has_handlers": has_handlers,
        "drop": drop,
        "events": events,
    }))
}

/// The list `source` names for event `name`, or nothing when it is not one.
fn source_list<'a>(hooks: &'a PyVal, source: Source, name: &str) -> &'a [PyVal] {
    let container = match source {
        Source::Events => hooks.get(EVENTS_KEY),
        Source::Hooks => Some(hooks),
    };
    container
        .and_then(|container| container.get(name))
        .and_then(PyVal::as_list)
        .unwrap_or_default()
}

fn entry_at<'a>(hooks: &'a PyVal, name: &str, (source, index): Ref) -> &'a PyVal {
    &source_list(hooks, source, name)[index]
}

fn refs(hooks: &PyVal, source: Source, name: &str) -> Vec<Ref> {
    (0..source_list(hooks, source, name).len())
        .map(|index| (source, index))
        .collect()
}

/// `is_managed_handler`: a handler object whose command is Guard's.
fn managed_handler(handler: &PyVal) -> bool {
    handler.as_dict().is_some() && managed_command(handler)
}

fn managed_command(value: &PyVal) -> bool {
    value
        .get("command")
        .and_then(PyVal::as_str)
        .is_some_and(is_managed)
}

/// `matcher.strip()` when that leaves text, else `None`.
fn matcher_key(matcher: Option<&PyVal>) -> Option<String> {
    let text = python_strip(matcher?.as_str()?);
    (!text.is_empty()).then(|| text.to_owned())
}

/// `_hooks_have_managed_entries`: a Guard handler nested in any event group
/// of either layout. A non-list `hooks` value carries no handler.
fn has_managed_entries(hooks: &PyVal) -> bool {
    hook_event_groups(hooks).iter().any(|(_, entries)| {
        entries.iter().any(|entry| {
            entry.as_dict().is_some()
                && entry
                    .get("hooks")
                    .and_then(PyVal::as_list)
                    .unwrap_or_default()
                    .iter()
                    .any(managed_handler)
        })
    })
}

/// `_valid_enabled_record`: the record as `{present, value}` when it is one.
fn valid_record(record: &Value) -> Option<Value> {
    let record = record.as_object()?;
    let present = record.get("present")?.as_bool()?;
    let value = record.get("value")?;
    (!present || value.is_boolean()).then(|| json!({"present": present, "value": value}))
}

/// `_recorded_enabled_for`: a saved record applies only while Guard's
/// entries are still in the file; legacy single-file state maps only onto
/// the file it managed. `null` means the live flag applies.
fn recorded_enabled(hooks: &PyVal, path: &str, history: &Value, managed_path: &Value) -> Value {
    if !has_managed_entries(hooks) {
        return Value::Null;
    }
    let saved = history
        .as_object()
        .and_then(|history| history.get(path))
        .and_then(valid_record);
    if let Some(record) = saved {
        return record;
    }
    match valid_record(history) {
        Some(record) if managed_path.as_str() == Some(path) => record,
        _ => Value::Null,
    }
}

/// `prune_managed_hook_entries`: drop Guard entries and Guard handlers, and
/// entries left without a handler. Non-object entries stay.
fn prune(hooks: &PyVal, name: &str, refs: &[Ref]) -> Vec<Entry> {
    let mut remaining = Vec::new();
    for &(source, index) in refs {
        let entry = entry_at(hooks, name, (source, index));
        if entry.as_dict().is_none() {
            remaining.push(Entry::Keep(source, index));
            continue;
        }
        if managed_command(entry) {
            continue;
        }
        let Some(handlers) = entry.get("hooks").and_then(PyVal::as_list) else {
            remaining.push(Entry::Keep(source, index));
            continue;
        };
        let own: Vec<Handler> = handlers
            .iter()
            .enumerate()
            .filter(|(_, handler)| !managed_handler(handler))
            .map(|(position, _)| Handler::Own(position))
            .collect();
        // An entry left without a handler goes, even one that had none.
        if own.is_empty() {
            continue;
        }
        if own.len() == handlers.len() {
            remaining.push(Entry::Keep(source, index));
        } else {
            remaining.push(Entry::Copy(source, index, own));
        }
    }
    remaining
}

/// `merge_hook_entry`: Guard's handler replaces the Guard handlers of the
/// first object entry whose matcher key matches, else joins that entry, else
/// arrives as a new group.
fn merge(hooks: &PyVal, name: &str, plan: &mut Vec<Entry>, matcher: Option<&str>) {
    let key = matcher.map(python_strip).filter(|text| !text.is_empty());
    for slot in plan.iter_mut() {
        let (source, index, items) = match slot {
            // A Guard group holds only Guard's handler, so it is current.
            Entry::Group(group) if group.as_deref() == key => return,
            Entry::Group(_) => continue,
            Entry::Keep(source, index) => (*source, *index, None),
            Entry::Copy(source, index, items) => (*source, *index, Some(items.clone())),
        };
        let entry = entry_at(hooks, name, (source, index));
        if entry.as_dict().is_none() || matcher_key(entry.get("matcher")).as_deref() != key {
            continue;
        }
        let own = entry
            .get("hooks")
            .and_then(PyVal::as_list)
            .unwrap_or_default();
        let mut handlers = items.unwrap_or_else(|| (0..own.len()).map(Handler::Own).collect());
        let guard = |item: &Handler| match item {
            Handler::Guard => true,
            Handler::Own(position) => managed_handler(&own[*position]),
        };
        if handlers.iter().any(guard) {
            for item in &mut handlers {
                if guard(&*item) {
                    *item = Handler::Guard;
                }
            }
        } else {
            handlers.push(Handler::Guard);
        }
        *slot = Entry::Copy(source, index, handlers);
        return;
    }
    plan.push(Entry::Group(key.map(str::to_owned)));
}

/// `_sync_managed_hook_groups`: fold legacy flat event groups into
/// `hooks.events` (equal entries once), then reconcile Guard's `PreToolUse`
/// group per matcher and its matcherless `UserPromptSubmit` group.
fn install(hooks: &PyVal, matchers: &[&str]) -> (Vec<String>, Assigned) {
    let mut drop = Vec::new();
    let mut lists: Vec<(String, Vec<Ref>)> = Vec::new();
    for (name, value) in hooks.as_dict().unwrap_or_default() {
        if name == EVENTS_KEY || !HOOK_EVENT_NAMES.contains(&name.as_str()) {
            continue;
        }
        if value.as_list().is_none() {
            continue;
        }
        let mut seen = HashSet::new();
        let merged: Vec<Ref> = refs(hooks, Source::Events, name)
            .into_iter()
            .chain(refs(hooks, Source::Hooks, name))
            .filter(|reference| seen.insert(entry_at(hooks, name, *reference).canonical_key()))
            .collect();
        lists.push((name.clone(), merged));
        drop.push(name.clone());
    }
    let mut events: Assigned = lists
        .iter()
        .map(|(name, merged)| {
            let kept = merged
                .iter()
                .map(|&(source, index)| Entry::Keep(source, index))
                .collect();
            (name.clone(), kept)
        })
        .collect();
    let jobs: [(&str, Vec<Option<&str>>); 2] = [
        (PRETOOL, matchers.iter().copied().map(Some).collect()),
        (PROMPT, vec![None]),
    ];
    for (name, job_matchers) in jobs {
        let current = match lists.iter().find(|(listed, _)| listed == name) {
            Some((_, merged)) => merged.clone(),
            None => refs(hooks, Source::Events, name),
        };
        let mut plan = prune(hooks, name, &current);
        for matcher in job_matchers {
            merge(hooks, name, &mut plan, matcher);
        }
        match events.iter_mut().find(|(listed, _)| listed == name) {
            Some((_, slot)) => *slot = plan,
            None => events.push((name.to_owned(), plan)),
        }
    }
    (drop, events)
}

/// `_prune_managed_hook_groups`: every `hooks.events` list, then every other
/// list-valued key of `hooks` (legacy flat groups from older installs).
fn uninstall(hooks: &PyVal) -> (EventPlans, EventPlans) {
    let pruned = |source: Source, name: &str| {
        let plan = prune(hooks, name, &refs(hooks, source, name));
        (name.to_owned(), (!plan.is_empty()).then_some(plan))
    };
    let events: EventPlans = hooks
        .get(EVENTS_KEY)
        .and_then(PyVal::as_dict)
        .unwrap_or_default()
        .iter()
        .map(|(name, _)| pruned(Source::Events, name.as_str()))
        .collect();
    let flat: EventPlans = hooks
        .as_dict()
        .unwrap_or_default()
        .iter()
        .filter(|(name, value)| name != EVENTS_KEY && value.as_list().is_some())
        .map(|(name, _)| pruned(Source::Hooks, name.as_str()))
        .collect();
    (events, flat)
}

fn reference_json((source, index): Ref) -> Value {
    let source = match source {
        Source::Events => "events",
        Source::Hooks => "hooks",
    };
    json!([source, index])
}

fn plan_json(plan: &[Entry]) -> Value {
    let entries = plan.iter().map(|entry| match entry {
        Entry::Keep(source, index) => reference_json((*source, *index)),
        Entry::Copy(source, index, items) => {
            let handlers: Vec<Value> = items
                .iter()
                .map(|item| match item {
                    Handler::Own(position) => json!(position),
                    Handler::Guard => json!("guard"),
                })
                .collect();
            let mut copy = Map::new();
            copy.insert("copy".to_owned(), reference_json((*source, *index)));
            copy.insert("hooks".to_owned(), Value::Array(handlers));
            Value::Object(copy)
        }
        Entry::Group(matcher) => json!({ "group": matcher }),
    });
    Value::Array(entries.collect())
}

fn plans_json(plans: &[EventPlan]) -> Value {
    Value::Array(
        plans
            .iter()
            .map(|(name, plan)| match plan {
                Some(plan) => json!([name, plan_json(plan)]),
                None => json!([name, Value::Null]),
            })
            .collect(),
    )
}
