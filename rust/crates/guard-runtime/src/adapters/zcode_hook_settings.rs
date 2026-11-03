//! The plan behind the `zcode_hook_settings` kind (see `zcode_hook_surface`):
//! Guard's hook groups in a ZCode `hooks` settings mapping, ported from
//! `ZCodeHarnessAdapter` in `adapters/zcode.py`. Every planned list names
//! entries of the caller's own lists, so user objects and their key order
//! are kept, and is then built over the parsed mapping.

use std::collections::HashSet;

use serde_json::{json, Value};

use super::context_digest::python_strip;
use super::pyjson::PyVal;
use super::zcode_artifacts::{hook_event_groups, is_managed, HOOK_EVENT_NAMES};

const EVENTS_KEY: &str = "events";
pub(crate) const PRETOOL: &str = "PreToolUse";
pub(crate) const PROMPT: &str = "UserPromptSubmit";

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
/// An ordered JSON object; also Guard's handler per event name.
pub(crate) type Dict = Vec<(String, PyVal)>;

pub(crate) fn lookup<'a>(target: &'a [(String, PyVal)], key: &str) -> Option<&'a PyVal> {
    target
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
}

/// `target[key] = value`: in place when the key is there, else last.
pub(crate) fn set_key(target: &mut Dict, key: &str, value: PyVal) {
    match target.iter_mut().find(|(name, _)| name == key) {
        Some((_, slot)) => *slot = value,
        None => target.push((key.to_owned(), value)),
    }
}

pub(crate) fn remove_key(target: &mut Dict, key: &str) {
    target.retain(|(name, _)| name != key);
}

/// `_hooks_have_handlers`: any event group in either layout.
pub(crate) fn has_handlers(hooks: &PyVal) -> bool {
    hook_event_groups(hooks)
        .iter()
        .any(|(_, entries)| !entries.is_empty())
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
pub(crate) fn recorded_enabled(
    hooks: &PyVal,
    path: &str,
    history: &Value,
    managed_path: &Value,
) -> Value {
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

/// Event `name`'s new list from its plan, over the caller's own entries.
fn build(hooks: &PyVal, name: &str, plan: &[Entry], guard: Option<&PyVal>) -> PyVal {
    let entries = plan.iter().map(|entry| match entry {
        Entry::Keep(source, index) => entry_at(hooks, name, (*source, *index)).clone(),
        Entry::Group(matcher) => {
            let mut group: Dict = vec![(
                "hooks".to_owned(),
                PyVal::List(guard.into_iter().cloned().collect()),
            )];
            if let Some(matcher) = matcher {
                group.push(("matcher".to_owned(), PyVal::Str(matcher.clone())));
            }
            PyVal::Dict(group)
        }
        Entry::Copy(source, index, items) => {
            let entry = entry_at(hooks, name, (*source, *index));
            let own = entry
                .get("hooks")
                .and_then(PyVal::as_list)
                .unwrap_or_default();
            let kept = items
                .iter()
                .filter_map(|item| match item {
                    Handler::Own(position) => own.get(*position).cloned(),
                    Handler::Guard => guard.cloned(),
                })
                .collect();
            let mut copy = entry.as_dict().unwrap_or_default().to_vec();
            set_key(&mut copy, "hooks", PyVal::List(kept));
            PyVal::Dict(copy)
        }
    });
    PyVal::List(entries.collect())
}

/// The `hooks` mapping after install, before the `enabled` opt-in: legacy
/// flat keys dropped and the planned `hooks.events` lists assigned.
pub(crate) fn install_hooks(
    hooks: &PyVal,
    matchers: &[&str],
    handlers: &[(String, PyVal)],
) -> Dict {
    let (drop, plans) = install(hooks, matchers);
    let mut events = hooks
        .get(EVENTS_KEY)
        .and_then(PyVal::as_dict)
        .map(<[_]>::to_vec)
        .unwrap_or_default();
    for (name, plan) in &plans {
        let guard = lookup(handlers, name);
        set_key(&mut events, name, build(hooks, name, plan, guard));
    }
    let mut after = hooks.as_dict().unwrap_or_default().to_vec();
    after.retain(|(name, _)| !drop.contains(name));
    set_key(&mut after, EVENTS_KEY, PyVal::Dict(events));
    after
}

/// The `hooks` mapping after Guard's entries are pruned from both layouts;
/// an emptied list goes, and so does an emptied `hooks.events`.
pub(crate) fn uninstall_hooks(hooks: &PyVal) -> Dict {
    let (events, flat) = uninstall(hooks);
    let assign = |target: &mut Dict, plans: &EventPlans| {
        for (name, plan) in plans {
            match plan {
                Some(plan) => set_key(target, name, build(hooks, name, plan, None)),
                None => remove_key(target, name),
            }
        }
    };
    let mut after = hooks.as_dict().unwrap_or_default().to_vec();
    if let Some(current) = hooks.get(EVENTS_KEY).and_then(PyVal::as_dict) {
        let mut assigned = current.to_vec();
        assign(&mut assigned, &events);
        if assigned.is_empty() {
            remove_key(&mut after, EVENTS_KEY);
        } else {
            set_key(&mut after, EVENTS_KEY, PyVal::Dict(assigned));
        }
    }
    assign(&mut after, &flat);
    after
}
