//! Guard's hook entries in Claude Code's `settings.json`: the SessionStart
//! refresh, the runtime hook groups the contract names, and the prune that
//! removes them again.
//!
//! The plans come from `claude_hook_plan`; this module applies them to the
//! settings as read, so every user entry keeps its own keys and order.

use serde_json::{Map, Value};

use super::files::{self, Doc};
use super::{Failure, Step};
use crate::claude_hook_plan::{self as plan, Entry, Item, Unhashable};
use crate::claude_session_start_contract::HookGroupsContract;
use crate::pyjson::PyVal;

const UNHASHABLE: &str = "Claude hook handler type is unhashable";
const ARGV_EMPTY: &str =
    "claude_guard_hook_argv_empty: provide the Guard executable and its argument vector";

fn unhashable(_: Unhashable) -> Failure {
    Failure::Refusal(UNHASHABLE.to_owned())
}

/// The wire form a plan reads; a non-finite float, which no plan inspects,
/// goes as `null`.
fn lenient(value: &PyVal) -> Value {
    match value {
        PyVal::Float(number) if !number.is_finite() => Value::Null,
        PyVal::List(items) => Value::Array(items.iter().map(lenient).collect()),
        PyVal::Dict(entries) => Value::Object(
            entries
                .iter()
                .map(|(key, value)| (key.clone(), lenient(value)))
                .collect(),
        ),
        other => other.to_json().unwrap_or(Value::Null),
    }
}

/// The settings object as a plan reads it.
pub(super) fn wire_object(entries: &[(String, PyVal)]) -> Map<String, Value> {
    match lenient(&PyVal::Dict(entries.to_vec())) {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

/// `entry_list(hooks.get(event))`.
fn entry_list(hooks: &Doc, event: &str) -> Vec<PyVal> {
    match hooks.0.iter().find(|(key, _)| key == event) {
        Some((_, PyVal::List(items))) => items.clone(),
        _ => Vec::new(),
    }
}

/// `guard_command_handler(argv, timeout=..., status_message=...)`.
pub(super) fn handler(argv: &[String], timeout: u64, status: Option<&str>) -> Step<PyVal> {
    let (command, args) = argv
        .split_first()
        .ok_or_else(|| Failure::Refusal(ARGV_EMPTY.to_owned()))?;
    let mut doc = Doc::default();
    doc.set("type", files::text("command"))
        .set("command", files::text(command.as_str()))
        .set(
            "args",
            PyVal::List(args.iter().map(|arg| files::text(arg.as_str())).collect()),
        )
        .set("timeout", PyVal::Int(timeout.to_string()));
    if let Some(status) = status {
        doc.set("statusMessage", files::text(status));
    }
    Ok(doc.value())
}

/// A plan over `entries`, rebuilt from the entries themselves.
fn apply(entries: &[PyVal], steps: &[Entry], handler: Option<&PyVal>) -> Step<Vec<PyVal>> {
    let guard = || handler.cloned().ok_or(Failure::Invalid);
    let mut rebuilt = Vec::with_capacity(steps.len());
    for step in steps {
        rebuilt.push(match step {
            Entry::Keep(index) => entries.get(*index).cloned().ok_or(Failure::Invalid)?,
            Entry::Copy(index, items) => {
                let Some(PyVal::Dict(entry)) = entries.get(*index) else {
                    return Err(Failure::Invalid);
                };
                let own = match entry.iter().find(|(key, _)| key == "hooks") {
                    Some((_, PyVal::List(own))) => own.as_slice(),
                    _ => &[],
                };
                let hooks = items
                    .iter()
                    .map(|item| match item {
                        Item::Own(position) => own.get(*position).cloned().ok_or(Failure::Invalid),
                        Item::Guard => guard(),
                    })
                    .collect::<Step<Vec<_>>>()?;
                let mut copy = Doc(entry.clone());
                copy.set("hooks", PyVal::List(hooks));
                copy.value()
            }
            Entry::Group(matcher) => {
                let mut group = Doc::default();
                group.set("hooks", PyVal::List(vec![guard()?]));
                if let Some(matcher) = matcher {
                    group.set("matcher", files::text(matcher.as_str()));
                }
                group.value()
            }
        });
    }
    Ok(rebuilt)
}

/// `prune_guard_hook_entries`.
fn pruned(contract: &HookGroupsContract, entries: &[PyVal]) -> Step<Vec<PyVal>> {
    let wire: Vec<Value> = entries.iter().map(lenient).collect();
    let steps = plan::prune(contract, &wire).map_err(unhashable)?;
    apply(entries, &steps, None)
}

/// One merge job: prune `entries`, then `merge_hook_group` once per matcher.
fn merged(
    contract: &HookGroupsContract,
    entries: &[PyVal],
    matchers: &[Option<&str>],
    handler: &PyVal,
) -> Step<Vec<PyVal>> {
    let wire: Vec<Value> = entries.iter().map(lenient).collect();
    let Value::Object(guard) = lenient(handler) else {
        return Err(Failure::Invalid);
    };
    let mut steps = plan::prune(contract, &wire).map_err(unhashable)?;
    for matcher in matchers {
        let matcher = matcher.map_or(Value::Null, Value::from);
        steps = plan::merge(&wire, steps, Some(&matcher), &guard);
    }
    apply(entries, &steps, Some(handler))
}

/// The SessionStart refresh and every runtime group, then the unsupported
/// events dropped: what install and the SessionStart refresh both write.
pub(super) fn sync(
    contract: &HookGroupsContract,
    hooks: &mut Doc,
    session_argv: &[String],
    daemon_argv: &[String],
) -> Step<()> {
    let session = handler(session_argv, contract.session_start_timeout_seconds, None)?;
    let matchers: Vec<Option<&str>> = contract
        .session_start_matchers
        .iter()
        .map(|matcher| Some(matcher.as_str()))
        .collect();
    let event = contract.session_start_event.as_str();
    let entries = merged(contract, &entry_list(hooks, event), &matchers, &session)?;
    hooks.set(event, PyVal::List(entries));
    // Every job reads the hooks as they stood before any group was written.
    let mut results = Vec::with_capacity(contract.runtime_groups.len());
    for group in &contract.runtime_groups {
        let guard = handler(
            daemon_argv,
            group.timeout_seconds,
            group.status_message.as_deref(),
        )?;
        let entries = entry_list(hooks, &group.event);
        let matchers = [group.matcher.as_deref()];
        results.push(merged(contract, &entries, &matchers, &guard)?);
    }
    for (group, entries) in contract.runtime_groups.iter().zip(results) {
        hooks.set(&group.event, PyVal::List(entries));
    }
    remove_unsupported(contract, hooks)
}

/// `remove_unsupported_guard_hook_groups`: prune the contract's retired
/// events and drop the ones left empty.
pub(super) fn remove_unsupported(contract: &HookGroupsContract, hooks: &mut Doc) -> Step<()> {
    let mut events: Vec<&str> = Vec::new();
    for event in &contract.pruned_events {
        let listed = matches!(
            hooks.0.iter().find(|(key, _)| key == event),
            Some((_, PyVal::List(_)))
        );
        if listed && !events.contains(&event.as_str()) {
            events.push(event);
        }
    }
    let mut results = Vec::with_capacity(events.len());
    for event in &events {
        results.push(pruned(contract, &entry_list(hooks, event))?);
    }
    for (event, remaining) in events.into_iter().zip(results) {
        if remaining.is_empty() {
            hooks.0.retain(|(key, _)| key != event);
        } else {
            hooks.set(event, PyVal::List(remaining));
        }
    }
    Ok(())
}

/// `prune_guard_hook_events`: every named event is written, pruned.
pub(super) fn prune_events(
    contract: &HookGroupsContract,
    hooks: &mut Doc,
    events: &[&str],
) -> Step<()> {
    let mut results = Vec::with_capacity(events.len());
    for event in events {
        results.push(pruned(contract, &entry_list(hooks, event))?);
    }
    for (event, entries) in events.iter().zip(results) {
        hooks.set(event, PyVal::List(entries));
    }
    Ok(())
}
