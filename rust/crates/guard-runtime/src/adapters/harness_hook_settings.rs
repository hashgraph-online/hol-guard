//! `runner_authority` kind `harness_hook_settings`: the `hooks` rewrite the
//! Muse and Devin adapters apply to their user settings on install and
//! uninstall.
//!
//! Python keeps the file I/O, the JSON and JSONC parse, the launcher shim, the
//! bridge command and Muse's bridge deadline. This kind validates the `hooks`
//! value, prunes the handlers Guard owns (the per-harness
//! `is_guard_managed_hook_command` predicate), computes each managed group's
//! timeout and merges Guard's handler back in. serde_json does not keep
//! object order, so every answer names events in their final order and lists
//! by index into the caller's own values; user JSON is never rebuilt here.
//!
//! A list plan is an array of steps: an index keeps that entry,
//! `{"entry": i, "hooks": [j | null]}` copies entry `i` with those of its own
//! handlers (`null` is Guard's handler) and `{"matcher": m | null}` adds a new
//! group holding only Guard's handler.

use serde_json::{json, Map, Value};

use super::codex_hook_bridge::MAX_APPROVAL_WAIT_SECONDS;
use super::guard_store_json::py_strip;
use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};
use super::{devin_detect, muse_detect};

const ERR_NOT_OBJECT: &str = "harness_hook_settings_hooks_not_object";
const ERR_NOT_LIST: &str = "harness_hook_settings_event_not_list";
const GRACE_SECONDS: i64 = 5;
/// Events that never wait for an approval only outlast the bridge client's
/// own 25-second floor.
const SHORT_TIMEOUT_SECONDS: i64 = 30;
const MUSE_STATUS: &str = "HOL Guard is checking this action";
/// Every Devin tool that carries something for Guard to review; Devin's
/// interactive shell helpers carry no new command and are left out.
const DEVIN_TOOLS: &str =
    "^(exec|read|write|edit|apply_patch|notebook_read|notebook_edit|grep|glob|webfetch|mcp_call_tool|mcp__.*)$";

#[derive(Clone, Copy)]
enum Harness {
    Muse,
    Devin,
}

/// One Guard-managed hook group.
struct Group {
    event: &'static str,
    matcher: Option<&'static str>,
    timeout: i64,
    status: Option<&'static str>,
}

impl Harness {
    fn parse(value: Option<&Value>) -> Result<Self, &'static str> {
        match value.and_then(Value::as_str) {
            Some("muse") => Ok(Self::Muse),
            Some("devin") => Ok(Self::Devin),
            _ => Err(ERR_INVALID),
        }
    }

    fn timing_key(self) -> &'static str {
        match self {
            Self::Muse => "bridge_seconds",
            Self::Devin => "wait_seconds",
        }
    }

    /// `is_guard_managed_hook_command`: only a string command can be Guard's.
    fn owns(self, command: Option<&Value>) -> bool {
        command
            .and_then(Value::as_str)
            .is_some_and(|command| match self {
                Self::Muse => muse_detect::guard_managed(command),
                Self::Devin => devin_detect::guard_managed(command),
            })
    }

    fn owns_handler(self, handler: &Value) -> bool {
        handler
            .as_object()
            .is_some_and(|handler| self.owns(handler.get("command")))
    }

    /// The managed groups in install order. Muse's long timeout outlasts the
    /// bridge deadline Python computed; Devin's outlasts the clamped approval
    /// wait. Muse's groups name no matcher, which Muse reads as every tool:
    /// naming a subset would exempt the rest from review.
    fn groups(self, timing: i64) -> Result<Vec<Group>, &'static str> {
        let group = |event: &'static str, matcher: Option<&'static str>, timeout: i64| Group {
            event,
            matcher,
            timeout,
            status: matches!(self, Self::Muse).then_some(MUSE_STATUS),
        };
        Ok(match self {
            Self::Muse => {
                let long = timing.checked_add(GRACE_SECONDS).ok_or(ERR_INVALID)?;
                vec![
                    group("PreToolUse", None, long),
                    group("PermissionRequest", None, SHORT_TIMEOUT_SECONDS),
                    group("UserPromptSubmit", None, SHORT_TIMEOUT_SECONDS),
                    group("PostToolUse", None, long),
                    group("SessionStart", None, SHORT_TIMEOUT_SECONDS),
                    group("Stop", None, SHORT_TIMEOUT_SECONDS),
                ]
            }
            Self::Devin => {
                let long = timing.clamp(0, MAX_APPROVAL_WAIT_SECONDS) + GRACE_SECONDS;
                let tools = Some(DEVIN_TOOLS);
                vec![
                    group("PreToolUse", tools, long),
                    group("PermissionRequest", tools, SHORT_TIMEOUT_SECONDS),
                    group("UserPromptSubmit", None, SHORT_TIMEOUT_SECONDS),
                    group("PostToolUse", tools, long),
                ]
            }
        })
    }
}

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let map = args_object(args)?;
    let harness = Harness::parse(map.get("harness"))?;
    let op = map.get("op").and_then(Value::as_str).ok_or(ERR_INVALID)?;
    let keys: &[&str] = match (op, harness) {
        ("install", Harness::Muse) => &["hooks", "hooks_keys", "bridge_seconds"],
        ("install", Harness::Devin) => &["hooks", "hooks_keys", "wait_seconds"],
        ("prune", _) => &["hooks", "hooks_keys"],
        ("managed", _) => &["commands"],
        _ => return Err(ERR_INVALID),
    };
    if map.len() != keys.len() + 2 || !keys.iter().all(|key| map.contains_key(*key)) {
        return Err(ERR_INVALID);
    }
    match op {
        "install" => install(harness, map),
        "prune" => {
            let hooks = map["hooks"].as_object().ok_or(ERR_INVALID)?;
            let keys = ordered_keys(hooks, &map["hooks_keys"])?;
            Ok(json!({ "hooks": prune_events(harness, hooks, &keys) }))
        }
        _ => {
            let commands = map["commands"].as_array().ok_or(ERR_INVALID)?;
            let managed: Vec<bool> = commands
                .iter()
                .map(|command| harness.owns(Some(command)))
                .collect();
            Ok(json!({ "managed": managed }))
        }
    }
}

/// The caller's key order for `hooks`: distinct strings naming exactly its keys.
fn ordered_keys<'a>(
    hooks: &Map<String, Value>,
    keys: &'a Value,
) -> Result<Vec<&'a str>, &'static str> {
    let keys = keys
        .as_array()
        .ok_or(ERR_INVALID)?
        .iter()
        .map(|key| key.as_str().ok_or(ERR_INVALID))
        .collect::<Result<Vec<_>, _>>()?;
    let distinct: std::collections::BTreeSet<&str> = keys.iter().copied().collect();
    if distinct.len() != keys.len()
        || keys.len() != hooks.len()
        || !keys.iter().all(|key| hooks.contains_key(*key))
    {
        return Err(ERR_INVALID);
    }
    Ok(keys)
}

enum Step {
    Keep(usize),
    Copy(usize, Vec<Option<usize>>),
    Group(Option<String>),
}

impl Step {
    /// The caller's entry this step keeps or copies.
    fn entry(&self) -> Option<usize> {
        match self {
            Self::Keep(index) | Self::Copy(index, _) => Some(*index),
            Self::Group(_) => None,
        }
    }
}

fn plan_json(steps: &[Step]) -> Value {
    let steps: Vec<Value> = steps
        .iter()
        .map(|step| match step {
            Step::Keep(index) => json!(index),
            Step::Copy(index, hooks) => json!({ "entry": index, "hooks": hooks }),
            Step::Group(matcher) => json!({ "matcher": matcher }),
        })
        .collect();
    Value::Array(steps)
}

/// `prune_managed_hook_entries`: drop entries whose own `command` is Guard's
/// and Guard's nested handlers, and every group the prune leaves empty.
/// Non-object entries and entries without a `hooks` list are kept.
fn prune(harness: Harness, entries: &[Value]) -> Vec<Step> {
    let mut steps = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let Some(object) = entry.as_object() else {
            steps.push(Step::Keep(index));
            continue;
        };
        if harness.owns(object.get("command")) {
            continue;
        }
        let Some(hooks) = object.get("hooks").and_then(Value::as_array) else {
            steps.push(Step::Keep(index));
            continue;
        };
        let kept: Vec<Option<usize>> = (0..hooks.len())
            .filter(|position| !harness.owns_handler(&hooks[*position]))
            .map(Some)
            .collect();
        if kept.is_empty() {
            continue;
        }
        steps.push(if kept.len() == hooks.len() {
            Step::Keep(index)
        } else {
            Step::Copy(index, kept)
        });
    }
    steps
}

/// A matcher's key: its stripped text, or none when absent, blank or not text.
fn matcher_key(matcher: Option<&Value>) -> Option<&str> {
    matcher
        .and_then(Value::as_str)
        .map(py_strip)
        .filter(|matcher| !matcher.is_empty())
}

/// `merge_hook_entry` over a pruned plan: Guard's handler joins the first
/// object group under the same matcher key, else a new group. The prune left
/// no Guard handler to replace; a `hooks` value that is not a list counts as
/// empty.
fn merge(entries: &[Value], mut steps: Vec<Step>, matcher: Option<&str>) -> Vec<Step> {
    let key = matcher.map(py_strip).filter(|matcher| !matcher.is_empty());
    let target = steps.iter().position(|step| {
        step.entry().is_some_and(|index| {
            entries[index]
                .as_object()
                .is_some_and(|object| matcher_key(object.get("matcher")) == key)
        })
    });
    let Some(position) = target else {
        steps.push(Step::Group(key.map(str::to_owned)));
        return steps;
    };
    let (index, mut items) = match &steps[position] {
        Step::Copy(index, items) => (*index, items.clone()),
        step => {
            let index = step.entry().unwrap_or_default();
            let own = entries[index].get("hooks").and_then(Value::as_array);
            (index, (0..own.map_or(0, Vec::len)).map(Some).collect())
        }
    };
    items.push(None);
    steps[position] = Step::Copy(index, items);
    steps
}

/// Every event in the caller's order: a list is pruned and dropped once
/// empty; any other value is kept as it is (`None`).
fn pruned_events<'a>(
    harness: Harness,
    hooks: &Map<String, Value>,
    keys: &[&'a str],
) -> Vec<(&'a str, Option<Vec<Step>>)> {
    keys.iter()
        .filter_map(|key| match hooks[*key].as_array() {
            Some(entries) => {
                let steps = prune(harness, entries);
                (!steps.is_empty()).then_some((*key, Some(steps)))
            }
            None => Some((*key, None)),
        })
        .collect()
}

/// The uninstall prune: `[[event, plan | null], ...]`.
fn prune_events(harness: Harness, hooks: &Map<String, Value>, keys: &[&str]) -> Value {
    let events: Vec<Value> = pruned_events(harness, hooks, keys)
        .into_iter()
        .map(|(event, steps)| json!([event, steps.as_deref().map(plan_json)]))
        .collect();
    Value::Array(events)
}

/// The install rewrite: `[[event, plan | null, guard | null], ...]`, where
/// `guard` names the timeout and status message of Guard's handler.
fn install(harness: Harness, map: &Map<String, Value>) -> KindResult {
    let timing = &map[harness.timing_key()];
    let timing = timing
        .as_i64()
        .or_else(|| timing.as_u64().map(|_| i64::MAX))
        .ok_or(ERR_INVALID)?;
    let groups = harness.groups(timing)?;
    let empty = Map::new();
    let (hooks, keys) = match &map["hooks"] {
        Value::Null if map["hooks_keys"].is_null() => (&empty, Vec::new()),
        Value::Object(hooks) => (hooks, ordered_keys(hooks, &map["hooks_keys"])?),
        _ if map["hooks_keys"].is_null() => {
            return Ok(json!({ "error": ERR_NOT_OBJECT, "event": null }))
        }
        _ => return Err(ERR_INVALID),
    };
    if matches!(harness, Harness::Muse) {
        if let Some(event) = keys
            .iter()
            .find(|key| !matches!(hooks[**key], Value::Null | Value::Array(_)))
        {
            return Ok(json!({ "error": ERR_NOT_LIST, "event": event }));
        }
    }
    let mut events: Vec<(&str, Option<Vec<Step>>, Option<&Group>)> =
        pruned_events(harness, hooks, &keys)
            .into_iter()
            .map(|(event, steps)| (event, steps, None))
            .collect();
    for group in &groups {
        let entries = hooks
            .get(group.event)
            .and_then(Value::as_array)
            .map_or(&[][..], Vec::as_slice);
        match events.iter().position(|(event, ..)| *event == group.event) {
            Some(position) => {
                let (_, steps, guard) = &mut events[position];
                let pruned = steps.take().unwrap_or_default();
                *steps = Some(merge(entries, pruned, group.matcher));
                *guard = Some(group);
            }
            None => events.push((
                group.event,
                Some(merge(entries, Vec::new(), group.matcher)),
                Some(group),
            )),
        }
    }
    let events: Vec<Value> = events
        .into_iter()
        .map(|(event, steps, guard)| {
            let guard =
                guard.map(|group| json!({ "timeout": group.timeout, "status": group.status }));
            json!([event, steps.as_deref().map(plan_json), guard])
        })
        .collect();
    Ok(json!({ "hooks": events }))
}
