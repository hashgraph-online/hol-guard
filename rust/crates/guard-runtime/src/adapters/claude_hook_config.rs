//! `runner_authority` kind `claude_hook_config`: which Claude Code hook
//! handlers Guard owns, and the prune and merge that install Guard's handlers
//! into `settings.json`.
//!
//! Python keeps the contract constants, the file I/O, the handler rendering
//! and the diagnostics text. Every op is lexical over the JSON it is given and
//! reads Guard's markers from the compiled hook-groups contract. serde_json
//! does not keep object order, so list answers name entries by index into the
//! caller's own lists (see `claude_hook_plan`) and user JSON is never rebuilt.
//!
//! A handler `type` Python could not hash (a list or an object) answers
//! `{"error": "claude_hook_handler_type_unhashable"}` for the whole request,
//! where the Python helpers raised `TypeError`.

use std::collections::BTreeSet;

use serde_json::{json, Map, Value};

use super::claude_hook_plan::{self as plan, Unhashable, ERR_UNHASHABLE};
use super::claude_session_start_contract::{
    contract, handler_argv, is_guard_command, is_guard_handler, is_guard_url, HookGroupsContract,
};
use super::guard_store_json::py_strip;
use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};

const ERR_CONTRACT: &str = "claude_hook_contract_invalid";

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let map = args_object(args)?;
    let op = map.get("op").and_then(Value::as_str).ok_or(ERR_INVALID)?;
    let keys: &[&str] = match op {
        "text" => &["value"],
        "handler" => &["handler"],
        "prune" => &["lists"],
        "merge" => &["jobs"],
        "missing" => &["payload", "events", "matcher"],
        _ => return Err(ERR_INVALID),
    };
    if map.len() != keys.len() + 1 || !keys.iter().all(|key| map.contains_key(*key)) {
        return Err(ERR_INVALID);
    }
    let contract = contract().map_err(|_| ERR_CONTRACT)?;
    let answer = match op {
        "text" => Ok(text(&contract, &map["value"])),
        "handler" => Ok(handler(&contract, &map["handler"])),
        "prune" => prune(&contract, &lists(&map["lists"])?),
        "merge" => merge(&contract, &jobs(&map["jobs"])?),
        _ => {
            let payload = map["payload"].as_object().ok_or(ERR_INVALID)?;
            let events = array(&map["events"])?
                .iter()
                .map(|event| event.as_str().ok_or(ERR_INVALID))
                .collect::<Result<Vec<_>, _>>()?;
            let required = matcher_parts(map["matcher"].as_str().ok_or(ERR_INVALID)?);
            missing(&contract, payload, &events, &required)
        }
    };
    Ok(answer.unwrap_or_else(|Unhashable| json!({ "error": ERR_UNHASHABLE })))
}

type Answer = Result<Value, Unhashable>;

fn array(value: &Value) -> Result<&Vec<Value>, &'static str> {
    value.as_array().ok_or(ERR_INVALID)
}

/// `is_guard_hook_command` and `is_guard_hook_url` of one value.
fn text(contract: &HookGroupsContract, value: &Value) -> Value {
    let text = value.as_str();
    json!({
        "command": text.is_some_and(|text| is_guard_command(contract, text)),
        "url": text.is_some_and(is_guard_url),
    })
}

/// `is_guard_hook_handler` (`null` where it raised), `command_handler_argv`
/// and `handler_identity` of one handler.
fn handler(contract: &HookGroupsContract, handler: &Value) -> Value {
    let object = handler.as_object();
    json!({
        "guard": is_guard_handler(contract, handler).ok(),
        "argv": object.and_then(handler_argv),
        "identity": object.map(plan::identity),
    })
}

/// Every list of a prune request, checked before any is pruned.
fn lists(value: &Value) -> Result<Vec<&Vec<Value>>, &'static str> {
    array(value)?.iter().map(array).collect()
}

/// `prune_guard_hook_entries` of each list.
fn prune(contract: &HookGroupsContract, lists: &[&Vec<Value>]) -> Answer {
    let mut plans = Vec::with_capacity(lists.len());
    for entries in lists {
        plans.push(plan::plan_json(&plan::prune(contract, entries)?));
    }
    Ok(json!({ "lists": plans }))
}

/// One merge job: optionally prune `entries`, then `merge_hook_group` once
/// per matcher with the same handler.
struct Job<'a> {
    entries: &'a [Value],
    prune: bool,
    matchers: &'a [Value],
    handler: &'a Map<String, Value>,
}

/// Every job of a merge request, checked before any is merged.
fn jobs(value: &Value) -> Result<Vec<Job<'_>>, &'static str> {
    array(value)?.iter().map(job).collect()
}

fn job(value: &Value) -> Result<Job<'_>, &'static str> {
    let map = value.as_object().ok_or(ERR_INVALID)?;
    let field = |key: &str| map.get(key).ok_or(ERR_INVALID);
    let job = Job {
        entries: array(field("entries")?)?,
        prune: field("prune")?.as_bool().ok_or(ERR_INVALID)?,
        matchers: array(field("matchers")?)?,
        handler: field("handler")?.as_object().ok_or(ERR_INVALID)?,
    };
    if map.len() != 4 {
        return Err(ERR_INVALID);
    }
    Ok(job)
}

fn merge(contract: &HookGroupsContract, jobs: &[Job<'_>]) -> Answer {
    let mut plans = Vec::with_capacity(jobs.len());
    for job in jobs {
        let mut entries = if job.prune {
            plan::prune(contract, job.entries)?
        } else {
            plan::kept(job.entries)
        };
        for matcher in job.matchers {
            entries = plan::merge(job.entries, entries, Some(matcher), job.handler);
        }
        plans.push(plan::plan_json(&entries));
    }
    Ok(json!({ "jobs": plans }))
}

/// `missing_guard_hook_events` for these required events and tool matcher.
fn missing(
    contract: &HookGroupsContract,
    payload: &Map<String, Value>,
    events: &[&str],
    required: &BTreeSet<&str>,
) -> Answer {
    let hooks = payload.get("hooks").and_then(Value::as_object);
    let mut missing = Vec::new();
    for event in events {
        let entries = hooks
            .and_then(|hooks| hooks.get(*event))
            .and_then(Value::as_array);
        let mut covered = false;
        for entry in entries.into_iter().flatten() {
            if covers(contract, entry, required)? {
                covered = true;
                break;
            }
        }
        if !covered {
            missing.push(*event);
        }
    }
    Ok(json!({ "missing": missing }))
}

/// `missing_guard_hook_events` of a settings object: the required events
/// whose Guard handler does not cover the PreToolUse group's tools.
pub(crate) fn missing_events(
    contract: &HookGroupsContract,
    payload: &Map<String, Value>,
) -> Result<Vec<String>, Unhashable> {
    let matcher = contract
        .runtime_groups
        .iter()
        .find(|group| group.event == "PreToolUse")
        .and_then(|group| group.matcher.as_deref())
        .unwrap_or_default();
    let events = ["PreToolUse", "PermissionRequest"];
    let answer = missing(contract, payload, &events, &matcher_parts(matcher))?;
    Ok(answer["missing"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect())
}

/// The stripped, non-empty `|` parts of a matcher.
fn matcher_parts(matcher: &str) -> BTreeSet<&str> {
    matcher
        .split('|')
        .map(py_strip)
        .filter(|part| !part.is_empty())
        .collect()
}

/// `_entry_covers_guard_tools`: a Guard handler (the entry itself or one of
/// its `hooks`) under a matcher that is omitted or names every required tool.
fn covers(
    contract: &HookGroupsContract,
    entry: &Value,
    required: &BTreeSet<&str>,
) -> Result<bool, Unhashable> {
    let Some(object) = entry.as_object() else {
        return Ok(false);
    };
    let guard = |handler: &Value| is_guard_handler(contract, handler).map_err(|()| Unhashable);
    let mut has_guard = guard(entry)?;
    if !has_guard {
        for handler in object
            .get("hooks")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if guard(handler)? {
                has_guard = true;
                break;
            }
        }
    }
    if !has_guard {
        return Ok(false);
    }
    Ok(match object.get("matcher") {
        None | Some(Value::Null) => true,
        Some(Value::String(matcher)) => required.is_subset(&matcher_parts(matcher)),
        Some(_) => false,
    })
}
