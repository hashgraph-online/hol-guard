//! Guard's entries in Cursor's `hooks.json`: the managed hook commands, the
//! merge that installs them beside other tools' hooks and the hook script
//! source.

use std::path::Path;

use serde_json::{json, Map, Value};

use super::cursor::{
    self, get, malformed, runtime, wire, Ask, Attestation, Facts, BLOCKING, EVENTS,
};
use super::cursor_files::live_script;
use super::files::{self, Doc};
use super::{path_text, Failure, Step};
use crate::pyjson::PyVal;

const TIMEOUT_SECONDS: &str = "45";
const MUTATION_MATCHER: &str = "^(Write|Edit|StrReplace|MultiEdit|Delete)$";
const SHELL_ROUTE_MATCHER: &str = "^(Write|Edit|StrReplace|MultiEdit|Delete|Shell)$";
const SCRIPT_MALFORMED: &str = "Cursor hook script answer is malformed";

/// Each managed event's hook entry; a command Windows cannot render fails
/// only its own event.
pub(super) fn entries(
    ask: &Ask,
    facts: &Facts,
    attestation: &Attestation,
) -> Step<Vec<(&'static str, Step<PyVal>)>> {
    facts.require_bridge()?;
    let ctx = ask.ctx;
    let script = path_text(&ctx.resolved(&cursor::script_path(ctx)));
    let mut prefix = Vec::new();
    if let Some(bridge) = &facts.bridge {
        prefix.extend([bridge.clone(), "cursor-hook-bridge".to_owned()]);
    }
    let interpreter = attestation
        .python
        .as_ref()
        .map(|python| python.executable.clone())
        .or_else(|| facts.interpreter.clone())
        .unwrap_or_default();
    let argvs: Vec<Vec<String>> = EVENTS
        .iter()
        .map(|event| {
            let mut argv = prefix.clone();
            if interpreter.is_empty() && facts.frozen {
                argv.push(facts.frozen_launcher.clone().unwrap_or_default());
                argv.push("__guard-cursor-hook".into());
            } else if interpreter.is_empty() {
                argv.extend([facts.executable.clone(), "-I".into()]);
            } else {
                argv.extend([interpreter.clone(), "-I".into()]);
            }
            argv.extend([
                script.clone(),
                "--cursor-hook-event".into(),
                (*event).into(),
            ]);
            argv
        })
        .collect();
    let commands = ask.render(&argvs)?;
    Ok(EVENTS
        .iter()
        .zip(commands)
        .map(|(event, command)| (*event, command.map(|command| entry(ask, event, command))))
        .collect())
}

fn entry(ask: &Ask, event: &str, command: String) -> PyVal {
    let mut doc = Doc::default();
    doc.set("command", PyVal::Str(command))
        .set("timeout", PyVal::Int(TIMEOUT_SECONDS.into()))
        .set("failClosed", PyVal::Bool(BLOCKING.contains(&event)));
    if event == "preToolUse" {
        let matcher = if ask.ctx.windows {
            MUTATION_MATCHER
        } else {
            SHELL_ROUTE_MATCHER
        };
        doc.set("matcher", files::text(matcher));
    }
    doc.value()
}

/// Every managed entry, or the first render failure.
pub(super) fn all_entries(
    ask: &Ask,
    facts: &Facts,
    attestation: &Attestation,
) -> Step<Vec<(&'static str, PyVal)>> {
    entries(ask, facts, attestation)?
        .into_iter()
        .map(|(event, entry)| Ok((event, entry?)))
        .collect()
}

/// `[[name, entries], ...]` in the caller's order.
pub(super) fn pairs(hooks: &[(String, PyVal)]) -> Step<Value> {
    hooks
        .iter()
        .map(|(name, value)| Ok(json!([name, wire(value)?])))
        .collect::<Step<Vec<_>>>()
        .map(Value::Array)
}

pub(super) fn index(value: &Value, size: usize) -> Step<usize> {
    match value.as_u64() {
        Some(index) if (index as usize) < size && !value.is_boolean() => Ok(index as usize),
        _ => Err(malformed()),
    }
}

fn integer(value: &Value) -> Step<PyVal> {
    let text = value
        .as_number()
        .map(ToString::to_string)
        .filter(|text| {
            let digits = text.strip_prefix('-').unwrap_or(text);
            !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
        })
        .ok_or_else(malformed)?;
    Ok(PyVal::Int(text))
}

/// `_managed_hooks_payload`: the normalized config with Guard's entries
/// merged into each managed event.
pub(super) fn merge(
    ask: &Ask,
    payload: &[(String, PyVal)],
    managed: &[(&'static str, PyVal)],
    script: &str,
) -> Step<PyVal> {
    let nested = match get(payload, "hooks") {
        Some(PyVal::Dict(nested)) => Some(nested.as_slice()),
        _ => None,
    };
    let source = nested.unwrap_or(payload);
    let keys = |entries: &[(String, PyVal)]| -> Vec<String> {
        entries.iter().map(|(key, _)| key.clone()).collect()
    };
    let commands: Vec<Value> = managed
        .iter()
        .map(|(event, entry)| {
            let command = entry.get("command").and_then(PyVal::as_str).unwrap_or("");
            json!([event, command])
        })
        .collect();
    let mut request = Map::new();
    request.insert("payload".into(), wire(&PyVal::Dict(payload.to_vec()))?);
    request.insert("top_keys".into(), json!(keys(payload)));
    request.insert("hooks_keys".into(), json!(nested.map(keys)));
    request.insert("managed".into(), json!(commands));
    request.insert("script".into(), json!(script));
    let answer = ask.hook_config("install", request)?;
    if let Some(error) = answer.get("error").and_then(Value::as_str) {
        return Err(runtime(error));
    }
    let version = integer(&answer["version"])?;
    let specs = answer["hooks"].as_array().ok_or_else(malformed)?;
    let mut hooks: Vec<(String, PyVal)> = Vec::new();
    for spec in specs {
        let [Value::String(event), kept, Value::Bool(guard)] =
            spec.as_array().map(Vec::as_slice).ok_or_else(malformed)?
        else {
            return Err(malformed());
        };
        if hooks.iter().any(|(name, _)| name == event) {
            return Err(malformed());
        }
        let current = get(source, event);
        if kept.is_null() {
            if *guard || current.is_none() || matches!(current, Some(PyVal::List(_))) {
                return Err(malformed());
            }
            hooks.push((event.clone(), current.cloned().unwrap_or(PyVal::Null)));
            continue;
        }
        let existing = match current {
            Some(PyVal::List(items)) => items.as_slice(),
            _ => &[],
        };
        let guard_entry = managed.iter().find(|(name, _)| name == event);
        let kept = kept.as_array().ok_or_else(malformed)?;
        if *guard && guard_entry.is_none() {
            return Err(malformed());
        }
        let mut merged = kept
            .iter()
            .map(|position| Ok(existing[index(position, existing.len())?].clone()))
            .collect::<Step<Vec<_>>>()?;
        if let (true, Some((_, entry))) = (*guard, guard_entry) {
            merged.push(entry.clone());
        }
        hooks.push((event.clone(), PyVal::List(merged)));
    }
    let mut doc = Doc::default();
    doc.set("version", version).set("hooks", PyVal::Dict(hooks));
    Ok(doc.value())
}

/// One `cursor_hook_script` answer: the single field asked for.
fn script_kind(request: Value, field: &str) -> Step<Value> {
    let answer = crate::cursor_hook_script::dispatch(&request)
        .map_err(|error| runtime(format!("Cursor hook script request failed: {error}")))?;
    let mut answer = match answer {
        Value::Object(answer) if answer.len() == 1 => answer,
        _ => return Err(runtime(SCRIPT_MALFORMED)),
    };
    answer
        .remove(field)
        .ok_or_else(|| runtime(SCRIPT_MALFORMED))
}

/// `cursor_hook_script_source`: the hook script this Guard would install.
pub(super) fn script_source(ask: &Ask, facts: &Facts, attestation: &Attestation) -> Step<String> {
    let ctx = ask.ctx;
    let recovery = match &attestation.python {
        Some(python) => script_kind(
            json!({
                "op": "recovery",
                "python": python.target,
                "import_roots": python.import_roots,
                "guard_home": path_text(&ctx.resolved(&ctx.guard_home)),
                "home": path_text(&ctx.resolved(&ctx.home)),
            }),
            "command",
        )?,
        None => json!(facts.frozen_recovery.clone().ok_or(Failure::Invalid)?),
    };
    if !recovery
        .as_array()
        .is_some_and(|items| items.iter().all(Value::is_string))
    {
        return Err(runtime(SCRIPT_MALFORMED));
    }
    let home = (!ctx.default_home()).then(|| path_text(&ctx.home));
    let source = script_kind(
        json!({
            "op": "render",
            "guard_home": path_text(&ctx.guard_home),
            "guard_home_resolved": path_text(&ctx.resolved(&ctx.guard_home)),
            "home": home,
            "guard_cli": attestation.command,
            "recovery_command": recovery,
        }),
        "source",
    )?;
    source
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| runtime(SCRIPT_MALFORMED))
}

/// Which entries of one event list are Guard's.
pub(super) fn entry_flags(ask: &Ask, items: &[PyVal], command: &str) -> Step<Vec<bool>> {
    let mut request = Map::new();
    request.insert("entries".into(), wire(&PyVal::List(items.to_vec()))?);
    request.insert("command".into(), json!(command));
    let answer = ask.hook_config("entries", request)?;
    let flags = answer["managed"].as_array().ok_or_else(malformed)?;
    if flags.len() != items.len() {
        return Err(malformed());
    }
    flags
        .iter()
        .map(|flag| flag.as_bool().ok_or_else(malformed))
        .collect()
}

/// `_render_without_managed_hook_entries`: the config without Guard's
/// entries, `None` when nothing else remains, and whether any were found.
pub(super) fn without_managed(
    ask: &Ask,
    payload: &PyVal,
    script: &str,
) -> Step<(Option<PyVal>, bool)> {
    let PyVal::Dict(top) = payload else {
        return Ok((None, false));
    };
    let Some(PyVal::Dict(hooks)) = get(top, "hooks") else {
        return Ok((Some(payload.clone()), false));
    };
    let (mut cleaned, mut managed, mut others) = (Vec::new(), false, false);
    for (event, value) in hooks {
        let PyVal::List(items) = value else {
            cleaned.push((event.clone(), value.clone()));
            others = true;
            continue;
        };
        let flags = entry_flags(ask, items, script)?;
        managed |= flags.iter().any(|flag| *flag);
        let kept: Vec<PyVal> = items
            .iter()
            .zip(flags)
            .filter(|(_, flag)| !flag)
            .map(|(item, _)| item.clone())
            .collect();
        if !kept.is_empty() {
            cleaned.push((event.clone(), PyVal::List(kept)));
            others = true;
        }
    }
    if !managed {
        return Ok((Some(payload.clone()), false));
    }
    if !others {
        return Ok((None, true));
    }
    let mut doc = Doc(top.clone());
    doc.set("hooks", PyVal::Dict(cleaned));
    Ok((Some(doc.value()), true))
}

/// Live Guard commands and whether each boots the frozen control plane.
pub(super) fn live_commands(ask: &Ask, hooks: &[(String, PyVal)]) -> Step<Vec<(String, bool)>> {
    let mut request = Map::new();
    request.insert("hooks".into(), pairs(hooks)?);
    let answer = ask.hook_config("commands", request)?;
    let mut commands = Vec::new();
    for item in answer["commands"].as_array().ok_or_else(malformed)? {
        let fields = item.as_object().filter(|fields| fields.len() == 3);
        let (Some(Value::String(command)), Some(Value::Bool(frozen)), Some(Value::String(script))) = (
            fields.and_then(|fields| fields.get("command")),
            fields.and_then(|fields| fields.get("frozen")),
            fields.and_then(|fields| fields.get("script")),
        ) else {
            return Err(malformed());
        };
        if live_script(ask.ctx, Path::new(script)) {
            commands.push((command.clone(), *frozen));
        }
    }
    Ok(commands)
}
