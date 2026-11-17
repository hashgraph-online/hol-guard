//! Whether Guard's Cursor hooks protect Cursor: the registered entries, the
//! hook scripts and the attested Guard CLI they run.

use std::fs;
use std::path::Path;

use serde_json::{json, Map, Value};

use super::cursor::{self, get, malformed, wire, Ask, BLOCKING, BRIDGE_UNAVAILABLE};
use super::cursor_files::{self, live_script};
use super::cursor_hooks::{entries, index, pairs, script_source};
use super::files::{self, Doc};
use super::{Failure, Step};
use crate::pyjson::PyVal;

const MUTATION_TOOLS: [&str; 5] = ["Write", "Edit", "StrReplace", "MultiEdit", "Delete"];

/// A preToolUse entry fails closed and its matcher selects every file
/// mutation tool.
fn guards_mutations(entry: &[(String, PyVal)]) -> bool {
    if !matches!(get(entry, "failClosed"), Some(PyVal::Bool(true))) {
        return false;
    }
    let matcher = match get(entry, "matcher") {
        None | Some(PyVal::Null) => return true,
        Some(PyVal::Str(matcher)) if matcher.is_empty() || matcher == "*" => return true,
        Some(PyVal::Str(matcher)) => matcher,
        Some(_) => return false,
    };
    let Ok(pattern) = fancy_regex::Regex::new(matcher) else {
        return false;
    };
    MUTATION_TOOLS
        .iter()
        .all(|tool| pattern.is_match(tool).unwrap_or(false))
}

/// `cursor_runtime_hooks_verified`: whether the live config still routes
/// every blocking event through a live Guard script; `None` when unreadable.
pub(super) fn health(ask: &Ask) -> Step<Option<bool>> {
    let path = ask.ctx.absolute(&cursor::hooks_path(ask.ctx));
    if !path.is_file() {
        return Ok(None);
    }
    let Some(payload) = fs::read_to_string(&path)
        .ok()
        .and_then(|text| cursor::parse_object(&text))
    else {
        return Ok(None);
    };
    let Some(PyVal::Dict(hooks)) = get(&payload, "hooks") else {
        return Ok(Some(false));
    };
    let mut request = Map::new();
    request.insert("hooks".into(), pairs(hooks)?);
    let answer = ask.hook_config("intercept", request)?;
    let events = match &answer["events"] {
        Value::Null => return Ok(Some(false)),
        Value::Array(events) if events.len() == BLOCKING.len() => events,
        _ => return Err(malformed()),
    };
    for (event, routed) in BLOCKING.iter().zip(events) {
        let (Some(PyVal::List(items)), Some([name, Value::Array(candidates)])) =
            (get(hooks, event), routed.as_array().map(Vec::as_slice))
        else {
            return Err(malformed());
        };
        if name != event {
            return Err(malformed());
        }
        let mut intercepts = false;
        for candidate in candidates {
            let Some([position, Value::String(script)]) = candidate.as_array().map(Vec::as_slice)
            else {
                return Err(malformed());
            };
            let PyVal::Dict(entry) = &items[index(position, items.len())?] else {
                continue;
            };
            if live_script(ask.ctx, Path::new(script))
                && (*event != "preToolUse" || guards_mutations(entry))
            {
                intercepts = true;
                break;
            }
        }
        if !intercepts {
            return Ok(Some(false));
        }
    }
    Ok(Some(true))
}

/// `_read_script`: a link to a file reads as tampered, anything else that
/// is not a regular file as missing.
fn read_script(ctx: &super::Ctx, path: &Path, label: &str) -> Step<Value> {
    let path = ctx.absolute(path);
    let Ok(meta) = fs::symlink_metadata(&path) else {
        return Ok(Value::Null);
    };
    if !meta.file_type().is_file() {
        let linked_file = meta.file_type().is_symlink() && path.is_file();
        return Ok(if linked_file {
            json!({"regular": false, "text": ""})
        } else {
            Value::Null
        });
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let Ok(mut file) = options.open(&path) else {
        return Ok(Value::Null);
    };
    match file.metadata() {
        Ok(meta) if meta.file_type().is_file() => {}
        _ => return Ok(Value::Null),
    }
    let mut bytes = Vec::new();
    if std::io::Read::read_to_end(&mut file, &mut bytes).is_err() {
        return Ok(Value::Null);
    }
    let text = super::kimi::utf8(bytes, label)?;
    Ok(json!({"regular": true, "text": crate::copilot_detect::universal_newlines(text)}))
}

fn verdict(active: bool, status: &str, reason: Option<&str>) -> Doc {
    let mut doc = Doc::default();
    doc.set("protection_active", PyVal::Bool(active))
        .set("integrity_status", files::text(status))
        .set("reason", reason.map_or(PyVal::Null, files::text));
    doc
}

/// `cursor_native_hook_state`: registration, scripts and the attested CLI.
pub(super) fn hook_state(ask: &Ask) -> Step<Doc> {
    let ctx = ask.ctx;
    let facts = ask.facts()?;
    if facts.require_bridge().is_err() {
        return Ok(verdict(false, "missing", Some(BRIDGE_UNAVAILABLE)));
    }
    let unavailable = || {
        verdict(
            false,
            "attestation-unavailable",
            Some("guard_cursor_cli_attestation_unavailable"),
        )
    };
    let Ok(attestation) = facts.attestation() else {
        return Ok(unavailable());
    };
    let source = match script_source(ask, &facts, attestation) {
        Err(Failure::Runtime(_)) => return Ok(unavailable()),
        source => source?,
    };
    let hooks = cursor::hooks_path(ctx);
    let state = cursor::digest_path(ctx, &hooks, "hooks-", "state");
    let mut kept: Vec<(String, Failure)> = Vec::new();
    let mut observe = |label: &str, read: Step<Value>| match read {
        Ok(value) => Ok(value),
        Err(Failure::Reply(needed)) => Err(Failure::Reply(needed)),
        Err(error) => {
            kept.push((label.to_owned(), error));
            Ok(json!(false))
        }
    };
    let scripts = json!([
        observe(
            "script",
            read_script(ctx, &cursor::script_path(ctx), "script")
        )?,
        observe(
            "managed_script",
            read_script(ctx, &cursor::managed_script_path(ctx), "managed_script"),
        )?,
    ]);
    let hooks_text = if ctx.absolute(&hooks).is_file() {
        observe(
            "hooks",
            cursor_files::read_text(ctx, &hooks, "hooks").map(|text| json!(text)),
        )?
    } else {
        Value::Null
    };
    let mut rendered = Map::new();
    for (event, entry) in entries(ask, &facts, attestation)? {
        let value = observe(event, entry.and_then(|entry| wire(&entry)))?;
        rendered.insert(event.into(), value);
    }
    let request = json!({
        "source": source,
        "identity": wire(&attestation.identity)?,
        "state_text": cursor_files::read_text(ctx, &state, "state")?,
        "scripts": scripts,
        "hooks_text": hooks_text,
        "entries": rendered,
    });
    let answer = crate::cursor_hook_state::dispatch(&request).map_err(|_| Failure::Invalid)?;
    let malformed_state = || Failure::Refusal("Cursor hook state answer is malformed".into());
    let answer = answer.as_object().ok_or_else(malformed_state)?;
    if let (1, Some(Value::String(label))) = (answer.len(), answer.get("raise")) {
        if let Some(index) = kept.iter().position(|(name, _)| name == label) {
            return Err(kept.swap_remove(index).1);
        }
    }
    if answer.len() != 2 {
        return Err(malformed_state());
    }
    match (&answer["integrity_status"], &answer["reason"]) {
        (Value::String(status), Value::Null) if status == "valid" => {
            let mut doc = verdict(true, "valid", None);
            doc.set("guard_cli_identity", attestation.identity.clone());
            Ok(doc)
        }
        (Value::String(status), Value::String(reason))
            if matches!(status.as_str(), "missing" | "tampered" | "stale") =>
        {
            Ok(verdict(false, status, Some(reason)))
        }
        _ => Err(malformed_state()),
    }
}

/// Whether a hook-state verdict reports protection, and its reason.
pub(super) fn active(doc: &Doc) -> (bool, String) {
    let field = |key: &str| {
        doc.0
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value)
    };
    let active = matches!(field("protection_active"), Some(PyVal::Bool(true)));
    let reason = match field("reason") {
        Some(PyVal::Str(reason)) => reason.clone(),
        _ => "None".to_owned(),
    };
    (active, reason)
}
