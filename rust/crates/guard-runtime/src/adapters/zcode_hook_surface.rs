//! `runner_authority` kind `zcode_hook_settings`: one ZCode hook surface
//! (`config.json` for the Desktop app, the CLI's `setting.json`) rewritten
//! with Guard's hook groups, ported from `ZCodeHarnessAdapter` in
//! `adapters/zcode.py`.
//!
//! Python keeps the file reads, the path checks, the install state and the
//! writes. It sends the file text (`null` for an absent `config.json`) and
//! gets back the whole new text, rendered like `json.dumps(indent=2)` with
//! every user object and its key order kept:
//!
//! - `install` answers `{"text", "enabled"}`, where `enabled` is the JSON
//!   text of the pre-install `enabled` record to save, or `{"refusal"}`:
//!   `not_object` for text that is not a JSON object, `hooks_disabled` when
//!   the user turned hooks off and has handlers of their own;
//! - `uninstall` answers `{"text"}`, `null` when the file stays as it is.
//!
//! Legacy flat groups fold into `hooks.events` on install (current ZCode
//! rejects the flat keys and drops the whole file), Guard's `PreToolUse`
//! group per matcher and its `UserPromptSubmit` group are refreshed, and
//! `hooks.enabled` is set; uninstall prunes Guard's entries from both layouts
//! and restores the saved `enabled` flag.

use serde_json::{json, Value};

use super::hook_removal_prune::write_indented;
use super::pyjson::{self, JsonFailure, PyVal, LONE_SURROGATE_MARK};
use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};
use super::zcode_artifacts::MANAGED_MARKER;
use super::zcode_hook_settings::{
    has_handlers, install_hooks, lookup, recorded_enabled, remove_key, set_key, uninstall_hooks,
    Dict, PRETOOL, PROMPT,
};

/// ZCode renders this label beside the hook in its Hooks settings UI instead
/// of the full managed command.
const STATUS_MESSAGE: &str = "HOL Guard runtime policy enforcement";

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let map = args_object(args)?;
    let op = map.get("op").and_then(Value::as_str).ok_or(ERR_INVALID)?;
    let keys: &[&str] = match op {
        "install" => &[
            "text",
            "path",
            "history",
            "managed_config_path",
            "desktop",
            "matchers",
            "command",
            "timeouts",
        ],
        "uninstall" => &["text", "path", "history", "managed_config_path"],
        _ => return Err(ERR_INVALID),
    };
    if map.len() != keys.len() + 1 || !keys.iter().all(|key| map.contains_key(*key)) {
        return Err(ERR_INVALID);
    }
    let text = match &map["text"] {
        Value::Null if op == "install" => None,
        Value::String(text) => Some(text.as_str()),
        _ => return Err(ERR_INVALID),
    };
    let path = map["path"].as_str().ok_or(ERR_INVALID)?;
    let saved =
        |hooks: &PyVal| recorded_enabled(hooks, path, &map["history"], &map["managed_config_path"]);
    if op == "uninstall" {
        // `_json_payload`: text that is not a JSON object reads as `{}`.
        let payload = read_payload(text.unwrap_or_default())?.unwrap_or_default();
        return Ok(json!({ "text": uninstall_surface(payload, saved)? }));
    }
    let desktop = map["desktop"].as_bool().ok_or(ERR_INVALID)?;
    let matchers = map["matchers"]
        .as_array()
        .ok_or(ERR_INVALID)?
        .iter()
        .map(|matcher| matcher.as_str().ok_or(ERR_INVALID))
        .collect::<Result<Vec<_>, _>>()?;
    let command = map["command"].as_str().ok_or(ERR_INVALID)?;
    let handlers = guard_handlers(command, &map["timeouts"])?;
    let mut payload = Dict::new();
    if let Some(text) = text {
        let Some(read) = read_payload(text)? else {
            return Ok(json!({ "refusal": "not_object" }));
        };
        payload = read;
        if desktop {
            for key in ["mcp", "plugins"] {
                if !matches!(lookup(&payload, key), Some(PyVal::Dict(_))) {
                    set_key(&mut payload, key, PyVal::Dict(Dict::new()));
                }
            }
        }
    }
    let hooks = match lookup(&payload, "hooks") {
        Some(hooks @ PyVal::Dict(_)) => hooks.clone(),
        _ => PyVal::Dict(Dict::new()),
    };
    let enabled = enabled_text(&hooks, saved(&hooks))?;
    if matches!(hooks.get("enabled"), Some(PyVal::Bool(false))) && has_handlers(&hooks) {
        return Ok(json!({ "refusal": "hooks_disabled" }));
    }
    let mut after = install_hooks(&hooks, &matchers, &handlers);
    // Each surface registers hooks only after its own `hooks.enabled` opt-in.
    set_key(&mut after, "enabled", PyVal::Bool(true));
    set_key(&mut payload, "hooks", PyVal::Dict(after));
    Ok(json!({ "text": render_file(payload)?, "enabled": enabled }))
}

/// `json.loads(text)` when it is an object, `None` for text that is not one
/// (`json.JSONDecodeError` or another value); input CPython raises anything
/// else on is refused.
fn read_payload(text: &str) -> Result<Option<Dict>, &'static str> {
    match pyjson::parse_marking_lone_surrogates(text) {
        Ok(PyVal::Dict(entries)) => Ok(Some(entries)),
        Ok(_) | Err(JsonFailure::Syntax) => Ok(None),
        Err(_) => Err(ERR_INVALID),
    }
}

/// Guard's handler per event: the managed command with the marker riding
/// along as a trailing shell comment, so ZCode runs it verbatim.
fn guard_handlers(command: &str, timeouts: &Value) -> Result<Dict, &'static str> {
    let timeouts = timeouts.as_object().ok_or(ERR_INVALID)?;
    if timeouts.len() != 2 {
        return Err(ERR_INVALID);
    }
    [PRETOOL, PROMPT]
        .into_iter()
        .map(|event| -> Result<(String, PyVal), &'static str> {
            let timeout = timeouts
                .get(event)
                .and_then(Value::as_u64)
                .filter(|timeout| *timeout > 0)
                .ok_or(ERR_INVALID)?;
            let handler = vec![
                ("type".to_owned(), PyVal::Str("command".to_owned())),
                (
                    "command".to_owned(),
                    PyVal::Str(format!("{command} # {MANAGED_MARKER}")),
                ),
                ("timeout".to_owned(), PyVal::Int(timeout.to_string())),
                (
                    "statusMessage".to_owned(),
                    PyVal::Str(STATUS_MESSAGE.to_owned()),
                ),
            ];
            Ok((event.to_owned(), PyVal::Dict(handler)))
        })
        .collect()
}

/// The pre-install `enabled` record as JSON text: the saved one, else the
/// live flag (any JSON value, rendered the way Python saves it).
pub(crate) fn enabled_text(hooks: &PyVal, saved: Value) -> Result<String, &'static str> {
    if !saved.is_null() {
        return serde_json::to_string(&saved).map_err(|_| ERR_INVALID);
    }
    let value = hooks.get("enabled");
    let record = vec![
        ("present".to_owned(), PyVal::Bool(value.is_some())),
        ("value".to_owned(), value.cloned().unwrap_or(PyVal::Null)),
    ];
    render(&PyVal::Dict(record))
}

/// One uninstalled surface's new text, `None` when nothing changed or the
/// file holds no `hooks` object.
fn uninstall_surface(
    mut payload: Dict,
    saved: impl Fn(&PyVal) -> Value,
) -> Result<Option<String>, &'static str> {
    let Some(hooks) = lookup(&payload, "hooks").filter(|hooks| hooks.as_dict().is_some()) else {
        return Ok(None);
    };
    let hooks = hooks.clone();
    let record = saved(&hooks);
    let mut after = uninstall_hooks(&hooks);
    // Guard's opt-in goes back to the pre-install flag; with no saved record
    // the live `true` stays.
    if matches!(lookup(&after, "enabled"), Some(PyVal::Bool(true))) && !record.is_null() {
        match record["value"].as_bool() {
            Some(value) if record["present"] == Value::Bool(true) => {
                set_key(&mut after, "enabled", PyVal::Bool(value));
            }
            _ => remove_key(&mut after, "enabled"),
        }
    }
    let after = PyVal::Dict(after);
    // `json.dumps(sort_keys=True)` equality.
    if after.canonical_key() == hooks.canonical_key() {
        return Ok(None);
    }
    match after {
        PyVal::Dict(entries) if entries.is_empty() => remove_key(&mut payload, "hooks"),
        after => set_key(&mut payload, "hooks", after),
    }
    render_file(payload).map(Some)
}

/// `json.dumps(value, indent=2)`. A lone surrogate escape, which CPython
/// keeps and writes back, has no Rust string form, so it is refused.
fn render(value: &PyVal) -> Result<String, &'static str> {
    if marked(value) {
        return Err(ERR_INVALID);
    }
    let mut out = Vec::new();
    write_indented(value, 0, &mut out).ok_or(ERR_INVALID)?;
    String::from_utf8(out).map_err(|_| ERR_INVALID)
}

fn render_file(payload: Dict) -> Result<String, &'static str> {
    render(&PyVal::Dict(payload)).map(|text| text + "\n")
}

fn marked(value: &PyVal) -> bool {
    match value {
        PyVal::Str(text) => text.contains(LONE_SURROGATE_MARK),
        PyVal::List(items) => items.iter().any(marked),
        PyVal::Dict(entries) => entries
            .iter()
            .any(|(key, item)| key.contains(LONE_SURROGATE_MARK) || marked(item)),
        _ => false,
    }
}
