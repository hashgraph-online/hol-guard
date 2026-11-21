//! Codex: the live hook configuration as Python's adapter read it, and the
//! health check protection status uses (`codex_runtime_hooks_verified`).

use std::fs;
use std::path::Path;

use serde_json::{json, Map, Value};

use super::codex::{config_path, hooks_path};
use super::codex_hook_state::with_syntax;
use super::codex_live_hooks::intercept;
use super::codex_live_state::live_hook_state;
use super::{Ctx, Failure, Step};
use crate::codex_toml_read::{self, TomlVal};
use crate::pyjson::{self, PyVal};

/// `config.toml`'s `features` and `hooks`, `hooks.json`'s `hooks`, and the
/// tokens standing for the TOML values JSON cannot carry.
pub(super) struct LiveHooks {
    pub(super) features: PyVal,
    pub(super) toml_hooks: PyVal,
    pub(super) json_hooks: PyVal,
    pub(super) tokens: Map<String, Value>,
}

impl LiveHooks {
    /// Each file read leniently: a missing or unreadable file reads as absent.
    pub(super) fn read(ctx: &Ctx) -> Self {
        let json_hooks = read_json_hooks(&ctx.absolute(&hooks_path(ctx)));
        let mut avoid = Vec::new();
        if let Some(hooks) = &json_hooks {
            strings_in(hooks, &mut avoid);
        }
        let avoid: Vec<&str> = avoid.iter().map(String::as_str).collect();
        let (payload, tokens) =
            codex_toml_read::wire_avoiding(&read_config(&ctx.absolute(&config_path(ctx))), &avoid);
        Self {
            features: payload.get("features").cloned().unwrap_or(PyVal::Null),
            toml_hooks: payload.get("hooks").cloned().unwrap_or(PyVal::Null),
            json_hooks: json_hooks.unwrap_or(PyVal::Null),
            tokens,
        }
    }
}

/// The hooks Codex runs: the TOML table when there is one, else `hooks.json`.
pub(super) fn live_hooks<'a>(toml_hooks: &'a PyVal, json_hooks: &'a PyVal) -> &'a PyVal {
    if matches!(toml_hooks, PyVal::Dict(_)) {
        toml_hooks
    } else {
        json_hooks
    }
}

/// `codex_runtime_hooks_verified`: Guard's launchable hooks still intercept
/// the shell on the live config, or the verified hook state says the shell
/// is protected. Request fields are `live_hook_state`'s.
pub(super) fn runtime_hooks_verified(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let read = LiveHooks::read(ctx);
    let enabled = match &read.features {
        PyVal::Dict(_) => !matches!(read.features.get("hooks"), Some(PyVal::Bool(false))),
        _ => true,
    };
    let intercepts = match live_hooks(&read.toml_hooks, &read.json_hooks) {
        PyVal::Dict(hooks) if enabled => {
            with_syntax(fields, |syntax| Ok(intercept(hooks, syntax)))?
        }
        _ => false,
    };
    if intercepts {
        return Ok(json!({ "verified": true }));
    }
    let verified = match live_hook_state(ctx, fields) {
        Ok(answer) => answer
            .get("state")
            .and_then(Value::as_str)
            .and_then(|state| serde_json::from_str::<Value>(state).ok())
            .is_some_and(|state| state["shell_protection_active"] == json!(true)),
        // The caller expands the short names and asks again.
        Err(Failure::Reply(reply)) => return Err(Failure::Reply(reply)),
        Err(_) => false,
    };
    Ok(json!({ "verified": verified }))
}

/// `read_toml_payload`: the payload, or nothing when the file is missing or
/// does not parse.
fn read_config(path: &Path) -> Vec<(String, TomlVal)> {
    if !path.is_file() {
        return Vec::new();
    }
    let Ok(data) = fs::read(path) else {
        return Vec::new();
    };
    std::str::from_utf8(&data)
        .ok()
        .and_then(|text| codex_toml_read::read(text).ok())
        .unwrap_or_default()
}

/// `hooks.json`'s `hooks` value, when the file holds a JSON object.
fn read_json_hooks(path: &Path) -> Option<PyVal> {
    if !path.is_file() {
        return None;
    }
    let text = fs::read_to_string(path).ok()?;
    match pyjson::parse(&text) {
        Ok(payload @ PyVal::Dict(_)) => payload.get("hooks").cloned(),
        _ => None,
    }
}

fn strings_in(value: &PyVal, out: &mut Vec<String>) {
    match value {
        PyVal::Str(text) => out.push(text.clone()),
        PyVal::List(items) => items.iter().for_each(|item| strings_in(item, out)),
        PyVal::Dict(entries) => {
            for (key, item) in entries {
                out.push(key.clone());
                strings_in(item, out);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
#[path = "codex_live_read_tests.rs"]
mod tests;
