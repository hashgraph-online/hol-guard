//! The ops that answer whether a Grok hook command, hook file or event
//! configuration is Guard's. Python reads the TOML it already holds and asks
//! here; an answer is `{"valid": bool}`, or for the files `{"pretool": bool,
//! "prompt": bool}`.
//!
//! - `grok_hook_command` takes `command`.
//! - `grok_hook_missing` takes `command` and the `replacement` that would
//!   supersede it: whether `command` is an orphaned client of the same home.
//! - `grok_hook_files` takes the `pretool` and `prompt` hook file paths and
//!   answers whether each is Guard's catch-all pre-tool hook and its prompt
//!   and lifecycle hooks.
//! - `grok_hook_events` takes the `events` configurations and whether only
//!   `catchall` entries count.
//!
//! Each carries `owner`: whether the context's Guard home, home and workspace
//! own the hook, or the context only supplies the caller's process facts.

use std::path::Path;

use serde_json::{json, Map, Value};

use super::grok_hook_command::{Checker, Owner};
use super::grok_hook_files::{
    event_has_catchall_hook, event_has_hook, pretool_is_catchall, prompt_is_observe,
};
use super::{Ctx, Failure, Step};
use crate::native_install_verdict::SystemRunner;
use crate::pyjson;

pub(super) fn handles(op: &str) -> bool {
    matches!(
        op,
        "grok_hook_command" | "grok_hook_missing" | "grok_hook_files" | "grok_hook_events"
    )
}

fn text<'a>(fields: &'a Map<String, Value>, key: &str) -> Step<&'a str> {
    fields
        .get(key)
        .and_then(Value::as_str)
        .ok_or(Failure::Invalid)
}

pub(super) fn dispatch(op: &str, ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let owned = fields
        .get("owner")
        .and_then(Value::as_bool)
        .ok_or(Failure::Invalid)?;
    let owner = owned.then(|| Owner {
        guard_home: &ctx.guard_home,
        home: &ctx.home,
        workspace: ctx.workspace.as_deref(),
    });
    let owner = owner.as_ref();
    let mut runner = SystemRunner;
    let mut checker = Checker::new(ctx, cfg!(target_os = "macos"), &mut runner);
    let valid = match op {
        "grok_hook_command" => checker.recognizes(text(fields, "command")?, owner),
        "grok_hook_missing" => {
            checker.is_missing(text(fields, "command")?, text(fields, "replacement")?)
        }
        "grok_hook_files" => {
            let pretool = Path::new(text(fields, "pretool")?);
            let prompt = Path::new(text(fields, "prompt")?);
            return Ok(json!({
                "pretool": pretool_is_catchall(&mut checker, ctx, pretool, owner),
                "prompt": prompt_is_observe(&mut checker, ctx, prompt, owner),
            }));
        }
        "grok_hook_events" => {
            let catchall = fields
                .get("catchall")
                .and_then(Value::as_bool)
                .ok_or(Failure::Invalid)?;
            let events = fields
                .get("events")
                .and_then(Value::as_array)
                .ok_or(Failure::Invalid)?;
            events.iter().all(|entries| {
                let Ok(entries) = pyjson::parse(&entries.to_string()) else {
                    return false;
                };
                if catchall {
                    event_has_catchall_hook(&mut checker, &entries, owner)
                } else {
                    event_has_hook(&mut checker, Some(&entries), owner)
                }
            })
        }
        _ => return Err(Failure::Invalid),
    };
    Ok(json!({ "valid": valid }))
}
