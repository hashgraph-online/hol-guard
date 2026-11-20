//! Rebinding stale Cursor hooks: whether the live hook script still bakes a
//! pruneable Core path, skips the native bridge or differs from the script
//! this Guard would write. Python runs the hooks install the answer asks for.

use std::path::Path;

use serde_json::{json, Map, Value};

use super::cursor::{self, get, Ask, Facts};
use super::cursor_files::read_text;
use super::cursor_hooks::{live_commands, script_source};
use super::{Failure, Step};
use crate::pyjson::PyVal;

fn not_rebound(reason: &str) -> Value {
    json!({ "rebound": false, "reason": reason })
}

fn rebind_failed(error: Failure) -> Step<Value> {
    match error {
        Failure::Runtime(message) => Ok(json!({
            "rebound": false,
            "reason": "cursor_hook_script_rebind_failed",
            "error": message,
        })),
        other => Err(other),
    }
}

/// A managed script's text, or the answer that stops the rebind.
fn managed_source(ask: &Ask, path: &Path) -> Step<Result<String, Value>> {
    match read_text(ask.ctx, path, "The Cursor hook script") {
        Ok(Some(source)) if crate::cursor_hook_config::is_managed_script(&source) => Ok(Ok(source)),
        Ok(Some(_)) => Ok(Err(not_rebound("cursor_hook_script_unmanaged"))),
        Ok(None) | Err(Failure::Refusal(_)) => {
            Ok(Err(not_rebound("cursor_hook_script_unreadable")))
        }
        Err(other) => Err(other),
    }
}

/// `rebind_stale_cursor_hooks`: whether Guard's hooks still bake a pruneable
/// Core path or an outdated script; `{"install": true}` when Python should
/// run the hooks install.
pub(super) fn rebind(ask: &Ask) -> Step<Value> {
    let ctx = ask.ctx;
    let facts = ask.facts()?;
    if !facts.can_rebind {
        return Ok(not_rebound("stable_frozen_cli_unavailable"));
    }
    let live = cursor::script_path(ctx);
    if !ctx.absolute(&live).is_file() {
        return Ok(not_rebound("cursor_hook_script_absent"));
    }
    let live_source = match managed_source(ask, &live)? {
        Ok(source) => source,
        Err(answer) => return Ok(answer),
    };
    let managed = cursor::managed_script_path(ctx);
    let managed_text = if ctx.absolute(&managed).is_file() {
        match managed_source(ask, &managed)? {
            Ok(source) => Some(source),
            Err(answer) => return Ok(answer),
        }
    } else {
        None
    };
    let expected = match facts
        .attestation()
        .and_then(|att| script_source(ask, &facts, att))
    {
        Ok(source) => source,
        Err(error) => return rebind_failed(error),
    };
    let hooks = cursor::read_object(ctx, &cursor::hooks_path(ctx)).map(|payload| {
        match get(&payload, "hooks") {
            Some(PyVal::Dict(nested)) => nested.clone(),
            _ => payload,
        }
    });
    let commands = match hooks {
        Some(hooks) => live_commands(ask, &hooks),
        None => Ok(Vec::new()),
    };
    let request = commands.map(|commands| {
        let mut request = Map::new();
        request.insert("live".into(), json!(live_source));
        request.insert("managed".into(), json!(managed_text));
        request.insert("expected".into(), json!(expected));
        request.insert("commands".into(), json!(commands));
        request.insert("isolated_python".into(), json!(facts.interpreter.is_some()));
        request.insert("native_bridge".into(), json!(facts.bridge.is_some()));
        request
    });
    let needs = match request.and_then(|request| ask.hook_config("rebind", request)) {
        Ok(answer) => answer["rebind"].as_bool().ok_or_else(cursor::malformed),
        Err(error) => Err(error),
    };
    let needs = match needs {
        Ok(needs) => needs,
        Err(error) => return rebind_failed(error),
    };
    if !needs && state_matches(ask, &facts) {
        return Ok(not_rebound("cursor_hook_script_current"));
    }
    Ok(json!({ "install": true }))
}

/// `_state_matches_attested_cli`: the hooks state names this Guard CLI.
fn state_matches(ask: &Ask, facts: &Facts) -> bool {
    let hooks = cursor::hooks_path(ask.ctx);
    let state = cursor::digest_path(ask.ctx, &hooks, "hooks-", "state");
    let (Some(state), Ok(attestation)) =
        (cursor::read_object(ask.ctx, &state), facts.attestation())
    else {
        return false;
    };
    let recorded = get(&state, "guard_cli_identity").and_then(PyVal::to_json);
    recorded.is_some() && recorded == attestation.identity.to_json()
}
