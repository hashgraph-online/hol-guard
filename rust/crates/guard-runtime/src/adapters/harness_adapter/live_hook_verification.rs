//! `live_hook_verification`: whether each active managed install's live hooks
//! still intercept Guard's boundary.
//!
//! The question has one answer per harness, and which proof settles it is the
//! runtime's: Codex and Cursor read their live hook registration, Grok its hook
//! files and managed config, and every other harness the artifact proof its
//! install recorded. An install whose proof cannot be read says nothing, so
//! the map leaves it out and a caller treats it as unproven, not as unprotected.

use serde_json::{json, Map, Value};

use super::{describe, grok_protection_checks, proof, route, Ctx, Step};

pub(super) fn handles(op: &str) -> bool {
    op == "live_hook_verification"
}

/// The request names the store's installs (`harness`, `active`, `manifest`)
/// and, when one is Codex, the launch facts its live read needs as `codex`.
pub(super) fn dispatch(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let installs = fields
        .get("managed_installs")
        .and_then(Value::as_array)
        .ok_or(super::Failure::Invalid)?;
    let codex = fields
        .get("codex")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let mut verified = Map::new();
    for install in installs {
        let Some(harness) = install.get("harness").and_then(Value::as_str) else {
            continue;
        };
        if install.get("active") != Some(&Value::Bool(true)) {
            continue;
        }
        if let Some(proven) = proven(ctx, harness, install, &codex) {
            verified.insert(harness.to_owned(), Value::Bool(proven));
        }
    }
    Ok(json!({ "verified": verified }))
}

fn proven(ctx: &Ctx, harness: &str, install: &Value, codex: &Map<String, Value>) -> Option<bool> {
    match harness {
        // A Codex read that fails proves nothing about interception.
        "codex" => Some(
            asked(ctx, "codex", "runtime_hooks_verified", codex)
                .is_some_and(|answer| answer.get("verified") == Some(&Value::Bool(true))),
        ),
        "cursor" => asked(ctx, "cursor", "health", &Map::new())?
            .get("verified")?
            .as_bool(),
        "grok" => grok_protection_checks::dispatch("grok_hooks_verified", ctx)
            .ok()?
            .get("verified")?
            .as_bool(),
        _ => {
            Some(proof::verify(ctx, install.get("manifest").unwrap_or(&Value::Null)) == Some(true))
        }
    }
}

fn asked(ctx: &Ctx, harness: &str, op: &str, fields: &Map<String, Value>) -> Option<Value> {
    route(describe::spec(harness)?, op, ctx, fields).ok()
}
