//! Codex: `verify_manifest`, the integrity state of one authenticated hook
//! manifest against the installation a caller expects.
//!
//! The runtime reads the hook key itself: it authenticates the manifest on
//! disk, or the captured text a repair or an inverse plan names, builds the
//! canonical spellings the verifier compares and decides the state. The caller
//! sends only the installation it expects (`spec`), the live hooks it parsed
//! (`hooks`: each managed event's groups, each as JSON text) and its package
//! roots; it never holds key bytes.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::codex::EVENTS;
use super::codex_live_state::{
    authenticated, owned, plain, settled, spec_text, verified_state, UNAVAILABLE,
};
use super::{Ctx, Failure, Step};
use crate::codex_hook_manifest_auth as manifest_auth;
use crate::pyjson;

/// `verify_manifest`. Request fields: `spec`, `hooks` (`null`, or an object
/// naming each managed event's groups as JSON text, `null` for one that does
/// not parse), `manifest_text` (a captured manifest, else the one on disk),
/// `package_roots`, `windows`, `long_paths` and an optional `budget_spent`.
/// Answer: `{"state": {...}}`.
pub(super) fn verify_manifest(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let spec = fields
        .get("spec")
        .and_then(Value::as_object)
        .ok_or(Failure::Invalid)?;
    let config = PathBuf::from(spec_text(spec, "config_path")?);
    let loaded = if fields.get("budget_spent").and_then(Value::as_bool) == Some(true) {
        (None, Some(owned(UNAVAILABLE)))
    } else {
        match fields.get("manifest_text") {
            None | Some(Value::Null) => authenticated(ctx, spec, &config)?,
            Some(Value::String(text)) => {
                let guard_home = ctx.absolute(Path::new(spec_text(spec, "guard_home")?));
                let home = guard_home.to_str().ok_or(Failure::Invalid)?;
                settled(manifest_auth::authenticate_text(home, text, None, None))
            }
            Some(_) => return Err(Failure::Invalid),
        }
    };
    let hooks = hooks_from_texts(fields.get("hooks"))?;
    let state = verified_state(ctx, spec, &config, loaded, hooks, fields)?;
    Ok(json!({ "state": Value::Object(state) }))
}

/// The live hooks as the verifier reads them: each managed event's group
/// list, with a group JSON cannot carry sent as `null`. Anything but an
/// object leaves the hooks unread.
fn hooks_from_texts(hooks: Option<&Value>) -> Step<Option<Value>> {
    let Some(Value::Object(events)) = hooks else {
        return Ok(None);
    };
    let tokens = Map::new();
    let mut wire = Map::new();
    for (event, ..) in EVENTS {
        let Some(groups) = events.get(event) else {
            continue;
        };
        let groups = groups.as_array().ok_or(Failure::Invalid)?;
        let groups = groups
            .iter()
            .map(|group| {
                group
                    .as_str()
                    .and_then(|text| pyjson::parse(text).ok())
                    .and_then(|group| plain(&group, 1, &tokens))
                    .unwrap_or(Value::Null)
            })
            .collect();
        wire.insert(event.to_owned(), Value::Array(groups));
    }
    Ok(Some(Value::Object(wire)))
}

#[cfg(test)]
#[path = "codex_manifest_verify_tests.rs"]
mod tests;
