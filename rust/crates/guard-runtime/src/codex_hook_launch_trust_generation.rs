//! Which authenticated generation a Codex hook registration belongs to,
//! ported from `codex_hook_runtime_trust`: the exact current layout, or a
//! retained layout install recorded a compatibility hash for.

use serde_json::Value;

use super::{invalid, mapping, Checked, Object};
use crate::codex_hook_bridge::trust::{argv_sha256, bridge_argv};
use crate::codex_hook_bridge::{decode_config_argument, BRIDGE_COMMAND};

const MAX_GENERATIONS: usize = 8;

/// `_selected_launch_generation`: the exact current or explicitly retained
/// authenticated generation that registers this argv.
pub(super) fn selected_generation<'a>(
    manifest: &'a Object,
    config_json: &str,
) -> Checked<&'a Object> {
    let list = |name: &str| match manifest.get(name) {
        None => Ok(&[][..]),
        Some(Value::Array(items)) if items.len() <= MAX_GENERATIONS => Ok(items.as_slice()),
        Some(_) => Err(invalid("retained generation identity is invalid")),
    };
    let retained = list("retained_bridge_generations")?;
    let allowed = list("compatible_bridge_argv_sha256")?;
    let well_formed = |value: &Value| {
        value.as_str().is_some_and(|text| {
            text.len() == 64 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        })
    };
    if !allowed.iter().all(well_formed) {
        return Err(invalid("bridge compatibility identity is invalid"));
    }
    let candidates =
        std::iter::once(Some(manifest)).chain(retained.iter().rev().map(Value::as_object));
    for (index, candidate) in candidates.enumerate() {
        let candidate =
            candidate.ok_or_else(|| invalid("retained generation identity is invalid"))?;
        let Some(bridge) = packaged_identity(candidate, "bridge")? else {
            // A generation from before the native launcher names a removed file.
            continue;
        };
        let expected = native_argv(bridge, config_json)?;
        let events = events(candidate)?;
        let exact = registers(events, &expected)?;
        let hash = argv_sha256(&expected);
        if exact && (index == 0 || allowed.iter().any(|item| item == &hash)) {
            if candidate.get("installation_id") != manifest.get("installation_id")
                || candidate.get("context") != manifest.get("context")
            {
                return Err(invalid("retained generation context is invalid"));
            }
            return Ok(candidate);
        }
    }
    // Legacy manifests have a compatibility hash but no complete old layout;
    // the current-layout checks still apply and no old path is inferred.
    Ok(manifest)
}

pub(super) fn events(generation: &Object) -> Checked<&[Value]> {
    generation
        .get("events")
        .and_then(Value::as_array)
        .filter(|events| !events.is_empty())
        .map(Vec::as_slice)
        .ok_or_else(|| invalid("event identity is invalid"))
}

/// `_event_bridge_argv`: an event's argv list, past any native launcher
/// prefix; `None` when it records no list.
pub(super) fn event_argv(event: &Value) -> Checked<Option<Vec<Value>>> {
    Ok(mapping(Some(event), "event")?
        .get("argv")
        .and_then(Value::as_array)
        .map(|argv| bridge_argv(argv).to_vec()))
}

/// Whether every event registers exactly `expected`.
fn registers(events: &[Value], expected: &[&str; 3]) -> Checked<bool> {
    let expected: Vec<Value> = expected.iter().map(|item| Value::from(*item)).collect();
    let mut exact = true;
    for event in events {
        exact &= event_argv(event)?.as_ref() == Some(&expected);
    }
    Ok(exact)
}

/// `_native_bridge_argv`: the authenticated runtime, its subcommand and config.
pub(super) fn native_argv<'a>(bridge: &'a Object, config_json: &'a str) -> Checked<[&'a str; 3]> {
    let path = bridge
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("bridge identity is invalid"))?;
    Ok([path, BRIDGE_COMMAND, config_json])
}

/// `_packaged_identity`: the first recorded file with `role`.
pub(super) fn packaged_identity<'a>(
    generation: &'a Object,
    role: &str,
) -> Checked<Option<&'a Object>> {
    let packaged = generation
        .get("packaged_files")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("packaged-file identity is invalid"))?;
    Ok(packaged
        .iter()
        .filter_map(Value::as_object)
        .find(|identity| identity.get("role").and_then(Value::as_str) == Some(role)))
}

/// `_verify_registered_bridge_argv`: every event registers this argv, or
/// install recorded its compatibility hash.
pub(super) fn registered_bridge_argv(
    manifest: &Object,
    bridge: &Object,
    config_json: &str,
) -> Checked<()> {
    let config = decode_config_argument(config_json)
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .filter(Value::is_object);
    if config.is_none() {
        return Err(invalid("bridge config is malformed"));
    }
    let expected = native_argv(bridge, config_json)?;
    let events = events(manifest)?;
    if registers(events, &expected)? {
        return Ok(());
    }
    let hashes = manifest
        .get("compatible_bridge_argv_sha256")
        .and_then(Value::as_array)
        .filter(|hashes| hashes.iter().any(|hash| hash == &argv_sha256(&expected)))
        .ok_or_else(|| invalid("bridge config changed after authentication"))?;
    if !hashes
        .iter()
        .all(|hash| hash.as_str().is_some_and(|text| text.len() == 64))
    {
        return Err(invalid("bridge compatibility identity is invalid"));
    }
    for event in events {
        if !mapping(Some(event), "event")?
            .get("argv")
            .is_some_and(Value::is_array)
        {
            return Err(invalid("event identity is invalid"));
        }
    }
    Ok(())
}
