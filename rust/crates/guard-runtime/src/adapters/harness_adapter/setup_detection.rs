//! What an app's Guard setup looks like on this machine: whether it is
//! installed, whether it needs repair, whether its command is on the path and
//! which of its config files exist, plus the canonical install rows protection
//! health reads.
//!
//! Both answers come from the Guard store, which the runtime reads itself:
//! the caller names the store's Guard home and the runtime decides everything
//! else, including which cached fleet check is still current.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};

use super::{contract_config_paths, describe, managed_store, proof, route, Ctx, Failure, Step};
use crate::context_digest::python_strip;
use crate::policy_bundle_time::from_isoformat;

/// `DIAGNOSTICS_STATE_KEY`.
const DIAGNOSTICS_STATE_KEY: &str = "fleet_posture_diagnostics";
const MICROS_PER_SECOND: i64 = 1_000_000;
/// `_FLEET_CHECK_MAX_AGE`: 24 hours.
const FLEET_CHECK_MAX_AGE: i64 = 24 * 60 * 60 * MICROS_PER_SECOND;
/// `_FLEET_CHECK_SETTLE`: 5 minutes.
const FLEET_CHECK_SETTLE: i64 = 5 * 60 * MICROS_PER_SECOND;

pub(super) fn handles(op: &str) -> bool {
    matches!(op, "setup_detection" | "canonical_managed_installs")
}

pub(super) fn dispatch(op: &str, ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    match op {
        "setup_detection" => setup_detection(ctx, fields),
        "canonical_managed_installs" => canonical_managed_installs(fields),
        _ => Err(Failure::Invalid),
    }
}

/// The Guard home of the store the caller holds, when it holds one.
fn store_home(fields: &Map<String, Value>) -> Step<Option<&Path>> {
    match fields.get("store_home") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(home)) => Ok(Some(Path::new(home))),
        Some(_) => Err(Failure::Invalid),
    }
}

/// `parse_timestamp`, to UTC microseconds.
fn parse_timestamp(value: Option<&Value>) -> Option<i64> {
    let stripped = python_strip(value?.as_str()?);
    if stripped.is_empty() {
        return None;
    }
    let normalized = match stripped.strip_suffix(['Z', 'z']) {
        Some(prefix) => format!("{prefix}+00:00"),
        None => stripped.to_owned(),
    };
    from_isoformat(&normalized)?.utc_micros()
}

/// The clock the fleet check ages against; a request may name it so a check
/// is repeatable.
fn now_micros(fields: &Map<String, Value>) -> i64 {
    parse_timestamp(fields.get("now")).unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| {
                i64::try_from(elapsed.as_micros()).unwrap_or(i64::MAX)
            })
    })
}

/// `_fleet_checked_setup_status`: the setup status Guard last reported to
/// Cloud for this app, when it is still current.
///
/// An install change wins until a check has run `FLEET_CHECK_SETTLE` after
/// it, so connect, disconnect and repair show at once and a check that
/// overlapped them is ignored.
fn fleet_checked_status(
    home: &Path,
    harness: &str,
    managed: Option<&Value>,
    now: i64,
) -> Option<&'static str> {
    let cached = managed_store::sync_payload(home, DIAGNOSTICS_STATE_KEY)?;
    let entry = cached.as_object()?.get(harness)?.as_object()?;
    let diagnostics = entry.get("diagnostics")?.as_object()?;
    let checked_at = parse_timestamp(entry.get("at"))?;
    let age = now.checked_sub(checked_at)?;
    if !(0..=FLEET_CHECK_MAX_AGE).contains(&age) {
        return None;
    }
    let managed_at = managed.and_then(|row| parse_timestamp(row.get("updated_at")));
    if managed_at.is_some_and(|managed_at| checked_at < managed_at + FLEET_CHECK_SETTLE) {
        return None;
    }
    match diagnostics.get("setup_status")?.as_str()? {
        "active" => Some("active"),
        "broken" => Some("broken"),
        "partial" => Some("partial"),
        "not_found" => Some("not_found"),
        _ => None,
    }
}

fn is_active(managed: Option<&Value>) -> bool {
    managed.is_some_and(|row| row.get("active") == Some(&Value::Bool(true)))
}

/// `_safe_setup_detection`.
///
/// The request names the `harness`, the `store_home` of the caller's store
/// (absent when it holds none), `use_fleet_check` (only the app list sets it,
/// so it matches what Guard Cloud shows) and, for Paseo, the `diagnostics`
/// the caller gathered. Verification keeps reading the install record and runs
/// its own checks.
fn setup_detection(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let harness = fields
        .get("harness")
        .and_then(Value::as_str)
        .ok_or(Failure::Invalid)?;
    let spec = describe::spec(harness).ok_or(Failure::Invalid)?;
    let home = store_home(fields)?;
    let managed = match home {
        Some(home) => managed_store::managed_install(home, harness)?,
        None => None,
    };
    if harness == "paseo" {
        let diagnostics = fields
            .get("diagnostics")
            .and_then(Value::as_object)
            .ok_or(Failure::Invalid)?;
        let installed = is_active(managed.as_ref())
            && diagnostics.get("setup_status") == Some(&json!("active"))
            && managed
                .as_ref()
                .and_then(|row| row.get("manifest"))
                .is_some_and(|manifest| proof::verify(ctx, manifest) == Some(true));
        return Ok(json!({
            "installed": installed,
            "managed_active": is_active(managed.as_ref()),
            "needs_repair": false,
            "command_available": diagnostics
                .get("command_available")
                .cloned()
                .unwrap_or(Value::Bool(false)),
            "config_paths": diagnostics.get("config_paths").cloned().unwrap_or_else(|| json!([])),
        }));
    }
    let managed_active = is_active(managed.as_ref());
    let use_fleet_check = fields.get("use_fleet_check") == Some(&Value::Bool(true));
    let checked = match (use_fleet_check, home) {
        (true, Some(home)) => {
            fleet_checked_status(home, harness, managed.as_ref(), now_micros(fields))
        }
        _ => None,
    };
    let command = route(spec, "resolved_executable", ctx, fields)?;
    let config_paths = contract_config_paths::dispatch(ctx, fields)?;
    Ok(json!({
        "installed": checked == Some("active") || (checked.is_none() && managed_active),
        "managed_active": managed_active,
        "needs_repair": checked == Some("broken")
            || (managed_active && matches!(checked, Some("partial" | "not_found"))),
        "command_available": command.get("path").is_some_and(Value::is_string),
        "config_paths": config_paths
            .get("config_paths")
            .cloned()
            .unwrap_or_else(|| json!([])),
    }))
}

/// `_canonical_managed_installs_for_health`: one row per canonical harness
/// from the store's rows, sorted by harness.
///
/// A row under an alias is renamed to its adapter's harness. Where two rows
/// name the same harness the active one wins, then the one stored under the
/// canonical name, and the earlier of two equals stays.
fn canonical_managed_installs(fields: &Map<String, Value>) -> Step<Value> {
    let home = store_home(fields)?.ok_or(Failure::Invalid)?;
    let mut canonical: std::collections::BTreeMap<String, ((bool, bool), Value)> =
        std::collections::BTreeMap::new();
    for mut install in managed_store::managed_installs(home)? {
        let Some(harness) = install.get("harness").and_then(Value::as_str) else {
            continue;
        };
        let name = describe::resolve(harness).map_or(harness, |spec| spec.harness);
        let priority = (is_active(Some(&install)), harness == name);
        let name = name.to_owned();
        install["harness"] = Value::String(name.clone());
        let replaces = canonical
            .get(&name)
            .is_none_or(|(existing, _)| priority > *existing);
        if replaces {
            canonical.insert(name, (priority, install));
        }
    }
    let installs: Vec<Value> = canonical
        .into_values()
        .map(|(_, install)| install)
        .collect();
    Ok(json!({ "installs": installs }))
}
