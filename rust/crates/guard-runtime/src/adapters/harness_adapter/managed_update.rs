//! `managed_update`: the repairs `hol-guard update` makes to harness installs
//! the previous release left behind.
//!
//! `update: "grok"` rewrites an active Grok install whose hook files no
//! longer hold what an install would write now; `update: "bounded"`
//! reinstalls each active harness that still runs an old bounded hook client
//! script and removes the script once the install moved. Each reinstall is a
//! managed install under its own owner, from the install record's own
//! workspace. The request carries what `managed_install` does, less `command`,
//! `targets` and `actor`, plus the Guard home's store: `now`, `source` and the
//! update's `workspace`.
//!
//! The answer is `{ok: true, installs, notes}`: the row each repaired harness
//! recorded (or the row it already had), and the warning for each repair that
//! could not finish. A repair that fails never stops the next one.

use serde_json::{json, Map, Value};

use super::describe;
use super::managed_install::{run, within};
use super::managed_install_target::Owned;
use super::opencode_update::rebind;
use super::{grok_update, managed_store, path_text, update_bounded, Ctx, Failure};
use crate::runner_authority_op::{KindResult, ERR_INVALID};
use crate::transition_files::OwnedFailure;

const ACTOR: &str = "managed.install";
const TRANSITION_PREFIX: &str = "Runtime transition requires recovery: ";

/// What a repair that raised would have printed: Python's message for the
/// exception the failure stands for.
fn failure_message(failure: &OwnedFailure) -> String {
    match failure {
        OwnedFailure::Timeout(message) => (*message).to_owned(),
        OwnedFailure::Runtime(message) | OwnedFailure::Integrity(_, message) => message.clone(),
        OwnedFailure::Untrusted(untrusted) => untrusted
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        OwnedFailure::Transition(reason) => format!("{TRANSITION_PREFIX}{reason}"),
        OwnedFailure::Fault(fault) => fault_message(fault),
    }
}

fn fault_message(fault: &Value) -> String {
    let field = |key: &str| fault.get(key).and_then(Value::as_str);
    if let Some(message) = field("runtime") {
        return message.to_owned();
    }
    if let Some(reason) = field("transition") {
        return match field("detail") {
            Some(detail) => format!("{TRANSITION_PREFIX}{reason} ({detail})"),
            None => format!("{TRANSITION_PREFIX}{reason}"),
        };
    }
    if let (Some(_), Some(message)) = (field("integrity"), field("message")) {
        return message.to_owned();
    }
    if let Some(message) = field("os") {
        return match fault.get("errno").and_then(Value::as_i64) {
            Some(errno) => format!("[Errno {errno}] {message}"),
            None => message.to_owned(),
        };
    }
    if let Some(adapter) = fault.get("adapter").and_then(Value::as_object) {
        if let Some(message) = adapter.values().find_map(Value::as_str) {
            return message.to_owned();
        }
    }
    format!("{TRANSITION_PREFIX}native_transition_invalid")
}

/// The message of a step that failed as a Python `OSError`, `RuntimeError` or
/// `ValueError` an update reports as a warning.
fn step_message(failure: Failure) -> String {
    match failure {
        Failure::Refusal(message)
        | Failure::Os(message)
        | Failure::NotFound(message)
        | Failure::Runtime(message) => message,
        Failure::Integrity(reason) => reason.to_owned(),
        Failure::Reply(_) | Failure::Invalid => "native runtime answer was malformed".to_owned(),
    }
}

/// The store's row for an active install, or `None` for an absent, inactive
/// or unreadable one, which an update leaves alone.
fn active_install(ctx: &Ctx, harness: &str) -> Option<Value> {
    managed_store::managed_install(&ctx.guard_home, harness)
        .ok()
        .flatten()
        .filter(|row| row.get("active") == Some(&Value::Bool(true)))
}

/// The row an install recorded, or the one the store already held.
fn wire_row(stored: &Value) -> Value {
    json!({
        "harness": stored.get("harness"),
        "active": stored.get("active"),
        "workspace": stored.get("workspace"),
        "manifest": stored.get("manifest"),
        "updated_at": stored.get("updated_at"),
    })
}

/// How one reinstall ended: the hooks were already current, or it recorded
/// the row (`None` when the install answered none).
enum Done {
    Current,
    Installed(Option<Value>),
}

fn reinstall(
    ctx: &Ctx,
    fields: &Map<String, Value>,
    harness: &str,
    stored: &Value,
    check_current: bool,
) -> Result<Done, String> {
    let repair = rebind(ctx, stored.get("workspace")).map_err(str::to_owned)?;
    if check_current {
        let spec = describe::spec(harness).ok_or("unknown harness")?;
        let current = grok_update::hooks_current(spec, &repair).map_err(step_message)?;
        if current.get("current") == Some(&Value::Bool(true)) {
            return Ok(Done::Current);
        }
    }
    let workspace = match &repair.workspace {
        Some(path) => json!(path_text(path)),
        None => fields.get("workspace").cloned().unwrap_or(Value::Null),
    };
    let mut request = fields.clone();
    request.insert("command".into(), json!("install"));
    request.insert("actor".into(), json!(ACTOR));
    request.insert("targets".into(), json!([{ "harness": harness }]));
    request.insert("workspace".into(), workspace);
    request.remove("owner");
    let target = repair.guard_home.join("managed");
    let done: Owned<Value> = within(&repair, &request, &target, |owner| {
        run(&repair, &request, owner)
    });
    let answer = done.map_err(|failure| failure_message(&failure))?;
    let row = answer
        .get("rows")
        .and_then(Value::as_array)
        .and_then(|rows| rows.first())
        .cloned();
    Ok(Done::Installed(row))
}

fn refused(message: &str) -> String {
    format!("Could not refresh Grok protection during update: {message}")
}

/// `repair_grok_install`.
fn grok(ctx: &Ctx, fields: &Map<String, Value>) -> (Vec<Value>, Vec<String>) {
    let Some(stored) = active_install(ctx, "grok") else {
        return (Vec::new(), Vec::new());
    };
    match reinstall(ctx, fields, "grok", &stored, true) {
        Ok(Done::Installed(Some(row))) => (vec![row], Vec::new()),
        Ok(Done::Current) => (Vec::new(), Vec::new()),
        Ok(Done::Installed(None)) => (
            Vec::new(),
            vec![refused("managed install was not recorded")],
        ),
        Err(message) => (Vec::new(), vec![refused(&message)]),
    }
}

/// `refresh_bounded_hook_clients`.
fn bounded(ctx: &Ctx, fields: &Map<String, Value>) -> (Vec<Value>, Vec<String>) {
    let scripts = match update_bounded::scripts(ctx) {
        Ok(answer) => answer,
        Err(failure) => {
            // An unavailable, old or slow resident must not stop the repairs
            // after this one.
            return (
                Vec::new(),
                vec![format!(
                    "Could not check bounded hook clients for the native runtime during update: {}",
                    step_message(failure)
                )],
            );
        }
    };
    let mut installs = Vec::new();
    let mut notes = Vec::new();
    for script in scripts
        .get("scripts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let (Some(harness), Some(display)) = (
            script.get("harness").and_then(Value::as_str),
            script.get("display_name").and_then(Value::as_str),
        ) else {
            continue;
        };
        let Some(stored) = active_install(ctx, harness) else {
            continue;
        };
        let moved = reinstall(ctx, fields, harness, &stored, false).and_then(|done| {
            let mut asked = Map::new();
            asked.insert("harness".into(), json!(harness));
            update_bounded::remove(ctx, &asked).map_err(step_message)?;
            Ok(done)
        });
        match moved {
            Ok(Done::Installed(Some(row))) => installs.push(row),
            Ok(Done::Installed(None) | Done::Current) => installs.push(wire_row(&stored)),
            Err(message) => notes.push(format!(
                "Could not move {display} hooks to the native runtime during update: {message}"
            )),
        }
    }
    (installs, notes)
}

pub(super) fn dispatch(ctx: &Ctx, fields: &Map<String, Value>) -> KindResult {
    let (installs, notes) = match fields.get("update").and_then(Value::as_str) {
        Some("grok") => grok(ctx, fields),
        Some("bounded") => bounded(ctx, fields),
        _ => return Err(ERR_INVALID),
    };
    Ok(json!({ "ok": true, "installs": installs, "notes": notes }))
}
