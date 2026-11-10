//! `GET /v1/update/status` and `POST /v1/update`: whether this install can
//! update, the refusals, the Desktop hand-off and every reply.
//!
//! The daemon owns the decision and the bodies. Reading the install's update
//! status, recording a Desktop hand-off and starting the detached update
//! runner are `update.*` Guard library calls (`routes/update_calls.py`).

use serde_json::{json, Map, Value};

use super::super::super::library::{self, CallError};
use super::super::ReadConfig;
use super::supply_chain::truthy;
use super::DROPPED;

const UPDATE_PATH: &str = "/v1/update";
const STATUS_PATH: &str = "/v1/update/status";
const LATEST: &str = "Guard is already on the latest version.";

type Reply = (u16, Value);
type Call<'a> = dyn FnMut(&str, Value) -> Result<Value, CallError> + 'a;

/// Why a step gave no answer: the library was unreachable (the request is
/// relayed) or raised (the connection drops).
enum Stop {
    Unavailable,
    Dropped,
}

struct Host<'a, 'b> {
    call: &'a mut Call<'b>,
    args: Map<String, Value>,
}

impl Host<'_, '_> {
    fn step(&mut self, name: &str, extra: Value) -> Result<Map<String, Value>, Stop> {
        let mut args = self.args.clone();
        if let Value::Object(extra) = extra {
            args.extend(extra);
        }
        match (self.call)(name, Value::Object(args)) {
            Ok(Value::Object(answer)) => Ok(answer),
            Ok(_) | Err(CallError::Raised(_)) => Err(Stop::Dropped),
            Err(CallError::Unavailable) => Err(Stop::Unavailable),
        }
    }
}

/// `None` relays the request; a dropped step drops the connection.
fn finish(answer: Result<Reply, Stop>) -> Option<Reply> {
    match answer {
        Ok(reply) => Some(reply),
        Err(Stop::Unavailable) => None,
        Err(Stop::Dropped) => Some((DROPPED, Value::Null)),
    }
}

/// The `POST /v1/update` reply. `None` is a path this module does not
/// answer; `Some(None)` relays the request.
pub(super) fn post(
    path: &str,
    payload: &Map<String, Value>,
    config: &ReadConfig,
    args: Map<String, Value>,
) -> Option<Option<Reply>> {
    if path != UPDATE_PATH {
        return None;
    }
    let mut call = |name: &str, args: Value| library::call_resident(config, name, args);
    let mut host = Host {
        call: &mut call,
        args,
    };
    Some(finish(update(&mut host, payload)))
}

/// The `GET /v1/update/status` reply, sent `no-store`; `Some(None)` relays
/// the request.
pub(in super::super) fn get(
    path: &str,
    config: &ReadConfig,
    args: Map<String, Value>,
) -> Option<Option<Reply>> {
    if path != STATUS_PATH {
        return None;
    }
    let mut call = |name: &str, args: Value| library::call_resident(config, name, args);
    let mut host = Host {
        call: &mut call,
        args,
    };
    Some(finish(status(&mut host)))
}

fn status(host: &mut Host<'_, '_>) -> Result<Reply, Stop> {
    let status = host.step("update.status", json!({ "progress": true }))?;
    Ok((200, Value::Object(status)))
}

fn refused(error: &str, message: Value) -> Reply {
    (400, json!({ "error": error, "message": message }))
}

/// `status.get("blocked_reason") or fallback`.
fn blocked_reason(status: &Map<String, Value>, fallback: &str) -> Value {
    match status.get("blocked_reason") {
        Some(reason) if truthy(Some(reason)) => reason.clone(),
        _ => json!(fallback),
    }
}

fn update(host: &mut Host<'_, '_>, payload: &Map<String, Value>) -> Result<Reply, Stop> {
    let force = truthy(payload.get("force_pypi_reinstall"));
    let status = host.step("update.status", Value::Null)?;
    if payload.get("handoff_to_desktop") == Some(&Value::Bool(true)) {
        return handoff(host, &status);
    }
    let flag = |key: &str| status.get(key) == Some(&Value::Bool(true));
    if flag("python_update_required") {
        return Ok(refused(
            "update_not_supported",
            blocked_reason(&status, "Update requires a different Python runtime."),
        ));
    }
    if force && !truthy(status.get("recovery_reinstall_available")) {
        return Ok(refused(
            "update_not_supported",
            blocked_reason(&status, "Reinstall is not available for this install."),
        ));
    }
    if !flag("auto_updatable") && !force {
        return Ok(refused(
            "update_not_supported",
            blocked_reason(&status, "Automatic update is not available."),
        ));
    }
    if !flag("update_available") && !force {
        return Ok(refused("update_not_available", json!(LATEST)));
    }
    let include_alpha = status.get("release_channel").and_then(Value::as_str) == Some("alpha");
    let scheduled = host.step(
        "update.schedule",
        json!({
            "force_pypi_reinstall": force,
            "include_alpha": include_alpha,
            "status": status,
        }),
    )?;
    Ok((200, Value::Object(scheduled)))
}

/// Records the dashboard's request for Desktop to open its updater. Only a
/// Desktop-managed install with a newer release has one to hand off to;
/// Desktop re-verifies the release itself.
fn handoff(host: &mut Host<'_, '_>, status: &Map<String, Value>) -> Result<Reply, Stop> {
    if status.get("installer").and_then(Value::as_str) != Some("desktop") {
        return Ok(refused(
            "desktop_handoff_unavailable",
            json!("This install is not managed by the HOL Guard app."),
        ));
    }
    let latest = status
        .get("latest_version")
        .filter(|latest| latest.is_string());
    let (true, Some(latest)) = (
        status.get("update_available") == Some(&Value::Bool(true)),
        latest,
    ) else {
        return Ok(refused("update_not_available", json!(LATEST)));
    };
    let recorded = host.step("update.handoff", json!({ "latest_version": latest }))?;
    if recorded.get("recorded") != Some(&Value::Bool(true)) {
        return Ok((
            500,
            json!({
                "error": "desktop_handoff_failed",
                "message": "The update request could not be recorded. Try again.",
            }),
        ));
    }
    Ok((
        200,
        json!({
            "handoff_requested": true,
            "current_version": status.get("current_version").cloned().unwrap_or(Value::Null),
            "latest_version": latest,
        }),
    ))
}

#[cfg(test)]
#[path = "daemon_edge_update_tests.rs"]
mod tests;
