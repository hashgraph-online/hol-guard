//! `POST /v1/apps/{action}`, `GET /v1/runtime` and `GET /v1/local-clis`:
//! the app action table, every refusal, the state a finished action reports,
//! the reconnect summary, the operator health verdict and every reply.
//!
//! The daemon owns the decisions and the bodies. Running an app action,
//! building the runtime snapshot and listing custom extensions are
//! `headless.*`, `runtime.*` and `local_clis.*` Guard library calls
//! (`routes/headless_calls.py`).

use guard_contracts::{ManagedInstallFactV1, VerificationFactV1};
use serde_json::{json, Map, Value};

use super::super::super::http::query_pairs;
use super::super::super::library::{self, CallError};
use super::super::{hook_scheduler, ReadConfig};
use super::supply_chain::truthy;
use super::DROPPED;
use crate::daemon_handler_fields::{query_bool, query_string};
use crate::daemon_handler_headless::{headless_cursor_surface, headless_error, headless_state};
use crate::daemon_handler_op::Reply as Answer;

const RUNTIME_PATH: &str = "/v1/runtime";
const LOCAL_CLIS_PATH: &str = "/v1/local-clis";

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

fn parts(answer: Answer) -> Reply {
    let (_, status, body, _) = answer.into_parts();
    (status, body)
}

fn text(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

/// The `POST /v1/apps/{action}` reply. `None` is a path this module does not
/// answer; `Some(None)` relays the request.
pub(super) fn post(
    path: &str,
    payload: &Map<String, Value>,
    config: &ReadConfig,
    args: Map<String, Value>,
) -> Option<Option<Reply>> {
    let action = path.strip_prefix("/v1/apps/")?;
    if action.is_empty() || action.contains('/') {
        return None;
    }
    let mut call = |name: &str, args: Value| library::call_resident(config, name, args);
    let mut host = Host {
        call: &mut call,
        args,
    };
    Some(finish(app_action(&mut host, action, payload)))
}

/// `(operation, harness action)` for each app action path.
fn action_table(action: &str) -> Option<(&'static str, &'static str)> {
    match action {
        "connect" => Some(("install", "install")),
        "repair" => Some(("repair", "repair")),
        "disconnect" => Some(("remove", "uninstall")),
        "status" => Some(("status", "verify")),
        "test" => Some(("scan", "verify")),
        _ => None,
    }
}

fn app_action(
    host: &mut Host<'_, '_>,
    action: &str,
    payload: &Map<String, Value>,
) -> Result<Reply, Stop> {
    let Some((operation, harness_action)) = action_table(action) else {
        return Ok(parts(headless_error(action, "unsupported_operation")));
    };
    let Some(harness) = text(payload.get("harness")) else {
        return Ok(parts(headless_error(operation, "missing_harness")));
    };
    let answer = host.step(
        "headless.app_action",
        json!({
            "operation": operation,
            "harness_action": harness_action,
            "harness": harness,
            "action_path": action,
            "payload": payload,
        }),
    )?;
    if let Some(reply) = answer.get("reply").and_then(Value::as_array) {
        let status = reply
            .first()
            .and_then(Value::as_u64)
            .and_then(|status| u16::try_from(status).ok())
            .ok_or(Stop::Dropped)?;
        return Ok((status, reply.get(1).cloned().unwrap_or(Value::Null)));
    }
    if let Some(code) = answer.get("error").and_then(Value::as_str) {
        if code == "invalid_cursor_surface" {
            let (status, mut body) = parts(headless_cursor_surface());
            if status == 400 {
                if let Some(error) = body.get_mut("error").and_then(Value::as_object_mut) {
                    let surface = text(payload.get("surface")).unwrap_or_default();
                    error.insert("surface".to_owned(), json!(surface));
                }
            }
            return Ok((status, body));
        }
        return Ok(parts(headless_error(operation, code)));
    }
    let harness = text(answer.get("harness")).ok_or(Stop::Dropped)?.to_owned();
    let result = answer
        .get("result")
        .and_then(Value::as_object)
        .ok_or(Stop::Dropped)?;
    let receipt = answer.get("receipt").cloned().unwrap_or(json!({}));
    let cloud_sync = answer.get("cloud_sync").cloned().unwrap_or(json!({}));
    let mut state = action_state(&harness, operation, result);
    state.insert(
        "receipt_summary".to_owned(),
        json!({
            "id": receipt.get("id"),
            "operation": receipt.get("operation"),
            "status": receipt.get("status"),
            "timestamp": receipt.get("timestamp"),
        }),
    );
    let facts = answer
        .get("reconnect")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let reconnect = reconnect(&facts, &cloud_sync, answer.get("location_id"));
    Ok((
        200,
        json!({
            "cloud_sync": cloud_sync,
            "harness": harness,
            "operation": operation,
            "result": result,
            "receipt": receipt,
            "state": state,
            "reconnect": reconnect,
            "status": "completed",
        }),
    ))
}

fn action_state(harness: &str, operation: &str, result: &Map<String, Value>) -> Map<String, Value> {
    let managed = result.get("managed_install").and_then(Value::as_object);
    let managed = ManagedInstallFactV1 {
        present: managed.is_some(),
        active_truthy: managed.is_some_and(|found| truthy(found.get("active"))),
        active_is_false: managed.is_some_and(|found| found.get("active") == Some(&json!(false))),
    };
    let verification = result
        .get("verification")
        .and_then(Value::as_object)
        .map(|found| VerificationFactV1 {
            installed: truthy(found.get("installed")),
            command_or_config: truthy(found.get("command_available"))
                || truthy(found.get("config_paths")),
        });
    let (_, _, _, fields) =
        headless_state(harness, operation, &managed, &verification).into_parts();
    match fields {
        Value::Object(fields) => fields,
        _ => Map::new(),
    }
}

fn reconciliation_status(cloud_sync: &Value) -> &'static str {
    match text(cloud_sync.get("status")) {
        Some("queued") => "queued",
        Some("in_progress") => "in_progress",
        Some("auth_expired") => "auth_expired",
        Some("not_configured") => "not_configured",
        Some("synced") => "synced",
        _ => "pending",
    }
}

fn correlation_id() -> String {
    let mut bytes = [0u8; 16];
    if getrandom::fill(&mut bytes).is_err() {
        // The id only correlates a reconnect with its receipt; not a secret.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        bytes = nanos.to_le_bytes();
    }
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = hex::encode(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

fn reconnect(facts: &Map<String, Value>, cloud_sync: &Value, location_id: Option<&Value>) -> Value {
    let latest = facts
        .get("latest_cloud_sync")
        .filter(|latest| latest.is_object())
        .cloned()
        .unwrap_or(json!({}));
    let fact = |key: &str| text(facts.get(key)).map_or(Value::Null, |value| json!(value));
    json!({
        "correlation_id": correlation_id(),
        "freshness": {
            "last_receipt_sync_at": text(latest.get("synced_at")),
            "last_runtime_sync_at": fact("last_runtime_sync_at"),
            "local_guard_online_at": fact("local_guard_online_at"),
        },
        "latest_cloud_sync": latest,
        "local_identity": {
            "daemon_id": fact("daemon_id"),
            "daemon_version": facts.get("daemon_version").cloned().unwrap_or(Value::Null),
            "hostname": fact("hostname"),
            "ip_address": null,
            "private_ip_address": null,
            "public_ip_address": null,
        },
        "location_id": text(location_id),
        "reconciliation_status": reconciliation_status(cloud_sync),
    })
}

/// The `GET /v1/runtime` and `GET /v1/local-clis` replies as
/// `(status, body, no_store)`. `None` is a path this module does not answer;
/// `Some(None)` relays the request.
pub(in super::super) fn get(
    path: &str,
    query: &str,
    config: &ReadConfig,
    args: Map<String, Value>,
) -> Option<Option<(u16, Value, bool)>> {
    let mut call = |name: &str, args: Value| library::call_resident(config, name, args);
    let mut host = Host {
        call: &mut call,
        args,
    };
    route_get(path, query, &mut host)
}

fn route_get(
    path: &str,
    query: &str,
    host: &mut Host<'_, '_>,
) -> Option<Option<(u16, Value, bool)>> {
    let (answer, no_store) = match path {
        RUNTIME_PATH => (runtime(host, query), false),
        LOCAL_CLIS_PATH => (local_clis(host, query), true),
        _ => return None,
    };
    Some(finish(answer).map(|(status, body)| (status, body, no_store)))
}

fn runtime(host: &mut Host<'_, '_>, query: &str) -> Result<Reply, Stop> {
    let mut answer = host.step(
        "runtime.snapshot",
        json!({
            "include_receipts": query_bool(query, "include_receipts", true),
            "include_items": query_bool(query, "include_items", true),
            "active_request_id": query_string(query, "active_request_id"),
        }),
    )?;
    let mut body = answer
        .get("snapshot")
        .and_then(Value::as_object)
        .cloned()
        .ok_or(Stop::Dropped)?;
    body.insert(
        "security_level".to_owned(),
        answer.get("security_level").cloned().unwrap_or(Value::Null),
    );
    // The edge admits hooks, so its scheduler is the one whose load counts.
    answer.insert("scheduler".to_owned(), hook_scheduler::shared().stats());
    body.insert("operator_health".to_owned(), operator_health(&answer));
    Ok((200, Value::Object(body)))
}

fn number(map: Option<&Value>, key: &str) -> i64 {
    map.and_then(|map| map.get(key))
        .and_then(Value::as_i64)
        .unwrap_or(0)
}

fn operator_health(answer: &Map<String, Value>) -> Value {
    let scheduler = answer.get("scheduler");
    let writer = answer.get("evidence_writer");
    let activity = answer.get("activity");
    let started = writer
        .and_then(|writer| writer.get("started"))
        .is_none_or(|started| truthy(Some(started)));
    let running = truthy(writer.and_then(|writer| writer.get("running")));
    let evidence_fault = started && !running;
    let store_busy = number(activity, "persistence_error_count") > 0
        && activity
            .and_then(|activity| activity.get("last_error_code"))
            .and_then(Value::as_str)
            .is_some_and(|code| code.starts_with("sqlite."));
    let queued = number(scheduler, "queued");
    let queued_limit = number(scheduler, "queued_limit");
    let active = number(scheduler, "active");
    let active_limit = number(scheduler, "active_limit");
    let saturated = queued_limit > 0 && queued >= queued_limit;
    let (state, cause) = if evidence_fault {
        (
            "saturated",
            "A local processing component stopped and needs repair.",
        )
    } else if store_busy {
        (
            "store-contended",
            "The local evidence store is busy; queued writes are retrying automatically.",
        )
    } else if saturated {
        (
            "saturated",
            "Local review capacity is full; new work waits or receives a typed retry.",
        )
    } else if queued > 0 {
        (
            "backlogged",
            "A short local backlog is waiting behind active reviews.",
        )
    } else {
        (
            "healthy",
            "Local reviews are processing within available capacity.",
        )
    };
    json!({
        "state": state,
        "cause": cause,
        "automatic_recovery": if evidence_fault {
            "Repair restores the stopped local component."
        } else {
            "Guard drains queued work and adjusts ready workers automatically."
        },
        "repairable": evidence_fault,
        "queue_depth": queued,
        "queue_limit": queued_limit,
        "oldest_wait_ms": number(scheduler, "oldest_queued_ms"),
        "workers_busy": active,
        "workers_ready": (active_limit - active).max(0),
        "workers_configured": active_limit,
    })
}

fn identity_filter(query: &str) -> Result<Option<String>, ()> {
    let values: Vec<String> = query_pairs(query)?
        .into_iter()
        .filter(|(name, _)| name == "identity")
        .map(|(_, value)| value)
        .collect();
    match values.as_slice() {
        [] => Ok(None),
        [value]
            if value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) =>
        {
            Ok(Some(value.clone()))
        }
        _ => Err(()),
    }
}

fn local_clis(host: &mut Host<'_, '_>, query: &str) -> Result<Reply, Stop> {
    let Ok(identity) = identity_filter(query) else {
        return Ok((
            400,
            json!({"error": "invalid_identity", "message": "Use a 64-character connector identity."}),
        ));
    };
    let answer = host.step("local_clis.list", json!({ "identity": identity }))?;
    match answer.get("payload") {
        Some(payload @ Value::Object(_)) => Ok((200, payload.clone())),
        _ => Ok((
            500,
            json!({
                "error": "local_cli_unavailable",
                "message": "Guard could not load custom extensions.",
            }),
        )),
    }
}

#[cfg(test)]
#[path = "daemon_edge_headless_tests.rs"]
mod tests;
