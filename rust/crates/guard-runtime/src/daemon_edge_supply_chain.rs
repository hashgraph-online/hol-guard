//! The `/v1/supply-chain/*` control routes: package protection status, its
//! actions, the full repair and the project folder picker.
//!
//! The daemon owns dispatch, the per-workspace action rate limit, the
//! one-change-at-a-time mutation lock, manager validation, the approval gate
//! and every reply. Entitlement, workspace resolution and the package shim
//! work itself are `supply_chain.*` Guard library calls
//! (`routes/supply_chain_calls.py`) that report their outcome as data.

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};

use super::super::super::library::{self, CallError};
use super::super::ReadConfig;
use super::gate::{self, Gate};
use super::DROPPED;

/// `PackageFirewallActionRateLimiter()`: 30 actions a minute per key.
const RATE_LIMIT: usize = 30;
const RATE_WINDOW: Duration = Duration::from_secs(60);

const PACKAGE_ACTIONS: [&str; 10] = [
    "activate",
    "install",
    "repair",
    "test",
    "audit",
    "sync",
    "remove",
    "uninstall",
    "connect",
    "open-shell",
];
/// Package actions that change shims or the runtime run one at a time.
const MUTATING_ACTIONS: [&str; 7] = [
    "install",
    "repair",
    "uninstall",
    "remove",
    "activate",
    "open-shell",
    "sync",
];
/// Operations that need the approval gate's high-risk proof.
const GATED_OPERATIONS: [&str; 5] = ["install", "repair", "remove", "test", "sync"];

const AUTHORITY_UNAVAILABLE: &str = "package_firewall_authority_unavailable";
const AUTHORITY_UNAVAILABLE_MESSAGE: &str =
    "The HOL Guard runtime could not answer what package firewall access permits on this machine.";
const WORKSPACE_UNAVAILABLE: &str = "supply_chain_workspace_unavailable";

type Reply = (u16, Value);

/// Why a step gave no answer: the library was unreachable (the request is
/// relayed) or raised (the connection drops).
enum Stop {
    Unavailable,
    Dropped,
}

/// Runs one library call by name.
type Call<'a> = dyn FnMut(&str, Value) -> Result<Value, CallError> + 'a;
/// Runs `require_high_risk(purpose="supply_chain_firewall")` on a payload.
type Check<'a> = dyn FnMut(&Map<String, Value>) -> Option<Gate> + 'a;

struct Host<'a, 'b> {
    call: &'a mut Call<'b>,
    gate: &'a mut Check<'b>,
    guard_home: &'a str,
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

/// The `POST` reply for a supply-chain path. `None` is a path this module
/// does not answer; `Some(None)` relays the request.
pub(super) fn post(
    path: &str,
    payload: &Map<String, Value>,
    config: &ReadConfig,
    args: Map<String, Value>,
) -> Option<Option<Reply>> {
    let mut call = |name: &str, args: Value| library::call_resident(config, name, args);
    let mut check = |input: &Map<String, Value>| {
        gate::require_high_risk("supply_chain_firewall", input, config)
    };
    let mut host = Host {
        call: &mut call,
        gate: &mut check,
        guard_home: &config.guard_home,
        args,
    };
    route_post(path, payload, &mut host)
}

/// The `GET` reply for `/v1/supply-chain/package-shims` and
/// `/v1/supply-chain/entitlement`; `Some(None)` relays the request.
pub(in super::super) fn get(
    path: &str,
    config: &ReadConfig,
    args: Map<String, Value>,
) -> Option<Option<Reply>> {
    let mut call = |name: &str, args: Value| library::call_resident(config, name, args);
    let mut check = |_: &Map<String, Value>| None;
    let mut host = Host {
        call: &mut call,
        gate: &mut check,
        guard_home: &config.guard_home,
        args,
    };
    route_get(path, &mut host)
}

fn route_get(path: &str, host: &mut Host<'_, '_>) -> Option<Option<Reply>> {
    match path {
        "/v1/supply-chain/entitlement" => Some(finish(
            host.step("supply_chain.entitlement", Value::Null)
                .map(|entitlement| (200, Value::Object(entitlement))),
        )),
        "/v1/supply-chain/package-shims" => Some(finish(status(host))),
        _ => None,
    }
}

fn route_post(
    path: &str,
    payload: &Map<String, Value>,
    host: &mut Host<'_, '_>,
) -> Option<Option<Reply>> {
    let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    match parts.as_slice() {
        ["v1", "supply-chain", "repair"] => Some(mutation(host, "repair_all", |host| {
            repair_all(host, payload)
        })),
        ["v1", "supply-chain", "choose-folder"] => Some(finish(choose_folder(host))),
        ["v1", "supply-chain", "package-shims", "connect"] => None,
        ["v1", "supply-chain", "package-shims", action] if PACKAGE_ACTIONS.contains(action) => {
            let action = *action;
            if MUTATING_ACTIONS.contains(&action) {
                Some(mutation(host, action, |host| {
                    package_action(host, action, payload)
                }))
            } else {
                Some(finish(package_action(host, action, payload)))
            }
        }
        ["v1", "supply-chain", "sync"] => Some(mutation(host, "sync", |host| {
            package_action(host, "sync", payload)
        })),
        ["v1", "supply-chain", "audit"] => Some(finish(package_action(host, "audit", payload))),
        _ => None,
    }
}

fn locks() -> &'static Mutex<HashSet<String>> {
    static LOCKS: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    LOCKS.get_or_init(Mutex::default)
}

/// The package-protection mutation lock for one Guard home, released on drop.
struct Held(String);

impl Drop for Held {
    fn drop(&mut self) {
        locks()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.0);
    }
}

fn hold(guard_home: &str) -> Option<Held> {
    let mut held = locks().lock().unwrap_or_else(PoisonError::into_inner);
    held.insert(guard_home.to_owned())
        .then(|| Held(guard_home.to_owned()))
}

/// Runs `action` holding the mutation lock; a change already running is a
/// `409` that names the requested operation.
fn mutation(
    host: &mut Host<'_, '_>,
    operation: &str,
    action: impl FnOnce(&mut Host<'_, '_>) -> Result<Reply, Stop>,
) -> Option<Reply> {
    let Some(_held) = hold(host.guard_home) else {
        return Some((
            409,
            json!({
                "error": "operation_in_progress",
                "message": "Guard is still finishing a package protection change. Check its status before retrying.",
                "operation": operation,
            }),
        ));
    };
    finish(action(host))
}

/// `allow(key)`: `Err(retry_after_seconds)` once the window is full.
fn rate_limit(key: String, now: Instant) -> Result<(), u64> {
    static EVENTS: OnceLock<Mutex<HashMap<String, Vec<Instant>>>> = OnceLock::new();
    let mut events = EVENTS
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let bucket = events.entry(key).or_default();
    bucket.retain(|at| now.saturating_duration_since(*at) < RATE_WINDOW);
    if let Some(first) = bucket.first().filter(|_| bucket.len() >= RATE_LIMIT) {
        let left = RATE_WINDOW.saturating_sub(now.saturating_duration_since(*first));
        return Err(left.as_secs().max(1));
    }
    bucket.push(now);
    Ok(())
}

fn text(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

/// The rate-limit refusal, or `None` when the action may run.
fn limited(
    host: &mut Host<'_, '_>,
    operation: &str,
    payload: &Map<String, Value>,
) -> Result<Option<Reply>, Stop> {
    let mut workspace = text(payload.get("workspace_id"))
        .or_else(|| text(payload.get("workspaceId")))
        .map(str::to_owned);
    if workspace.is_none() {
        let answer = host.step("supply_chain.workspace_id", Value::Null)?;
        workspace = text(answer.get("workspace_id")).map(str::to_owned);
    }
    let workspace = workspace.unwrap_or_else(|| "local".to_owned());
    let key = format!("{}\u{0}{workspace}:{operation}", host.guard_home);
    Ok(rate_limit(key, Instant::now()).err().map(|retry| {
        (
            429,
            json!({
                "error": "rate_limited",
                "message": "Package firewall actions are temporarily rate limited.",
                "operation": operation,
                "retry_after_seconds": retry,
            }),
        )
    }))
}

fn workspace_unavailable(operation: &str) -> Reply {
    (
        503,
        json!({
            "error": WORKSPACE_UNAVAILABLE,
            "message": "Guard could not check the project folder right now. Try again in a moment.",
            "operation": operation,
        }),
    )
}

/// `_supply_chain_value_error_payload`.
fn value_error(operation: &str, code: &str) -> Reply {
    let mut body = json!({ "error": code, "operation": operation });
    let message = match code {
        "workspace_dir_required" => Some(
            "Guard needs a project folder with package manifests before it can run the workspace audit. \
             Choose a local project folder and try again.",
        ),
        "workspace_dir_invalid" => Some(
            "Guard could not use the selected project folder. \
             Choose an existing folder inside your home folder and try again.",
        ),
        _ => None,
    };
    if let Some(message) = message {
        body["message"] = Value::from(message);
    }
    (400, body)
}

fn authority_unavailable(entitlement: &Value, operation: &str) -> Reply {
    (
        503,
        json!({
            "available_actions": [],
            "entitlement": entitlement,
            "error": AUTHORITY_UNAVAILABLE,
            "message": AUTHORITY_UNAVAILABLE_MESSAGE,
            "operation": operation,
        }),
    )
}

/// What `prepare` settled: the entitlement and the access verdict, or the
/// reply that ends the request.
struct Prepared {
    entitlement: Value,
    access: Map<String, Value>,
    supported_managers: Vec<String>,
}

fn prepare(
    host: &mut Host<'_, '_>,
    operation: &str,
    access_operation: &str,
    reported: &str,
    payload: &Map<String, Value>,
) -> Result<Result<Prepared, Reply>, Stop> {
    let answer = host.step(
        "supply_chain.prepare",
        json!({
            "operation": operation,
            "access_operation": access_operation,
            "payload": payload,
        }),
    )?;
    let entitlement = answer.get("entitlement").cloned().unwrap_or(Value::Null);
    match answer.get("workspace").and_then(Value::as_str) {
        Some("ok") => {}
        Some("unavailable") => return Ok(Err(workspace_unavailable(reported))),
        Some("invalid") => {
            let code = text(answer.get("error")).unwrap_or("workspace_dir_invalid");
            return Ok(Err(value_error(reported, code)));
        }
        _ => return Err(Stop::Dropped),
    }
    let Some(access) = answer.get("access").and_then(Value::as_object).cloned() else {
        return Ok(Err(authority_unavailable(&entitlement, reported)));
    };
    let supported_managers = answer
        .get("supported_managers")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    Ok(Ok(Prepared {
        entitlement,
        access,
        supported_managers,
    }))
}

/// The access block as `(status, error, message)`.
fn block(access: &Map<String, Value>) -> Option<(u16, Value, Value)> {
    let block = access.get("block")?.as_array()?;
    let status = u16::try_from(block.first()?.as_u64()?).ok()?;
    Some((status, block.get(1)?.clone(), block.get(2)?.clone()))
}

fn allowed(access: &Map<String, Value>) -> bool {
    access.get("operation_allowed") == Some(&Value::Bool(true))
}

/// `_supply_chain_managers`: the normalized list, or the error code.
fn managers(
    payload: &Map<String, Value>,
    supported: &[String],
) -> Result<Option<Vec<String>>, &'static str> {
    let Some(value) = payload.get("managers").filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let Some(items) = value.as_array() else {
        return Err("invalid_managers");
    };
    let mut normalized = Vec::new();
    for item in items {
        let Some(item) = item.as_str() else {
            return Err("invalid_managers");
        };
        let item = item.trim();
        if !item.is_empty() {
            normalized.push(item.to_lowercase());
        }
    }
    let unique: HashSet<&String> = normalized.iter().collect();
    if unique.len() != normalized.len() {
        return Err("duplicate_manager");
    }
    if normalized.is_empty() {
        return Err("invalid_managers");
    }
    if !normalized.iter().all(|manager| supported.contains(manager)) {
        return Err("unsupported_manager");
    }
    Ok(Some(normalized))
}

fn gate_refusal(
    host: &mut Host<'_, '_>,
    payload: &Map<String, Value>,
) -> Result<Option<Reply>, Stop> {
    match (host.gate)(payload) {
        Some(Gate::Passed(_)) => Ok(None),
        Some(Gate::Refused(status, body)) => Ok(Some((status, Value::Object(body)))),
        None => Err(Stop::Unavailable),
    }
}

fn package_action(
    host: &mut Host<'_, '_>,
    action: &str,
    payload: &Map<String, Value>,
) -> Result<Reply, Stop> {
    let operation = match action {
        "uninstall" => "remove",
        "open-shell" => "activate",
        other => other,
    };
    if let Some(refusal) = limited(host, operation, payload)? {
        return Ok(refusal);
    }
    let prepared = match prepare(host, operation, operation, operation, payload)? {
        Ok(prepared) => prepared,
        Err(reply) => return Ok(reply),
    };
    if !allowed(&prepared.access) {
        let (status, error, message) = block(&prepared.access).ok_or(Stop::Dropped)?;
        return Ok((
            status,
            json!({
                "available_actions": prepared.access.get("available_actions").cloned().unwrap_or(json!([])),
                "entitlement": prepared.entitlement,
                "error": error,
                "message": message,
                "operation": operation,
            }),
        ));
    }
    let managers = match managers(payload, &prepared.supported_managers) {
        Ok(managers) => managers,
        Err(code) => return Ok((400, json!({ "error": code, "operation": operation }))),
    };
    if GATED_OPERATIONS.contains(&operation) {
        if let Some(refusal) = gate_refusal(host, payload)? {
            return Ok(refusal);
        }
    }
    let answer = host.step(
        "supply_chain.run",
        json!({ "operation": operation, "payload": payload, "managers": managers }),
    )?;
    if let Some(reply) = answer.get("reply").and_then(Value::as_array) {
        let status = reply
            .first()
            .and_then(Value::as_u64)
            .and_then(|status| u16::try_from(status).ok())
            .ok_or(Stop::Dropped)?;
        return Ok((status, reply.get(1).cloned().unwrap_or(Value::Null)));
    }
    if answer.get("workspace").and_then(Value::as_str) == Some("unavailable") {
        return Ok(workspace_unavailable(operation));
    }
    if let Some(code) = text(answer.get("value_error")) {
        return Ok(value_error(operation, code));
    }
    let result = answer
        .get("result")
        .filter(|result| result.is_object())
        .ok_or(Stop::Dropped)?;
    let incomplete = operation == "audit"
        && result.get("audit_status").and_then(Value::as_str) == Some("incomplete");
    let mut body = json!({
        "entitlement": prepared.entitlement,
        "operation": operation,
        "receipt": answer.get("receipt").cloned().unwrap_or(Value::Null),
        "result": result,
        "status": if incomplete { "incomplete" } else { "completed" },
    });
    if let Some(cloud_sync) = answer.get("cloud_sync") {
        body["cloud_sync"] = cloud_sync.clone();
    }
    Ok((200, body))
}

fn repair_all(host: &mut Host<'_, '_>, payload: &Map<String, Value>) -> Result<Reply, Stop> {
    if let Some(refusal) = limited(host, "repair", payload)? {
        return Ok(refusal);
    }
    let prepared = match prepare(host, "repair_all", "repair", "repair_all", payload)? {
        Ok(prepared) => prepared,
        Err(reply) => return Ok(reply),
    };
    if !allowed(&prepared.access) {
        let (status, error, message) = block(&prepared.access).ok_or(Stop::Dropped)?;
        return Ok((
            status,
            json!({
                "entitlement": prepared.entitlement,
                "error": error,
                "message": message,
                "operation": "repair_all",
            }),
        ));
    }
    if let Some(refusal) = gate_refusal(host, payload)? {
        return Ok(refusal);
    }
    let install_missing = truthy(prepared.entitlement.get("allowed"));
    let answer = host.step(
        "supply_chain.repair_all",
        json!({ "payload": payload, "install_missing": install_missing }),
    )?;
    if answer.get("workspace").and_then(Value::as_str) == Some("unavailable") {
        return Ok(workspace_unavailable("repair_all"));
    }
    let result = answer
        .get("result")
        .filter(|result| result.is_object())
        .ok_or(Stop::Dropped)?;
    let repaired = result.get("repaired") == Some(&Value::Bool(true));
    Ok((
        200,
        json!({
            "entitlement": prepared.entitlement,
            "operation": "repair_all",
            "receipt": answer.get("receipt").cloned().unwrap_or(Value::Null),
            "result": result,
            "status": if repaired { "completed" } else { "incomplete" },
        }),
    ))
}

/// Python truthiness for a JSON value.
fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(Value::Number(number)) => number.as_f64().is_some_and(|number| number != 0.0),
        Some(Value::String(text)) => !text.is_empty(),
        Some(Value::Array(items)) => !items.is_empty(),
        Some(Value::Object(map)) => !map.is_empty(),
    }
}

fn status(host: &mut Host<'_, '_>) -> Result<Reply, Stop> {
    let answer = host.step("supply_chain.status", Value::Null)?;
    let entitlement = answer.get("entitlement").cloned().unwrap_or(Value::Null);
    let Some(access) = answer.get("access").and_then(Value::as_object) else {
        return Ok(authority_unavailable(&entitlement, "status"));
    };
    if answer.get("workspace").and_then(Value::as_str) != Some("ok") {
        return Ok(workspace_unavailable("status"));
    }
    let field = |key: &str| answer.get(key).cloned().unwrap_or(Value::Null);
    Ok((
        200,
        json!({
            "actions": access.get("action_states").cloned().unwrap_or(Value::Null),
            "audit_workspace_dir": field("audit_workspace_dir"),
            "cli_fallback": {
                "connect": "hol-guard connect",
                "install": "hol-guard package-shims install --json",
                "status": "hol-guard package-shims status --json",
                "remove": "hol-guard package-shims uninstall --json",
            },
            "connect_flow": field("connect_flow"),
            "entitlement": entitlement,
            "operation": "status",
            "status": "completed",
            "supported_managers": field("supported_managers"),
            "package_shims": field("package_shims"),
        }),
    ))
}

fn choose_folder(host: &mut Host<'_, '_>) -> Result<Reply, Stop> {
    const OPERATION: &str = "choose-folder";
    let answer = host.step("supply_chain.choose_folder", Value::Null)?;
    Ok(match answer.get("picker").and_then(Value::as_str) {
        Some("busy") => (
            409,
            json!({
                "error": "folder_picker_busy",
                "message": "A folder selection is already open.",
                "operation": OPERATION,
            }),
        ),
        Some("unavailable") => (
            503,
            json!({
                "error": "folder_picker_unavailable",
                "message": "Folder selection is unavailable. Paste a project folder path instead.",
                "operation": OPERATION,
            }),
        ),
        Some("cancelled") => (
            200,
            json!({ "cancelled": true, "operation": OPERATION, "workspace_dir": null }),
        ),
        Some("chosen") => match answer.get("workspace").and_then(Value::as_str) {
            Some("ok") => (
                200,
                json!({
                    "cancelled": false,
                    "operation": OPERATION,
                    "workspace_dir": answer.get("workspace_dir").cloned().unwrap_or(Value::Null),
                }),
            ),
            Some("unavailable") => workspace_unavailable(OPERATION),
            _ => value_error(
                OPERATION,
                text(answer.get("error")).unwrap_or("workspace_dir_invalid"),
            ),
        },
        _ => return Err(Stop::Dropped),
    })
}

#[cfg(all(test, unix))]
#[path = "daemon_edge_supply_chain_tests.rs"]
mod tests;
