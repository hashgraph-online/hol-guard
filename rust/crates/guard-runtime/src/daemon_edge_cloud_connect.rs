//! Guard Cloud connect: `GET`/`POST /v1/cloud/connect` and
//! `POST /v1/supply-chain/package-shims/connect`.
//!
//! The daemon owns whether connect applies, the flow states the dashboard
//! polls, the request id, the one-flow-at-a-time replies and every body. The
//! store facts, the shared flow state, the browser session and its background
//! completion are `connect.*` Guard library calls
//! (`routes/connect_calls.py`) that report their outcome as data.

use serde_json::{json, Map, Value};

use super::super::super::library::{self, CallError};
use super::super::ReadConfig;
use super::DROPPED;

/// `_SUPPLY_CHAIN_CONNECT_POLL_AFTER_MS`: how often the dashboard polls a
/// flow in flight.
const POLL_AFTER_MS: u64 = 1_500;
const CLOUD_PATH: &str = "/v1/cloud/connect";
const PACKAGE_FIREWALL_PATH: &str = "/v1/supply-chain/package-shims/connect";
/// Entitlement reasons package-firewall connect can resolve.
const CONNECT_REASONS: [&str; 2] = [
    "guard_cloud_connect_required",
    "guard_cloud_reconnect_required",
];

type Reply = (u16, Value);
type Call<'a> = dyn FnMut(&str, Value) -> Result<Value, CallError> + 'a;

/// Why a step gave no answer: the library was unreachable (the request is
/// relayed) or raised (the connection drops).
enum Stop {
    Unavailable,
    Dropped,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Cloud,
    PackageFirewall,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::Cloud => "cloud",
            Self::PackageFirewall => "package_firewall",
        }
    }
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

/// The `POST` reply for a connect path. `None` is a path this module does
/// not answer; `Some(None)` relays the request.
pub(super) fn post(
    path: &str,
    config: &ReadConfig,
    args: Map<String, Value>,
) -> Option<Option<Reply>> {
    let mut call = |name: &str, args: Value| library::call_resident(config, name, args);
    let mut host = Host {
        call: &mut call,
        args,
    };
    route_post(path, &mut host)
}

/// The `GET /v1/cloud/connect` reply; `Some(None)` relays the request.
pub(in super::super) fn get(
    path: &str,
    config: &ReadConfig,
    args: Map<String, Value>,
) -> Option<Option<Reply>> {
    if path != CLOUD_PATH {
        return None;
    }
    let mut call = |name: &str, args: Value| library::call_resident(config, name, args);
    let mut host = Host {
        call: &mut call,
        args,
    };
    Some(finish(status(&mut host)))
}

fn route_post(path: &str, host: &mut Host<'_, '_>) -> Option<Option<Reply>> {
    let kind = match path {
        CLOUD_PATH => Kind::Cloud,
        PACKAGE_FIREWALL_PATH => Kind::PackageFirewall,
        _ => return None,
    };
    Some(finish(start(host, kind, &request_id())))
}

fn request_id() -> String {
    let mut bytes = [0u8; 16];
    if getrandom::fill(&mut bytes).is_err() {
        // The id only correlates polls with one flow; it is not a secret.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        bytes = nanos.to_le_bytes();
    }
    format!("guard-connect-{}", hex::encode(bytes))
}

fn text<'a>(map: &'a Map<String, Value>, key: &str) -> &'a str {
    map.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn dashboard_url(connect_url: &str) -> &str {
    connect_url.strip_suffix("/connect").unwrap_or(connect_url)
}

fn in_flight(state: Option<&Value>) -> bool {
    matches!(
        state
            .and_then(|state| state.get("state"))
            .and_then(Value::as_str),
        Some("starting" | "running")
    )
}

/// `_default_guard_cloud_connect_flow` and
/// `_default_package_firewall_connect_flow`: the idle flow.
fn default_flow(kind: Kind, connect_url: &str, repair: bool) -> Map<String, Value> {
    let (title, detail, action_label) = match (kind, repair) {
        (Kind::Cloud, true) => (
            "Repair Guard Cloud access to publish insights",
            "Guard Cloud sign-in on this machine needs repair before it can publish a public share \
             link. Start local connect here and finish approval in your browser.",
            "Repair Guard Cloud access",
        ),
        (Kind::Cloud, false) => (
            "Connect Guard Cloud to publish insights",
            "Local Guard remains available. Connect Guard Cloud here so the daemon can publish a \
             public share link with preview image support.",
            "Connect Guard Cloud",
        ),
        (Kind::PackageFirewall, true) => (
            "Repair Guard Cloud access to restore package firewall",
            "Guard already has package-firewall coverage for this machine, but the local cloud \
             authorization is not usable right now. Repair it here and Guard will unlock the \
             firewall again.",
            "Repair Guard Cloud access",
        ),
        (Kind::PackageFirewall, false) => (
            "Connect HOL Guard Cloud to enable package firewall",
            "Guard continues running locally. Connect HOL Guard Cloud here so the daemon can \
             verify package-firewall access before it changes package-manager routing.",
            "Connect HOL Guard Cloud",
        ),
    };
    let mut flow = json!({
        "state": "idle",
        "title": title,
        "detail": detail,
        "action_label": action_label,
        "connect_url": connect_url,
        "authorize_url": null,
        "browser_opened": null,
        "request_id": null,
        "poll_after_ms": null,
    });
    if kind == Kind::Cloud {
        flow["purpose"] = json!("insights_share");
    }
    match flow {
        Value::Object(flow) => flow,
        _ => Map::new(),
    }
}

fn with(mut flow: Map<String, Value>, fields: Value) -> Value {
    if let Value::Object(fields) = fields {
        flow.extend(fields);
    }
    Value::Object(flow)
}

/// `_resolve_guard_cloud_connect_flow`: the flow the insights modal shows,
/// or `None` when Guard Cloud connect is not required.
fn resolve_flow(facts: &Map<String, Value>) -> Value {
    if facts.get("required") != Some(&Value::Bool(true)) {
        return Value::Null;
    }
    let default = default_flow(
        Kind::Cloud,
        text(facts, "connect_url"),
        facts.get("repair") == Some(&Value::Bool(true)),
    );
    let package = facts.get("package_state");
    let current = if in_flight(package) {
        package
    } else {
        facts.get("cloud_state")
    };
    let Some(Value::Object(current)) = current else {
        return Value::Object(default);
    };
    let state = current
        .get("state")
        .and_then(Value::as_str)
        .filter(|state| !state.is_empty())
        .unwrap_or("idle")
        .to_owned();
    let mut flow = default;
    flow.extend(current.clone());
    match state.as_str() {
        "starting" | "running" => {
            let detail = if flow.get("browser_opened") == Some(&Value::Bool(true)) {
                "HOL Guard opened the secure sign-in flow in your browser. Finish sign-in there and \
                 this modal will unlock public sharing automatically."
            } else if state == "starting" {
                "HOL Guard is opening the secure sign-in flow in your browser."
            } else {
                "HOL Guard is waiting for browser approval. Open the sign-in page below if your \
                 browser did not open automatically."
            };
            flow.insert(
                "title".to_owned(),
                json!("Finish Guard Cloud sign-in in your browser"),
            );
            flow.insert("detail".to_owned(), json!(detail));
            flow.insert("poll_after_ms".to_owned(), json!(POLL_AFTER_MS));
        }
        "failed" => {
            flow.insert(
                "title".to_owned(),
                json!("Guard Cloud sign-in needs attention"),
            );
            flow.insert("poll_after_ms".to_owned(), Value::Null);
        }
        _ => {}
    }
    Value::Object(flow)
}

fn status(host: &mut Host<'_, '_>) -> Result<Reply, Stop> {
    let facts = host.step("connect.facts", json!({ "kind": "cloud" }))?;
    let flow = resolve_flow(&facts);
    Ok((
        200,
        json!({
            "connect_required": !flow.is_null(),
            "connect_flow": flow,
            "dashboard_url": dashboard_url(text(&facts, "connect_url")),
        }),
    ))
}

/// The cloud route wraps its flow; package-firewall connect replies with it.
fn wrap(kind: Kind, flow: Value, message: Option<&str>) -> Value {
    match kind {
        Kind::PackageFirewall => flow,
        Kind::Cloud => {
            let mut body = json!({ "connect_required": true, "connect_flow": flow });
            if let Some(message) = message {
                body["message"] = json!(message);
            }
            body
        }
    }
}

fn start(host: &mut Host<'_, '_>, kind: Kind, request_id: &str) -> Result<Reply, Stop> {
    let mut reason = String::new();
    if kind == Kind::PackageFirewall {
        let entitlement = host.step("supply_chain.entitlement", Value::Null)?;
        reason = text(&entitlement, "reason").trim().to_lowercase();
        if !CONNECT_REASONS.contains(&reason.as_str()) {
            return Ok((
                409,
                json!({
                    "error": "guard_cloud_connect_not_required",
                    "entitlement": entitlement,
                    "message": "Guard Cloud connect is not required for package firewall on this machine.",
                }),
            ));
        }
    }
    let facts = host.step(
        "connect.facts",
        json!({ "kind": kind.name(), "reason": reason }),
    )?;
    let connect_url = text(&facts, "connect_url").to_owned();
    if kind == Kind::Cloud && facts.get("required") != Some(&Value::Bool(true)) {
        return Ok((
            409,
            json!({
                "error": "guard_cloud_connect_not_required",
                "connect_required": false,
                "connect_flow": null,
                "dashboard_url": dashboard_url(&connect_url),
                "message": "Guard Cloud connect is not required to publish insights from this machine.",
            }),
        ));
    }
    let default = default_flow(
        kind,
        &connect_url,
        facts.get("repair") == Some(&Value::Bool(true)),
    );
    let starting = with(
        default.clone(),
        json!({
            "state": "starting",
            "title": "Opening Guard Cloud sign-in",
            "detail": "HOL Guard is opening the secure sign-in flow in your browser.",
            "request_id": request_id,
            "poll_after_ms": POLL_AFTER_MS,
        }),
    );
    let begun = host.step(
        "connect.begin",
        json!({ "kind": kind.name(), "state": starting }),
    )?;
    if begun.get("started") != Some(&Value::Bool(true)) {
        let current = begun.get("current").cloned().unwrap_or(Value::Null);
        return Ok((202, wrap(kind, current, None)));
    }
    let opened = match host.step("connect.open", json!({ "connect_url": connect_url })) {
        Ok(opened) => opened,
        Err(stop) => {
            // Never leave the flow in flight when the session could not open.
            let failure = failed(&default, "Guard Cloud sign-in could not start.");
            let _ = host.step(
                "connect.set_state",
                json!({ "kind": kind.name(), "state": failure }),
            );
            return Err(stop);
        }
    };
    if let Some(error) = opened.get("error").and_then(Value::as_str) {
        let failure = failed(&default, error);
        host.step(
            "connect.set_state",
            json!({ "kind": kind.name(), "state": failure }),
        )?;
        return Ok((500, wrap(kind, failure, Some(error))));
    }
    let browser_opened = opened.get("browser_opened") == Some(&Value::Bool(true));
    let unlocks = match kind {
        Kind::Cloud => "this modal will unlock public sharing automatically.",
        Kind::PackageFirewall => "this page will unlock package-firewall controls automatically.",
    };
    let detail = if browser_opened {
        format!(
            "HOL Guard opened the secure sign-in flow in your browser. Finish sign-in there and \
             {unlocks}"
        )
    } else {
        "HOL Guard is waiting for browser approval. Open the sign-in page below if your browser \
         did not open automatically."
            .to_owned()
    };
    let running = with(
        default,
        json!({
            "state": "running",
            "title": "Finish Guard Cloud sign-in in your browser",
            "detail": detail,
            "authorize_url": opened.get("authorize_url").cloned().unwrap_or(Value::Null),
            "browser_opened": browser_opened,
            "request_id": request_id,
            "poll_after_ms": POLL_AFTER_MS,
        }),
    );
    host.step(
        "connect.run",
        json!({
            "kind": kind.name(),
            "session_id": opened.get("session_id").cloned().unwrap_or(Value::Null),
            "connect_url": connect_url,
            "browser_opened": browser_opened,
            "state": running,
        }),
    )?;
    Ok((202, wrap(kind, running, None)))
}

fn failed(default: &Map<String, Value>, detail: &str) -> Value {
    with(
        default.clone(),
        json!({
            "state": "failed",
            "detail": detail,
            "browser_opened": false,
            "poll_after_ms": null,
        }),
    )
}

#[cfg(test)]
#[path = "daemon_edge_cloud_connect_tests.rs"]
mod tests;
