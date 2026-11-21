//! The `command_lease` action of `cloud-event-sync`: lease the next Guard
//! Cloud command job, exact Cloud Review jobs first. Ported from
//! `lease_next_job` in `runtime/exact_cloud_review_transport.py` and
//! `command_queue_lease_payload` in `runtime/command_queue_state.py`.
//!
//! The runtime builds each lease body, sends it through the `request` action's
//! signed transport, checks the Cloud Review protocol version and picks the
//! extra exact jobs a batch lease returned. The caller keeps its queue state:
//! the answer reports what to record (the exact route's health, the batch
//! limit Guard Cloud advertised and each response's policy revision) beside
//! the leased job, and a `failure` the caller raises after
//! recording them, with the route base whose lease failed. A generic lease
//! that fails outright after the exact route answered reports its error as
//! `sync`, so that state is still recorded.

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::cloud_bundle_command::failure;
use crate::cloud_bundle_fetch::SyncError;
use crate::cloud_event_sync::trusted_base;
use crate::cloud_json_request::{send, JsonRequest};

/// The one operation the exact Cloud Review route leases.
pub(crate) const EXACT_OPERATION: &str = "guard.review.resolveExact";
pub(crate) const EXACT_PROTOCOL_VERSION: i64 = 2;
pub(crate) const QUEUE_BASE: &str = "/api/guard/commands";
pub(crate) const EXACT_BASE: &str = "/api/guard/review/v2/commands";
const PROTOCOL_UPGRADE: &str = "cloud_review_protocol_upgrade_required";
/// A lease waits on Guard Cloud's long poll; a gateway error is retried after
/// a short pause rather than the minute a sync waits.
pub(crate) const TIMEOUT_SECONDS: f64 = 35.0;
pub(crate) const RETRY_TIMEOUT_SECONDS: f64 = 60.0;

/// What the caller asks to lease, and the fields every lease body carries.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct LeaseCall {
    operations: Vec<String>,
    wait_ms: i64,
    /// How many exact Review jobs one lease may return.
    max_jobs: i64,
    /// Whether the caller settles the extra exact jobs a batch returns.
    collect_extras: bool,
    workspace_id: String,
    device_id: String,
    daemon_version: String,
    /// The schema version of each generic operation Guard knows.
    #[serde(default)]
    schema_versions: Map<String, Value>,
}

/// What one lease request came back with.
pub(crate) enum Reply {
    Response(Map<String, Value>),
    Refusal(Value),
    Transport(Value),
}

/// What the caller records and returns.
#[derive(Debug, Default)]
struct Outcome {
    item: Option<Map<String, Value>>,
    exact: bool,
    extras: Vec<Value>,
    exact_route: Option<&'static str>,
    exact_refusal: Option<Value>,
    batch_limit: Option<i64>,
    responses: Vec<Value>,
    failure: Option<Value>,
}

impl Outcome {
    fn failed(mut self, failure: Value) -> Self {
        self.failure = Some(failure);
        self
    }

    fn answer(self) -> Value {
        json!({
            "lease": {
                "item": self.item.map(Value::Object),
                "exact": self.exact,
                "extras": self.extras,
                "exactRoute": self.exact_route,
                "exactRefusal": self.exact_refusal,
                "batchLimit": self.batch_limit,
                "responses": self.responses,
            },
            "failure": self.failure,
        })
    }
}

/// Lease through the signed transport, to the connected Guard Cloud's origin.
pub(crate) fn lease(
    auth: Option<&Map<String, Value>>,
    call: &LeaseCall,
) -> Result<Value, SyncError> {
    let signed_in = auth.ok_or_else(|| {
        SyncError::NotConfigured("A Guard Cloud request needs a resolved sign-in.".to_owned())
    })?;
    let base = trusted_base(signed_in)?;
    let origin = origin(&base)
        .ok_or_else(|| SyncError::Failed(format!("Guard sync URL is invalid: {base}")))?;
    lease_with(call, |route, body| {
        let request: JsonRequest = serde_json::from_value(json!({
            "url": format!("{origin}{route}/lease"),
            "method": "POST",
            "body": body.to_string(),
            "timeoutSeconds": TIMEOUT_SECONDS,
            "retryTimeoutSeconds": RETRY_TIMEOUT_SECONDS,
        }))
        .map_err(|_| SyncError::Failed("The Guard command lease was not built.".to_owned()))?;
        reply(send(auth, &request)?)
    })
}

/// `lease_next_job`, with `post` sending one lease body to a route base.
pub(crate) fn lease_with(
    call: &LeaseCall,
    mut post: impl FnMut(&str, &Value) -> Result<Reply, SyncError>,
) -> Result<Value, SyncError> {
    let mut outcome = Outcome::default();
    let generic: Vec<String> = call
        .operations
        .iter()
        .filter(|operation| *operation != EXACT_OPERATION)
        .cloned()
        .collect();
    if call
        .operations
        .iter()
        .any(|operation| operation == EXACT_OPERATION)
    {
        let exact_only = generic.is_empty();
        let wait_ms = if exact_only { call.wait_ms } else { 0 };
        let operations = [EXACT_OPERATION.to_owned()];
        let body = lease_body(call, &operations, wait_ms, call.max_jobs);
        match post(EXACT_BASE, &body)? {
            Reply::Refusal(refusal) => {
                let status = refusal.get("status").and_then(Value::as_i64);
                if call.max_jobs > 1 && status == Some(400) {
                    // A Guard Cloud rolled back to one that leases a single
                    // job rejects the batch; ask it for one from the next poll.
                    outcome.batch_limit = Some(1);
                }
                if status == Some(401) || generic.is_empty() {
                    return Ok(outcome
                        .failed(json!({"refusal": refusal, "route": EXACT_BASE}))
                        .answer());
                }
                outcome.exact_route = Some("failed");
                outcome.exact_refusal = Some(refusal);
            }
            Reply::Transport(transport) => {
                return Ok(outcome
                    .failed(json!({"transport": transport, "route": EXACT_BASE}))
                    .answer());
            }
            Reply::Response(response) => {
                if !is_exact_protocol(&response) {
                    return Ok(outcome
                        .failed(json!({"protocol": PROTOCOL_UPGRADE}))
                        .answer());
                }
                outcome.exact_route = Some("ok");
                outcome.batch_limit = Some(advertised_batch_limit(&response).unwrap_or(1));
                outcome.responses.push(revision_view(&response));
                if let Some(item) = object(response.get("item")) {
                    if !is_exact_protocol(item) {
                        return Ok(outcome
                            .failed(json!({"protocol": PROTOCOL_UPGRADE}))
                            .answer());
                    }
                    if call.collect_extras {
                        outcome.extras = extra_exact_jobs(&response, item);
                    }
                    outcome.item = Some(item.clone());
                    outcome.exact = true;
                    return Ok(outcome.answer());
                }
            }
        }
    }
    if generic.is_empty() {
        return Ok(outcome.answer());
    }
    let body = lease_body(call, &generic, call.wait_ms, 1);
    let reply = match post(QUEUE_BASE, &body) {
        Ok(reply) => reply,
        // The exact route's health and batch limit are already known; the
        // caller records them before it raises the generic lease's error.
        Err(error) => {
            return Ok(outcome
                .failed(json!({"sync": failure(&error), "route": QUEUE_BASE}))
                .answer())
        }
    };
    match reply {
        Reply::Refusal(refusal) => Ok(outcome
            .failed(json!({"refusal": refusal, "route": QUEUE_BASE}))
            .answer()),
        Reply::Transport(transport) => Ok(outcome
            .failed(json!({"transport": transport, "route": QUEUE_BASE}))
            .answer()),
        Reply::Response(response) => {
            outcome.item = object(response.get("item")).cloned();
            outcome.responses.push(revision_view(&response));
            Ok(outcome.answer())
        }
    }
}

/// The part of a lease response the caller reads: its policy revision, kept
/// only when Guard Cloud sent the field. The leased jobs already travel as
/// `item` and `extras`, so repeating the whole response would write every job
/// twice to the runtime's bounded output.
fn revision_view(response: &Map<String, Value>) -> Value {
    let mut view = Map::new();
    if let Some(revision) = response.get("policyRevision") {
        view.insert("policyRevision".to_owned(), revision.clone());
    }
    Value::Object(view)
}

/// `command_queue_lease_payload`: one lease body for `operations`.
fn lease_body(call: &LeaseCall, operations: &[String], wait_ms: i64, max_jobs: i64) -> Value {
    let exact_only = operations.len() == 1 && operations[0] == EXACT_OPERATION;
    let mut capabilities = Map::new();
    capabilities.insert("operations".to_owned(), json!(operations));
    let schema_versions: Map<String, Value> = operations
        .iter()
        .filter(|operation| *operation != EXACT_OPERATION)
        .filter_map(|operation| {
            call.schema_versions
                .get(operation)
                .map(|version| (operation.clone(), version.clone()))
        })
        .collect();
    if !schema_versions.is_empty() {
        capabilities.insert("schemaVersions".to_owned(), Value::Object(schema_versions));
    }
    let mut body = Map::new();
    body.insert("workspaceId".to_owned(), json!(call.workspace_id));
    body.insert("deviceId".to_owned(), json!(call.device_id));
    body.insert("daemonVersion".to_owned(), json!(call.daemon_version));
    body.insert("capabilities".to_owned(), Value::Object(capabilities));
    // Only the exact Review route leases more than one job at a time.
    body.insert(
        "maxJobs".to_owned(),
        json!(if exact_only { max_jobs } else { 1 }),
    );
    body.insert("waitMs".to_owned(), json!(wait_ms));
    if exact_only {
        body.insert("protocolVersion".to_owned(), json!(EXACT_PROTOCOL_VERSION));
    }
    Value::Object(body)
}

/// `advertised_lease_batch_limit`: the most exact jobs one lease may return.
fn advertised_batch_limit(response: &Map<String, Value>) -> Option<i64> {
    response
        .get("maxJobs")
        .and_then(Value::as_i64)
        .filter(|limit| *limit >= 1)
}

/// `_extra_exact_jobs`: the exact jobs leased beside `first`, each with a
/// distinct lease. A job on another protocol stays leased and goes stale, the
/// same as one whose worker stopped before its result.
fn extra_exact_jobs(response: &Map<String, Value>, first: &Map<String, Value>) -> Vec<Value> {
    let Some(items) = response.get("items").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut seen: Vec<String> = first
        .get("leaseId")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .into_iter()
        .collect();
    let mut extras = Vec::new();
    for job in items.iter().filter_map(|value| object(Some(value))) {
        let Some(lease) = job.get("leaseId").and_then(Value::as_str) else {
            continue;
        };
        if lease.is_empty() || seen.iter().any(|known| known == lease) || !is_exact_protocol(job) {
            continue;
        }
        seen.push(lease.to_owned());
        extras.push(Value::Object(job.clone()));
    }
    extras
}

/// A non-empty JSON object, as `_mapping(...)` is truthy.
fn object(value: Option<&Value>) -> Option<&Map<String, Value>> {
    value
        .and_then(Value::as_object)
        .filter(|map| !map.is_empty())
}

/// `protocolVersion == 2`, as Python compares it (`2.0` is equal, `true` is not).
fn is_exact_protocol(map: &Map<String, Value>) -> bool {
    match map.get("protocolVersion") {
        Some(Value::Number(number)) => number
            .as_f64()
            .is_some_and(|version| version == EXACT_PROTOCOL_VERSION as f64),
        _ => false,
    }
}

/// The `request` action's answer as one of the three replies.
fn reply(answer: Value) -> Result<Reply, SyncError> {
    let invalid =
        || SyncError::Failed("Guard Cloud sync returned an invalid response payload.".to_owned());
    let Value::Object(mut answer) = answer else {
        return Err(invalid());
    };
    if let Some(Value::Object(response)) = answer.remove("response") {
        return Ok(Reply::Response(response));
    }
    if let Some(refusal) = answer.remove("refusal") {
        return Ok(Reply::Refusal(refusal));
    }
    answer
        .remove("transport")
        .map(Reply::Transport)
        .ok_or_else(invalid)
}

/// `scheme://authority` of the trusted sync URL, as `command_api_url` keeps it.
pub(crate) fn origin(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    (!scheme.is_empty() && !authority.is_empty()).then(|| format!("{scheme}://{authority}"))
}

#[cfg(test)]
#[path = "cloud_command_lease_tests.rs"]
mod tests;
