//! `queue_blocked_approvals`: one approval request per evaluation item that
//! needs a review, with its canonical surfaces, incident copy and
//! continuation snapshot, written through the queue write in this store
//! transaction.
//!
//! Each item is written under its own savepoint, so a later item's error
//! keeps the earlier requests, as the former Python loop did. The reply
//! names the persisted requests with the fields their desktop notice reads,
//! and the error that stopped the loop.

use guard_contracts::{normalize_guard_action_result, GuardAction};
use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::context_digest::parse_context_token;
use crate::continuation_authority_op;
use crate::guard_store_approval_queue_item::{
    envelope, extension_allow_hint, launch_target, nonempty, review_text, risk_signals,
    risk_summary, scanner_evidence, str_or, string_list, with_command_category, workspace,
    Artifact,
};
use crate::guard_store_approval_write::add_request;
use crate::guard_store_args::Args;
use crate::guard_store_db::{StoreError, StoreResult};
use crate::guard_store_json::py_strip;
use crate::guard_store_outbox_identity::{correlation_id, correlation_shaped};
use crate::signal_projection_receipt::surfaces;

const INCONSISTENT: &str = "authoritative_decision_inconsistent";
const INVALID_ARGS: StoreError = StoreError::Invalid("native_guard_store_args_invalid");
const SAVEPOINT: &str = "approval_queue_item";
/// `_ARTIFACT_FIELDS`: the item keys whose values the decision owner reads.
const ARTIFACT_FIELDS: [&str; 18] = [
    "artifact_id",
    "artifact_type",
    "inventory_only",
    "approval_context_hash",
    "policy_action",
    "verdict_action",
    "policy_composition",
    "decision_v2_json",
    "action_envelope_json",
    "authoritative_decision",
    "approval_reuse",
    "approval_reuse_status",
    "approval_reuse_reason_code",
    "trusted_request_override",
    "approval_claim",
    "scanner_evidence",
    "decision_contract_error",
    "user_override",
];
const CORRELATION_KEYS: [&str; 2] = ["correlationId", "correlation_id"];

#[cfg(test)]
thread_local! {
    /// Request ids the replay assigns in place of random ones.
    pub(crate) static TEST_REQUEST_ID_COUNTER: std::cell::Cell<Option<u128>> =
        const { std::cell::Cell::new(None) };
    /// Each request the replay saw written, with its persisted id.
    pub(crate) static TEST_WRITES: std::cell::RefCell<Vec<(Value, String)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// The Python exception an item raised: its class tag and message.
struct ItemError(&'static str, String);

impl ItemError {
    fn value(message: &str) -> Self {
        Self("value", message.to_owned())
    }
}

/// The store errors Python raised to the caller keep the earlier requests;
/// any other failure aborts the whole transaction.
fn item_error(error: StoreError) -> Result<ItemError, StoreError> {
    match error {
        StoreError::Value(message) => Ok(ItemError("value", message)),
        StoreError::Runtime(message) => Ok(ItemError("runtime", message)),
        StoreError::Integrity(message) => Ok(ItemError("integrity", message)),
        other => Err(other),
    }
}

pub(crate) fn queue_blocked_approvals(
    connection: &Connection,
    source: &str,
    args: &Args,
) -> StoreResult<Value> {
    let items = args
        .raw("items")
        .and_then(Value::as_array)
        .ok_or(INVALID_ARGS)?;
    let artifacts = args.object("artifacts")?;
    let mut queued = Vec::new();
    let mut failure = Value::Null;
    for item in items.iter().filter_map(Value::as_object) {
        let artifact = item_artifact_id(item)
            .and_then(|id| artifacts.get(&id))
            .and_then(Value::as_object)
            .map(Artifact);
        let request = match item_request(item, artifact.as_ref(), args) {
            Ok(Some(request)) => request,
            Ok(None) => continue,
            Err(error) => {
                failure = json!({"type": error.0, "message": error.1});
                break;
            }
        };
        match write(connection, source, &request, args)? {
            Ok(request_id) => queued.push(queued_notice(&request, request_id, args)?),
            Err(error) => {
                failure = json!({"type": error.0, "message": error.1});
                break;
            }
        }
    }
    Ok(json!({"queued": queued, "error": failure}))
}

/// `str(item.get("artifact_id") or "")`, when not empty.
fn item_artifact_id(item: &Map<String, Value>) -> Option<String> {
    Some(str_or(item, "artifact_id", "")).filter(|id| !id.is_empty())
}

fn write(
    connection: &Connection,
    source: &str,
    request: &Value,
    args: &Args,
) -> StoreResult<Result<String, ItemError>> {
    let now = args.str("now")?;
    let prompt_shown = args.flag("prompt_shown")?;
    connection.execute_batch(&format!("SAVEPOINT {SAVEPOINT}"))?;
    match add_request(connection, source, Some(request), now, Some(prompt_shown)) {
        Ok(request_id) => {
            connection.execute_batch(&format!("RELEASE {SAVEPOINT}"))?;
            #[cfg(test)]
            TEST_WRITES.with(|writes| {
                writes
                    .borrow_mut()
                    .push((request.clone(), request_id.clone()))
            });
            Ok(Ok(request_id))
        }
        Err(error) => {
            connection.execute_batch(&format!("ROLLBACK TO {SAVEPOINT}; RELEASE {SAVEPOINT}"))?;
            item_error(error).map(Err)
        }
    }
}

/// The fields `_notify_pending_approval` reads, under the persisted id.
fn queued_notice(request: &Value, request_id: String, args: &Args) -> StoreResult<Value> {
    let center = args.str("approval_center_url")?;
    Ok(json!({
        "request_id": request_id,
        "notice": {
            "request_id": request_id,
            "harness": request["harness"],
            "workspace": request["workspace"],
            "approval_url": approval_url(center, &request_id),
            "artifact_name": request["artifact_name"],
            "risk_headline": request["risk_headline"],
            "trigger_summary": request["trigger_summary"],
        },
    }))
}

/// `build_approval_request_url`.
fn approval_url(center: &str, request_id: &str) -> String {
    format!(
        "{}/requests/{}",
        center.trim_end_matches('/'),
        py_strip(request_id)
    )
}

/// The `GuardApprovalRequest.to_dict()` of one item, or `None` for an item
/// that needs no review.
fn item_request(
    item: &Map<String, Value>,
    artifact: Option<&Artifact>,
    args: &Args,
) -> Result<Option<Value>, ItemError> {
    let normalization = normalize_guard_action_result(
        item.get("policy_action").unwrap_or(&Value::Null),
        GuardAction::RequireReapproval,
    );
    if !matches!(
        normalization.action,
        GuardAction::RequireReapproval | GuardAction::Review
    ) {
        return Ok(None);
    }
    let Some(artifact_id) = item_artifact_id(item) else {
        return Ok(None);
    };
    let item = with_command_category(item, artifact);
    let envelope = envelope(&item);
    if item
        .get("action_envelope_json")
        .is_some_and(|raw| !raw.is_null())
        && envelope.is_none()
    {
        return Err(ItemError::value(INCONSISTENT));
    }
    let canonical = canonical_surfaces(&item, normalization.action, envelope.as_ref())
        .ok_or_else(|| ItemError::value(INCONSISTENT))?;
    let policy_action = canonical["policy_action"].clone();
    let mut evidence = scanner_evidence(&item);
    if !normalization.recognized() {
        evidence.push(json!({
            "source": "guard_action_normalizer",
            "reason_code": normalization.reason_code,
            "original_action": normalization.original_action,
            "normalized_action": normalization.action.as_str(),
        }));
    }
    let artifact_hash = match item.get("approval_context_hash") {
        Some(token @ Value::String(hash)) if parse_context_token(token).is_some() => hash.clone(),
        _ => str_or(&item, "artifact_hash", "unknown"),
    };
    let request_id = new_request_id()?;
    let risk_summary = risk_summary(&item, artifact);
    let launch_target = launch_target(&item, artifact);
    let raw_command_text = match args.str("redaction_level") {
        Ok("full") => None,
        _ => review_text(&item, artifact, envelope.as_ref())
            .map(|text| guard_command::redacted_command_tokens::redact_text(&text).text),
    };
    let artifact_name = nonempty(&item, "artifact_name")
        .unwrap_or(&artifact_id)
        .to_owned();
    let source_scope = match artifact {
        Some(artifact) => artifact.wire_text("source_scope"),
        None => nonempty(&item, "source_scope")
            .unwrap_or("project")
            .to_owned(),
    };
    let config_path = config_path(&item, artifact, args)?;
    let changed_fields = string_list(item.get("changed_fields"));
    let harness = args.raw("harness").cloned().unwrap_or(Value::Null);
    let incident = crate::consumer_result::incident_context(&json!({
        "harness": harness,
        "artifact": artifact.map_or(&Value::Null, Artifact::wire_value),
        "changed_fields": changed_fields,
        "artifact_id": artifact_id,
        "artifact_name": artifact_name,
        "artifact_type": match artifact {
            Some(artifact) => artifact.wire_text("artifact_type"),
            None => nonempty(&item, "artifact_type").unwrap_or("artifact").to_owned(),
        },
        "source_scope": source_scope,
        "config_path": config_path,
        "policy_action": policy_action,
        "launch_target": launch_target,
        "risk_summary": risk_summary,
    }))
    .map_err(|code| ItemError("consumer", code.to_owned()))?;
    let incident_text = |key: &str| {
        incident
            .get(key)
            .and_then(crate::guard_store_json::py_str)
            .map_or(Value::Null, Value::String)
    };
    let center = args.str("approval_center_url").unwrap_or_default();
    let guard_version = args.raw("guard_version").cloned().unwrap_or(Value::Null);
    let workspace = workspace(&item, &config_path);
    let snapshot = continuation_snapshot(&request_id, &canonical, args)?;
    Ok(Some(json!({
        "request_id": request_id,
        "harness": harness,
        "artifact_id": artifact_id,
        "artifact_name": artifact_name,
        "artifact_hash": artifact_hash,
        "policy_action": policy_action,
        "recommended_scope": match artifact {
            Some(artifact) if crate::cloud_request_text::py_truthy(&artifact.wire_optional("publisher")) => "publisher",
            _ => "artifact",
        },
        "changed_fields": changed_fields,
        "source_scope": source_scope,
        "config_path": config_path,
        "review_command": format!("hol-guard approvals approve {request_id}"),
        "approval_url": approval_url(center, &request_id),
        "workspace": workspace,
        "artifact_type": artifact.map_or_else(|| "artifact".to_owned(), |artifact| artifact.wire_text("artifact_type")),
        "launch_target": launch_target,
        "transport": artifact.map_or(Value::Null, |artifact| artifact.wire_optional("transport")),
        "publisher": artifact.map_or(Value::Null, |artifact| artifact.wire_optional("publisher")),
        "risk_summary": risk_summary,
        "risk_signals": risk_signals(&item, artifact),
        "artifact_label": incident_text("artifact_label"),
        "source_label": incident_text("source_label"),
        "trigger_summary": incident_text("trigger_summary"),
        "why_now": incident_text("why_now"),
        "launch_summary": incident_text("launch_summary"),
        "risk_headline": incident_text("risk_headline"),
        "action_envelope_json": canonical["action_envelope_json"],
        "decision_v2_json": canonical["decision_v2_json"],
        "fallback_cli_command": null,
        "action_identity": null,
        "queue_group_id": null,
        "dedupe_count": 1,
        "last_seen_at": null,
        "scanner_evidence": evidence,
        "browser_intent": item.get("browser_intent").filter(|value| value.is_object()),
        "raw_command_text": raw_command_text,
        "guard_version": guard_version,
        "first_seen_guard_version": guard_version,
        "last_seen_guard_version": guard_version,
        "continuation_snapshot": snapshot,
        "extension_allow_hint": extension_allow_hint(&item, artifact),
    })))
}

/// `canonical_approval_artifact` of the item under its normalized action.
fn canonical_surfaces(
    item: &Map<String, Value>,
    action: GuardAction,
    envelope: Option<&Map<String, Value>>,
) -> Option<Value> {
    let mut boundary = item.clone();
    boundary.insert("policy_action".to_owned(), Value::from(action.as_str()));
    boundary.insert(
        "action_envelope_json".to_owned(),
        envelope.cloned().map_or(Value::Null, Value::Object),
    );
    // `artifact_transport_fields`: keys outside the owner's fields go null.
    for (key, value) in boundary.iter_mut() {
        if !ARTIFACT_FIELDS.contains(&key.as_str()) {
            *value = Value::Null;
        }
    }
    let artifact = Value::Object(boundary);
    guard_command::decisions::authoritative_decision_from_artifact(&artifact, false).ok()?;
    surfaces(
        &artifact["policy_action"],
        &artifact["decision_v2_json"],
        &artifact["action_envelope_json"],
        true,
    )
    .ok()
}

/// `_config_path`: the artifact's, else the item's, else the working
/// directory the caller observed.
fn config_path(
    item: &Map<String, Value>,
    artifact: Option<&Artifact>,
    args: &Args,
) -> Result<String, ItemError> {
    if let Some(artifact) = artifact {
        return Ok(artifact.wire_text("config_path"));
    }
    if let Some(path) = nonempty(item, "config_path") {
        return Ok(path.to_owned());
    }
    match args.raw("cwd").and_then(Value::as_str) {
        Some(cwd) => Ok(cwd.to_owned()),
        None => Err(ItemError("os", "working directory unavailable".to_owned())),
    }
}

/// `continuation_offer_payload` for a headless queue write, from the
/// operation facts the caller resolved once for the batch.
fn continuation_snapshot(
    request_id: &str,
    canonical: &Value,
    args: &Args,
) -> Result<Value, ItemError> {
    let facts = args.raw("continuation").unwrap_or(&Value::Null);
    let operation = facts["correlation_candidates"]
        .as_array()
        .into_iter()
        .flatten();
    let surfaces = ["decision_v2_json", "action_envelope_json"]
        .into_iter()
        .flat_map(|key| CORRELATION_KEYS.map(|name| &canonical[key][name]));
    let correlation = operation
        .chain(surfaces)
        .filter_map(Value::as_str)
        .map(py_strip)
        .find(|text| correlation_shaped(text))
        .map(str::to_owned)
        .or_else(|| correlation_id(request_id))
        .ok_or_else(|| ItemError::value("continuation_request_id_missing"))?;
    let offer = continuation_authority_op::evaluate(&json!({
        "call": "offer",
        "harness": facts["harness"],
        "wait_deadline": facts["wait_deadline"],
        "original_hook_attached": facts["original_hook_attached"],
        "session_target_verified": facts["session_target_verified"],
        "headless": true,
        "opaque_target_id": facts["opaque_target_id"],
        "correlation_id": correlation,
        "now": facts["now"],
    }))
    .map_err(|code| ItemError("runtime", code.to_owned()))?;
    let offer = &offer["offer"];
    Ok(json!({
        "correlationId": offer["correlation_id"],
        "capability": offer["capability"],
        "hookAttached": offer["original_hook_attached"],
        "opaqueTargetId": offer["opaque_target_id"],
        "waitDeadline": offer["wait_deadline"],
    }))
}

/// `uuid.uuid4().hex`.
fn new_request_id() -> Result<String, ItemError> {
    #[cfg(test)]
    if let Some(next) = TEST_REQUEST_ID_COUNTER.with(std::cell::Cell::get) {
        TEST_REQUEST_ID_COUNTER.with(|counter| counter.set(Some(next + 1)));
        return Ok(format!("{next:032x}"));
    }
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|_| ItemError("runtime", "native_guard_store_random_failed".to_owned()))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(hex::encode(bytes))
}

#[cfg(all(test, unix))]
#[path = "guard_store_approval_queue_tests.rs"]
mod tests;
