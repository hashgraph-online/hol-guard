//! The Extensions affordances a local `GET /v1/requests/{id}` carries.
//!
//! A pending review may hold a queue-time hint naming the permissions that
//! would let its command run, and which extension matched which step. The
//! detail read swaps that private hint for what still applies: the live
//! recommendation and the labelled coverage, both re-checked by the resident
//! against the catalog and control view it admitted. A row queued without a
//! hint, or with coverage alone, gets what one read-time review can recover.
//!
//! Every part is advisory and never fails the read: a resident that does not
//! answer means no recommendation, never a different approval.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use guard_contracts::{
    ApprovalExtensionControlViewV1, ApprovalExtensionRecommendationPayloadV1,
    APPROVAL_EXTENSION_RECOMMENDATION_MAX_BYTES, APPROVAL_EXTENSION_RECOMMENDATION_REQUEST_SCHEMA,
    APPROVAL_EXTENSION_RECOMMENDATION_RESULT_SCHEMA, APPROVAL_EXTENSION_RECOMMENDATION_SCHEMA,
};
use serde_json::{json, Map, Value};

use super::{NativeReads, ReadConfig};

const RECOMMENDATION_TIMEOUT: Duration = Duration::from_secs(3);
/// The read-time review and its counterfactual, as the daemon budgeted them.
const LIVE_BUDGET_MS: u64 = 1200;
const REVIEW_HINT_REQUEST_SCHEMA: &str = "guard-extension-review-hint-request.v1";
const REVIEW_HINT_RESULT_SCHEMA: &str = "guard-extension-review-hint-result.v1";
const REVIEW_HINT_MAX_BYTES: usize = 1024 * 1024;
const COVERAGE_SCHEMA: &str = "guard.approval-extension-coverage.v1";
const MAX_PERMISSIONS: usize = 12;
const STATUSES: [&str; 2] = ["available", "authority_unavailable"];
/// Tool-input keys that never carry a path, payload or other content the
/// command-only re-review could miss.
const COMMAND_ONLY_INPUT_KEYS: [&str; 14] = [
    "command",
    "cmd",
    "shell_command",
    "shellCommand",
    "description",
    "timeout",
    "timeout_ms",
    "timeoutMs",
    "run_in_background",
    "runInBackground",
    "workdir",
    "cwd",
    "working_directory",
    "workingDirectory",
];

static REQUEST_IDS: AtomicU64 = AtomicU64::new(1);

/// `_approval_with_extension_recommendation` for a local caller: the stored
/// row with its private hint replaced by what still applies. `None` sends
/// the read to the daemon, which owns connector-setup recommendations.
pub(super) fn local_detail(
    mut approval: Map<String, Value>,
    config: &ReadConfig,
    reads: &NativeReads,
) -> Option<Map<String, Value>> {
    let request_id = approval
        .get("request_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let stored = reads.store_call(
        config,
        "get_approval_extension_allow_hint",
        json!({"request_id": request_id}),
    )?;
    if shape(&stored, "connector").is_some() {
        return None;
    }
    approval.remove("extension_allow_hint");
    let Some(view) = control_view(config) else {
        return Some(approval);
    };
    let hint = recovered(stored, &approval, &view, config);
    if shape(&hint, "connector").is_some() {
        return None;
    }
    if approval.get("status").and_then(Value::as_str) != Some("pending") {
        return Some(approval);
    }
    if let Some(allow) = shape(&hint, "allow") {
        if let Some(recommendation) = recommend(allow, &view, config) {
            approval.insert("extension_recommendation".to_owned(), recommendation);
        }
    }
    if hint.is_object() {
        if let Some(coverage) = coverage(hint, config) {
            approval.insert("extension_coverage".to_owned(), coverage);
        }
    }
    Some(approval)
}

/// The runtime's checked copy of one kind of stored hint (`allow`,
/// `coverage` or `connector`), or `None`.
pub(super) fn shape(value: &Value, key: &str) -> Option<Value> {
    if !value.is_object() {
        return None;
    }
    let answer = crate::extension_hint_shape::dispatch(&json!({"hint": value})).ok()?;
    answer.get(key).filter(|shaped| shaped.is_object()).cloned()
}

/// `recovered_approval_extension_hint`: the stored hint, plus whatever one
/// read-time review can still recover. A row carrying coverage alone has to
/// re-review exactly as a row carrying nothing does, or it loses the Always
/// allow offer it used to get back here.
fn recovered(
    stored: Value,
    approval: &Map<String, Value>,
    view: &ApprovalExtensionControlViewV1,
    config: &ReadConfig,
) -> Value {
    let coverage = shape(&stored, "coverage");
    if !stored.is_null() && (coverage.is_none() || shape(&stored, "allow").is_some()) {
        return stored;
    }
    let live = live_hint(approval, view, config);
    let Some(coverage) = coverage else {
        return live.unwrap_or(stored);
    };
    let Some(live) = live else {
        return stored;
    };
    // The queue-time coverage saw the directory the command really ran in,
    // so it outranks anything this review measured.
    crate::extension_coverage_hint::with_coverage(shape(&live, "allow"), Some(coverage))
        .unwrap_or(stored)
}

/// `hint_authority_admitted`: a protected authority can apply the Allow
/// now, and a device that never enrolled can once it enrolls.
fn hint_authority_admitted(view: &ApprovalExtensionControlViewV1) -> bool {
    let snapshot = &view.snapshot;
    snapshot.health == "protected"
        || (snapshot.health == "unenrolled"
            && snapshot.revision == 0
            && view.managed_revision == 0
            && snapshot.layers.is_empty())
}

/// `live_approval_extension_hint`: both hints from one re-review of a
/// pending shell review.
fn live_hint(
    approval: &Map<String, Value>,
    view: &ApprovalExtensionControlViewV1,
    config: &ReadConfig,
) -> Option<Value> {
    if !hint_authority_admitted(view) {
        return None;
    }
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let (command, cwd) = live_reviewed_command(approval, home.as_deref())?;
    let mut payload = json!({"tool_input": {"command": command}});
    if let Some(cwd) = cwd {
        payload["cwd"] = Value::from(cwd.to_string_lossy().into_owned());
    }
    let home_dir = home
        .map(|home| home.to_string_lossy().into_owned())
        .unwrap_or_default();
    let request = json!({
        "schema": REVIEW_HINT_REQUEST_SCHEMA,
        "request_id": next_request_id("rh"),
        "query": {
            "kind": "review_hint",
            "payload": payload,
            "workspace": "",
            "home_dir": home_dir,
            "budget_ms": LIVE_BUDGET_MS,
        },
    });
    let answer = ask(
        config,
        "extension_review_hint",
        &request,
        REVIEW_HINT_RESULT_SCHEMA,
        REVIEW_HINT_MAX_BYTES,
        Duration::from_millis(LIVE_BUDGET_MS),
    )?;
    if answer.len() != 2 || answer.get("kind").and_then(Value::as_str) != Some("review_hint") {
        return None;
    }
    let hint = answer.get("hint")?;
    if hint.is_null() {
        return None;
    }
    hint.is_object().then_some(())?;
    crate::extension_coverage_hint::with_coverage(shape(hint, "allow"), shape(hint, "coverage"))
}

/// `_live_reviewed_command`: the command of a pending shell review and the
/// directory to review it in again. A stored envelope redacts a launch
/// directory outside the home to its last segment, so a row whose directory
/// cannot be traced back recovers nothing rather than a hint measured
/// somewhere else.
pub(super) fn live_reviewed_command(
    approval: &Map<String, Value>,
    home: Option<&Path>,
) -> Option<(String, Option<PathBuf>)> {
    if approval.get("status").and_then(Value::as_str) != Some("pending") {
        return None;
    }
    let envelope = approval
        .get("action_envelope_json")
        .and_then(Value::as_object);
    if let Some(envelope) = envelope {
        match envelope.get("action_type") {
            None | Some(Value::Null) => {}
            Some(Value::String(kind)) if kind == "shell_command" => {}
            Some(_) => return None,
        }
    }
    let blank_free = |value: Option<&Value>| {
        value
            .and_then(Value::as_str)
            .filter(|text| !text.trim().is_empty())
            .map(str::to_owned)
    };
    let command = blank_free(approval.get("raw_command_text"))
        .or_else(|| blank_free(envelope.and_then(|envelope| envelope.get("command"))))?;
    let workspace = blank_free(approval.get("workspace")).map(PathBuf::from);
    let raw_payload = envelope
        .and_then(|envelope| envelope.get("raw_payload_redacted"))
        .and_then(Value::as_object);
    let cwd = match raw_payload {
        Some(raw_payload) if pre_tool_input(raw_payload).is_some() => {
            if !command_only_payload(raw_payload) {
                return None;
            }
            let cwd = stored_launch_cwd(raw_payload, workspace.as_deref(), home);
            let names_directory = raw_payload
                .get("cwd")
                .and_then(Value::as_str)
                .is_some_and(|text| !text.trim().is_empty());
            if cwd.is_none() && names_directory {
                return None;
            }
            cwd
        }
        _ => launch_cwd(None, workspace.as_deref()),
    };
    Some((command, cwd))
}

fn pre_tool_input(payload: &Map<String, Value>) -> Option<&Map<String, Value>> {
    ["tool_input", "toolInput"]
        .iter()
        .find_map(|key| payload.get(*key).and_then(Value::as_object))
}

fn command_only_payload(payload: &Map<String, Value>) -> bool {
    pre_tool_input(payload).is_some_and(|input| {
        input
            .keys()
            .all(|key| COMMAND_ONLY_INPUT_KEYS.contains(&key.as_str()))
    })
}

/// The launch directory of a stored approval, whose payload keeps only a
/// redacted `cwd`: a `~` label expands against the daemon's home.
fn stored_launch_cwd(
    raw_payload: &Map<String, Value>,
    workspace: Option<&Path>,
    home: Option<&Path>,
) -> Option<PathBuf> {
    let raw = raw_payload.get("cwd").and_then(Value::as_str);
    if let Some(text) = raw.map(str::trim) {
        if text == "~" || text.starts_with("~/") {
            let rest = text.get(2..).unwrap_or("");
            let expanded = home?.join(rest);
            return launch_cwd(Some(&expanded.to_string_lossy()), workspace);
        }
    }
    launch_cwd(raw, workspace)
}

/// `launch_cwd`: the absolute, existing directory an action would launch in.
fn launch_cwd(raw: Option<&str>, workspace: Option<&Path>) -> Option<PathBuf> {
    let candidate = match raw.filter(|text| !text.trim().is_empty()) {
        Some(text) => PathBuf::from(text),
        None => workspace?.to_path_buf(),
    };
    if !candidate.is_absolute() {
        return None;
    }
    let resolved = std::fs::canonicalize(candidate).ok()?;
    resolved.is_dir().then_some(resolved)
}

/// The control authority view the resident admitted.
fn control_view(config: &ReadConfig) -> Option<ApprovalExtensionControlViewV1> {
    match recommendation_query(config, json!({"kind": "control_view"}))? {
        ApprovalExtensionRecommendationPayloadV1::ControlView { view } => view,
        _ => None,
    }
}

/// `build_approval_extension_recommendation` for an allow hint already
/// shape-checked.
fn recommend(
    hint: Value,
    view: &ApprovalExtensionControlViewV1,
    config: &ReadConfig,
) -> Option<Value> {
    let query = json!({
        "kind": "recommend",
        "hint": hint,
        "registry_catalog_digest": view.registry_catalog_digest,
        "snapshot": view.snapshot,
    });
    let ApprovalExtensionRecommendationPayloadV1::Recommend { recommendation } =
        recommendation_query(config, query)?
    else {
        return None;
    };
    let recommendation = recommendation?;
    if recommendation.schema != APPROVAL_EXTENSION_RECOMMENDATION_SCHEMA
        || !STATUSES.contains(&recommendation.status.as_str())
        || recommendation.permissions.is_empty()
        || recommendation.permissions.len() > MAX_PERMISSIONS
    {
        return None;
    }
    serde_json::to_value(recommendation).ok()
}

/// `build_approval_extension_coverage`: which extension matched which step.
fn coverage(hint: Value, config: &ReadConfig) -> Option<Value> {
    let ApprovalExtensionRecommendationPayloadV1::Coverage { coverage } =
        recommendation_query(config, json!({"kind": "coverage", "hint": hint}))?
    else {
        return None;
    };
    let coverage = coverage?;
    let fields = coverage.as_object()?;
    let shaped = fields.len() == 4
        && fields.get("schema").and_then(Value::as_str) == Some(COVERAGE_SCHEMA)
        && fields.get("catalog_digest").is_some_and(Value::is_string)
        && fields.get("compound").is_some_and(Value::is_boolean)
        && fields
            .get("segments")
            .and_then(Value::as_array)
            .is_some_and(|segments| !segments.is_empty());
    shaped.then_some(coverage)
}

fn recommendation_query(
    config: &ReadConfig,
    query: Value,
) -> Option<ApprovalExtensionRecommendationPayloadV1> {
    let request = json!({
        "schema": APPROVAL_EXTENSION_RECOMMENDATION_REQUEST_SCHEMA,
        "request_id": next_request_id("aer"),
        "query": query,
    });
    let payload = ask(
        config,
        "approval_extension_recommendation",
        &request,
        APPROVAL_EXTENSION_RECOMMENDATION_RESULT_SCHEMA,
        APPROVAL_EXTENSION_RECOMMENDATION_MAX_BYTES,
        RECOMMENDATION_TIMEOUT,
    )?;
    serde_json::from_value(Value::Object(payload)).ok()
}

fn next_request_id(kind: &str) -> String {
    format!(
        "daemon-edge-{kind}-{}",
        REQUEST_IDS.fetch_add(1, Ordering::Relaxed)
    )
}

/// One bound resident answer: the `ok` payload of a result that names this
/// request and its digest, else `None`.
fn ask(
    config: &ReadConfig,
    operation: &str,
    request: &Value,
    result_schema: &str,
    limit: usize,
    timeout: Duration,
) -> Option<Map<String, Value>> {
    let digest = crate::package_authority_op::request_digest_with_limit(request, limit).ok()?;
    let encoded = serde_json::to_vec(&json!({"operation": operation, "request": request})).ok()?;
    let state_dir = std::fs::canonicalize(Path::new(&config.guard_home))
        .ok()?
        .join("native-runtime");
    let output = crate::managed_resident::client_request(&state_dir, &encoded, timeout).ok()?;
    let envelope: Value = serde_json::from_slice(&output).ok()?;
    bound_payload(envelope, request, &digest, result_schema)
}

pub(super) fn bound_payload(
    envelope: Value,
    request: &Value,
    digest: &str,
    result_schema: &str,
) -> Option<Map<String, Value>> {
    let Value::Object(mut envelope) = envelope else {
        return None;
    };
    let bound = envelope.get("schema").and_then(Value::as_str) == Some(result_schema)
        && envelope.get("request_id") == request.get("request_id")
        && envelope.get("request_sha256").and_then(Value::as_str) == Some(digest)
        && envelope.get("status").and_then(Value::as_str) == Some("ok");
    match envelope.remove("payload") {
        Some(Value::Object(payload)) if bound => Some(payload),
        _ => None,
    }
}

#[cfg(test)]
#[path = "daemon_edge_recommend_tests.rs"]
mod tests;
