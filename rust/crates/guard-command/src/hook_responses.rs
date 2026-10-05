//! `daemon/hook_worker_responses.py` — mechanical harness response rendering
//! for the daemon hook worker (RTM-024). Envelope emitters
//! (`hookSpecificOutput` / `permissionDecision` / `additionalContext` /
//! `decision` per-harness shapes) are byte-parity-critical: golden-event
//! transcripts downstream bind the exact key/value shapes.
//!
//! TODO(deps): Python lazily resolves `..adapters` (`get_adapter`),
//! `.hook_availability_policy` (`availability_harness_response`,
//! `hook_action_is_emergency_safe`), `.hook_request_parsing`
//! (`runtime_hook_event_name`), `.hook_pretool_rendering` (the two `render`
//! delegates), `..approval_link_output` (`native_review_reason`), and
//! `..native_decision_receipt` (`valid_prompt_risk_classes`). Until those
//! ports land, the module keeps those surfaces behind seam traits
//! (`HarnessAdapterApi`, `HookAvailabilityApi`, `HookRequestApi`,
//! `PreToolRenderingApi`, `ApprovalLinkApi`, `PromptRiskClassesApi`) plus
//! daemon-server/handler traits. `Mapping[str, object]` → `&Map<String, Value>`.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use serde_json::{json, Map, Value};

// ---------------------------------------------------------------------------
// Dependency seams — traits replacing unported modules (see TODO(deps)).
// ---------------------------------------------------------------------------

/// `..adapters.get_adapter` seam (`ValueError`/`ImportError` → `None`).
pub trait HarnessAdapterApi {
    /// `get_adapter(harness).harness` — canonical harness id; `None` when the
    /// adapter lookup raises.
    fn adapter_harness(&self, harness: &str) -> Option<String>;
}

/// `.hook_availability_policy` seam.
pub trait HookAvailabilityApi {
    /// `hook_action_is_emergency_safe(payload, workspace=)`.
    fn hook_action_is_emergency_safe(
        &self,
        payload: &Map<String, Value>,
        workspace: Option<&Path>,
    ) -> bool;
    /// `availability_harness_response(payload, *, harness, event_name,
    /// reason_code, reason, recording_only)`.
    fn availability_harness_response(
        &self,
        payload: &Map<String, Value>,
        harness: &str,
        event_name: &str,
        reason_code: &str,
        reason: &str,
        recording_only: bool,
    ) -> Map<String, Value>;
}

/// `.hook_request_parsing` seam.
pub trait HookRequestApi {
    /// `runtime_hook_event_name(payload)`.
    fn runtime_hook_event_name(&self, payload: &Map<String, Value>) -> String;
}

/// `.hook_pretool_rendering` seam — the two deferred `render` delegates.
pub trait PreToolRenderingApi {
    /// `hook_pretool_rendering.harness_json_from_native_pre_tool`.
    fn render_native_pre_tool(
        &self,
        harness: &str,
        response: &Map<String, Value>,
    ) -> Map<String, Value>;
    /// `hook_pretool_rendering.harness_json_from_native_pre_tool_review`.
    fn render_native_pre_tool_review(
        &self,
        harness: &str,
        response: &Map<String, Value>,
        approval: Option<&Map<String, Value>>,
        guard_home: Option<&Path>,
    ) -> Map<String, Value>;
}

/// `..approval_link_output.native_review_reason` seam.
pub trait ApprovalLinkApi {
    /// `native_review_reason(canonical_harness, reason, approval_url,
    /// guard_home=)` — adds the safe approval link to a native review reason.
    fn native_review_reason(
        &self,
        canonical_harness: &str,
        reason: &str,
        approval_url: &str,
        guard_home: Option<&Path>,
    ) -> String;
}

/// `..native_decision_receipt.valid_prompt_risk_classes` seam.
pub trait PromptRiskClassesApi {
    /// `valid_prompt_risk_classes(value)` — list membership/order validation.
    fn valid_prompt_risk_classes(&self, value: &Value) -> bool;
}

/// `daemon_server` (worker + store attributes) seam.
pub trait DaemonServerApi {
    /// `daemon_server.store` — `None` when the attribute is missing.
    fn store(&self) -> Option<&dyn EvidenceManagedInstallStore>;
    /// `daemon_server.hook_worker` — `None` when the attribute is missing.
    fn hook_worker(&self) -> Option<&dyn HookWorkerApi>;
}

/// `daemon_server.store` — managed-install introspection for the
/// unprotected-app passthrough. `get_managed_install`/`list_managed_installs`
/// return `None` when the store method is absent OR raises (Python treats a
/// non-callable attribute and a caught `Exception` identically).
pub trait EvidenceManagedInstallStore {
    /// `store.get_managed_install(canonical)` — outer `None` = missing/raised;
    /// inner `None` = lookup returned `None`; `Some(dict)` = install record.
    fn get_managed_install(&self, canonical: &str) -> Option<Option<Map<String, Value>>>;
    /// `store.list_managed_installs()` — `None` when absent/raised.
    fn list_managed_installs(&self) -> Option<Vec<Map<String, Value>>>;
}

/// `daemon_server.hook_worker` seam.
pub trait HookWorkerApi {
    /// `hook_worker.prepare_workspace_policy(workspace_path, deadline=)` —
    /// `Some(policy)` when a prepared policy exists, `None` otherwise.
    fn prepare_workspace_policy(&self, workspace: Option<&Path>, deadline: f64) -> Option<Value>;
    /// `hook_worker.metrics.record_route(route)`.
    fn record_route(&self, route: &str);
    /// `hook_worker.policy_snapshot_publisher` — `None` when missing.
    fn policy_snapshot_publisher(&self) -> Option<&dyn PolicySnapshotPublisherApi>;
}

/// `hook_worker.policy_snapshot_publisher` seam.
pub trait PolicySnapshotPublisherApi {
    /// `publisher.last_error` — `None` when missing or non-string.
    fn last_error(&self) -> Option<String>;
}

/// `handler` seam — `_write_json` side effect plus the delegated
/// `_runtime_hook_fail_safe_response` renderer.
pub trait HookHandlerApi {
    /// `handler._write_json(payload)` — emit the response envelope.
    fn write_json(&self, payload: &Map<String, Value>);
    /// `handler._runtime_hook_fail_safe_response(payload, params, *, ...)`.
    fn runtime_hook_fail_safe_response(
        &self,
        payload: &Map<String, Value>,
        params: &Map<String, Value>,
        default_harness: &str,
        reason: &str,
        reason_code: &str,
        native_authoritative: bool,
    ) -> Map<String, Value>;
}

/// `response.to_harness_json` seam for `harness_json_from_review_response` —
/// `None` argument mirrors a response object without the method.
pub trait HarnessJsonResponse {
    /// `response.to_harness_json()`.
    fn to_harness_json(&self) -> Value;
}

// ---------------------------------------------------------------------------
// `prepare_native_hook_policy` (:14-51) — native-policy admission barrier.
// ---------------------------------------------------------------------------

/// `prepare_native_hook_policy` (:14-51). Apply the production native-policy
/// barrier before hook admission.
#[allow(clippy::too_many_arguments)]
pub fn prepare_native_hook_policy(
    handler: &dyn HookHandlerApi,
    daemon_server: &dyn DaemonServerApi,
    payload: &Map<String, Value>,
    params: &Map<String, Value>,
    default_harness: &str,
    workspace: Option<&str>,
    deadline: f64,
    adapters: &dyn HarnessAdapterApi,
    availability: &dyn HookAvailabilityApi,
    request_parsing: &dyn HookRequestApi,
) -> bool {
    let harness = _canonical_managed_harness(default_harness, adapters);
    if _hook_harness_is_unmanaged(daemon_server, &harness, adapters) {
        _write_unmanaged_harness_passthrough(
            handler,
            payload,
            &harness,
            availability,
            request_parsing,
        );
        return false;
    }
    let workspace_path = workspace.map(PathBuf::from);
    let prepared_policy = daemon_server
        .hook_worker()
        .map(|worker| worker.prepare_workspace_policy(workspace_path.as_deref(), deadline));
    if let Some(Some(_)) = prepared_policy {
        return true;
    }
    if availability.hook_action_is_emergency_safe(payload, workspace_path.as_deref()) {
        return true;
    }
    if let Some(worker) = daemon_server.hook_worker() {
        worker.record_route("native_fail_safe");
    }
    handler.write_json(&handler.runtime_hook_fail_safe_response(
        payload,
        params,
        default_harness,
        &_native_policy_not_ready_reason(daemon_server),
        "native_policy_not_ready",
        true,
    ));
    false
}

/// `_canonical_managed_harness` (:52-60).
fn _canonical_managed_harness(harness: &str, adapters: &dyn HarnessAdapterApi) -> String {
    match adapters.adapter_harness(harness) {
        Some(canonical) => canonical,
        None => _canonical_hook_harness(harness),
    }
}

/// `_hook_harness_is_unmanaged` (:61-93). True when leftover hooks belong to
/// an app Guard is not currently protecting.
fn _hook_harness_is_unmanaged(
    daemon_server: &dyn DaemonServerApi,
    harness: &str,
    adapters: &dyn HarnessAdapterApi,
) -> bool {
    let Some(store) = daemon_server.store() else {
        return false;
    };
    let canonical = _canonical_managed_harness(harness, adapters);
    if let Some(Some(install)) = store.get_managed_install(&canonical) {
        return install.get("active") == Some(&Value::Bool(false));
    }
    let Some(installs) = store.list_managed_installs() else {
        return false;
    };
    installs.iter().any(|item| {
        item.get("active") == Some(&Value::Bool(true))
            && _canonical_managed_harness(
                item.get("harness").and_then(Value::as_str).unwrap_or(""),
                adapters,
            ) != canonical
    })
}

/// `_write_unmanaged_harness_passthrough` (:94-114).
fn _write_unmanaged_harness_passthrough(
    handler: &dyn HookHandlerApi,
    payload: &Map<String, Value>,
    harness: &str,
    availability: &dyn HookAvailabilityApi,
    request_parsing: &dyn HookRequestApi,
) {
    let event_name = request_parsing.runtime_hook_event_name(payload);
    handler.write_json(&availability.availability_harness_response(
        payload,
        harness,
        &event_name,
        "harness_not_managed",
        "HOL Guard is not protecting this app.",
        true,
    ));
}

/// `_native_policy_not_ready_reason` (:115-123).
fn _native_policy_not_ready_reason(daemon_server: &dyn DaemonServerApi) -> String {
    let reason = "HOL Guard could not prepare the native policy safely.".to_string();
    let last_error = daemon_server
        .hook_worker()
        .and_then(|worker| worker.policy_snapshot_publisher())
        .and_then(|publisher| publisher.last_error());
    if let Some(last_error) = last_error {
        let stripped = last_error.trim();
        if !stripped.is_empty() {
            return format!("{reason} {stripped}.");
        }
    }
    reason
}

/// `_canonical_hook_harness` (:124-132).
fn _canonical_hook_harness(harness: &str) -> String {
    harness.trim().to_lowercase().replace('_', "-")
}

/// `_GROK_DECISION_HARNESSES` (:128) — shared with `hook_pretool_rendering`.
pub static GROK_DECISION_HARNESSES: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| ["grok", "openclaw"].into_iter().collect());

/// `_SILENT_WARNING_CODES` (:130) — shared with `hook_pretool_rendering`.
pub static SILENT_WARNING_CODES: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| ["native_policy_observed"].into_iter().collect());

/// `harness_json_from_native_pre_tool` (:133-138) — deferred rendering delegate.
pub fn harness_json_from_native_pre_tool(
    harness: &str,
    response: &Map<String, Value>,
    rendering: &dyn PreToolRenderingApi,
) -> Map<String, Value> {
    rendering.render_native_pre_tool(harness, response)
}

/// `harness_json_from_native_pre_tool_review` (:139-150) — deferred delegate.
pub fn harness_json_from_native_pre_tool_review(
    harness: &str,
    response: &Map<String, Value>,
    approval: Option<&Map<String, Value>>,
    guard_home: Option<&Path>,
    rendering: &dyn PreToolRenderingApi,
) -> Map<String, Value> {
    rendering.render_native_pre_tool_review(harness, response, approval, guard_home)
}

/// `_native_review_reason` (:151-165) — delegated to `approval_link_output`.
pub fn native_review_reason(
    canonical_harness: &str,
    reason: &str,
    approval_url: &str,
    guard_home: Option<&Path>,
    approval_links: &dyn ApprovalLinkApi,
) -> String {
    approval_links.native_review_reason(canonical_harness, reason, approval_url, guard_home)
}

/// `_attach_native_review_approval_aliases` (:166-179).
pub fn _attach_native_review_approval_aliases(
    payload: &mut Map<String, Value>,
    approval_request_id: Option<&str>,
    approval_url: Option<&str>,
) {
    let (Some(request_id), Some(url)) = (approval_request_id, approval_url) else {
        return;
    };
    payload.insert("primary_approval_request_id".to_string(), json!(request_id));
    payload.insert("primary_approval_url".to_string(), json!(url));
    payload.insert("guardApprovalRequestId".to_string(), json!(request_id));
    payload.insert("guardApprovalUrl".to_string(), json!(url));
    payload.insert(
        "approval_requests".to_string(),
        json!([{"request_id": request_id, "approval_url": url}]),
    );
}

/// `_native_review_permission_decision` (:180-199). zcode opens its native
/// permission prompt for review-tier decisions, so the review envelope must
/// ask rather than deny.
fn _native_review_permission_decision(harness: &str) -> &'static str {
    let canonical = _canonical_hook_harness(harness);
    if ["codex", "kimi", "grok", "hermes", "devin"].contains(&canonical.as_str()) {
        return "deny";
    }
    "ask"
}

/// `_NATIVE_PROMPT_RISK_LABELS` (:203-211).
fn _native_prompt_risk_label(code: &str) -> Option<&'static str> {
    Some(match code {
        "local_env_read" => "Prompt requests a local .env file.",
        "sensitive_material" => "Prompt requests potentially sensitive local material.",
        "exfil_intent" => "Prompt includes exfiltration-oriented transfer intent.",
        "destructive_intent" => "Prompt includes a destructive local action.",
        "subprocess_intent" => "Prompt requests subprocess execution.",
        "guard_bypass_intent" => "Prompt includes Guard bypass intent.",
        "prompt_injection_intent" => "Prompt asks to override trusted instructions.",
        _ => return None,
    })
}

/// `harness_json_from_native_prompt` (:200-249).
pub fn harness_json_from_native_prompt(
    harness: &str,
    response: &Map<String, Value>,
    risk_classes: &dyn PromptRiskClassesApi,
) -> Map<String, Value> {
    let canonical = _canonical_hook_harness(harness);
    if canonical == "grok" {
        return Map::new();
    }
    let action = response.get("minimum_action").and_then(Value::as_str);
    let reason_code = response
        .get("reason_code")
        .and_then(Value::as_str)
        .unwrap_or("native_prompt_unavailable")
        .to_string();
    let classes = response
        .get("prompt_risk_classes")
        .cloned()
        .unwrap_or(Value::Null);
    let risk_signals: Vec<Value> = if risk_classes.valid_prompt_risk_classes(&classes) {
        classes
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str())
                    .filter_map(_native_prompt_risk_label)
                    .map(|label| json!(label))
                    .collect()
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    if response.get("decision") == Some(&json!("allow"))
        && matches!(action, Some("allow") | Some("warn"))
    {
        if canonical == "codex" {
            return json!({"hookSpecificOutput": {"hookEventName": "UserPromptSubmit"}})
                .as_object()
                .cloned()
                .unwrap_or_default();
        }
        let mut output = json!({
            "policy_action": action.unwrap_or(""),
            "reason_code": reason_code,
            "hookSpecificOutput": {"hookEventName": "UserPromptSubmit"},
        })
        .as_object()
        .cloned()
        .unwrap_or_default();
        if !risk_signals.is_empty() && canonical != "copilot" {
            output.insert("risk_signals".to_string(), json!(risk_signals));
        }
        return output;
    }
    let reason = response
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("HOL Guard could not complete native prompt review safely.")
        .to_string();
    let policy_action = match action {
        Some("review" | "require-reapproval" | "sandbox-required" | "block") => {
            action.unwrap_or("block")
        }
        _ => "block",
    };
    if canonical == "copilot" {
        return json!({
            "behavior": "deny",
            "message": reason,
            "interrupt": false,
            "policy_action": policy_action,
            "reason_code": reason_code,
        })
        .as_object()
        .cloned()
        .unwrap_or_default();
    }
    let mut output = json!({
        "decision": "block",
        "reason": reason,
        "systemMessage": reason,
        "policy_action": policy_action,
        "reason_code": reason_code,
        "hookSpecificOutput": {"hookEventName": "UserPromptSubmit"},
    })
    .as_object()
    .cloned()
    .unwrap_or_default();
    if !risk_signals.is_empty() {
        output.insert("risk_signals".to_string(), json!(risk_signals));
    }
    if canonical == "codex" {
        output.insert("continue".to_string(), json!(false));
        output.insert("stopReason".to_string(), json!(reason));
        output.insert(
            "hookSpecificOutput".to_string(),
            json!({"hookEventName": "UserPromptSubmit", "additionalContext": reason}),
        );
    }
    output
}

/// `harness_json_from_native_post_tool` (:250-293).
pub fn harness_json_from_native_post_tool(
    harness: &str,
    response: &Map<String, Value>,
) -> Map<String, Value> {
    let canonical_harness = _canonical_hook_harness(harness);
    if canonical_harness == "pi" || canonical_harness == "omp" {
        return response.clone();
    }
    if canonical_harness == "cline" {
        // The managed AgentPlugin can replace the model-visible result. Keep
        // Rust's reviewed-output directive and digest intact for that seam;
        // the native Cline hook itself remains observation-only.
        let mut output = Map::new();
        for key in [
            "decision",
            "model_output_action",
            "reviewed_output_sha256",
            "reviewed_excerpt",
            "policy_action",
        ] {
            if let Some(value) = response.get(key) {
                output.insert(key.to_string(), value.clone());
            }
        }
        return output;
    }
    if response.get("decision") == Some(&json!("allow"))
        && response.get("model_output_action") == Some(&json!("allow_original"))
    {
        let action = response
            .get("policy_action")
            .and_then(Value::as_str)
            .unwrap_or("allow");
        let mut output = json!({
            "policy_action": action,
            "hookSpecificOutput": {"hookEventName": "PostToolUse"},
        })
        .as_object()
        .cloned()
        .unwrap_or_default();
        if action == "warn" {
            let reason = response.get("reason").and_then(Value::as_str).unwrap_or(
                "HOL Guard raised a non-blocking warning under the installed native policy.",
            );
            output.insert(
                "hookSpecificOutput".to_string(),
                json!({
                    "hookEventName": "PostToolUse",
                    "permissionDecisionReason": reason,
                }),
            );
        }
        return output;
    }
    let reason = response
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("HOL Guard blocked this tool output because it could not be proven safe.");
    let reason_code = response
        .get("reason_code")
        .and_then(Value::as_str)
        .unwrap_or("native_hook_edge_block");
    post_tool_native_block_response(reason, reason_code)
}

/// `post_tool_native_block_response` (:294-315).
pub fn post_tool_native_block_response(reason: &str, reason_code: &str) -> Map<String, Value> {
    json!({
        "decision": "block",
        "reason": reason,
        "continue": true,
        "stopReason": reason,
        "policy_action": "block",
        "risk_summary": reason,
        "model_output_action": "block",
        "notice": "warning",
        "reason_code": reason_code,
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": reason,
        },
    })
    .as_object()
    .cloned()
    .unwrap_or_default()
}

/// `post_tool_fail_safe_response` (:316-329). `reason` is intentionally
/// dropped (`del reason`) — parity with the Python surface.
pub fn post_tool_fail_safe_response(
    harness: &str,
    _reason: &str,
    reason_code: &str,
) -> Map<String, Value> {
    observe_lifecycle_fail_safe_response(harness, "PostToolUse", reason_code)
}

/// `integrity_fail_closed_pre_tool_response` (:330-363). Deny PreToolUse when
/// hook payload authenticity cannot be proven.
pub fn integrity_fail_closed_pre_tool_response(
    harness: &str,
    reason: &str,
    reason_code: &str,
) -> Map<String, Value> {
    let canonical = _canonical_hook_harness(harness);
    if canonical == "pi" || canonical == "omp" {
        return json!({
            "decision": "deny",
            "reason": reason,
            "policy_action": "block",
            "reason_code": reason_code,
        })
        .as_object()
        .cloned()
        .unwrap_or_default();
    }
    if ["grok", "hermes", "openclaw"].contains(&canonical.as_str()) {
        return json!({
            "decision": if canonical == "hermes" { "block" } else { "deny" },
            "reason": reason,
            "policy_action": "block",
            "reason_code": reason_code,
        })
        .as_object()
        .cloned()
        .unwrap_or_default();
    }
    json!({
        "policy_action": "block",
        "reason_code": reason_code,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        },
    })
    .as_object()
    .cloned()
    .unwrap_or_default()
}

/// `permission_unavailable_response` (:364-404). Continue Permission* hooks
/// when native review cannot finish — Copilot keeps the v1 `behavior: deny`
/// JSON so the tool is not auto-approved, but the turn is not interrupted.
pub fn permission_unavailable_response(
    harness: &str,
    event_name: &str,
    reason: &str,
    reason_code: &str,
) -> Map<String, Value> {
    let canonical = _canonical_hook_harness(harness);
    if canonical == "copilot" {
        return json!({
            "behavior": "deny",
            "message": reason,
            "interrupt": false,
            "reason_code": reason_code,
        })
        .as_object()
        .cloned()
        .unwrap_or_default();
    }
    if canonical == "pi" || canonical == "omp" {
        return json!({
            "decision": "allow",
            "reason": reason,
            "policy_action": "warn",
            "notice": "warning",
            "reason_code": reason_code,
        })
        .as_object()
        .cloned()
        .unwrap_or_default();
    }
    if ["grok", "hermes", "openclaw"].contains(&canonical.as_str()) {
        return json!({
            "decision": "allow",
            "reason": reason,
            "reason_code": reason_code,
        })
        .as_object()
        .cloned()
        .unwrap_or_default();
    }
    json!({
        "continue": true,
        "systemMessage": reason,
        "reason_code": reason_code,
        "hookSpecificOutput": {
            "hookEventName": event_name,
        },
    })
    .as_object()
    .cloned()
    .unwrap_or_default()
}

/// `observe_lifecycle_fail_safe_response` (:405-431). Continue prompt/session
/// inventory hooks when native review cannot run.
pub fn observe_lifecycle_fail_safe_response(
    harness: &str,
    event_name: &str,
    reason_code: &str,
) -> Map<String, Value> {
    let canonical = _canonical_hook_harness(harness);
    if canonical == "grok" {
        // Grok UserPromptSubmit honors only "block". "allow" is logged as an
        // unknown decision and shown as a hook failure. Empty JSON is success.
        return Map::new();
    }
    if ["hermes", "openclaw", "pi", "omp"].contains(&canonical.as_str()) {
        return json!({
            "decision": "allow",
            "policy_action": "allow",
            "reason_code": reason_code,
        })
        .as_object()
        .cloned()
        .unwrap_or_default();
    }
    json!({
        "continue": true,
        "policy_action": "allow",
        "reason_code": reason_code,
        "hookSpecificOutput": {"hookEventName": event_name},
    })
    .as_object()
    .cloned()
    .unwrap_or_default()
}

/// `harness_json_from_review_response` (:432-468).
pub fn harness_json_from_review_response(
    harness: &str,
    event_name: &str,
    response: Option<&dyn HarnessJsonResponse>,
) -> Map<String, Value> {
    let payload = response
        .and_then(|responder| responder.to_harness_json().as_object().cloned())
        .unwrap_or_default();
    if event_name != "PostToolUse" {
        return payload;
    }
    let canonical = _canonical_hook_harness(harness);
    if canonical == "pi" || canonical == "omp" {
        return payload;
    }
    let decision = payload
        .get("decision")
        .and_then(Value::as_str)
        .unwrap_or("");
    let model_output_action = payload
        .get("model_output_action")
        .and_then(Value::as_str)
        .unwrap_or("");
    if decision == "allow" && model_output_action == "allow_original" {
        return json!({
            "policy_action": "allow",
            "hookSpecificOutput": {"hookEventName": event_name},
        })
        .as_object()
        .cloned()
        .unwrap_or_default();
    }
    let reason = payload
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("HOL Guard blocked this tool output because it could not be proven safe.");
    let reason_code = payload
        .get("reason_code")
        .and_then(Value::as_str)
        .unwrap_or("fast_path_block");
    post_tool_native_block_response(reason, reason_code)
}
