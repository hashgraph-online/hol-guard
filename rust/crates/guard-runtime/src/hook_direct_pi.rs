//! Oh My Pi hooks the resident answers as the daemon does.
//!
//! The daemon reviews a `pi` or `omp` hook as it reviews any other, with two
//! steps of its own. It lets the edge resolve a `guard_source_ref` outside
//! the workspace, a flag that both the request digest and the decision
//! receipt carry, so the lane sets it as the daemon does. After a
//! `PostToolUse` it resolves structured output mediation from the managed
//! policy. The publisher binds the managed-policy view the daemon resolves
//! it from, and the resident resolves that view with the same native query.
//!
//! Mediation itself is three native queries the daemon only transports: the
//! view resolves to a binding, `mediate_prepare` scans the model-visible
//! content against it, and `mediate_finish` forwards only once a second read
//! of the view still names the binding the scan ran under. The resident holds
//! that view in its own lane binding, so it runs all three itself and answers
//! the mediated hook too. A hook whose view the lane does not hold still
//! defers, and the daemon resolves it.

use super::POST_TOOL_USE;
use serde_json::{json, Value};
use std::time::{Duration, Instant};

/// The harnesses the daemon treats as Oh My Pi.
const PI_HARNESSES: [&str; 2] = ["pi", "omp"];
/// The keys of the managed-policy view `_config_wire` builds.
const CONFIG_VIEW_KEYS: [&str; 4] = [
    "managed_policy_status",
    "managed_policy_hash",
    "managed_locked_settings",
    "managed_policy",
];
/// What resolving one bounded managed-policy view may take.
const RESOLUTION_BUDGET: Duration = Duration::from_millis(100);
/// `STRUCTURED_CONTENT_MEDIATION_SCHEMA`, which every disposition carries.
const MEDIATION_SCHEMA: &str = "guard-structured-content-mediation.v1";
/// The spellings `canonical_harness_name` maps onto them.
const PI_ALIASES: [(&str, &str); 3] = [
    ("pi-agent", "pi"),
    ("pi-coding-agent", "pi"),
    ("oh-my-pi", "omp"),
];

/// `value.strip().lower().replace("_", "-")`. Python strips the separators
/// U+001C to U+001F as whitespace; Rust does not.
fn normalized(value: &str) -> String {
    value
        .trim_matches(|character: char| {
            character.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&character)
        })
        .to_lowercase()
        .replace('_', "-")
}

/// `default_harness.strip().lower().replace("_", "-") in {"pi", "omp"}`, the
/// `source_ref_external_allowed` that `_review_native_edge_with_snapshot`
/// passes the edge.
pub(super) fn source_ref_external_allowed(harness: &str) -> bool {
    PI_HARNESSES.contains(&normalized(harness).as_str())
}

/// Whether `_apply_structured_mediation` projects this hook: a `PostToolUse`
/// for a harness `canonical_harness_name` names `pi` or `omp`.
pub(super) fn structured_mediation(harness: &str, event: &str) -> bool {
    if event != POST_TOOL_USE {
        return false;
    }
    let name = normalized(harness);
    let canonical = PI_ALIASES
        .iter()
        .find(|(alias, _)| *alias == name.as_str())
        .map_or(name.as_str(), |&(_, canonical)| canonical);
    PI_HARNESSES.contains(&canonical)
}

/// What `resolve_managed_structured_output_resolution` reads from the bound
/// managed-policy view: the binding a managed destination names, whether one
/// is required at all, and the reason a required destination has none.
///
/// Without a view of `_config_wire`'s shape, or when the query fails, there
/// is no resolution, and the hook keeps the daemon path, which then resolves
/// and mediates itself.
pub(super) fn resolution(harness: &str, view: Option<&Value>) -> Option<Value> {
    let config = view?;
    let Value::Object(fields) = config else {
        return None;
    };
    if fields.len() != CONFIG_VIEW_KEYS.len()
        || CONFIG_VIEW_KEYS
            .iter()
            .any(|key| !fields.contains_key(*key))
    {
        return None;
    }
    let query = json!({"config": config, "harness": harness});
    let deadline = Instant::now() + RESOLUTION_BUDGET;
    guard_command::content_sensitivity::evaluate("resolution", &query, deadline)
        .ok()
        .map(|result| result["ok"].clone())
}

/// The binding a resolution names, as `recheck_binding` reads it.
pub(super) fn resolved_binding(resolution: &Value) -> Value {
    resolution["binding"].clone()
}

/// Whether `_apply_structured_mediation` returns the edge response unchanged:
/// the resolution finds nothing required for the bound managed-policy view.
fn unrequired(resolution: &Value) -> bool {
    resolution["required"].as_bool() != Some(true)
}

/// What the daemon's `_apply_structured_mediation` passes `mediate_prepare`
/// once the edge has decided.
pub(super) struct Mediation<'a> {
    pub harness: &'a str,
    /// The resolution the hook's own lane admission produced.
    pub resolution: &'a Value,
    /// The edge's native result.
    pub result: &'a Value,
    /// The decision receipt the edge returned, as the daemon mediates only
    /// against the receipt it accepted.
    pub receipt: &'a Value,
    /// `payload["structured_output_json"]`, the model-visible content.
    pub content: &'a Value,
    /// Watch, which mediates an observed result the daemon would skip.
    pub recording_only: bool,
    /// The hook's own deadline: a scan that outruns it withholds.
    pub deadline: Instant,
}

/// The withhold a transport failure leaves, as the daemon's two handlers do:
/// an exhausted deadline is named as one, and anything else is the managed
/// authority being unreachable. Neither may forward.
fn unavailable(error: &str) -> Value {
    let reason = if error == "content_scan_deadline_exceeded" {
        "structured_review_deadline_exceeded"
    } else {
        "structured_managed_authority_unavailable"
    };
    json!({"schema": MEDIATION_SCHEMA, "action": "withhold", "reason_code": reason})
}

/// `to_harness_json`: the identifier is carried only when the disposition
/// names one, and the digest only on a forward.
fn harness_json(disposition: &Value) -> Option<Value> {
    let action = disposition["action"].as_str()?;
    let mut rendered = json!({
        "schema": MEDIATION_SCHEMA,
        "action": action,
        "reason_code": disposition["reason_code"].clone(),
    });
    if let Some(identifier) = disposition["native_decision_id"]
        .as_str()
        .filter(|value| !value.is_empty())
    {
        rendered["native_decision_id"] = json!(identifier);
    }
    if action == "forward" {
        if let Some(digest) = disposition["content_sha256"]
            .as_str()
            .filter(|value| !value.is_empty())
        {
            rendered["content_sha256"] = json!(digest);
        }
    }
    Some(rendered)
}

/// The `structured_content_mediation` the daemon adds to the edge response,
/// or `None` where it adds none.
///
/// `refresh` is the daemon's `recheck_binding`: the binding a second read of
/// the managed-policy view names, which forwarding requires to still be the
/// one the scan ran under. A read that fails names none, and the content is
/// withheld as a changed binding.
pub(super) fn mediate(context: &Mediation<'_>, refresh: impl FnOnce() -> Value) -> Option<Value> {
    if unrequired(context.resolution) {
        return None;
    }
    // The daemon mediates against the receipt it accepted; anything else is
    // no receipt at all, which `mediate_prepare` withholds on.
    let receipt = if context.receipt.is_object() {
        context.receipt.clone()
    } else {
        Value::Null
    };
    let mut body = json!({
        "harness": context.harness,
        "event_name": POST_TOOL_USE,
        "native_result": {
            "decision": context.result["decision"].clone(),
            "observe_mode": context.result["observe_mode"].clone(),
            "model_output_action": context.result["model_output_action"].clone(),
        },
        "validated_receipt": receipt,
        "structured_output_json": context.content.clone(),
        "binding": resolved_binding(context.resolution),
        "required_reason_code": context.resolution["reason_code"].clone(),
        "cancelled": false,
        "allow_observe_mode": context.recording_only,
        "recheck_available": true,
    });
    let prepared = match guard_command::content_sensitivity::evaluate(
        "mediate_prepare",
        &body,
        context.deadline,
    ) {
        Ok(result) => result["ok"].clone(),
        Err(error) => return Some(unavailable(error)),
    };
    if prepared["recheck_required"] != Value::Bool(true) {
        return harness_json(&prepared);
    }
    body["refreshed_binding"] = refresh();
    // A recheck the resident runs itself has no failure the daemon's callback
    // reports separately: a view it cannot read names no binding, which
    // `mediate_finish` already withholds as a changed one.
    body["recheck_error"] = Value::Bool(false);
    match guard_command::content_sensitivity::evaluate("mediate_finish", &body, context.deadline) {
        Ok(result) => harness_json(&result["ok"]),
        Err(error) => Some(unavailable(error)),
    }
}
