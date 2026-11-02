//! `temporary_mcp_grant` — the bounded grants a routine browser MCP capability
//! may carry.
//!
//! A queued browser call offers the approval card a short grant (15m, 1h or
//! 5h) for the exact call, its category or the whole server, but only when the
//! call's projected risk is the routine category of its intent and nothing
//! else. The intent arrives as the approval request filed it, so it is
//! untrusted: anything that is not such an intent answers "no grant" rather
//! than failing. For one pick the op returns the selector the grant is filed
//! under and the moment it runs out; a pick the card does not offer is refused
//! by code, never widened to fit.
//!
//! Two shapes share the kind:
//! - `{"browser_intents": [intent, ...]}` answers `{"approvals": [...]}`, one
//!   card payload or `null` per intent, in order.
//! - `{"browser_intent": intent, "selection": {...}}` answers
//!   `{"selection": ..., "refusal": ...}` for one pick.

use serde_json::{json, Map, Value};

use crate::context_digest::python_strip;
use crate::mcp_tool_policy_grants::{
    category_for, exact_grant_selector, scope_grant_selector, INFORMATIONAL_CATEGORY,
};
use crate::runner_authority_op::KindResult;

const ERR_INVALID: &str = "native_temporary_mcp_grant_invalid";
/// The most intents one read may ask about; a queue page is far smaller.
const MAX_INTENTS: usize = 4096;
/// `TEMPORARY_MCP_GRANT_TARGETS`.
const TARGETS: [&str; 3] = ["exact", "category", "server"];
/// `TEMPORARY_MCP_GRANT_DURATIONS` and their `_DURATION_SECONDS`.
const DURATIONS: [(&str, i64); 3] = [("15m", 900), ("1h", 3600), ("5h", 18000)];
/// `_HARD_RISK_EXCLUSIONS` — the shapes no grant ever covers, carried on the
/// card so the surface can say so.
const HARD_RISK_EXCLUSIONS: [&str; 10] = [
    "browser_transfer",
    "browser_privileged",
    "browser_sensitive_surface",
    "browser_shared_profile",
    "secret_access",
    "filesystem_access",
    "command_execution",
    "destructive_mutation",
    "privileged_system_mutation",
    "tool_schema_mismatch",
];

/// A routine browser capability that may carry a bounded grant.
struct Eligibility {
    server_identity_hash: String,
    server_name: String,
    category: &'static str,
    target_label: Option<String>,
}

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let fields = args.as_object().ok_or(ERR_INVALID)?;
    if let Some(intents) = fields.get("browser_intents") {
        let intents = intents.as_array().ok_or(ERR_INVALID)?;
        if intents.len() > MAX_INTENTS || fields.len() != 1 {
            return Err(ERR_INVALID);
        }
        let approvals: Vec<Value> = intents
            .iter()
            .map(|intent| approval(Some(intent)).unwrap_or(Value::Null))
            .collect();
        return Ok(json!({ "approvals": approvals }));
    }
    let pick = fields
        .get("selection")
        .and_then(Value::as_object)
        .ok_or(ERR_INVALID)?;
    let (selection, refusal) = match eligibility(fields.get("browser_intent")) {
        None => (Value::Null, json!("temporary_mcp_approval_ineligible")),
        Some(found) => match select(&found, pick)? {
            Ok(selection) => (selection, Value::Null),
            Err(code) => (Value::Null, json!(code)),
        },
    };
    Ok(json!({ "selection": selection, "refusal": refusal }))
}

/// `temporary_mcp_approval_payload`: the card payload for one filed intent.
pub(crate) fn approval(intent: Option<&Value>) -> Option<Value> {
    let found = eligibility(intent)?;
    Some(json!({
        "version": 1,
        "eligible": true,
        "server_name": found.server_name,
        "server_identity_hash": found.server_identity_hash,
        "category": found.category,
        "target_label": found.target_label,
        "allowed_targets": TARGETS,
        "allowed_durations": ["once", "15m", "1h", "5h"],
        "hard_risk_exclusions": HARD_RISK_EXCLUSIONS,
    }))
}

/// `eligibility_from_browser_intent`: the routine category must be claimed,
/// and nothing beyond it but the informational external-domain flag.
fn eligibility(intent: Option<&Value>) -> Option<Eligibility> {
    let intent = intent?.as_object()?;
    let server_identity_hash = nonempty(intent, "mcp_server_identity_hash");
    let server_name = nonempty(intent, "mcp_server_name");
    let category = nonempty(intent, "intent").and_then(|named| category_for(&named));
    let (Some(server_identity_hash), Some(server_name), Some(category)) =
        (server_identity_hash, server_name, category)
    else {
        return None;
    };
    let risk_categories: Vec<&str> = intent
        .get("risk_categories")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    if !risk_categories.contains(&category)
        || risk_categories
            .iter()
            .any(|risk| *risk != category && *risk != INFORMATIONAL_CATEGORY)
    {
        return None;
    }
    let target_label =
        nonempty(intent, "target_domain").or_else(|| nonempty(intent, "target_origin"));
    Some(Eligibility {
        server_identity_hash,
        server_name,
        category,
        target_label,
    })
}

/// `parse_temporary_mcp_grant_selection` and the selector
/// `temporary_mcp_grant_decision` files it under. The outer error is a
/// malformed request; the inner one is a pick the card refuses.
fn select(
    found: &Eligibility,
    pick: &Map<String, Value>,
) -> Result<Result<Value, &'static str>, &'static str> {
    let text = |key: &str| match pick.get(key) {
        Some(Value::String(text)) => Ok(text.as_str()),
        _ => Err(ERR_INVALID),
    };
    let (now, artifact_id, artifact_hash) =
        (text("now")?, text("artifact_id")?, text("artifact_hash")?);
    let target = pick
        .get("target")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !TARGETS.contains(&target) {
        return Ok(Err("invalid_mcp_grant_target"));
    }
    let duration = pick
        .get("duration")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let Some(seconds) = DURATIONS
        .iter()
        .find_map(|(name, seconds)| (*name == duration).then_some(*seconds))
    else {
        return Ok(Err("invalid_mcp_grant_duration"));
    };
    let Some(expires_at) =
        crate::guard_store_json::add_seconds_utc_isoformat(now, seconds * 1_000_000)
    else {
        return Ok(Err("invalid_mcp_grant_timestamp"));
    };
    let artifact_id = match target {
        "exact" => exact_grant_selector(artifact_id, artifact_hash),
        "category" => scope_grant_selector(&found.server_identity_hash, Some(found.category)),
        _ => scope_grant_selector(&found.server_identity_hash, None),
    };
    Ok(Ok(json!({
        "target": target,
        "duration": duration,
        "expires_at": expires_at,
        "server_name": found.server_name,
        "server_identity_hash": found.server_identity_hash,
        "category": found.category,
        "artifact_id": artifact_id,
    })))
}

/// `_nonempty_string`.
fn nonempty(fields: &Map<String, Value>, key: &str) -> Option<String> {
    let text = python_strip(fields.get(key)?.as_str()?);
    (!text.is_empty()).then(|| text.to_owned())
}

#[cfg(test)]
#[path = "temporary_mcp_grant_tests.rs"]
mod tests;
