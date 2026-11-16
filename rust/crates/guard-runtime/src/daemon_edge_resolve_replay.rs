//! A decision on a request that is no longer pending, answered in the daemon.
//!
//! `library_calls._approval_resolve` read the stored request first. One
//! already resolved was never resolved again: a repeat of the recorded
//! decision got the idempotent body, any other decision `already_resolved`.
//! Both compare against the scope the user's choice selects, so the choice is
//! selected here with the same op the library asked, and its refusals become
//! the errors the library raised.
//!
//! A request the library would still resolve, and one whose answer depends
//! on what only the library holds (a temporary MCP or local tool grant offer,
//! or a native Bash review the policy owner verifies), goes to the library.

use guard_contracts::{ApprovalScopeSelectRequestV1, APPROVAL_SCOPE_SELECT_REQUEST_SCHEMA};
use serde_json::{json, Map, Value};

use crate::guard_store_approval_read_scope::{scope_contract, scope_item};

/// `models.DECISION_SCOPE_VALUES`.
const DECISION_SCOPE_VALUES: [&str; 5] =
    ["global", "harness", "workspace", "artifact", "publisher"];
/// `approval_scope_selection._INELIGIBLE_REASONS`.
const INELIGIBLE_REASONS: [&str; 5] = [
    "ineligible_request_scope",
    "request_action_not_overridable",
    "saved_allow_scope_ineligible",
    "saved_block_scope_ineligible",
    "execution_binding_unavailable",
];

/// The user's decision as the route read it.
pub(in crate::daemon_edge) struct Decision<'a> {
    pub(super) action: &'a str,
    pub(super) scope: &'a str,
    pub(super) contract_version: Option<&'a str>,
    pub(super) contract_digest: Option<&'a str>,
}

/// The library's answer for `existing`, or `None` when the library resolves
/// it. `Err` holds the error the library would have raised.
pub(super) fn replay(
    existing: &Map<String, Value>,
    decision: &Decision<'_>,
    cwd: Option<&str>,
) -> Option<Result<Value, Map<String, Value>>> {
    if existing.get("status").and_then(Value::as_str) == Some("pending")
        || super::super::super::requests::may_carry_grant_offer(existing)
        || existing.get("artifact_type").and_then(Value::as_str)
            == Some(guard_contracts::NATIVE_BASH_REVIEW_ARTIFACT_TYPE)
    {
        return None;
    }
    Some(answer(existing, decision, cwd))
}

fn answer(
    existing: &Map<String, Value>,
    decision: &Decision<'_>,
    cwd: Option<&str>,
) -> Result<Value, Map<String, Value>> {
    let applied_scope = select(existing, decision, cwd)?;
    let repeated = existing.get("resolution_action").and_then(Value::as_str)
        == Some(decision.action)
        && existing.get("resolution_scope").and_then(Value::as_str) == Some(&applied_scope);
    if !repeated {
        return Ok(json!({"already_resolved": true}));
    }
    // `_idempotent_body`, its contract derived again from the stored request
    // as `request_scope_contract_payload` derived it.
    let mut body = scope_contract(existing, cwd, None).map_err(|_| unavailable())?;
    body.insert("resolved".to_owned(), Value::Bool(true));
    body.insert("idempotent".to_owned(), Value::Bool(true));
    body.insert(
        "resolved_request".to_owned(),
        Value::Object(existing.clone()),
    );
    body.insert("requested_scope".to_owned(), json!(decision.scope));
    body.insert("applied_scope".to_owned(), json!(applied_scope));
    Ok(json!({"idempotent": body}))
}

/// `resolve_request_scope_selection` without the persistence question: the
/// scope the decision applies at, or the error it raised.
fn select(
    existing: &Map<String, Value>,
    decision: &Decision<'_>,
    cwd: Option<&str>,
) -> Result<String, Map<String, Value>> {
    let item = scope_item(existing, cwd).map_err(|_| unavailable())?;
    let request = ApprovalScopeSelectRequestV1 {
        schema: APPROVAL_SCOPE_SELECT_REQUEST_SCHEMA.to_owned(),
        request_id: String::new(),
        item,
        action: decision.action.to_owned(),
        requested_scope: decision.scope.to_owned(),
        contract_version: decision.contract_version.map(str::to_owned),
        contract_digest: decision.contract_digest.map(str::to_owned),
        persist: None,
    };
    let answer = crate::approval_scope_select_op::evaluate(&request);
    let mut contract = answer.get("contract").and_then(Value::as_object).cloned();
    if let Some(contract) = &mut contract {
        contract.remove("exact_context_token");
    }
    match answer.get("outcome").and_then(Value::as_str) {
        Some("selected") => {
            let applied = answer
                .get("applied_scope")
                .and_then(Value::as_str)
                .filter(|scope| DECISION_SCOPE_VALUES.contains(scope));
            let warning_ok = matches!(answer.get("warning"), None | Some(Value::Null))
                || answer.get("warning").is_some_and(Value::is_string);
            match applied {
                Some(applied) if warning_ok => Ok(applied.to_owned()),
                _ => Err(unavailable()),
            }
        }
        Some("refused") => Err(refusal(&answer, contract, decision)),
        _ => Err(unavailable()),
    }
}

/// The error `resolve_request_scope_selection` raised for a refusal, as
/// `_error_payload` reported it.
fn refusal(
    answer: &Value,
    contract: Option<Map<String, Value>>,
    decision: &Decision<'_>,
) -> Map<String, Value> {
    let reason = answer.get("reason").and_then(Value::as_str).unwrap_or("");
    match reason {
        "unsupported_resolution_action" => return value_error(reason.to_owned()),
        "unsupported_approval_scope" => {
            return value_error(format!("Unsupported approval scope: {}", decision.scope));
        }
        _ => {}
    }
    let Some(contract) = contract else {
        return unavailable();
    };
    if reason == "incomplete_scope_contract" {
        return value_error(reason.to_owned());
    }
    if reason == "stale_scope_contract" {
        return error(
            "StaleApprovalScopeContractError",
            "stale_scope_contract",
            reason,
            [("contract", Value::Object(contract))],
        );
    }
    if INELIGIBLE_REASONS.contains(&reason) {
        let requested_scope = answer
            .get("applied_scope")
            .and_then(Value::as_str)
            .filter(|scope| !scope.is_empty())
            .unwrap_or(decision.scope);
        return error(
            "IneligibleApprovalScopeError",
            "ineligible_scope",
            reason,
            [
                ("contract", Value::Object(contract)),
                ("action", json!(decision.action)),
                ("requested_scope", json!(requested_scope)),
            ],
        );
    }
    unavailable()
}

fn error<const N: usize>(
    kind_type: &str,
    kind: &str,
    message: &str,
    extra: [(&str, Value); N],
) -> Map<String, Value> {
    let mut error = Map::new();
    error.insert("type".to_owned(), json!(kind_type));
    error.insert("message".to_owned(), json!(message));
    error.insert("kind".to_owned(), json!(kind));
    for (key, value) in extra {
        error.insert(key.to_owned(), value);
    }
    error
}

/// `ApprovalRequestNotFoundError`, which resolving an unknown request raised
/// before anything else.
pub(super) fn not_found(request_id: &str) -> Map<String, Value> {
    error(
        "ApprovalRequestNotFoundError",
        "not_found",
        &format!("Unknown approval request: {request_id}"),
        [],
    )
}

fn value_error(message: String) -> Map<String, Value> {
    error("ValueError", "value", &message, [])
}

fn unavailable() -> Map<String, Value> {
    error(
        "ApprovalScopeUnavailableError",
        "scope_unavailable",
        crate::guard_store_approval_read_scope::UNAVAILABLE,
        [],
    )
}

#[cfg(test)]
#[path = "daemon_edge_resolve_replay_tests.rs"]
mod tests;
