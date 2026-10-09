//! `PackageEvaluationCompose` — resident op owning the package-verdict
//! rewrites that `local_supply_chain.py` used to compute in Python:
//! `_package_evaluation_with_current_policy_action`,
//! `_package_evaluation_with_rejected_reuse`, the saved-allow / saved-block
//! overrides of `_resolve_stored_package_policy_override`, and the external
//! archive binding blocks.
//!
//! The caller sends only the evaluation fields a rewrite reads
//! (`policy_action`, `reasons`, `packages`) plus kind-specific facts. The
//! runtime picks every resulting decision, policy action, reason, and copy
//! field and returns a patch of the rewritten fields; the caller applies it
//! mechanically and never recomputes a verdict.

use guard_command::approval_reuse::ApprovalReuseDecision;
use guard_command::effect_decision::GuardAction;
use guard_command::package_policy_override as policy;
use guard_contracts::{
    PackageEvaluationComposeRequestV1, SupplyChainEvalResultV1, PACKAGE_AUTHORITY_REQUEST_SCHEMA,
    PACKAGE_AUTHORITY_RESULT_SCHEMA,
};
use serde_json::{Map, Value};

use crate::package_authority_op::{request_digest, ResidentPackageEval};

const PATCH_KEYS: [&str; 7] = [
    "decision",
    "policy_action",
    "reasons",
    "packages",
    "risk_summary",
    "user_copy",
    "record_monitor_evidence",
];

const SAVED_ALLOW_SUMMARY: &str = "HOL Guard reused your saved approval for this package request.";
const SAVED_BLOCK_SUMMARY: &str =
    "HOL Guard kept this package blocked because a saved package policy already exists.";

fn invalid() -> String {
    "native_package_evaluation_compose_invalid".to_owned()
}

fn parse_action(text: &str) -> Result<GuardAction, String> {
    [
        GuardAction::Allow,
        GuardAction::Warn,
        GuardAction::Review,
        GuardAction::RequireReapproval,
        GuardAction::SandboxRequired,
        GuardAction::Block,
    ]
    .into_iter()
    .find(|action| action.as_str() == text)
    .ok_or_else(invalid)
}

fn evidence_str<'a>(evidence: &'a Map<String, Value>, key: &str) -> Result<&'a str, String> {
    evidence
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(invalid)
}

/// Strictly rebuild the reuse decision from `ApprovalReuseDecision.to_evidence()`.
fn parse_reuse(value: Option<&Value>) -> Result<ApprovalReuseDecision, String> {
    let evidence = value.and_then(Value::as_object).ok_or_else(invalid)?;
    let status = match evidence_str(evidence, "status")? {
        "accepted" => "accepted",
        "rejected" => "rejected",
        "not-applicable" => "not-applicable",
        _ => return Err(invalid()),
    };
    let reason_code = evidence_str(evidence, "reason_code")?;
    if reason_code.trim().is_empty() {
        return Err(invalid());
    }
    let saved_action = match evidence.get("saved_action") {
        None | Some(Value::Null) => None,
        Some(Value::String(text)) => Some(parse_action(text)?),
        Some(_) => return Err(invalid()),
    };
    let should_claim = evidence
        .get("should_claim")
        .and_then(Value::as_bool)
        .ok_or_else(invalid)?;
    Ok(ApprovalReuseDecision {
        action: parse_action(evidence_str(evidence, "action")?)?,
        status,
        reason_code: reason_code.to_owned(),
        current_action: parse_action(evidence_str(evidence, "current_action")?)?,
        saved_action,
        should_claim,
        current_normalization_reason_code: None,
        saved_normalization_reason_code: None,
        original_current_action: None,
        original_saved_action: None,
        original_current_type: "str".to_owned(),
        original_saved_type: None,
        saved_artifact_hash_is_context_token: None,
    })
}

/// The evaluation subset must hold a valid action and dict-only lists; Python
/// would raise on anything else, so the runtime rejects it rather than guess.
fn parse_evaluation(value: &Value) -> Result<Map<String, Value>, String> {
    let map = value.as_object().ok_or_else(invalid)?;
    if map
        .keys()
        .any(|key| !matches!(key.as_str(), "policy_action" | "reasons" | "packages"))
    {
        return Err(invalid());
    }
    parse_action(
        map.get("policy_action")
            .and_then(Value::as_str)
            .ok_or_else(invalid)?,
    )?;
    for key in ["reasons", "packages"] {
        let items = map.get(key).and_then(Value::as_array).ok_or_else(invalid)?;
        if items.iter().any(|item| !item.is_object()) {
            return Err(invalid());
        }
    }
    Ok(map.clone())
}

/// Reuse evidence is carried verbatim on the reason (Python emits nulls the
/// Rust struct would skip), after the strict parse above bound its fields.
fn with_evidence(mut out: Map<String, Value>, evidence: Option<&Value>) -> Map<String, Value> {
    if let (Some(evidence), Some(Value::Array(reasons))) = (evidence, out.get_mut("reasons")) {
        if let Some(Value::Object(first)) = reasons.first_mut() {
            first.insert("approval_reuse".to_owned(), evidence.clone());
        }
    }
    out
}

/// Saved allow/block overrides drop prior reasons equal to the new one
/// (Python `item != reason`). The equality must be judged against the reason
/// as Python builds it (verbatim evidence, nulls, original types), so the
/// caller's evidence is attached first and the prior reasons are re-filtered.
fn with_evidence_deduped(
    out: Map<String, Value>,
    evidence: Option<&Value>,
    original: &Map<String, Value>,
) -> Map<String, Value> {
    let mut out = with_evidence(out, evidence);
    let Some(Value::Array(reasons)) = out.get("reasons") else {
        return out;
    };
    let Some(first) = reasons.first().cloned() else {
        return out;
    };
    let mut deduped = vec![first.clone()];
    if let Some(prior) = original.get("reasons").and_then(Value::as_array) {
        deduped.extend(prior.iter().filter(|item| **item != first).cloned());
    }
    out.insert("reasons".to_owned(), Value::Array(deduped));
    out
}

fn reject_unused(
    request: &PackageEvaluationComposeRequestV1,
    used: [bool; 5],
) -> Result<(), String> {
    let present = [
        request.current_action.is_some(),
        request.approval_reuse.is_some(),
        request.variant.is_some(),
        request.claim_disposition.is_some(),
        request.clear_command.is_some(),
    ];
    if present
        .iter()
        .zip(used)
        .any(|(has, allowed)| *has && !allowed)
    {
        return Err(invalid());
    }
    Ok(())
}

fn override_external_archive(
    eval: &ResidentPackageEval,
    map: &Map<String, Value>,
    variant: &str,
) -> Result<Map<String, Value>, String> {
    let (verdict, title, summary, harness, code, message) = match variant {
        "launch_unbound" => (
            "block",
            "External archive blocked",
            "The inspected external archive could not be bound to the installer launch.",
            "HOL Guard blocked an external archive whose digest-bound blob was unavailable.",
            "external_archive_digest_mismatch",
            "The inspected external archive changed or was not present in the installer command.",
        ),
        "mcp_unbound" => (
            "block",
            "External archive blocked",
            "The inspected external archive could not be bound to the forwarded installer request.",
            "HOL Guard blocked an external archive whose digest-bound blob was unavailable.",
            "external_archive_digest_mismatch",
            "The inspected external archive changed or was absent from the forwarded request.",
        ),
        "binding_unavailable" => (
            "block",
            "External archive binding unavailable",
            "Guard cannot prove this command will execute through its digest-binding package shim.",
            "HOL Guard blocked the external archive because the verified package shim is not the resolved executable. Repair or activate package shims and retry.",
            "external_archive_binding_unavailable",
            "External archives may run only through a verified Guard package shim that installs the already inspected blob.",
        ),
        "shim_delegated" => (
            "allow",
            "External archive delegated to Guard shim",
            "The verified package shim will own approval and digest-bound execution.",
            "HOL Guard delegated this package request to its verified digest-binding package shim.",
            "external_archive_delegated_to_binding_shim",
            "The runtime hook permits only the exact verified shim; that shim requires approval before restricted download and executes only the inspected digest-bound blob.",
        ),
        _ => return Err(invalid()),
    };
    Ok(policy::package_policy_override_evaluation(
        eval, map, verdict, verdict, title, summary, harness, None, code, message, None, None,
    ))
}

fn compose(request: &PackageEvaluationComposeRequestV1) -> Result<Map<String, Value>, String> {
    let eval = ResidentPackageEval;
    let map = parse_evaluation(&request.evaluation)?;
    let variant = request.variant.as_deref();
    match request.kind.as_str() {
        "current_policy_action" => {
            reject_unused(request, [true, false, false, false, false])?;
            let action = parse_action(request.current_action.as_deref().ok_or_else(invalid)?)?;
            Ok(policy::package_evaluation_with_current_policy_action(
                &eval, &map, action,
            ))
        }
        "rejected_reuse" => {
            reject_unused(request, [false, true, false, false, false])?;
            let reuse = parse_reuse(request.approval_reuse.as_ref())?;
            let out = policy::package_evaluation_with_rejected_reuse(&eval, &map, &reuse);
            Ok(with_evidence(out, request.approval_reuse.as_ref()))
        }
        "saved_allow" => {
            reject_unused(request, [false, true, true, true, false])?;
            let reuse = parse_reuse(request.approval_reuse.as_ref())?;
            let (harness, disposition) = match variant {
                Some("reused") => (
                    "HOL Guard verified the same repository, package manager, dependency files, settings, and registry environment before reusing your saved approval.",
                    match request.claim_disposition.as_deref() {
                        None => None,
                        Some(d @ ("consumed" | "retained")) => Some(d),
                        Some(_) => return Err(invalid()),
                    },
                ),
                Some("claimed_revalidated") if request.claim_disposition.is_none() => (
                    "HOL Guard revalidated the repository, package manager, dependency files, settings, registry environment, and current advisory authority after atomically claiming approval.",
                    None,
                ),
                _ => return Err(invalid()),
            };
            let out = policy::package_policy_override_evaluation(
                &eval,
                &map,
                "allow",
                "allow",
                "Allowed by saved approval",
                SAVED_ALLOW_SUMMARY,
                harness,
                None,
                "saved_package_approval",
                SAVED_ALLOW_SUMMARY,
                Some(&reuse),
                disposition,
            );
            Ok(with_evidence_deduped(
                out,
                request.approval_reuse.as_ref(),
                &map,
            ))
        }
        "saved_block" => {
            reject_unused(request, [false, true, false, false, true])?;
            let reuse = parse_reuse(request.approval_reuse.as_ref())?;
            let clear = request.clear_command.as_deref().ok_or_else(invalid)?;
            let harness = format!(
                "HOL Guard kept this package blocked because a saved package policy already exists. To reconsider, run `{clear}`, then retry the install."
            );
            let out = policy::package_policy_override_evaluation(
                &eval,
                &map,
                "block",
                "block",
                "Blocked by saved policy",
                SAVED_BLOCK_SUMMARY,
                &harness,
                Some(clear),
                "saved_package_block",
                SAVED_BLOCK_SUMMARY,
                Some(&reuse),
                None,
            );
            Ok(with_evidence_deduped(
                out,
                request.approval_reuse.as_ref(),
                &map,
            ))
        }
        "external_archive_override" => {
            reject_unused(request, [false, false, true, false, false])?;
            override_external_archive(&eval, &map, variant.ok_or_else(invalid)?)
        }
        _ => Err(invalid()),
    }
}

/// Fields a rewrite changed or introduced relative to the caller's subset.
fn patch(input: &Value, output: Map<String, Value>) -> Value {
    let mut patch = Map::new();
    for key in PATCH_KEYS {
        if let Some(value) = output.get(key) {
            if input.get(key) != Some(value) {
                patch.insert(key.to_owned(), value.clone());
            }
        }
    }
    Value::Object(patch)
}

pub(crate) fn evaluate_package_evaluation_compose(
    request: &PackageEvaluationComposeRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request)?;
    if request.schema != PACKAGE_AUTHORITY_REQUEST_SCHEMA {
        return Err("native_package_evaluation_compose_schema_mismatch".to_owned());
    }
    if request.request_id.is_empty() || request.guard_home.is_empty() {
        return Err(invalid());
    }
    let output = compose(request)?;
    let mut payload = Map::new();
    payload.insert("patch".to_owned(), patch(&request.evaluation, output));
    crate::encode_response(&SupplyChainEvalResultV1 {
        schema: PACKAGE_AUTHORITY_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: "ok".to_owned(),
        code: "ok".to_owned(),
        payload: Some(Value::Object(payload)),
    })
}

#[cfg(test)]
#[path = "package_evaluation_compose_op_tests.rs"]
mod tests;
