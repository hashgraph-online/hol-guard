//! Compose pure reported Native, prompt, CLI, route and cancel relations.
//! This does not independently observe the processes or physical effects.

use crate::{
    canonical_value, recompute_native_review_summary, verify_cancel_reported_relation,
    verify_contained_cli_results, verify_contained_output_custody,
    verify_contained_route_accounting, verify_native_review_summary,
    verify_private_runtime_prompt_relation, ControlReportedTail, EvidenceError, Result,
};
use serde_json::{json, Value};

const INVALID: EvidenceError = EvidenceError::Invalid("invalid reported control relation");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlReportedRelations {
    pub contained_routes: usize,
    pub output_bindings: usize,
    pub public_prompts: usize,
    pub contained_cli_results: usize,
    pub cancel_partial_relation: bool,
}

pub fn verify_control_reported_relations(
    record_raw: &[u8],
    role: &str,
    outside_public_key: &[u8],
    outside_runtime: &Value,
    tail: &ControlReportedTail,
) -> Result<ControlReportedRelations> {
    if !matches!(
        role,
        "success" | "input-binding" | "boundary" | "timeout" | "cancel"
    ) || tail.role != role
    {
        return Err(INVALID);
    }
    let record: Value = serde_json::from_slice(record_raw).map_err(|_| INVALID)?;
    let builtin = &tail.session.signed.builtin;
    let reviews = verify_native_review_summary(builtin)?;
    if reviews["review_complete"] != (role != "cancel")
        || (role == "cancel"
            && builtin["review_summary"]["missing_required_post_call_ids"]
                != json!(["sdk-contained-control"]))
    {
        return Err(EvidenceError::Invalid(
            "control Native review status differs from role",
        ));
    }
    if role == "cancel" {
        let summary = recompute_native_review_summary(
            &builtin["transport_observations"],
            &builtin["contained_transport_observations"],
        )?;
        verify_cancel_reported_relation(record_raw, outside_public_key, outside_runtime, &summary)?;
        return Ok(ControlReportedRelations {
            contained_routes: 0,
            output_bindings: 0,
            public_prompts: 0,
            contained_cli_results: 0,
            cancel_partial_relation: true,
        });
    }
    let runtime_raw = canonical_value(&record["developer_runtime"])?;
    let prompt_digest = tail.session.public_prompt_digest.as_str().ok_or(INVALID)?;
    let prompt = verify_private_runtime_prompt_relation(
        &runtime_raw,
        outside_public_key,
        &tail.session.session_id,
        prompt_digest,
    )?;
    if prompt["matched_public_prompts"].as_u64() != Some(1) {
        return Err(INVALID);
    }
    let cli = verify_contained_cli_results(
        &tail.session.signed.plane,
        &tail.session.signed.settings,
        &tail.session.agent_identity,
    )?;
    if cli["checked_executions"].as_u64() != Some(1) {
        return Err(INVALID);
    }
    let route = verify_contained_route_accounting(builtin, &tail.session.signed.plane)?;
    let routes = route["matched_routes"].as_u64().ok_or(INVALID)? as usize;
    let bindings = verify_contained_output_custody(builtin)?;
    if routes != 1 || bindings != 1 {
        return Err(EvidenceError::Invalid(
            "control contained-route or output count differs from role",
        ));
    }
    Ok(ControlReportedRelations {
        contained_routes: routes,
        output_bindings: bindings,
        public_prompts: 1,
        contained_cli_results: 1,
        cancel_partial_relation: false,
    })
}
