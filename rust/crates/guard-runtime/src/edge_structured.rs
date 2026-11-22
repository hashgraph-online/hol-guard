//! Structured output mediation for a Pi or Oh My Pi `PostToolUse` the daemon
//! sends the edge.
//!
//! The edge resolves the managed-policy view from the authenticated direct
//! lane and runs the same resolution and mediation the resident's direct lane
//! runs. Its answer already carries `structured_content_mediation`, so the
//! daemon does not supply or recheck a second policy copy. The envelope field
//! remains a compatibility path for isolated callers and older fixtures.

use crate::hook_direct::{
    pi, DEFAULT_DEADLINE_BUDGET_MS, MAX_DEADLINE_BUDGET_MS, STRUCTURED_OUTPUT_FIELD,
};
use guard_contracts::{GuardHookEdgeResultV2, GuardHookEnvelopeV2};
use serde_json::{json, Value};
use std::time::{Duration, Instant};

/// The key the mediation rides under in the harness response.
const MEDIATION_FIELD: &str = "structured_content_mediation";
pub(crate) const DIRECT_LANE_FEATURE: &str = "edge-structured-output-binding-v1";

/// What the daemon resolves when it cannot establish the managed policy: the
/// destination is required, and nothing names a binding it may be forwarded
/// under, so it is withheld.
fn authority_unavailable() -> Value {
    json!({
        "binding": null,
        "required": true,
        "reason_code": "structured_managed_authority_unavailable",
    })
}

/// Adds `structured_content_mediation` to the harness response of an allowed
/// Pi or Oh My Pi `PostToolUse` whose envelope carried a managed-policy view.
///
/// Every other hook keeps the response the edge rendered: another harness or
/// event, a verdict that is not an allow (a native denial leaves no
/// model-visible content to project), and an envelope without a view, which
/// is the direct lane's and every other caller's. A view that is not the shape
/// the resolution reads, or whose query fails, resolves as the daemon resolves
/// a config it cannot read: required, with no binding, so the content is
/// withheld. A policy that requires nothing adds no field.
///
/// `started` is when the edge began the hook, so the scan's deadline counts
/// the review it followed, as the daemon's absolute deadline did. This runs
/// once the edge result has been checked: the mediation projects its verdict
/// and receipt and changes neither.
pub(crate) fn attached(
    envelope: &GuardHookEnvelopeV2,
    mut edge: GuardHookEdgeResultV2,
    started: Instant,
    origin_store: Option<&crate::policy_store::PolicySnapshotStore>,
) -> GuardHookEdgeResultV2 {
    attach(envelope, &mut edge, started, origin_store);
    edge
}

fn attach(
    envelope: &GuardHookEnvelopeV2,
    edge: &mut GuardHookEdgeResultV2,
    started: Instant,
    origin_store: Option<&crate::policy_store::PolicySnapshotStore>,
) {
    if !pi::structured_mediation(&edge.harness, &edge.event_name)
        || edge.result["decision"] != "allow"
    {
        return;
    }
    if edge
        .harness_response
        .as_ref()
        .and_then(Value::as_object)
        .is_some_and(|response| response.contains_key(MEDIATION_FIELD))
    {
        return;
    }
    let budget = envelope
        .deadline_budget_ms
        .unwrap_or(DEFAULT_DEADLINE_BUDGET_MS)
        .clamp(1, MAX_DEADLINE_BUDGET_MS);
    let deadline = started + Duration::from_millis(budget);
    // A lane the daemon closed to republish is awaited for at most three
    // quarters of the budget, which leaves the rest for the scan and reply.
    let wait_until = started + Duration::from_millis(budget.saturating_mul(3) / 4);
    let resident = origin_store.map(|store| {
        let digest = envelope
            .policy_snapshot
            .get("policy_digest")
            .and_then(Value::as_str)?;
        store.structured_output_binding_awaiting(envelope.policy_generation, digest, wait_until)
    });
    let view = match &resident {
        Some(Some(lane)) => match &lane.view {
            Some(view) => Some(view.clone()),
            None => return,
        },
        Some(None) => Some(authority_unavailable()),
        None => envelope.structured_output_config.clone(),
    };
    let Some(view) = view else {
        return;
    };
    let resolution =
        pi::resolution(&edge.harness, Some(&view)).unwrap_or_else(authority_unavailable);
    // The edge's own receipt, which the daemon mediates against once it has
    // recorded it; a receipt that cannot be encoded is no receipt, which
    // `mediate_prepare` withholds on.
    let receipt = serde_json::to_value(&edge.receipt).unwrap_or(Value::Null);
    let content = envelope
        .raw_payload
        .get(STRUCTURED_OUTPUT_FIELD)
        .cloned()
        .unwrap_or(Value::Null);
    let context = pi::Mediation {
        harness: &edge.harness,
        resolution: &resolution,
        result: &edge.result,
        receipt: &receipt,
        content: &content,
        recording_only: envelope.recording_only,
        deadline,
    };
    let mediation = pi::mediate(&context, || {
        let Some(store) = origin_store else {
            return pi::resolved_binding(&resolution);
        };
        // Recheck against the binding the view was read under, which may be
        // a republish newer than the generation the daemon decided under.
        let (generation, digest) = match &resident {
            Some(Some(lane)) => (lane.generation, lane.policy_digest.as_str()),
            _ => match envelope
                .policy_snapshot
                .get("policy_digest")
                .and_then(Value::as_str)
            {
                Some(digest) => (envelope.policy_generation, digest),
                None => return Value::Null,
            },
        };
        match store.structured_output_binding(generation, digest, Some(deadline)) {
            Some(Some(current_view)) => pi::resolution(&edge.harness, Some(&current_view))
                .map(|current| pi::resolved_binding(&current))
                .unwrap_or(Value::Null),
            Some(None) | None => Value::Null,
        }
    });
    if let (Some(mediation), Some(Value::Object(response))) =
        (mediation, edge.harness_response.as_mut())
    {
        response.insert(MEDIATION_FIELD.to_owned(), mediation);
    }
}

#[cfg(test)]
#[path = "edge_structured_tests.rs"]
mod tests;
