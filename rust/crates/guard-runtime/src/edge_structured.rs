//! Structured output mediation for a Pi or Oh My Pi `PostToolUse` the daemon
//! sends the edge.
//!
//! After the edge decides, the daemon used to load the managed policy from
//! Guard config and run three native queries it only transported: the view
//! resolves to a binding, `mediate_prepare` scans the model-visible content
//! against it, and `mediate_finish` forwards only once a second read of the
//! view still names the binding the scan ran under. The daemon now sends the
//! managed-policy view with the envelope (`structured_output_config`), and
//! the edge runs the same resolution and mediation the resident's direct
//! lane runs, so its answer already carries `structured_content_mediation`.
//!
//! The second read stays with the daemon, which alone holds the config: the
//! edge has no later view to compare against, so it proposes the forward
//! against the view it was given, and the daemon withholds it if a fresh read
//! of the config no longer matches that view.

use crate::hook_direct::{
    pi, DEFAULT_DEADLINE_BUDGET_MS, MAX_DEADLINE_BUDGET_MS, STRUCTURED_OUTPUT_FIELD,
};
use guard_contracts::{GuardHookEdgeResultV2, GuardHookEnvelopeV2};
use serde_json::{json, Value};
use std::time::{Duration, Instant};

/// The key the mediation rides under in the harness response.
const MEDIATION_FIELD: &str = "structured_content_mediation";

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
) -> GuardHookEdgeResultV2 {
    attach(envelope, &mut edge, started);
    edge
}

fn attach(envelope: &GuardHookEnvelopeV2, edge: &mut GuardHookEdgeResultV2, started: Instant) {
    let Some(view) = envelope.structured_output_config.as_ref() else {
        return;
    };
    if !pi::structured_mediation(&edge.harness, &edge.event_name)
        || edge.result["decision"] != "allow"
    {
        return;
    }
    let resolution =
        pi::resolution(&edge.harness, Some(view)).unwrap_or_else(authority_unavailable);
    // The edge's own receipt, which the daemon mediates against once it has
    // recorded it; a receipt that cannot be encoded is no receipt, which
    // `mediate_prepare` withholds on.
    let receipt = serde_json::to_value(&edge.receipt).unwrap_or(Value::Null);
    let content = envelope
        .raw_payload
        .get(STRUCTURED_OUTPUT_FIELD)
        .cloned()
        .unwrap_or(Value::Null);
    let budget = envelope
        .deadline_budget_ms
        .unwrap_or(DEFAULT_DEADLINE_BUDGET_MS)
        .clamp(1, MAX_DEADLINE_BUDGET_MS);
    let context = pi::Mediation {
        harness: &edge.harness,
        resolution: &resolution,
        result: &edge.result,
        receipt: &receipt,
        content: &content,
        recording_only: envelope.recording_only,
        deadline: started + Duration::from_millis(budget),
    };
    let mediation = pi::mediate(&context, || pi::resolved_binding(&resolution));
    if let (Some(mediation), Some(Value::Object(response))) =
        (mediation, edge.harness_response.as_mut())
    {
        response.insert(MEDIATION_FIELD.to_owned(), mediation);
    }
}

#[cfg(test)]
#[path = "edge_structured_tests.rs"]
mod tests;
