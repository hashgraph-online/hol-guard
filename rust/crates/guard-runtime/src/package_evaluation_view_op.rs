//! `PackageEvaluationView` — resident op that reads a stored or replayed
//! package evaluation back into the view a caller shows.
//!
//! Python used to hold a second copy of this grammar: the default for every
//! missing field, the review an unrecognised policy action falls back to and
//! the reason row that records it, the support metadata each package row
//! carries, the sha256 shape an external archive hash has to have, and the way
//! the user copy reads once the local route has no cloud inbox to send anyone
//! to. All of it already lived in `PackageEvalResult::from_cache_dict`, so the
//! caller now sends the payload and reads the answer rather than deriving a
//! second one beside it.

use guard_command::supply_chain_package_eval::PackageEvalResult;
use guard_contracts::{
    PackageEvaluationViewRequestV1, SupplyChainEvalResultV1, PACKAGE_AUTHORITY_REQUEST_SCHEMA,
    PACKAGE_AUTHORITY_RESULT_SCHEMA, PACKAGE_EVALUATION_VIEW_MAX_REQUEST_BYTES,
};
use serde_json::Value;

use crate::package_authority_op::request_digest_with_limit;

fn invalid() -> String {
    "native_package_evaluation_view_invalid".to_owned()
}

pub(crate) fn evaluate_package_evaluation_view(
    request: &PackageEvaluationViewRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 =
        request_digest_with_limit(request, PACKAGE_EVALUATION_VIEW_MAX_REQUEST_BYTES)?;
    if request.schema != PACKAGE_AUTHORITY_REQUEST_SCHEMA {
        return Err("native_package_evaluation_view_schema_mismatch".to_owned());
    }
    if request.request_id.is_empty() {
        return Err(invalid());
    }
    // A payload that is not an object names no evaluation. Defaulting it to an
    // empty one here would invent an allow-shaped view out of nothing.
    let Value::Object(payload) = &request.payload else {
        return Err(invalid());
    };
    let view = PackageEvalResult::from_cache_dict(
        payload,
        &request.package_intent_hash,
        &request.policy_version,
        request.bundle_version.as_deref(),
        request.workspace_fingerprint.as_deref(),
    );
    crate::encode_response(&SupplyChainEvalResultV1 {
        schema: PACKAGE_AUTHORITY_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: "ok".to_owned(),
        code: "ok".to_owned(),
        payload: Some(view.to_dict()),
    })
}

#[cfg(test)]
#[path = "package_evaluation_view_op_tests.rs"]
mod tests;
