//! `LocalToolEligibility` — whether one shell command may carry a reusable
//! local tool grant.
//!
//! The command earns a grant identity only through an authenticated local
//! Node validation routine, a narrow package-run profile, or a verified local
//! executable whose operation and options are read-only. Any refusal or
//! unreadable input answers `null`: not eligible, never more permissive.

use std::path::Path;

use guard_command::local_tool_eligibility::{
    local_tool_eligibility, LocalToolEligibility, LocalToolEligibilityInput, TrustedTree,
    TRUSTED_PACKAGE_TREES,
};
use guard_contracts::{
    LocalToolEligibilityRequestV1, LocalToolEligibilityResultV1,
    LOCAL_TOOL_ELIGIBILITY_REQUEST_SCHEMA, LOCAL_TOOL_ELIGIBILITY_RESULT_SCHEMA,
};
use serde_json::{json, Map, Value};

pub(crate) fn evaluate_local_tool_eligibility_request(
    request: &LocalToolEligibilityRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request)?;
    if request.schema != LOCAL_TOOL_ELIGIBILITY_REQUEST_SCHEMA {
        return Err("native_local_tool_eligibility_schema_mismatch".to_owned());
    }
    let payload = eligibility(request, TRUSTED_PACKAGE_TREES)
        .map_or(Value::Null, |found| eligibility_payload(&found));
    crate::resident_protocol::encode_response(&LocalToolEligibilityResultV1 {
        schema: LOCAL_TOOL_ELIGIBILITY_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: "ok".to_owned(),
        code: "ok".to_owned(),
        payload,
    })
}

fn request_digest(request: &LocalToolEligibilityRequestV1) -> Result<String, String> {
    let material = serde_json::to_value(request)
        .map_err(|_| "native_local_tool_eligibility_request_invalid".to_owned())?;
    let mut bytes = Vec::new();
    crate::context_digest_json::write_canonical_json_with_limit(&material, &mut bytes, usize::MAX)
        .map_err(|_| "native_local_tool_eligibility_request_invalid".to_owned())?;
    Ok(format!(
        "sha256:{}",
        guard_policy_snapshot::digest_bytes(&bytes)
    ))
}

/// The decision for one request against the given trusted package trees.
pub(crate) fn eligibility(
    request: &LocalToolEligibilityRequestV1,
    trusted_trees: &[TrustedTree<'_>],
) -> Option<LocalToolEligibility> {
    let launch_env = Value::Object(
        request
            .launch_env
            .iter()
            .map(|(name, value)| (name.clone(), Value::String(value.clone())))
            .collect::<Map<String, Value>>(),
    );
    let input = LocalToolEligibilityInput {
        command: &request.command,
        cwd: Path::new(&request.cwd),
        home_dir: request.home_dir.as_deref().map(Path::new),
        user_home: request.user_home.as_deref().map(Path::new),
        launch_env: &launch_env,
    };
    local_tool_eligibility(&input, trusted_trees)
}

fn eligibility_payload(found: &LocalToolEligibility) -> Value {
    json!({
        "tool_name": found.tool_name,
        "tool_identity_hash": found.tool_identity_hash,
        "capability": found.capability,
        "read_only_reason": found.read_only_reason,
        "trust_basis": found.trust_basis,
        "indefinite_allowed": found.indefinite_allowed,
    })
}

#[cfg(all(test, unix))]
#[path = "local_tool_eligibility_op_tests.rs"]
mod tests;
