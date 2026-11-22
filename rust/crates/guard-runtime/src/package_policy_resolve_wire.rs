use guard_contracts::{
    PackagePolicyResolveRequestV1, SupplyChainEvalResultV1, PACKAGE_AUTHORITY_REQUEST_SCHEMA,
    PACKAGE_AUTHORITY_RESULT_SCHEMA,
};
use serde_json::{Map, Value};

use super::{invalid, malformed, resolve};
use crate::package_authority_op::request_digest;
use crate::package_evaluation_compose_op::patch;

pub(crate) fn evaluate_package_policy_resolve(
    request: &PackagePolicyResolveRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request)?;
    if request.schema != PACKAGE_AUTHORITY_REQUEST_SCHEMA {
        return Err("native_package_policy_resolve_schema_mismatch".to_owned());
    }
    if malformed(request) {
        return Err(invalid());
    }
    let resolution = resolve(request)?;
    let mut payload = Map::new();
    payload.insert(
        "patch".to_owned(),
        patch(&request.evaluation, resolution.output),
    );
    payload.insert("claim".to_owned(), serde_json::json!(resolution.claim));
    payload.insert(
        "claim_disposition".to_owned(),
        serde_json::json!(resolution.claim_disposition),
    );
    payload.insert("reused".to_owned(), serde_json::json!(resolution.reused));
    payload.insert(
        "decision".to_owned(),
        resolution.decision.unwrap_or(Value::Null),
    );
    payload.insert(
        "authority".to_owned(),
        resolution.authority.unwrap_or(Value::Null),
    );
    crate::encode_response(&SupplyChainEvalResultV1 {
        schema: PACKAGE_AUTHORITY_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: "ok".to_owned(),
        code: "ok".to_owned(),
        payload: Some(Value::Object(payload)),
    })
}
