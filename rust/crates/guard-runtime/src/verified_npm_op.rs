//! `VerifiedNpm` — resident op proving which `npm` an agent's `PATH` runs.
//!
//! Port of the npm-proving half of
//! `daemon/hook_native_package_review.py`. The caller forwards the stamped
//! execution environment and the workspace; the runtime resolves `npm` and
//! `node`, reads the npm manifest and the npm config files above the project,
//! and returns a version only when nothing in that environment could have
//! moved the fetch. The caller applies the answer and never re-derives it.

use std::path::Path;

use guard_command::verified_npm;
use guard_contracts::{
    SupplyChainEvalResultV1, VerifiedNpmRequestV1, PACKAGE_AUTHORITY_REQUEST_SCHEMA,
    PACKAGE_AUTHORITY_RESULT_SCHEMA,
};
use serde_json::{Map, Value};

use crate::package_authority_op::request_digest;

fn invalid() -> String {
    "native_verified_npm_invalid".to_owned()
}

pub(crate) fn evaluate_verified_npm(request: &VerifiedNpmRequestV1) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request)?;
    if request.schema != PACKAGE_AUTHORITY_REQUEST_SCHEMA {
        return Err("native_verified_npm_schema_mismatch".to_owned());
    }
    if request.request_id.is_empty() || request.guard_home.is_empty() {
        return Err(invalid());
    }
    let workspace = Path::new(&request.workspace);
    if !workspace.is_absolute() {
        return Err(invalid());
    }
    let environment = verified_npm::ExecutionEnvironment::from_value(request.environment.as_ref());
    let version = verified_npm::verified_npm_version(&environment, workspace);
    let filters_outside =
        verified_npm::filters_outside_workspace(&request.filter_programs, &environment, workspace);

    let mut payload = Map::new();
    payload.insert(
        "version".to_owned(),
        version.map_or(Value::Null, Value::String),
    );
    payload.insert(
        "filters_outside_workspace".to_owned(),
        Value::Bool(filters_outside),
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

#[cfg(test)]
#[path = "verified_npm_op_tests.rs"]
mod tests;
