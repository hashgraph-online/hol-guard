//! Contract tests for the `verified_npm` resident op.

use guard_contracts::{VerifiedNpmRequestV1, PACKAGE_AUTHORITY_REQUEST_SCHEMA};
use serde_json::{json, Value};

use super::evaluate_verified_npm;
use crate::package_authority_op::request_digest;

fn request(workspace: &str) -> VerifiedNpmRequestV1 {
    VerifiedNpmRequestV1 {
        schema: PACKAGE_AUTHORITY_REQUEST_SCHEMA.to_owned(),
        request_id: "verified-npm-1".to_owned(),
        guard_home: "/tmp/guard-home".to_owned(),
        workspace: workspace.to_owned(),
        environment: Some(json!({"environment_names": ["PATH"], "path": ""})),
        filter_programs: Vec::new(),
    }
}

fn payload(request: &VerifiedNpmRequestV1) -> Value {
    let bytes = evaluate_verified_npm(request).expect("request must encode a result");
    let decoded: Value = serde_json::from_slice(&bytes).expect("result must decode");
    decoded
        .get("payload")
        .cloned()
        .expect("result must carry a payload")
}

#[test]
fn an_unprovable_environment_answers_an_explicit_null_version() {
    let workspace = std::env::temp_dir();
    let answer = payload(&request(&workspace.to_string_lossy()));
    // Python reads `version` as "no proof"; the key must be present, because
    // a missing key and a null one would be indistinguishable to the caller.
    assert_eq!(answer.get("version"), Some(&Value::Null));
    assert_eq!(
        answer.get("filters_outside_workspace"),
        Some(&Value::Bool(true)),
        "no output filter needs no program"
    );
}

#[test]
fn an_output_filter_without_a_search_path_is_refused() {
    let workspace = std::env::temp_dir();
    let mut input = request(&workspace.to_string_lossy());
    input.filter_programs = vec!["tail".to_owned()];
    let answer = payload(&input);
    assert_eq!(
        answer.get("filters_outside_workspace"),
        Some(&Value::Bool(false))
    );
}

#[test]
fn a_relative_workspace_is_refused() {
    let mut input = request("relative/workspace");
    input.filter_programs = Vec::new();
    assert_eq!(
        evaluate_verified_npm(&input).unwrap_err(),
        "native_verified_npm_invalid"
    );
}

#[test]
fn a_foreign_schema_is_refused() {
    let workspace = std::env::temp_dir();
    let mut input = request(&workspace.to_string_lossy());
    input.schema = "guard-other-request.v1".to_owned();
    assert_eq!(
        evaluate_verified_npm(&input).unwrap_err(),
        "native_verified_npm_schema_mismatch"
    );
}

#[test]
fn an_unpiped_request_digest_matches_the_fields_the_caller_sent() {
    let workspace = std::env::temp_dir();
    // The bridge always sends both fields, even with no output filter and no
    // stamped environment, and hashes them as sent.
    let sent = json!({
        "schema": PACKAGE_AUTHORITY_REQUEST_SCHEMA,
        "request_id": "verified-npm-1",
        "guard_home": "/tmp/guard-home",
        "workspace": workspace.to_string_lossy(),
        "environment": null,
        "filter_programs": [],
    });
    let input: VerifiedNpmRequestV1 =
        serde_json::from_value(sent.clone()).expect("request must decode");
    let bytes = evaluate_verified_npm(&input).expect("request must encode a result");
    let decoded: Value = serde_json::from_slice(&bytes).expect("result must decode");
    assert_eq!(
        decoded.get("request_sha256").and_then(Value::as_str),
        Some(request_digest(&sent).expect("digest").as_str())
    );
}
