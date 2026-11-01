use serde_json::{json, Value};
use tempfile::TempDir;

use super::{evaluate_contained_node_execute, evaluate_contained_typescript_execute};
use guard_contracts::{
    ContainedNodeExecuteRequestV2, ContainedTypescriptExecuteRequestV2,
    CONTAINED_NODE_EXECUTE_REQUEST_SCHEMA, CONTAINED_NODE_EXECUTE_RESULT_SCHEMA,
    CONTAINED_TYPESCRIPT_EXECUTE_REQUEST_SCHEMA, CONTAINED_TYPESCRIPT_EXECUTE_RESULT_SCHEMA,
};

/// A request body as the package shim sends it: the manager and argv it
/// received, with no parsed intent or execution evidence of its own.
fn request(schema: &str, workspace: &str, manager: &str, shim_directory: &TempDir) -> Value {
    json!({
        "schema": schema,
        "workspace": workspace,
        "manager": manager,
        "argv": ["--no-install", "vitest", "run"],
        "shim_directory": shim_directory.path().to_str().unwrap(),
        "environment": {"PATH": "/usr/bin"},
        "guard_home": shim_directory.path().to_str().unwrap(),
    })
}

fn node(body: Value) -> Result<Value, String> {
    let request: ContainedNodeExecuteRequestV2 = serde_json::from_value(body).unwrap();
    evaluate_contained_node_execute(&request).map(|bytes| serde_json::from_slice(&bytes).unwrap())
}

fn typescript(body: Value) -> Result<Value, String> {
    let request: ContainedTypescriptExecuteRequestV2 = serde_json::from_value(body).unwrap();
    evaluate_contained_typescript_execute(&request)
        .map(|bytes| serde_json::from_slice(&bytes).unwrap())
}

#[test]
fn contained_runner_ops_refuse_an_older_request_schema() {
    let shims = TempDir::new().unwrap();
    let workspace = shims.path().to_str().unwrap();
    let node_v1 = request(
        "guard-contained-node-execute-request.v1",
        workspace,
        "npx",
        &shims,
    );
    assert_eq!(
        node(node_v1),
        Err("schema_mismatch:guard-contained-node-execute-request.v1".to_owned())
    );
    let typescript_v1 = request(
        "guard-contained-typescript-execute-request.v1",
        workspace,
        "npx",
        &shims,
    );
    assert_eq!(
        typescript(typescript_v1),
        Err("schema_mismatch:guard-contained-typescript-execute-request.v1".to_owned())
    );
}

#[test]
fn an_unsupported_manager_returns_to_review_without_a_refusal() {
    let shims = TempDir::new().unwrap();
    let workspace = shims.path().to_str().unwrap();
    let body = request(
        CONTAINED_NODE_EXECUTE_REQUEST_SCHEMA,
        workspace,
        "pnpm",
        &shims,
    );
    assert_eq!(
        node(body),
        Ok(json!({
            "schema": CONTAINED_NODE_EXECUTE_RESULT_SCHEMA,
            "result": null,
            "refusal": null,
        }))
    );
    let body = request(
        CONTAINED_TYPESCRIPT_EXECUTE_REQUEST_SCHEMA,
        workspace,
        "bunx",
        &shims,
    );
    assert_eq!(
        typescript(body),
        Ok(json!({"schema": CONTAINED_TYPESCRIPT_EXECUTE_RESULT_SCHEMA, "result": null}))
    );
}

#[test]
fn a_system_root_workspace_or_missing_shim_directory_returns_to_review() {
    let shims = TempDir::new().unwrap();
    let body = request(CONTAINED_NODE_EXECUTE_REQUEST_SCHEMA, "/usr", "npx", &shims);
    assert_eq!(
        node(body),
        Ok(json!({
            "schema": CONTAINED_NODE_EXECUTE_RESULT_SCHEMA,
            "result": null,
            "refusal": null,
        }))
    );
    let body = request(
        CONTAINED_TYPESCRIPT_EXECUTE_REQUEST_SCHEMA,
        "/usr",
        "npx",
        &shims,
    );
    assert_eq!(
        typescript(body),
        Ok(json!({"schema": CONTAINED_TYPESCRIPT_EXECUTE_RESULT_SCHEMA, "result": null}))
    );
    let mut body = request(
        CONTAINED_NODE_EXECUTE_REQUEST_SCHEMA,
        shims.path().to_str().unwrap(),
        "npx",
        &shims,
    );
    body.as_object_mut().unwrap().remove("shim_directory");
    assert_eq!(
        node(body),
        Ok(json!({
            "schema": CONTAINED_NODE_EXECUTE_RESULT_SCHEMA,
            "result": null,
            "refusal": null,
        }))
    );
}
