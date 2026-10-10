//! The op loads the bundled catalog itself; requests carry only identity
//! fields, the tool name, and the verified extension-control layers.

use std::fs;
use std::path::{Path, PathBuf};

use guard_contracts::{
    ContributedMcpControlV1, ContributedMcpDecisionRequestV1, ContributedMcpLayerV1,
    CONTRIBUTED_MCP_DECISION_REQUEST_SCHEMA,
};
use serde_json::{json, Value};

use super::evaluate_contributed_mcp_decision_request;

const EXTENSION: &str = "command.mcp-filesystem";

fn home(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("contributed-mcp-op-{}-{name}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    fs::canonicalize(dir).unwrap()
}

fn layer(kind: &str, lockdown: bool, state: &str) -> ContributedMcpLayerV1 {
    ContributedMcpLayerV1 {
        kind: kind.to_owned(),
        global_lockdown: lockdown,
        controls: vec![ContributedMcpControlV1 {
            target_id: EXTENSION.to_owned(),
            state: state.to_owned(),
        }],
    }
}

fn request(home: &Path, tool: &str, action: &str) -> ContributedMcpDecisionRequestV1 {
    ContributedMcpDecisionRequestV1 {
        schema: CONTRIBUTED_MCP_DECISION_REQUEST_SCHEMA.to_owned(),
        request_id: "contributed-mcp-test".to_owned(),
        store_path: home.join("guard.db").to_string_lossy().into_owned(),
        guard_home: home.to_string_lossy().into_owned(),
        current_action: action.to_owned(),
        server_identity: json!({
            "package_name": "@modelcontextprotocol/server-filesystem", "command": "npx",
            "transport": "stdio", "package_source": "default", "package_version": null,
            "env_keys": []
        })
        .as_object()
        .cloned(),
        artifact_transport: None,
        server_name: None,
        tool_name: Some(json!(tool)),
        layers: vec![layer("local-admin", false, "enabled")],
    }
}

fn run(request: &ContributedMcpDecisionRequestV1) -> Value {
    let bytes = evaluate_contributed_mcp_decision_request(request).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[test]
fn blocked_tool_is_decided_from_the_bundled_catalog() {
    let home = home("blocked");
    let result = run(&request(&home, "write_file", "allow"));
    assert_eq!(result["status"], "ok");
    assert_eq!(result["payload"]["state"], "decided");
    assert_eq!(result["payload"]["action"], "block");
    assert_eq!(result["payload"]["source"], "catalog-mcp-extension");
    assert_eq!(result["request_id"], "contributed-mcp-test");
    assert!(result["request_sha256"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
}

#[test]
fn package_allow_binding_relaxes_a_reviewed_tool() {
    let home = home("allow");
    let enola = |lockdown: bool| {
        let mut request = request(&home, "query_facts", "review");
        request
            .server_identity
            .as_mut()
            .unwrap()
            .insert("command".to_owned(), json!("uvx"));
        request
            .server_identity
            .as_mut()
            .unwrap()
            .insert("package_name".to_owned(), json!("enola-cli"));
        request.layers = vec![ContributedMcpLayerV1 {
            kind: "local-admin".to_owned(),
            global_lockdown: lockdown,
            controls: vec![ContributedMcpControlV1 {
                target_id: "command.mcp-enola".to_owned(),
                state: "enabled".to_owned(),
            }],
        }];
        request
    };
    let result = run(&enola(false));
    assert_eq!(result["payload"]["action"], "allow");
    assert_eq!(run(&enola(true))["payload"]["state"], "none");
}

#[test]
fn inactive_external_extension_decides_nothing() {
    let home = home("inactive");
    let mut missing = request(&home, "write_file", "allow");
    missing.layers.clear();
    assert_eq!(run(&missing)["payload"]["state"], "none");
    let mut disabled = request(&home, "write_file", "allow");
    disabled
        .layers
        .push(layer("signed-cloud", false, "disabled"));
    assert_eq!(run(&disabled)["payload"]["state"], "none");
}

#[test]
fn digest_binds_the_request() {
    let home = home("digest");
    let first = run(&request(&home, "write_file", "allow"));
    let again = run(&request(&home, "write_file", "allow"));
    let other = run(&request(&home, "write_file", "warn"));
    assert_eq!(first["request_sha256"], again["request_sha256"]);
    assert_ne!(first["request_sha256"], other["request_sha256"]);
}

#[test]
fn rejects_schema_path_and_bounds() {
    let home = home("invalid");
    let mut wrong_schema = request(&home, "write_file", "allow");
    wrong_schema.schema = "other".to_owned();
    assert_eq!(
        evaluate_contributed_mcp_decision_request(&wrong_schema).unwrap_err(),
        "native_contributed_mcp_schema_mismatch"
    );
    let mut wrong_store = request(&home, "write_file", "allow");
    wrong_store.store_path = home.join("other.db").to_string_lossy().into_owned();
    assert_eq!(
        run(&wrong_store)["code"],
        "native_contributed_mcp_path_invalid"
    );
    let mut relative = request(&home, "write_file", "allow");
    relative.guard_home = "relative".to_owned();
    assert_eq!(
        run(&relative)["code"],
        "native_contributed_mcp_path_invalid"
    );
    let mut long_tool = request(&home, "write_file", "allow");
    long_tool.tool_name = Some(json!("x".repeat(5000)));
    assert_eq!(
        run(&long_tool)["code"],
        "native_contributed_mcp_request_invalid"
    );
    let mut extra_key = request(&home, "write_file", "allow");
    extra_key
        .server_identity
        .as_mut()
        .unwrap()
        .insert("extra".to_owned(), json!(1));
    assert_eq!(
        run(&extra_key)["code"],
        "native_contributed_mcp_request_invalid"
    );
    let mut many_layers = request(&home, "write_file", "allow");
    many_layers.layers = vec![layer("local-admin", false, "enabled"); 3];
    assert_eq!(
        run(&many_layers)["code"],
        "native_contributed_mcp_request_invalid"
    );
    let mut bad_kind = request(&home, "write_file", "allow");
    bad_kind.layers = vec![layer("bogus", false, "enabled")];
    assert_eq!(
        run(&bad_kind)["code"],
        "native_contributed_mcp_request_invalid"
    );
    let mut bad_state = request(&home, "write_file", "allow");
    bad_state.layers = vec![layer("local-admin", false, "maybe")];
    assert_eq!(
        run(&bad_state)["code"],
        "native_contributed_mcp_request_invalid"
    );
}
