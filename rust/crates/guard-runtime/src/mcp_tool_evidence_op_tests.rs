//! Language-neutral vectors shared with the Python transport tests
//! (`tests/fixtures/mcp-tool-evidence/cases.v1.json`). Expected values were
//! captured from the Python implementations this op replaced.

use super::*;
use guard_command::mcp_tool_signals::evaluate_risk_evidence;
use guard_contracts::McpToolRiskInputV1;
use serde_json::json;

const CASES: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../tests/fixtures/mcp-tool-evidence/cases.v1.json"
));

fn cases() -> Value {
    serde_json::from_str(CASES).expect("fixture parses")
}

fn request_value(subop: &str, firewall: Value) -> Value {
    json!({
        "schema": MCP_TOOL_EVIDENCE_REQUEST_SCHEMA,
        "request_id": "t-1",
        "subop": subop,
        "guard_home": "/tmp/guard-home",
        "firewall": firewall,
    })
}

/// The risk evidence the MCP proxy's `call_projection` check renders.
fn risk(input: Value) -> Result<Value, &'static str> {
    let input: McpToolRiskInputV1 =
        serde_json::from_value(input).expect("risk input matches the wire contract");
    evaluate_risk_evidence(&input)
}

fn run_value(request: Value) -> McpToolEvidenceResultV1 {
    let request: McpToolEvidenceRequestV1 =
        serde_json::from_value(request).expect("request matches the wire contract");
    serde_json::from_slice(&evaluate_mcp_tool_evidence(&request).unwrap()).unwrap()
}

fn ok_payload(request: Value) -> Value {
    let result = run_value(request);
    assert_eq!(
        (result.status.as_str(), result.code.as_str()),
        ("ok", "ok"),
        "{result:?}"
    );
    assert_eq!(result.request_sha256.len(), 64);
    assert_eq!(result.request_id, "t-1");
    result.payload.expect("ok result carries a payload")
}

fn error_code(request: Value) -> String {
    let result = run_value(request);
    assert_eq!(result.status, "error");
    assert!(result.payload.is_none());
    result.code
}

fn risk_input(name: &str) -> Value {
    cases()["risk"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == name)
        .unwrap_or_else(|| panic!("missing risk case {name}"))["input"]
        .clone()
}

fn firewall_input(name: &str) -> Value {
    cases()["firewall"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == name)
        .unwrap_or_else(|| panic!("missing firewall case {name}"))["input"]
        .clone()
}

#[test]
fn risk_vectors_match_the_python_oracle() {
    let cases = cases();
    let vectors = cases["risk"].as_array().unwrap();
    assert!(vectors.len() >= 20);
    for case in vectors {
        let payload = risk(case["input"].clone()).unwrap();
        assert_eq!(payload, case["expected"], "risk case {}", case["name"]);
    }
}

#[test]
fn firewall_vectors_match_the_python_oracle() {
    let cases = cases();
    let firewall = cases["firewall"].as_array().unwrap();
    assert!(firewall.len() >= 15);
    for case in firewall {
        let payload = ok_payload(request_value("firewall", case["input"].clone()));
        let mut merged = case["metadata_before"].as_object().unwrap().clone();
        match &payload["metadata_patch"] {
            Value::Null => assert!(case["expected_patch_changed_keys"].is_null()),
            Value::Object(patch) => {
                for key in case["expected_patch_changed_keys"].as_array().unwrap() {
                    assert!(
                        patch.contains_key(key.as_str().unwrap()),
                        "{}",
                        case["name"]
                    );
                }
                merged.extend(patch.clone());
            }
            other => panic!("unexpected patch {other}"),
        }
        assert_eq!(
            Value::Object(merged),
            case["expected_metadata"],
            "firewall case {}",
            case["name"]
        );
    }
}

#[test]
fn result_is_bound_to_the_request_digest() {
    let first = run_value(request_value(
        "firewall",
        firewall_input("server_npx_tools"),
    ));
    let second = run_value(request_value(
        "firewall",
        firewall_input("server_npx_tools"),
    ));
    let mut changed = firewall_input("server_npx_tools");
    changed["name"] = json!("other-server");
    let other = run_value(request_value("firewall", changed));
    assert_eq!(first.request_sha256, second.request_sha256);
    assert_ne!(first.request_sha256, other.request_sha256);
}

#[test]
fn schema_mismatch_is_a_typed_error() {
    let mut request = request_value("firewall", firewall_input("server_npx_tools"));
    request["schema"] = json!("guard-mcp-tool-evidence-request.v0");
    assert_eq!(
        error_code(request),
        "native_mcp_tool_evidence_schema_mismatch"
    );
}

#[test]
fn unknown_subop_is_a_typed_error() {
    // `risk` moved to the MCP proxy's `call_projection` check.
    for subop in ["other", "risk"] {
        let request = request_value(subop, firewall_input("server_npx_tools"));
        assert_eq!(
            error_code(request),
            "native_mcp_tool_evidence_unknown_subop"
        );
    }
}

#[test]
fn subop_without_its_own_input_is_invalid() {
    let missing = request_value("firewall", Value::Null);
    assert_eq!(error_code(missing), "native_mcp_tool_evidence_invalid");
}

#[test]
fn empty_guard_home_is_invalid() {
    let mut request = request_value("firewall", firewall_input("server_npx_tools"));
    request["guard_home"] = json!("");
    assert_eq!(error_code(request), "native_mcp_tool_evidence_invalid");
}

#[test]
fn unknown_summary_code_fails_closed() {
    let mut input = risk_input("provided_no_risk");
    input["summary_code"] = json!("fine");
    assert_eq!(
        risk(input),
        Err("native_mcp_tool_evidence_unknown_summary_code")
    );
}

#[test]
fn unknown_category_fails_closed() {
    let mut input = risk_input("provided_no_risk");
    input["risk_categories"] = json!(["not_a_category"]);
    assert_eq!(
        risk(input),
        Err("native_mcp_tool_evidence_unknown_category")
    );
}

#[test]
fn browser_category_without_a_browser_intent_fails_closed() {
    let mut input = risk_input("provided_no_risk");
    input["risk_categories"] = json!(["browser_navigation"]);
    assert_eq!(
        risk(input),
        Err("native_mcp_tool_evidence_unknown_category")
    );
}

#[test]
fn unsupported_artifact_type_fails_closed() {
    let mut input = firewall_input("server_npx_tools");
    input["artifact_type"] = json!("prompt");
    let request = request_value("firewall", input);
    assert_eq!(
        error_code(request),
        "native_mcp_tool_evidence_unsupported_artifact_type"
    );
}

#[test]
fn oversized_request_is_a_typed_error() {
    let mut input = firewall_input("server_npx_tools");
    let padding = "x".repeat(MCP_TOOL_EVIDENCE_MAX_BYTES);
    input["tool_description"] = json!(padding);
    let request = request_value("firewall", input);
    assert_eq!(
        error_code(request),
        "native_mcp_tool_evidence_request_too_large"
    );
}

#[test]
fn unknown_wire_fields_are_rejected() {
    let mut request = request_value("firewall", firewall_input("server_npx_tools"));
    request["extra"] = json!(true);
    assert!(serde_json::from_value::<McpToolEvidenceRequestV1>(request).is_err());
    let mut stale = request_value("firewall", firewall_input("server_npx_tools"));
    stale["risk"] = Value::Null;
    assert!(serde_json::from_value::<McpToolEvidenceRequestV1>(stale).is_err());
    let mut missing = request_value("firewall", firewall_input("server_npx_tools"));
    missing.as_object_mut().unwrap().remove("firewall");
    assert!(serde_json::from_value::<McpToolEvidenceRequestV1>(missing).is_err());
}

#[test]
fn mapping_arguments_keep_insertion_order_for_browser_scope() {
    // Entries arrive ordered; the sorted JSON object Rust parses elsewhere
    // would lose this, which is why the wire carries entries.
    let mut input = risk_input("browser_nav_none");
    input["arguments"] = json!({
        "format": "mapping",
        "entries": [["url", "https://a.example/x"], ["type", "url"]],
    });
    input["risk_categories"] = Value::Null;
    let payload = risk(input).unwrap();
    assert_eq!(
        payload["signals"][0],
        json!("browser navigation to a.example")
    );
}
