//! Vectors captured from the Python `build_runtime_action_record` /
//! `extract_mcp_command_text` implementations these ops replaced.

use super::*;
use guard_contracts::McpRuntimeEnvelopeV1;

fn request(subop: &str) -> McpRuntimeEvidenceRequestV1 {
    McpRuntimeEvidenceRequestV1 {
        schema: MCP_RUNTIME_EVIDENCE_REQUEST_SCHEMA.to_owned(),
        request_id: "t-1".to_owned(),
        subop: subop.to_owned(),
        guard_home: "/tmp/guard-home".to_owned(),
        artifact_name: "srv:tool".to_owned(),
        tool_description: None,
        arguments: None,
        risk_categories: Vec::new(),
        envelope: None,
    }
}

fn run(request: &McpRuntimeEvidenceRequestV1) -> McpRuntimeEvidenceResultV1 {
    serde_json::from_slice(&evaluate_mcp_runtime_evidence(request).unwrap()).unwrap()
}

fn entries(items: &[(&str, Option<&str>)]) -> Option<Vec<(String, Option<String>)>> {
    Some(
        items
            .iter()
            .map(|(key, value)| ((*key).to_owned(), value.map(str::to_owned)))
            .collect(),
    )
}

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

fn action(request: &McpRuntimeEvidenceRequestV1) -> Value {
    let result = run(request);
    assert_eq!((result.status.as_str(), result.code.as_str()), ("ok", "ok"));
    result.payload.unwrap()["runtime_action"].clone()
}

fn command_text(arguments: Option<Vec<(String, Option<String>)>>) -> Value {
    let mut request = request("command_text");
    request.arguments = arguments;
    run(&request).payload.unwrap()["command_text"].clone()
}

#[test]
fn empty_evidence_is_null() {
    assert_eq!(action(&request("runtime_action")), Value::Null);
}

#[test]
fn description_only_claims_capability() {
    let mut request = request("runtime_action");
    request.tool_description = Some("  reads files ".to_owned());
    assert_eq!(
        action(&request),
        json!({
            "claimedCapabilities": ["tool_description"], "domainsContacted": [],
            "filesTouched": [], "observedCapabilities": [], "packageManagersInvoked": [],
            "sensitiveDataClasses": [], "subprocessesSpawned": [],
        })
    );
    request.tool_description = Some("   ".to_owned());
    assert_eq!(action(&request), Value::Null);
}

#[test]
fn observed_preserves_order_and_duplicates_sensitive_dedupes() {
    let mut request = request("runtime_action");
    request.risk_categories = strings(&["network", "secret_access", "network"]);
    let record = action(&request);
    assert_eq!(
        record["observedCapabilities"],
        json!(["network", "secret_access", "network"])
    );
    assert_eq!(record["sensitiveDataClasses"], json!(["secret_access"]));
    request.risk_categories = strings(&[
        "secret_access",
        "api-key_leak",
        "outbound_network",
        "PaymentFlow",
    ]);
    assert_eq!(
        action(&request)["sensitiveDataClasses"],
        json!(["secret_access", "api-key_leak", "PaymentFlow"])
    );
}

#[test]
fn argument_paths_are_redacted_to_basename() {
    let mut request = request("runtime_action");
    request.arguments = entries(&[
        ("file_path", Some("/home/u/.ssh/id_rsa")),
        ("Target", Some("C:\\x\\y.txt")),
        ("other", Some("/z")),
        ("path", None),
        ("source", Some("///")),
    ]);
    assert_eq!(
        action(&request)["filesTouched"],
        json!(["[redacted]/id_rsa", "[redacted]/y.txt", "[redacted-path]"])
    );
}

#[test]
fn envelope_contributes_hosts_subprocess_and_package_manager() {
    let mut request = request("runtime_action");
    request.tool_description = Some("d".to_owned());
    request.arguments = entries(&[("path", Some("a/b/c/"))]);
    request.risk_categories = strings(&["command_execution"]);
    request.envelope = Some(McpRuntimeEnvelopeV1 {
        target_paths: strings(&["/a/b", ""]),
        network_hosts: strings(&["h.com", " h.com ", "", "x.org"]),
        package_manager: Some("npm".to_owned()),
        command: Some("NPM install left-pad".to_owned()),
    });
    assert_eq!(
        action(&request),
        json!({
            "claimedCapabilities": ["tool_description"],
            "domainsContacted": ["h.com", "x.org"],
            "filesTouched": ["[redacted]/c", "[redacted]/b", "[redacted-path]"],
            "observedCapabilities": ["command_execution"],
            "packageManagersInvoked": ["npm"],
            "sensitiveDataClasses": [],
            "subprocessesSpawned": ["NPM"],
        })
    );
}

#[test]
fn package_manager_detection_matches_word_boundaries() {
    let mut request = request("runtime_action");
    let envelope = |manager: Option<&str>, command: &str| {
        Some(McpRuntimeEnvelopeV1 {
            target_paths: Vec::new(),
            network_hosts: Vec::new(),
            package_manager: manager.map(str::to_owned),
            command: Some(command.to_owned()),
        })
    };
    request.envelope = envelope(Some("cargo"), "cargo build");
    assert_eq!(action(&request)["packageManagersInvoked"], json!(["cargo"]));
    request.envelope = envelope(None, "  /usr/bin/python3 -c x");
    let record = action(&request);
    assert_eq!(record["packageManagersInvoked"], json!([]));
    assert_eq!(record["subprocessesSpawned"], json!(["/usr/bin/python3"]));
    request.envelope = envelope(None, "brew-cask install");
    assert_eq!(action(&request)["packageManagersInvoked"], json!(["brew"]));
    request.envelope = envelope(None, "npmx run");
    assert_eq!(
        action(&request),
        json!({
            "claimedCapabilities": [], "domainsContacted": [], "filesTouched": [],
            "observedCapabilities": [], "packageManagersInvoked": [],
            "sensitiveDataClasses": [], "subprocessesSpawned": ["npmx"],
        })
    );
}

#[test]
fn empty_envelope_and_non_mapping_arguments_yield_null() {
    let mut request = request("runtime_action");
    request.envelope = Some(McpRuntimeEnvelopeV1 {
        target_paths: Vec::new(),
        network_hosts: Vec::new(),
        package_manager: None,
        command: None,
    });
    assert_eq!(action(&request), Value::Null);
    request.envelope = Some(McpRuntimeEnvelopeV1 {
        target_paths: Vec::new(),
        network_hosts: Vec::new(),
        package_manager: None,
        command: Some("   ".to_owned()),
    });
    assert_eq!(action(&request), Value::Null);
}

#[test]
fn command_text_prefers_command_keys_in_order() {
    assert_eq!(
        command_text(entries(&[("command", Some("  ls -la  "))])),
        json!("ls -la")
    );
    assert_eq!(
        command_text(entries(&[("query", Some("q")), ("cmd", Some("c"))])),
        json!("c")
    );
}

#[test]
fn command_text_falls_back_to_paths_then_none() {
    assert_eq!(
        command_text(entries(&[("command", Some("   ")), ("path", Some(" /x "))])),
        json!("srv:tool /x")
    );
    assert_eq!(
        command_text(entries(&[("url", Some("http://u")), ("path", Some("p"))])),
        json!("srv:tool p")
    );
    assert_eq!(
        command_text(entries(&[("command", None), ("cwd", Some("/w"))])),
        json!("srv:tool /w")
    );
    assert_eq!(command_text(entries(&[("other", None)])), Value::Null);
    assert_eq!(command_text(None), Value::Null);
}

#[test]
fn result_is_bound_to_request_digest() {
    let mut first = request("command_text");
    first.arguments = entries(&[("command", Some("a"))]);
    let mut second = first.clone();
    second.arguments = entries(&[("command", Some("b"))]);
    let (one, two) = (run(&first), run(&second));
    assert_eq!(one.request_id, "t-1");
    assert_eq!(one.request_sha256.len(), 64);
    assert_ne!(one.request_sha256, two.request_sha256);
    assert_eq!(one.request_sha256, run(&first).request_sha256);
}

#[test]
fn schema_subop_and_scope_failures_are_typed_errors() {
    let mut bad_schema = request("command_text");
    bad_schema.schema = "bogus".to_owned();
    let result = run(&bad_schema);
    assert_eq!(result.status, "error");
    assert_eq!(result.code, "native_mcp_runtime_evidence_schema_mismatch");
    assert!(result.payload.is_none());
    assert_eq!(
        run(&request("nope")).code,
        "native_mcp_runtime_evidence_unknown_subop"
    );
    let mut no_home = request("command_text");
    no_home.guard_home = String::new();
    assert_eq!(run(&no_home).code, "native_mcp_runtime_evidence_invalid");
}

#[test]
fn oversized_request_is_rejected_before_evaluation() {
    let mut large = request("runtime_action");
    large.tool_description = Some("x".repeat(MCP_RUNTIME_EVIDENCE_MAX_BYTES));
    let result = run(&large);
    assert_eq!(result.status, "error");
    assert_eq!(result.code, "native_mcp_runtime_evidence_request_too_large");
    assert_eq!(result.request_id, "t-1");
    assert!(result.payload.is_none());
}

#[test]
fn receipt_evidence_returns_both_values_in_one_reply() {
    let mut request = request("receipt_evidence");
    request.tool_description = Some("d".to_owned());
    request.arguments = entries(&[("command", Some("ls")), ("file_path", Some("/a/b.txt"))]);
    request.risk_categories = strings(&["credential"]);
    let payload = run(&request).payload.unwrap();
    assert_eq!(payload["command_text"], "ls");
    // Call arguments never feed the receipt runtimeAction record.
    assert_eq!(payload["runtime_action"]["filesTouched"], json!([]));
    assert_eq!(
        payload["runtime_action"]["claimedCapabilities"],
        json!(["tool_description"])
    );
}

#[test]
fn request_rejects_unknown_and_missing_fields() {
    let good = serde_json::to_value(request("command_text")).unwrap();
    assert!(serde_json::from_value::<McpRuntimeEvidenceRequestV1>(good.clone()).is_ok());
    let mut extra = good.clone();
    extra["extra"] = json!(1);
    assert!(serde_json::from_value::<McpRuntimeEvidenceRequestV1>(extra).is_err());
    let mut missing = good;
    missing.as_object_mut().unwrap().remove("envelope");
    assert!(serde_json::from_value::<McpRuntimeEvidenceRequestV1>(missing).is_err());
}
