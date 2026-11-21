use guard_contracts::{
    InventoryScanFindingsRequestV1, InventoryScanFindingsResultV1,
    INVENTORY_SCAN_FINDINGS_MAX_ITEMS, INVENTORY_SCAN_FINDINGS_MAX_RUNS,
    INVENTORY_SCAN_FINDINGS_REQUEST_SCHEMA, INVENTORY_SCAN_FINDINGS_RESULT_SCHEMA,
};
use serde_json::{json, Value};

use super::{evaluate_inventory_scan_findings_request, evaluate_request, refusal};

fn request(runs: Vec<Value>, items: Vec<Value>) -> Value {
    json!({
        "schema": INVENTORY_SCAN_FINDINGS_REQUEST_SCHEMA,
        "request_id": "inventory-scan-findings-test",
        "harness": "claude",
        "home_dir": "/home/operator",
        "workspace_dir": "/workspace",
        "cwd": "/workspace",
        "include_symlinks": true,
        "cisco_runs": runs,
        "items": items,
    })
}

fn parse(wire: &Value) -> InventoryScanFindingsRequestV1 {
    serde_json::from_value(wire.clone()).expect("request")
}

fn findings(wire: &Value) -> Vec<Value> {
    evaluate_request(&parse(wire))["findings"]
        .as_array()
        .expect("findings")
        .clone()
}

fn sources(wire: &Value) -> Vec<Value> {
    evaluate_request(&parse(wire))["sources"]
        .as_array()
        .expect("sources")
        .clone()
}

fn scanner_run(status: &str, raw_findings: Vec<Value>) -> Value {
    json!({
        "source": "cisco-mcp-scanner",
        "status": status,
        "message": "scan complete",
        "duration_ms": 1200,
        "metadata": {"totalFindings": raw_findings.len()},
        "findings": raw_findings,
    })
}

fn raw_finding(severity: &str) -> Value {
    json!({
        "rule_id": "MCP-001",
        "title": "Tool poisoning",
        "description": "A tool description rewrites the agent's instructions.",
        "file_path": "/home/operator/.claude/mcp.json",
        "line_number": 12,
        "severity": severity,
    })
}

#[test]
fn a_scanner_finding_keeps_its_severity_and_score_delta() {
    let wire = request(
        vec![scanner_run("enabled", vec![raw_finding("critical")])],
        vec![],
    );
    let answers = findings(&wire);
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0]["severity"], json!("critical"));
    assert_eq!(answers[0]["confidence"], json!("high"));
    assert_eq!(answers[0]["check_id"], json!("MCP-001"));
    assert_eq!(
        answers[0]["evidence"]["riskComponent"]["scoreDelta"],
        json!(-40)
    );
}

#[test]
fn an_unknown_severity_normalizes_down_rather_than_up() {
    let wire = request(
        vec![scanner_run("enabled", vec![raw_finding("catastrophic")])],
        vec![],
    );
    let answers = findings(&wire);
    assert_eq!(answers[0]["severity"], json!("info"));
    assert_eq!(
        answers[0]["evidence"]["riskComponent"]["scoreDelta"],
        json!(0)
    );
}

#[test]
fn a_scanner_that_was_not_enabled_reports_unknown_confidence() {
    let wire = request(
        vec![scanner_run("failed", vec![raw_finding("high")])],
        vec![],
    );
    let answers = findings(&wire);
    assert_eq!(answers[0]["confidence"], json!("unknown"));
    assert_eq!(
        answers[0]["evidence"]["riskComponent"]["confidence"],
        json!("unknown")
    );
}

#[test]
fn a_finding_path_is_redacted_before_it_leaves() {
    let wire = request(
        vec![scanner_run("enabled", vec![raw_finding("high")])],
        vec![],
    );
    let answers = findings(&wire);
    let path = answers[0]["evidence"]["filePath"]
        .as_str()
        .expect("filePath");
    assert!(path.starts_with("{home}/"), "{path}");
    assert!(!path.contains("/home/operator"), "{path}");
}

#[test]
fn a_finding_is_attributed_to_the_item_whose_config_path_it_names() {
    let wire = request(
        vec![scanner_run("enabled", vec![raw_finding("high")])],
        vec![json!({
            "item_id": "item-mcp",
            "metadata": {"configPath": "{home}/.claude/mcp.json"},
        })],
    );
    let answers = findings(&wire);
    assert_eq!(answers[0]["artifact_id"], json!("item-mcp"));
}

#[test]
fn a_finding_with_no_matching_item_is_attributed_to_unknown() {
    let wire = request(
        vec![scanner_run("enabled", vec![raw_finding("high")])],
        vec![json!({
            "item_id": "item-other",
            "metadata": {"configPath": "{home}/.codex/config.toml"},
        })],
    );
    let answers = findings(&wire);
    assert_eq!(answers[0]["artifact_id"], json!("unknown"));
}

#[test]
fn the_same_finding_twice_in_one_scan_is_reported_once() {
    let wire = request(
        vec![scanner_run(
            "enabled",
            vec![raw_finding("high"), raw_finding("high")],
        )],
        vec![],
    );
    assert_eq!(findings(&wire).len(), 1);
}

#[test]
fn a_scanner_guard_does_not_recognise_contributes_nothing() {
    let wire = request(
        vec![json!({
            "source": "some-other-scanner",
            "status": "enabled",
            "findings": [raw_finding("critical")],
        })],
        vec![],
    );
    assert!(findings(&wire).is_empty());
    assert!(sources(&wire).is_empty());
}

#[test]
fn a_failed_scanner_reports_as_failed_not_as_missing() {
    let wire = request(vec![scanner_run("failed", vec![])], vec![]);
    let answers = sources(&wire);
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0]["status"], json!("failed"));
    assert_eq!(answers[0]["source_type"], json!("scanner"));
}

#[test]
fn a_status_guard_cannot_read_reports_as_missing() {
    let wire = request(vec![scanner_run("partially-enabled", vec![])], vec![]);
    assert_eq!(sources(&wire)[0]["status"], json!("missing"));
}

#[test]
fn an_enabled_scanner_reports_as_available_with_its_finding_count() {
    let wire = request(
        vec![scanner_run("enabled", vec![raw_finding("low")])],
        vec![],
    );
    let answers = sources(&wire);
    assert_eq!(answers[0]["status"], json!("available"));
    assert_eq!(answers[0]["detail"], json!("status=enabled, findings=1"));
}

#[test]
fn an_escaped_symlink_source_reports_a_high_finding() {
    let wire = request(
        vec![],
        vec![json!({
            "item_id": "item-skill",
            "metadata": {
                "sourceOfTruth": {
                    "validationState": "escape_blocked",
                    "sourceFingerprint": "abc",
                    "pathClass": "outside_root",
                },
            },
        })],
    );
    let answers = findings(&wire);
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0]["severity"], json!("high"));
    assert_eq!(answers[0]["source"], json!("hol-detector"));
    assert_eq!(
        answers[0]["check_id"],
        json!("aibom.symlink.escape_blocked")
    );
    assert_eq!(
        answers[0]["finding_id"],
        json!("claude:symlink:item-skill:escape_blocked")
    );
}

#[test]
fn an_unrecognised_symlink_state_still_reports_a_finding() {
    let wire = request(
        vec![],
        vec![json!({
            "item_id": "item-skill",
            "metadata": {"sourceOfTruth": {"validationState": "dangling"}},
        })],
    );
    let answers = findings(&wire);
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0]["severity"], json!("medium"));
}

#[test]
fn a_valid_symlink_source_reports_nothing() {
    let wire = request(
        vec![],
        vec![json!({
            "item_id": "item-skill",
            "metadata": {"sourceOfTruth": {"validationState": "valid"}},
        })],
    );
    assert!(findings(&wire).is_empty());
}

#[test]
fn an_item_with_no_symlink_evidence_reports_nothing() {
    let wire = request(
        vec![],
        vec![
            json!({"item_id": "item-a", "metadata": {}}),
            json!({"item_id": "item-b", "metadata": {"sourceOfTruth": "not-a-mapping"}}),
            json!({"item_id": "item-c", "metadata": {"sourceOfTruth": {"validationState": 7}}}),
        ],
    );
    assert!(findings(&wire).is_empty());
}

#[test]
fn scanner_findings_come_before_symlink_findings() {
    let wire = request(
        vec![scanner_run("enabled", vec![raw_finding("high")])],
        vec![json!({
            "item_id": "item-skill",
            "metadata": {"sourceOfTruth": {"validationState": "loop"}},
        })],
    );
    let answers = findings(&wire);
    assert_eq!(answers.len(), 2);
    assert_eq!(answers[0]["source"], json!("cisco-mcp-scanner"));
    assert_eq!(answers[1]["source"], json!("hol-detector"));
}

#[test]
fn a_request_naming_another_contract_is_refused() {
    let mut wire = request(vec![], vec![]);
    wire["schema"] = json!("guard-inventory-snapshot-digest-request.v1");
    assert_eq!(
        refusal(&parse(&wire)),
        Some("native_inventory_scan_findings_schema_mismatch")
    );
}

#[test]
fn an_oversized_request_is_refused() {
    let runs = vec![scanner_run("enabled", vec![]); INVENTORY_SCAN_FINDINGS_MAX_RUNS + 1];
    assert_eq!(
        refusal(&parse(&request(runs, vec![]))),
        Some("native_inventory_scan_findings_too_many_runs")
    );
    let items =
        vec![json!({"item_id": "item", "metadata": {}}); INVENTORY_SCAN_FINDINGS_MAX_ITEMS + 1];
    assert_eq!(
        refusal(&parse(&request(vec![], items))),
        Some("native_inventory_scan_findings_too_many_items")
    );
}

/// A run carrying `count` distinct findings, each as wordy as the redactor
/// will let a finding be.
fn wordy_run(count: usize) -> Value {
    let filler = "sentence ".repeat(80);
    let raw: Vec<Value> = (0..count)
        .map(|index| {
            let title = format!("Tool poisoning {index} {filler}");
            let description = format!("A tool rewrites the agent's instructions. {filler}");
            json!({
                "rule_id": format!("MCP-{index:05}"),
                "title": title,
                "description": description,
                "file_path": "/home/operator/.claude/mcp.json",
                "line_number": index,
                "severity": "high",
            })
        })
        .collect();
    let mut run = scanner_run("enabled", raw);
    run["message"] = json!(format!("scan complete {filler}"));
    run
}

#[test]
fn a_scan_whose_answer_will_not_fit_is_refused_by_name() {
    // The run and item caps bound the request, not the answer: a run's message
    // rides in the evidence of every finding it produced, so a single run well
    // inside those caps can describe more bytes coming back than one reply
    // carries. The op says which scan was too large to answer rather than
    // leaving the frame boundary to report an undeliverable reply as a runtime
    // that stopped responding.
    let wire = request(vec![wordy_run(2048)], vec![]);
    let encoded =
        evaluate_inventory_scan_findings_request(&parse(&wire)).expect("encoded response");
    let result: InventoryScanFindingsResultV1 = serde_json::from_slice(&encoded).expect("result");
    assert_eq!(result.status, "error");
    assert_eq!(
        result.code,
        "native_inventory_scan_findings_reply_too_large"
    );
    assert!(result.payload.is_none());
    // The refusal itself has to reach the caller, so it is framed like any
    // other reply.
    assert!(encoded.len() <= guard_contracts::MAX_NATIVE_RESPONSE_BYTES);
}

#[test]
fn a_scan_the_transport_can_carry_is_still_answered() {
    let wire = request(vec![wordy_run(256)], vec![]);
    let encoded =
        evaluate_inventory_scan_findings_request(&parse(&wire)).expect("encoded response");
    let result: InventoryScanFindingsResultV1 = serde_json::from_slice(&encoded).expect("result");
    assert_eq!(result.status, "ok");
    assert_eq!(result.code, "ok");
    let payload = result.payload.expect("payload");
    assert_eq!(payload["findings"].as_array().expect("findings").len(), 256);
    assert!(encoded.len() <= guard_contracts::MAX_NATIVE_RESPONSE_BYTES);
}

#[test]
fn the_response_binds_itself_to_its_request() {
    let wire = request(
        vec![scanner_run("enabled", vec![raw_finding("low")])],
        vec![],
    );
    let encoded =
        evaluate_inventory_scan_findings_request(&parse(&wire)).expect("encoded response");
    let result: InventoryScanFindingsResultV1 = serde_json::from_slice(&encoded).expect("result");
    assert_eq!(result.schema, INVENTORY_SCAN_FINDINGS_RESULT_SCHEMA);
    assert_eq!(result.request_id, "inventory-scan-findings-test");
    assert_eq!(result.status, "ok");
    assert_eq!(result.code, "ok");
    // The caller binds the reply by comparing this against its own
    // "sha256:" + hex of the request it sent, so the prefix is part of the
    // contract, not decoration.
    assert!(result.request_sha256.starts_with("sha256:"));
    assert_eq!(result.request_sha256.len(), "sha256:".len() + 64);
    assert!(result.payload.is_some());
}

#[test]
fn a_refused_request_carries_no_payload() {
    let mut wire = request(vec![], vec![]);
    wire["schema"] = json!("guard-inventory-snapshot-digest-request.v1");
    let encoded =
        evaluate_inventory_scan_findings_request(&parse(&wire)).expect("encoded response");
    let result: InventoryScanFindingsResultV1 = serde_json::from_slice(&encoded).expect("result");
    assert_eq!(result.status, "error");
    assert_eq!(
        result.code,
        "native_inventory_scan_findings_schema_mismatch"
    );
    assert!(result.payload.is_none());
}

#[test]
fn a_detection_that_did_not_walk_symlinks_reports_no_symlink_findings() {
    let mut wire = request(
        vec![],
        vec![json!({
            "item_id": "item-skill",
            "metadata": {"sourceOfTruth": {"validationState": "loop"}},
        })],
    );
    wire["include_symlinks"] = json!(false);
    assert!(findings(&wire).is_empty());
}

#[test]
fn a_request_missing_a_scan_input_is_not_read_as_an_empty_scan() {
    // Every caller sends all three, so a request without one was built wrong
    // or lost something in transit. Defaulting them would answer such a
    // request `ok` with no symlink evidence and no scanner findings, which the
    // caller cannot tell apart from an inventory that is actually clean, so
    // the decode has to refuse it instead.
    for field in ["include_symlinks", "cisco_runs", "items"] {
        let mut wire = request(vec![], vec![]);
        wire.as_object_mut().expect("object").remove(field);
        let parsed = serde_json::from_value::<InventoryScanFindingsRequestV1>(wire);
        assert!(parsed.is_err(), "{field} was read as a default");
    }
}

#[test]
fn the_feature_is_advertised() {
    assert!(crate::resident_op_features::RESIDENT_OP_FEATURES
        .contains(&guard_contracts::INVENTORY_SCAN_FINDINGS_FEATURE));
}
