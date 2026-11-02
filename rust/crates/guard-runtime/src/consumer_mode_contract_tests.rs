use serde_json::{json, Value};

use super::*;

const TARGET: &str = "/work/demo-plugin";

fn scan() -> Value {
    json!({
        "score": 92,
        "grade": "A",
        "timestamp": "2026-11-01T00:00:00Z",
        "plugin_dir": TARGET,
        "scope": "plugin",
        "ecosystems": ["codex"],
        "packages": [{
            "ecosystem": "npm",
            "package_kind": "node",
            "root_path": TARGET,
            "manifest_path": "/work/demo-plugin/package.json",
            "name": "démo",
            "version": null,
        }],
        "category_names": ["Manifest", "Security"],
        "findings": [],
        "severity_counts": {},
        "integrations": [],
        "trust_total": 87.5,
    })
}

fn contract_for(scan: Value) -> Value {
    let args = json!({
        "target": TARGET,
        "target_name": "demo-plugin",
        "intended_harness": "codex",
        "scan": scan,
    });
    dispatch(&args).unwrap()["contract"].clone()
}

fn with(mut scan: Value, key: &str, value: Value) -> Value {
    scan[key] = value;
    scan
}

fn cisco(status: &str, findings: i64, metadata: Value) -> Value {
    json!({
        "name": "cisco-mcp-scanner",
        "status": status,
        "message": "",
        "findings_count": findings,
        "metadata": metadata,
    })
}

#[test]
fn a_clean_scan_is_allowed_with_the_python_artifact_hash() {
    let contract = contract_for(scan());
    assert_eq!(contract["schema_version"], "guard-consumer.v2");
    assert_eq!(contract["generated_at"], "2026-11-01T00:00:00Z");
    assert_eq!(
        contract["install_target"],
        json!({"path": TARGET, "intended_harness": "codex"})
    );
    // `json.dumps(summary, sort_keys=True)` hashed by the Python builder.
    assert_eq!(
        contract["artifact_snapshot"],
        json!({
            "path": TARGET,
            "artifact_hash": "63530248fa63d878fb949b65a48c6854b047e8c792ab99f83aed717321ee6486",
            "score": 92,
            "grade": "A",
        })
    );
    assert_eq!(
        contract["capability_manifest"]["category_names"],
        json!(["Manifest", "Security"])
    );
    assert_eq!(
        contract["artifact_diff"],
        json!({"changed": false, "changed_fields": []})
    );
    assert_eq!(
        contract["provenance_record"],
        json!({"scope": "plugin", "plugin_dir": TARGET, "trust_score": 87.5})
    );
    assert_eq!(
        contract["install_verdict"],
        json!({
            "action": "allow",
            "reason": "Install-time scan found no blocking issues in the local artifact.",
            "can_install": true,
        })
    );
    assert_eq!(
        contract["policy_recommendation"]["action"],
        contract["install_verdict"]["action"]
    );
    assert_eq!(
        contract["abom_entry"]["artifact_id"],
        "preflight:demo-plugin"
    );
    assert_eq!(contract["abom_entry"]["artifact_name"], "demo-plugin");
    assert_eq!(contract["abom_entry"]["artifact_type"], "plugin");
    assert_eq!(
        contract["threat_intelligence"],
        json!({"verdict_source": "local-scan", "highest_severity": "info", "finding_count": 0})
    );
    assert!(contract.get("cisco_evidence").is_none());
}

#[test]
fn findings_decide_review_or_block() {
    let low = with(
        scan(),
        "findings",
        json!([{"title": "loose", "severity": "medium"}, {"title": "note", "severity": "low"}]),
    );
    let reviewed = contract_for(low);
    assert_eq!(reviewed["install_verdict"]["action"], "review");
    assert_eq!(reviewed["install_verdict"]["can_install"], false);
    assert_eq!(
        reviewed["threat_intelligence"]["highest_severity"],
        "medium"
    );

    let high = with(
        scan(),
        "findings",
        json!([{"title": "a", "severity": "low"}, {"title": "b", "severity": "high"}]),
    );
    let blocked = contract_for(high);
    assert_eq!(blocked["install_verdict"]["action"], "block");
    assert_eq!(blocked["threat_intelligence"]["highest_severity"], "high");

    let low_score = contract_for(with(scan(), "score", json!(59)));
    assert_eq!(low_score["install_verdict"]["action"], "block");
    assert_eq!(
        low_score["policy_recommendation"]["reason"],
        "Install-time scan found severe findings that need review before you trust this artifact."
    );
}

#[test]
fn only_the_first_ten_titles_are_listed() {
    let findings: Vec<Value> = (0..12)
        .map(|index| json!({"title": format!("t{index}"), "severity": "info"}))
        .collect();
    let contract = contract_for(with(scan(), "findings", Value::Array(findings)));
    assert_eq!(
        contract["trust_evidence_bundle"]["findings"]
            .as_array()
            .unwrap()
            .len(),
        10
    );
    assert_eq!(contract["threat_intelligence"]["finding_count"], 12);
}

#[test]
fn cisco_evidence_counts_applicable_integrations() {
    let integrations = json!([
        cisco("enabled", 1, json!({"targets_scanned": 2})),
        cisco("skipped", 0, json!({"scan_mode": "offline"})),
        {"name": "cisco-mcp-scanner", "status": "failed", "message": "", "findings_count": 9, "metadata": {}},
        {"name": "other", "status": "failed", "message": "", "findings_count": 4, "metadata": {"targets_scanned": 3}},
    ]);
    let contract = contract_for(with(scan(), "integrations", integrations));
    let evidence = &contract["cisco_evidence"];
    assert_eq!(evidence["mode"], "offline-only");
    assert_eq!(evidence["status"], "enabled");
    assert_eq!(evidence["finding_count"], 1);
    assert_eq!(evidence["target_count"], 2);
    assert_eq!(
        evidence["summary"],
        "1 finding across 2 local MCP target(s)"
    );
    assert_eq!(evidence["integrations"].as_array().unwrap().len(), 2);
    assert_eq!(
        contract["trust_evidence_bundle"]["integrations"]
            .as_array()
            .unwrap()
            .len(),
        4
    );
}

#[test]
fn cisco_status_prefers_the_most_severe_report() {
    for (statuses, expected, summary) in [
        (
            vec!["enabled", "failed"],
            "failed",
            "Cisco MCP scan failed for 2 local MCP target(s)",
        ),
        (
            vec!["unavailable", "enabled"],
            "unavailable",
            "Cisco MCP scanner unavailable for 2 local MCP target(s)",
        ),
        (
            vec!["skipped", "skipped"],
            "skipped",
            "Cisco MCP scanning disabled for 2 local MCP target(s)",
        ),
        (
            vec!["odd", "odd"],
            "skipped",
            "Cisco MCP scanning disabled for 2 local MCP target(s)",
        ),
        (
            vec!["enabled", "enabled"],
            "enabled",
            "0 findings across 2 local MCP target(s)",
        ),
    ] {
        let integrations: Vec<Value> = statuses
            .iter()
            .map(|status| cisco(status, 0, json!({"targets_scanned": 1})))
            .collect();
        let contract = contract_for(with(scan(), "integrations", Value::Array(integrations)));
        assert_eq!(contract["cisco_evidence"]["status"], expected);
        assert_eq!(contract["cisco_evidence"]["summary"], summary);
    }
}

#[test]
fn target_counts_coerce_like_int() {
    for (raw, expected) in [
        (json!("2"), Some(2)),
        (json!(" 1_0 "), Some(10)),
        (json!("two"), None),
        (json!(true), Some(1)),
        (json!(3.9), Some(3)),
        (json!(null), None),
    ] {
        let integration = cisco("enabled", 0, json!({"targets_scanned": raw}));
        assert_eq!(
            target_count_of(integration.as_object().unwrap()),
            Ok(expected),
            "{raw}"
        );
    }
    for raw in [json!([1]), json!({"n": 1})] {
        let integration = cisco("enabled", 0, json!({"targets_scanned": raw}));
        assert_eq!(
            target_count_of(integration.as_object().unwrap()),
            Err(ERR_INVALID)
        );
    }
}

#[test]
fn a_missing_trust_report_and_harness_stay_null() {
    let args = json!({
        "target": TARGET,
        "target_name": "demo-plugin",
        "intended_harness": null,
        "scan": with(scan(), "trust_total", Value::Null),
    });
    let contract = dispatch(&args).unwrap()["contract"].clone();
    assert_eq!(contract["install_target"]["intended_harness"], Value::Null);
    assert_eq!(contract["provenance_record"]["trust_score"], Value::Null);
}

#[test]
fn malformed_arguments_are_refused() {
    let base = json!({
        "target": TARGET,
        "target_name": "demo-plugin",
        "intended_harness": null,
        "scan": scan(),
    });
    let mut cases = vec![json!([]), json!({})];
    for key in base.as_object().unwrap().keys() {
        let mut missing = base.clone();
        missing.as_object_mut().unwrap().remove(key);
        cases.push(missing);
    }
    for key in scan().as_object().unwrap().keys() {
        let mut missing = base.clone();
        missing["scan"].as_object_mut().unwrap().remove(key);
        cases.push(missing);
    }
    for (key, bad) in [
        ("score", json!("92")),
        ("ecosystems", json!([1])),
        ("findings", json!([{"title": "x", "severity": "severe"}])),
        ("findings", json!(["x"])),
        ("integrations", json!([1])),
        ("trust_total", json!("high")),
        ("severity_counts", json!([])),
    ] {
        let mut case = base.clone();
        case["scan"][key] = bad;
        cases.push(case);
    }
    let mut harness = base.clone();
    harness["intended_harness"] = json!(1);
    cases.push(harness);
    let mut no_count = base.clone();
    no_count["scan"]["integrations"] =
        json!([{"name": "cisco-mcp-scanner", "status": "enabled", "metadata": {"scan_mode": "x"}}]);
    cases.push(no_count);
    for case in cases {
        assert_eq!(dispatch(&case), Err(ERR_INVALID), "{case}");
    }
}
