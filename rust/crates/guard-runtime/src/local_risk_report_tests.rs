use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::{build_report, render_html, report_json, run_command};
use crate::guard_store_json::dumps_sorted;

fn status(value: Value) -> Map<String, Value> {
    value.as_object().cloned().unwrap_or_default()
}

fn active_status() -> Map<String, Value> {
    status(json!({
        "generated_at": "2026-05-15T12:00:00+00:00",
        "runtime_status": "active",
        "managed_harnesses": 2,
        "pending_approvals": 1,
        "receipt_count": 7,
        "sync_configured": true,
        "harnesses": [
            {"harness": "codex", "installed": true, "review_count": 0},
            {"harness": "claude-code", "installed": true, "review_count": 3},
            {"harness": "cursor", "installed": false, "review_count": 1},
        ],
    }))
}

fn digest_without_itself(report: &Map<String, Value>) -> String {
    let mut base = report.clone();
    base.remove("integrity_sha256");
    let canonical = dumps_sorted(&Value::Object(base)).unwrap_or_default();
    hex::encode(Sha256::digest(canonical.as_bytes()))
}

#[test]
fn report_is_coarse_and_carries_a_verifiable_digest() {
    let report = build_report(&active_status(), "2.0.0").unwrap_or_default();
    assert_eq!(report["schema_version"], "guard-local-risk-report/v1");
    assert_eq!(report["generated_at"], "2026-05-15T12:00:00+00:00");
    assert_eq!(report["risk_band"], "review");
    assert_eq!(
        report["installed_harnesses"],
        json!(["claude-code", "codex"])
    );
    assert_eq!(report["managed_harness_count"], 2);
    assert_eq!(report["review_item_count"], 4);
    assert_eq!(report["pending_approval_count"], 1);
    assert_eq!(report["receipt_count"], 7);
    assert_eq!(report["cloud_sync_configured"], true);
    assert_eq!(report["sensitive_content_included"], false);
    assert_eq!(report["certification"], false);
    assert_eq!(report["integrity_sha256"], digest_without_itself(&report));
    let checks: Vec<(&str, &str)> = report["checks"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|check| {
            (
                check["id"].as_str().unwrap_or_default(),
                check["status"].as_str().unwrap_or_default(),
            )
        })
        .collect();
    assert_eq!(
        checks,
        [
            ("runtime", "pass"),
            ("managed_harnesses", "pass"),
            ("configuration_review", "review"),
            ("pending_approvals", "review"),
        ]
    );
    assert_eq!(
        report["checks"][2]["summary"],
        "4 managed artifact change(s) need review."
    );
}

#[test]
fn report_excludes_sensitive_status_content() {
    let mut payload = active_status();
    payload.insert("prompt".to_owned(), json!("secret prompt text"));
    payload.insert("workspace".to_owned(), json!("/Users/alice/private-repo"));
    payload.insert("token".to_owned(), json!("ghp_exampletoken"));
    if let Some(Value::Array(harnesses)) = payload.get_mut("harnesses") {
        harnesses.push(json!({
            "harness": "codex",
            "installed": true,
            "config_path": "/Users/alice/.codex/config.toml",
            "command": "rm -rf /",
        }));
    }
    let report = build_report(&payload, "2.0.0").unwrap_or_default();
    let body = report_json(&report).unwrap_or_default();
    for leaked in [
        "secret prompt",
        "/Users/alice",
        "ghp_exampletoken",
        "rm -rf",
        "config.toml",
    ] {
        assert!(!body.contains(leaked), "{leaked} leaked into the report");
    }
}

#[test]
fn offline_runtime_is_high_risk_and_unmanaged_is_review() {
    let report = build_report(
        &status(json!({"runtime_status": "offline", "managed_harnesses": 0})),
        "2.0.0",
    )
    .unwrap_or_default();
    assert_eq!(report["risk_band"], "high");
    assert_eq!(report["checks"][0]["status"], "fail");
    assert_eq!(report["checks"][1]["status"], "review");
    assert_eq!(report["generated_at"], "");
    assert_eq!(report["installed_harnesses"], json!([]));
    assert_eq!(report["cloud_sync_configured"], false);
}

#[test]
fn healthy_runtime_with_nothing_waiting_is_low_risk() {
    let report = build_report(
        &status(json!({"runtime_status": "active", "managed_harnesses": 1})),
        "2.0.0",
    )
    .unwrap_or_default();
    assert_eq!(report["risk_band"], "low");
    assert_eq!(
        report["checks"][1]["summary"],
        "1 detected harness(es) are managed by Guard."
    );
}

#[test]
fn counters_follow_python_int_coercion() {
    let report = build_report(
        &status(json!({
            "runtime_status": "active",
            "managed_harnesses": true,
            "pending_approvals": -4,
            "receipt_count": 2.5,
            "harnesses": [{"review_count": "3"}, "codex", {"review_count": 2}],
        })),
        "2.0.0",
    )
    .unwrap_or_default();
    assert_eq!(report["managed_harness_count"], 1);
    assert_eq!(report["pending_approval_count"], 0);
    assert_eq!(report["receipt_count"], 0);
    assert_eq!(report["review_item_count"], 2);
}

#[test]
fn tampering_with_the_report_changes_its_digest() {
    let report = build_report(&active_status(), "2.0.0").unwrap_or_default();
    let mut tampered = report.clone();
    tampered.insert("risk_band".to_owned(), json!("low"));
    assert_ne!(digest_without_itself(&tampered), report["integrity_sha256"]);
}

#[test]
fn json_body_is_sorted_indented_and_ascii() {
    let report = build_report(&active_status(), "2.0.0-é").unwrap_or_default();
    let body = report_json(&report).unwrap_or_default();
    assert!(body.starts_with("{\n  \"certification\": false,\n  \"checks\": [\n    {\n"));
    assert!(body.ends_with("}\n"));
    assert!(body.contains("\"guard_version\": \"2.0.0-\\u00e9\""));
    assert!(body.is_ascii());
    let parsed: Value = serde_json::from_str(&body).unwrap_or_default();
    assert_eq!(parsed, Value::Object(report));
}

#[test]
fn html_is_noindex_and_escapes_values() {
    let report = build_report(&active_status(), "<b>&'\"").unwrap_or_default();
    let html = render_html(&report).unwrap_or_default();
    assert!(html.starts_with("<!doctype html><html lang=\"en\">"));
    assert!(html.contains("<meta name=\"robots\" content=\"noindex,nofollow\">"));
    assert!(html.contains("<p>Guard version: &lt;b&gt;&amp;&#x27;&quot;</p>"));
    assert!(html.contains("<p>Installed harnesses: claude-code, codex</p>"));
    assert!(html.contains(
        "<li><strong>runtime</strong>: pass \u{2014} Local Guard runtime is active.</li>"
    ));
    assert!(html.contains("<p>Sensitive local content included: no.</p>"));
    assert!(html.ends_with("</main></body></html>\n"));
    let empty = build_report(&Map::new(), "2.0.0").unwrap_or_default();
    assert!(render_html(&empty)
        .unwrap_or_default()
        .contains("<p>Installed harnesses: None detected</p>"));
}

#[test]
fn command_answers_the_requested_format() {
    let request = |format: &str| {
        json!({
            "schema": "local-risk-report.v1",
            "status": active_status(),
            "guard_version": "2.0.0",
            "format": format,
        })
        .to_string()
    };
    let answer = |format: &str| -> Value {
        let bytes = run_command(request(format).as_bytes()).unwrap_or_default();
        serde_json::from_slice(&bytes).unwrap_or_default()
    };
    assert!(answer("html")["body"]
        .as_str()
        .unwrap_or_default()
        .starts_with("<!doctype html>"));
    let body: Value = serde_json::from_str(answer("json")["body"].as_str().unwrap_or_default())
        .unwrap_or_default();
    assert_eq!(body["risk_band"], "review");
}

#[test]
fn command_refuses_malformed_requests() {
    for request in [
        "not json".to_owned(),
        json!({"schema": "other", "status": {}, "guard_version": "", "format": "json"}).to_string(),
        json!({"schema": "local-risk-report.v1", "status": [], "guard_version": "", "format": "json"})
            .to_string(),
        json!({"schema": "local-risk-report.v1", "status": {}, "guard_version": "", "format": "json", "extra": 1})
            .to_string(),
    ] {
        assert_eq!(
            run_command(request.as_bytes()),
            Err("local_risk_report_request_invalid".to_owned())
        );
    }
}
