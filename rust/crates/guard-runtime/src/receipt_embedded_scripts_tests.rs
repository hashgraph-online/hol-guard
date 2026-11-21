use serde_json::{json, Value};

use super::dispatch;
use crate::runner_authority_op::ERR_INVALID;

const AUDITABLE: &str = "python3 - <<'EOF'\nimport os\nprint('auditable')\nEOF";
const AUDITABLE_SHA: &str = "67c24926da79e1b494daac26952b0ce013620e0deac269ab2150ee38f6883ec0";

fn marker(sha: &str, bytes: i64, start: i64, end: i64) -> Value {
    json!({
        "source": "embedded_script",
        "kind": "heredoc",
        "index": 0,
        "delimiter": "EOF",
        "quoted": true,
        "executable": "python3",
        "executed": true,
        "execution_status": "executed",
        "sha256": sha,
        "bytes": bytes,
        "lines": 2,
        "span": {"start": start, "end": end},
    })
}

fn request(evidence: Value, raw: Value, envelope: Value) -> Value {
    json!({
        "scanner_evidence": evidence,
        "raw_command_text": raw,
        "envelope_command": envelope,
    })
}

fn scripts(args: &Value) -> Vec<Value> {
    let answer = dispatch(args).expect("scripts");
    answer["scripts"].as_array().cloned().expect("script list")
}

#[test]
fn body_is_recovered_and_verified() {
    let evidence = json!([marker(AUDITABLE_SHA, 29, 18, 47)]);
    let found = scripts(&request(evidence, json!(AUDITABLE), Value::Null));
    assert_eq!(found.len(), 1);
    assert_eq!(found[0]["body"], "import os\nprint('auditable')\n");
    assert_eq!(found[0]["sha256_verified"], true);
    assert_eq!(found[0]["executed"], true);
    assert_eq!(found[0]["span"], json!({"start": 18, "end": 47}));
    assert!(found[0].get("source").is_none());
}

#[test]
fn whitespace_shifted_envelope_command_still_verifies() {
    let evidence = json!([marker(AUDITABLE_SHA, 29, 18, 47)]);
    let shifted = format!(" {AUDITABLE}\n");
    let found = scripts(&request(evidence, json!(""), json!(shifted)));
    assert_eq!(found[0]["body"], "import os\nprint('auditable')\n");
    assert_eq!(found[0]["sha256_verified"], true);
}

#[test]
fn spans_count_code_points_and_bytes_count_utf8() {
    let command = "echo '日本語' && python3 - <<'EOF'\nprint('héllo')\nEOF";
    let sha = "aec43b85c11d38220dee4804d34ff306af62f3284dd4ac5351b813488c668908";
    let evidence = json!([marker(sha, 16, 32, 47)]);
    let found = scripts(&request(
        evidence,
        Value::Null,
        json!(format!(" {command}")),
    ));
    assert_eq!(found[0]["body"], "print('héllo')\n");
    assert_eq!(found[0]["sha256_verified"], true);
}

#[test]
fn tampered_body_falls_back_to_the_span_unverified() {
    let sha = "25718360e05d3c2d0963d1381e9dd4dae5fca789244ee4b9f861adcc0cc96218";
    let evidence = json!([marker(sha, 9, 18, 27)]);
    let tampered = "python3 - <<'EOF'\ntampered\nEOF";
    let found = scripts(&request(evidence, json!(tampered), Value::Null));
    assert_eq!(found[0]["body"], "tampered\n");
    assert_eq!(found[0]["sha256_verified"], false);
}

#[test]
fn missing_command_text_or_span_keeps_only_the_marker_facts() {
    let evidence = json!([marker(AUDITABLE_SHA, 29, 18, 47)]);
    let found = scripts(&request(evidence, json!(""), Value::Null));
    assert!(found[0].get("body").is_none());
    assert!(found[0].get("sha256_verified").is_none());
    let mut no_span = marker(AUDITABLE_SHA, 29, 18, 47);
    no_span["span"] = Value::Null;
    let found = scripts(&request(json!([no_span]), json!(AUDITABLE), Value::Null));
    assert!(found[0].get("body").is_none());
    assert_eq!(found[0]["span"], Value::Null);
}

#[test]
fn receipts_without_heredoc_markers_have_no_scripts() {
    for evidence in [
        Value::Null,
        json!({}),
        json!([]),
        json!([{"source": "policy_composition"}, "text"]),
        json!([{"source": "embedded_script", "kind": "summary"}]),
    ] {
        assert!(scripts(&request(evidence, json!(AUDITABLE), Value::Null)).is_empty());
    }
}

#[test]
fn malformed_requests_are_refused() {
    let mut extra = request(json!([]), Value::Null, Value::Null);
    extra["extra"] = json!(true);
    let mut missing = request(json!([]), Value::Null, Value::Null);
    if let Some(fields) = missing.as_object_mut() {
        fields.remove("envelope_command");
    }
    for args in [extra, missing, json!([])] {
        assert_eq!(dispatch(&args), Err(ERR_INVALID), "{args}");
    }
}
