use super::*;

use super::super::policy_enforcement_facts::payload_facts;

/// The shape a delegated subtask returns when its parent asked for named
/// findings: every field is an answer about a credential, none is one.
fn report() -> Value {
    json!({"tool_name": "yield", "tool_input": {"data": {
        "firstSentence": "Settings example project.",
        "tokenMentions": "No, the README does not mention a token.",
        "apiKeyMentions": "No, the README does not mention an API key."
    }}})
}

fn facts(payload: &Value, harness: &str, reason_code: &str) -> bool {
    payload_facts(payload, harness, PreToolActionTypeV1::Harness, reason_code)
        .expect("yield payload")
        .sensitive_target
}

fn decision(payload: &Value) -> String {
    let mut installed = policy("allow");
    installed
        .risk_actions
        .insert("local_secret_read".into(), "block".into());
    let native = guard_command::pretool::evaluate_pre_tool_envelope("omp", "PreToolUse", payload);
    apply_pre_tool_policy(&snapshot(installed), payload, native)
        .expect("yield envelope")
        .decision
}

#[test]
fn a_verified_report_answers_in_its_parents_field_names() {
    assert!(!facts(&report(), "omp", "native_omp_yield_metadata"));
    assert_eq!(decision(&report()), "allow");
}

#[test]
fn a_nested_finding_carries_the_same_labels() {
    let payload = json!({"tool_name": "yield", "tool_input": {"data": {
        "summary": "No credentials are referenced.",
        "findings": [
            {"file": "README.md", "tokenMentions": "none", "secretsFound": false},
            {"file": "SETUP.md", "apiKeyMentions": "none"}
        ],
        "counts": {"passwordHits": 0}
    }}});
    assert!(!facts(&payload, "omp", "native_omp_yield_metadata"));
}

#[test]
fn a_path_selector_in_the_report_keeps_its_floor() {
    let payload = json!({"tool_name": "yield", "tool_input": {"data": {
        "tokenMentions": "No, the README does not mention a token.",
        "path": "~/.aws/credentials"
    }}});
    assert!(facts(&payload, "omp", "native_omp_yield_metadata"));
}

#[test]
fn a_native_sensitive_verdict_inside_the_report_still_counts() {
    let payload = json!({"tool_name": "yield", "tool_input": {"data": {
        "tokenMentions": "No, the README does not mention a token.",
        "sensitive_target": true
    }}});
    assert!(facts(&payload, "omp", "native_omp_yield_metadata"));
}

#[test]
fn only_a_verified_omp_yield_report_is_exempt() {
    for (harness, reason_code) in [
        ("omp", "native_omp_yield_report_review"),
        ("omp", "native_pre_tool_unknown"),
        ("claude-code", "native_omp_yield_metadata"),
        ("codex", "native_omp_yield_metadata"),
    ] {
        assert!(
            facts(&report(), harness, reason_code),
            "{harness} {reason_code}"
        );
    }
}

#[test]
fn the_exemption_is_only_for_the_report_body() {
    for payload in [
        // A credential-named argument beside the report, not inside it.
        json!({"tool_name": "yield", "tool_input": {
            "data": {"summary": "Done."}, "apiToken": "placeholder"}}),
        // Another tool reusing the report shape.
        json!({"tool_name": "eval", "tool_input": {"data": {
            "tokenMentions": "No, the README does not mention a token."}}}),
        // A report whose body is a string, which names nothing.
        json!({"tool_name": "yield", "tool_input": {
            "data": "{\"tokenMentions\":\"no\"}", "accessKey": "placeholder"}}),
    ] {
        assert!(
            facts(&payload, "omp", "native_omp_yield_metadata"),
            "{payload}"
        );
    }
}

/// The same report after the call, carrying the harness's acknowledgement.
fn post_report() -> Value {
    let mut payload = report();
    payload
        .as_object_mut()
        .expect("envelope")
        .insert("tool_response".into(), json!({"ok": true}));
    payload
}

#[test]
fn the_pre_tool_authority_names_a_verified_report() {
    let native = guard_command::pretool::evaluate_pre_tool_envelope("omp", "PreToolUse", &report());
    assert_eq!(native.decision, "allow");
    assert_eq!(native.reason_code, "native_omp_yield_metadata");
}

#[test]
fn the_report_is_still_labels_after_the_call() {
    for reason_code in [
        "output_scan_allow",
        "source_full_scan_allow",
        "output_empty_allow",
    ] {
        assert!(!facts(&post_report(), "omp", reason_code), "{reason_code}");
    }
}

#[test]
fn a_post_tool_exemption_needs_the_output_scan_to_have_allowed() {
    for reason_code in [
        "output_scan_review",
        "native_policy_reapproval_required",
        "output_secret_match",
    ] {
        assert!(facts(&post_report(), "omp", reason_code), "{reason_code}");
    }
}

#[test]
fn a_report_the_pre_tool_authority_would_not_verify_keeps_its_floor() {
    // A URL in the report is not plain task data, so the authority never
    // verified it and its field names are read as names again.
    let payload = json!({"tool_name": "yield", "tool_input": {"data": {
        "tokenMentions": "No, the README does not mention a token.",
        "url": "https://example.com/report"
    }}, "tool_response": {"ok": true}});
    assert!(facts(&payload, "omp", "output_scan_allow"));
}

#[test]
fn the_acknowledgement_of_a_verified_report_carries_its_labels() {
    let mut payload = report();
    payload.as_object_mut().expect("envelope").insert(
        "tool_response".into(),
        json!({"result": {"tokenMentions": "No", "apiKeyMentions": "No"}}),
    );
    assert!(!facts(&payload, "omp", "output_scan_allow"));
    // A path in the acknowledgement keeps its floor.
    payload["tool_response"]["path"] = json!("~/.aws/credentials");
    assert!(facts(&payload, "omp", "output_scan_allow"));
}
