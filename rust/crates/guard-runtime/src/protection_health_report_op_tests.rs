use super::*;

use serde_json::Value;

fn signal(status: &str, reason_code: &str) -> ProtectionSignalV1 {
    ProtectionSignalV1 {
        status: status.to_owned(),
        reason_code: reason_code.to_owned(),
    }
}

/// Every check proven, so the report has nothing left to doubt.
fn proven() -> BTreeMap<String, ProtectionSignalV1> {
    [
        "harness_hooks",
        "daemon",
        "policy_engine",
        "rule_packs",
        "decision_plane_compatibility",
        "containment_compatibility",
        "sandbox",
        "decision_stream",
        "tamper_checks",
    ]
    .into_iter()
    .map(|check_id| (check_id.to_owned(), signal("pass", "proof_current")))
    .collect()
}

fn request(
    signals: BTreeMap<String, ProtectionSignalV1>,
    harness_signals: BTreeMap<String, ProtectionSignalV1>,
) -> ProtectionHealthReportRequestV1 {
    ProtectionHealthReportRequestV1 {
        schema: PROTECTION_HEALTH_REPORT_REQUEST_SCHEMA.to_owned(),
        request_id: "req-1".to_owned(),
        signals,
        harness_signals,
    }
}

fn decode(request: &ProtectionHealthReportRequestV1) -> ProtectionHealthReportResultV1 {
    serde_json::from_slice(&evaluate_protection_health_report(request).unwrap()).unwrap()
}

fn payload(request: &ProtectionHealthReportRequestV1) -> Value {
    decode(request).payload.expect("payload")
}

#[test]
fn every_check_proven_reports_protected() {
    let report = payload(&request(proven(), BTreeMap::new()));
    assert_eq!(report["state"], "protected");
    assert_eq!(report["label"], "Protected");
    assert_eq!(report["evidence_gap"], false);
    assert_eq!(report["schema_version"], "guard.protection-health.v1");
    assert_eq!(report["checks"].as_array().expect("checks").len(), 9);
    assert_eq!(report["apps"].as_array().expect("apps").len(), 0);
}

#[test]
fn a_check_the_caller_left_out_is_unproven_not_passing() {
    let mut signals = proven();
    signals.remove("daemon");
    let report = payload(&request(signals, BTreeMap::new()));
    assert_eq!(report["state"], "degraded");
    assert_eq!(report["evidence_gap"], true);
    assert_eq!(report["checks"][1]["check_id"], "daemon");
    assert_eq!(report["checks"][1]["status"], "unknown");
    assert_eq!(report["checks"][1]["reason_code"], "proof_unavailable");
}

#[test]
fn a_harness_carries_its_own_hook_signal_over_the_shared_checks() {
    let harness_signals = BTreeMap::from([
        ("claude".to_owned(), signal("pass", "hooks_installed")),
        ("codex".to_owned(), signal("fail", "hooks_missing")),
    ]);
    let report = payload(&request(proven(), harness_signals));
    let apps = report["apps"].as_array().expect("apps");
    assert_eq!(apps.len(), 2);
    assert_eq!(apps[0]["harness"], "claude");
    assert_eq!(apps[0]["state"], "protected");
    assert_eq!(apps[1]["harness"], "codex");
    assert_eq!(apps[1]["state"], "degraded");
    // The machine-wide answer is unchanged by one harness's own gap.
    assert_eq!(report["state"], "protected");
}

#[test]
fn a_platform_without_a_check_does_not_degrade_the_report() {
    let mut signals = proven();
    signals.insert("sandbox".to_owned(), signal("fail", "unsupported_platform"));
    assert_eq!(
        payload(&request(signals, BTreeMap::new()))["state"],
        "protected"
    );
}

#[test]
fn only_the_four_optional_checks_may_fail_for_a_missing_platform() {
    let mut signals = proven();
    signals.insert("daemon".to_owned(), signal("fail", "unsupported_platform"));
    assert_eq!(
        payload(&request(signals, BTreeMap::new()))["state"],
        "degraded"
    );
}

#[test]
fn an_unproven_evidence_stream_is_partial_not_protected() {
    let mut signals = proven();
    signals.insert(
        "decision_stream".to_owned(),
        signal("unknown", "proof_unavailable"),
    );
    let report = payload(&request(signals, BTreeMap::new()));
    assert_eq!(report["state"], "partial");
    assert_eq!(report["label"], "Partially protected");
}

#[test]
fn an_unknown_check_id_refuses_the_whole_request() {
    let mut signals = proven();
    signals.insert("quantum_shield".to_owned(), signal("pass", "invented"));
    assert_eq!(
        evaluate_protection_health_report(&request(signals, BTreeMap::new())),
        Err("native_protection_health_report_invalid".to_owned())
    );
}

#[test]
fn a_free_form_reason_refuses_the_whole_request() {
    let mut signals = proven();
    signals.insert("daemon".to_owned(), signal("pass", "Daemon is fine!"));
    assert_eq!(
        evaluate_protection_health_report(&request(signals, BTreeMap::new())),
        Err("native_protection_health_report_invalid".to_owned())
    );
}

#[test]
fn a_status_outside_the_three_refuses_the_whole_request() {
    let mut signals = proven();
    signals.insert("daemon".to_owned(), signal("maybe", "proof_current"));
    assert_eq!(
        evaluate_protection_health_report(&request(signals, BTreeMap::new())),
        Err("native_protection_health_report_invalid".to_owned())
    );
}

#[test]
fn a_harness_identity_the_grammar_refuses_refuses_the_request() {
    let harness_signals =
        BTreeMap::from([("Claude Code".to_owned(), signal("pass", "hooks_installed"))]);
    assert_eq!(
        evaluate_protection_health_report(&request(proven(), harness_signals)),
        Err("native_protection_health_report_invalid".to_owned())
    );
}

#[test]
fn another_schema_is_refused_before_the_report_is_built() {
    let mut wire = request(proven(), BTreeMap::new());
    wire.schema = "guard-protection-health-report-request.v2".to_owned();
    assert_eq!(
        evaluate_protection_health_report(&wire),
        Err("native_protection_health_report_schema_mismatch".to_owned())
    );
}

#[test]
fn a_request_without_an_identifier_is_refused() {
    let mut wire = request(proven(), BTreeMap::new());
    wire.request_id = String::new();
    assert_eq!(
        evaluate_protection_health_report(&wire),
        Err("native_protection_health_report_invalid".to_owned())
    );
}

#[test]
fn the_reply_binds_to_the_request_that_asked_for_it() {
    let wire = request(proven(), BTreeMap::new());
    let result = decode(&wire);
    assert_eq!(result.schema, PROTECTION_HEALTH_REPORT_RESULT_SCHEMA);
    assert_eq!(result.request_id, "req-1");
    assert_eq!(result.status, "ok");
    assert_eq!(result.code, "ok");
    assert_eq!(
        result.request_sha256,
        request_digest_with_limit(&wire, PROTECTION_HEALTH_REPORT_MAX_REQUEST_BYTES).unwrap()
    );
}

#[test]
fn a_bad_row_past_the_reported_hundred_still_refuses_the_request() {
    // The report names at most a hundred harnesses, but validity is not
    // decided by where that cut falls: a row's own neighbours would otherwise
    // make the same malformed status acceptable. A caller that sent a status
    // the grammar has no word for built a malformed request wherever it sits.
    let mut harness_signals: BTreeMap<String, ProtectionSignalV1> = (0..100)
        .map(|index| {
            (
                format!("harness-{index:03}"),
                signal("pass", "hooks_installed"),
            )
        })
        .collect();
    harness_signals.insert("harness-900".to_owned(), signal("maybe", "hooks_installed"));
    assert_eq!(
        evaluate_protection_health_report(&request(proven(), harness_signals)),
        Err("native_protection_health_report_invalid".to_owned())
    );
}
