//! What a trusted-local-tool grant may be, held to the shapes the approval
//! card and the policy store agree on.

use serde_json::json;

use super::*;

const IDENTITY: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
const CAPABILITY: &str = "read-only-inspect";
/// `sha256("read-only-inspect")`, the capability target's subject.
const CAPABILITY_DIGEST: &str = "ba31c0bc03d0b765cf7c135722e999bc8781e64809f537ed74d3dec0a1c6c631";
/// `sha256("*")`, the version target's capability-independent subject.
const ANY_DIGEST: &str = "684888c0ebb17f374298b65ee2807526c066094c701bcc7ebbe1c1095f494fc1";
const NOW: &str = "2029-01-01T00:00:00.500000+00:00";

/// One eligible trusted-local-tool evidence entry.
fn entry(trust_basis: &str, indefinite: Value) -> Value {
    json!({
        "source": "trusted_local_tool",
        "eligible": true,
        "tool_name": "tsc",
        "tool_identity_hash": IDENTITY,
        "capability": CAPABILITY,
        "read_only_reason": "type check only",
        "trust_basis": trust_basis,
        "indefinite_allowed": indefinite,
    })
}

fn evidence(trust_basis: &str, indefinite: Value) -> Value {
    json!([{"source": "scanner", "eligible": true}, entry(trust_basis, indefinite)])
}

fn pick(target: &str, duration: &str) -> LocalToolGrantSelectionRequestV1 {
    LocalToolGrantSelectionRequestV1 {
        harness: "claude".to_owned(),
        target: json!(target),
        duration: json!(duration),
        now: NOW.to_owned(),
        reason: Some("read-only".to_owned()),
    }
}

fn answer(scanner_evidence: Value, selection: Option<LocalToolGrantSelectionRequestV1>) -> Value {
    let request = LocalToolGrantRequestV1 {
        schema: LOCAL_TOOL_GRANT_REQUEST_SCHEMA.to_owned(),
        request_id: "local-tool-grant-1".to_owned(),
        scanner_evidence,
        selection,
    };
    serde_json::from_slice(&evaluate_local_tool_grant_request(&request).unwrap()).unwrap()
}

fn payload(scanner_evidence: Value, selection: Option<LocalToolGrantSelectionRequestV1>) -> Value {
    answer(scanner_evidence, selection)["payload"].clone()
}

#[test]
fn verified_files_evidence_offers_both_targets_and_the_version_duration() {
    let answer = payload(evidence("verified-files", json!(false)), None);
    assert_eq!(
        answer["approval"]["allowed_targets"],
        json!(["capability", "version"])
    );
    assert_eq!(
        answer["approval"]["allowed_durations"],
        json!(["once", "15m", "1h", "5h", "version"])
    );
    assert_eq!(answer["approval"]["tool_name"], json!("tsc"));
    assert_eq!(answer["approval"]["version"], json!(1));
    assert_eq!(
        answer["approval"]["hard_risk_exclusions"][0],
        json!("shell_chaining")
    );
    assert_eq!(answer["selection"], Value::Null);
    assert_eq!(answer["refusal"], Value::Null);
}

#[test]
fn a_package_profile_offers_the_capability_target_only() {
    let answer = payload(evidence("package-profile", json!(false)), None);
    assert_eq!(answer["approval"]["allowed_targets"], json!(["capability"]));
    assert_eq!(
        answer["approval"]["allowed_durations"],
        json!(["once", "15m", "1h", "5h"])
    );
}

#[test]
fn an_indefinite_package_profile_offers_always() {
    let answer = payload(evidence("package-profile", json!(true)), None);
    assert_eq!(
        answer["approval"]["allowed_durations"],
        json!(["once", "15m", "1h", "5h", "always"])
    );
    assert_eq!(answer["approval"]["indefinite_allowed"], json!(true));
}

#[test]
fn an_indefinite_verified_files_tool_is_still_not_offered_always() {
    let answer = payload(evidence("verified-files", json!(true)), None);
    assert_eq!(
        answer["approval"]["allowed_durations"],
        json!(["once", "15m", "1h", "5h", "version"])
    );
}

#[test]
fn a_missing_trust_basis_reads_as_verified_files() {
    let mut only = entry("verified-files", json!(false));
    only.as_object_mut().unwrap().remove("trust_basis");
    let answer = payload(json!([only]), None);
    assert_eq!(answer["approval"]["trust_basis"], json!("verified-files"));
}

#[test]
fn evidence_without_an_eligible_trusted_local_tool_entry_carries_no_grant() {
    let mut uppercase = entry("verified-files", json!(false));
    uppercase.as_object_mut().unwrap().insert(
        "tool_identity_hash".to_owned(),
        json!(IDENTITY.to_uppercase()),
    );
    let mut blank_name = entry("verified-files", json!(false));
    blank_name
        .as_object_mut()
        .unwrap()
        .insert("tool_name".to_owned(), json!("   "));
    let mut not_eligible = entry("verified-files", json!(false));
    not_eligible
        .as_object_mut()
        .unwrap()
        .insert("eligible".to_owned(), json!(false));
    for broken in [
        json!([]),
        json!("not a list"),
        json!([entry("guessed", json!(false))]),
        json!([uppercase]),
        json!([blank_name]),
        json!([not_eligible]),
    ] {
        let answer = payload(broken.clone(), Some(pick("capability", "1h")));
        assert_eq!(answer["approval"], Value::Null, "{broken}");
        assert_eq!(answer["selection"], Value::Null, "{broken}");
        assert_eq!(
            answer["refusal"],
            json!("local_tool_approval_ineligible"),
            "{broken}"
        );
    }
}

#[test]
fn an_incomplete_entry_of_the_same_source_does_not_end_the_search() {
    let answer = payload(
        json!([
            {"source": "trusted_local_tool", "eligible": true},
            entry("verified-files", json!(false)),
        ]),
        None,
    );
    assert_eq!(answer["approval"]["tool_name"], json!("tsc"));
}

#[test]
fn a_bounded_duration_expires_that_far_past_the_resolution() {
    let answer = payload(
        evidence("verified-files", json!(false)),
        Some(pick("capability", "1h")),
    );
    assert_eq!(answer["refusal"], Value::Null);
    assert_eq!(answer["selection"]["target"], json!("capability"));
    assert_eq!(answer["selection"]["duration"], json!("1h"));
    assert_eq!(
        answer["selection"]["expires_at"],
        json!("2029-01-01T01:00:00.500000+00:00")
    );
    assert_eq!(
        answer["selection"]["decision"],
        json!({
            "harness": "claude",
            "scope": "artifact",
            "action": "allow",
            "artifact_id": format!("local-tool-grant:v1:{IDENTITY}:capability:{CAPABILITY_DIGEST}"),
            "reason": "read-only",
            "source": "trusted-local-tool",
            "expires_at": "2029-01-01T01:00:00.500000+00:00",
        })
    );
}

#[test]
fn the_version_target_is_filed_under_the_capability_independent_digest() {
    let answer = payload(
        evidence("verified-files", json!(false)),
        Some(pick("version", "version")),
    );
    assert_eq!(answer["refusal"], Value::Null);
    assert_eq!(answer["selection"]["expires_at"], Value::Null);
    assert_eq!(
        answer["selection"]["decision"]["artifact_id"],
        json!(format!(
            "local-tool-grant:v1:{IDENTITY}:version:{ANY_DIGEST}"
        ))
    );
    assert_eq!(answer["selection"]["decision"]["expires_at"], Value::Null);
}

#[test]
fn a_pick_the_evidence_does_not_offer_is_refused_by_code() {
    let cases = [
        (
            "package-profile",
            "version",
            "version",
            "invalid_local_tool_grant_target",
        ),
        (
            "verified-files",
            "workspace",
            "1h",
            "invalid_local_tool_grant_target",
        ),
        (
            "verified-files",
            "capability",
            "always",
            "invalid_local_tool_grant_duration",
        ),
        (
            "package-profile",
            "capability",
            "version",
            "invalid_local_tool_grant_duration",
        ),
        (
            "verified-files",
            "capability",
            "once",
            "invalid_local_tool_grant_duration",
        ),
        (
            "verified-files",
            "capability",
            "7d",
            "invalid_local_tool_grant_duration",
        ),
    ];
    for (trust_basis, target, duration, code) in cases {
        let answer = payload(
            evidence(trust_basis, json!(false)),
            Some(pick(target, duration)),
        );
        assert_eq!(answer["selection"], Value::Null, "{target} {duration}");
        assert_eq!(answer["refusal"], json!(code), "{target} {duration}");
    }
}

#[test]
fn a_pick_that_is_not_a_string_is_refused_rather_than_coerced() {
    let mut selection = pick("capability", "1h");
    selection.target = json!({"target": "capability"});
    let answer = payload(evidence("verified-files", json!(false)), Some(selection));
    assert_eq!(answer["refusal"], json!("invalid_local_tool_grant_target"));
}

#[test]
fn a_resolution_timestamp_that_names_no_instant_refuses_the_grant() {
    let mut selection = pick("capability", "15m");
    selection.now = "whenever".to_owned();
    let answer = payload(evidence("verified-files", json!(false)), Some(selection));
    assert_eq!(answer["selection"], Value::Null);
    assert_eq!(
        answer["refusal"],
        json!("invalid_local_tool_grant_timestamp")
    );
}

#[test]
fn the_reply_binds_the_request_it_answers() {
    let answered = answer(evidence("verified-files", json!(false)), None);
    assert_eq!(answered["request_id"], json!("local-tool-grant-1"));
    assert_eq!(answered["status"], json!("ok"));
    assert_eq!(answered["code"], json!("ok"));
    assert!(answered["request_sha256"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
}

#[test]
fn another_schema_is_refused_before_anything_is_derived() {
    let wrong = LocalToolGrantRequestV1 {
        schema: "guard-local-tool-grant-request.v2".to_owned(),
        request_id: "local-tool-grant-1".to_owned(),
        scanner_evidence: evidence("verified-files", json!(false)),
        selection: None,
    };
    assert_eq!(
        evaluate_local_tool_grant_request(&wrong).unwrap_err(),
        "native_local_tool_grant_schema_mismatch"
    );
}
