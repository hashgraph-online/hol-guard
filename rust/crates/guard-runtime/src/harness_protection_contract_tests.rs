use serde_json::{json, Value};

use super::{
    check_document, check_payload, CLAIM_STATES, CONTRACT, EVIDENCE_STATES, FAILURE_BEHAVIORS,
    SURFACES,
};

fn document(row: Value) -> String {
    json!({
        "schema": "hol-guard.harness-protection-contracts.v1",
        "contracts": [{"harness": "codex", "capability_events": [row]}],
    })
    .to_string()
}

fn blocking(claim: Value) -> Value {
    json!({
        "event": "PreToolUse",
        "transport": "native_hook",
        "mode": "blocking",
        "surface": "foreground",
        "failure_behavior": "fail_closed",
        "claim": claim,
    })
}

fn proven() -> Value {
    json!({
        "state": "live_block_proven",
        "guard_version": "3.4.0",
        "harness_version": "0.130.0",
        "platform": "macos-arm64",
        "evidence_reference": "gauntlet-run-1234",
        "observed_at": "2026-11-14T12:00:00Z",
        "expires_at": "2026-12-14T12:00:00Z",
    })
}

fn problems(row: Value) -> Vec<String> {
    check_document(&document(row)).1
}

fn rejects(row: Value, needle: &str) {
    let found = problems(row);
    assert!(
        found.iter().any(|problem| problem.contains(needle)),
        "expected a problem containing {needle:?}, got {found:?}"
    );
}

#[test]
fn the_bundled_contract_is_well_formed() {
    let payload = check_payload();
    assert_eq!(payload["valid"], true, "{payload:#}");
    assert!(payload["rows"].as_u64().is_some_and(|rows| rows > 0));
}

#[test]
fn every_bundled_row_names_a_declared_surface_failure_and_state() {
    let document: Value = serde_json::from_str(CONTRACT).expect("bundled contract parses");
    for contract in document["contracts"].as_array().expect("contracts") {
        for row in contract["capability_events"].as_array().expect("rows") {
            assert!(SURFACES.contains(&row["surface"].as_str().unwrap_or_default()));
            assert!(
                FAILURE_BEHAVIORS.contains(&row["failure_behavior"].as_str().unwrap_or_default())
            );
            assert!(CLAIM_STATES.contains(&row["claim"]["state"].as_str().unwrap_or_default()));
        }
    }
}

#[test]
fn a_proven_claim_with_all_its_evidence_is_accepted() {
    assert_eq!(problems(blocking(proven())), Vec::<String>::new());
    assert_eq!(
        problems(blocking(json!({"state": "configured"}))),
        Vec::<String>::new()
    );
}

#[test]
fn a_row_missing_a_claim_field_is_rejected() {
    for field in ["surface", "failure_behavior", "claim"] {
        let mut row = blocking(json!({"state": "configured"}));
        row.as_object_mut().expect("row").remove(field);
        rejects(row, &format!("missing {field}"));
    }
}

#[test]
fn an_undeclared_value_is_rejected() {
    let mut row = blocking(json!({"state": "configured"}));
    row["surface"] = json!("everywhere");
    rejects(row, "surface \"everywhere\" is not declared");
    let mut row = blocking(json!({"state": "configured"}));
    row["failure_behavior"] = json!("best_effort");
    rejects(row, "failure_behavior \"best_effort\" is not declared");
    rejects(
        blocking(json!({"state": "protected"})),
        "claim state \"protected\" is not declared",
    );
}

#[test]
fn every_evidence_state_needs_every_evidence_field() {
    for state in EVIDENCE_STATES {
        for field in [
            "guard_version",
            "harness_version",
            "platform",
            "evidence_reference",
            "observed_at",
            "expires_at",
        ] {
            let mut claim = proven();
            claim["state"] = json!(state);
            claim["limitations"] = json!(["Cloud agents are not covered."]);
            claim.as_object_mut().expect("claim").remove(field);
            rejects(blocking(claim), &format!("{state} claim needs {field}"));
        }
    }
}

#[test]
fn a_claim_without_evidence_cannot_carry_evidence_fields() {
    let mut claim = proven();
    claim["state"] = json!("configured");
    rejects(
        blocking(claim),
        "configured claim must not carry guard_version",
    );
}

#[test]
fn a_version_range_or_wildcard_is_not_exact() {
    for version in [
        "^0.130.0",
        ">=1.2",
        "1.x",
        "1.2.*",
        "latest",
        "1.2 - 1.4",
        "",
    ] {
        let mut claim = proven();
        claim["harness_version"] = json!(version);
        assert!(
            !problems(blocking(claim)).is_empty(),
            "{version:?} was accepted"
        );
    }
    for version in ["0.130.0", "2.1.32", "3.4.0-alpha.93", "1.0.0+build.7"] {
        let mut claim = proven();
        claim["harness_version"] = json!(version);
        assert_eq!(
            problems(blocking(claim)),
            Vec::<String>::new(),
            "{version:?}"
        );
    }
}

#[test]
fn evidence_times_are_fixed_utc_and_expire_after_they_were_observed() {
    let mut claim = proven();
    claim["observed_at"] = json!("2026-11-14 12:00");
    rejects(
        blocking(claim),
        "observed_at \"2026-11-14 12:00\" is not YYYY-MM-DDTHH:MM:SSZ",
    );
    let mut claim = proven();
    claim["expires_at"] = json!("2026-11-14T12:00:00+01:00");
    rejects(blocking(claim), "is not YYYY-MM-DDTHH:MM:SSZ");
    let mut claim = proven();
    claim["expires_at"] = json!("2026-11-13T12:00:00Z");
    rejects(blocking(claim), "expires_at must be after observed_at");
}

#[test]
fn an_evidence_reference_is_never_a_local_path_or_a_signed_url() {
    for reference in [
        "/Users/someone/run.json",
        "~/runs/1",
        "C:\\runs\\1",
        "https://example.test/a?token=1",
        "runs/home/x",
    ] {
        let mut claim = proven();
        claim["evidence_reference"] = json!(reference);
        let found = problems(blocking(claim));
        assert!(
            found
                .iter()
                .any(|problem| problem.contains("evidence_reference")),
            "{reference:?} was accepted: {found:?}"
        );
    }
}

#[test]
fn a_platform_names_os_and_arch() {
    for value in ["macos", "MacOS-ARM64", "macos arm64"] {
        let mut claim = proven();
        claim["platform"] = json!(value);
        rejects(blocking(claim), "is not os-arch");
    }
}

#[test]
fn a_partial_claim_names_what_it_leaves_out() {
    let mut claim = proven();
    claim["state"] = json!("partial");
    rejects(
        blocking(claim.clone()),
        "partial claim must name what it does not cover",
    );
    claim["limitations"] = json!([""]);
    rejects(blocking(claim), "each limitation needs");
}

#[test]
fn an_unknown_claim_field_is_rejected() {
    let mut claim = proven();
    claim["command"] = json!("rm -rf build");
    rejects(blocking(claim), "does not parse");
}

#[test]
fn failure_behavior_and_state_cannot_disagree() {
    let mut observe = blocking(json!({"state": "observe_only"}));
    observe["mode"] = json!("observe");
    rejects(
        observe.clone(),
        "observe_only and claim state observe_only must go together",
    );
    observe["failure_behavior"] = json!("observe_only");
    assert_eq!(problems(observe.clone()), Vec::<String>::new());
    observe["claim"] = json!({"state": "configured"});
    rejects(observe, "must go together");

    let mut declared = blocking(json!({"state": "configured"}));
    declared["transport"] = json!("adapter_declared");
    rejects(
        declared.clone(),
        "no enforceable transport must fail as unsupported",
    );
    declared["failure_behavior"] = json!("unsupported");
    declared["claim"] = json!({"state": "unsupported"});
    assert_eq!(problems(declared), Vec::<String>::new());
}

#[test]
fn the_claude_prompt_hook_is_published_as_failing_open() {
    let document: Value = serde_json::from_str(CONTRACT).expect("bundled contract parses");
    let prompt = document["contracts"]
        .as_array()
        .and_then(|contracts| {
            contracts
                .iter()
                .find(|contract| contract["harness"] == "claude-code")
        })
        .and_then(|contract| contract["capability_events"].as_array())
        .and_then(|rows| rows.iter().find(|row| row["event"] == "UserPromptSubmit"))
        .expect("Claude Code declares UserPromptSubmit");
    assert_eq!(prompt["failure_behavior"], "fail_open");
}

#[test]
fn the_cli_support_operation_returns_the_check() {
    let answer = crate::cli_runtime_support_op::evaluate("harness_protection_contract", &json!({}))
        .expect("operation answers");
    assert_eq!(
        answer["result"]["schema"],
        "hol-guard.harness-protection-contract-check.v1"
    );
    assert_eq!(answer["result"]["valid"], true);
}
