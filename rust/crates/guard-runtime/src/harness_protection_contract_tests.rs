use serde_json::{json, Value};

use super::{
    check_document, check_payload, check_payload_at, claims, CLAIM_STATES, CONTRACT,
    EVIDENCE_STATES, FAILURE_BEHAVIORS, SURFACES,
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
        "declared_actions": ["observe", "block", "approval"],
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
        "C:/Users/alice/run.json",
        "file:///tmp/run.json",
        "runs/private.json",
        "https://example.test/hashgraph-online/hol-guard/actions/runs/1",
        "https://github.com/hashgraph-online/hol-guard/../x",
        "..",
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
fn an_evidence_reference_names_a_run_or_a_page_in_this_repository() {
    for reference in [
        "gauntlet-run-1234",
        "hol-guard-v3.4.0-alpha.93_macos",
        "https://github.com/hashgraph-online/hol-guard/actions/runs/43642386292",
    ] {
        let mut claim = proven();
        claim["evidence_reference"] = json!(reference);
        assert_eq!(
            problems(blocking(claim)),
            Vec::<String>::new(),
            "{reference:?}"
        );
    }
}

#[test]
fn an_impossible_calendar_time_is_rejected() {
    for value in [
        "2026-13-01T12:00:00Z",
        "2026-02-30T12:00:00Z",
        "2025-02-29T12:00:00Z",
        "2026-04-31T12:00:00Z",
        "2026-11-00T12:00:00Z",
        "2026-11-14T24:00:00Z",
        "2026-11-14T12:60:00Z",
        "2026-11-14T12:00:60Z",
        "0000-01-01T00:00:00Z",
    ] {
        let mut claim = proven();
        claim["observed_at"] = json!(value);
        rejects(blocking(claim), "is not YYYY-MM-DDTHH:MM:SSZ");
    }
    let mut claim = proven();
    claim["observed_at"] = json!("2024-02-29T23:59:59Z");
    assert_eq!(problems(blocking(claim)), Vec::<String>::new());
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
    observe["declared_actions"] = json!(["observe"]);
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
    declared["declared_actions"] = json!(["observe"]);
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

#[test]
fn a_row_cannot_contradict_what_it_declares() {
    let mut observe = blocking(json!({"state": "observe_only"}));
    observe["mode"] = json!("observe");
    observe["failure_behavior"] = json!("observe_only");
    rejects(observe, "must not declare block, approval, or rewrite");
    let mut enforcing = blocking(json!({"state": "configured"}));
    enforcing["declared_actions"] = json!(["observe"]);
    rejects(enforcing, "an enforcing row must declare block");
}

#[test]
fn an_event_is_declared_once_per_surface_and_transport() {
    let row = blocking(json!({"state": "configured"}));
    let text = json!({
        "schema": "hol-guard.harness-protection-contracts.v1",
        "contracts": [{"harness": "codex", "capability_events": [row.clone(), row]}],
    })
    .to_string();
    let problems = check_document(&text).1;
    assert!(
        problems
            .iter()
            .any(|problem| problem.contains("declared twice")),
        "{problems:?}"
    );
}

fn split(rows: Vec<Value>) -> Vec<String> {
    let text = json!({
        "schema": "hol-guard.harness-protection-contracts.v1",
        "contracts": [{"harness": "codex", "capability_events": rows}],
    })
    .to_string();
    check_document(&text).1
}

fn with_tools(tools: Value) -> Value {
    let mut row = blocking(json!({"state": "configured"}));
    row["tools"] = tools;
    row
}

#[test]
fn an_event_may_be_split_into_rows_by_disjoint_tools() {
    let shell = with_tools(json!(["Bash", "mcp__*"]));
    let write = with_tools(json!(["apply_patch"]));
    assert_eq!(
        split(vec![shell.clone(), write.clone()]),
        Vec::<String>::new()
    );

    let overlapping = with_tools(json!(["apply_patch", "Bash"]));
    let unnamed = blocking(json!({"state": "configured"}));
    let named_under_prefix = with_tools(json!(["mcp__server__tool"]));
    let narrower_prefix = with_tools(json!(["mcp__s*"]));
    for rows in [
        vec![shell.clone(), overlapping],
        vec![write, unnamed],
        vec![shell.clone(), named_under_prefix],
        vec![shell.clone(), narrower_prefix],
    ] {
        let problems = split(rows);
        assert!(
            problems
                .iter()
                .any(|problem| problem.contains("declared twice")),
            "{problems:?}"
        );
    }
}

#[test]
fn tool_prefixes_overlap_the_names_they_cover() {
    for (a, b, overlap) in [
        ("mcp__*", "mcp__server__tool", true),
        ("mcp__server__tool", "mcp__*", true),
        ("mcp__*", "mcp__s*", true),
        ("Bash", "Bash", true),
        ("Bash", "BashOutput", false),
        ("mcp__*", "apply_patch", false),
        ("Write*", "Edit*", false),
    ] {
        assert_eq!(super::tools_overlap(a, b), overlap, "{a} {b}");
    }
}

#[test]
fn a_tool_is_a_name_or_a_name_prefix_listed_once() {
    for (tools, needle) in [
        (json!(["*"]), "not a tool name"),
        (json!(["Bash|Read"]), "not a tool name"),
        (json!(["mcp__*__x"]), "not a tool name"),
        (json!(["Bash", "Bash"]), "listed twice"),
    ] {
        rejects(with_tools(tools), needle);
    }
}

#[test]
fn a_split_row_is_labelled_with_its_tools() {
    let mut row = with_tools(json!(["apply_patch"]));
    row["claim"] = proven();
    let label = super::row_label(&claims(&document(row), None)[0]);
    assert_eq!(label, "codex PreToolUse [apply_patch] (native_hook)");
}

#[test]
fn expired_evidence_is_shown_stale_and_listed() {
    let text = document(blocking(proven()));
    let before = claims(&text, Some("2026-12-14T11:59:59Z"));
    assert_eq!(before[0]["effective_state"], "live_block_proven");
    let at = claims(&text, Some("2026-12-14T12:00:00Z"));
    assert_eq!(at[0]["effective_state"], "stale");
    assert_eq!(at[0]["state"], "live_block_proven");
    let timeless = claims(&text, None);
    assert_eq!(timeless[0]["effective_state"], "live_block_proven");
    let configured = claims(
        &document(blocking(json!({"state": "configured"}))),
        Some("2099-01-01T00:00:00Z"),
    );
    assert_eq!(configured[0]["effective_state"], "configured");
}

#[test]
fn the_check_takes_only_a_fixed_utc_time() {
    assert_eq!(
        check_payload_at(Some("2026-11-14")),
        Err("harness_protection_contract_time_invalid")
    );
    let payload = check_payload_at(Some("2026-11-14T12:00:00Z")).expect("valid time");
    assert_eq!(payload["as_of"], "2026-11-14T12:00:00Z");
    assert_eq!(payload["expired"], json!([]));
    assert_eq!(
        payload["claims"].as_array().map(Vec::len),
        payload["rows"]
            .as_u64()
            .and_then(|rows| usize::try_from(rows).ok())
    );
}

/// The generated file the hosted pages consume carries the same claim on
/// every semantic field as the runtime projection, row for row.
#[test]
fn the_generated_claims_file_matches_the_runtime_projection() {
    let generated: Value = serde_json::from_str(include_str!(
        "../../../../docs/guard/generated/harness-claims.v1.json"
    ))
    .expect("generated claims parse");
    let published = generated["claims"].as_array().expect("claims");
    let runtime = claims(CONTRACT, None);
    assert_eq!(published.len(), runtime.len());
    for (published, runtime) in published.iter().zip(&runtime) {
        for field in [
            "harness",
            "event",
            "tools",
            "transport",
            "mode",
            "surface",
            "failure_behavior",
            "state",
            "expires_at",
            "limitations",
            "known_blind_spots",
        ] {
            assert_eq!(published[field], runtime[field], "{field} of {runtime}");
        }
    }
}
