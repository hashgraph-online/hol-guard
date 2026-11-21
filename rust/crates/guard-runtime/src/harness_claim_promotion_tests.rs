use serde_json::{json, Value};

use super::{add_days, promote, promotion_payload};

const NOW: &str = "2026-11-14T18:00:00Z";

fn contract() -> String {
    json!({
        "schema": "hol-guard.harness-protection-contracts.v1",
        "contracts": [{
            "harness": "codex",
            "capability_events": [
                {
                    "event": "PreToolUse",
                    "transport": "native_hook",
                    "mode": "blocking",
                    "surface": "foreground",
                    "failure_behavior": "fail_closed",
                    "declared_actions": ["observe", "block", "approval"],
                    "claim": {"state": "configured"},
                },
                {
                    "event": "PostToolUse",
                    "transport": "native_hook",
                    "mode": "observe",
                    "surface": "foreground",
                    "failure_behavior": "observe_only",
                    "declared_actions": ["observe"],
                    "claim": {"state": "observe_only"},
                },
            ],
        }],
    })
    .to_string()
}

fn witness(outcome: &str) -> Value {
    json!({
        "outcome": outcome,
        "harness_event": "PreToolUse",
        "decided_by": "native",
        "before_effect": true,
    })
}

fn receipt() -> Value {
    json!({
        "schema": "hol-guard.harness-claim-evidence.v1",
        "harness": "codex",
        "event": "PreToolUse",
        "transport": "native_hook",
        "surface": "foreground",
        "state": "live_block_proven",
        "guard_version": "3.4.0-alpha.95",
        "harness_version": "0.130.0",
        "platform": "macos-arm64",
        "evidence_reference": "gauntlet-run-1234",
        "observed_at": "2026-11-14T12:00:00Z",
        "source": "installed_harness",
        "inference": "live",
        "independent_verifier": true,
        "witnesses": [witness("deny"), witness("allow")],
    })
}

fn refusals(receipt: Value) -> Vec<String> {
    let (refusals, claim) = promote(&contract(), &receipt, NOW);
    assert_eq!(claim.is_some(), refusals.is_empty());
    refusals
}

fn refused(receipt: Value, needle: &str) {
    let found = refusals(receipt);
    assert!(
        found.iter().any(|refusal| refusal.contains(needle)),
        "expected a refusal containing {needle:?}, got {found:?}"
    );
}

#[test]
fn a_live_verified_run_with_both_witnesses_promotes_a_block_claim() {
    let (refusals, claim) = promote(&contract(), &receipt(), NOW);
    assert_eq!(refusals, Vec::<String>::new());
    let claim = claim.expect("promotable");
    assert_eq!(claim["state"], "live_block_proven");
    assert_eq!(claim["observed_at"], "2026-11-14T12:00:00Z");
    assert_eq!(claim["expires_at"], "2026-12-14T12:00:00Z");
    assert!(claim.get("limitations").is_none());
}

#[test]
fn synthetic_evidence_never_promotes_however_complete() {
    for source in ["unit_test", "synthetic", "fixture", "replay", "probe", ""] {
        let mut receipt = receipt();
        receipt["source"] = json!(source);
        refused(receipt, "is synthetic and cannot promote a claim");
    }
    let mut scripted = receipt();
    scripted["inference"] = json!("scripted");
    refused(scripted, "is not a live harness run");
    let mut unverified = receipt();
    unverified["independent_verifier"] = json!(false);
    refused(unverified, "independent verifier");
}

#[test]
fn a_block_claim_needs_a_native_deny_before_effect_and_a_benign_allow() {
    let mut deny_only = receipt();
    deny_only["witnesses"] = json!([witness("deny")]);
    refused(deny_only, "benign counterpart");
    let mut late = receipt();
    late["witnesses"][0]["before_effect"] = json!(false);
    refused(late, "native deny of this event before the action ran");
    let mut fallback = receipt();
    fallback["witnesses"][0]["decided_by"] = json!("python");
    refused(fallback, "native deny");
    let mut other_event = receipt();
    other_event["witnesses"][0]["harness_event"] = json!("PermissionRequest");
    refused(other_event, "native deny");
}

#[test]
fn an_allow_claim_needs_only_the_allow_witness() {
    let mut allow = receipt();
    allow["state"] = json!("live_allow_proven");
    allow["witnesses"] = json!([witness("allow")]);
    assert_eq!(refusals(allow.clone()), Vec::<String>::new());
    allow["witnesses"] = json!([witness("deny")]);
    refused(allow, "native allow");
}

#[test]
fn a_receipt_cannot_promote_a_row_that_does_not_enforce_or_does_not_exist() {
    let mut observe = receipt();
    observe["event"] = json!("PostToolUse");
    for witness in observe["witnesses"].as_array_mut().expect("witnesses") {
        witness["harness_event"] = json!("PostToolUse");
    }
    refused(observe, "only a row that can enforce");
    let mut missing = receipt();
    missing["surface"] = json!("background");
    refused(missing, "declares no row");
    let mut other = receipt();
    other["harness"] = json!("cursor");
    refused(other, "declares no row");
}

#[test]
fn a_contract_with_an_unsupported_schema_is_refused() {
    let mut contract: Value = serde_json::from_str(&contract()).expect("contract");
    contract["schema"] = json!("hol-guard.harness-protection-contracts.v2");
    let (refusals, claim) = promote(&contract.to_string(), &receipt(), NOW);
    assert!(claim.is_none());
    assert!(
        refusals
            .iter()
            .any(|refusal| refusal.contains("contract schema")),
        "{refusals:?}"
    );
}

#[test]
fn only_evidence_states_can_be_promoted_to() {
    for state in [
        "configured",
        "stale",
        "observe_only",
        "unsupported",
        "protected",
    ] {
        let mut receipt = receipt();
        receipt["state"] = json!(state);
        refused(receipt, "is not a state evidence can promote to");
    }
}

#[test]
fn a_partial_claim_names_what_it_leaves_out() {
    let mut partial = receipt();
    partial["state"] = json!("partial");
    refused(
        partial.clone(),
        "partial claim must name what it does not cover",
    );
    partial["limitations"] = json!(["Background sessions are not covered."]);
    let (refusals, claim) = promote(&contract(), &partial, NOW);
    assert_eq!(refusals, Vec::<String>::new());
    assert_eq!(
        claim.expect("promotable")["limitations"],
        json!(["Background sessions are not covered."])
    );
}

#[test]
fn the_promoted_evidence_obeys_every_contract_rule() {
    let mut range = receipt();
    range["harness_version"] = json!("^0.130.0");
    refused(range, "is not an exact version");
    let mut path = receipt();
    path["evidence_reference"] = json!("/Users/someone/run.json");
    refused(path, "evidence_reference");
    let mut platform = receipt();
    platform["platform"] = json!("macOS");
    refused(platform, "is not os-arch");
    let mut time = receipt();
    time["observed_at"] = json!("2026-02-30T12:00:00Z");
    refused(time, "is not YYYY-MM-DDTHH:MM:SSZ");
}

#[test]
fn evidence_from_the_future_or_past_its_window_is_refused() {
    let mut future = receipt();
    future["observed_at"] = json!("2026-11-15T00:00:00Z");
    refused(future, "in the future");
    let mut old = receipt();
    old["observed_at"] = json!("2026-10-15T18:00:00Z");
    refused(old, "already expired");
    let mut fresh = receipt();
    fresh["observed_at"] = json!("2026-10-15T18:00:01Z");
    assert_eq!(refusals(fresh), Vec::<String>::new());
}

#[test]
fn a_receipt_with_an_unknown_field_is_refused() {
    let mut extra = receipt();
    extra["command"] = json!("rm -rf build");
    refused(extra, "receipt does not parse");
    let mut extra_witness = receipt();
    extra_witness["witnesses"][0]["prompt"] = json!("hello");
    refused(extra_witness, "receipt does not parse");
}

#[test]
fn the_expiry_window_crosses_months_years_and_leap_days() {
    assert_eq!(add_days("2026-12-20T08:30:00Z", 30), "2027-01-19T08:30:00Z");
    assert_eq!(add_days("2028-02-15T00:00:00Z", 30), "2028-03-16T00:00:00Z");
    assert_eq!(add_days("2027-02-15T00:00:00Z", 30), "2027-03-17T00:00:00Z");
    assert_eq!(add_days("2000-02-28T23:59:59Z", 1), "2000-02-29T23:59:59Z");
    assert_eq!(add_days("1900-02-28T00:00:00Z", 1), "1900-03-01T00:00:00Z");
}

#[test]
fn the_operation_needs_a_fixed_time_and_a_receipt() {
    assert_eq!(
        promotion_payload(&json!({"receipt": receipt()})),
        Err("harness_claim_promotion_time_invalid")
    );
    assert_eq!(
        promotion_payload(&json!({"now": NOW})),
        Err("harness_claim_promotion_receipt_missing")
    );
    assert_eq!(
        promotion_payload(&json!({"now": NOW, "receipt": receipt(), "contract": 1})),
        Err("harness_claim_promotion_contract_invalid")
    );
    let payload = promotion_payload(&json!({
        "now": NOW,
        "receipt": receipt(),
        "contract": contract(),
    }))
    .expect("answers");
    assert_eq!(payload["schema"], "hol-guard.harness-claim-promotion.v1");
    assert_eq!(payload["promotable"], true);
    // Nothing authenticates the receipt, and the payload must not pretend otherwise.
    assert_eq!(payload["provenance"], "self_reported");
    assert_eq!(payload["claim"]["expires_at"], "2026-12-14T12:00:00Z");
}

#[test]
fn the_bundled_contract_accepts_a_live_claude_code_receipt() {
    let mut claude = receipt();
    claude["harness"] = json!("claude-code");
    claude["harness_version"] = json!("2.1.32");
    let answer = crate::cli_runtime_support_op::evaluate(
        "harness_claim_promotion",
        &json!({"now": NOW, "receipt": claude}),
    )
    .expect("operation answers");
    assert_eq!(answer["result"]["promotable"], true, "{answer:#}");
}
