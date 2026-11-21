use serde_json::{json, Value};

use super::{below, dispatch};
use crate::runner_authority_op::ERR_INVALID;

fn complete() -> Value {
    json!({
        "detectors": {"supply_chain": "complete"},
        "reasons": ["detector_not_run:secrets"],
    })
}

fn run(coverage: Value, findings: Value) -> Value {
    json!({
        "run_id": "run-2",
        "snapshot_digest": "after",
        "started_at_ms": 2_000,
        "coverage": coverage,
        "findings": findings,
    })
}

fn proposal() -> Value {
    json!({
        "proposal_id": "p-1",
        "ecosystem": "npm",
        "package_name": "left-pad",
        "fix_version": "1.3.0",
        "advisory_ids": ["GHSA-1"],
        "rule_ids": ["known-vulnerable"],
        "snapshot_digest": "before",
        "applied_at_ms": 1_000,
        "state": "applied",
        "verification_run_id": null,
    })
}

fn finding(version: &str, advisories: Value, rules: Value) -> Value {
    json!({
        "ecosystem": "npm",
        "package_name": "left-pad",
        "package_version": version,
        "advisory_ids": advisories,
        "rule_ids": rules,
    })
}

fn updates(run: Value, proposals: Value) -> Vec<Value> {
    let answer = dispatch(&json!({"run": run, "proposals": proposals})).expect("updates");
    answer["updates"].as_array().cloned().expect("update list")
}

fn state(run: Value, proposal: Value) -> Option<String> {
    updates(run, json!([proposal]))
        .first()
        .map(|update| update["state"].as_str().expect("state").to_owned())
}

#[test]
fn a_complete_run_without_the_finding_marks_it_fixed() {
    let found = updates(run(complete(), json!([])), json!([proposal()]));
    assert_eq!(
        found,
        vec![json!({"proposal_id": "p-1", "state": "verified_fixed"})]
    );
}

#[test]
fn a_matching_finding_keeps_it_present() {
    let overlapping = finding("1.3.0", json!(["GHSA-1"]), json!([]));
    assert_eq!(
        state(run(complete(), json!([overlapping])), proposal()).as_deref(),
        Some("still_present")
    );
    let by_rule = finding("2.0.0", json!([]), json!(["known-vulnerable"]));
    assert_eq!(
        state(run(complete(), json!([by_rule])), proposal()).as_deref(),
        Some("still_present")
    );
    let still_below = finding("1.2.9", json!(["other"]), json!(["other"]));
    assert_eq!(
        state(run(complete(), json!([still_below])), proposal()).as_deref(),
        Some("still_present")
    );
}

#[test]
fn unrelated_findings_do_not_block_a_fix() {
    let mut other_package = finding("1.0.0", json!(["GHSA-1"]), json!([]));
    other_package["package_name"] = json!("other");
    let mut other_ecosystem = finding("1.0.0", json!(["GHSA-1"]), json!([]));
    other_ecosystem["ecosystem"] = json!("pypi");
    let fixed_version = finding("1.3.0", json!(["Y"]), json!(["new-rule"]));
    let findings = json!([other_package, other_ecosystem, fixed_version, "text"]);
    assert_eq!(
        state(run(complete(), findings), proposal()).as_deref(),
        Some("verified_fixed")
    );
}

#[test]
fn partial_coverage_never_settles_a_fix() {
    for coverage in [
        json!({"reasons": ["supply_chain_incomplete"], "detectors": {"supply_chain": "incomplete"}}),
        json!({"reasons": ["finding_cap"], "detectors": {"supply_chain": "complete"}}),
        json!({"reasons": ["lockfile_warnings"], "detectors": {"supply_chain": "complete"}}),
        json!({"reasons": ["advisory_data_unavailable"], "detectors": {"supply_chain": "complete"}}),
        json!({"reasons": ["snapshot_truncated"], "detectors": {"supply_chain": "complete"}}),
        json!({"reasons": [7], "detectors": {"supply_chain": "complete"}}),
        json!({"reasons": [], "detectors": {"supply_chain": "no_inputs"}}),
        json!({"reasons": [], "detectors": {}}),
        json!({"detectors": {"supply_chain": "complete"}}),
        json!({}),
        Value::Null,
    ] {
        assert!(
            updates(run(coverage.clone(), json!([])), json!([proposal()])).is_empty(),
            "{coverage}"
        );
    }
}

#[test]
fn snapshot_reasons_that_read_everything_still_verify() {
    for reason in [
        "snapshot_unsupported_dependency_input",
        "snapshot_undiscovered_dependency_input",
    ] {
        let coverage = json!({"detectors": {"supply_chain": "complete"}, "reasons": [reason]});
        assert_eq!(
            state(run(coverage, json!([])), proposal()).as_deref(),
            Some("verified_fixed")
        );
    }
}

#[test]
fn a_run_that_could_have_read_the_old_manifest_does_not_count() {
    let mut same_snapshot = proposal();
    same_snapshot["snapshot_digest"] = json!("after");
    let mut same_millisecond = proposal();
    same_millisecond["applied_at_ms"] = json!(2_000);
    let mut later_apply = proposal();
    later_apply["applied_at_ms"] = json!(5_000);
    for proposal in [same_snapshot, same_millisecond, later_apply] {
        assert!(state(run(complete(), json!([])), proposal).is_none());
    }
    let mut unstarted = run(complete(), json!([]));
    unstarted["started_at_ms"] = Value::Null;
    assert!(state(unstarted, proposal()).is_none());
}

#[test]
fn an_unchanged_verdict_from_the_same_run_is_not_rewritten() {
    let mut settled = proposal();
    settled["state"] = json!("verified_fixed");
    settled["verification_run_id"] = json!("run-2");
    assert!(state(run(complete(), json!([])), settled.clone()).is_none());
    settled["state"] = json!("still_present");
    assert_eq!(
        state(run(complete(), json!([])), settled).as_deref(),
        Some("verified_fixed")
    );
}

#[test]
fn versions_compare_numerically_and_unreadable_ones_count_as_older() {
    let older = |version: Value, fix: &str| below(Some(&version), fix);
    assert!(older(json!("1.2.9"), "1.3.0"));
    assert!(older(json!("1.3.0-beta.1"), "1.3.0"));
    assert!(older(json!("9.99.99"), "10.0.0"));
    assert!(older(
        json!("0099999999999999999999.0.0"),
        "100000000000000000000000.0.0"
    ));
    assert!(!older(json!("1.3.0"), "1.3.0"));
    assert!(!older(json!("1.3.0+build.5"), "1.3.0"));
    assert!(!older(json!("1.3.0-rc.1"), "1.3.0-rc.0"));
    assert!(!older(json!("01.3.0"), "1.3.0"));
    assert!(!older(json!("2.0.0"), "1.3.0"));
    for unreadable in [
        json!("1.3"),
        json!("1.3.0-"),
        json!("1.3.0+"),
        json!("1.3.0x"),
        json!("v1.3.0"),
        json!(130),
    ] {
        assert!(older(unreadable.clone(), "1.3.0"), "{unreadable}");
    }
    assert!(below(None, "1.3.0"));
    assert!(older(json!("2.0.0"), "not-a-version"));
}

#[test]
fn malformed_requests_are_refused() {
    let mut extra_run = run(complete(), json!([]));
    extra_run["extra"] = json!(1);
    let mut short_proposal = proposal();
    if let Some(fields) = short_proposal.as_object_mut() {
        fields.remove("state");
    }
    for args in [
        json!({"run": run(complete(), json!([])), "proposals": [], "extra": 1}),
        json!({"run": run(complete(), json!([]))}),
        json!({"run": extra_run, "proposals": []}),
        json!({"run": null, "proposals": []}),
        json!({"run": run(complete(), json!([])), "proposals": {}}),
        json!({"run": run(complete(), json!([])), "proposals": [short_proposal]}),
        json!({"run": run(complete(), json!([])), "proposals": ["p-1"]}),
        json!([]),
    ] {
        assert_eq!(dispatch(&args), Err(ERR_INVALID), "{args}");
    }
}
