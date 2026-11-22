//! The `bundle_candidate` query answers what `policy_bundle_candidate_decisions`
//! answered over four resident round trips.

use std::time::{Duration, Instant};

use serde_json::{json, Value};

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(30)
}

fn rule(id: &str, effect: &str, matcher: Value) -> Value {
    json!({
        "id": id,
        "enabled": true,
        "effect": effect,
        "match": matcher,
        "lifetime": {"mode": "permanent", "expiresAt": null},
        "provenance": {"source": "cloud", "createdAt": "2026-01-01T00:00:00Z"},
    })
}

fn canonical(mode: &str, rules: Value) -> Value {
    json!({
        "contractVersion": "guard-policy-bundle.v2",
        "issuedAt": "2026-11-20T10:00:00Z",
        "payload": {
            "apiVersion": "guard.hashgraphonline.com/v1alpha1",
            "kind": "GuardPolicy",
            "metadata": {"id": "managed-policy", "name": "Managed policy", "revision": 0},
            "spec": {"defaults": {"mode": mode}, "rules": rules},
        },
    })
}

fn allow_publish() -> Value {
    json!([rule(
        "allow-publish",
        "allow",
        json!({"commands": ["npm publish --tag next"]})
    )])
}

fn legacy(issued_at: &str) -> Value {
    json!({
        "bundleVersion": 1,
        "issuedAt": issued_at,
        "rules": [{"ruleId": "legacy-clean", "action": "block", "scope": {"command": "rm -rf build"}}],
    })
}

fn ask(bundle: &Value, is_v2: bool, enforcing: bool, stored: &Value, existing: &Value) -> Value {
    let input = json!({
        "bundle": bundle,
        "is_v2": is_v2,
        "device_id": "device-1",
        "device_name": "Workstation",
        "canonical_enforcement": enforcing,
        "stored_legacy": stored,
        "existing": existing,
    });
    let answer = super::super::query(super::QUERY, &input, deadline()).unwrap();
    answer
        .get("ok")
        .cloned()
        .unwrap_or_else(|| panic!("{answer}"))
}

#[test]
fn a_v1_candidate_activates_the_rows_the_authority_materializes() {
    let answer = ask(
        &legacy("2026-11-20T10:00:00Z"),
        false,
        false,
        &Value::Null,
        &Value::Null,
    );
    let rows = answer["decisions"].as_array().unwrap();
    assert!(!rows.is_empty(), "{answer}");
    assert!(rows
        .iter()
        .all(|row| row["action"] == "block" && row["owner"] == "legacy-clean"));
    assert_eq!(answer["rejection"], Value::Null);
    assert_eq!(answer["mismatch"], Value::Null);
}

#[test]
fn a_v2_candidate_compiles_to_canonical_rows_owned_by_their_rule() {
    let answer = ask(
        &canonical("prompt", allow_publish()),
        true,
        false,
        &Value::Null,
        &Value::Null,
    );
    let rows = answer["decisions"].as_array().unwrap();
    assert!(!rows.is_empty(), "{answer}");
    for row in rows {
        assert_eq!(row["owner"], "allow-publish");
        assert_eq!(row["source"], "policy-bundle-canonical");
        assert_eq!(row["action"], "allow");
        assert_eq!(row.as_object().unwrap().len(), 11);
    }
    // No shadow to compare with: recorded, but only a rollout device refuses
    // a real disagreement, and a missing shadow is not one.
    assert_eq!(answer["rejection"], Value::Null);
    assert_eq!(
        answer["mismatch"]["reasonCodes"],
        json!(["legacy_unavailable"])
    );
    assert_eq!(answer["mismatch"]["legacyRows"], 0);
    assert_eq!(answer["mismatch"]["canonicalRows"], rows.len());
    assert_eq!(answer["mismatch"]["status"], "mismatch");
}

#[test]
fn a_rollout_device_keeps_its_policy_when_the_shadow_disagrees() {
    let stored = legacy("2026-11-21T10:00:00Z");
    let candidate = canonical("prompt", allow_publish());
    let refused = ask(&candidate, true, true, &stored, &Value::Null);
    assert_eq!(
        refused["rejection"], "canonical_shadow_mismatch",
        "{refused}"
    );
    assert!(refused["mismatch"]["legacyRows"].as_u64().unwrap() > 0);
    let reasons = refused["mismatch"]["reasonCodes"].as_array().unwrap();
    assert!(!reasons.is_empty() && !reasons.contains(&json!("legacy_unavailable")));

    let recorded = ask(&candidate, true, false, &stored, &Value::Null);
    assert_eq!(recorded["rejection"], Value::Null);
    assert_eq!(recorded["mismatch"], refused["mismatch"]);
    assert_eq!(recorded["decisions"], refused["decisions"]);
}

#[test]
fn a_shadow_from_an_older_publication_is_not_compared() {
    let older = legacy("2026-11-19T10:00:00Z");
    let answer = ask(
        &canonical("prompt", allow_publish()),
        true,
        true,
        &Value::Null,
        &older,
    );
    assert_eq!(answer["rejection"], Value::Null, "{answer}");
    assert_eq!(
        answer["mismatch"]["reasonCodes"],
        json!(["legacy_unavailable"])
    );
}

#[test]
fn an_active_v2_bundle_is_never_the_shadow() {
    let existing = canonical("prompt", json!([]));
    let answer = ask(
        &canonical("prompt", allow_publish()),
        true,
        true,
        &json!("not a bundle"),
        &existing,
    );
    assert_eq!(
        answer["mismatch"]["reasonCodes"],
        json!(["legacy_unavailable"]),
        "{answer}"
    );
}

#[test]
fn an_evaluate_candidate_has_nothing_to_drift_from() {
    let stored = legacy("2026-11-21T10:00:00Z");
    let answer = ask(
        &canonical("observe", allow_publish()),
        true,
        true,
        &stored,
        &Value::Null,
    );
    assert_eq!(
        answer,
        json!({"decisions": [], "rejection": null, "rule_id": null, "mismatch": null})
    );
}

#[test]
fn a_candidate_that_fails_to_compile_names_the_rule() {
    let warn = json!([rule("warn-only", "warn", json!({}))]);
    let answer = ask(
        &canonical("prompt", warn),
        true,
        true,
        &Value::Null,
        &Value::Null,
    );
    assert_eq!(
        answer["rejection"], "canonical_compile_unsupported_policy_effect",
        "{answer}"
    );
    assert_eq!(answer["rule_id"], "warn-only");
    assert_eq!(answer["decisions"], json!([]));
    assert_eq!(answer["mismatch"], Value::Null);
}

#[test]
fn a_shadow_that_no_longer_compiles_stands_in_as_unavailable() {
    let mut stored = canonical("prompt", json!([rule("warn-only", "warn", json!({}))]));
    stored["contractVersion"] = json!("guard-policy-bundle.v2");
    stored["issuedAt"] = json!("2026-11-21T10:00:00Z");
    let answer = ask(
        &canonical("prompt", allow_publish()),
        true,
        true,
        &stored,
        &Value::Null,
    );
    assert_eq!(answer["rejection"], Value::Null, "{answer}");
    assert_eq!(
        answer["mismatch"]["reasonCodes"],
        json!(["legacy_unavailable"])
    );
}

#[test]
fn a_request_it_cannot_read_is_a_value_error() {
    for input in [json!([]), json!({"bundle": {}}), json!({"unknown": true})] {
        let answer = super::super::query(super::QUERY, &input, deadline()).unwrap();
        assert_eq!(answer["error"]["type"], "ValueError", "{input}");
    }
}

#[test]
fn a_compiled_row_that_would_not_build_a_decision_is_malformed() {
    let good = json!({
        "rule_id": "r",
        "provenance_json": "{}",
        "decision": {"harness": "codex", "scope": "global", "action": "allow"},
    });
    assert_eq!(
        super::canonical_decision(&good).unwrap()["source"],
        "policy-bundle-canonical"
    );
    for (key, value) in [
        ("action", json!("ignore")),
        ("scope", json!("everywhere")),
        ("harness", json!(1)),
        ("unknown", json!("x")),
    ] {
        let mut bad = good.clone();
        bad["decision"][key] = value;
        assert_eq!(super::canonical_decision(&bad), None, "{key}");
    }
}
