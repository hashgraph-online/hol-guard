use serde_json::{json, Value};

use super::dispatch;

fn plan(request: Value) -> Value {
    dispatch(&request).expect("object request")
}

fn rule(rule_id: &str, overrides: Value) -> Value {
    let mut rule = json!({
        "ruleId": rule_id,
        "harnessId": "cursor",
        "artifactId": "plugin:hol/deploy",
        "artifactHash": "b",
        "action": "allow",
        "scope": "workspace",
        "expiresAt": "2026-12-01T00:00:00+00:00",
        "target": { "workspaceIds": ["  ", "workspace-target"] },
    });
    for (key, value) in overrides.as_object().expect("overrides object") {
        rule[key] = value.clone();
    }
    rule
}

fn stored(rule_id: &str, harness: &str) -> Value {
    json!({
        "ruleId": rule_id,
        "decision": {
            "harness": harness,
            "scope": "artifact",
            "action": "block",
            "artifact_id": "a",
            "source": "cloud-signed-memory",
        },
    })
}

#[test]
fn a_workspace_rule_becomes_a_signed_memory_decision_for_its_target_workspace() {
    let answer = plan(json!({
        "rules": [rule(" r1 ", json!({}))],
        "workspace_id": "workspace-bundle",
    }));
    assert_eq!(answer["rejected_rule_ids"], json!([]));
    assert_eq!(answer["applied_rule_count"], 1);
    let decision = json!({
        "harness": "cursor",
        "scope": "workspace",
        "action": "allow",
        "artifact_id": "plugin:hol/deploy",
        "artifact_hash": "b",
        "workspace": "workspace-target",
        "publisher": null,
        "reason": "Guard Cloud signed decision memory sync",
        "owner": null,
        "source": "cloud-signed-memory",
        "expires_at": "2026-12-01T00:00:00+00:00",
    });
    assert_eq!(answer["registry_rule_ids"], json!(["r1"]));
    assert_eq!(answer["decisions"], json!([decision]));
}

#[test]
fn wider_scopes_map_to_workspace_or_artifact_and_fall_back_to_the_bundle_workspace() {
    let answer = plan(json!({
        "rules": [
            rule("team", json!({ "action": "block", "scope": "team", "target": [] })),
            rule("global", json!({ "action": "review", "scope": "global", "reason": "Cloud." })),
        ],
        "workspace_id": " workspace-bundle ",
    }));
    let decisions = &answer["decisions"];
    assert_eq!(decisions[0]["scope"], "workspace");
    assert_eq!(decisions[0]["workspace"], "workspace-bundle");
    assert_eq!(decisions[1]["scope"], "artifact");
    assert_eq!(decisions[1]["workspace"], Value::Null);
    assert_eq!(decisions[1]["reason"], "Cloud.");
}

#[test]
fn an_unusable_rule_rejects_the_whole_bundle_without_reading_the_registry() {
    let answer = plan(json!({
        "rules": [
            rule("ok", json!({})),
            rule("wide-allow", json!({ "scope": "machine" })),
            rule("alias", json!({ "action": "deny" })),
            rule("blank", json!({ "harnessId": "  " })),
            rule("no-artifact", json!({ "artifactId": null })),
            rule("no-scope", json!({ "scope": 7 })),
        ],
        "registry": [{ "ruleId": "bad", "decision": { "scope": "nowhere" } }],
    }));
    assert_eq!(
        answer,
        json!({ "rejected_rule_ids": ["wide-allow", "alias", "blank", "no-artifact", "no-scope"] })
    );
}

#[test]
fn a_rule_without_an_identity_fails_the_bundle() {
    for rules in [
        json!(["rule"]),
        json!([rule("  ", json!({}))]),
        json!([{ "harnessId": "x" }]),
    ] {
        assert_eq!(
            plan(json!({ "rules": rules })),
            json!({ "error": "invalid_decision_memory_rule" }),
            "{rules}"
        );
    }
}

#[test]
fn revocations_drop_rules_and_new_rules_replace_in_place() {
    let answer = plan(json!({
        "rules": [rule("keep", json!({ "action": "block" })), rule("new", json!({}))],
        "revocations": [" gone ", 3, null],
        "registry": [
            stored("keep", "old"),
            "not-an-entry",
            { "ruleId": "no-decision", "decision": [] },
            stored("gone", "codex"),
            stored("other", "claude-code"),
            stored("other", "copilot"),
        ],
    }));
    assert_eq!(answer["applied_rule_count"], 2);
    assert_eq!(answer["registry_rule_ids"], json!(["keep", "other", "new"]));
    let harnesses: Vec<&str> = answer["decisions"]
        .as_array()
        .expect("decision list")
        .iter()
        .filter_map(|decision| decision["harness"].as_str())
        .collect();
    assert_eq!(harnesses, ["cursor", "copilot", "cursor"]);
    assert_eq!(answer["decisions"][0]["action"], "block");
}

#[test]
fn only_usable_policy_bundle_decisions_are_kept_ahead_of_memory() {
    let answer = plan(json!({
        "rules": [],
        "policies": [
            { "source": "policy-bundle", "harness": " codex ", "scope": "harness", "action": "warn", "reason": "" },
            { "source": "local", "harness": "codex", "scope": "harness", "action": "warn" },
            { "source": "policy-bundle", "harness": "codex", "scope": "team", "action": "warn" },
            { "source": "policy-bundle", "harness": "codex", "scope": "harness", "action": "deny" },
        ],
        "registry": [stored("m", "cursor")],
    }));
    assert_eq!(answer["applied_rule_count"], 0);
    let decisions = answer["decisions"].as_array().expect("decision list");
    assert_eq!(decisions.len(), 2);
    assert_eq!(decisions[0]["harness"], "codex");
    assert_eq!(decisions[0]["source"], "policy-bundle");
    assert_eq!(decisions[0]["reason"], Value::Null);
    assert_eq!(decisions[1]["source"], "cloud-signed-memory");
}

#[test]
fn an_unusable_stored_decision_fails_the_registry() {
    for decision in [
        json!({ "harness": "x", "scope": "everywhere", "action": "block" }),
        json!({ "harness": "x", "scope": "artifact", "action": "deny" }),
        json!({ "scope": "artifact", "action": "block" }),
        json!({ "harness": "x", "scope": "artifact", "action": "block", "source": 5 }),
    ] {
        assert_eq!(
            plan(json!({ "registry": [{ "ruleId": "r", "decision": decision }] })),
            json!({ "error": "invalid_decision_memory_registry" }),
            "{decision}"
        );
    }
    let falsy = json!({ "harness": "x", "scope": "artifact", "action": "block", "source": "" });
    let answer = plan(json!({ "registry": [{ "ruleId": "r", "decision": falsy }] }));
    assert_eq!(answer["decisions"][0]["source"], "cloud-signed-memory");
}

#[test]
fn a_non_object_request_is_invalid() {
    assert!(dispatch(&json!([])).is_err());
}
