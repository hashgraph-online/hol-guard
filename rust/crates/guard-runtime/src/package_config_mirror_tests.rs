//! Which sent configurations hydrate the policy view, and which defer the call.

use super::*;

use serde_json::json;

/// The fields a caller holding the loaded configuration sends: the policy
/// fields and the managed-policy pair the approval hash binds, in one map.
fn facts() -> Map<String, Value> {
    json!({
        "mode": "enforce",
        "artifact_actions": Value::Null,
        "publisher_actions": Value::Null,
        "harness_actions": Value::Null,
        "risk_actions": {"package_script": "review"},
        "harness_risk_actions": {"codex": {"package_script": "block"}},
        "harness_postures": Value::Null,
        "security_level": "balanced",
        "protection_posture": "balanced",
        "protection_posture_explicit": false,
        "managed_locked_settings": ["mode"],
        "managed_policy_status": "enforced",
        "managed_policy_hash": "sha256:abc",
    })
    .as_object()
    .expect("object")
    .clone()
}

fn artifact<'a>(publisher: Option<&'a str>) -> ArtifactIdentity<'a> {
    ArtifactIdentity {
        artifact_id: "codex:plugin:demo",
        publisher,
        harness: "codex",
    }
}

fn view(facts: &Map<String, Value>) -> Value {
    config_policy(facts, facts, &artifact(Some("acme"))).expect("hydrated")
}

#[test]
fn one_map_hydrates_the_view_the_two_map_shape_does() {
    let facts = facts();
    // The relay holds the policy fields and the managed-policy pair apart; a
    // caller with the loaded configuration holds one map. Same view either way.
    let mut split = facts.clone();
    let mut hash_config = Map::new();
    for key in ["managed_policy_status", "managed_policy_hash"] {
        hash_config.insert(key.to_owned(), split.remove(key).expect("field"));
    }
    assert_eq!(
        config_policy(&split, &hash_config, &artifact(Some("acme"))).expect("hydrated"),
        view(&facts),
    );
}

#[test]
fn the_harness_package_script_action_beats_the_global_one() {
    let view = view(&facts());
    assert_eq!(view["effective_package_script_action"], json!("block"));
    assert_eq!(view["global_package_script_action"], json!("review"));
    assert_eq!(view["harness_package_script_action"], json!("block"));
    assert_eq!(view["managed_policy_hash"], json!("sha256:abc"));
    assert_eq!(view["managed_policy_status"], json!("enforced"));
    assert_eq!(view["mode"], json!("enforce"));
}

#[test]
fn the_narrowest_override_naming_the_artifact_is_the_resolved_one() {
    let mut facts = facts();
    facts.insert("harness_actions".to_owned(), json!({"codex": "warn"}));
    assert_eq!(view(&facts)["resolved_override"], json!("warn"));
    assert_eq!(view(&facts)["harness_override"], json!("warn"));

    facts.insert("publisher_actions".to_owned(), json!({"acme": "review"}));
    assert_eq!(view(&facts)["resolved_override"], json!("review"));

    facts.insert(
        "artifact_actions".to_owned(),
        json!({"codex:plugin:demo": "block"}),
    );
    let view = view(&facts);
    assert_eq!(view["resolved_override"], json!("block"));
    assert_eq!(view["artifact_override"], json!("block"));
    assert_eq!(view["publisher_override"], json!("review"));
}

#[test]
fn an_unnamed_publisher_falls_through_to_the_harness_override() {
    let mut facts = facts();
    facts.insert("publisher_actions".to_owned(), json!({"acme": "review"}));
    facts.insert("harness_actions".to_owned(), json!({"codex": "warn"}));
    let view = config_policy(&facts, &facts, &artifact(None)).expect("hydrated");
    assert_eq!(view["publisher_override"], Value::Null);
    assert_eq!(view["resolved_override"], json!("warn"));
}

#[test]
fn a_field_this_cannot_read_defers_the_call() {
    for (key, value) in [
        // An override map read as "no override" would drop a bound `block`
        // from the composed action rather than deferring.
        ("artifact_actions", json!([])),
        ("publisher_actions", json!("warn")),
        ("harness_actions", json!(7)),
        ("mode", json!(true)),
        ("risk_actions", json!({"package_script": 3})),
        ("harness_risk_actions", json!({"codex": "block"})),
        ("harness_postures", json!([])),
        ("security_level", Value::Null),
        ("protection_posture", json!(1)),
        ("protection_posture_explicit", json!("false")),
        ("managed_locked_settings", json!({"mode": true})),
        ("managed_locked_settings", json!(["mode", 2])),
        ("managed_policy_status", Value::Null),
        ("managed_policy_hash", json!(9)),
    ] {
        let mut facts = facts();
        facts.insert(key.to_owned(), value.clone());
        assert!(
            config_policy(&facts, &facts, &artifact(Some("acme"))).is_none(),
            "{key} = {value} should defer",
        );
    }
}

#[test]
fn an_absent_field_defers_the_call_too() {
    for key in [
        "mode",
        "artifact_actions",
        "publisher_actions",
        "harness_actions",
        "risk_actions",
        "harness_risk_actions",
        "harness_postures",
        "security_level",
        "protection_posture",
        "protection_posture_explicit",
        "managed_locked_settings",
        "managed_policy_status",
        "managed_policy_hash",
    ] {
        let mut facts = facts();
        facts.remove(key);
        assert!(
            config_policy(&facts, &facts, &artifact(Some("acme"))).is_none(),
            "a missing {key} should defer",
        );
    }
}
