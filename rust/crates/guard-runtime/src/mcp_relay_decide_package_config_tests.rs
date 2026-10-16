//! What the bound harness view hydrates, and which view defers the call.

use super::*;

use guard_command::package_intent_common::build_package_request_artifact;
use guard_command::package_intent_parser::parse_package_intent;
use serde_json::json;

/// `_tool_call_configuration` of a config with a harness override for the
/// package-script risk class, as the publisher binds it.
fn config() -> Map<String, Value> {
    json!({
        "mode": "enforce",
        "default_action": "warn",
        "artifact_actions": Value::Null,
        "publisher_actions": Value::Null,
        "harness_actions": Value::Null,
        "risk_actions": {"package_script": "review"},
        "harness_risk_actions": {"codex": {"package_script": "block"}},
        "security_level": "balanced",
        "protection_posture": "balanced",
        "protection_posture_explicit": false,
        "managed_locked_settings": ["mode"],
    })
    .as_object()
    .expect("object")
    .clone()
}

/// The same fields plus the ones the approval hash binds.
fn hash_config(config: &Map<String, Value>) -> Map<String, Value> {
    let mut hash_config = config.clone();
    hash_config.insert("managed_policy_hash".to_owned(), json!("sha256:abc"));
    hash_config.insert("managed_policy_status".to_owned(), json!("enforced"));
    hash_config.insert("sandbox_analysis".to_owned(), json!("audit"));
    hash_config
}

fn view(config: Map<String, Value>) -> HarnessView {
    let hash_config = hash_config(&config);
    HarnessView {
        mode: config
            .get("mode")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        config,
        hash_config,
        layers: Vec::new(),
        receipt_redaction_level: None,
    }
}

fn artifact() -> GuardArtifact {
    let intent = parse_package_intent("npm install left-pad", None, None, None, None)
        .expect("the command carries an intent");
    build_package_request_artifact("codex", &intent, "/home/dev/.mcp.json", "project")
}

#[test]
fn the_bound_view_hydrates_the_policy_the_proxy_sends() {
    let policy = config_policy(&view(config()), &artifact()).expect("the view is readable");

    assert_eq!(
        policy,
        json!({
            "artifact_override": Value::Null,
            "available": true,
            // The harness's own risk action, not the global one.
            "effective_package_script_action": "block",
            "global_package_script_action": "review",
            "harness": "codex",
            "harness_override": Value::Null,
            "harness_package_script_action": "block",
            "managed_locked_settings": ["mode"],
            "managed_policy_hash": "sha256:abc",
            "managed_policy_status": "enforced",
            "mode": "enforce",
            "publisher_override": Value::Null,
            "resolved_override": Value::Null,
            "security_level": "balanced",
        })
    );
}

#[test]
fn a_view_binding_no_risk_action_resolves_the_security_levels_default() {
    let mut config = config();
    config.insert("risk_actions".to_owned(), Value::Null);
    config.insert("harness_risk_actions".to_owned(), Value::Null);
    config.insert("security_level".to_owned(), json!("strict"));

    let policy = config_policy(&view(config), &artifact()).expect("the view is readable");

    assert_eq!(
        policy.get("effective_package_script_action"),
        Some(&json!("require-reapproval")),
        "the bound security level reaches the mirror"
    );
}

#[test]
fn the_narrowest_override_naming_the_artifact_is_the_resolved_one() {
    let mut artifact = artifact();
    artifact.publisher = Some("npm".to_owned());
    let mut config = config();
    config.insert("harness_actions".to_owned(), json!({"codex": "warn"}));

    let harness_only = config_policy(&view(config.clone()), &artifact).expect("readable");
    assert_eq!(harness_only.get("resolved_override"), Some(&json!("warn")));

    config.insert("publisher_actions".to_owned(), json!({"npm": "review"}));
    let publisher = config_policy(&view(config.clone()), &artifact).expect("readable");
    assert_eq!(
        publisher.get("resolved_override"),
        Some(&json!("review")),
        "a publisher override is narrower than the harness's"
    );

    let mut named_actions = Map::new();
    named_actions.insert(artifact.artifact_id.clone(), json!("block"));
    config.insert("artifact_actions".to_owned(), Value::Object(named_actions));
    let named = config_policy(&view(config), &artifact).expect("readable");
    assert_eq!(
        named.get("resolved_override"),
        Some(&json!("block")),
        "an override naming the artifact is narrower still"
    );
    assert_eq!(named.get("artifact_override"), Some(&json!("block")));
    assert_eq!(named.get("publisher_override"), Some(&json!("review")));
}

#[test]
fn the_sandbox_analysis_the_approval_hash_binds_is_read_from_the_view() {
    assert_eq!(
        sandbox_analysis(&view(config())).expect("bound"),
        "audit".to_owned()
    );
}

#[test]
fn a_view_this_cannot_read_defers_rather_than_reading_a_default() {
    // Every one of these reads permissively if it is defaulted: an unlocked
    // setting, an absent managed policy, no risk action bound at all.
    for key in [
        "mode",
        "security_level",
        "protection_posture",
        "protection_posture_explicit",
        "managed_locked_settings",
        "risk_actions",
        "harness_risk_actions",
        "artifact_actions",
        "publisher_actions",
        "harness_actions",
    ] {
        let mut config = config();
        config.remove(key);
        assert_eq!(
            config_policy(&view(config), &artifact()).err(),
            Some(CONFIG_INVALID),
            "{key} is not the view this reads"
        );
    }

    for key in ["managed_policy_hash", "managed_policy_status"] {
        let config = config();
        let mut bound = view(config);
        bound.hash_config.remove(key);
        assert_eq!(
            config_policy(&bound, &artifact()).err(),
            Some(CONFIG_INVALID),
            "{key} is not the view this reads"
        );
    }

    let mut bound = view(config());
    bound.hash_config.remove("sandbox_analysis");
    assert_eq!(sandbox_analysis(&bound).err(), Some(CONFIG_INVALID));
}

#[test]
fn an_override_map_this_cannot_read_defers_rather_than_resolving_no_override() {
    // Each of these reads as "nothing overrides this artifact" if it is taken
    // for an absent map, which is the permissive answer: a bound `block` would
    // leave the composed action untouched.
    for key in ["artifact_actions", "publisher_actions", "harness_actions"] {
        for bound in [json!("block"), json!(["block"]), json!({"codex": 7})] {
            let mut config = config();
            config.insert((*key).to_owned(), bound.clone());
            assert_eq!(
                config_policy(&view(config), &artifact()).err(),
                Some(CONFIG_INVALID),
                "{key} bound as {bound} is not the view this reads"
            );
        }
    }
}

#[test]
fn a_risk_action_that_is_not_an_action_defers() {
    let mut risk = config();
    risk.insert("risk_actions".to_owned(), json!({"package_script": 7}));
    assert_eq!(
        config_policy(&view(risk), &artifact()).err(),
        Some(CONFIG_INVALID)
    );

    let mut harness = config();
    harness.insert("harness_risk_actions".to_owned(), json!({"codex": "block"}));
    assert_eq!(
        config_policy(&view(harness), &artifact()).err(),
        Some(CONFIG_INVALID),
        "a harness maps to its risk classes, not to one action"
    );
}
