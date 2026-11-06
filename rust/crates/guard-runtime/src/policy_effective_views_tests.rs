//! Pins the direct-lane views a publication binds.

use super::*;

fn config(overrides: Value) -> Map<String, Value> {
    let mut config = json!({
        "mode": "prompt",
        "default_action": "warn",
        "artifact_actions": {},
        "publisher_actions": {},
        "harness_actions": {},
        "risk_actions": {},
        "harness_risk_actions": {},
        "security_level": "balanced",
        "protection_posture": "protected",
        "protection_posture_explicit": false,
        "managed_locked_settings": [],
        "managed_policy_hash": null,
        "managed_policy_status": "absent",
        "sandbox_analysis": "off",
        "blocked_request_mode": "safe-alternative",
        "receipt_redaction_level": "full",
        "harness_postures": null,
    });
    let object = config.as_object_mut().unwrap();
    for (key, value) in overrides.as_object().unwrap() {
        object.insert(key.clone(), value.clone());
    }
    object.clone()
}

#[test]
fn blocked_request_mode_binds_only_when_every_config_agrees() {
    let ask = config(json!({"blocked_request_mode": "ask"}));
    let safe = config(json!({}));
    let prompt = config(json!({"blocked_request_mode": "prompt"}));
    assert_eq!(
        uniform_blocked_request_mode(&[ask.clone(), ask.clone()]),
        json!("ask")
    );
    assert_eq!(
        uniform_blocked_request_mode(&[safe.clone()]),
        json!("safe-alternative")
    );
    assert_eq!(uniform_blocked_request_mode(&[ask, safe]), Value::Null);
    assert_eq!(uniform_blocked_request_mode(&[prompt]), Value::Null);
    assert_eq!(uniform_blocked_request_mode(&[]), Value::Null);
}

#[test]
fn a_harness_without_an_override_reads_the_loaded_config() {
    let view = harness_view(&config(json!({})), "codex").unwrap();
    assert_eq!(view["config"]["mode"], json!("prompt"));
    assert_eq!(view["config"]["protection_posture"], json!("protected"));
    assert_eq!(view["config"]["harness_postures"], json!({}));
    assert_eq!(
        view["hash_config"]["managed_policy_status"],
        json!("absent")
    );
    assert_eq!(view["hash_config"]["managed_policy_hash"], Value::Null);
    assert_eq!(view["hash_config"]["sandbox_analysis"], json!("off"));
    assert!(view["config"].get("managed_policy_status").is_none());
    assert!(view["hash_config"].get("harness_postures").is_none());
}

#[test]
fn an_override_resolves_the_harness_posture_mode_and_level() {
    let base = config(json!({"harness_postures": {"codex": "extra_careful", "cursor": "watch"}}));
    let codex = harness_view(&base, "codex").unwrap();
    assert_eq!(
        codex["config"]["protection_posture"],
        json!("extra_careful")
    );
    assert_eq!(codex["config"]["protection_posture_explicit"], json!(true));
    assert_eq!(codex["config"]["mode"], json!("enforce"));
    assert_eq!(codex["config"]["security_level"], json!("strict"));
    assert_eq!(
        codex["config"]["harness_postures"],
        json!({"codex": "extra_careful"})
    );
    assert_eq!(codex["hash_config"]["security_level"], json!("strict"));
    let cursor = harness_view(&base, "cursor").unwrap();
    assert_eq!(cursor["config"]["mode"], json!("observe"));
    assert_eq!(cursor["config"]["security_level"], json!("balanced"));
    // Another harness's override never reaches this harness's view.
    let cline = harness_view(&base, "cline").unwrap();
    assert_eq!(cline["config"]["harness_postures"], json!({}));
    assert_eq!(cline["config"]["protection_posture_explicit"], json!(false));
}

#[test]
fn a_weaker_override_never_weakens_a_stricter_baseline() {
    let base = config(json!({
        "protection_posture": "extra_careful",
        "harness_postures": {"codex": "protected"},
    }));
    let codex = harness_view(&base, "codex").unwrap();
    assert_eq!(
        codex["config"]["protection_posture"],
        json!("extra_careful")
    );
    assert_eq!(
        codex["config"]["harness_postures"],
        json!({"codex": "protected"})
    );
}

#[test]
fn a_malformed_override_overrides_nothing() {
    let base = config(json!({"harness_postures": {"codex": 3}}));
    assert_eq!(
        harness_view(&base, "codex"),
        harness_view(&config(json!({})), "codex")
    );
}

#[test]
fn harnesses_bind_only_where_every_config_agrees() {
    let home = config(json!({}));
    let workspace = config(json!({"harness_postures": {"codex": "watch"}}));
    let views = uniform_harness_views(&[home.clone(), workspace]);
    assert!(views.get("codex").is_none());
    let mut bound: Vec<&str> = views.keys().map(String::as_str).collect();
    bound.sort_unstable();
    assert_eq!(bound, ["cline", "copilot", "cursor", "hermes", "opencode"]);
    assert_eq!(views["cline"][REDACTION_LEVEL_KEY], json!("full"));
    assert!(uniform_harness_views(&[]).is_empty());
}

#[test]
fn the_redaction_level_rides_along_only_when_uniform() {
    let full = config(json!({}));
    let partial = config(json!({"receipt_redaction_level": "partial"}));
    let views = uniform_harness_views(&[full, partial]);
    assert!(views["codex"].get(REDACTION_LEVEL_KEY).is_none());
    let odd = config(json!({"receipt_redaction_level": "everything"}));
    assert!(uniform_harness_views(&[odd])["codex"]
        .get(REDACTION_LEVEL_KEY)
        .is_none());
}

#[test]
fn a_view_the_resident_would_read_differently_is_not_bound() {
    let float = config(json!({"risk_actions": {"x": 1.5}}));
    assert_eq!(harness_view(&float, "codex"), None);
    let unsafe_integer = config(json!({"risk_actions": {"x": 9_007_199_254_740_992_i64}}));
    assert_eq!(harness_view(&unsafe_integer, "codex"), None);
    let mut missing = config(json!({}));
    missing.remove("managed_policy_status");
    assert_eq!(harness_view(&missing, "codex"), None);
    let mode = config(json!({"mode": 1}));
    assert_eq!(harness_view(&mode, "codex"), None);
    let wide: Map<String, Value> = (0..=MAX_JSON_COLLECTION_ITEMS)
        .map(|index| (format!("k{index}"), json!("allow")))
        .collect();
    let too_wide = config(json!({"artifact_actions": wide}));
    assert_eq!(harness_view(&too_wide, "codex"), None);
}

#[test]
fn the_size_bound_counts_the_daemon_encoding() {
    assert_eq!(
        encoded_len(&json!({"a": [1, 2], "b": "é\n"})),
        r#"{"a": [1, 2], "b": "é\n"}"#.len()
    );
    assert_eq!(encoded_len(&json!({})), 2);
    assert_eq!(encoded_len(&json!([])), 2);
    let big = "x".repeat(MAX_VIEW_BYTES);
    assert_eq!(
        harness_view(&config(json!({"default_action": big})), "codex"),
        None
    );
}

#[test]
fn publish_returns_the_composed_policy_and_views() {
    let request = json!({
        "schema": super::super::SCHEMA,
        "op": "publish",
        "guard_config": true,
        "configs": [config(json!({"blocked_request_mode": "ask"}))],
        "observed": {"mcp_tool_actions": {}},
    });
    let bytes = super::super::evaluate(request.to_string().as_bytes()).unwrap();
    let response: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(response["ok"], json!(true));
    assert_eq!(response["policy"]["protection_posture"], json!("protected"));
    assert_eq!(response["views"]["blocked_request_mode"], json!("ask"));
    assert!(response["views"]["mcp_relay_harnesses"]["codex"].is_object());
    for refused in [
        json!({"schema": super::super::SCHEMA, "op": "publish", "guard_config": false, "configs": [config(json!({}))]}),
        json!({"schema": super::super::SCHEMA, "op": "publish", "guard_config": true, "configs": []}),
    ] {
        let bytes = super::super::evaluate(refused.to_string().as_bytes()).unwrap();
        let response: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(response["ok"], json!(false));
    }
}
