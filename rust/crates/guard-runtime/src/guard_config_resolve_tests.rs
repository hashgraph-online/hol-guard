use super::*;

fn facts(level: &str, posture: &str, explicit: bool) -> RiskActionConfigV1 {
    RiskActionConfigV1 {
        security_level: level.to_owned(),
        protection_posture: posture.to_owned(),
        protection_posture_explicit: explicit,
        ..Default::default()
    }
}

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        other => panic!("expected an object, got {other}"),
    }
}

fn managed(settings: Value, locked: &[&str]) -> ManagedInput {
    serde_json::from_value(json!({"settings": settings, "locked_settings": locked})).unwrap()
}

fn loaded() -> Map<String, Value> {
    object(json!({
        "mode": "enforce",
        "security_level": "balanced",
        "protection_posture": "protected",
        "protection_posture_explicit": true,
        "managed_locked_settings": [],
        "default_action": "warn",
        "unknown_publisher_action": "review",
        "changed_hash_action": "require-reapproval",
        "new_network_domain_action": "warn",
        "subprocess_action": "warn",
        "risk_actions": {},
        "harness_risk_actions": {},
        "telemetry": false,
        "sync": false,
        "receipt_redaction_level": "full",
    }))
}

fn run(request: &Value) -> Value {
    let bytes = run_command(request.to_string().as_bytes()).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[test]
fn every_security_level_resolves_every_risk_class() {
    for level in [
        "relaxed", "gentle", "balanced", "strict", "paranoid", "custom",
    ] {
        let resolved = risk_actions(&facts(level, "protected", false), None);
        assert_eq!(resolved.len(), VALID_RISK_ACTION_KEYS.len(), "{level}");
    }
}

#[test]
fn preset_sentinels_match_the_documented_tables() {
    let cases = [
        ("gentle", "guard_bypass", "warn"),
        ("gentle", "network_egress", "allow"),
        ("balanced", "network_egress", "warn"),
        ("balanced", "guard_bypass", "block"),
        ("strict", "data_flow_exfiltration", "block"),
        ("strict", "network_egress", "require-reapproval"),
        ("paranoid", "local_secret_read", "block"),
        ("relaxed", "credential_exfiltration", "warn"),
    ];
    for (level, class, expected) in cases {
        let resolved = risk_actions(&facts(level, "protected", false), Some("codex"));
        assert_eq!(resolved[class], expected, "{level} {class}");
    }
}

#[test]
fn an_explicit_posture_replaces_the_level_defaults_unless_the_level_is_locked() {
    let explicit = facts("balanced", "protected", true);
    assert_eq!(risk_actions(&explicit, None)["network_egress"], "allow");
    assert_eq!(
        risk_actions(&explicit, None)["package_script"],
        "require-reapproval"
    );

    let mut locked = explicit.clone();
    locked.managed_locked_settings = vec!["security_level".to_owned()];
    assert_eq!(risk_actions(&locked, None)["network_egress"], "warn");
}

#[test]
fn configured_actions_win_and_a_harness_override_wins_over_them() {
    let mut config = facts("balanced", "protected", false);
    config
        .risk_actions
        .insert("network_egress".to_owned(), "block".to_owned());
    config.harness_risk_actions.insert(
        "codex".to_owned(),
        [("network_egress".to_owned(), "allow".to_owned())]
            .into_iter()
            .collect(),
    );
    assert_eq!(risk_actions(&config, None)["network_egress"], "block");
    assert_eq!(
        risk_actions(&config, Some("codex"))["network_egress"],
        "allow"
    );
    assert_eq!(
        risk_actions(&config, Some("cursor"))["network_egress"],
        "block"
    );
}

#[test]
fn a_harness_extra_careful_override_only_strengthens() {
    let mut config = facts("relaxed", "protected", false);
    config
        .harness_postures
        .insert("codex".to_owned(), "extra_careful".to_owned());
    let codex = risk_actions(&config, Some("codex"));
    assert_eq!(codex["network_egress"], "require-reapproval");
    assert_eq!(codex["local_secret_read"], "require-reapproval");
    assert_eq!(risk_actions(&config, None)["network_egress"], "allow");
}

#[test]
fn a_synced_payload_never_switches_watch_off() {
    let mut config = loaded();
    config.insert("mode".to_owned(), json!("observe"));
    let overlaid = overlay(&config, Some(&object(json!({"mode": "enforce"}))), None);
    assert_eq!(overlaid["mode"], "observe");

    let overlaid = overlay(&loaded(), Some(&object(json!({"mode": "prompt"}))), None);
    assert_eq!(overlaid["mode"], "prompt");
    let overlaid = overlay(&loaded(), Some(&object(json!({"mode": "loud"}))), None);
    assert_eq!(overlaid["mode"], "enforce");
}

#[test]
fn synced_actions_keep_the_current_value_when_absent_and_fail_closed_when_unknown() {
    let payload = object(json!({
        "defaultAction": "block",
        "unknownPublisherAction": null,
        "changedHashAction": "future-action",
        "subprocessAction": "ask",
        "syncEnabled": "yes",
        "receiptRedactionLevel": "partial",
    }));
    let overlaid = overlay(&loaded(), Some(&payload), None);
    assert_eq!(overlaid["default_action"], "block");
    assert_eq!(overlaid["unknown_publisher_action"], "review");
    assert_eq!(overlaid["changed_hash_action"], "require-reapproval");
    assert_eq!(overlaid["new_network_domain_action"], "warn");
    assert_eq!(overlaid["subprocess_action"], "review");
    assert_eq!(overlaid["sync"], false);
    assert_eq!(overlaid["receipt_redaction_level"], "partial");

    let payload = object(json!({"syncEnabled": true, "receiptRedactionLevel": "loud"}));
    let overlaid = overlay(&loaded(), Some(&payload), None);
    assert_eq!(overlaid["sync"], true);
    assert_eq!(overlaid["receipt_redaction_level"], "full");
}

#[test]
fn a_mode_lock_keeps_an_explicit_posture() {
    let mut config = loaded();
    config.insert("managed_locked_settings".to_owned(), json!(["mode"]));
    let policy = managed(json!({"mode": "enforce"}), &["mode"]);
    let overlaid = overlay(&config, None, Some(&policy));
    assert_eq!(overlaid["protection_posture"], "protected");
    assert_eq!(overlaid["protection_posture_explicit"], true);
    assert_eq!(overlaid["mode"], "enforce");
}

#[test]
fn a_security_level_lock_derives_the_posture_from_the_level() {
    let mut config = loaded();
    config.insert(
        "managed_locked_settings".to_owned(),
        json!(["security_level"]),
    );
    let policy = managed(json!({"security_level": "strict"}), &["security_level"]);
    let overlaid = overlay(&config, None, Some(&policy));
    assert_eq!(overlaid["security_level"], "strict");
    assert_eq!(overlaid["protection_posture"], "extra_careful");
    assert_eq!(overlaid["protection_posture_explicit"], false);
}

#[test]
fn a_managed_policy_only_makes_the_synced_payload_stricter() {
    let policy = managed(
        json!({"default_action": "require-reapproval", "risk_actions": {"network_egress": "block"}}),
        &[],
    );
    let payload = object(json!({"defaultAction": "allow"}));
    let overlaid = overlay(&loaded(), Some(&payload), Some(&policy));
    assert_eq!(overlaid["default_action"], "require-reapproval");
    assert_eq!(overlaid["risk_actions"], json!({"network_egress": "block"}));
}

#[test]
fn invalid_composed_values_fall_back_or_fail_closed() {
    let mut config = loaded();
    config.insert("protection_posture_explicit".to_owned(), json!(false));
    for invalid in [
        json!(null),
        json!(7),
        json!(false),
        json!({}),
        json!({"action": null}),
        json!({"default_action": 7}),
    ] {
        let policy = managed(json!({"harnesses": {}}), &[]);
        config.insert(
            "risk_actions".to_owned(),
            json!({"network_egress": invalid.clone(), "not_a_class": "block"}),
        );
        config.insert("receipt_redaction_level".to_owned(), json!("loud"));
        config.insert("telemetry".to_owned(), json!("yes"));
        let overlaid = overlay(&config, None, Some(&policy));
        assert_eq!(
            overlaid["risk_actions"],
            json!({"network_egress": "require-reapproval"}),
            "{invalid}"
        );
        assert_eq!(overlaid["receipt_redaction_level"], "full");
        assert_eq!(overlaid["telemetry"], false);
    }
}

#[test]
fn the_derived_posture_follows_mode_and_level() {
    let cases = [
        ("observe", "balanced", "watch"),
        ("prompt", "balanced", "protected"),
        ("enforce", "strict", "extra_careful"),
        ("enforce", "paranoid", "extra_careful"),
        ("prompt", "gentle", "protected"),
    ];
    for (mode, level, expected) in cases {
        assert_eq!(
            base::derive_posture(Some(&json!(mode)), level),
            expected,
            "{mode} {level}"
        );
    }
}

#[test]
fn run_command_answers_both_ops() {
    let answer = run(&json!({
        "schema": SCHEMA,
        "op": "risk_actions",
        "facts": facts("balanced", "protected", false),
        "harness": null,
    }));
    assert_eq!(answer["ok"], true);
    assert_eq!(answer["result"]["risk_actions"]["guard_bypass"], "block");

    let answer = run(&json!({
        "schema": SCHEMA,
        "op": "overlay",
        "config": loaded(),
        "payload": {"defaultAction": "block"},
        "managed": null,
    }));
    assert_eq!(answer["ok"], true);
    assert_eq!(answer["result"]["config"]["default_action"], "block");
}

#[test]
fn run_command_rejects_unknown_ops_fields_and_schemas() {
    let answer = run(&json!({"schema": SCHEMA, "op": "nope"}));
    assert_eq!(answer, json!({"ok": false, "error": INVALID}));
    let answer = run(&json!({"schema": SCHEMA, "op": "overlay"}));
    assert_eq!(answer, json!({"ok": false, "error": INVALID}));
    for request in [
        json!({"schema": "guard-config-resolve.v0", "op": "overlay", "config": {}}),
        json!({"schema": SCHEMA, "op": "overlay", "config": {}, "extra": 1}),
    ] {
        assert!(run_command(request.to_string().as_bytes()).is_err());
    }
}
