//! Finite synthetic inputs and declared expectations for native policy tests.
//! This module never calls the native policy evaluator to construct an answer.

use guard_policy_snapshot::canonical_json_bytes;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub(super) const ACTIONS: [&str; 6] = [
    "allow",
    "warn",
    "review",
    "require-reapproval",
    "sandbox-required",
    "block",
];
pub(super) const REAPPROVAL: &str = "require-reapproval";
const RISKS: [&str; 14] = [
    "cloud_advisory",
    "credential_exfiltration",
    "data_flow_exfiltration",
    "destructive_shell",
    "encoded_execution",
    "encoded_exfiltration",
    "guard_bypass",
    "local_secret_read",
    "malicious_skill",
    "mcp_dangerous_tool",
    "network_egress",
    "package_script",
    "persistence",
    "prompt_injection",
];
pub(super) type Settings = Vec<(String, Value)>;

pub(super) fn sources() -> Vec<Value> {
    let fixture: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/sensitive-read-sources.json"
    ))
    .unwrap();
    let mut first = BTreeMap::new();
    for source in fixture["cases"].as_array().unwrap() {
        first
            .entry(source["harness"].as_str().unwrap())
            .or_insert(source.clone());
    }
    assert_eq!(first.len(), 4);
    first.into_values().collect()
}

pub(super) fn base(level: &str, posture: &str, explicit: bool) -> Value {
    let preset = if explicit && posture != "watch" {
        posture
    } else {
        match level {
            "gentle" => "relaxed",
            "custom" => "balanced",
            other => other,
        }
    };
    let r = REAPPROVAL;
    let values = match preset {
        "balanced" => [
            "warn", r, r, r, r, r, "block", r, r, r, "warn", "warn", r, r,
        ],
        "relaxed" => [
            "allow", "warn", "warn", "warn", "warn", "warn", "warn", "warn", "warn", "warn",
            "allow", "warn", "warn", "warn",
        ],
        "strict" => [
            r, r, "block", r, r, "block", "block", r, "block", "block", r, r, "block", "block",
        ],
        "paranoid" => ["block"; 14],
        "protected" => [
            "allow", r, r, r, r, "block", "block", r, r, r, "allow", r, r, r,
        ],
        "extra_careful" => [r, r, r, r, r, "block", "block", r, r, r, r, r, r, r],
        _ => panic!("undeclared fixture preset"),
    };
    let risks: Map<String, Value> = RISKS
        .into_iter()
        .zip(values)
        .map(|(key, value)| (key.to_owned(), json!(value)))
        .collect();
    json!({
        "artifact_actions": {}, "changed_hash_action": REAPPROVAL,
        "default_action": "allow", "harness_actions": {}, "harness_risk_actions": {},
        "new_network_domain_action": "warn", "protection_posture": posture,
        "publisher_actions": {}, "receipt_redaction_level": "full",
        "risk_actions": risks, "sandbox_analysis": "off", "security_level": level,
        "subprocess_action": "warn", "unknown_publisher_action": "review"
    })
}

pub(super) fn setting(selector: &str, action: &str, harness: &str, id: &str) -> Settings {
    let (key, value) = match selector {
        "default" => ("default_action", json!(action)),
        "risk" => ("risk_actions", json!({"local_secret_read": action})),
        "harness-risk" => (
            "harness_risk_actions",
            json!({harness: {"local_secret_read": action}}),
        ),
        "harness" => ("harnesses", json!({harness: action})),
        "artifact" => ("artifacts", json!({id: action})),
        "publisher" => ("publishers", json!({"synthetic-publisher": action})),
        _ => panic!("undeclared fixture selector"),
    };
    vec![(key.to_owned(), value)]
}

pub(super) fn put(policy: &mut Value, settings: &Settings) {
    for (key, value) in settings {
        let field = match key.as_str() {
            "harnesses" => "harness_actions",
            "publishers" => "publisher_actions",
            "artifacts" => "artifact_actions",
            "risk_actions" => {
                policy["risk_actions"]
                    .as_object_mut()
                    .unwrap()
                    .extend(value.as_object().unwrap().clone());
                continue;
            }
            "harness_risk_actions"
            | "default_action"
            | "unknown_publisher_action"
            | "changed_hash_action"
            | "new_network_domain_action"
            | "subprocess_action" => key,
            _ => panic!("undeclared fixture setting"),
        };
        policy[field] = value.clone();
    }
}

pub(super) fn managed(settings: &Settings, mode: &str) -> Value {
    if settings.is_empty() {
        return Value::Null;
    }
    let mut policy = base("custom", "protected", false);
    for key in [
        "default_action",
        "unknown_publisher_action",
        "changed_hash_action",
        "new_network_domain_action",
        "subprocess_action",
    ] {
        policy[key] = json!("allow");
    }
    policy["receipt_redaction_level"] = json!("none");
    policy["risk_actions"] = json!(RISKS
        .into_iter()
        .chain(["execution", "policy_bypass", "supply_chain"])
        .map(|key| (key.to_owned(), json!("allow")))
        .collect::<Map<String, Value>>());
    put(&mut policy, settings);
    let payload: Map<String, Value> = settings.iter().cloned().collect();
    let locked: Vec<&str> = settings.iter().map(|(key, _)| key.as_str()).collect();
    let root = json!({
        "schemaVersion": "hol-guard-mdm-policy.v1", "settings": payload, "lockedSettings": locked
    });
    json!({
        "schema": "guard-native-managed-config.v1",
        "source_digest": digest(&root),
        "mode": mode, "effective_policy": policy,
        "default_action_present": settings.iter().any(|(key, _)| key == "default_action")
    })
}

pub(super) fn digest(value: &Value) -> String {
    hex::encode(Sha256::digest(canonical_json_bytes(value).unwrap()))
}

fn decision(action: &str) -> &str {
    match action {
        "allow" => "allow",
        "warn" => "warn",
        "block" => "block",
        _ => "ask",
    }
}

pub(super) fn expected(harness: &str, mode: &str, evaluated: &str, observe: &str) -> Value {
    let mut result = json!({
        "evaluatedPolicyAction": evaluated, "evaluatedDecision": decision(evaluated)
    });
    if mode == "observe" {
        let rendered = match harness {
            "claude-code" => json!({
                "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"}
            }),
            "cline" | "cursor" => json!({"policy_action": observe}),
            _ => json!({}),
        };
        result["finalPolicyAction"] = json!(observe);
        result["finalDecision"] = json!(decision(observe));
        result["observedPolicyAction"] = if matches!(evaluated, "allow" | "warn") {
            Value::Null
        } else {
            json!(evaluated)
        };
        result["rendererExitCode"] = json!(0);
        result["renderedDecision"] = rendered;
    }
    result
}

pub(super) fn source_case(
    source: &Value,
    name: &str,
    mode: &str,
    policy: Value,
    answer: Value,
) -> Value {
    let harness = source["harness"].as_str().unwrap();
    json!({
        "name": format!("{harness}-{mode}-{name}"), "harness": harness,
        "source": source["source"], "payload": source["payload"],
        "artifactId": source["artifactId"], "mode": mode,
        "effectivePolicy": policy, "expected": answer
    })
}
