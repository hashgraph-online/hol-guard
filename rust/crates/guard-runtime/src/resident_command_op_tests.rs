use super::evaluate_resident_bytes;
use crate::resident_protocol::ResidentOperationV1;
use serde_json::{json, Value};

fn resident(envelope: &Value) -> Result<Vec<u8>, String> {
    evaluate_resident_bytes(&serde_json::to_vec(envelope).unwrap(), None)
}

#[test]
fn resident_policy_effective_answers_with_the_command_bytes() {
    let base =
        json!({"protection_posture": "protected", "security_level": "balanced", "mode": "prompt"});
    let mut watch = base.clone();
    watch["protection_posture"] = json!("watch");
    watch["mode"] = json!("observe");
    for request in [
        json!({"schema": "guard-effective-policy.v1", "op": "compose", "configs": [watch, base.clone()]}),
        json!({"schema": "guard-effective-policy.v1", "op": "effective", "configs": [base.clone(), base]}),
    ] {
        let command = crate::policy_effective::run_command(request.to_string().as_bytes()).unwrap();
        let answer =
            resident(&json!({"operation": "policy_effective", "request": request})).unwrap();
        assert_eq!(answer, command);
    }
}

#[test]
fn resident_policy_effective_refuses_what_the_command_refuses() {
    let base =
        json!({"protection_posture": "protected", "security_level": "balanced", "mode": "prompt"});
    let unknown = json!({"schema": "guard-effective-policy.v1", "op": "compose",
        "configs": [base.clone()], "extra": 1});
    assert!(crate::policy_effective::run_command(unknown.to_string().as_bytes()).is_err());
    assert!(resident(&json!({"operation": "policy_effective", "request": unknown})).is_err());
    let wrong = json!({"schema": "other", "op": "compose", "configs": [base]});
    let command = crate::policy_effective::run_command(wrong.to_string().as_bytes()).unwrap();
    let answer = resident(&json!({"operation": "policy_effective", "request": wrong})).unwrap();
    assert_eq!(answer, command);
    let value: Value = serde_json::from_slice(&answer).unwrap();
    assert_eq!(value["ok"], json!(false));
}

#[test]
fn resident_guard_config_load_is_pinned_to_the_resident_home() {
    let named = json!({"operation": "guard_config_load", "request": {
        "schema": "guard-config-load.v1", "guard_home": "/elsewhere/home"}});
    let operation: ResidentOperationV1 = serde_json::from_value(named.clone()).unwrap();
    assert_eq!(
        super::operation_guard_home(&operation),
        Some("/elsewhere/home")
    );
    // A request with no home, or one that is not text, still binds to a home
    // the resident never holds, so it cannot load some other home's files.
    for home in [Value::Null, json!(7)] {
        let operation: ResidentOperationV1 = serde_json::from_value(json!({
            "operation": "guard_config_load",
            "request": {"schema": "guard-config-load.v1", "guard_home": home}}))
        .unwrap();
        assert_eq!(super::operation_guard_home(&operation), Some(""));
    }
    // Without a policy store there is no home to pin to, so it never loads.
    assert_eq!(
        resident(&named).unwrap_err(),
        "native_guard_config_resident_required"
    );
}

#[test]
fn resident_command_features_are_advertised() {
    let features = crate::resident_protocol::capabilities().features;
    for feature in [
        crate::policy_effective::RESIDENT_FEATURE,
        crate::guard_config_load::RESIDENT_FEATURE,
    ] {
        assert!(features.iter().any(|known| known == feature), "{feature}");
    }
}
