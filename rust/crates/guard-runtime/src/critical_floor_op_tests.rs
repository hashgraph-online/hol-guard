//! Replay the actual Python owner before deleting its request-path authority.

use guard_contracts::RequestContextRequestV1;
use serde_json::{json, Value};

fn wire(script: &str) -> Value {
    let root = std::env::temp_dir().canonicalize().unwrap();
    #[cfg(unix)]
    let owner = Some(nix::unistd::geteuid().as_raw());
    #[cfg(not(unix))]
    let owner: Option<u32> = None;
    json!({"schema":"guard-request-context-request.v1","request_id":"synthetic-critical-floor","guard_home":root,"source":"direct_command","budget_ms":9000,"owner_uid":owner,"action":{"kind":"critical_floor","body":{"script":script,"cwd":root.join("workspace"),"home_dir":root.join("home")}}})
}

fn evaluate(wire: Value) -> Value {
    let request: RequestContextRequestV1 = serde_json::from_value(wire).unwrap();
    let bytes = crate::request_context_op::evaluate_request_context_request(&request).unwrap();
    let response: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(response["request_id"], request.request_id);
    assert_eq!(
        response["request_sha256"],
        crate::request_context_op::request_digest(&request).unwrap()
    );
    response
}

#[test]
fn critical_floors_match_recorded_python() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/critical-floor-python.v1.json"
    ))
    .unwrap();
    let mut failures = Vec::new();
    for case in fixture["cases"].as_array().unwrap() {
        let response = evaluate(wire(case["command"].as_str().unwrap()));
        if response["status"] != "ok" || response["payload"]["action"] != case["action"] {
            failures.push(format!(
                "{}: {} vs {}",
                case["command"], response, case["action"]
            ));
        }
    }
    for command in fixture["near_misses"].as_array().unwrap() {
        let response = evaluate(wire(command.as_str().unwrap()));
        if response["status"] != "ok" || response["payload"]["action"] == "block" {
            failures.push(format!("near miss {command}: {response}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} baseline differences: {:#?}",
        failures.len(),
        failures
    );
}

#[test]
fn critical_floor_admission_and_no_authorization_override() {
    for script in ["", "\0", &"x".repeat(guard_command::MAX_COMMAND_BYTES + 1)] {
        assert_eq!(
            evaluate(wire(script))["code"],
            "native_request_context_critical_floor_script_invalid"
        );
    }
    let mut invalid = wire("hol-guard status");
    invalid["action"]["body"]["cwd"] = json!("relative");
    assert_eq!(
        evaluate(invalid)["code"],
        "native_request_context_critical_floor_path_invalid"
    );
    for field in [
        "authorization",
        "explicitly_allowed_github_capabilities",
        "action",
    ] {
        let mut invalid = wire("hol-guard uninstall");
        invalid["action"]["body"][field] = json!(true);
        assert!(serde_json::from_value::<RequestContextRequestV1>(invalid).is_err());
    }
}
