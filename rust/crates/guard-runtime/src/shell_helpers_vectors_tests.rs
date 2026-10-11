use super::*;
use serde_json::{json, Value};

#[cfg(unix)]
#[test]
fn trusted_absolute_env_wrapper_uses_native_observations() {
    let result = guard_command::shell_helpers::evaluate(
        "normalization",
        &json!({"command":"/usr/bin/env bash -lc 'echo value'"}),
    )
    .unwrap();
    assert_eq!(result["wrapper_chain"], json!(["env", "bash"]));
    assert_eq!(result["normalized_command"], json!("echo value"));
}

#[test]
fn original_python_shell_helpers_replay() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/shell-helper-python.v1.json"
    ))
    .unwrap();
    for vector in fixture["vectors"].as_array().unwrap() {
        let command = &vector["command"];
        for action in [
            "segments",
            "pipe_segments",
            "redirects",
            "pipes",
            "heredocs",
            "substitutions",
            "expanded_substitutions",
            "masked_bodies",
            "masked_complete",
            "normalization",
            "trace",
        ] {
            let mut input = json!({"command":command});
            if action.starts_with("masked_") {
                input["heredocs"] = vector["expected"]["heredocs"].clone();
            }
            if action == "trace" {
                input["state"] = json!([null, 0, false]);
                input["index"] = json!(0);
            }
            let request = ShellHelpersRequest {
                schema: "guard-shell-helpers-request.v1".into(),
                request_id: "parity".into(),
                action: action.into(),
                input,
                timeout_ms: 10_000,
            };
            let reply: Value = serde_json::from_slice(&evaluate(&request).unwrap()).unwrap();
            assert_eq!(
                reply["result"], vector["expected"][action],
                "action={action}, command={command}"
            );
        }
    }
}

#[test]
fn malformed_and_out_of_range_spans_are_rejected() {
    for input in [
        json!({"command":"echo","heredocs":[{}]}),
        json!({"command":"echo","heredocs":[{"delimiter":"EOF","body":"","operator_start":0,"declaration_end":1,"body_start":0,"body_end":5,"end":5,"quoted":false,"strip_tabs":false}]}),
    ] {
        assert!(guard_command::shell_helpers::evaluate("masked_bodies", &input).is_err());
    }
    assert!(guard_command::shell_helpers::evaluate(
        "trace",
        &json!({"command":"echo","index":0,"state":["invalid",0,false]})
    )
    .is_err());
}
