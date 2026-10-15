use super::{payload_of, request, request_digest};
use guard_contracts::{RequestContextBuildV1, RequestContextKindV1};
use serde_json::{json, Value};

#[test]
fn environment_secret_verdict_is_folded_into_bound_context_response() {
    let cwd = std::env::temp_dir().canonicalize().unwrap();
    for (command, opted_in, expected) in [
        ("printenv TOKEN", true, json!(true)),
        ("printenv PATH", true, json!(false)),
        ("printenv TOKEN", false, Value::Null),
    ] {
        let request = request(RequestContextKindV1::Build(RequestContextBuildV1 {
            cwd: Some(cwd.to_string_lossy().into_owned()),
            workspace: Some(cwd.to_string_lossy().into_owned()),
            script: Some(command.to_owned()),
            classify_environment_secrets: opted_in,
            ..Default::default()
        }));
        let digest = request_digest(&request).unwrap();
        let frame =
            serde_json::to_vec(&json!({"operation": "request_context_build", "request": request}))
                .unwrap();
        let response: Value = serde_json::from_slice(
            &crate::resident_ops::evaluate_resident_bytes(&frame, None).unwrap(),
        )
        .unwrap();
        assert_eq!(response["request_id"], "request-context-test");
        assert_eq!(response["request_sha256"], digest);
        assert_eq!(payload_of(&response)["environment_secret_dump"], expected);
        assert!(payload_of(&response)["shell"].is_object());
    }
}
