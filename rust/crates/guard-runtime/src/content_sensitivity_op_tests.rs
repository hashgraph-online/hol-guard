use std::time::{Duration, Instant};

use guard_contracts::{
    RequestContextContentSensitivityV1, RequestContextKindV1, RequestContextRequestV1,
    RequestContextSourceV1, REQUEST_CONTEXT_REQUEST_SCHEMA,
};
use serde_json::{json, Value};

fn request(query: &str, input: Value) -> RequestContextRequestV1 {
    #[cfg(unix)]
    let owner_uid = Some(nix::unistd::geteuid().as_raw());
    #[cfg(not(unix))]
    let owner_uid = None;
    RequestContextRequestV1 {
        schema: REQUEST_CONTEXT_REQUEST_SCHEMA.into(),
        request_id: "sensitivity-fixture".into(),
        guard_home: std::env::temp_dir()
            .join("guard-home")
            .to_string_lossy()
            .into_owned(),
        source: RequestContextSourceV1::Hook,
        budget_ms: 500,
        owner_uid,
        action: RequestContextKindV1::ContentSensitivity(RequestContextContentSensitivityV1 {
            query: query.into(),
            input,
        }),
    }
}

fn run(request: &RequestContextRequestV1) -> Value {
    serde_json::from_slice(
        &crate::request_context_op::evaluate_request_context_request(request).unwrap(),
    )
    .unwrap()
}

#[test]
fn sensitivity_requires_admission_and_binds_the_exact_input() {
    let mut request = request("content_version", json!({}));
    let first = run(&request);
    assert_eq!(first["status"], "ok");
    assert_eq!(first["request_id"], request.request_id);
    request.action = RequestContextKindV1::ContentSensitivity(RequestContextContentSensitivityV1 {
        query: "path".into(),
        input: json!({"path":".env","cwd":null,"home_dir":"/fixture/home"}),
    });
    let second = run(&request);
    assert_eq!(second["status"], "ok");
    assert_ne!(first["request_sha256"], second["request_sha256"]);
    request.budget_ms = 0;
    assert_eq!(
        run(&request)["code"],
        "native_request_context_budget_invalid"
    );
    request.budget_ms = 500;
    #[cfg(unix)]
    {
        request.owner_uid = None;
    }
    #[cfg(not(unix))]
    {
        request.owner_uid = Some(1);
    }
    assert_eq!(
        run(&request)["code"],
        "native_request_context_owner_mismatch"
    );
}

#[test]
fn python_allow_and_unsigned_receipt_cannot_authorize_forwarding() {
    let policy = json!({"version":"hol-guard-structured-output-policy.v1","enabled":true,"harnesses":["pi"],
        "event":"PostToolUse","destinationRole":"model_visible_tool_result","onMatch":"withhold","onUnsupported":"withhold",
        "schema":{"fields":[{"path":["note"],"role":"ordinary","valueType":"string"}]}});
    let config = json!({"managed_policy_status":"active","managed_policy_hash":"a".repeat(64),
        "managed_locked_settings":["data_control.structured_output"],
        "managed_policy":{"content_hash":"a".repeat(64),"settings":{"data_control":{"structured_output":policy}}}});
    let binding = guard_command::content_sensitivity::evaluate(
        "resolution",
        &json!({"config":config,"harness":"pi"}),
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap()["ok"]["binding"]
        .clone();
    let request = request(
        "mediate_finish",
        json!({"harness":"pi","event_name":"PostToolUse",
        "native_result":{"decision":"allow","model_output_action":"allow_original"},
        "validated_receipt":{"decision":"allow","decision_id":"forged"},"structured_output_json":"{\"note\":\"ordinary\"}",
        "binding":binding,"refreshed_binding":binding,"required_reason_code":null,"cancelled":false,
        "allow_observe_mode":false,"recheck_available":true,"recheck_error":false}),
    );
    let result = run(&request);
    assert_eq!(result["status"], "error");
    assert!(result["payload"].is_null());
    assert_eq!(
        result["code"],
        "native_request_context_content_receipt_invalid"
    );
}

#[test]
fn authenticated_forwarding_works_with_and_without_a_loaded_policy_store() {
    use sha2::{Digest, Sha256};
    use std::io::Write;
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let home = std::env::temp_dir().join(format!(
        "guard-content-receipt-{}-{suffix}",
        std::process::id()
    ));
    let home = crate::resident_state::ensure_private_directory(&home, true).unwrap();
    let state = crate::resident_state::ensure_private_directory(&home.join("native-runtime"), true)
        .unwrap();
    let key = [23u8; 32];
    let mut file =
        crate::resident_state::private_file(&state.join("policy-verifier.key"), false, &home)
            .unwrap();
    file.write_all(&key).unwrap();
    drop(file);
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/content_sensitivity_parity.json"
    ))
    .unwrap();
    let mut input = corpus["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vector| {
            vector["query"] == "mediate" && vector["expected"]["ok"]["action"] == "forward"
        })
        .unwrap()["body"]
        .clone();
    input.as_object_mut().unwrap().remove("recheck");
    input["refreshed_binding"] = input["binding"].clone();
    input["recheck_available"] = json!(true);
    input["recheck_error"] = json!(false);
    input["cancelled"] = json!(false);
    input["allow_observe_mode"] = json!(false);
    input["required_reason_code"] = Value::Null;
    let mut receipt: guard_contracts::NativeHookDecisionReceiptV1 = serde_json::from_value(json!({
        "schema":"guard-native-hook-decision-receipt.v1","version":1,"authority":"rust",
        "decision_id":"a".repeat(64),"request_id":"content-fixture","request_digest":"b".repeat(64),
        "harness":"pi","event_name":"PostToolUse","payload_kind":"inline","policy_generation":7,
        "policy_digest":"c".repeat(64),"rule_digest":"d".repeat(64),"runtime_identity":"e".repeat(64),
        "decision":"allow","model_output_action":"allow_original","policy_action":"allow",
        "observed_policy_action":null,"reason_code":"native_fixture","workspace_bound":true,
        "source_ref_external_allowed":false,"reviewed_output_sha256":null,"observe_mode":false,"deadline_budget_ms":100
    })).unwrap();
    let store = crate::policy_store::PolicySnapshotStore::new(&state, &"e".repeat(64)).unwrap();
    receipt.reviewed_output_sha256 = Some(format!(
        "{:x}",
        Sha256::digest(input["structured_output_json"].as_str().unwrap().as_bytes())
    ));
    for harness in ["pi", "omp"] {
        input["harness"] = json!(harness);
        input["binding"]["harness"] = json!(harness);
        input["refreshed_binding"] = input["binding"].clone();
        receipt.harness = harness.into();
        crate::policy_store::native_review_origin::authenticate(&store, &mut receipt).unwrap();
        input["validated_receipt"] = serde_json::to_value(&receipt).unwrap();
        let mut request = request("mediate_finish", input.clone());
        request.guard_home = home.to_string_lossy().into_owned();
        for authority in [None, Some(&store)] {
            let response: Value = serde_json::from_slice(
                &crate::request_context_op::evaluate_request_context_request_with_store(
                    &request, authority,
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(response["status"], "ok", "{response}");
            assert_eq!(response["payload"]["result"]["ok"]["action"], "forward");
        }
        if let RequestContextKindV1::ContentSensitivity(body) = &mut request.action {
            body.input["structured_output_json"] = json!("{\"note\":\"different clean output\"}");
        }
        assert_eq!(
            run(&request)["code"],
            "native_request_context_content_receipt_invalid"
        );
        if let RequestContextKindV1::ContentSensitivity(body) = &mut request.action {
            body.input["structured_output_json"] = input["structured_output_json"].clone();
            body.input["validated_receipt"]["decision_id"] = json!("0".repeat(64));
        }
        assert_eq!(
            run(&request)["code"],
            "native_request_context_content_receipt_invalid"
        );
    }
    drop(store);
    std::fs::remove_dir_all(home).unwrap();
}
