use std::time::{Duration, Instant};

use serde_json::{json, Value};

#[test]
fn original_python_sensitivity_and_mediation_vectors_replay() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/content_sensitivity_parity.json"
    ))
    .expect("recorded original corpus");
    let vectors = fixture["vectors"].as_array().expect("vector list");
    assert_eq!(vectors.len(), 725);
    let mut failures = Vec::new();
    for (index, vector) in vectors.iter().enumerate() {
        let query = vector["query"].as_str().expect("query");
        let result = super::evaluate(
            query,
            &vector["body"],
            Instant::now() + Duration::from_secs(2),
        );
        match result.map(|actual| host_paths(query, actual)) {
            Ok(actual) if actual == host_expected(vector) => {}
            other => failures.push(format!(
                "vector {index} query {query}: {other:?}, expected {}",
                host_expected(vector)
            )),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The path vectors were recorded with POSIX paths. Windows resolves the
/// same paths and joins them with its own separator, so a resolved `path` is
/// compared in POSIX spelling there.
fn host_paths(query: &str, mut value: Value) -> Value {
    fn posix(value: &mut Value) {
        match value {
            Value::Object(map) => {
                for (key, item) in map.iter_mut() {
                    match item {
                        Value::String(path) if key == "path" => *path = path.replace('\\', "/"),
                        _ => posix(item),
                    }
                }
            }
            Value::Array(items) => items.iter_mut().for_each(posix),
            _ => {}
        }
    }
    if cfg!(windows) && matches!(query, "path" | "path_batch") {
        posix(&mut value);
    }
    value
}

/// A few path vectors spell the requested path with backslashes. POSIX
/// recorded them as one relative file name joined to `cwd`; Windows reads the
/// same text as separators, so a drive-rooted spelling stays absolute and a
/// relative one joins `cwd` component by component. The classification
/// (family, sensitivity, reason, requested path) must still match exactly.
fn host_expected(vector: &Value) -> Value {
    let mut expected = vector["expected"].clone();
    let requested = vector["body"]["path"].as_str().unwrap_or_default();
    if !cfg!(windows) || !requested.contains('\\') || !expected["ok"]["path"].is_string() {
        return expected;
    }
    let requested = requested.replace('\\', "/");
    let drive_rooted = requested.as_bytes().get(1..3) == Some(&b":/"[..]);
    expected["ok"]["path"] = Value::String(if drive_rooted {
        requested
    } else {
        let cwd = vector["body"]["cwd"].as_str().expect("recorded cwd");
        format!("{}/{requested}", cwd.trim_end_matches('/'))
    });
    expected
}

#[test]
fn large_output_encoding_is_lossless_and_native_decoding_rejects_invalid_frames() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/content_sensitivity_wire_parity.json"
    ))
    .unwrap();
    for vector in fixture["vectors"].as_array().unwrap() {
        let decoded = super::decode_input(&vector["input"]).unwrap();
        let expected = vector["unit"]
            .as_str()
            .unwrap()
            .repeat(vector["count"].as_u64().unwrap() as usize);
        assert_eq!(decoded["text"], expected);
        assert_eq!(decoded["suppress_samples"], true);
        assert_eq!(decoded["documentation_sample_context"], false);
        // A debug build scans each multi-megabyte frame with every rule, which
        // can exceed 30 seconds on a loaded runner. The test checks lossless
        // decoding and the scan result, not the production budget.
        let outcome = super::evaluate(
            "content",
            &decoded,
            Instant::now() + Duration::from_secs(300),
        )
        .unwrap();
        assert_eq!(outcome["ok"], json!([]));
        let mut wrong_length = vector["input"].clone();
        wrong_length["decoded_bytes"] = json!(1);
        assert!(super::decode_input(&wrong_length).is_err());
        let mut truncated = vector["input"].clone();
        let encoded = truncated["packed_json_gzip_v1"].as_str().unwrap();
        truncated["packed_json_gzip_v1"] = json!(&encoded[..encoded.len() - 8]);
        assert!(super::decode_input(&truncated).is_err());
    }
    assert!(super::decode_input(
        &json!({"packed_json_gzip_v1":"", "decoded_bytes":12*1024*1024+1})
    )
    .is_err());
    assert!(
        super::decode_input(&json!({"packed_json_gzip_v1":"!invalid", "decoded_bytes":1})).is_err()
    );
}

#[test]
fn schema_order_duplicates_numeric_types_and_unknown_claims_fail_closed() {
    let deadline = Instant::now() + Duration::from_secs(2);
    assert!(super::evaluate(
        "content",
        &json!({"text":"ordinary","suppress_samples":true,
        "documentation_sample_context":false,"allow":true}),
        deadline
    )
    .is_err());
    assert!(super::evaluate("content_version", &json!({}), Instant::now()).is_err());
    let schema = json!([{"path":["id"],"role":"protected_personal","value_type":"integer","category":"employee_id"}]);
    for (text, reason) in [
        ("{\"id\":true}", "field_type_invalid"),
        ("{\"id\":1.0}", "field_type_invalid"),
        ("{\"id\":0,\"id\":1}", "invalid_or_duplicate_json"),
    ] {
        let result = super::evaluate(
            "declared",
            &json!({"schema":schema,"content":text}),
            deadline,
        )
        .unwrap();
        assert_eq!(result["ok"]["status"], "unsupported");
        assert_eq!(result["ok"]["reason_code"], reason);
    }
}

#[test]
fn batched_paths_replay_original_python_outcomes_in_order() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/content_sensitivity_parity.json"
    ))
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    for vector in fixture["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|vector| vector["query"] == "path" && vector["body"]["path"].is_string())
    {
        let body = &vector["body"];
        let actual = super::evaluate(
            "path_batch",
            &json!({
                "paths":[body["path"],body["path"]],"cwd":body["cwd"],"home_dir":body["home_dir"]
            }),
            deadline,
        )
        .unwrap();
        assert_eq!(
            host_paths("path_batch", actual)["ok"],
            json!([host_expected(vector)["ok"], host_expected(vector)["ok"]])
        );
    }
    assert!(super::evaluate(
        "path_batch",
        &json!({
            "paths":vec!["ordinary.txt";129],"cwd":null,"home_dir":null
        }),
        deadline
    )
    .is_err());
}

/// The `mediate_prepare` body the daemon used to send for the recorded
/// forwarding vector, with the callback fields the resident now supplies.
fn mediation_body() -> Value {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/content_sensitivity_parity.json"
    ))
    .unwrap();
    let mut body = fixture["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vector| {
            vector["query"] == "mediate" && vector["expected"]["ok"]["action"] == "forward"
        })
        .unwrap()["body"]
        .clone();
    body.as_object_mut().unwrap().remove("recheck");
    body["required_reason_code"] = Value::Null;
    body["cancelled"] = json!(false);
    body["allow_observe_mode"] = json!(false);
    body["recheck_available"] = json!(true);
    body
}

fn mediate(query: &str, body: &Value) -> Value {
    super::evaluate(query, body, Instant::now() + Duration::from_secs(2)).unwrap()["ok"].clone()
}

#[test]
fn mediation_leaves_what_it_does_not_cover_to_the_native_verdict() {
    let ordinary = mediation_body();
    assert_eq!(
        mediate("mediate_prepare", &ordinary),
        json!({"recheck_required": true})
    );
    for (label, edit) in [
        ("another harness", ("harness", json!("codex"))),
        ("another event", ("event_name", json!("PreToolUse"))),
        (
            "a native denial",
            (
                "native_result",
                json!({"decision": "deny", "model_output_action": "block"}),
            ),
        ),
        (
            "an observed result without the Watch allowance",
            (
                "native_result",
                json!({
                    "decision": "allow",
                    "observe_mode": true,
                    "model_output_action": "allow_original"
                }),
            ),
        ),
        ("no binding and nothing required", ("binding", Value::Null)),
    ] {
        let mut body = ordinary.clone();
        body[edit.0] = edit.1;
        assert_eq!(mediate("mediate_prepare", &body), Value::Null, "{label}");
    }
    // A binding for another harness than the hook's resolves nothing for it.
    let mut body = ordinary;
    body["binding"]["harness"] = json!("omp");
    assert_eq!(mediate("mediate_prepare", &body), Value::Null);
}

#[test]
fn mediation_withholds_content_it_cannot_prove_clean() {
    let ordinary = mediation_body();
    for (label, reason, edit) in [
        (
            "unreviewed output",
            "structured_content_unproved",
            (
                "native_result",
                json!({"decision": "allow", "model_output_action": "review"}),
            ),
        ),
        (
            "no receipt",
            "structured_receipt_missing",
            ("validated_receipt", Value::Null),
        ),
        (
            "a cancelled review",
            "structured_review_cancelled",
            ("cancelled", json!(true)),
        ),
        (
            "output that is not canonical JSON",
            "structured_content_unproved",
            ("structured_output_json", json!("{'note': 'ordinary'}")),
        ),
        (
            "a declared protected field",
            "structured_declared_schema_scan",
            (
                "structured_output_json",
                json!(r#"{"employee":{"email":"person@example.test","id":7},"note":"x"}"#),
            ),
        ),
        (
            "no way to recheck the binding",
            "structured_binding_recheck_missing",
            ("recheck_available", json!(false)),
        ),
    ] {
        let mut body = ordinary.clone();
        body[edit.0] = edit.1;
        let disposition = mediate("mediate_prepare", &body);
        assert_eq!(disposition["action"], "withhold", "{label}: {disposition}");
        assert_eq!(disposition["reason_code"], reason, "{label}: {disposition}");
        assert_eq!(disposition["content_sha256"], Value::Null, "{label}");
    }
    // Without a binding, a required policy withholds under its own reason.
    let mut body = ordinary;
    body["binding"] = Value::Null;
    body["required_reason_code"] = json!("structured_managed_authority_unavailable");
    let disposition = mediate("mediate_prepare", &body);
    assert_eq!(
        disposition["reason_code"],
        "structured_managed_authority_unavailable"
    );
    assert_eq!(disposition["native_decision_id"], "fixture-decision");
}

#[test]
fn mediation_forwards_only_under_the_binding_the_scan_ran_under() {
    let mut body = mediation_body();
    body["refreshed_binding"] = body["binding"].clone();
    body["recheck_error"] = json!(false);
    let forwarded = mediate("mediate_finish", &body);
    assert_eq!(forwarded["action"], "forward");
    assert_eq!(forwarded["reason_code"], "structured_clean_forward");
    let mut changed = body.clone();
    changed["refreshed_binding"]["managed_policy_hash"] = json!("b".repeat(64));
    let mut revoked = body.clone();
    revoked["refreshed_binding"] = Value::Null;
    for (label, body) in [("a changed binding", changed), ("a revoked one", revoked)] {
        let disposition = mediate("mediate_finish", &body);
        assert_eq!(disposition["action"], "withhold", "{label}");
        assert_eq!(
            disposition["reason_code"], "structured_binding_changed",
            "{label}"
        );
        assert_eq!(disposition["content_sha256"], Value::Null, "{label}");
    }
    body["recheck_error"] = json!(true);
    let failed = mediate("mediate_finish", &body);
    assert_eq!(failed["action"], "withhold");
    assert_eq!(failed["reason_code"], "structured_binding_recheck_failed");
}

#[test]
fn mediation_withholds_once_its_deadline_has_passed() {
    let mut body = mediation_body();
    assert_eq!(
        super::evaluate("mediate_prepare", &body, Instant::now()),
        Err("content_scan_deadline_exceeded")
    );
    body["refreshed_binding"] = body["binding"].clone();
    body["recheck_error"] = json!(false);
    assert_eq!(
        super::evaluate("mediate_finish", &body, Instant::now()),
        Err("content_scan_deadline_exceeded")
    );
}
