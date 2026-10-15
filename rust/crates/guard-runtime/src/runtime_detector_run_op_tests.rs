//! Vectors recorded from the Python `DetectorRegistry` this op replaced, by
//! `scripts/record_runtime_detector_vectors.py` (gzipped).

use guard_contracts::RuntimeDetectorActionV1;

use super::*;

fn request(action_type: &str, command: Option<&str>) -> RuntimeDetectorRunRequestV1 {
    RuntimeDetectorRunRequestV1 {
        schema: RUNTIME_DETECTOR_RUN_REQUEST_SCHEMA.to_owned(),
        request_id: "t-1".to_owned(),
        guard_home: "/tmp/guard-home".to_owned(),
        workspace: Some("/workspace/project".to_owned()),
        action: RuntimeDetectorActionV1 {
            action_type: action_type.to_owned(),
            command: command.map(str::to_owned),
            prompt_text: None,
            prompt_excerpt: None,
            mcp_tool: None,
            target_paths: Vec::new(),
        },
        timeout_ms: 60_000,
        disabled_detector_ids: Vec::new(),
        enabled_categories: None,
    }
}

fn evaluate(request: &RuntimeDetectorRunRequestV1) -> RuntimeDetectorRunResultV1 {
    serde_json::from_slice(&evaluate_runtime_detector_run(request).unwrap()).unwrap()
}

fn entries(request: &RuntimeDetectorRunRequestV1) -> Vec<Value> {
    let result = evaluate(request);
    assert_eq!((result.status.as_str(), result.code.as_str()), ("ok", "ok"));
    result.payload.unwrap()["detectors"]
        .as_array()
        .unwrap()
        .clone()
}

fn without_elapsed(mut entry: Value) -> Value {
    let elapsed = entry
        .as_object_mut()
        .unwrap()
        .remove("elapsed_ms")
        .expect("every entry reports elapsed_ms");
    assert!(elapsed.as_i64().is_some_and(|ms| ms >= 0));
    entry
}

#[test]
fn every_default_detector_reports_in_id_order() {
    let ids: Vec<String> = entries(&request("shell_command", Some("ls")))
        .iter()
        .map(|entry| entry["detector_id"].as_str().unwrap().to_owned())
        .collect();
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(ids, sorted);
    assert_eq!(ids.len(), 11);
    assert!(!ids.iter().any(|id| id.starts_with("cisco.")));
}

#[test]
fn disabled_and_filtered_detectors_do_not_run() {
    let mut request = request("shell_command", Some("rm -rf ~/.hol-guard"));
    request.disabled_detector_ids = vec!["bypass.shell".to_owned()];
    request.enabled_categories = Some(vec!["no-such-category".to_owned()]);
    for entry in entries(&request) {
        let expected = if entry["detector_id"] == "bypass.shell" {
            "disabled"
        } else {
            "filtered"
        };
        assert_eq!(entry["status"], expected, "{entry}");
        assert_eq!(entry["signals"], json!([]));
    }
}

#[test]
fn oversized_data_flow_command_fails_the_run_closed() {
    let command = "x".repeat(256 * 1024 + 1);
    let result = evaluate(&request("shell_command", Some(&command)));
    assert_eq!(result.status, "error");
    assert_eq!(result.code, "native_data_flow_analyze_command_too_large");
    assert!(result.payload.is_none());
    assert!(!result.request_sha256.is_empty());
}

#[test]
fn schema_mismatch_and_empty_home_are_typed_errors() {
    let mut bad_schema = request("shell_command", Some("ls"));
    bad_schema.schema = "other".to_owned();
    let result = evaluate(&bad_schema);
    assert_eq!(result.code, "native_runtime_detector_run_schema_mismatch");
    assert_eq!(result.status, "error");
    assert!(result.payload.is_none());

    let mut no_home = request("shell_command", Some("ls"));
    no_home.guard_home.clear();
    assert_eq!(
        evaluate(&no_home).code,
        "native_runtime_detector_run_invalid"
    );
}

#[test]
fn oversized_request_is_a_typed_error_with_no_digest() {
    let huge = "x".repeat(RUNTIME_DETECTOR_RUN_MAX_BYTES + 1);
    let result = evaluate(&request("shell_command", Some(&huge)));
    assert_eq!(result.code, "native_runtime_detector_run_request_too_large");
    assert!(result.request_sha256.is_empty());

    // Within the UTF-8 bound, but the ASCII-escaped canonical form is over it.
    let emoji = "\u{1f600}".repeat(RUNTIME_DETECTOR_RUN_MAX_BYTES / 8);
    let result = evaluate(&request("prompt", Some(&emoji)));
    assert_eq!(result.code, "native_runtime_detector_run_request_too_large");
}

#[test]
fn result_binds_to_the_request_digest() {
    let request = request("shell_command", Some("ls"));
    let result = evaluate(&request);
    assert_eq!(result.request_id, "t-1");
    assert_eq!(result.request_sha256, request_digest(&request).unwrap());
}

#[test]
fn unknown_and_missing_fields_are_rejected() {
    let mut wire = serde_json::to_value(request("shell_command", Some("ls"))).unwrap();
    wire["extra"] = json!(1);
    assert!(serde_json::from_value::<RuntimeDetectorRunRequestV1>(wire.clone()).is_err());
    wire.as_object_mut().unwrap().remove("extra");
    wire["action"].as_object_mut().unwrap().remove("mcp_tool");
    assert!(serde_json::from_value::<RuntimeDetectorRunRequestV1>(wire).is_err());
}

#[test]
fn parity_vectors_match_the_recorded_python_outputs() {
    let fixture = crate::store_vectors_support_tests::gunzip_json(include_bytes!(
        "../tests/fixtures/runtime_detector_vectors.json.gz"
    ));
    let vectors = fixture.as_array().unwrap();
    assert!(vectors.len() > 700);
    let mut mismatches = Vec::new();
    for vector in vectors {
        let wire = &vector["request"];
        let request = RuntimeDetectorRunRequestV1 {
            schema: RUNTIME_DETECTOR_RUN_REQUEST_SCHEMA.to_owned(),
            request_id: "parity".to_owned(),
            guard_home: "/tmp/guard-home".to_owned(),
            workspace: wire["workspace"].as_str().map(str::to_owned),
            action: serde_json::from_value(wire["action"].clone()).unwrap(),
            timeout_ms: 60_000,
            disabled_detector_ids: serde_json::from_value(wire["disabled_detector_ids"].clone())
                .unwrap(),
            enabled_categories: serde_json::from_value(wire["enabled_categories"].clone()).unwrap(),
        };
        let result = evaluate(&request);
        let actual: Option<Vec<Value>> = result.payload.map(|payload| {
            payload["detectors"]
                .as_array()
                .unwrap()
                .iter()
                .cloned()
                .map(without_elapsed)
                .collect()
        });
        let expected = vector["expected"].as_array().unwrap();
        match &actual {
            Some(actual) if actual == expected => {}
            Some(actual) if actual.len() == expected.len() => {
                for (got, want) in actual.iter().zip(expected) {
                    if got != want {
                        mismatches.push(format!(
                            "{} {}:\n  expected {want}\n  got      {got}",
                            vector["name"], want["detector_id"]
                        ));
                    }
                }
            }
            _ => mismatches.push(format!(
                "{}: code {} expected {} got {:?}",
                vector["name"],
                result.code,
                Value::Array(expected.clone()),
                actual.map(Value::Array)
            )),
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} mismatches:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}
