use super::*;

use serde_json::json;

fn request(
    payload: Value,
    workspace: Option<&str>,
    envelope: Option<Value>,
) -> RetryLineageCaptureRequestV1 {
    RetryLineageCaptureRequestV1 {
        schema: RETRY_LINEAGE_CAPTURE_REQUEST_SCHEMA.to_owned(),
        request_id: "req-1".to_owned(),
        harness: "codex".to_owned(),
        payload: payload.as_object().expect("payload object").clone(),
        workspace: workspace.map(str::to_owned),
        action_envelope: envelope.map(|value| value.as_object().expect("envelope").clone()),
    }
}

fn decode(request: &RetryLineageCaptureRequestV1) -> RetryLineageCaptureResultV1 {
    serde_json::from_slice(&evaluate_retry_lineage_capture(request).unwrap()).unwrap()
}

fn lineage(request: &RetryLineageCaptureRequestV1) -> Option<Value> {
    decode(request).lineage.map(Value::Object)
}

// Expected records were produced by the retired Python `capture_retry_lineage`
// from the same inputs, so a digest drift here is a parity break.
#[test]
fn capture_matches_the_retired_python_records() {
    // The envelope is parsed from the text Python's transport sends, so its
    // numbers keep CPython's spelling (`1e+20`) on the way in.
    let envelope: Value = serde_json::from_str(
        r#"{"command":"ls -l","nested":{"z":[1,2.5,1e+20,null,true],"a":"ünï "},"n":12345678901234567890}"#,
    )
    .unwrap();
    let full = request(
        json!({
            "sessionId": "s-1", "threadId": "t-1", "toolUseId": "call_9", "turn_id": "turn-2",
            "eventId": "ev", "requestId": "req-7", "cwd": "/w/café", "deviceId": "dev-ü",
            "tool_input": false,
        }),
        Some("/w/café"),
        Some(envelope),
    );
    assert_eq!(
        lineage(&full),
        Some(json!({
            "action_sha256": "29fe0339fb244f4bc342bea8f14ec1d74322988b8c4674e233e4302269553bc8",
            "device_sha256": "e9f65b607f66ca5869307eea11c1e2e104604461f8ab1d126d3a2207651a01f8",
            "harness": "codex",
            "invocation_id": "ev",
            "lineage_id": "a73ae5789b62d2339d334726b1126081591182490dcd2f3e630ff6a0144e8ab6",
            "provider_request_id": "req-7",
            "session_id": "s-1",
            "source": "hook",
            "thread_id": "t-1",
            "tool_call_id": "call_9",
            "turn_id": "turn-2",
            "version": 1,
            "workspace_sha256": "b39d6d30bb3eecc286b5e157022c2cac04dbd15bbd37a7a1dde9af5d992472ca",
        }))
    );

    let mut agree = request(json!({"session_id": "s", "sessionId": "s"}), None, None);
    agree.harness = "claude-code".to_owned();
    assert_eq!(
        lineage(&agree),
        Some(json!({
            "harness": "claude-code",
            "lineage_id": "e536f134cf9590f1b34b703e25cd27dbff121530ccd41a6fa9be87f584763127",
            "session_id": "s",
            "source": "hook",
            "version": 1,
        }))
    );

    let mut payload_workspace = request(
        json!({"thread_id": "t", "workspace": "/p"}),
        None,
        Some(json!({})),
    );
    payload_workspace.harness = "copilot".to_owned();
    assert_eq!(
        lineage(&payload_workspace),
        Some(json!({
            "action_sha256": "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
            "harness": "copilot",
            "lineage_id": "772d98ed3b02f5d0cc4dd911d216164307306cf3d36c7ab7a08508e46c875e47",
            "source": "hook",
            "thread_id": "t",
            "version": 1,
            "workspace_sha256": "00d74baf14ea415c6164614838c91f834c38c3e564444dfa5bc3aa0d2809e265",
        }))
    );
}

#[test]
fn ambiguous_malformed_or_unbounded_identifiers_carry_no_lineage() {
    let refused = [
        json!({"session_id": "a", "sessionId": "b"}),
        json!({"session_id": " padded"}),
        json!({"session_id": "line\nbreak"}),
        json!({"session_id": "del\u{7f}"}),
        json!({"session_id": ""}),
        json!({"session_id": "x".repeat(257)}),
        json!({"session_id": false}),
        json!({"session_id": 7}),
        json!({"session_id": "s", "requestId": "a", "approval_request_id": "b"}),
        json!({"session_id": "s", "deviceId": "a", "device_id": "b"}),
        json!({"session_id": "s", "cwd": "/a", "workspace": "/b"}),
    ];
    for payload in refused {
        assert_eq!(
            lineage(&request(payload.clone(), None, None)),
            None,
            "{payload}"
        );
    }
    // 256 characters is the bound itself, counted in characters, not bytes.
    let bound = "é".repeat(256);
    assert!(lineage(&request(json!({"session_id": bound}), None, None)).is_some());
}

#[test]
fn a_provider_identifier_is_required() {
    for payload in [
        json!({}),
        json!({"session_id": null}),
        json!({"requestId": "r", "cwd": "/w", "deviceId": "d"}),
    ] {
        assert_eq!(
            lineage(&request(payload.clone(), Some("/w"), None)),
            None,
            "{payload}"
        );
    }
}

#[test]
fn the_runtime_workspace_wins_and_a_contradicting_claim_refuses_the_record() {
    let digest_of = |text: &str| sha256_hex(text.as_bytes());
    let runtime_only =
        lineage(&request(json!({"session_id": "s"}), Some("/runtime"), None)).unwrap();
    assert_eq!(
        runtime_only["workspace_sha256"],
        json!(digest_of("/runtime"))
    );
    let agreeing = lineage(&request(
        json!({"session_id": "s", "cwd": "/runtime"}),
        Some("/runtime"),
        None,
    ));
    assert_eq!(agreeing, Some(runtime_only));
    assert_eq!(
        lineage(&request(
            json!({"session_id": "s", "cwd": "/other"}),
            Some("/runtime"),
            None
        )),
        None
    );
    assert_eq!(
        lineage(&request(json!({"session_id": "s"}), Some(""), None)),
        None
    );
    let mut bad_harness = request(json!({"session_id": "s"}), None, None);
    bad_harness.harness = " codex".to_owned();
    assert_eq!(lineage(&bad_harness), None);
}

#[test]
fn a_captured_record_is_one_the_store_preserves() {
    let captured = lineage(&request(
        json!({"session_id": "s", "toolUseId": "tu", "cwd": "/w"}),
        None,
        Some(json!({"command": "rm -rf build"})),
    ))
    .unwrap();
    let existing = json!({"retry_lineage": captured.clone()}).to_string();
    let persisted = crate::guard_store_lineage::persisted_metadata(
        &existing,
        r#"{"retry_lineage":{"version":2}}"#,
    )
    .unwrap();
    let persisted: Value = serde_json::from_str(&persisted).unwrap();
    assert_eq!(persisted["retry_lineage"], captured);
}

#[test]
fn the_reply_binds_to_its_request_and_refuses_a_foreign_schema() {
    let ok = request(json!({"session_id": "s"}), None, None);
    let reply = decode(&ok);
    assert_eq!(reply.schema, RETRY_LINEAGE_CAPTURE_RESULT_SCHEMA);
    assert_eq!(reply.request_id, "req-1");
    assert_eq!(
        reply.request_sha256,
        request_digest_with_limit(&ok, RETRY_LINEAGE_CAPTURE_MAX_REQUEST_BYTES).unwrap()
    );
    assert_eq!((reply.status.as_str(), reply.code.as_str()), ("ok", "ok"));

    let mut foreign = ok.clone();
    foreign.schema = "guard-retry-lineage-capture-request.v0".to_owned();
    assert_eq!(
        evaluate_retry_lineage_capture(&foreign).unwrap_err(),
        "native_retry_lineage_capture_schema_mismatch"
    );
    let mut anonymous = ok.clone();
    anonymous.request_id.clear();
    assert_eq!(
        evaluate_retry_lineage_capture(&anonymous).unwrap_err(),
        "native_retry_lineage_capture_invalid"
    );

    // A refused payload is still a well-formed answer, not a resident failure.
    let refused = decode(&request(json!({"session_id": 7}), None, None));
    assert_eq!((refused.code.as_str(), refused.lineage), ("ok", None));
}

#[test]
fn a_payload_naming_its_own_workspace_and_device_matches_the_retired_python_record() {
    let mut provider = request(
        json!({
            "session_id": "provider-session-001",
            "tool_call_id": "provider-tool-call-001",
            "turn_id": "provider-turn-001",
            "invocation_id": "provider-invocation-001",
            "request_id": "provider-request-001",
            "workspace": "/workspace/example",
            "device_id": "device-001",
        }),
        None,
        None,
    );
    provider.harness = "pi".to_owned();
    let captured = lineage(&provider).unwrap();
    assert_eq!(
        captured["lineage_id"],
        json!("2189a00d6d6b1f695640aa814fbc019cda40551907aade614c81774b5785720b")
    );
    assert_eq!(
        captured["workspace_sha256"],
        json!("863c29bb9a6e7822955a80f7e09466e156f7019807c3c0c030592cff4af0f348")
    );
    assert_eq!(
        captured["device_sha256"],
        json!("99f93d33035dd7bef57594c41d0f5efc7a5ffefbd00cc24856437596341d444d")
    );
}

#[test]
fn a_stored_record_that_is_not_canonical_is_not_preserved() {
    let captured = lineage(&request(json!({"session_id": "s"}), None, None)).unwrap();
    let requested = r#"{"retry_lineage":{"session_id":"next"}}"#;
    let mut boolean_version = captured.clone();
    boolean_version["version"] = json!(true);
    let mut accented_id = captured.clone();
    accented_id["lineage_id"] = json!("é".repeat(64));
    for stored in [boolean_version, accented_id] {
        let existing = json!({"retry_lineage": stored}).to_string();
        assert_eq!(
            crate::guard_store_lineage::persisted_metadata(&existing, requested).unwrap(),
            requested
        );
    }
}
