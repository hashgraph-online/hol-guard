use super::*;

#[cfg(not(windows))]
#[test]
fn recorded_python_model_and_helpers() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/native_rich_command_model.json"
    ))
    .unwrap();
    for (index, vector) in fixture["vectors"].as_array().unwrap().iter().enumerate() {
        let actual = result(vector["action"].as_str().unwrap(), &vector["args"]);
        if let Some(error) = vector.get("error") {
            assert_eq!(
                actual.unwrap_err(),
                error.as_str().unwrap(),
                "vector {index}"
            );
        } else {
            assert_eq!(actual.unwrap(), vector["result"], "vector {index}");
        }
    }
}

#[test]
fn invalid_redirect_ranges_do_not_panic_or_mask_command() {
    for (start, end) in [(2, 1), (0, 99), (99, 100), (usize::MAX, 1)] {
        assert_eq!(
            result(
                "segment_tokens",
                &json!({
                    "command": "echo hi", "source_offset": 0,
                    "redirects": [{"operator": ">", "target": "out", "start": start, "end": end}]
                })
            )
            .unwrap(),
            json!(["echo", "hi"])
        );
    }
}

#[test]
fn long_plain_and_numeric_commands_do_not_rescan_or_copy_suffixes() {
    for command in [
        "a".repeat(262_144),
        "1".repeat(262_144),
        format!("{}>", "1".repeat(262_144)),
    ] {
        assert_eq!(
            result("redirects", &json!({"command": command, "heredocs": []})).unwrap(),
            json!([])
        );
    }
    let command = " >out".repeat(4096);
    let redirects = result("redirects", &json!({"command": command, "heredocs": []})).unwrap();
    assert_eq!(redirects.as_array().unwrap().len(), 4096);
    assert_eq!(redirects[0]["start"], 1);
    assert_eq!(redirects[4095]["end"], command.chars().count());
}

#[test]
fn shadow_parser_supplies_the_existing_native_identity() {
    let command = guard_command::parse_command(&guard_command::CommandModelRequestV1 {
        command: "echo hi".to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    })
    .unwrap();
    assert_eq!(
        command.security_identity,
        guard_command::canonical_command::command_security_identity(&command)
    );
    assert!(command
        .security_identity
        .starts_with("command-security-v2:"));
}

#[test]
fn large_uncertain_parse_uses_a_bound_text_reference() {
    let command = format!(" {} ", "a".repeat(1_100_000));
    let parsed = result(
        "parse",
        &json!({
            "command": command, "dialect": "posix", "transport": "shell_string",
            "extraction_provenance": "guard-shell", "normalize_wrappers": true,
        }),
    )
    .unwrap();
    assert_eq!(parsed["confidence"], "uncertain");
    assert_eq!(parsed["raw_text"], "");
    assert_eq!(parsed["normalized_text"], "");
    assert_eq!(
        parsed["source_text_span"],
        json!({"start": 1, "end": 1_100_001})
    );
    assert!(serde_json::to_vec(&parsed).unwrap().len() < 2048);
}

#[test]
fn compressed_unicode_and_multi_megabyte_requests_remain_native_uncertain_models() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/rich_command_gzip_transport.json"
    ))
    .unwrap();
    for vector in fixture["vectors"].as_array().unwrap() {
        let request = RichCommandModelRequest {
            schema: REQUEST_SCHEMA.into(),
            request_id: "compressed-fixture".into(),
            guard_home: "/fixture".into(),
            action: "parse".into(),
            args: json!({"command_gzip_chunks": vector["command_gzip_chunks"]}),
        };
        let reply: Value = serde_json::from_slice(&evaluate(&request).unwrap()).unwrap();
        assert_eq!(reply["status"], "ok");
        assert_eq!(reply["result"]["confidence"], "uncertain");
        assert_eq!(
            reply["result"]["uncertainty_reason"],
            "command_byte_limit_exceeded"
        );
        assert!(reply["result"]["security_identity"]
            .as_str()
            .unwrap()
            .starts_with("command-security-v2:"));
    }
}

#[test]
fn public_token_projection_preserves_redirect_without_widening_argument_proofs() {
    assert_eq!(
        result("tokens", &json!({"command": "echo 2>/dev/null"})).unwrap(),
        json!([["echo", "2>/dev/null"], true])
    );
    let model = guard_command::parse_command(&guard_command::CommandModelRequestV1 {
        command: "echo 2>/dev/null".to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    })
    .unwrap();
    assert_eq!(model.segments[0].tokens, vec!["echo"]);
}

#[test]
fn response_is_bound_to_exact_request_and_rejects_unknown_inputs() {
    let request = RichCommandModelRequest {
        schema: REQUEST_SCHEMA.into(),
        request_id: "fixture".into(),
        guard_home: "/fixture".into(),
        action: "parse".into(),
        args: json!({"command": "echo hi"}),
    };
    let first: Value = serde_json::from_slice(&evaluate(&request).unwrap()).unwrap();
    let changed = RichCommandModelRequest {
        args: json!({"command": "echo bye"}),
        ..request
    };
    let second: Value = serde_json::from_slice(&evaluate(&changed).unwrap()).unwrap();
    assert_ne!(first["request_sha256"], second["request_sha256"]);
    assert!(result("parse", &json!({"command": "echo hi", "extra": true})).is_err());
    assert!(result("unknown", &json!({})).is_err());
}

#[test]
fn windows_token_errors_preserve_fallback_confidence() {
    assert_eq!(
        result("windows_tokens", &json!({"command": "echo \"unterminated"})).unwrap(),
        json!([["echo", "\"unterminated"], false])
    );
    assert_eq!(
        result(
            "windows_tokens",
            &json!({"command": "echo C:\\Work\\file.txt"})
        )
        .unwrap(),
        json!([["echo", "C:\\Work\\file.txt"], true])
    );
}
