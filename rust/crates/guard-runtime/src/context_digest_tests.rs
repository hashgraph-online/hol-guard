//! Parity and unit coverage for the native approval-context digest op.

use super::*;
use crate::context_digest_json::python_float_repr;
use guard_contracts::CONTEXT_COMPONENT_MAX_BYTES;
use serde_json::{json, Map, Value};

const PARITY_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../tests/fixtures/context-digest-parity/cases.v1.json"
));

fn corpus() -> Value {
    serde_json::from_str(PARITY_FIXTURE).expect("context digest parity fixture must parse")
}

fn request_for(kind: ContextDigestKindV1) -> ContextDigestRequestV1 {
    ContextDigestRequestV1 {
        schema: CONTEXT_DIGEST_REQUEST_SCHEMA.to_owned(),
        request_id: "parity".to_owned(),
        kind,
    }
}

fn components_of(value: &Value, ext_digest: &str) -> ContextDigestComponentsV1 {
    ContextDigestComponentsV1 {
        identity: value.get("identity").cloned().unwrap_or(Value::Null),
        content: value.get("content").cloned().unwrap_or(Value::Null),
        capabilities: value.get("capabilities").cloned().unwrap_or(Value::Null),
        policy: value.get("policy").cloned().unwrap_or(Value::Null),
        sandbox: value.get("sandbox").cloned().unwrap_or(Value::Null),
        extension_control_digest: ext_digest.to_owned(),
    }
}

fn evaluate(request: ContextDigestRequestV1) -> ContextDigestResultV1 {
    let bytes = evaluate_context_digest_request(&request).expect("request must encode a result");
    serde_json::from_slice(&bytes).expect("result must decode")
}

#[test]
fn persisted_mcp_approval_digest_survives_byte_and_resident_numeric_decoding() {
    let raw = br#"{"schema":"guard-context-digest-request.v1","request_id":"numeric-approval","kind":"mcp_tool_approval_digest","request":{"content":{"artifact_id":"codex:mcp:filesystem:read_file","config_path":".mcp.json","arguments":{"path":"/opt/neutral/data/\u65e5\u672c\u8a9e.txt","limits":[1.0,-0.0,1e-7,1208925819614629174706177],"nested":{"empty":{},"missing":null}}},"transport":"stdio","server_fingerprint":{"resolved_executable":"/opt/bin/server","tool_catalog_fingerprint":"catalog"},"server_identity":{"identity_hash":"server"},"tool_identity":{"schema_hash":"schema"},"authority_hash":{"revision":1},"provider_hash":false,"workspace":null}}"#;
    let direct: ContextDigestResultV1 =
        serde_json::from_slice(&evaluate_context_digest_bytes(raw).unwrap()).unwrap();
    assert_eq!(
        direct.digest.as_deref(),
        Some("42166ca3ebc09245c93f0b33ce989a75df475c38817fded4168ab4ec5699b0e4")
    );
    let request: Value = serde_json::from_slice(raw).unwrap();
    let envelope =
        serde_json::to_vec(&json!({"operation": "context_digest", "request": request})).unwrap();
    let resident: ContextDigestResultV1 = serde_json::from_slice(
        &crate::resident_ops::evaluate_resident_bytes(&envelope, None).unwrap(),
    )
    .unwrap();
    assert_eq!(resident.digest, direct.digest);
}

#[test]
fn component_cases_match_python_tokens() {
    for case in corpus()["component_cases"].as_array().unwrap() {
        let components = components_of(
            &case["components"],
            case["extension_control_digest"].as_str().unwrap(),
        );
        let result = evaluate(request_for(
            ContextDigestKindV1::BuildApprovalContextToken { components },
        ));
        assert_eq!(result.status, "ok", "case {}", case["id"]);
        let expected = case["token"].as_str().unwrap();
        let actual = result.token.as_deref().unwrap();
        assert_eq!(actual, expected, "case {}", case["id"]);
    }
}

/// Project a corpus `values` input the way the Python transport shim does:
/// mappings become caller-ordered `["key", value]` pairs; everything else
/// passes through unchanged for the typed rejection boundary.
fn wire_values(values: &Value) -> Value {
    match values {
        Value::Object(entries) => Value::Array(
            entries
                .iter()
                .map(|(key, value)| Value::Array(vec![Value::String(key.clone()), value.clone()]))
                .collect(),
        ),
        other => other.clone(),
    }
}

#[test]
fn value_cases_match_python_digests() {
    for case in corpus()["value_cases"].as_array().unwrap() {
        // Order-sensitive cases carry an explicit wire projection; the Python
        // adapter derives the same pairs from the `values` mapping in
        // insertion order, which this fallback mirrors for unordered cases.
        let values = case
            .get("wire_values")
            .cloned()
            .or_else(|| case.get("values").map(wire_values));
        let configured_keys = case
            .get("configured_keys")
            .and_then(Value::as_array)
            .map(|keys| {
                keys.iter()
                    .map(|key| key.as_str().unwrap().to_owned())
                    .collect::<Vec<_>>()
            });
        let kind = match case["domain"].as_str().unwrap() {
            "environment" => ContextDigestKindV1::ConfiguredEnvironmentHash {
                values,
                configured_keys,
            },
            "headers" => ContextDigestKindV1::ConfiguredHeadersHash {
                values,
                configured_keys,
            },
            other => panic!("unknown domain {other}"),
        };
        let result = evaluate(request_for(kind));
        match case.get("error") {
            Some(_) => {
                assert_eq!(result.status, "error", "case {}", case["id"]);
                assert_eq!(result.code, ERR_VALUES, "case {}", case["id"]);
            }
            None => {
                assert_eq!(result.status, "ok", "case {}", case["id"]);
                assert_eq!(
                    result.digest.as_deref(),
                    case["digest"].as_str(),
                    "case {}",
                    case["id"]
                );
            }
        }
    }
}

#[test]
fn argv_cases_match_python_digests() {
    for case in corpus()["argv_cases"].as_array().unwrap() {
        let argv = case["argv"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item.as_str().unwrap().to_owned())
            .collect();
        let result = evaluate(request_for(ContextDigestKindV1::LaunchArgvDigest { argv }));
        assert_eq!(result.status, "ok", "case {}", case["id"]);
        assert_eq!(
            result.digest.as_deref(),
            case["digest"].as_str(),
            "case {}",
            case["id"]
        );
    }
}
#[test]
fn canonical_sha256_cases_match_python_digests() {
    for case in corpus()["canonical_sha256_cases"].as_array().unwrap() {
        let material = case["material"].clone();
        let prefix = case
            .get("prefix")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let result = evaluate(request_for(ContextDigestKindV1::CanonicalSha256 {
            material,
            prefix,
        }));
        assert_eq!(result.status, "ok", "case {}", case["id"]);
        assert_eq!(
            result.digest.as_deref(),
            case["digest"].as_str(),
            "case {}",
            case["id"]
        );
    }
}

#[test]
fn opaque_material_cases_match_python_digests() {
    for case in corpus()["opaque_material_cases"].as_array().unwrap() {
        let material = case["material"].as_str().unwrap().to_owned();
        let result = evaluate(request_for(ContextDigestKindV1::OpaqueMaterialDigest {
            material,
        }));
        assert_eq!(result.status, "ok", "case {}", case["id"]);
        assert_eq!(
            result.digest.as_deref(),
            case["digest"].as_str(),
            "case {}",
            case["id"]
        );
    }
}

#[test]
fn mcp_arguments_projection_cases_match_python() {
    for case in corpus()["mcp_arguments_projection_cases"]
        .as_array()
        .unwrap()
    {
        let arguments = case["arguments"].clone();
        let arguments = if arguments.is_null() {
            // `null` in the fixture encodes "no arguments key" — serde maps
            // absent and `null` to `None`, matching `params.get("arguments")`.
            None
        } else {
            Some(arguments)
        };
        let result = evaluate(request_for(ContextDigestKindV1::McpArgumentsProjection {
            tool_name: case["tool_name"].as_str().unwrap().to_owned(),
            arguments,
        }));
        assert_eq!(result.status, "ok", "case {}", case["id"]);
        assert_eq!(
            result.digest.as_deref(),
            case["digest"].as_str(),
            "case {}",
            case["id"]
        );
        assert_eq!(
            result.mcp_launch_target.as_deref(),
            case["launch_target"].as_str(),
            "case {}",
            case["id"]
        );
        assert_eq!(
            result.mcp_serialized_arguments.as_deref(),
            case["serialized_arguments"].as_str(),
            "case {}",
            case["id"]
        );
        let expected_safe = if case["safe_arguments"].is_null() {
            // Wire `null` parses as `None`; Python `_safe_mcp_arguments(None)`
            // also yields `None`.
            None
        } else {
            Some(&case["safe_arguments"])
        };
        assert_eq!(
            result.mcp_safe_arguments.as_ref(),
            expected_safe,
            "case {}",
            case["id"]
        );
    }
}

#[test]
fn mcp_redact_json_cases_match_python() {
    for case in corpus()["mcp_redact_json_cases"].as_array().unwrap() {
        let result = evaluate(request_for(ContextDigestKindV1::McpRedactJson {
            material: case["material"].clone(),
        }));
        assert_eq!(result.status, "ok", "case {}", case["id"]);
        assert_eq!(
            result.mcp_redacted_value.as_ref(),
            Some(&case["redacted"]),
            "case {}",
            case["id"]
        );
    }
}

#[test]
fn token_cases_match_python_parse() {
    for case in corpus()["token_cases"].as_array().unwrap() {
        let parsed = parse_context_token(&case["token"]);
        match case.get("parsed") {
            Some(Value::Null) | None => {
                assert!(parsed.is_none(), "case {}", case["id"]);
            }
            Some(expected) => {
                let parsed = parsed.unwrap_or_else(|| panic!("case {}", case["id"]));
                assert_eq!(parsed.identity, expected["identity"].as_str().unwrap());
                assert_eq!(parsed.content, expected["content"].as_str().unwrap());
                assert_eq!(
                    parsed.capabilities,
                    expected["capabilities"].as_str().unwrap()
                );
                assert_eq!(parsed.policy, expected["policy"].as_str().unwrap());
                assert_eq!(parsed.sandbox, expected["sandbox"].as_str().unwrap());
            }
        }
    }
}

#[test]
fn validation_cases_match_python_reasons() {
    for case in corpus()["validation_cases"].as_array().unwrap() {
        let result = evaluate(request_for(
            ContextDigestKindV1::ValidateApprovalContextTokens {
                saved_token: case["saved_token"].clone(),
                current_token: case["current_token"].clone(),
            },
        ));
        assert_eq!(result.status, "ok", "case {}", case["id"]);
        assert_eq!(
            result.validation_reason.as_deref(),
            case["reason"].as_str(),
            "case {}",
            case["id"]
        );
    }
}

#[test]
fn validate_context_kind_builds_and_compares() {
    let corpus = corpus();
    let case = &corpus["component_cases"].as_array().unwrap()[0];
    let components = components_of(
        &case["components"],
        case["extension_control_digest"].as_str().unwrap(),
    );
    let saved = case["token"].clone();
    let unchanged = evaluate(request_for(ContextDigestKindV1::ValidateApprovalContext {
        saved_token: saved.clone(),
        components: components.clone(),
    }));
    assert_eq!(unchanged.status, "ok");
    assert_eq!(unchanged.validation_reason, None);

    let mut drifted = components;
    drifted.content = Value::String("different-content".to_owned());
    let changed = evaluate(request_for(ContextDigestKindV1::ValidateApprovalContext {
        saved_token: saved,
        components: drifted,
    }));
    assert_eq!(changed.status, "ok");
    assert_eq!(
        changed.validation_reason.as_deref(),
        Some("approval_reuse_content_changed")
    );
}

#[test]
fn python_float_repr_matches_cpython() {
    let cases: [(f64, &str); 16] = [
        (0.0, "0.0"),
        (-0.0, "-0.0"),
        (1.0, "1.0"),
        (1.5, "1.5"),
        (0.1, "0.1"),
        (100.0, "100.0"),
        (1e15, "1000000000000000.0"),
        (1e16, "1e+16"),
        (1e-4, "0.0001"),
        (1e-5, "1e-05"),
        (1e300, "1e+300"),
        (-2.5e-7, "-2.5e-07"),
        (0.30000000000000004, "0.30000000000000004"),
        (1.7976931348623157e308, "1.7976931348623157e+308"),
        (5e-324, "5e-324"),
        (1234567890123456.0, "1234567890123456.0"),
    ];
    for (value, expected) in cases {
        assert_eq!(python_float_repr(value), expected, "value {value}");
    }
}

#[test]
fn canonical_json_escapes_like_cpython() {
    let mut out = Vec::new();
    write_canonical_json(
        &json!({"a": "café ☃ 😀", "b": "\u{0}\u{1f}\u{7f}\u{80}\"", "c": ["x\n", 1, true]}),
        &mut out,
    )
    .unwrap();
    let encoded = String::from_utf8(out).unwrap();
    assert_eq!(
        encoded,
        "{\"a\":\"caf\\u00e9 \\u2603 \\ud83d\\ude00\",\"b\":\"\\u0000\\u001f\\u007f\\u0080\\\"\",\"c\":[\"x\\n\",1,true]}"
    );
}

#[test]
fn token_parse_rejects_malformed_variants() {
    assert!(parse_context_token(&json!("not-a-token")).is_none());
    assert!(parse_context_token(&json!(42)).is_none());
    let prefix_only = APPROVAL_CONTEXT_TOKEN_PREFIX.to_string();
    assert!(parse_context_token(&json!(prefix_only)).is_none());
}

#[test]
fn token_parse_accepts_bool_version_for_python_parity() {
    // Python compares `payload.get("version") != 1` numerically, so a stored
    // token whose payload carries `"version": true` satisfies `True == 1`.
    // Pin that quirk: accepting it preserves legacy validation behavior.
    let bool_version_token = "guard-approval-context:v1:eyJjYXBhYmlsaXRpZXMiOiIwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwiY29udGVudCI6IjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLCJpZGVudGl0eSI6IjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLCJwb2xpY3kiOiIwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwic2FuZGJveCI6IjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLCJ2ZXJzaW9uIjp0cnVlfQ";
    assert!(parse_context_token(&json!(bool_version_token)).is_some());
}

#[test]
fn schema_mismatch_fails_request() {
    let request = ContextDigestRequestV1 {
        schema: "wrong".to_owned(),
        request_id: "x".to_owned(),
        kind: ContextDigestKindV1::LaunchArgvDigest { argv: vec![] },
    };
    let error = evaluate_context_digest_request(&request).unwrap_err();
    assert_eq!(error, "native_context_digest_schema_mismatch");
}

#[test]
fn request_digest_is_order_independent() {
    let bytes_a = br#"{"schema":"guard-context-digest-request.v1","request_id":"r","kind":"launch_argv_digest","argv":["a","b"]}"#;
    let bytes_b = br#"{"request_id":"r","kind":"launch_argv_digest","argv":["a","b"],"schema":"guard-context-digest-request.v1"}"#;
    let result_a = evaluate_context_digest_bytes(bytes_a).unwrap();
    let result_b = evaluate_context_digest_bytes(bytes_b).unwrap();
    let decoded_a: ContextDigestResultV1 = serde_json::from_slice(&result_a).unwrap();
    let decoded_b: ContextDigestResultV1 = serde_json::from_slice(&result_b).unwrap();
    assert_eq!(decoded_a.request_sha256, decoded_b.request_sha256);
    assert_eq!(decoded_a.digest, decoded_b.digest);
}

#[test]
fn oversized_component_fails() {
    let mut components = Map::new();
    components.insert(
        "blob".to_owned(),
        Value::String("x".repeat(CONTEXT_COMPONENT_MAX_BYTES + 1)),
    );
    let request = request_for(ContextDigestKindV1::BuildApprovalContextToken {
        components: ContextDigestComponentsV1 {
            identity: Value::Object(components),
            content: Value::Null,
            capabilities: Value::Null,
            policy: Value::Null,
            sandbox: Value::Null,
            extension_control_digest: "0".repeat(64),
        },
    });
    let result = evaluate(request);
    assert_eq!(result.status, "error");
    assert_eq!(result.code, ERR_COMPONENT);
}
