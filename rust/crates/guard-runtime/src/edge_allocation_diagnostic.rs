//! Actual codec, identity, edge and receipt components, without socket transport.
use super::*;
use crate::native_allocation_diagnostic::measure;
use crate::resident_protocol::{LifecycleDisposition, ResidentRequestV1};
use guard_contracts::{GuardHookSourceMetadataV2, MAX_NATIVE_REQUEST_BYTES};
use serde_json::json;

fn fixture(maximum: bool, event: &str, command: &str) -> GuardHookEnvelopeV2 {
    let mut envelope = GuardHookEnvelopeV2 {
        schema: GUARD_HOOK_ENVELOPE_V2_SCHEMA.into(),
        request_id: Some("allocation-fixture".into()),
        harness: "claude-code".into(),
        event: event.into(),
        deadline_budget_ms: Some(9_000),
        policy_generation: 1,
        policy_snapshot: json!({"generation":1, "policy_digest":"a".repeat(64),
            "rule_digest":guard_rule_contract::rule_digest(), "runtime_identity":"b".repeat(64)}),
        raw_payload: json!({"tool_name":"Bash", "tool_input":{"command":command}}),
        source: GuardHookSourceMetadataV2 {
            cwd: Some("/workspace".into()),
            home_dir: "/home/fixture".into(),
            guard_home: "/home/fixture/.guard".into(),
            source_ref_external_allowed: false,
        },
    };
    if event == "PostToolUse" {
        envelope.raw_payload["tool_response"] = json!("fixture tool output");
    }
    if maximum {
        // Respect the independent 1 MiB string limit while reaching the exact
        // 6 MiB envelope limit. Padding is a synthetic inert metadata field.
        envelope.raw_payload["diagnostic_padding"] = json!(vec!["x".repeat(1024 * 1024); 6]);
        let excess = serde_json::to_vec(&envelope).unwrap().len() - MAX_NATIVE_REQUEST_BYTES;
        envelope.raw_payload["diagnostic_padding"][5] = json!("x".repeat(1024 * 1024 - excess));
        assert_eq!(
            serde_json::to_vec(&envelope).unwrap().len(),
            MAX_NATIVE_REQUEST_BYTES
        );
    }
    envelope
}

#[test]
#[ignore = "allocation diagnostic; run release mode with diagnostic-allocations and one test thread"]
fn native_protocol_edge_allocation_phases() {
    // Warm immutable source identities and scanner tables before component
    // counting. Cold program admission has its own uninstrumented diagnostic.
    let _ = guard_rule_contract::rule_digest();
    for (name, maximum, event, command) in [
        ("pretool-small-benign", false, "PreToolUse", "pwd"),
        ("pretool-small-destructive", false, "PreToolUse", "rm -rf /"),
        ("pretool-maximum", true, "PreToolUse", "pwd"),
        ("posttool-small", false, "PostToolUse", "printf fixture"),
        ("posttool-maximum", true, "PostToolUse", "printf fixture"),
    ] {
        let envelope = fixture(maximum, event, command);
        let encoded = serde_json::to_vec(&envelope).unwrap();
        let length = encoded.len();
        let value = crate::strict_json_value(&encoded).unwrap();
        let expected_identity = request_identity(&envelope).unwrap();
        measure(
            name,
            "client_timeout_projection",
            length,
            || &encoded,
            |bytes| crate::strict_json::deadline_budget_ms(bytes).unwrap(),
            |budget| assert_eq!(*budget, Some(9_000)),
        );
        measure(
            name,
            "client_timeout_full_decode_reference",
            length,
            || &encoded,
            |bytes| {
                crate::strict_json_value(bytes)
                    .unwrap()
                    .get("deadline_budget_ms")
                    .and_then(Value::as_u64)
            },
            |budget| assert_eq!(*budget, Some(9_000)),
        );
        measure(
            name,
            "protocol_strict_json",
            length,
            || &encoded,
            |bytes| crate::strict_json_value(bytes).unwrap(),
            |actual| assert_eq!(*actual, value),
        );
        measure(
            name,
            "protocol_typed_decode",
            length,
            || value.clone(),
            |value| serde_json::from_value::<ResidentRequestV1>(value).unwrap(),
            |request| assert!(matches!(request, ResidentRequestV1::Edge(_))),
        );
        measure(
            name,
            "request_identity_hash_and_payload_copy",
            length,
            || &envelope,
            |request| request_identity(request).unwrap(),
            |identity| assert_eq!(*identity, expected_identity),
        );
        measure(
            name,
            "edge_bounds_identity_validation",
            length,
            || envelope.clone(),
            |request| validate_envelope_shape(request, Instant::now()).unwrap(),
            |validated| assert_eq!(validated.request_digest, expected_identity.1),
        );
        let expected = evaluate_validated_envelope(
            validate_envelope_shape(envelope.clone(), Instant::now()).unwrap(),
            None,
        )
        .unwrap();
        measure(
            name,
            "edge_evaluation_receipt_response_without_policy_store",
            length,
            || validate_envelope_shape(envelope.clone(), Instant::now()).unwrap(),
            |validated| evaluate_validated_envelope(validated, None).unwrap(),
            |result| assert_eq!(*result, expected),
        );
        let response: GuardHookEdgeResultV2 = serde_json::from_slice(&expected).unwrap();
        measure(
            name,
            "response_serialization",
            length,
            || &response,
            |value| crate::encode_response(value).unwrap(),
            |result| assert_eq!(*result, expected),
        );
        if event == "PreToolUse" {
            let native = guard_command::pretool::evaluate_pre_tool_envelope_with_extensions(
                "claude-code",
                event,
                &envelope.raw_payload,
                None,
                None,
            );
            let expected_receipt = receipt_from_pre_tool(
                &envelope,
                None,
                &expected_identity.0,
                &expected_identity.1,
                "claude-code",
                &GuardHookPayloadKindV2::Inline,
                &native,
            )
            .unwrap();
            measure(
                name,
                "typed_receipt_hash_and_encoding",
                length,
                || &native,
                |result| {
                    receipt_from_pre_tool(
                        &envelope,
                        None,
                        &expected_identity.0,
                        &expected_identity.1,
                        "claude-code",
                        &GuardHookPayloadKindV2::Inline,
                        result,
                    )
                    .unwrap()
                },
                |receipt| assert_eq!(receipt, &expected_receipt),
            );
        }
    }
    for (name, maximum) in [("shutdown-small", false), ("shutdown-maximum", true)] {
        let mut shutdown = json!({"operation":"shutdown", "request":{}});
        if maximum {
            shutdown["request"]["padding"] = json!(vec!["x".repeat(1024 * 1024); 6]);
            let excess = serde_json::to_vec(&shutdown).unwrap().len() - MAX_NATIVE_REQUEST_BYTES;
            shutdown["request"]["padding"][5] = json!("x".repeat(1024 * 1024 - excess));
        }
        let shutdown = serde_json::to_vec(&shutdown).unwrap();
        let evaluated = crate::resident_protocol::evaluate_resident_bytes(&shutdown, None).unwrap();
        measure(
            name,
            "typed_shutdown_disposition",
            shutdown.len(),
            || &evaluated,
            |value| value.disposition == LifecycleDisposition::Shutdown,
            |shutdown| assert!(*shutdown),
        );
        measure(
            name,
            "shutdown_full_reparse_reference",
            shutdown.len(),
            || shutdown.as_slice(),
            |bytes| crate::strict_json_value(bytes).unwrap()["operation"] == "shutdown",
            |shutdown| assert!(*shutdown),
        );
    }
    println!(
        "{}",
        json!({"schema":"guard.native-allocation-scope.v1",
            "not_measured":["client process startup", "native connection", "queue wait", "policy store authority lease", "evidence submission", "peak live allocation"],
            "phase_values_are_nonadditive":true, "command_extensions":"measured in separate catalog/control matrix",
            "fixture_commands_executed":false, "production_allocator_instrumented":false,
        })
    );
}
