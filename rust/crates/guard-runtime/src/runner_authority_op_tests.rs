//! Replays language-neutral vectors recorded from the Python runner before its
//! authority logic moved here (`tests/fixtures/runner_authority/vectors.json`).

use super::*;
use guard_contracts::RunnerAuthorityResultV1;
use serde_json::json;

const VECTORS: &str = include_str!("../../../../tests/fixtures/runner_authority/vectors.json");

fn vectors() -> Vec<Value> {
    let document: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(document["version"], 1);
    document["vectors"].as_array().unwrap().clone()
}

/// Applies a result patch the way the Python adapter does: `set` keys replace
/// evaluation keys and `artifact_patches` update artifacts by request index.
fn merged(base: &Value, patch: &Value) -> Value {
    let mut out = base.as_object().cloned().unwrap_or_default();
    for (key, value) in patch["set"].as_object().unwrap() {
        if key != "artifact_patches" {
            out.insert(key.clone(), value.clone());
        }
    }
    if let Some(patches) = patch["set"].get("artifact_patches") {
        let mut artifacts = base["artifacts"].as_array().cloned().unwrap_or_default();
        for entry in patches.as_array().unwrap() {
            let index = entry["index"].as_u64().unwrap() as usize;
            let artifact = artifacts[index].as_object_mut().unwrap();
            for (key, value) in entry["set"].as_object().unwrap() {
                artifact.insert(key.clone(), value.clone());
            }
        }
        out.insert("artifacts".to_owned(), Value::Array(artifacts));
    }
    Value::Object(out)
}

fn call(kind: &str, args: &Value) -> Value {
    dispatch(kind, args).unwrap_or_else(|code| panic!("{kind} failed: {code}"))
}

fn replay(vector: &Value) {
    let kind = vector["kind"].as_str().unwrap();
    let (args, expected) = (&vector["args"], &vector["expected"]);
    let base = &vector["merge_base"];
    match kind {
        "apply_detector_result" => {
            assert_eq!(merged(base, &call(kind, args)), *expected);
        }
        "preclaim_failure" | "claim_context_failure" => {
            let result = call(kind, args);
            assert_eq!(merged(base, &result), expected["evaluation"]);
            assert_eq!(result["receipt_evidence"], expected["receipt_evidence"]);
        }
        "authority_signature_pair" => {
            let signature =
                |side: &str| call("authority_signature", &args[side])["signature"].clone();
            let (a, b) = (signature("a"), signature("b"));
            assert_eq!(a.is_null(), expected["a_null"]);
            assert_eq!(b.is_null(), expected["b_null"]);
            assert_eq!(!a.is_null() && a == b, expected["equal"]);
        }
        _ => assert_eq!(call(kind, args), *expected),
    }
}

#[test]
fn recorded_python_vectors_replay_exactly() {
    let vectors = vectors();
    assert!(vectors.len() > 200);
    for vector in &vectors {
        let label = format!("{} / {}", vector["kind"], vector["name"]);
        let outcome = std::panic::catch_unwind(|| replay(vector));
        assert!(outcome.is_ok(), "vector mismatch: {label}");
    }
}

fn request(kind: &str, args: Value) -> RunnerAuthorityRequestV1 {
    RunnerAuthorityRequestV1 {
        schema: RUNNER_AUTHORITY_REQUEST_SCHEMA.to_owned(),
        request_id: "req-1".to_owned(),
        guard_home: "/tmp/guard-home".to_owned(),
        kind: kind.to_owned(),
        args,
    }
}

fn run(request: &RunnerAuthorityRequestV1) -> RunnerAuthorityResultV1 {
    serde_json::from_slice(&evaluate_runner_authority(request).unwrap()).unwrap()
}

#[test]
fn envelope_binds_request_id_and_digest() {
    let result = run(&request("detector_composition", json!({"signals": []})));
    assert_eq!((result.status.as_str(), result.code.as_str()), ("ok", "ok"));
    assert_eq!(result.request_id, "req-1");
    assert_eq!(result.request_sha256.len(), 64);
    assert_eq!(result.payload.unwrap()["blocks"], false);
}

#[test]
fn unknown_kind_and_schema_fail_closed_with_typed_codes() {
    let unknown = run(&request("nope", json!({})));
    assert_eq!(unknown.code, "native_runner_authority_unknown_kind");
    assert!(unknown.payload.is_none());
    let mut stale = request("detector_composition", json!({"signals": []}));
    stale.schema = "guard-runner-authority-request.v0".to_owned();
    assert_eq!(run(&stale).code, "native_runner_authority_schema_mismatch");
    let mut homeless = request("detector_composition", json!({"signals": []}));
    homeless.guard_home = String::new();
    assert_eq!(run(&homeless).code, "native_runner_authority_invalid");
}

#[test]
fn oversized_request_is_rejected_before_evaluation() {
    let huge = "x".repeat(RUNNER_AUTHORITY_MAX_BYTES + 1);
    let result = run(&request("detector_composition", json!({"signals": [huge]})));
    assert_eq!(result.code, "native_runner_authority_request_too_large");
    assert!(result.request_sha256.is_empty());
}

#[test]
fn oversized_result_is_a_typed_error_not_a_transport_failure() {
    // Each row echoes back as an update, so a request under the 4 MiB request
    // bound can still produce a result over the 2 MiB response bound.
    let pad = "p".repeat(600 * 1024);
    let entries = serde_json::to_string(&json!([{"source": "other", "pad": pad}])).unwrap();
    let rows: Vec<Value> = (0..4)
        .map(|rowid| {
            json!({
                "rowid": rowid,
                "artifact_id": "a",
                "policy_decision": "allow",
                "scanner_evidence_json": entries,
                "approval_source": null,
            })
        })
        .collect();
    let result = run(&request(
        "receipt_evidence_merge",
        json!({
            "rows": rows,
            "artifact_ids": ["a"],
            "evidence": {"source": "approval_reuse", "reason_code": "x"},
            "approval_source": null,
            "source_actions": [],
            "replace_existing_source": false,
        }),
    ));
    assert_eq!(result.status, "error");
    assert_eq!(result.code, "native_runner_authority_response_too_large");
    assert!(result.payload.is_none());
    assert_eq!(result.request_sha256.len(), 64);
}

#[test]
fn malformed_arguments_are_typed_errors_not_allows() {
    for kind in [
        "detector_authority",
        "current_authority_actions",
        "request_overrides",
        "claim_partition",
        "apply_detector_result",
        "preclaim_failure",
        "claim_context_failure",
        "receipt_evidence_merge",
        "authority_signature",
        "authority_gate",
        "policy_shadow_mismatch",
    ] {
        assert_eq!(
            dispatch(kind, &json!("not-an-object")),
            Err(ERR_INVALID),
            "{kind}"
        );
    }
    assert_eq!(
        dispatch(
            "preclaim_failure",
            &json!({"affected_artifact_ids": [], "reason_code": "other"})
        ),
        Err(ERR_INVALID)
    );
}
