//! Paged results of the `PolicyBundleAuthority` op.

use guard_contracts::MAX_NATIVE_RESPONSE_BYTES;
use serde_json::{json, Value};

use crate::policy_bundle_op::evaluate_policy_bundle_authority_request;
use crate::policy_bundle_op_vectors_tests::{run, run_page};

fn chunks(document: &Value) -> Vec<Value> {
    let text = document.to_string();
    let characters: Vec<char> = text.chars().collect();
    characters
        .chunks(100_000)
        .map(|piece| Value::String(piece.iter().collect()))
        .collect()
}

/// A valid v1-shaped rule set whose expansion (one long reason repeated across
/// every location and family) is far larger than the bundle that carries it.
fn expanding_bundle() -> Value {
    let places: Vec<String> = (0..200)
        .map(|index| format!("/work/project-{index}"))
        .collect();
    let reason = "r".repeat(12_000);
    json!({
        "rules": [{
            "ruleId": "wide",
            "action": "allow",
            "reason": reason,
            "scope": {"harnesses": ["codex"], "locations": places},
            "matcherFamilies": ["mcp", "mcp-tool", "prompt", "file-read"],
        }],
    })
}

fn request_input(bundle: &Value) -> Value {
    json!({"bundle_chunks": chunks(bundle), "device_id": "device", "device_name": "name"})
}

#[test]
fn decisions_larger_than_one_response_are_paged_and_reassemble() {
    let input = request_input(&expanding_bundle());
    let whole = run("build_decisions", input.clone());
    let rows = whole["decisions"].as_array().unwrap();
    let serialized = serde_json::to_vec(rows).unwrap().len();
    assert!(
        serialized > MAX_NATIVE_RESPONSE_BYTES,
        "fixture must exceed one response: {serialized}"
    );
    let first = run_page("build_decisions", input.clone());
    assert_eq!(first["total"], rows.len());
    assert!(first["next"].is_u64(), "first page must not be the last");
    assert!(first["decisions"].as_array().unwrap().len() < rows.len());
    let mut offset = 0;
    let mut pages = 0;
    loop {
        let mut request = input.clone();
        request["offset"] = Value::from(offset);
        let call = evaluate_policy_bundle_authority_request(
            &guard_contracts::PolicyBundleAuthorityRequestV1 {
                schema: guard_contracts::POLICY_BUNDLE_AUTHORITY_REQUEST_SCHEMA.to_owned(),
                request_id: "page".to_owned(),
                kind: "build_decisions".to_owned(),
                input: request,
            },
        )
        .expect("every page must fit one resident response");
        let page: Value = serde_json::from_slice(&call).unwrap();
        assert_eq!(page["status"], "ok");
        pages += 1;
        match page["result"]["next"].as_u64() {
            Some(next) => offset = next as usize,
            None => break,
        }
    }
    assert!(pages >= 3, "{pages}");
}

#[test]
fn out_of_range_offsets_are_invalid_requests() {
    let mut input = request_input(&expanding_bundle());
    input["offset"] = Value::from(10_000_000);
    let page = run_page_raw("build_decisions", input);
    assert_eq!(page["code"], "native_policy_bundle_authority_invalid");
}

fn run_page_raw(kind: &str, input: Value) -> Value {
    let bytes = evaluate_policy_bundle_authority_request(
        &guard_contracts::PolicyBundleAuthorityRequestV1 {
            schema: guard_contracts::POLICY_BUNDLE_AUTHORITY_REQUEST_SCHEMA.to_owned(),
            request_id: "raw".to_owned(),
            kind: kind.to_owned(),
            input,
        },
    )
    .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[test]
fn non_ascii_requests_inside_the_wire_cap_are_not_rejected() {
    // ~2.8 MB on the wire, ~8.4 MB once ASCII-escaped for the request digest.
    let emoji = "\u{1F600}".repeat(700_000);
    let response = run_page_raw("not_a_kind", json!({"text": emoji}));
    assert_eq!(
        response["code"],
        "native_policy_bundle_authority_unknown_kind"
    );
    assert!(response["request_sha256"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
}

#[test]
fn requests_beyond_the_wire_cap_are_rejected() {
    let text = "a".repeat(4 * 1024 * 1024 + 1);
    let response = run_page_raw("not_a_kind", json!({"text": text}));
    assert_eq!(response["code"], "native_policy_bundle_authority_invalid");
}

#[test]
fn text_pages_reassemble_on_character_boundaries() {
    use crate::policy_bundle_op_page::page_text;
    // Multi-byte text longer than several pages; every page boundary must be a
    // character boundary and the digest must describe the whole text.
    let text = "\"é\u{1F600}".repeat(400_000);
    let mut joined = String::new();
    let mut offset = 0;
    let mut pages = 0;
    loop {
        let Ok(page) = page_text(text.clone().into_bytes(), offset) else {
            panic!("page at {offset} failed");
        };
        joined.push_str(page["value"].as_str().unwrap());
        assert_eq!(page["total"], text.len());
        assert_eq!(page["sha256"].as_str().unwrap().len(), 64);
        pages += 1;
        match page["next"].as_u64() {
            Some(next) => offset = next as usize,
            None => break,
        }
    }
    assert_eq!(joined, text);
    assert!(pages > 3, "{pages}");
}
