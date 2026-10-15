use super::*;

const VECTORS: &str = include_str!("../../testdata/hook_cli_vectors.json");
const FLAGS: [&str; 5] = [
    "generic_path",
    "native_protocol_payload",
    "content_flagged",
    "command_surface",
    "verified_benign",
];

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("vectors parse")
}

fn params(case: &Value) -> Object {
    let mut params = Object::new();
    for (key, source) in [
        ("canonical_harness", "canonical"),
        ("event_name", "event"),
        ("policy_action", "action"),
        ("reason", "reason"),
        ("additional_context", "additional_context"),
        ("system_message", "system_message"),
    ] {
        params.insert(key.to_owned(), case[source].clone());
    }
    params
}

#[test]
fn response_matches_recorded_vectors() {
    let vectors = vectors();
    let cases = vectors["response"].as_array().expect("response vectors");
    assert!(!cases.is_empty());
    for case in cases {
        let rendered = cli_response(case["harness"].as_str().expect("harness"), &params(case));
        let expected = case["expected"].as_object().cloned();
        assert_eq!(rendered, expected, "{case}");
    }
}

#[test]
fn document_matches_recorded_vectors() {
    let vectors = vectors();
    let envelopes = vectors["envelopes"].as_array().expect("envelopes");
    let cases = vectors["document"].as_array().expect("document vectors");
    assert!(!cases.is_empty());
    for case in cases {
        let mut params = params(case);
        if let Some(index) = case["envelope"].as_u64() {
            params.insert("envelope".into(), envelopes[index as usize].clone());
        }
        let bits = case["flags"].as_u64().expect("flags");
        for (position, name) in FLAGS.iter().enumerate() {
            params.insert((*name).into(), Value::Bool(bits & (1 << position) != 0));
        }
        let outcome = cli_document(case["harness"].as_str().expect("harness"), &params);
        let expected = &case["expected"];
        match (expected["outcome"].as_str(), &outcome) {
            (Some("fallback"), CliOutcome::Fallback) | (Some("silent"), CliOutcome::Silent) => {}
            (Some("document"), CliOutcome::Document(document)) => {
                assert_eq!(
                    &Value::Object(document.clone()),
                    &expected["document"],
                    "{case}"
                );
            }
            _ => panic!("outcome {outcome:?} does not match {case}"),
        }
    }
}
