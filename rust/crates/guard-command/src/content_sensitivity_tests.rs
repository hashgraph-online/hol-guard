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
        match result {
            Ok(actual) if actual == vector["expected"] => {}
            other => failures.push(format!(
                "vector {index} query {query}: {other:?}, expected {}",
                vector["expected"]
            )),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
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
        let outcome = super::evaluate(
            "content",
            &decoded,
            Instant::now() + Duration::from_secs(30),
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
            actual["ok"],
            json!([vector["expected"]["ok"], vector["expected"]["ok"]])
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
