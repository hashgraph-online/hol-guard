use super::*;
use guard_contracts::{
    RequestContextKindV1, RequestContextPolicyDocumentV1, RequestContextRequestV1,
    RequestContextSourceV1, REQUEST_CONTEXT_REQUEST_SCHEMA,
};

fn request(query: &str, input: Value, home: &str) -> Value {
    #[cfg(unix)]
    let owner_uid = Some(nix::unistd::geteuid().as_raw());
    #[cfg(not(unix))]
    let owner_uid = None;
    let request = RequestContextRequestV1 {
        schema: REQUEST_CONTEXT_REQUEST_SCHEMA.into(),
        request_id: "wire-fixture".into(),
        guard_home: home.into(),
        source: RequestContextSourceV1::DirectCommand,
        budget_ms: 30_000,
        owner_uid,
        action: RequestContextKindV1::PolicyDocument(RequestContextPolicyDocumentV1 {
            query: query.into(),
            input,
        }),
    };
    serde_json::from_slice(
        &crate::request_context_op::evaluate_request_context_request(&request).unwrap(),
    )
    .unwrap()
}

fn run(query: &str, input: Value, home: &str) -> Value {
    let response = request(query, input, home);
    assert_eq!(response["status"], "ok", "{response}");
    response["payload"]["result"].clone()
}

#[test]
fn large_policy_input_and_output_round_trip_without_evaluating_partial_uploads() {
    let suffix = crate::unique_nanos::unique_nanos();
    let home = std::env::temp_dir()
        .join(format!("guard-document-wire-{suffix}"))
        .to_string_lossy()
        .into_owned();
    let text = "x".repeat(7 * 1024 * 1024);
    let input = serde_json::to_vec(&json!({"value":text})).unwrap();
    let start = run(
        "wire_start",
        json!({"query":"canonical","size":input.len(),"sha256":hex::encode(Sha256::digest(&input))}),
        &home,
    );
    let token = start["wire_upload"]["handle"].as_str().unwrap();
    assert_eq!(
        request(
            "wire_append",
            json!({"handle":token,"offset":1,"bytes":Base64::encode_string(b"x")}),
            &home
        )["status"],
        "error"
    );
    assert_eq!(
        request(
            "wire_append",
            json!({"handle":token,"offset":0,"bytes":Base64::encode_string(b"x")}),
            &(home.clone() + "-other")
        )["status"],
        "error"
    );
    for (index, chunk) in input.chunks(CHUNK).enumerate() {
        let result = run(
            "wire_append",
            json!({"handle":token,"offset":index*CHUNK,"bytes":Base64::encode_string(chunk)}),
            &home,
        );
        assert_eq!(result["wire_upload"]["offset"], index * CHUNK + chunk.len());
    }
    let mut result = run("wire_finish", json!({"handle":token}), &home);
    let token = result["wire_download"]["handle"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut bytes = Vec::new();
    loop {
        let page = &result["wire_download"];
        assert_eq!(page["offset"], bytes.len());
        bytes.extend(Base64::decode_vec(page["bytes"].as_str().unwrap()).unwrap());
        if page["total"] == bytes.len() {
            break;
        }
        result = run(
            "wire_read",
            json!({"handle":token,"offset":bytes.len()}),
            &home,
        );
    }
    let decoded: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(decoded["ok"], serde_json::to_string(&text).unwrap());
    assert_eq!(
        request("wire_read", json!({"handle":token,"offset":0}), &home)["status"],
        "error"
    );
}

#[test]
fn incomplete_or_wrong_digest_uploads_never_reach_document_evaluation() {
    let home = std::env::temp_dir()
        .join("guard-document-wire-rejection")
        .to_string_lossy()
        .into_owned();
    for size in [1, 0] {
        let start = run(
            "wire_start",
            json!({"query":"canonical","size":size,"sha256":"0".repeat(64)}),
            &home,
        );
        assert_eq!(
            request(
                "wire_finish",
                json!({"handle":start["wire_upload"]["handle"]}),
                &home
            )["status"],
            "error"
        );
    }
    assert_eq!(
        request(
            "wire_start",
            json!({"query":"canonical","size":LIMIT+1,"sha256":"0".repeat(64)}),
            &home
        )["status"],
        "error"
    );
}
