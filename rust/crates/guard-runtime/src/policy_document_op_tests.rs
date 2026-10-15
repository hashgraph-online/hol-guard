use guard_contracts::{
    RequestContextKindV1, RequestContextPolicyDocumentV1, RequestContextRequestV1,
    RequestContextSourceV1, REQUEST_CONTEXT_REQUEST_SCHEMA,
};
use serde_json::{json, Value};

fn request(input: Value) -> RequestContextRequestV1 {
    #[cfg(unix)]
    let owner_uid = Some(nix::unistd::geteuid().as_raw());
    #[cfg(not(unix))]
    let owner_uid = None;
    RequestContextRequestV1 {
        schema: REQUEST_CONTEXT_REQUEST_SCHEMA.into(),
        request_id: "document-fixture".into(),
        guard_home: std::env::temp_dir()
            .join("guard-document-home")
            .to_string_lossy()
            .into_owned(),
        source: RequestContextSourceV1::DirectCommand,
        budget_ms: 500,
        owner_uid,
        action: RequestContextKindV1::PolicyDocument(RequestContextPolicyDocumentV1 {
            query: "canonical".into(),
            input,
        }),
    }
}

fn run(request: &RequestContextRequestV1) -> Value {
    serde_json::from_slice(
        &crate::request_context_op::evaluate_request_context_request(request).unwrap(),
    )
    .unwrap()
}

#[test]
fn document_projection_requires_admission_and_binds_its_exact_input() {
    let mut request = request(json!({"value":{"private":"fixture-only"}}));
    let first = run(&request);
    assert_eq!(first["status"], "ok");
    assert_eq!(first["payload"]["kind"], "policy_document");
    assert_eq!(first["request_id"], request.request_id);
    request.action = RequestContextKindV1::PolicyDocument(RequestContextPolicyDocumentV1 {
        query: "canonical".into(),
        input: json!({"value":{"private":"different-fixture"}}),
    });
    assert_ne!(first["request_sha256"], run(&request)["request_sha256"]);
    request.budget_ms = 0;
    assert_eq!(
        run(&request)["code"],
        "native_request_context_budget_invalid"
    );
    request.budget_ms = 500;
    #[cfg(unix)]
    {
        request.owner_uid = None;
    }
    #[cfg(not(unix))]
    {
        request.owner_uid = Some(1);
    }
    assert_eq!(
        run(&request)["code"],
        "native_request_context_owner_mismatch"
    );
}
