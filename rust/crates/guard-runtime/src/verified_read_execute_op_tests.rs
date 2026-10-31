use super::*;

fn request(argv: &[&str], cwd: &str) -> VerifiedReadExecuteRequestV1 {
    VerifiedReadExecuteRequestV1 {
        schema: VERIFIED_READ_EXECUTE_REQUEST_SCHEMA.to_owned(),
        request_id: "req-1".to_owned(),
        query: VerifiedReadExecuteQueryV1::Local {
            argv: argv.iter().map(|value| (*value).to_owned()).collect(),
            cwd: cwd.to_owned(),
            home_dir: None,
        },
    }
}

fn decode(request: &VerifiedReadExecuteRequestV1) -> VerifiedReadExecuteResultV1 {
    serde_json::from_slice(&evaluate_verified_read_execute(request).unwrap()).unwrap()
}

#[test]
fn a_foreign_schema_is_refused_before_anything_is_read() {
    let mut request = request(&["pwd"], "/");
    request.schema = "guard-verified-read-execute-request.v0".to_owned();
    let result = decode(&request);
    assert_eq!(result.status, "error");
    assert_eq!(result.code, "native_verified_read_execute_schema_mismatch");
    assert_eq!(result.request_id, "req-1");
    assert!(result.request_sha256.starts_with("sha256:"));
    assert!(result.payload.is_none());
}

#[test]
fn an_oversized_request_fails_closed() {
    let long = "a".repeat(VERIFIED_READ_EXECUTE_MAX_BYTES);
    let error = evaluate_verified_read_execute(&request(&["head", "-1", &long], "/")).unwrap_err();
    assert_eq!(error, "native_verified_read_execute_request_too_large");
}

#[test]
fn an_argv_outside_the_cohort_is_refused() {
    let result = decode(&request(&["cat", "README.md"], "/"));
    assert_eq!(result.status, "error");
    #[cfg(unix)]
    assert_eq!(result.code, "native_verified_read_execute_refused");
    #[cfg(not(unix))]
    assert_eq!(result.code, "native_verified_read_execute_unsupported");
}

#[test]
fn the_request_digest_is_stable_for_the_same_request() {
    let first = decode(&request(&["pwd"], "/")).request_sha256;
    let second = decode(&request(&["pwd"], "/")).request_sha256;
    assert_eq!(first, second);
    assert_ne!(first, decode(&request(&["pwd"], "/tmp")).request_sha256);
}
