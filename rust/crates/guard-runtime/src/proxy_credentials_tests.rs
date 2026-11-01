use super::*;
use guard_command::egress_caller::EgressProxyCredentials;

fn run(request: &str) -> Result<Value, String> {
    run_command(request.as_bytes()).map(|bytes| serde_json::from_slice(&bytes).expect("json"))
}

#[test]
fn every_store_outcome_has_one_answer_shape() {
    assert_eq!(answer(Ok(None)), json!({"ok": true, "credentials": null}));
    assert_eq!(
        answer(Ok(Some(EgressProxyCredentials {
            username: "svc".to_owned(),
            password: "p@ss word".to_owned(),
        }))),
        json!({"ok": true, "credentials": {"username": "svc", "password": "p@ss word"}})
    );
    assert_eq!(
        answer(Err("managed_proxy_credentials_invalid")),
        json!({"ok": false, "reason_code": "managed_proxy_credentials_invalid"})
    );
}

#[test]
fn a_request_must_name_the_schema_and_a_proxy() {
    for request in [
        r#"{"schema":"proxy-credentials.v2","proxy_url":"http://proxy:8080"}"#,
        r#"{"schema":"proxy-credentials.v1","proxy_url":""}"#,
        r#"{"schema":"proxy-credentials.v1"}"#,
        r#"{"schema":"proxy-credentials.v1","proxy_url":"http://proxy:8080","account":"x"}"#,
        "not json",
    ] {
        assert_eq!(
            run(request).err().as_deref(),
            Some("proxy_credentials_request_invalid"),
            "{request}"
        );
    }
    let oversized = format!(
        r#"{{"schema":"proxy-credentials.v1","proxy_url":"{}"}}"#,
        "a".repeat(17 * 1024)
    );
    assert_eq!(
        run(&oversized).err().as_deref(),
        Some("proxy_credentials_request_too_large")
    );
}
