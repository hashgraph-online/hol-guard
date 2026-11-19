use super::*;

fn auth(sync_url: &str) -> Map<String, Value> {
    Map::from_iter([("sync_url".to_owned(), json!(sync_url))])
}

fn request(url: &str) -> JsonRequest {
    serde_json::from_value(json!({
        "url": url,
        "body": "{\"protocolVersion\":2}",
        "timeoutSeconds": 5.0,
        "retryTimeoutSeconds": 5.0,
    }))
    .unwrap()
}

#[test]
fn a_request_without_a_sign_in_is_not_configured() {
    let answer = send(None, &request("https://hol.org/api/guard/commands/lease"));
    assert!(
        matches!(answer, Err(SyncError::NotConfigured(_))),
        "{answer:?}"
    );
}

#[test]
fn a_request_to_another_origin_never_carries_the_sign_in() {
    let auth = auth("https://hol.org/api/guard/receipts/sync");
    for url in [
        "https://cloud.example.invalid/api/guard/commands/lease",
        "http://127.0.0.1:9/api/guard/commands/lease",
        "https://hol.org.example.invalid/api/guard/commands/lease",
        "not a url",
    ] {
        let answer = send(Some(&auth), &request(url));
        assert!(
            matches!(answer, Err(SyncError::EndpointUntrusted(_))),
            "{url}: {answer:?}"
        );
    }
}

#[test]
fn an_untrusted_sync_url_is_refused_before_any_request() {
    let auth = auth("https://cloud.example.invalid/api/guard/receipts/sync");
    let answer = send(
        Some(&auth),
        &request("https://cloud.example.invalid/api/guard/commands/lease"),
    );
    assert!(
        matches!(answer, Err(SyncError::EndpointUntrusted(_))),
        "{answer:?}"
    );
}

#[test]
fn the_same_origin_passes_the_endpoint_check() {
    let auth = auth("https://hol.org/api/guard/receipts/sync");
    assert_eq!(
        check_endpoint(&auth, "https://HOL.org/api/guard/review/v2/events:batch"),
        Ok(())
    );
}

#[test]
fn origin_is_scheme_and_authority() {
    assert_eq!(
        origin("https://hol.org/api/guard?x=1"),
        Some("https://hol.org".to_owned())
    );
    assert_eq!(
        origin("http://127.0.0.1:8080"),
        Some("http://127.0.0.1:8080".to_owned())
    );
    assert_eq!(origin("https:///path"), None);
    assert_eq!(origin("hol.org/path"), None);
}

#[test]
fn an_answer_must_be_an_object_within_its_budget() {
    assert_eq!(
        accepted(json!({"ok": true}), None),
        Ok(json!({"response": {"ok": true}}))
    );
    assert_eq!(
        accepted(json!([1]), None),
        Err(SyncError::Failed(INVALID_RESPONSE.to_owned()))
    );
    assert_eq!(
        accepted(json!({"ok": true}), Some(11)),
        Ok(json!({"response": {"ok": true}}))
    );
    assert!(matches!(
        accepted(json!({"ok": true}), Some(10)),
        Err(SyncError::Failed(message)) if message.contains("byte budget")
    ));
}

#[test]
fn a_transport_failure_says_whether_it_timed_out_or_was_an_outage() {
    assert_eq!(
        transport("timeout: 5s"),
        json!({"transport": {"reason": "timeout: 5s", "timeout": true, "outage": true}})
    );
    assert_eq!(
        transport("host not found"),
        json!({"transport": {"reason": "host not found", "timeout": false, "outage": true}})
    );
    assert_eq!(
        transport("tls"),
        json!({"transport": {"reason": "tls", "timeout": false, "outage": false}})
    );
}

#[test]
fn an_unknown_request_field_is_refused() {
    let parsed = serde_json::from_value::<JsonRequest>(json!({
        "url": "https://hol.org/x",
        "body": "{}",
        "timeoutSeconds": 1.0,
        "retryTimeoutSeconds": 1.0,
        "method": "DELETE",
    }));
    assert!(parsed.is_err());
}
