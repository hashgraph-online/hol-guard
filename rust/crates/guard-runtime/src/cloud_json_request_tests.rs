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
    assert_eq!(
        origin("https://hol.org:443/api"),
        Some("https://hol.org".to_owned())
    );
    assert_eq!(
        origin("http://127.0.0.1:80/api"),
        Some("http://127.0.0.1".to_owned())
    );
    assert_eq!(
        origin("https://hol.org:8443/api"),
        Some("https://hol.org:8443".to_owned())
    );
    assert_eq!(origin("https:///path"), None);
    assert_eq!(origin("https://:443/path"), None);
    assert_eq!(origin("hol.org/path"), None);
}

#[test]
fn an_answer_must_be_an_object() {
    assert_eq!(
        accepted(json!({"ok": true})),
        Ok(json!({"response": {"ok": true}}))
    );
    assert_eq!(
        accepted(json!([1])),
        Err(SyncError::Failed(INVALID_RESPONSE.to_owned()))
    );
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
        "headers": {"Authorization": "x"},
    }));
    assert!(parsed.is_err());
}

#[test]
fn only_get_and_post_are_accepted() {
    let parse = |method: &str| {
        serde_json::from_value::<JsonRequest>(json!({
            "url": "https://hol.org/x",
            "method": method,
            "timeoutSeconds": 1.0,
            "retryTimeoutSeconds": 1.0,
        }))
    };
    assert_eq!(parse("GET").unwrap().method, Method::Get);
    assert_eq!(parse("POST").unwrap().method, Method::Post);
    assert!(parse("DELETE").is_err());
    assert!(parse("get").is_err());
}

#[test]
fn a_post_needs_a_body_and_a_get_carries_none() {
    let auth = auth("https://hol.org/api/guard/receipts/sync");
    for (method, body) in [("POST", None), ("GET", Some("{}"))] {
        let request: JsonRequest = serde_json::from_value(json!({
            "url": "https://hol.org/api/guard/policy/delivery",
            "method": method,
            "body": body,
            "timeoutSeconds": 1.0,
            "retryTimeoutSeconds": 1.0,
        }))
        .unwrap();
        let answer = send(Some(&auth), &request);
        assert!(
            matches!(answer, Err(SyncError::Failed(_))),
            "{method}: {answer:?}"
        );
    }
}

fn post_with(fields: Value) -> JsonRequest {
    let mut request = json!({
        "url": "https://hol.org/api/guard/extensions/catalog",
        "method": "POST",
        "timeoutSeconds": 1.0,
        "retryTimeoutSeconds": 1.0,
    });
    if let (Some(target), Value::Object(extra)) = (request.as_object_mut(), fields) {
        target.extend(extra);
    }
    serde_json::from_value(request).unwrap()
}

#[test]
fn a_body_file_is_read_byte_for_byte() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("page.json");
    fs::write(&path, b"{\"page\":1}").unwrap();
    let request = post_with(json!({"bodyFile": path.to_str().unwrap()}));
    assert_eq!(
        request_body(&request).unwrap().as_deref(),
        Some(&b"{\"page\":1}"[..])
    );
}

#[test]
fn a_post_carries_one_body_and_a_get_no_body_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("page.json");
    fs::write(&path, b"{}").unwrap();
    let file = path.to_str().unwrap();
    let both = post_with(json!({"body": "{}", "bodyFile": file}));
    assert!(matches!(request_body(&both), Err(SyncError::Failed(_))));
    let mut get = post_with(json!({"bodyFile": file}));
    get.method = Method::Get;
    assert!(matches!(request_body(&get), Err(SyncError::Failed(_))));
}

#[test]
fn a_body_file_must_be_an_absolute_regular_file_within_the_limit() {
    let dir = tempfile::tempdir().unwrap();
    let relative = post_with(json!({"bodyFile": "page.json"}));
    assert!(matches!(request_body(&relative), Err(SyncError::Failed(_))));
    let directory = post_with(json!({"bodyFile": dir.path().to_str().unwrap()}));
    assert!(matches!(
        request_body(&directory),
        Err(SyncError::Failed(_))
    ));
    let missing = dir.path().join("missing.json");
    let missing = post_with(json!({"bodyFile": missing.to_str().unwrap()}));
    assert!(matches!(request_body(&missing), Err(SyncError::Failed(_))));
    let large = dir.path().join("large.json");
    fs::write(
        &large,
        vec![b'x'; EGRESS_MAX_IN_PROCESS_NEED_BODY_BYTES + 1],
    )
    .unwrap();
    let large = post_with(json!({"bodyFile": large.to_str().unwrap()}));
    assert!(matches!(request_body(&large), Err(SyncError::Failed(_))));
}

#[cfg(unix)]
#[test]
fn a_body_file_link_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("page.json");
    fs::write(&target, b"{}").unwrap();
    let link = dir.path().join("link.json");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let request = post_with(json!({"bodyFile": link.to_str().unwrap()}));
    assert!(matches!(request_body(&request), Err(SyncError::Failed(_))));
}

#[test]
fn a_request_reads_json_unless_it_asks_for_the_raw_answer() {
    assert_eq!(request("https://hol.org/api").answer, Answer::Json);
    let raw: JsonRequest = serde_json::from_value(json!({
        "url": "https://hol.org/api",
        "method": "GET",
        "answer": "raw",
        "timeoutSeconds": 5.0,
        "retryTimeoutSeconds": 5.0,
    }))
    .unwrap();
    assert_eq!(raw.answer, Answer::Raw);
    let unknown = serde_json::from_value::<JsonRequest>(json!({
        "url": "https://hol.org/api",
        "answer": "text",
        "timeoutSeconds": 5.0,
        "retryTimeoutSeconds": 5.0,
    }));
    assert!(unknown.is_err());
}

#[test]
fn a_raw_answer_keeps_the_status_and_an_empty_body() {
    assert_eq!(
        raw(204, Vec::new(), None).unwrap(),
        json!({"raw": {"status": 204, "body": ""}})
    );
    assert_eq!(
        raw(200, b"{\"ok\":true}".to_vec(), None).unwrap(),
        json!({"raw": {"status": 200, "body": "{\"ok\":true}"}})
    );
}

#[test]
fn a_raw_answer_that_is_not_utf8_is_invalid() {
    assert!(matches!(
        raw(200, vec![0xff, 0xfe], None),
        Err(SyncError::Failed(reason)) if reason == INVALID_RESPONSE
    ));
}

#[test]
fn raw_reports_a_body_over_the_callers_limit_as_oversized() {
    assert_eq!(
        raw(200, vec![b'x'; 5], Some(4)).unwrap(),
        json!({"raw": {"status": 200, "oversized": true}})
    );
    assert_eq!(
        raw(200, b"abcd".to_vec(), Some(4)).unwrap(),
        json!({"raw": {"status": 200, "body": "abcd"}})
    );
}
