use std::collections::BTreeMap;

use serde_json::{json, Value};

use super::*;

fn respond(request: &[u8], proxies: BTreeMap<String, String>) -> Result<Value, String> {
    answer(request, || proxies).map(|bytes| serde_json::from_slice(&bytes).unwrap())
}

#[test]
fn the_answer_carries_the_platform_proxies() {
    let proxies = BTreeMap::from([("https".to_owned(), "http://proxy.example:443".to_owned())]);
    let request = serde_json::to_vec(&json!({"schema": SCHEMA})).unwrap();
    assert_eq!(
        respond(&request, proxies),
        Ok(json!({"ok": true, "proxies": {"https": "http://proxy.example:443"}}))
    );
    assert_eq!(
        respond(&request, BTreeMap::new()),
        Ok(json!({"ok": true, "proxies": {}}))
    );
}

#[test]
fn requests_with_another_schema_or_extra_fields_are_refused() {
    let invalid = Err("system_proxies_request_invalid".to_owned());
    for request in [
        json!({"schema": "other"}),
        json!({"schema": SCHEMA, "platform": "macos"}),
        json!([]),
    ] {
        let bytes = serde_json::to_vec(&request).unwrap();
        assert_eq!(respond(&bytes, BTreeMap::new()), invalid, "{request}");
    }
}

#[test]
fn an_oversized_request_is_refused() {
    let request = vec![b' '; usize::try_from(MAX_REQUEST_BYTES).unwrap() + 1];
    assert_eq!(
        respond(&request, BTreeMap::new()),
        Err("system_proxies_request_too_large".to_owned())
    );
}
