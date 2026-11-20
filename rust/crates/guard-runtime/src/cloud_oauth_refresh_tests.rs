use super::*;

fn call(token_endpoint: &str) -> RefreshCall {
    serde_json::from_value(json!({
        "tokenEndpoint": token_endpoint,
        "clientId": "client",
        "refreshToken": "grant",
        "dpopKey": {"privateKeyPem": "unused", "publicJwk": {}, "algorithm": "ES256"},
    }))
    .unwrap()
}

#[test]
fn an_endpoint_outside_the_allowlist_is_untrusted() {
    let answer = refresh(&call("https://cloud.example.invalid/api/guard/oauth/token"));
    assert!(matches!(answer, Err(SyncError::EndpointUntrusted(_))));
}

#[test]
fn a_trusted_origin_with_another_path_is_untrusted() {
    let answer = refresh(&call("https://hol.org/api/guard/other"));
    assert!(matches!(answer, Err(SyncError::EndpointUntrusted(_))));
}

#[test]
fn an_unknown_field_is_not_understood() {
    let parsed = serde_json::from_value::<RefreshCall>(json!({
        "tokenEndpoint": "https://hol.org/api/guard/oauth/token",
        "clientId": "client",
        "refreshToken": "grant",
        "dpopKey": {"privateKeyPem": "unused", "publicJwk": {}, "algorithm": "ES256"},
        "extra": true,
    }));
    assert!(parsed.is_err());
}

#[test]
fn an_unsignable_key_is_unusable() {
    let (_, _, endpoint, ..) = gst::resolve_guard_oauth_client_config("https://hol.org").unwrap();
    let answer = refresh(&call(&endpoint)).unwrap();
    assert_eq!(answer["outcome"], json!("unusable"));
}
