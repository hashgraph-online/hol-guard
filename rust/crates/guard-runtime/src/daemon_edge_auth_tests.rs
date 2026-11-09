use super::super::http::{parse_get, parse_request};
use super::*;
use serde_json::json;

const TOKEN: &[u8] = b"edge-auth-test-token";

fn session(claims: &Value, key: &[u8]) -> String {
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(payload.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("{SESSION_PREFIX}.{payload}.{signature}")
}

fn dashboard_claims() -> Value {
    json!({
        "aud": SESSION_AUDIENCE,
        "version": "guard-local-daemon-session.v1",
        "surface": "dashboard",
        "expires_at": "2999-01-01T00:00:00+00:00",
        "session_started_at": "2026-01-01T00:00:00+00:00",
    })
}

fn allows(head: &str) -> Option<Option<String>> {
    let head = format!("{head}\r\n\r\n");
    let request = parse_get(head.as_bytes()).unwrap();
    authorize(&request, TOKEN).map(|caller| caller.cors_origin)
}

#[test]
fn normalizes_origins_as_the_daemon_does_or_not_at_all() {
    // Each `Some` is what the daemon's `_normalize_origin` returns for the
    // same text. A `None` the daemon would accept only sends the request to
    // the daemon.
    for (raw, expected) in [
        ("http://127.0.0.1:5474", Some("http://127.0.0.1:5474")),
        ("http://127.0.0.1:5474/", Some("http://127.0.0.1:5474")),
        ("http://LocalHost:080", Some("http://localhost")),
        ("https://hol.org:443", Some("https://hol.org")),
        (" http://[::1]:9 ", Some("http://[::1]:9")),
        ("http://[::1]", Some("http://[::1]")),
        ("http://127.0.0.1:0", Some("http://127.0.0.1:0")),
        ("http://[::FFFF:7f00:1]:80", Some("http://[::ffff:7f00:1]")),
        ("http://127.0.0.1:65536", None),
        ("http://u@127.0.0.1", None),
        ("http://127.0.0.1/x", None),
        ("ftp://127.0.0.1", None),
        ("http://127.0.0.1:", None),
        ("http://127.0.0.1:5474?", None),
        ("HTTP://127.0.0.1", None),
        ("http://", None),
    ] {
        assert_eq!(normalize_origin(raw).as_deref(), expected, "{raw}");
    }
}

#[test]
fn takes_the_daemon_token_from_any_allowed_origin() {
    let token = std::str::from_utf8(TOKEN).unwrap();
    assert_eq!(
        allows(&format!(
            "GET /v1/receipts HTTP/1.1\r\nX-Guard-Token: {token}"
        )),
        Some(None)
    );
    assert_eq!(
        allows(&format!(
            "GET /v1/receipts HTTP/1.1\r\nOrigin: http://127.0.0.1:5474/\r\nX-Guard-Token: {token}"
        )),
        Some(Some("http://127.0.0.1:5474".to_owned()))
    );
    for head in [
        // The daemon reads trailing blanks as part of the token.
        format!("GET /v1/receipts HTTP/1.1\r\nX-Guard-Token: {token} "),
        format!("GET /v1/receipts HTTP/1.1\r\nX-Guard-Token: {token}\r\nX-Guard-Token: {token}"),
        format!("GET /v1/receipts HTTP/1.1\r\nOrigin: https://evil.test\r\nX-Guard-Token: {token}"),
        format!("GET /v1/receipts HTTP/1.1\r\nOrigin: null\r\nX-Guard-Token: {token}"),
        format!(
            "GET /v1/receipts HTTP/1.1\r\nOrigin: http://127.0.0.1\r\nOrigin: http://127.0.0.1\r\nX-Guard-Token: {token}"
        ),
        // A hosted origin reaches only the hosted dashboard API.
        format!("GET /v1/healthz/details HTTP/1.1\r\nOrigin: https://hol.org\r\nX-Guard-Token: {token}"),
        "GET /v1/receipts HTTP/1.1\r\nX-Guard-Token: wrong".to_owned(),
    ] {
        assert_eq!(allows(&head), None, "{head}");
    }
}

#[test]
fn takes_a_signed_dashboard_session_from_either_header() {
    let token = session(&dashboard_claims(), TOKEN);
    for head in [
        format!("GET /v1/receipts HTTP/1.1\r\nX-Guard-Dashboard-Session: {token}"),
        format!("GET /v1/read-state HTTP/1.1\r\nAuthorization: bearer   {token} "),
        format!("GET /v1/receipts HTTP/1.1\r\nX-Guard-Token: wrong\r\nX-Guard-Dashboard-Session: {token}"),
        format!(
            "GET /v1/receipts HTTP/1.1\r\nX-Guard-Dashboard-Session: junk\r\nAuthorization: Bearer {token}"
        ),
    ] {
        assert_eq!(allows(&head), Some(None), "{head}");
    }
    assert_eq!(
        allows(&format!(
            "GET /v1/receipts/latest HTTP/1.1\r\nOrigin: http://localhost:5474\r\nX-Guard-Dashboard-Session: {token}"
        )),
        Some(Some("http://localhost:5474".to_owned()))
    );
}

#[test]
fn leaves_every_other_session_to_the_daemon() {
    let signed = |claims: Value| session(&claims, TOKEN);
    let mut expired = dashboard_claims();
    expired["expires_at"] = json!("2000-01-01T00:00:00Z");
    let mut naive = dashboard_claims();
    naive["expires_at"] = json!("2999-01-01T00:00:00");
    let mut audience = dashboard_claims();
    audience["aud"] = json!("guard-cloud");
    let mut bound = dashboard_claims();
    bound["surface"] = json!("approval-center");
    bound["request_id"] = json!("req-1");
    let scoped = json!({
        "aud": SESSION_AUDIENCE,
        "expires_at": "2999-01-01T00:00:00+00:00",
        "action_path": "status",
        "allowed_read_paths": ["/v1/receipts"],
        "nonce": "n-1",
    });
    let valid = signed(dashboard_claims());
    for (path, token) in [
        ("/v1/receipts", signed(expired)),
        ("/v1/receipts", signed(naive)),
        ("/v1/receipts", signed(audience)),
        (
            "/v1/receipts",
            session(&dashboard_claims(), b"another-token"),
        ),
        ("/v1/receipts", format!("{valid}.extra")),
        ("/v1/receipts", valid.replacen("gld1", "gld2", 1)),
        ("/v1/receipts", format!("{valid} ")),
        // A session bound to one request may not pull exports; nor may any
        // session read a path that takes the daemon token alone.
        ("/v1/evidence/export", signed(bound)),
        ("/v1/healthz/details", valid.clone()),
        // Its nonce is not in the request, so the daemon refuses it.
        ("/v1/receipts", signed(scoped.clone())),
    ] {
        let head = format!("GET {path} HTTP/1.1\r\nX-Guard-Dashboard-Session: {token}");
        assert_eq!(allows(&head), None, "{head}");
    }
    let nonce_head = format!(
        "GET /v1/receipts HTTP/1.1\r\nX-Guard-Dashboard-Nonce: n-1\r\nX-Guard-Dashboard-Session: {}",
        signed(scoped.clone())
    );
    assert_eq!(allows(&nonce_head), Some(None));
    let repeated = format!(
        "GET /v1/receipts HTTP/1.1\r\nX-Guard-Dashboard-Session: {valid}\r\nX-Guard-Dashboard-Session: {valid}"
    );
    assert_eq!(allows(&repeated), None);
    let repeated_nonce = format!(
        "GET /v1/receipts HTTP/1.1\r\nX-Guard-Dashboard-Nonce: n-1\r\nX-Guard-Dashboard-Nonce: n-1\r\nX-Guard-Dashboard-Session: {}",
        signed(scoped)
    );
    assert_eq!(allows(&repeated_nonce), None);
}

fn writes(head: &str) -> bool {
    let head = format!("{head}\r\n\r\n");
    let request = parse_request(head.as_bytes()).unwrap();
    authorize_write(&request, TOKEN).is_some()
}

fn post_with(claims: &Value, path: &str) -> String {
    let header = session(claims, TOKEN);
    format!("POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Guard-Dashboard-Session: {header}")
}

#[test]
fn takes_a_dashboard_session_for_the_writes_it_opens() {
    let path = "/v1/requests/req-1/approve";
    assert!(session_path("POST", path));
    assert!(writes(&post_with(&dashboard_claims(), path)));
    let mut approval_center = dashboard_claims();
    approval_center["surface"] = json!("approval-center");
    assert!(writes(&post_with(&approval_center, path)));
    // A path no session may write stays with the key alone.
    assert!(!session_path("POST", "/v1/daemon/stop"));
    assert!(!writes(&post_with(&dashboard_claims(), "/v1/daemon/stop")));
}

#[test]
fn leaves_link_bound_repair_and_scoped_sessions_to_the_daemon() {
    let path = "/v1/requests/req-1/approve";
    for (key, value) in [
        ("request_id", json!("req-1")),
        ("request_id", json!("")),
        ("surface", json!("protection-repair")),
        ("surface", json!("package-firewall")),
        ("aud", json!("someone-else")),
        ("expires_at", json!("2000-01-01T00:00:00+00:00")),
    ] {
        let mut claims = dashboard_claims();
        claims[key] = value;
        assert!(!writes(&post_with(&claims, path)), "{key}");
    }
    let forged = session(&dashboard_claims(), b"another-daemon");
    assert!(!writes(&format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Guard-Dashboard-Session: {forged}"
    )));
    let mut null_bound = dashboard_claims();
    null_bound["request_id"] = Value::Null;
    assert!(writes(&post_with(&null_bound, path)));
}
