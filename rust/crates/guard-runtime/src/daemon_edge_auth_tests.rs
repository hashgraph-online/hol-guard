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
fn writes_as_the_session_verdict_decides() {
    let path = "/v1/requests/req-1/approve";
    for (key, value, allowed) in [
        ("surface", json!("protection-repair"), false),
        ("surface", json!("package-firewall"), false),
        ("aud", json!("someone-else"), false),
        ("expires_at", json!("2000-01-01T00:00:00+00:00"), false),
    ] {
        let mut claims = dashboard_claims();
        claims[key] = value;
        assert_eq!(writes(&post_with(&claims, path)), allowed, "{key}");
    }
    // A session opened from an approval link decides its own request only.
    for (bound, allowed) in [("req-1", true), ("req-2", false)] {
        let mut claims = dashboard_claims();
        claims["surface"] = json!("approval-center");
        claims["request_id"] = json!(bound);
        assert_eq!(writes(&post_with(&claims, path)), allowed, "{bound}");
    }
    let forged = session(&dashboard_claims(), b"another-daemon");
    assert!(!writes(&format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Guard-Dashboard-Session: {forged}"
    )));
    let mut null_bound = dashboard_claims();
    null_bound["request_id"] = Value::Null;
    assert!(writes(&post_with(&null_bound, path)));
}

fn initialize_request(head: &str) -> String {
    format!("POST /v1/initialize HTTP/1.1\r\nHost: 127.0.0.1\r\n{head}\r\n\r\n")
}

#[test]
fn initializes_for_any_allowed_origin_with_sessions_for_the_key_alone() {
    let initializes = |head: &str| {
        let head = initialize_request(head);
        authorize_initialize(&parse_request(head.as_bytes()).unwrap(), TOKEN)
            .map(|(_, holds_key)| holds_key)
    };
    let header = std::str::from_utf8(TOKEN).unwrap();
    assert_eq!(
        initializes(&format!("X-Guard-To{}: {header}", "ken")),
        Some(true)
    );
    assert_eq!(initializes("Origin: http://127.0.0.1:5474"), Some(false));
    // `initialize` is no session path, so a session shows no sessions.
    assert_eq!(
        initializes(&format!(
            "X-Guard-Dashboard-Session: {}",
            session(&dashboard_claims(), TOKEN)
        )),
        Some(false)
    );
    assert_eq!(initializes("Origin: https://evil.example"), None);
}

fn refreshed(claims: &Value, surface: &str) -> Option<Map<String, Value>> {
    let head = initialize_request(&format!(
        "X-Guard-Dashboard-Session: {}",
        session(claims, TOKEN)
    ));
    let fresh = refreshed_session(&parse_request(head.as_bytes()).unwrap(), TOKEN, surface)?;
    let claims = verified_payload(&fresh, TOKEN, now_micros()).expect("signed for the daemon");
    let order: Vec<&str> = claims.keys().map(String::as_str).collect();
    let mut expected = vec![
        "aud",
        "expires_at",
        "session_started_at",
        "surface",
        "version",
    ];
    expected.sort_unstable();
    let mut sorted = order.clone();
    sorted.sort_unstable();
    assert_eq!(sorted, expected);
    Some(claims)
}

fn iso(micros: i128) -> String {
    micros_to_utc_isoformat(i64::try_from(micros).unwrap(), "+00:00").unwrap()
}

#[test]
fn refreshes_a_local_session_within_its_week() {
    let now = now_micros();
    let mut claims = dashboard_claims();
    claims["session_started_at"] = json!(iso(now - 3_600_000_000));
    // A session that expired an hour ago still refreshes.
    claims["expires_at"] = json!(iso(now - 3_600_000_000));
    let fresh = refreshed(&claims, "approval-center").expect("refreshed");
    assert_eq!(fresh["surface"], json!("approval-center"));
    assert_eq!(fresh["session_started_at"], claims["session_started_at"]);
    let expires = aware_epoch_micros(fresh["expires_at"].as_str().unwrap()).unwrap();
    assert!((expires - now - SESSION_TTL_MICROS).abs() < 60_000_000);
    // A surface the dashboard does not name refreshes as the dashboard.
    assert_eq!(
        refreshed(&claims, "cli").unwrap()["surface"],
        json!("dashboard")
    );
    // Repair stays repair, whatever surface initialize names.
    let mut repair = claims.clone();
    repair["surface"] = json!("protection-repair");
    assert_eq!(
        refreshed(&repair, "dashboard").unwrap()["surface"],
        json!("protection-repair")
    );
    // Near the end of the week, the refreshed session ends with it.
    let mut late = claims.clone();
    late["session_started_at"] = json!(iso(now - SESSION_MAX_AGE_MICROS + 600_000_000));
    let expires = aware_epoch_micros(
        refreshed(&late, "dashboard").unwrap()["expires_at"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert!((expires - now - 600_000_000).abs() < 60_000_000);
    // With no start claim, the start is twelve hours before its expiry.
    let mut unstarted = claims.clone();
    unstarted
        .as_object_mut()
        .unwrap()
        .remove("session_started_at");
    let fresh = refreshed(&unstarted, "dashboard").unwrap();
    assert_eq!(
        fresh["session_started_at"],
        json!(iso(now - 3_600_000_000 - SESSION_TTL_MICROS))
    );
}

#[test]
fn refreshes_no_bound_scoped_or_spent_session() {
    let now = now_micros();
    let mut claims = dashboard_claims();
    claims["session_started_at"] = json!(iso(now - 3_600_000_000));
    let mut bound = claims.clone();
    bound["request_id"] = json!("req-1");
    assert!(refreshed(&bound, "dashboard").is_none());
    let mut scoped = claims.clone();
    scoped["surface"] = json!("package-firewall");
    assert!(refreshed(&scoped, "dashboard").is_none());
    let mut spent = claims.clone();
    spent["session_started_at"] = json!(iso(now - SESSION_MAX_AGE_MICROS));
    assert!(refreshed(&spent, "dashboard").is_none());
    let mut stale = claims;
    stale["expires_at"] = json!(iso(now - REFRESH_GRACE_MICROS - 60_000_000));
    assert!(refreshed(&stale, "dashboard").is_none());
}

#[test]
fn signs_a_session_as_the_daemon_writes_one() {
    let fresh = signed_session(TOKEN, "dashboard", 0, "2026-01-01T00:00:00+00:00\u{e9}").unwrap();
    let payload = fresh.split('.').nth(1).unwrap();
    let decoded = String::from_utf8(URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
    assert_eq!(
        decoded,
        "{\"aud\":\"guard-local-daemon\",\"version\":\"guard-local-daemon-session.v1\",\"surface\":\"dashboard\",\"expires_at\":\"1970-01-01T00:00:00+00:00\",\"session_started_at\":\"2026-01-01T00:00:00+00:00\\u00e9\"}"
    );
}

#[test]
fn takes_a_local_session_for_session_and_operation_writes() {
    let writes = |claims: &Value, path: &str| {
        let head = format!("{}\r\n\r\n", post_with(claims, path));
        authorize_session_write(&parse_request(head.as_bytes()).unwrap(), TOKEN).is_some()
    };
    let mut approval_center = dashboard_claims();
    approval_center["surface"] = json!("approval-center");
    assert!(writes(&approval_center, "/v1/sessions/start"));
    assert!(writes(&dashboard_claims(), "/v1/operations/op-1/status"));
    let mut repair = dashboard_claims();
    repair["surface"] = json!("protection-repair");
    assert!(!writes(&repair, "/v1/sessions/start"));
    let mut bound = approval_center.clone();
    bound["request_id"] = json!("req-1");
    assert!(!writes(&bound, "/v1/sessions/start"));
}
