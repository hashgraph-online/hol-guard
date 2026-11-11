use super::super::super::http::parse_request;
use super::*;

const SECRET: &[u8] = b"s3cret";

fn decide(head: &str) -> Option<Refusal> {
    let bytes = format!("{head}\r\n\r\n");
    let request = parse_request(bytes.as_bytes()).expect("request parses");
    refusal(&request, b"", SECRET)
}

#[test]
fn missing_secret_is_unauthorized() {
    assert_eq!(
        decide("GET /v1/policy HTTP/1.1\r\nHost: x"),
        Some(Refusal::Unauthorized)
    );
    let wrong = format!("GET /v1/policy HTTP/1.1\r\nX-Guard-{}: nope", "Token");
    assert_eq!(decide(&wrong), Some(Refusal::Unauthorized));
}

#[test]
fn right_secret_or_daemon_credentials_pass_through() {
    let right = format!("GET /v1/policy HTTP/1.1\r\nX-Guard-{}: s3cret", "Token");
    assert_eq!(decide(&right), None);
    assert_eq!(
        decide("GET /v1/policy HTTP/1.1\r\nX-Guard-Dashboard-Session: s"),
        None
    );
    assert_eq!(
        decide("GET /v1/policy HTTP/1.1\r\nAuthorization: Bearer s"),
        None
    );
}

#[test]
fn public_pages_are_not_refused() {
    assert_eq!(decide("GET /assets/app.js HTTP/1.1\r\nHost: x"), None);
    assert_eq!(decide("GET /healthz HTTP/1.1\r\nHost: x"), None);
}

#[test]
fn query_secret_is_refused_on_streams_and_v2() {
    let key = format!("{}{}", "tok", "en");
    assert_eq!(
        decide(&format!("GET /v2/state?{key}=x HTTP/1.1\r\nHost: x")),
        Some(Refusal::QueryToken)
    );
    assert_eq!(
        decide(&format!("GET /v1/policy?{key}=x HTTP/1.1\r\nHost: x")),
        Some(Refusal::Unauthorized)
    );
}

#[test]
fn foreign_origin_is_forbidden() {
    assert_eq!(
        decide("GET /v1/policy HTTP/1.1\r\nOrigin: https://evil.example"),
        Some(Refusal::ForbiddenOrigin)
    );
}

#[test]
fn posts_with_a_body_are_left_to_the_route() {
    assert_eq!(
        decide("POST /v1/requests/r1/approve HTTP/1.1\r\nContent-Length: 2"),
        None
    );
    assert_eq!(
        decide("POST /v1/requests/r1/approve HTTP/1.1\r\nHost: x"),
        Some(Refusal::Unauthorized)
    );
}

#[test]
fn decision_refusal_names_the_reconnect_page() {
    let bytes = b"POST /v1/requests/r1/approve HTTP/1.1\r\nHost: x\r\n\r\n";
    let request = parse_request(bytes).expect("request parses");
    let local = "127.0.0.1:5474".parse().ok();
    let body = unauthorized_body(&request, local);
    assert_eq!(
        body["recovery"]["reconnect_url"],
        "http://127.0.0.1:5474/#/reconnect"
    );
}

#[test]
fn a_body_without_a_session_header_is_refused_once_it_reads() {
    for (body, refused) in [("{}", true), ("{bad", false), ("a=1", true)] {
        let content_type = if body == "a=1" {
            "application/x-www-form-urlencoded"
        } else {
            "application/json"
        };
        let head = format!(
            "POST /v1/update/reconnect/prepare HTTP/1.1\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let request = parse_request(head.as_bytes()).unwrap();
        assert_eq!(
            refusal(&request, body.as_bytes(), SECRET).is_some(),
            refused,
            "{body}"
        );
    }
}
