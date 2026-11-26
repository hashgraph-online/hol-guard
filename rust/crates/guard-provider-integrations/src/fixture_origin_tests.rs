use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::Duration;

use guard_command::egress_caller::{EgressPolicy, EgressProxy};
use zeroize::Zeroizing;

use super::*;
use crate::client::ProviderMethod;

const FIXTURE: &str = "provider.fixture-shield";
const STORED: &str = "kept-in-the-resident";

struct DirectPolicy;

impl EgressPolicy for DirectPolicy {
    fn validate(&self, _url: &str) -> Result<(), String> {
        Ok(())
    }

    fn proxy(&self, _url: &str) -> EgressProxy {
        EgressProxy::Direct
    }
}

fn request(path: &str) -> ProviderRequest {
    ProviderRequest {
        method: ProviderMethod::Post,
        host: "api.provider.exampleshield.test".to_owned(),
        path: path.to_owned(),
        header: "x-api-key".to_owned(),
        key: Zeroizing::new(STORED.to_owned()),
        body: Some(r#"{"target":"https://storefront.example.com/"}"#.to_owned()),
    }
}

const LIMITS: ProviderLimits = ProviderLimits {
    timeout_ms: 5000,
    max_response_bytes: 4096,
};

#[test]
fn only_a_plain_loopback_origin_is_accepted() {
    assert_eq!(
        FixtureOrigin::parse("http://127.0.0.1:8123").map(FixtureOrigin::port),
        Some(8123)
    );
    assert!(FixtureOrigin::parse("http://127.0.0.1:65535").is_some());
    for value in [
        "",
        "http://127.0.0.1",
        "http://127.0.0.1:",
        "http://127.0.0.1:0",
        "http://127.0.0.1:65536",
        "http://127.0.0.1:080000",
        "http://127.0.0.1:+80",
        "http://127.0.0.1:80/",
        "http://127.0.0.1:80/v1",
        "http://127.0.0.1:80?x=1",
        "http://127.0.0.1:80#x",
        "http://127.0.0.1:80 ",
        " http://127.0.0.1:80",
        "https://127.0.0.1:80",
        "HTTP://127.0.0.1:80",
        "http://localhost:80",
        "http://[::1]:80",
        "http://127.0.0.2:80",
        "http://127.1:80",
        "http://0x7f000001:80",
        "http://user@127.0.0.1:80",
        "http://127.0.0.1.example.test:80",
        "http://api.provider.exampleshield.test:80",
    ] {
        assert_eq!(FixtureOrigin::parse(value), None, "{value:?}");
    }
}

#[test]
fn only_the_reserved_prefix_is_a_fixture_provider() {
    assert!(is_fixture_provider(FIXTURE));
    for id in [
        "provider.fixture-",
        "provider.fixture",
        "provider.exampleshield",
        "provider.exampleshield-fixture-shield",
        "x.provider.fixture-shield",
        "",
    ] {
        assert!(!is_fixture_provider(id), "{id}");
    }
}

#[test]
fn the_fixture_origin_never_reroutes_another_provider() {
    let origin = FixtureOrigin::parse("http://127.0.0.1:8123");
    assert_eq!(
        route("provider.exampleshield", origin),
        Some(ProviderRoute::Pinned)
    );
    assert_eq!(
        route("provider.exampleshield", None),
        Some(ProviderRoute::Pinned)
    );
    assert_eq!(
        route(FIXTURE, origin),
        Some(ProviderRoute::Fixture(origin.unwrap()))
    );
    assert_eq!(route(FIXTURE, None), None);
    assert!(FixtureProviderTransport::new(
        "provider.exampleshield",
        origin.unwrap(),
        &DirectPolicy
    )
    .is_none());
}

#[test]
fn only_the_fixture_key_is_ever_sent() {
    let headers = fixture_headers(&request("/v1/check"));
    assert_eq!(
        headers.get("x-api-key").map(String::as_str),
        Some(FIXTURE_KEY)
    );
    assert!(headers.values().all(|value| !value.contains(STORED)));
}

#[test]
fn a_fixture_request_with_a_bad_path_is_refused_before_any_connection() {
    let origin = FixtureOrigin::parse("http://127.0.0.1:9").unwrap();
    let transport = FixtureProviderTransport::new(FIXTURE, origin, &DirectPolicy).unwrap();
    for path in ["v1", "/v1/../admin", "/v1?x=1", "//evil.example.test/v1"] {
        assert_eq!(
            transport.send(&request(path), LIMITS).err(),
            Some(ProviderClientError::PathInvalid),
            "{path}"
        );
    }
}

#[test]
fn the_stub_receives_the_fixture_key_and_never_the_stored_secret() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let stub = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut seen = Vec::new();
        let mut buffer = [0; 1024];
        while !String::from_utf8_lossy(&seen).contains("storefront.example.com") {
            match socket.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(read) => seen.extend_from_slice(&buffer[..read]),
            }
        }
        let body = r#"{"verdict":"clean"}"#;
        let _ = socket.write_all(
            format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        );
        String::from_utf8_lossy(&seen).into_owned()
    });
    let origin = FixtureOrigin::parse(&format!("http://127.0.0.1:{port}")).unwrap();
    let transport = FixtureProviderTransport::new(FIXTURE, origin, &DirectPolicy).unwrap();
    let response = transport.send(&request("/v1/check"), LIMITS).unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.body, br#"{"verdict":"clean"}"#);
    let seen = stub.join().unwrap().to_ascii_lowercase();
    assert!(seen.starts_with("post /v1/check http/1.1\r\n"), "{seen}");
    assert!(
        seen.contains(&format!("x-api-key: {FIXTURE_KEY}\r\n")),
        "{seen}"
    );
    assert!(!seen.contains(&STORED.to_ascii_lowercase()), "{seen}");
}
