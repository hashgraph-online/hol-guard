use std::cell::RefCell;

use guard_command::egress_caller::EgressPolicy;
use zeroize::Zeroizing;

use super::*;
use crate::testkit::FakeProvider;

const HOST: &str = "api.provider.exampleshield.test";
const KEY: &str = "example-provider-key";

const LIMITS: ProviderLimits = ProviderLimits {
    timeout_ms: 1500,
    max_response_bytes: 4096,
};

fn request(host: &str, path: &str) -> ProviderRequest {
    ProviderRequest {
        method: ProviderMethod::Post,
        host: host.to_owned(),
        path: path.to_owned(),
        header: "x-api-key".to_owned(),
        key: Zeroizing::new(KEY.to_owned()),
        body: Some(r#"{"target":"https://shop.example.test/basket"}"#.to_owned()),
    }
}

/// A managed policy that refuses every destination and records what it was asked about.
#[derive(Default)]
struct RefuseAll {
    asked: RefCell<Vec<String>>,
}

impl EgressPolicy for RefuseAll {
    fn validate(&self, url: &str) -> Result<(), String> {
        self.asked.borrow_mut().push(url.to_owned());
        Err("destination_refused".to_owned())
    }
}

#[test]
fn only_a_pinned_dns_host_is_reached() {
    let pinned = vec![HOST.to_owned()];
    assert_eq!(
        checked_url(&request(HOST, "/v1/check"), &pinned),
        Ok(format!("https://{HOST}/v1/check"))
    );
    for host in [
        "other.exampleshield.test",
        "api.provider.exampleshield.test:8443",
        "user@api.provider.exampleshield.test",
        "API.PROVIDER.EXAMPLESHIELD.TEST",
        "api.exampleshield.123",
        "localhost",
        "",
    ] {
        assert_eq!(
            checked_url(&request(host, "/v1/check"), &pinned),
            Err(ProviderClientError::HostNotPinned),
            "{host}"
        );
    }
    let numeric = vec!["api.exampleshield.123".to_owned()];
    assert_eq!(
        checked_url(&request("api.exampleshield.123", "/v1/check"), &numeric),
        Err(ProviderClientError::HostNotPinned)
    );
}

#[test]
fn the_path_is_a_literal_absolute_path() {
    let pinned = vec![HOST.to_owned()];
    for path in ["/", "/v1/check", "/v1/url-check.json", "/a/b_c/~d"] {
        assert!(checked_url(&request(HOST, path), &pinned).is_ok(), "{path}");
    }
    for path in [
        "",
        "v1/check",
        "//evil.test/x",
        "/v1/../admin",
        "/v1/./check",
        "/v1/check?key=1",
        "/v1/check#frag",
        "/v1/%2e%2e",
        "/v1/ check",
        "/v1//check",
    ] {
        assert_eq!(
            checked_url(&request(HOST, path), &pinned),
            Err(ProviderClientError::PathInvalid),
            "{path}"
        );
    }
}

#[test]
fn a_bad_credential_header_or_key_is_refused_before_connect() {
    let pinned = vec![HOST.to_owned()];
    let mut bad = request(HOST, "/v1/check");
    bad.header = "X-Api-Key".to_owned();
    assert_eq!(
        checked_url(&bad, &pinned),
        Err(ProviderClientError::CredentialInvalid)
    );
    for header in [
        "accept",
        "content-type",
        "content-length",
        "transfer-encoding",
        "host",
        "connection",
        "proxy-authorization",
        "cookie",
    ] {
        let mut bad = request(HOST, "/v1/check");
        bad.header = header.to_owned();
        assert_eq!(
            checked_url(&bad, &pinned),
            Err(ProviderClientError::CredentialInvalid),
            "{header}"
        );
    }
    let mut good = request(HOST, "/v1/check");
    good.header = "authorization".to_owned();
    assert!(checked_url(&good, &pinned).is_ok());
    let mut bad = request(HOST, "/v1/check");
    bad.key = Zeroizing::new("line\nbreak".to_owned());
    assert_eq!(
        checked_url(&bad, &pinned),
        Err(ProviderClientError::CredentialInvalid)
    );
    let mut bad = request(HOST, "/v1/check");
    bad.key = Zeroizing::new(String::new());
    assert_eq!(
        checked_url(&bad, &pinned),
        Err(ProviderClientError::CredentialInvalid)
    );
}

#[test]
fn the_managed_policy_is_asked_and_its_refusal_is_reported_as_blocked() {
    let policy = RefuseAll::default();
    let transport = HttpProviderTransport::new(vec![HOST.to_owned()], &policy);
    assert_eq!(
        transport.send(&request(HOST, "/v1/check"), LIMITS),
        Err(ProviderClientError::Blocked)
    );
    assert_eq!(
        *policy.asked.borrow(),
        vec![format!("https://{HOST}/v1/check")]
    );
}

#[test]
fn an_unpinned_host_never_reaches_the_policy() {
    let policy = RefuseAll::default();
    let transport = HttpProviderTransport::new(vec![HOST.to_owned()], &policy);
    assert_eq!(
        transport.send(&request("evil.example.test", "/v1/check"), LIMITS),
        Err(ProviderClientError::HostNotPinned)
    );
    assert!(policy.asked.borrow().is_empty());
}

#[test]
fn outcomes_map_to_stable_codes_without_provider_text() {
    use guard_contracts::EgressOutcomeV1;
    assert_eq!(
        refused(&EgressOutcomeV1::Blocked {
            code: "x".to_owned()
        }),
        ProviderClientError::Blocked
    );
    assert_eq!(
        refused(&EgressOutcomeV1::Timeout),
        ProviderClientError::Timeout
    );
    assert_eq!(
        refused(&EgressOutcomeV1::Error {
            message: "response too large".to_owned()
        }),
        ProviderClientError::ResponseTooLarge
    );
    assert_eq!(
        refused(&EgressOutcomeV1::Error {
            message: "tls".to_owned()
        }),
        ProviderClientError::Transport
    );
    assert_eq!(
        ProviderClientError::Blocked.to_string(),
        "provider_blocked_by_policy"
    );
}

#[test]
fn the_fake_provider_checks_like_the_client_and_records_requests() {
    let fake = FakeProvider::new(&[HOST], KEY);
    fake.script_json("/v1/check", 200, r#"{"verdict":"clean"}"#);
    fake.script_json("/v1/check", 302, "");
    fake.script_json("/v1/check", 200, &"x".repeat(5000));

    let answer = fake.send(&request(HOST, "/v1/check"), LIMITS).unwrap();
    assert_eq!(answer.status, 200);
    assert_eq!(answer.body, br#"{"verdict":"clean"}"#);
    assert_eq!(
        fake.send(&request(HOST, "/v1/check"), LIMITS),
        Err(ProviderClientError::Transport)
    );
    assert_eq!(
        fake.send(&request(HOST, "/v1/check"), LIMITS),
        Err(ProviderClientError::ResponseTooLarge)
    );
    assert_eq!(
        fake.send(&request(HOST, "/v1/check"), LIMITS),
        Err(ProviderClientError::Transport)
    );
    assert_eq!(
        fake.send(&request("evil.example.test", "/v1/check"), LIMITS),
        Err(ProviderClientError::HostNotPinned)
    );

    let seen = fake.requests();
    assert_eq!(seen.len(), 4);
    assert!(seen.iter().all(|seen| seen.key_matched));
    assert_eq!(seen[0].method, "POST");
    assert_eq!(seen[0].url, format!("https://{HOST}/v1/check"));
    assert_eq!(seen[0].header, "x-api-key");
    assert_eq!(seen[0].limits, LIMITS);
    assert!(!format!("{seen:?}").contains(KEY));
}
