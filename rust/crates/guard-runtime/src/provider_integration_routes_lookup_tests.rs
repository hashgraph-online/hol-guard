use guard_contracts::{ProviderConnectionStateV1 as State, ProviderVerdictV1};
use guard_provider_integrations::testkit::FakeProvider;
use rusqlite::Connection;
use zeroize::Zeroizing;

use super::*;
use crate::provider_integration_managed::ManagedProviderSettings;
use crate::provider_integration_routes::tests::provider;
use crate::provider_integration_secret::{store_provider_key, ProviderKey};
use crate::provider_integration_store::{
    ensure_provider_integration_schema, provider_connection, put_connection, signals_for_subject,
    ProviderConnection,
};

const SHIELD: &str = "provider.exampleshield";
const HOST: &str = "api.exampleshield.example";
const LOOKUP: &str = "/v1/guard/origin";
const ORIGIN: &str = "https://storefront.example-org.com";
const NOW: u64 = 70_000_000;

fn key() -> String {
    format!("fixture-lookup-{}", "f".repeat(24))
}

struct Fixture {
    home: tempfile::TempDir,
    connection: Connection,
    providers: Vec<CompiledProviderIntegrationV1>,
    managed: ManagedProviderSettings,
    worker: ProviderWorker,
    enabled: bool,
}

impl Fixture {
    fn new() -> Self {
        let connection = Connection::open_in_memory().unwrap();
        ensure_provider_integration_schema(&connection).unwrap();
        Self {
            home: tempfile::tempdir().unwrap(),
            connection,
            providers: vec![provider()],
            managed: ManagedProviderSettings::none(),
            worker: ProviderWorker::new(),
            enabled: true,
        }
    }

    fn connected() -> Self {
        let fixture = Self::new();
        let provider = &fixture.providers[0];
        put_connection(
            &fixture.connection,
            &ProviderConnection {
                provider_id: SHIELD.to_owned(),
                manifest_digest: provider.manifest_digest.clone(),
                state: State::Connected,
                opt_in_facts: Vec::new(),
                connected_at_ms: 1_000,
                updated_at_ms: 1_000,
                last_verified_at_ms: Some(1_000),
            },
        )
        .unwrap();
        let mut secrets = EncryptedFileSecretStore::new(fixture.home.path());
        let stored = ProviderKey::new(Zeroizing::new(key()));
        store_provider_key(&mut secrets, SHIELD, &stored, &provider.auth).unwrap();
        fixture
    }

    fn test(&mut self, origin: &str, fake: &FakeProvider) -> RouteAnswer {
        let context = RouteContext {
            enabled: self.enabled,
            providers: &self.providers,
            connection: &self.connection,
            managed: &self.managed,
            guard_home: self.home.path(),
            now_ms: NOW,
        };
        let body = serde_json::to_vec(
            &json!({"capability": "browser.origin-reputation", "origin": origin}),
        )
        .unwrap();
        let path = format!("/v1/integrations/providers/{SHIELD}/test");
        assert!(is_test("POST", &path));
        run_test(&mut self.worker, &context, &path, &body, &|_, send| {
            send(fake)
        })
    }
}

fn code(answer: &RouteAnswer) -> &str {
    answer.body["error"].as_str().unwrap_or_default()
}

#[test]
fn an_origin_has_one_subject_and_private_origins_have_none() {
    let (canonical, subject) = origin_subject(" HTTPS://Storefront.Example-Org.com/ ").unwrap();
    assert_eq!(canonical, ORIGIN);
    assert_eq!(subject, origin_subject(ORIGIN).unwrap().1);
    assert_eq!(subject.kind, ProviderSubjectKindV1::Origin);
    assert_eq!(subject.digest.len(), 64);
    for spelling in [
        "https://storefront.example-org.com:443",
        "https://storefront.example-org.com:443/",
    ] {
        assert_eq!(
            origin_subject(spelling).unwrap(),
            (ORIGIN.to_owned(), subject.clone())
        );
    }
    let plain = origin_subject("http://storefront.example-org.com").unwrap();
    assert_eq!(
        origin_subject("http://storefront.example-org.com:80").unwrap(),
        plain
    );
    assert_ne!(
        origin_subject("https://storefront.example-org.com:8443").map(|o| o.1),
        Some(subject.clone())
    );
    for refused in [
        "http://localhost:8080",
        "https://10.0.0.8",
        "https://build.internal",
        "https://intranet",
        "https://storefront.example-org.com/items",
        "https://someone@storefront.example-org.com",
        "ftp://storefront.example-org.com",
        "https://storefront.example-org.com/:443",
        "https://someone@storefront.example-org.com:443",
    ] {
        assert_eq!(origin_subject(refused), None, "{refused}");
    }
}

#[test]
fn a_test_sends_one_lookup_and_answers_the_mapped_signal() {
    let mut fixture = Fixture::connected();
    let fake = FakeProvider::new(&[HOST], &key());
    fake.script_json(
        LOOKUP,
        200,
        r#"{"verdict": "malicious", "reasons": ["phishing", "unlisted"], "ttl": 600}"#,
    );
    let answer = fixture.test(ORIGIN, &fake);
    assert_eq!(answer.status, 200, "{}", answer.body);
    let signal: guard_contracts::ProviderSignalV1 =
        serde_json::from_value(answer.body["signal"].clone()).unwrap();
    assert_eq!(signal.verdict, ProviderVerdictV1::Danger);
    assert_eq!(signal.reason_codes, ["phishing"]);
    assert_eq!(signal.subject, origin_subject(ORIGIN).unwrap().1);
    let text = answer.body.to_string();
    assert!(
        !text.contains("storefront"),
        "the origin is named by digest"
    );
    assert!(!text.contains(&key()), "the key never comes back");

    let requests = fake.requests();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].key_matched);
    assert!(requests[0].body.as_deref().unwrap().contains(ORIGIN));
    let cached = signals_for_subject(
        &fixture.connection,
        signal.capability,
        &signal.subject.digest,
    )
    .unwrap();
    assert!(
        cached.is_empty(),
        "a test answer never reaches the decide cache"
    );
}

#[test]
fn a_private_origin_or_missing_connection_sends_nothing() {
    let fake = FakeProvider::new(&[HOST], &key());
    fake.script_json(LOOKUP, 200, r#"{"verdict": "clean"}"#);

    let mut fixture = Fixture::connected();
    let refused = fixture.test("https://build.internal", &fake);
    assert_eq!(
        (refused.status, code(&refused)),
        (400, "provider_fact_refused")
    );

    let mut unconnected = Fixture::new();
    let refused = unconnected.test(ORIGIN, &fake);
    assert_eq!(
        (refused.status, code(&refused)),
        (409, "provider_not_connected")
    );

    unconnected.enabled = false;
    let off = unconnected.test(ORIGIN, &fake);
    assert_eq!(
        (off.status, code(&off)),
        (503, "provider_capability_unavailable")
    );
    assert!(fake.requests().is_empty());
}

#[test]
fn tests_draw_on_the_providers_request_budget() {
    let mut fixture = Fixture::connected();
    let fake = FakeProvider::new(&[HOST], &key());
    let mut statuses = Vec::new();
    for index in 0..6 {
        fake.script_json(LOOKUP, 200, r#"{"verdict": "clean"}"#);
        let origin = format!("https://shop{index}.example-org.com");
        statuses.push(fixture.test(&origin, &fake).status);
    }
    // The fixture manifest allows 30 requests a minute, a burst of three.
    assert_eq!(statuses, [200, 200, 200, 429, 429, 429]);
    assert_eq!(fake.requests().len(), 3);
}

#[test]
fn a_refused_key_answers_key_invalid_and_stops_calls() {
    let mut fixture = Fixture::connected();
    let fake = FakeProvider::new(&[HOST], &key());
    fake.script_json(LOOKUP, 401, "{}");
    let refused = fixture.test(ORIGIN, &fake);
    assert_eq!(
        (refused.status, code(&refused)),
        (400, "provider_key_invalid")
    );
    assert_eq!(refused.body["key_invalidated"], true);
    let stored = provider_connection(&fixture.connection, SHIELD)
        .unwrap()
        .unwrap();
    assert_eq!(stored.state, State::KeyInvalid);

    let again = fixture.test("https://other.example-org.com", &fake);
    assert_eq!(
        (again.status, code(&again)),
        (409, "provider_not_connected")
    );
    assert_eq!(fake.requests().len(), 1);
}
