use guard_contracts::{
    ProviderCapabilityV1 as Cap, ProviderConnectionStateV1 as State, ProviderVerdictV1 as Verdict,
};
use guard_provider_integrations::testkit::FakeProvider;
use zeroize::Zeroizing;

use super::*;
use crate::provider_integration_queue::request_lookup;
use crate::provider_integration_routes::origin_subject;
use crate::provider_integration_routes::tests::{provider, SHIELD};
use crate::provider_integration_secret::{store_provider_key, ProviderKey};
use crate::provider_integration_store::{
    ensure_provider_integration_schema, put_connection, ProviderConnection,
};

const HOST: &str = "api.exampleshield.example";
const PATH: &str = "/v1/guard/origin";
const SITE: &str = "https://shop.example.com";
const NOW: u64 = 50_000_000;

struct Rig {
    _home: tempfile::TempDir,
    secrets: EncryptedFileSecretStore,
    connection: Connection,
    worker: ProviderWorker,
    providers: Vec<CompiledProviderIntegrationV1>,
    fake: FakeProvider,
}

/// A synthetic credential built at run time, in the manifest's charset and length.
fn fixture_credential() -> String {
    "q".repeat(32)
}

fn rig() -> Rig {
    let home = tempfile::tempdir().unwrap();
    let providers = vec![provider()];
    let mut secrets = EncryptedFileSecretStore::new(home.path());
    store_provider_key(
        &mut secrets,
        SHIELD,
        &ProviderKey::new(Zeroizing::new(fixture_credential())),
        &providers[0].auth,
    )
    .unwrap();
    let connection = Connection::open_in_memory().unwrap();
    ensure_provider_integration_schema(&connection).unwrap();
    put_connection(
        &connection,
        &ProviderConnection {
            provider_id: SHIELD.to_owned(),
            manifest_digest: providers[0].manifest_digest.clone(),
            state: State::Connected,
            opt_in_facts: Vec::new(),
            connected_at_ms: 1_000,
            updated_at_ms: 1_000,
            last_verified_at_ms: Some(1_000),
        },
    )
    .unwrap();
    Rig {
        _home: home,
        secrets,
        connection,
        worker: ProviderWorker::new(),
        providers,
        fake: FakeProvider::new(&[HOST], &fixture_credential()),
    }
}

fn pass(rig: &mut Rig, now_ms: u64) -> Vec<PassEntry> {
    let fake = &rig.fake;
    let transport_for = |_: &CompiledProviderIntegrationV1,
                         send: &mut dyn FnMut(
        &dyn ProviderTransport,
    ) -> ProviderStoreResult<LookupReport>| { Some(send(fake)) };
    drain_lookups(
        &mut rig.worker,
        &rig.connection,
        &mut rig.secrets,
        &rig.providers,
        &transport_for,
        now_ms,
        &mut || 7,
    )
    .unwrap()
}

fn ask(rig: &Rig, provider_id: &str, origin: &str) {
    assert!(request_lookup(
        &rig.connection,
        provider_id,
        Cap::OriginReputation,
        origin,
        NOW
    )
    .unwrap());
}

fn outcomes(entries: &[PassEntry]) -> Vec<&'static str> {
    entries.iter().map(|entry| entry.outcome).collect()
}

#[test]
fn a_queued_origin_is_looked_up_and_cached_for_the_decide_step() {
    let mut rig = rig();
    rig.fake.script_json(
        PATH,
        200,
        r#"{"verdict":"malicious","reasons":["phishing"],"ttl":120}"#,
    );
    ask(&rig, SHIELD, SITE);
    assert_eq!(
        outcomes(&pass(&mut rig, NOW + 1)),
        vec!["provider_answered"]
    );
    let requests = rig.fake.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].body.as_deref(),
        Some(r#"{"origin":"https://shop.example.com"}"#)
    );
    let subject = origin_subject(SITE).unwrap().1;
    let cached =
        signals_for_subject(&rig.connection, Cap::OriginReputation, &subject.digest).unwrap();
    assert_eq!(cached.len(), 1);
    assert_eq!(cached[0].signal.verdict, Verdict::Danger);
    assert!(pass(&mut rig, NOW + 2).is_empty(), "the request was taken");
}

#[test]
fn a_fresh_answer_or_an_unshipped_provider_sends_nothing() {
    let mut rig = rig();
    rig.fake
        .script_json(PATH, 200, r#"{"verdict":"clean","ttl":120}"#);
    ask(&rig, SHIELD, SITE);
    pass(&mut rig, NOW + 1);
    ask(&rig, SHIELD, SITE);
    ask(&rig, "provider.otherwatch", SITE);
    assert_eq!(
        outcomes(&pass(&mut rig, NOW + 2)),
        vec!["provider_answer_fresh", "provider_not_shipped"]
    );
    assert_eq!(rig.fake.requests().len(), 1);
}

#[test]
fn a_missing_transport_or_a_refused_credential_is_reported_by_code() {
    let mut rig = rig();
    ask(&rig, SHIELD, SITE);
    let none =
        |_: &CompiledProviderIntegrationV1,
         _: &mut dyn FnMut(&dyn ProviderTransport) -> ProviderStoreResult<LookupReport>| {
            None
        };
    let entries = drain_lookups(
        &mut rig.worker,
        &rig.connection,
        &mut rig.secrets,
        &rig.providers,
        &none,
        NOW + 1,
        &mut || 7,
    )
    .unwrap();
    assert_eq!(outcomes(&entries), vec!["provider_transport_unavailable"]);

    rig.fake.script_json(PATH, 401, "{}");
    ask(&rig, SHIELD, SITE);
    let entries = pass(&mut rig, NOW + 2);
    assert_eq!(entries[0].provider_id, SHIELD);
    assert_ne!(entries[0].outcome, "provider_answered");
    ask(&rig, SHIELD, "https://next.example.com");
    assert_eq!(
        outcomes(&pass(&mut rig, NOW + 3)),
        vec!["provider_not_connected"],
        "a refused credential stops calls"
    );
}

#[test]
fn one_pass_takes_a_bounded_number_of_requests() {
    let mut rig = rig();
    rig.fake
        .script_json(PATH, 200, r#"{"verdict":"clean","ttl":120}"#);
    for index in 0..(MAX_LOOKUPS_PER_PASS + 3) {
        ask(&rig, SHIELD, &format!("https://site{index}.example.com"));
    }
    assert_eq!(pass(&mut rig, NOW + 1).len(), MAX_LOOKUPS_PER_PASS);
    assert_eq!(pass(&mut rig, NOW + 2).len(), 3);
}
