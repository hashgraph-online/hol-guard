use std::collections::{BTreeMap, BTreeSet};

use guard_command::provider_integration_compile::{
    CompiledProviderAuthV1, CompiledProviderCapabilityV1, CompiledProviderIntegrationV1,
    CompiledProviderLimitsV1, CompiledProviderReasonCodesV1, CompiledProviderRequestV1,
    CompiledProviderTtlV1, ProviderHttpMethodV1, ProviderKeyCharsetV1,
};
use guard_contracts::{
    ProviderCapabilityV1 as Cap, ProviderConnectionStateV1 as State,
    ProviderShareableFactV1 as Fact, ProviderSubjectKindV1, ProviderVerdictV1 as Verdict,
};
use guard_provider_integrations::testkit::FakeProvider;
use guard_provider_integrations::ProviderClientError;
use serde_json::json;
use tempfile::TempDir;

use super::*;
use crate::provider_integration_secret::{store_provider_key, ProviderKey};
use crate::provider_integration_store::{
    ensure_provider_integration_schema, put_connection, signals_for_subject, ProviderConnection,
};

const SHIELD: &str = "provider.exampleshield";
const HOST: &str = "api.example.net";
const PATH: &str = "/v1/origin";
const KEY: &str = "abcdefghijklmnopqrstuvwxyz012345";
const NOW: u64 = 1_000_000;

fn digest(n: u8) -> String {
    format!("{n:064x}")
}

fn manifest(body: Vec<(&str, Fact)>) -> CompiledProviderIntegrationV1 {
    let shares: BTreeSet<Fact> = body.iter().map(|(_, fact)| *fact).collect();
    let verdict_map = BTreeMap::from([
        ("clean".to_owned(), Verdict::Ok),
        ("suspicious".to_owned(), Verdict::Caution),
        ("malicious".to_owned(), Verdict::Danger),
    ]);
    CompiledProviderIntegrationV1 {
        id: SHIELD.to_owned(),
        name: "ExampleShield".to_owned(),
        summary: "Checks sites against ExampleShield.".to_owned(),
        publisher_name: "Example Org".to_owned(),
        publisher_url: None,
        verified: false,
        surfaces: vec!["browser".to_owned()],
        auth: CompiledProviderAuthV1 {
            header: "x-api-key".to_owned(),
            key_min_length: 32,
            key_max_length: 32,
            key_charset: ProviderKeyCharsetV1::Alphanumeric,
        },
        obtain_url: None,
        hosts: vec![HOST.to_owned()],
        capabilities: vec![CompiledProviderCapabilityV1 {
            capability: Cap::OriginReputation,
            request: CompiledProviderRequestV1 {
                method: ProviderHttpMethodV1::Post,
                host: HOST.to_owned(),
                path: PATH.to_owned(),
                body: body
                    .into_iter()
                    .map(|(field, fact)| (field.to_owned(), fact))
                    .collect(),
            },
            verdict_pointer: "/verdict".to_owned(),
            verdict_map,
            reason_codes: Some(CompiledProviderReasonCodesV1 {
                pointer: "/reasons".to_owned(),
                allow: vec!["phishing".to_owned(), "new_domain".to_owned()],
                labels: BTreeMap::new(),
            }),
            ttl: Some(CompiledProviderTtlV1 {
                pointer: "/ttl".to_owned(),
                min_seconds: 60,
                max_seconds: 3600,
            }),
            shares,
        }],
        verify: None,
        limits: CompiledProviderLimitsV1 {
            timeout_ms: 2_000,
            max_response_bytes: 4_096,
            max_requests_per_minute: 60,
        },
        privacy_url: "https://example.net/privacy".to_owned(),
        terms_url: "https://example.net/terms".to_owned(),
        icon: None,
        manifest_digest: format!("{:064x}", 7),
    }
}

fn origin_manifest() -> CompiledProviderIntegrationV1 {
    manifest(vec![("origin", Fact::TargetOrigin)])
}

struct Rig {
    _home: TempDir,
    secrets: EncryptedFileSecretStore,
    connection: Connection,
    worker: ProviderWorker,
}

fn rig_with(opt_in_facts: Vec<Fact>, with_key: bool) -> Rig {
    let home = tempfile::tempdir().unwrap();
    let mut secrets = EncryptedFileSecretStore::new(home.path());
    if with_key {
        store_provider_key(
            &mut secrets,
            SHIELD,
            &ProviderKey::new(Zeroizing::new(KEY.to_owned())),
            &origin_manifest().auth,
        )
        .unwrap();
    }
    let connection = Connection::open_in_memory().unwrap();
    ensure_provider_integration_schema(&connection).unwrap();
    put_connection(
        &connection,
        &ProviderConnection {
            provider_id: SHIELD.to_owned(),
            manifest_digest: digest(7),
            state: State::Connected,
            opt_in_facts,
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
    }
}

fn connected_rig() -> Rig {
    rig_with(Vec::new(), true)
}

fn subject() -> ProviderSubjectV1 {
    ProviderSubjectV1 {
        kind: ProviderSubjectKindV1::Origin,
        digest: digest(9),
    }
}

fn facts(origin: &str) -> BTreeMap<Fact, Value> {
    BTreeMap::from([
        (Fact::TargetOrigin, json!(origin)),
        (Fact::TargetPathPrefix, json!("/checkout")),
        (Fact::GuardVersion, json!("3.61.0")),
    ])
}

fn fake() -> FakeProvider {
    FakeProvider::new(&[HOST], KEY)
}

fn lookup(
    rig: &mut Rig,
    transport: &FakeProvider,
    manifest: &CompiledProviderIntegrationV1,
    facts: &BTreeMap<Fact, Value>,
    now_ms: u64,
) -> LookupReport {
    let job = LookupJob {
        manifest,
        manifest_digest: &digest(7),
        capability: Cap::OriginReputation,
        subject: subject(),
        facts,
        jitter: 12_345,
        cache: true,
    };
    run_lookup(
        &mut rig.worker,
        &rig.connection,
        &mut rig.secrets,
        transport,
        &job,
        now_ms,
    )
    .unwrap()
}

#[test]
fn an_answer_is_mapped_and_cached_from_only_the_declared_facts() {
    let mut rig = connected_rig();
    let transport = fake();
    transport.script_json(
        PATH,
        200,
        r#"{"verdict":"malicious","reasons":["phishing","free text"],"ttl":120}"#,
    );
    let report = lookup(
        &mut rig,
        &transport,
        &origin_manifest(),
        &facts("https://shop.example.com"),
        NOW,
    );
    let LookupReport::Answered {
        signal,
        stored,
        refresh_at_ms,
        recorded,
    } = report
    else {
        panic!("expected an answer, got {report:?}");
    };
    assert_eq!(signal.verdict, Verdict::Danger);
    assert_eq!(signal.reason_codes, vec!["phishing".to_owned()]);
    assert_eq!(signal.observed_at_ms, NOW);
    assert_eq!(signal.expires_at_ms, NOW + 120_000);
    assert_eq!(signal.inventory, ProviderInventoryV1::None);
    assert_eq!(signal.state, ProviderSignalStateV1::Fresh);
    assert!(matches!(stored, Some(PutSignalOutcome::Stored(_))));
    assert!(refresh_at_ms > NOW && refresh_at_ms < NOW + 120_000);
    assert_eq!(recorded, Recorded::default());

    let requests = transport.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "POST");
    assert_eq!(requests[0].url, format!("https://{HOST}{PATH}"));
    assert_eq!(requests[0].header, "x-api-key");
    assert!(requests[0].key_matched);
    assert_eq!(
        requests[0].body.as_deref(),
        Some(r#"{"origin":"https://shop.example.com"}"#)
    );
    assert_eq!(requests[0].limits.timeout_ms, 2_000);
    assert_eq!(requests[0].limits.max_response_bytes, 4_096);

    let cached = signals_for_subject(&rig.connection, Cap::OriginReputation, &digest(9)).unwrap();
    assert_eq!(cached.len(), 1);
    assert_eq!(cached[0].signal, signal);
}

#[test]
fn an_answer_with_no_declared_lifetime_uses_the_default() {
    let mut rig = connected_rig();
    let mut manifest = origin_manifest();
    manifest.capabilities[0].ttl = None;
    let transport = fake();
    transport.script_json(PATH, 200, r#"{"verdict":"clean"}"#);
    let report = lookup(
        &mut rig,
        &transport,
        &manifest,
        &facts("https://shop.example.com"),
        NOW,
    );
    let LookupReport::Answered { signal, .. } = report else {
        panic!("expected an answer, got {report:?}");
    };
    assert_eq!(signal.verdict, Verdict::Ok);
    assert_eq!(signal.expires_at_ms, NOW + DEFAULT_ANSWER_TTL_MS);
}

#[test]
fn a_private_origin_is_never_sent() {
    for origin in [
        "https://shop.example.test",
        "http://localhost:3000",
        "https://10.0.0.8",
        "https://intranet",
        "https://shop.example.com/path?q=1",
    ] {
        let mut rig = connected_rig();
        let transport = fake();
        transport.script_json(PATH, 200, r#"{"verdict":"clean"}"#);
        let report = lookup(
            &mut rig,
            &transport,
            &origin_manifest(),
            &facts(origin),
            NOW,
        );
        assert_eq!(
            report,
            LookupReport::NotSent(NotSent::FactRefused(Fact::TargetOrigin)),
            "{origin}"
        );
        assert!(transport.requests().is_empty(), "{origin}");
    }
}

#[test]
fn an_opt_in_fact_goes_out_only_when_the_user_turned_it_on() {
    let manifest = manifest(vec![
        ("origin", Fact::TargetOrigin),
        ("prefix", Fact::TargetPathPrefix),
    ]);
    let mut rig = connected_rig();
    let transport = fake();
    let report = lookup(
        &mut rig,
        &transport,
        &manifest,
        &facts("https://shop.example.com"),
        NOW,
    );
    assert_eq!(
        report,
        LookupReport::NotSent(NotSent::FactRefused(Fact::TargetPathPrefix))
    );
    assert!(transport.requests().is_empty());

    let mut rig = rig_with(vec![Fact::TargetPathPrefix], true);
    transport.script_json(PATH, 200, r#"{"verdict":"clean"}"#);
    let report = lookup(
        &mut rig,
        &transport,
        &manifest,
        &facts("https://shop.example.com"),
        NOW,
    );
    assert!(
        matches!(report, LookupReport::Answered { .. }),
        "{report:?}"
    );
    assert_eq!(
        transport.requests()[0].body.as_deref(),
        Some(r#"{"origin":"https://shop.example.com","prefix":"/checkout"}"#)
    );
}

#[test]
fn a_request_that_carries_no_fact_is_never_sent() {
    let mut rig = connected_rig();
    let transport = fake();
    let mut get = manifest(Vec::new());
    get.capabilities[0].request.method = ProviderHttpMethodV1::Get;
    for declared in [get, manifest(Vec::new())] {
        let report = lookup(
            &mut rig,
            &transport,
            &declared,
            &facts("https://shop.example.com"),
            NOW,
        );
        assert_eq!(report, LookupReport::NotSent(NotSent::SubjectNotCarried));
        assert_eq!(
            NotSent::SubjectNotCarried.code(),
            "provider_subject_not_carried"
        );
    }
    assert!(transport.requests().is_empty());
    assert!(
        signals_for_subject(&rig.connection, Cap::OriginReputation, &subject().digest)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn a_missing_fact_stops_the_lookup() {
    let mut rig = connected_rig();
    let transport = fake();
    let report = lookup(
        &mut rig,
        &transport,
        &origin_manifest(),
        &BTreeMap::new(),
        NOW,
    );
    assert_eq!(
        report,
        LookupReport::NotSent(NotSent::FactRefused(Fact::TargetOrigin))
    );
    assert!(transport.requests().is_empty());
}

#[test]
fn nothing_is_sent_without_a_matching_connection_or_a_key() {
    let transport = fake();
    let origin = facts("https://shop.example.com");

    let mut rig = connected_rig();
    let mut other = origin_manifest();
    other.id = "provider.otherwatch".to_owned();
    assert_eq!(
        lookup(&mut rig, &transport, &other, &origin, NOW),
        LookupReport::NotSent(NotSent::NotConnected)
    );

    let mut rig = connected_rig();
    let job = LookupJob {
        manifest: &origin_manifest(),
        manifest_digest: &digest(8),
        capability: Cap::OriginReputation,
        subject: subject(),
        facts: &origin,
        jitter: 0,
        cache: true,
    };
    let report = run_lookup(
        &mut rig.worker,
        &rig.connection,
        &mut rig.secrets,
        &transport,
        &job,
        NOW,
    )
    .unwrap();
    assert_eq!(report, LookupReport::NotSent(NotSent::ManifestChanged));

    let mut rig = connected_rig();
    let job = LookupJob {
        capability: Cap::DownloadReputation,
        ..job
    };
    let job = LookupJob {
        manifest_digest: &digest(7),
        ..job
    };
    let report = run_lookup(
        &mut rig.worker,
        &rig.connection,
        &mut rig.secrets,
        &transport,
        &job,
        NOW,
    )
    .unwrap();
    assert_eq!(report, LookupReport::NotSent(NotSent::CapabilityUndeclared));

    let mut rig = rig_with(Vec::new(), false);
    assert_eq!(
        lookup(&mut rig, &transport, &origin_manifest(), &origin, NOW),
        LookupReport::NotSent(NotSent::KeyMissing)
    );
    assert!(transport.requests().is_empty());
}

#[test]
fn an_unauthorized_answer_invalidates_the_key_and_stops_calls() {
    let mut rig = connected_rig();
    let transport = fake();
    let origin = facts("https://shop.example.com");
    transport.script_json(PATH, 401, "{}");
    let report = lookup(&mut rig, &transport, &origin_manifest(), &origin, NOW);
    let LookupReport::Failed {
        outcome,
        code,
        recorded,
    } = report
    else {
        panic!("expected a failure, got {report:?}");
    };
    assert_eq!(outcome, ExchangeOutcome::Unauthorized);
    assert_eq!(code, "provider_unauthorized");
    assert!(recorded.key_invalidated);
    assert_eq!(
        provider_connection(&rig.connection, SHIELD)
            .unwrap()
            .unwrap()
            .state,
        State::KeyInvalid
    );

    let report = lookup(&mut rig, &transport, &origin_manifest(), &origin, NOW + 1);
    assert_eq!(
        report,
        LookupReport::NotSent(NotSent::Held(Admission::NotConnected(State::KeyInvalid)))
    );
    assert_eq!(transport.requests().len(), 1);
    assert!(
        signals_for_subject(&rig.connection, Cap::OriginReputation, &digest(9))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn a_failed_exchange_is_counted_and_the_subject_waits() {
    let origin = facts("https://shop.example.com");
    for (scripted, code) in [
        (Err(ProviderClientError::Timeout), "provider_timeout"),
        (
            Ok(guard_provider_integrations::client::ProviderResponse {
                status: 500,
                body: b"{}".to_vec(),
            }),
            "provider_status_failed",
        ),
        (
            Ok(guard_provider_integrations::client::ProviderResponse {
                status: 200,
                body: b"not json".to_vec(),
            }),
            "provider_answer_invalid",
        ),
    ] {
        let mut rig = connected_rig();
        let transport = fake();
        transport.script(PATH, scripted);
        let report = lookup(&mut rig, &transport, &origin_manifest(), &origin, NOW);
        assert_eq!(
            report,
            LookupReport::Failed {
                outcome: ExchangeOutcome::Failed,
                code,
                recorded: Recorded::default(),
            }
        );
        let report = lookup(&mut rig, &transport, &origin_manifest(), &origin, NOW + 1);
        assert!(
            matches!(
                report,
                LookupReport::NotSent(NotSent::Held(Admission::RecentlyFailed { .. }))
            ),
            "{code}: {report:?}"
        );
        assert_eq!(transport.requests().len(), 1, "{code}");
        assert!(
            signals_for_subject(&rig.connection, Cap::OriginReputation, &digest(9))
                .unwrap()
                .is_empty()
        );
    }
}

#[test]
fn a_slow_down_answer_empties_the_budget() {
    let mut rig = connected_rig();
    let transport = fake();
    let origin = facts("https://shop.example.com");
    transport.script_json(PATH, 429, "{}");
    let report = lookup(&mut rig, &transport, &origin_manifest(), &origin, NOW);
    assert!(
        matches!(
            report,
            LookupReport::Failed {
                outcome: ExchangeOutcome::RateLimited,
                code: "provider_rate_limited",
                ..
            }
        ),
        "{report:?}"
    );
    let mut other = origin.clone();
    other.insert(Fact::TargetOrigin, json!("https://other.example.com"));
    let job = LookupJob {
        manifest: &origin_manifest(),
        manifest_digest: &digest(7),
        capability: Cap::OriginReputation,
        subject: ProviderSubjectV1 {
            kind: ProviderSubjectKindV1::Origin,
            digest: digest(10),
        },
        facts: &other,
        jitter: 0,
        cache: true,
    };
    let report = run_lookup(
        &mut rig.worker,
        &rig.connection,
        &mut rig.secrets,
        &transport,
        &job,
        NOW + 1,
    )
    .unwrap();
    assert_eq!(
        report,
        LookupReport::NotSent(NotSent::Held(Admission::RateLimited))
    );
    assert_eq!(transport.requests().len(), 1);
}

#[test]
fn script_hashes_mark_the_answer_as_device_inventory() {
    let mut manifest = manifest(vec![
        ("origin", Fact::TargetOrigin),
        ("scripts", Fact::PageScriptHashes),
    ]);
    manifest.capabilities[0].capability = Cap::ScriptIntegrity;
    let capability = &manifest.capabilities[0];
    assert_eq!(inventory(capability), ProviderInventoryV1::Device);

    let mut provider_side = manifest.clone();
    provider_side.capabilities[0].request.body.truncate(1);
    assert_eq!(
        inventory(&provider_side.capabilities[0]),
        ProviderInventoryV1::ProviderSide
    );
}

#[test]
fn every_fact_id_matches_its_contract_spelling() {
    for fact in Fact::ALL {
        assert_eq!(
            serde_json::to_value(fact).unwrap(),
            json!(fact_id(fact)),
            "{fact:?}"
        );
    }
}
