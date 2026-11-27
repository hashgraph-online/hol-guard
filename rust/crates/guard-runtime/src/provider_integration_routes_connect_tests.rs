use guard_contracts::{ProviderConnectionStateV1 as State, ProviderShareableFactV1 as Fact};
use guard_provider_integrations::testkit::FakeProvider;
use guard_provider_integrations::ProviderClientError;
use serde_json::json;

use super::tests::provider;
use super::*;
use crate::provider_integration_secret::load_provider_key;
use crate::provider_integration_store::ensure_provider_integration_schema;

const SHIELD: &str = "provider.exampleshield";
const HOST: &str = "api.exampleshield.example";
const VERIFY: &str = "/v1/guard/key";
const NOW: u64 = 60_000_000;

fn key() -> String {
    format!("fixture-connect-{}", "c".repeat(24))
}

struct Fixture {
    home: tempfile::TempDir,
    connection: Connection,
    providers: Vec<CompiledProviderIntegrationV1>,
    managed: ManagedProviderSettings,
    ledger: ProofLedger,
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
            ledger: ProofLedger::new(),
        }
    }

    fn context(&self) -> RouteContext<'_> {
        RouteContext {
            enabled: true,
            providers: &self.providers,
            connection: &self.connection,
            managed: &self.managed,
            guard_home: self.home.path(),
            now_ms: NOW,
        }
    }

    fn proof(&mut self) -> String {
        let context = RouteContext {
            enabled: true,
            providers: &self.providers,
            connection: &self.connection,
            managed: &self.managed,
            guard_home: self.home.path(),
            now_ms: NOW,
        };
        let path = format!("{PREFIX}/{SHIELD}/connect/preview");
        let preview = answer(&mut self.ledger, &context, "POST", &path, b"").unwrap();
        assert_eq!(preview.status, 200, "{}", preview.body);
        preview.body["challenge"].as_str().unwrap().to_owned()
    }

    /// Runs the three phases the way the daemon edge does.
    fn connect(&mut self, body: Value, transport: &FakeProvider) -> RouteAnswer {
        let path = format!("{PREFIX}/{SHIELD}/connect");
        assert!(is_connect("POST", &path));
        let bytes = serde_json::to_vec(&body).unwrap();
        let providers = self.providers.clone();
        let prepared = match prepare_connect(&mut self.ledger, true, &providers, &path, &bytes, NOW)
        {
            Ok(prepared) => prepared,
            Err(answer) => return answer,
        };
        let verified = match verify_connect(&prepared, transport) {
            Ok(verified) => verified,
            Err(answer) => return answer,
        };
        self.finish(prepared, verified)
    }

    fn finish(&mut self, prepared: PreparedConnect<'_>, verified: bool) -> RouteAnswer {
        let mut ledger = std::mem::take(&mut self.ledger);
        let answer = finish_connect(&mut ledger, &self.context(), prepared, verified);
        self.ledger = ledger;
        answer
    }

    fn prepare<'p>(
        &mut self,
        providers: &'p [CompiledProviderIntegrationV1],
        key: &str,
    ) -> PreparedConnect<'p> {
        let proof = self.proof();
        let path = format!("{PREFIX}/{SHIELD}/connect");
        let bytes = serde_json::to_vec(&json!({"key": key, "proof": proof})).unwrap();
        prepare_connect(&mut self.ledger, true, providers, &path, &bytes, NOW)
            .unwrap_or_else(|answer| panic!("{}", answer.body))
    }

    fn disconnect(&mut self) -> RouteAnswer {
        let mut ledger = std::mem::take(&mut self.ledger);
        let context = self.context();
        let base = format!("{PREFIX}/{SHIELD}/disconnect");
        let preview = answer(
            &mut ledger,
            &context,
            "POST",
            &format!("{base}/preview"),
            b"",
        );
        let proof = preview.unwrap().body["challenge"]
            .as_str()
            .unwrap()
            .to_owned();
        let body = serde_json::to_vec(&json!({"proof": proof})).unwrap();
        let answered = answer(&mut ledger, &context, "POST", &base, &body).unwrap();
        self.ledger = ledger;
        answered
    }

    fn stored_key(&self) -> Option<String> {
        let mut store = EncryptedFileSecretStore::new(self.home.path());
        load_provider_key(&mut store, SHIELD).map(|key| key.expose().to_owned())
    }

    fn key_stored(&self) -> bool {
        let mut store = EncryptedFileSecretStore::new(self.home.path());
        load_provider_key(&mut store, SHIELD).is_some()
    }

    fn stored(&self) -> Option<ProviderConnection> {
        provider_connection(&self.connection, SHIELD).unwrap()
    }
}

fn code(answer: &RouteAnswer) -> &str {
    answer.body["error"].as_str().unwrap_or_default()
}

#[test]
fn connect_checks_the_key_then_stores_it_bound_to_the_manifest() {
    let mut fixture = Fixture::new();
    let proof = fixture.proof();
    let fake = FakeProvider::new(&[HOST], &key());
    fake.script_json(VERIFY, 200, "{}");

    let answer = fixture.connect(json!({"key": key(), "proof": proof}), &fake);
    assert_eq!(answer.status, 200, "{}", answer.body);
    assert_eq!(answer.body["summary"]["id"], SHIELD);
    assert!(
        !answer.body.to_string().contains(&key()),
        "the key never comes back"
    );

    let requests = fake.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "GET");
    assert!(requests[0].key_matched);
    assert_eq!(requests[0].body, None, "verify shares no facts");

    let stored = fixture.stored().unwrap();
    assert_eq!(stored.state, State::Connected);
    assert_eq!(stored.manifest_digest, fixture.providers[0].manifest_digest);
    assert_eq!(stored.manifest_digest.len(), 64);
    assert_eq!(stored.last_verified_at_ms, Some(NOW));
    assert!(fixture.key_stored());
}

#[test]
fn a_bad_proof_or_key_format_never_reaches_the_provider() {
    let mut fixture = Fixture::new();
    let fake = FakeProvider::new(&[HOST], &key());
    let refused = fixture.connect(json!({"key": key(), "proof": "not-a-proof"}), &fake);
    assert_eq!((refused.status, code(&refused)), (403, PROOF_INVALID));

    let proof = fixture.proof();
    let refused = fixture.connect(json!({"key": "short", "proof": proof}), &fake);
    assert_eq!(
        (refused.status, code(&refused)),
        (400, "provider_key_invalid")
    );
    let reused = fixture.connect(json!({"key": key(), "proof": proof}), &fake);
    assert_eq!(code(&reused), PROOF_INVALID, "the proof was spent");

    let proof = fixture.proof();
    let facts =
        json!({"key": key(), "proof": proof, "enabled_opt_in_facts": [Fact::TargetPathPrefix]});
    let refused = fixture.connect(facts, &fake);
    assert_eq!(
        (refused.status, code(&refused)),
        (400, INVALID_REQUEST),
        "an opt-in fact the provider does not take"
    );

    assert!(fake.requests().is_empty());
    assert_eq!(fixture.stored(), None);
    assert!(!fixture.key_stored());
}

#[test]
fn provider_refusals_store_nothing() {
    let cases: [(Result<u16, ProviderClientError>, u16, &str); 6] = [
        (Ok(401), 400, "provider_key_invalid"),
        (Ok(403), 400, "provider_key_invalid"),
        (Ok(429), 429, "provider_rate_limited"),
        (Ok(500), 502, "provider_integration_unavailable"),
        (
            Err(ProviderClientError::Blocked),
            403,
            "provider_host_refused",
        ),
        (
            Err(ProviderClientError::ResponseTooLarge),
            502,
            "provider_response_too_large",
        ),
    ];
    for (scripted, status, error_code) in cases {
        let mut fixture = Fixture::new();
        let proof = fixture.proof();
        let fake = FakeProvider::new(&[HOST], &key());
        match scripted {
            Ok(provider_status) => fake.script_json(VERIFY, provider_status, "{}"),
            Err(failure) => fake.script(VERIFY, Err(failure)),
        }
        let answer = fixture.connect(json!({"key": key(), "proof": proof}), &fake);
        assert_eq!((answer.status, code(&answer)), (status, error_code));
        assert_eq!(fixture.stored(), None, "{error_code}");
        assert!(!fixture.key_stored(), "{error_code}");
    }
}

#[test]
fn a_host_the_manifest_does_not_pin_is_refused() {
    let mut fixture = Fixture::new();
    let proof = fixture.proof();
    let fake = FakeProvider::new(&["api.otherwatch.example"], &key());
    let answer = fixture.connect(json!({"key": key(), "proof": proof}), &fake);
    assert_eq!(
        (answer.status, code(&answer)),
        (403, "provider_host_refused")
    );
    assert!(!fixture.key_stored());
}

#[test]
fn connect_is_never_answered_in_one_step() {
    let mut fixture = Fixture::new();
    let proof = fixture.proof();
    let providers = fixture.providers.clone();
    let path = format!("{PREFIX}/{SHIELD}/connect");
    let body = serde_json::to_vec(&json!({"key": key(), "proof": proof})).unwrap();
    let context = RouteContext {
        enabled: true,
        providers: &providers,
        connection: &fixture.connection,
        managed: &fixture.managed,
        guard_home: fixture.home.path(),
        now_ms: NOW,
    };
    let answered = answer(&mut fixture.ledger, &context, "POST", &path, &body).unwrap();
    assert_eq!(answered.status, 503);
    assert!(!fixture.key_stored());

    let off = prepare_connect(&mut fixture.ledger, false, &providers, &path, &body, NOW);
    assert_eq!(off.err().unwrap().status, 503);
    assert!(!is_connect("GET", &path));
    assert!(!is_connect("POST", &format!("{path}/preview")));
}

#[test]
fn a_misshapen_apply_still_spends_the_proof_it_presents() {
    let mut fixture = Fixture::new();
    let fake = FakeProvider::new(&[HOST], &key());
    let proof = fixture.proof();
    let refused = fixture.connect(json!({"key": 5, "proof": proof}), &fake);
    assert_eq!((refused.status, code(&refused)), (400, INVALID_REQUEST));
    let reused = fixture.connect(json!({"key": key(), "proof": proof}), &fake);
    assert_eq!(code(&reused), PROOF_INVALID);

    put_connection(
        &fixture.connection,
        &ProviderConnection {
            provider_id: SHIELD.to_owned(),
            manifest_digest: fixture.providers[0].manifest_digest.clone(),
            state: State::Connected,
            opt_in_facts: Vec::new(),
            connected_at_ms: 1_000,
            updated_at_ms: 1_000,
            last_verified_at_ms: Some(1_000),
        },
    )
    .unwrap();
    let base = format!("{PREFIX}/{SHIELD}");
    let empty = json!({"settings": [], "enabled_opt_in_facts": []});
    for (preview_body, action, misshapen, valid) in [
        (
            empty.clone(),
            "settings",
            json!({"settings": true, "enabled_opt_in_facts": []}),
            empty.clone(),
        ),
        (json!({}), "disconnect", json!({"extra": 1}), json!({})),
    ] {
        let mut ledger = std::mem::replace(&mut fixture.ledger, ProofLedger::new());
        let context = fixture.context();
        let preview_path = format!("{base}/{action}/preview");
        let preview_bytes = serde_json::to_vec(&preview_body).unwrap();
        let preview = answer(&mut ledger, &context, "POST", &preview_path, &preview_bytes).unwrap();
        assert_eq!(preview.status, 200, "{}", preview.body);
        let proof = preview.body["challenge"].clone();
        let apply = format!("{base}/{action}");
        let mut bad = misshapen;
        bad["proof"] = proof.clone();
        let bytes = serde_json::to_vec(&bad).unwrap();
        let refused = answer(&mut ledger, &context, "POST", &apply, &bytes).unwrap();
        assert_eq!(refused.status, 400, "{action}");
        let mut good = valid;
        good["proof"] = proof;
        let bytes = serde_json::to_vec(&good).unwrap();
        let reused = answer(&mut ledger, &context, "POST", &apply, &bytes).unwrap();
        assert_eq!(code(&reused), PROOF_INVALID, "{action}");
        fixture.ledger = ledger;
    }
    assert!(fixture.stored().is_some(), "nothing was disconnected");
}

#[test]
fn a_disconnect_during_the_provider_call_wins() {
    let mut fixture = Fixture::new();
    let providers = fixture.providers.clone();
    let first = fixture.prepare(&providers, &key());
    assert_eq!(fixture.finish(first, true).status, 200);

    let pending = fixture.prepare(&providers, &key());
    let disconnected = fixture.disconnect();
    assert_eq!(disconnected.status, 200, "{}", disconnected.body);
    let late = fixture.finish(pending, true);
    assert_eq!((late.status, code(&late)), (409, CONNECT_SUPERSEDED));
    assert_eq!(fixture.stored(), None, "the disconnect stands");
    assert!(!fixture.key_stored(), "no key comes back");
}

#[test]
fn of_two_overlapping_connects_only_the_first_to_finish_is_stored() {
    let mut fixture = Fixture::new();
    let providers = fixture.providers.clone();
    let other = format!("fixture-connect-{}", "e".repeat(24));
    let first = fixture.prepare(&providers, &key());
    let second = fixture.prepare(&providers, &other);
    assert_eq!(fixture.finish(second, true).status, 200);
    let late = fixture.finish(first, true);
    assert_eq!((late.status, code(&late)), (409, CONNECT_SUPERSEDED));
    assert_eq!(fixture.stored_key(), Some(other));
}

#[test]
fn a_reconnect_whose_row_fails_keeps_the_previous_key() {
    let mut fixture = Fixture::new();
    let providers = fixture.providers.clone();
    let first = fixture.prepare(&providers, &key());
    assert_eq!(fixture.finish(first, true).status, 200);
    fixture
        .connection
        .execute_batch(
            "create trigger refuse_insert before insert on provider_connections \
             begin select raise(abort, 'refused'); end; \
             create trigger refuse_update before update on provider_connections \
             begin select raise(abort, 'refused'); end;",
        )
        .unwrap();

    // The new manifest asks for longer keys than the one already stored.
    let mut providers = providers;
    providers[0].auth.key_min_length = 48;
    fixture.providers = providers.clone();
    let other = format!("fixture-connect-{}", "e".repeat(40));
    let failed = fixture.prepare(&providers, &other);
    assert_eq!(fixture.finish(failed, true).status, 503);
    assert_eq!(
        fixture.stored_key(),
        Some(key()),
        "the previous key is put back though it no longer fits the format"
    );
}

#[test]
fn a_refused_settings_change_does_not_supersede_a_connect() {
    let mut fixture = Fixture::new();
    let providers = fixture.providers.clone();
    let first = fixture.prepare(&providers, &key());
    assert_eq!(fixture.finish(first, true).status, 200);

    let base = format!("{PREFIX}/{SHIELD}/settings");
    let change = json!({
        "settings": [{"capability": "browser.origin-reputation", "effect": "enforce",
                      "require_fresh_check": true, "quieted_reason_codes": []}],
        "enabled_opt_in_facts": [],
    });
    let mut ledger = std::mem::take(&mut fixture.ledger);
    let preview = answer(
        &mut ledger,
        &fixture.context(),
        "POST",
        &format!("{base}/preview"),
        &serde_json::to_vec(&change).unwrap(),
    )
    .unwrap();
    fixture.ledger = ledger;
    assert_eq!(preview.status, 200, "{}", preview.body);
    let pending = fixture.prepare(&providers, &key());

    // Managed policy locks the setting after the preview, so the apply is refused.
    let mut settings = serde_json::Map::new();
    settings.insert(
        "provider_integrations".to_owned(),
        json!([{"provider_id": SHIELD, "capability": "browser.origin-reputation", "effect": "observe"}]),
    );
    fixture.managed = ManagedProviderSettings::from_settings(&settings, true).unwrap();
    let mut apply = change;
    apply["proof"] = preview.body["challenge"].clone();
    let mut ledger = std::mem::take(&mut fixture.ledger);
    let refused = answer(
        &mut ledger,
        &fixture.context(),
        "POST",
        &base,
        &serde_json::to_vec(&apply).unwrap(),
    )
    .unwrap();
    fixture.ledger = ledger;
    assert_eq!((refused.status, code(&refused)), (409, SETTING_MANAGED));
    assert_eq!(
        fixture.finish(pending, true).status,
        200,
        "the connect still lands"
    );
}
