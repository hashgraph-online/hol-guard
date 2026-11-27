use guard_command::provider_integration_compile::compile_provider_integration;
use guard_contracts::{
    ProviderCapabilityV1 as Cap, ProviderConnectPreviewV1, ProviderConnectionStateV1 as State,
    ProviderDetailV1, ProviderEffectLevelV1 as Level,
};
use serde_json::Map;
use zeroize::Zeroizing;

use super::*;
use crate::provider_integration_secret::{load_provider_key, store_provider_key, ProviderKey};
use crate::provider_integration_store::{capability_settings, ensure_provider_integration_schema};

pub(crate) const SHIELD: &str = "provider.exampleshield";
const NOW: u64 = 50_000_000;
const KEY: &str = "fixture-key-aaaaaaaaaaaaaaaaaaaaaaaa";

pub(crate) fn provider() -> CompiledProviderIntegrationV1 {
    let manifest = json!({
        "schemaVersion": "guard.provider-integration.v1",
        "id": SHIELD,
        "name": "ExampleShield",
        "publisher": {"name": "ExampleShield Inc.", "url": "https://exampleshield.example", "verified": false},
        "summary": "Checks the sites an agent opens against your ExampleShield account.",
        "surfaces": ["browser"],
        "auth": {
            "kind": "api-key",
            "header": "x-provider-key",
            "keyFormat": {"minLength": 24, "maxLength": 128, "charset": "base64url"},
            "obtainUrl": "https://exampleshield.example/keys"
        },
        "hosts": ["api.exampleshield.example"],
        "capabilities": [{
            "id": "browser.origin-reputation",
            "request": {
                "method": "POST",
                "path": "/v1/guard/origin",
                "body": {"origin": {"fact": "target.origin"}}
            },
            "response": {
                "verdict": {"pointer": "/verdict", "map": {"clean": "ok", "malicious": "danger"}},
                "reasonCodes": {"pointer": "/reasons", "allow": ["phishing"]},
                "ttlSeconds": {"pointer": "/ttl", "min": 60, "max": 86400}
            },
            "shares": ["target.origin"]
        }],
        "verify": {"method": "GET", "path": "/v1/guard/key"},
        "limits": {"timeoutMs": 1200, "maxResponseBytes": 16384, "maxRequestsPerMinute": 30},
        "privacyUrl": "https://exampleshield.example/privacy",
        "termsUrl": "https://exampleshield.example/terms"
    });
    compile_provider_integration(&serde_json::to_vec(&manifest).unwrap(), &[]).unwrap()
}

pub(crate) struct Fixture {
    home: tempfile::TempDir,
    pub(crate) connection: Connection,
    providers: Vec<CompiledProviderIntegrationV1>,
    managed: ManagedProviderSettings,
    ledger: ProofLedger,
    enabled: bool,
    pub(crate) now_ms: u64,
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
            enabled: true,
            now_ms: NOW,
        }
    }

    pub(crate) fn connected() -> Self {
        let fixture = Self::new();
        put_connection(
            &fixture.connection,
            &ProviderConnection {
                provider_id: SHIELD.to_owned(),
                manifest_digest: format!("{:064x}", 7),
                state: State::Connected,
                opt_in_facts: Vec::new(),
                connected_at_ms: 1_000,
                updated_at_ms: 1_000,
                last_verified_at_ms: Some(1_000),
            },
        )
        .unwrap();
        let mut store = EncryptedFileSecretStore::new(fixture.home.path());
        store_provider_key(
            &mut store,
            SHIELD,
            &ProviderKey::new(Zeroizing::new(KEY.to_owned())),
            &fixture.providers[0].auth,
        )
        .unwrap();
        fixture
    }

    pub(crate) fn call(&mut self, method: &str, path: &str, body: Value) -> RouteAnswer {
        let context = RouteContext {
            enabled: self.enabled,
            providers: &self.providers,
            connection: &self.connection,
            managed: &self.managed,
            guard_home: self.home.path(),
            now_ms: self.now_ms,
        };
        let bytes = if body.is_null() {
            Vec::new()
        } else {
            serde_json::to_vec(&body).unwrap()
        };
        answer(&mut self.ledger, &context, method, path, &bytes).expect(path)
    }

    fn key_stored(&self) -> bool {
        let mut store = EncryptedFileSecretStore::new(self.home.path());
        load_provider_key(&mut store, SHIELD).is_some()
    }
}

pub(crate) fn path(rest: &str) -> String {
    format!("{PREFIX}/{SHIELD}{rest}")
}

pub(crate) fn code(answer: &RouteAnswer) -> &str {
    answer.body["error"].as_str().unwrap_or_default()
}

pub(crate) fn enforce_change() -> Value {
    json!({
        "settings": [{"capability": "browser.origin-reputation", "effect": "enforce",
                      "require_fresh_check": true, "quieted_reason_codes": []}],
        "enabled_opt_in_facts": [],
    })
}

pub(crate) fn with_proof(change: &Value, proof: &str) -> Value {
    let mut request = change.clone();
    request["proof"] = json!(proof);
    request
}

/// What the store reports for a capability nobody has set.
pub(crate) const UNCHANGED: Option<CapabilitySetting> = Some(CapabilitySetting {
    effect_level: Level::Tighten,
    require_fresh: false,
});

pub(crate) fn stored_setting(fixture: &Fixture) -> Option<CapabilitySetting> {
    capability_settings(&fixture.connection, SHIELD)
        .unwrap()
        .get(&Cap::OriginReputation)
        .copied()
}

#[test]
fn the_rollback_switch_reads_off_values_only() {
    for off in ["0", "off", "OFF", " false ", "disabled"] {
        assert!(!provider_integrations_enabled(Some(off)), "{off}");
    }
    for on in [None, Some(""), Some("1"), Some("on"), Some("yes")] {
        assert!(provider_integrations_enabled(on), "{on:?}");
    }
}

#[test]
fn only_the_local_routes_are_owned() {
    for (method, path) in [
        ("GET", PREFIX.to_owned()),
        ("GET", path("")),
        ("POST", path("/connect/preview")),
        ("POST", path("/settings/preview")),
        ("POST", path("/settings")),
        ("POST", path("/disconnect/preview")),
        ("POST", path("/disconnect")),
        ("POST", path("/connect")),
        ("POST", path("/test")),
    ] {
        assert!(owns(method, &path), "{method} {path}");
    }
    for (method, path) in [
        ("POST", path("/test/extra")),
        ("POST", PREFIX.to_owned()),
        ("GET", path("/settings")),
        ("DELETE", path("")),
        ("GET", format!("{PREFIX}s")),
        ("GET", format!("{PREFIX}/")),
        ("POST", path("/settings/preview/extra")),
    ] {
        assert!(!owns(method, &path), "{method} {path}");
    }
}

#[test]
fn switched_off_every_route_is_unavailable() {
    let mut fixture = Fixture::connected();
    fixture.enabled = false;
    for (method, route) in [
        ("GET", PREFIX.to_owned()),
        ("GET", path("")),
        ("POST", path("/settings/preview")),
        ("POST", path("/disconnect")),
    ] {
        let answer = fixture.call(method, &route, Value::Null);
        assert_eq!(answer.status, 503, "{route}");
        assert_eq!(code(&answer), "provider_capability_unavailable");
    }
    assert!(fixture.key_stored());
}

#[test]
fn list_and_detail_show_the_provider_without_secrets() {
    let mut fixture = Fixture::new();
    let list = fixture.call("GET", PREFIX, Value::Null);
    assert_eq!(list.status, 200);
    assert_eq!(list.body["providers"][0]["id"], SHIELD);
    assert_eq!(
        list.body["providers"][0]["state"],
        json!(State::NotConnected)
    );

    let mut fixture = Fixture::connected();
    let detail = fixture.call("GET", &path(""), Value::Null);
    assert_eq!(detail.status, 200);
    let parsed: ProviderDetailV1 = serde_json::from_value(detail.body.clone()).unwrap();
    assert_eq!(parsed.summary.state, State::Connected);
    assert_eq!(parsed.shares, vec![ProviderShareableFactV1::TargetOrigin]);
    assert_eq!(parsed.settings[0].effect, Level::Tighten);
    assert_eq!(
        parsed.cache_counts.get("browser.origin-reputation"),
        Some(&0)
    );
    assert!(!detail.body.to_string().contains(KEY));

    let missing = fixture.call("GET", &format!("{PREFIX}/provider.otherwatch"), Value::Null);
    assert_eq!((missing.status, code(&missing)), (404, NOT_FOUND));
}

#[test]
fn detail_reports_the_managed_effective_setting() {
    let mut fixture = Fixture::connected();
    let mut settings = Map::new();
    settings.insert(
        "provider_integrations".to_owned(),
        json!([{"provider_id": SHIELD, "capability": "browser.origin-reputation", "effect": "enforce"}]),
    );
    fixture.managed = ManagedProviderSettings::from_settings(&settings, true).unwrap();
    let detail = fixture.call("GET", &path(""), Value::Null);
    assert_eq!(detail.body["settings"][0]["effect"], "enforce");
}

#[test]
fn connect_preview_lists_what_is_shared_and_its_challenge_is_spent_once() {
    let mut fixture = Fixture::new();
    let preview = fixture.call("POST", &path("/connect/preview"), Value::Null);
    assert_eq!(preview.status, 200);
    let parsed: ProviderConnectPreviewV1 = serde_json::from_value(preview.body).unwrap();
    assert_eq!(parsed.hosts, vec!["api.exampleshield.example".to_owned()]);
    assert_eq!(parsed.shares, vec![ProviderShareableFactV1::TargetOrigin]);
    assert!(parsed.opt_in_facts.is_empty());
    assert_eq!(parsed.challenge.len(), 64);
    assert_eq!(parsed.expires_at_ms, NOW + PROOF_TTL_MS);

    let provider = provider();
    assert!(spend_connect_proof(
        &mut fixture.ledger,
        &parsed.challenge,
        &provider,
        NOW + 1
    ));
    assert!(!spend_connect_proof(
        &mut fixture.ledger,
        &parsed.challenge,
        &provider,
        NOW + 2
    ));
}

#[test]
fn settings_apply_exactly_what_was_previewed_once() {
    let mut fixture = Fixture::connected();
    let change = enforce_change();
    let preview = fixture.call("POST", &path("/settings/preview"), change.clone());
    assert_eq!(preview.status, 200, "{}", preview.body);
    let proof = preview.body["challenge"].as_str().unwrap().to_owned();
    assert_eq!(
        stored_setting(&fixture),
        UNCHANGED,
        "a preview writes nothing"
    );

    let applied = fixture.call("POST", &path("/settings"), with_proof(&change, &proof));
    assert_eq!(applied.status, 200, "{}", applied.body);
    assert_eq!(
        stored_setting(&fixture),
        Some(CapabilitySetting {
            effect_level: Level::Enforce,
            require_fresh: true,
        })
    );

    let again = fixture.call("POST", &path("/settings"), with_proof(&change, &proof));
    assert_eq!((again.status, code(&again)), (403, PROOF_INVALID));
}

#[test]
fn a_proof_does_not_carry_to_another_body_action_or_time() {
    let mut fixture = Fixture::connected();
    let change = enforce_change();
    let issue = |fixture: &mut Fixture| {
        fixture
            .call("POST", &path("/settings/preview"), change.clone())
            .body["challenge"]
            .as_str()
            .unwrap()
            .to_owned()
    };

    let proof = issue(&mut fixture);
    let mut other = change.clone();
    other["settings"][0]["effect"] = json!("tighten");
    let answer = fixture.call("POST", &path("/settings"), with_proof(&other, &proof));
    assert_eq!((answer.status, code(&answer)), (403, PROOF_INVALID));
    let spent = fixture.call("POST", &path("/settings"), with_proof(&change, &proof));
    assert_eq!(code(&spent), PROOF_INVALID, "a refused proof is spent");

    let proof = issue(&mut fixture);
    let answer = fixture.call("POST", &path("/disconnect"), json!({"proof": proof}));
    assert_eq!((answer.status, code(&answer)), (403, PROOF_INVALID));
    assert!(fixture.key_stored());

    let proof = issue(&mut fixture);
    fixture.now_ms = NOW + PROOF_TTL_MS;
    let answer = fixture.call("POST", &path("/settings"), with_proof(&change, &proof));
    assert_eq!((answer.status, code(&answer)), (403, PROOF_INVALID));

    let forged = fixture.call(
        "POST",
        &path("/settings"),
        with_proof(&change, &"0".repeat(64)),
    );
    assert_eq!(code(&forged), PROOF_INVALID);
    assert_eq!(stored_setting(&fixture), UNCHANGED);
}

#[test]
fn settings_refuse_what_the_provider_or_managed_policy_does_not_allow() {
    let mut fixture = Fixture::new();
    let answer = fixture.call("POST", &path("/settings/preview"), enforce_change());
    assert_eq!((answer.status, code(&answer)), (409, NOT_CONNECTED));

    let mut fixture = Fixture::connected();
    let undeclared = json!({
        "settings": [{"capability": "browser.download-reputation", "effect": "enforce",
                      "require_fresh_check": false, "quieted_reason_codes": []}],
        "enabled_opt_in_facts": [],
    });
    let answer = fixture.call("POST", &path("/settings/preview"), undeclared);
    assert_eq!(
        (answer.status, code(&answer)),
        (422, "provider_capability_unavailable")
    );

    let mut quieted = enforce_change();
    quieted["settings"][0]["quieted_reason_codes"] = json!(["phishing"]);
    let mut twice = enforce_change();
    let first = twice["settings"][0].clone();
    twice["settings"].as_array_mut().unwrap().push(first);
    let mut not_opt_in = enforce_change();
    not_opt_in["enabled_opt_in_facts"] = json!(["target.origin"]);
    let mut unknown = enforce_change();
    unknown["extra"] = json!(true);
    for body in [quieted, twice, not_opt_in, unknown, json!([1])] {
        let answer = fixture.call("POST", &path("/settings/preview"), body.clone());
        assert_eq!(
            (answer.status, code(&answer)),
            (400, INVALID_REQUEST),
            "{body}"
        );
    }
    let oversized = json!({"settings": [], "enabled_opt_in_facts": [], "pad": "x".repeat(MAX_ROUTE_BODY_BYTES)});
    assert_eq!(
        fixture
            .call("POST", &path("/settings/preview"), oversized)
            .status,
        400
    );

    let mut settings = Map::new();
    settings.insert(
        "provider_integrations".to_owned(),
        json!([{"provider_id": SHIELD, "capability": "browser.origin-reputation", "effect": "observe"}]),
    );
    fixture.managed = ManagedProviderSettings::from_settings(&settings, true).unwrap();
    let answer = fixture.call("POST", &path("/settings/preview"), enforce_change());
    assert_eq!((answer.status, code(&answer)), (409, SETTING_MANAGED));
    assert_eq!(fixture.ledger.pending(), 0);
}

#[test]
fn managed_policy_set_after_the_preview_still_wins() {
    let mut fixture = Fixture::connected();
    let change = enforce_change();
    let proof = fixture
        .call("POST", &path("/settings/preview"), change.clone())
        .body["challenge"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut settings = Map::new();
    settings.insert(
        "provider_integrations".to_owned(),
        json!([{"provider_id": SHIELD, "capability": "browser.origin-reputation",
                "require_fresh_check": false}]),
    );
    fixture.managed = ManagedProviderSettings::from_settings(&settings, true).unwrap();
    let answer = fixture.call("POST", &path("/settings"), with_proof(&change, &proof));
    assert_eq!((answer.status, code(&answer)), (409, SETTING_MANAGED));
    assert_eq!(stored_setting(&fixture), UNCHANGED);
}

#[test]
fn disconnect_deletes_the_key_settings_and_connection() {
    let mut fixture = Fixture::connected();
    put_capability_setting(
        &fixture.connection,
        SHIELD,
        Cap::OriginReputation,
        CapabilitySetting {
            effect_level: Level::Enforce,
            require_fresh: false,
        },
    )
    .unwrap();
    let preview = fixture.call("POST", &path("/disconnect/preview"), Value::Null);
    assert_eq!(preview.status, 200);
    let proof = preview.body["challenge"].as_str().unwrap().to_owned();
    assert!(fixture.key_stored(), "a preview deletes nothing");

    let answer = fixture.call("POST", &path("/disconnect"), json!({"proof": proof}));
    assert_eq!(answer.status, 200, "{}", answer.body);
    assert_eq!(answer.body["disconnected"], true);
    assert!(!fixture.key_stored());
    assert_eq!(
        provider_connection(&fixture.connection, SHIELD).unwrap(),
        None
    );
    assert_eq!(stored_setting(&fixture), UNCHANGED);

    let list = fixture.call("GET", PREFIX, Value::Null);
    assert_eq!(
        list.body["providers"][0]["state"],
        json!(State::NotConnected)
    );
}

#[test]
fn the_ledger_stays_bounded() {
    let mut fixture = Fixture::connected();
    for _ in 0..(MAX_PENDING_PROOFS * 2) {
        assert_eq!(
            fixture
                .call("POST", &path("/disconnect/preview"), Value::Null)
                .status,
            200
        );
    }
    assert_eq!(fixture.ledger.pending(), MAX_PENDING_PROOFS);
    fixture.now_ms = NOW + PROOF_TTL_MS;
    fixture.call("POST", &path("/disconnect/preview"), Value::Null);
    assert_eq!(fixture.ledger.pending(), 1);
}

#[test]
fn an_oversized_body_is_refused_even_when_it_is_only_whitespace() {
    let mut fixture = Fixture::connected();
    let context = RouteContext {
        enabled: true,
        providers: &fixture.providers,
        connection: &fixture.connection,
        managed: &fixture.managed,
        guard_home: fixture.home.path(),
        now_ms: NOW,
    };
    let route = path("/disconnect/preview");
    let blank = vec![b' '; MAX_ROUTE_BODY_BYTES];
    let answered = answer(&mut fixture.ledger, &context, "POST", &route, &blank).unwrap();
    assert_eq!(answered.status, 200);
    let oversized = vec![b' '; MAX_ROUTE_BODY_BYTES + 1];
    let answered = answer(&mut fixture.ledger, &context, "POST", &route, &oversized).unwrap();
    assert_eq!((answered.status, code(&answered)), (400, INVALID_REQUEST));
    assert_eq!(fixture.ledger.pending(), 1);
}

#[test]
fn a_failed_settings_apply_leaves_nothing_applied() {
    let mut fixture = Fixture::connected();
    let change = enforce_change();
    let proof = fixture
        .call("POST", &path("/settings/preview"), change.clone())
        .body["challenge"]
        .as_str()
        .unwrap()
        .to_owned();
    // The connection row is written last; make that write fail.
    fixture
        .connection
        .execute_batch(
            "create trigger refuse_connection_write before insert on provider_connections \
             begin select raise(abort, 'refused'); end;
             create trigger refuse_connection_update before update on provider_connections \
             begin select raise(abort, 'refused'); end;",
        )
        .unwrap();
    let answer = fixture.call("POST", &path("/settings"), with_proof(&change, &proof));
    assert_eq!(answer.status, 503, "{}", answer.body);
    assert_eq!(stored_setting(&fixture), UNCHANGED);
    let again = fixture.call("POST", &path("/settings"), with_proof(&change, &proof));
    assert_eq!(code(&again), PROOF_INVALID, "the proof stays spent");
}
