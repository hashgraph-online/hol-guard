use guard_contracts::{
    ProviderCapabilityV1 as Cap, ProviderConnectionStateV1 as State, ProviderInventoryV1,
    ProviderSignalStateV1, ProviderSignalV1, ProviderVerdictV1 as V, PROVIDER_SIGNAL_V1_VERSION,
};
use serde_json::{json, Value};

use super::*;
use crate::approval_browser_card::approval_browser_card;
use crate::provider_integration_routes::tests::{provider, SHIELD};
use crate::provider_integration_store::{
    ensure_provider_integration_schema, put_connection, put_signal, ProviderConnection,
};

const SITE: &str = "https://shop.example.com";
const OBSERVED: u64 = 600_000;
const EXPIRES: u64 = 1_200_000;

fn store(state: State, manifest_digest: &str) -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    ensure_provider_integration_schema(&connection).unwrap();
    put_connection(
        &connection,
        &ProviderConnection {
            provider_id: SHIELD.to_owned(),
            manifest_digest: manifest_digest.to_owned(),
            state,
            opt_in_facts: Vec::new(),
            connected_at_ms: 1_000,
            updated_at_ms: 1_000,
            last_verified_at_ms: Some(1_000),
        },
    )
    .unwrap();
    let (_, subject) = origin_subject(SITE).unwrap();
    put_signal(
        &connection,
        &ProviderSignalV1 {
            version: PROVIDER_SIGNAL_V1_VERSION,
            provider_id: SHIELD.to_owned(),
            capability: Cap::OriginReputation,
            subject,
            verdict: V::Danger,
            reason_codes: vec!["phishing".to_owned()],
            observed_at_ms: OBSERVED,
            expires_at_ms: EXPIRES,
            inventory: ProviderInventoryV1::ProviderSide,
            state: ProviderSignalStateV1::Fresh,
        },
    )
    .unwrap();
    connection
}

fn connected() -> Connection {
    store(State::Connected, &provider().manifest_digest)
}

#[test]
fn a_cached_answer_for_the_site_is_listed() {
    let rows = provider_rows(&connected(), &[provider()], SITE, OBSERVED + 1);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].provider_id, SHIELD);
    assert_eq!(rows[0].provider_name, "ExampleShield");
    assert_eq!(rows[0].verdict, V::Danger);
    assert_eq!(rows[0].state, ProviderSignalStateV1::Fresh);
    assert_eq!(rows[0].observed_at_ms, OBSERVED);
}

#[test]
fn the_same_origin_spelled_differently_finds_the_same_answer() {
    let rows = provider_rows(
        &connected(),
        &[provider()],
        "HTTPS://Shop.Example.Com:443/",
        OBSERVED + 1,
    );
    assert_eq!(rows.len(), 1);
}

#[test]
fn an_expired_answer_is_listed_as_stale() {
    let rows = provider_rows(&connected(), &[provider()], SITE, EXPIRES);
    assert_eq!(rows[0].state, ProviderSignalStateV1::Stale);
}

#[test]
fn another_site_a_disconnected_provider_or_a_changed_manifest_lists_nothing() {
    let now = OBSERVED + 1;
    assert!(provider_rows(
        &connected(),
        &[provider()],
        "https://other.example.org",
        now
    )
    .is_empty());
    let digest = provider().manifest_digest;
    for state in [State::Disabled, State::KeyInvalid] {
        assert!(provider_rows(&store(state, &digest), &[provider()], SITE, now).is_empty());
    }
    let changed = store(State::Connected, &format!("{:064x}", 9));
    assert!(provider_rows(&changed, &[provider()], SITE, now).is_empty());
    assert!(
        provider_rows(&connected(), &[], SITE, now).is_empty(),
        "a provider that no longer ships lists nothing"
    );
}

#[test]
fn a_store_without_provider_tables_or_a_private_origin_lists_nothing() {
    let bare = Connection::open_in_memory().unwrap();
    assert!(provider_rows(&bare, &[provider()], SITE, OBSERVED + 1).is_empty());
    assert!(provider_rows(
        &connected(),
        &[provider()],
        "http://127.0.0.1:3000",
        OBSERVED + 1
    )
    .is_empty());
    assert!(provider_rows(
        &connected(),
        &[provider()],
        "https://shop.example.test",
        OBSERVED + 1
    )
    .is_empty());
}

fn navigation(url: &str) -> Value {
    json!({
        "action_type": "mcp_tool",
        "tool_name": "mcp__playwright__browser_navigate",
        "raw_payload_redacted": {
            "tool_name": "mcp__playwright__browser_navigate",
            "tool_input": {"url": url},
        },
    })
}

#[test]
fn the_approval_card_carries_the_rows_for_its_site() {
    let store = connected();
    let rows = |origin: &str| provider_rows(&store, &[provider()], origin, OBSERVED + 1);
    let card = approval_browser_card(
        &navigation("https://shop.example.com/cart"),
        "claude-code",
        &rows,
    )
    .expect("card");
    let findings = card["provider_findings"].as_array().expect("provider rows");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["provider_id"], SHIELD);
    assert_eq!(findings[0]["verdict"], "danger");

    let elsewhere = approval_browser_card(
        &navigation("https://other.example.org/"),
        "claude-code",
        &rows,
    )
    .expect("card");
    assert_eq!(elsewhere["provider_findings"], json!([]));
}
