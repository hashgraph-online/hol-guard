use guard_contracts::{
    ProviderCapabilityV1 as Cap, ProviderConnectionStateV1 as State,
    ProviderEffectLevelV1 as Level, ProviderInventoryV1, ProviderSignalStateV1, ProviderSignalV1,
    ProviderVerdictV1 as V, PROVIDER_SIGNAL_V1_VERSION,
};

use super::*;
use crate::provider_integration_routes::tests::{provider, SHIELD};
use crate::provider_integration_store::{
    ensure_provider_integration_schema, put_capability_setting, put_connection, put_signal,
    CapabilitySetting, ProviderConnection,
};

const SITE: &str = "https://shop.example.com";
const OBSERVED: u64 = 600_000;
const EXPIRES: u64 = 1_200_000;
const NOW: u64 = OBSERVED + 1;

fn store(verdict: V, manifest_digest: &str) -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    ensure_provider_integration_schema(&connection).unwrap();
    put_connection(
        &connection,
        &ProviderConnection {
            provider_id: SHIELD.to_owned(),
            manifest_digest: manifest_digest.to_owned(),
            state: State::Connected,
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
            verdict,
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

fn connected(verdict: V) -> Connection {
    store(verdict, &provider().manifest_digest)
}

fn enforce(connection: &Connection) {
    put_capability_setting(
        connection,
        SHIELD,
        Cap::OriginReputation,
        CapabilitySetting {
            effect_level: Level::Enforce,
            require_fresh: false,
        },
    )
    .unwrap();
}

fn current(action: GuardAction) -> Current {
    Current {
        action,
        source: "guard".to_owned(),
        signals: vec!["browser-navigation".to_owned()],
        summary: "Guard's own recommendation.".to_owned(),
        risk_categories: Vec::new(),
    }
}

fn run(connection: &Connection, origin: &str, now_ms: u64, action: GuardAction) -> Current {
    run_with(
        connection,
        Some(&ManagedProviderSettings::none()),
        origin,
        now_ms,
        action,
    )
}

fn run_with(
    connection: &Connection,
    managed: Option<&ManagedProviderSettings>,
    origin: &str,
    now_ms: u64,
    action: GuardAction,
) -> Current {
    let providers = [provider()];
    floor(&Floor {
        connection,
        providers: &providers,
        managed,
        origin,
        now_ms,
        current: current(action),
    })
}

fn unchanged(result: &Current, action: GuardAction) {
    assert_eq!(result.action, action);
    assert_eq!(result.source, "guard");
    assert_eq!(result.signals, vec!["browser-navigation".to_owned()]);
}

#[test]
fn no_shipped_provider_leaves_the_call_as_guard_decided() {
    // This build ships no provider manifest, so neither the hook nor the relay opens or reads
    // anything for a provider, whatever the call.
    assert!(shipped_providers().is_empty());
    let connection = connected(V::Danger);
    for action in [GuardAction::Allow, GuardAction::Review, GuardAction::Block] {
        let result = with_provider_floor(Some(&connection), None, current(action));
        unchanged(&result, action);
    }
    assert!(open_provider_store(None).is_none());
}

#[test]
fn a_fresh_danger_answer_reviews_an_allowed_call() {
    let result = run(&connected(V::Danger), SITE, NOW, GuardAction::Allow);
    assert_eq!(result.action, GuardAction::Review);
    assert_eq!(result.source, PROVIDER_REVIEW_SOURCE);
    assert!(result
        .signals
        .contains(&format!("{PROVIDER_REVIEW_SOURCE}:{SHIELD}")));
    assert_eq!(result.signals[0], "browser-navigation");
}

#[test]
fn an_enforced_danger_answer_blocks_even_a_reviewed_call() {
    let connection = connected(V::Danger);
    enforce(&connection);
    for action in [
        GuardAction::Allow,
        GuardAction::Review,
        GuardAction::RequireReapproval,
    ] {
        let result = run(&connection, SITE, NOW, action);
        assert_eq!(result.action, GuardAction::Block, "{action:?}");
        assert_eq!(result.source, PROVIDER_BLOCK_SOURCE);
    }
}

#[test]
fn provider_answers_never_loosen_guard() {
    for verdict in [V::Ok, V::Caution, V::Danger, V::Unknown] {
        let connection = connected(verdict);
        enforce(&connection);
        let blocked = run(&connection, SITE, NOW, GuardAction::Block);
        unchanged(&blocked, GuardAction::Block);
        let reviewed = run(&connection, SITE, NOW, GuardAction::Review);
        assert!(
            reviewed.action.severity() >= GuardAction::Review.severity(),
            "{verdict:?}"
        );
    }
    for verdict in [V::Ok, V::Unknown] {
        let allowed = run(&connected(verdict), SITE, NOW, GuardAction::Allow);
        unchanged(&allowed, GuardAction::Allow);
    }
}

#[test]
fn a_review_guard_raises_anyway_keeps_its_own_reason() {
    let result = run(&connected(V::Danger), SITE, NOW, GuardAction::Review);
    unchanged(&result, GuardAction::Review);
}

#[test]
fn stale_answers_other_sites_private_origins_and_old_manifests_change_nothing() {
    unchanged(
        &run(&connected(V::Danger), SITE, EXPIRES, GuardAction::Allow),
        GuardAction::Allow,
    );
    unchanged(
        &run(
            &connected(V::Danger),
            "https://other.example.org",
            NOW,
            GuardAction::Allow,
        ),
        GuardAction::Allow,
    );
    unchanged(
        &run(
            &connected(V::Danger),
            "http://127.0.0.1:3000",
            NOW,
            GuardAction::Allow,
        ),
        GuardAction::Allow,
    );
    let old_manifest = store(V::Danger, &format!("{:064x}", 9));
    unchanged(
        &run(&old_manifest, SITE, NOW, GuardAction::Allow),
        GuardAction::Allow,
    );
    let bare = Connection::open_in_memory().unwrap();
    unchanged(
        &run(&bare, SITE, NOW, GuardAction::Allow),
        GuardAction::Allow,
    );
}

#[test]
fn the_same_origin_spelled_differently_finds_the_same_answer() {
    let result = run(
        &connected(V::Danger),
        "HTTPS://Shop.Example.Com:443/",
        NOW,
        GuardAction::Allow,
    );
    assert_eq!(result.action, GuardAction::Review);
}

#[test]
fn unknown_managed_settings_review_a_site_a_connected_provider_could_answer() {
    let connection = connected(V::Ok);
    let result = run_with(&connection, None, SITE, NOW, GuardAction::Allow);
    assert_eq!(result.action, GuardAction::Review);
    assert_eq!(result.source, PROVIDER_MANAGED_UNKNOWN_SOURCE);
    let blocked = run_with(&connection, None, SITE, NOW, GuardAction::Block);
    unchanged(&blocked, GuardAction::Block);
    let old_manifest = store(V::Ok, &format!("{:064x}", 9));
    unchanged(
        &run_with(&old_manifest, None, SITE, NOW, GuardAction::Allow),
        GuardAction::Allow,
    );
}

#[test]
fn a_missing_fresh_check_reviews_without_naming_a_provider_finding() {
    let connection = connected(V::Ok);
    put_capability_setting(
        &connection,
        SHIELD,
        Cap::OriginReputation,
        CapabilitySetting {
            effect_level: Level::Tighten,
            require_fresh: true,
        },
    )
    .unwrap();
    let result = run(&connection, SITE, EXPIRES, GuardAction::Allow);
    assert_eq!(result.action, GuardAction::Review);
    assert_eq!(result.source, PROVIDER_FRESH_CHECK_SOURCE);
    assert_eq!(
        result.signals.last().unwrap(),
        &format!("{PROVIDER_FRESH_CHECK_SOURCE}:{SHIELD}")
    );
    assert!(!result.summary.contains("flagged"));
}

#[test]
fn a_fresh_ok_beside_a_missing_fresh_check_is_not_named_as_the_flag() {
    const OTHER: &str = "provider.otherwatch";
    let connection = connected(V::Ok);
    let mut other = provider();
    other.id = OTHER.to_owned();
    put_connection(
        &connection,
        &ProviderConnection {
            provider_id: OTHER.to_owned(),
            manifest_digest: other.manifest_digest.clone(),
            state: State::Connected,
            opt_in_facts: Vec::new(),
            connected_at_ms: 1_000,
            updated_at_ms: 1_000,
            last_verified_at_ms: Some(1_000),
        },
    )
    .unwrap();
    put_capability_setting(
        &connection,
        OTHER,
        Cap::OriginReputation,
        CapabilitySetting {
            effect_level: Level::Tighten,
            require_fresh: true,
        },
    )
    .unwrap();
    let providers = [provider(), other];
    let result = floor(&Floor {
        connection: &connection,
        providers: &providers,
        managed: Some(&ManagedProviderSettings::none()),
        origin: SITE,
        now_ms: NOW,
        current: current(GuardAction::Allow),
    });
    assert_eq!(result.action, GuardAction::Review);
    assert_eq!(result.source, PROVIDER_FRESH_CHECK_SOURCE);
    assert_eq!(
        result.signals.last().unwrap(),
        &format!("{PROVIDER_FRESH_CHECK_SOURCE}:{OTHER}")
    );
    assert!(!result.summary.contains("flagged"));
}

#[test]
fn the_snapshot_nests_in_a_caller_transaction_and_is_always_ended() {
    let connection = connected(V::Danger);
    connection.execute_batch("begin").unwrap();
    assert_eq!(
        run(&connection, SITE, NOW, GuardAction::Allow).action,
        GuardAction::Review
    );
    assert!(
        !connection.is_autocommit(),
        "the caller's transaction is still open"
    );
    connection.execute_batch("commit").unwrap();
    assert_eq!(
        run(&connection, SITE, NOW, GuardAction::Allow).action,
        GuardAction::Review
    );
    assert!(connection.is_autocommit(), "no snapshot is left open");
}
