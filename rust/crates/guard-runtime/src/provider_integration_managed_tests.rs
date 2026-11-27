use guard_contracts::{
    ProviderCapabilityV1 as Cap, ProviderConnectionStateV1 as State,
    ProviderEffectLevelV1 as Level, ProviderInventoryV1, ProviderSignalStateV1, ProviderSignalV1,
    ProviderSubjectKindV1, ProviderSubjectV1, ProviderVerdictV1 as Verdict,
    PROVIDER_SIGNAL_V1_VERSION,
};
use guard_provider_integrations::noise::BaselineDecision::{self, Allow, Block, Review};
use guard_provider_integrations::noise::NoiseLedger;
use rusqlite::Connection;
use serde_json::{json, Value};

use super::*;
use crate::managed_policy::{parse_managed_policy, POLICY_SCHEMA_VERSION};
use crate::provider_integration_decide::{decide, DecideProvider, DecideRequest};
use crate::provider_integration_store::{
    ensure_provider_integration_schema, put_capability_setting, put_connection, put_signal,
    ProviderConnection,
};

const SHIELD: &str = "provider.exampleshield";
const OTHER: &str = "provider.otherwatch";
const NOW: u64 = 10_000_000;

fn settings(entries: Value) -> Map<String, Value> {
    let mut settings = Map::new();
    settings.insert(PROVIDER_INTEGRATIONS_SETTING.to_owned(), entries);
    settings
}

fn managed(entries: Value, locked: bool) -> ManagedProviderSettings {
    ManagedProviderSettings::from_settings(&settings(entries), locked).unwrap()
}

fn local(effect_level: Level, require_fresh: bool) -> CapabilitySetting {
    CapabilitySetting {
        effect_level,
        require_fresh,
    }
}

const LEVELS: [Level; 3] = [Level::Observe, Level::Tighten, Level::Enforce];

#[test]
fn no_managed_entry_keeps_the_local_setting() {
    let none = ManagedProviderSettings::none();
    let other = managed(
        json!([{"provider_id": OTHER, "capability": "browser.origin-reputation", "effect": "enforce"}]),
        true,
    );
    for level in LEVELS {
        for fresh in [false, true] {
            let setting = local(level, fresh);
            assert_eq!(
                none.effective(SHIELD, Cap::OriginReputation, setting),
                setting
            );
            assert_eq!(
                other.effective(SHIELD, Cap::OriginReputation, setting),
                setting
            );
            assert_eq!(
                other.effective(OTHER, Cap::DownloadReputation, setting),
                setting
            );
        }
    }
    assert!(other.locally_changeable(SHIELD, Cap::OriginReputation));
}

#[test]
fn an_unlocked_entry_is_a_floor_the_local_setting_cannot_go_below() {
    let floor = managed(
        json!([{"provider_id": SHIELD, "capability": "browser.origin-reputation",
                "effect": "tighten", "require_fresh_check": true}]),
        false,
    );
    for level in LEVELS {
        for fresh in [false, true] {
            let effective = floor.effective(SHIELD, Cap::OriginReputation, local(level, fresh));
            assert_eq!(effective.effect_level, level.max(Level::Tighten));
            assert!(effective.require_fresh);
        }
    }
    assert!(floor.locally_changeable(SHIELD, Cap::OriginReputation));

    let off = managed(
        json!([{"provider_id": SHIELD, "capability": "browser.origin-reputation",
                "require_fresh_check": false}]),
        false,
    );
    let effective = off.effective(SHIELD, Cap::OriginReputation, local(Level::Enforce, true));
    assert_eq!(
        effective,
        local(Level::Enforce, true),
        "a floor never loosens"
    );
}

#[test]
fn a_locked_entry_replaces_the_fields_it_names() {
    let exact = managed(
        json!([{"provider_id": SHIELD, "capability": "browser.origin-reputation",
                "effect": "enforce", "require_fresh_check": false}]),
        true,
    );
    for level in LEVELS {
        for fresh in [false, true] {
            assert_eq!(
                exact.effective(SHIELD, Cap::OriginReputation, local(level, fresh)),
                local(Level::Enforce, false)
            );
        }
    }
    assert!(!exact.locally_changeable(SHIELD, Cap::OriginReputation));

    let partial = managed(
        json!([{"provider_id": SHIELD, "capability": "browser.origin-reputation", "effect": "observe"}]),
        true,
    );
    assert_eq!(
        partial.effective(SHIELD, Cap::OriginReputation, local(Level::Enforce, true)),
        local(Level::Observe, true)
    );
    assert!(partial.locally_changeable(SHIELD, Cap::OriginReputation));
}

#[test]
fn a_malformed_value_is_an_error_not_an_empty_list() {
    let bad = [
        json!({"provider_id": SHIELD}),
        json!("enforce"),
        json!([7]),
        json!([{"capability": "browser.origin-reputation", "effect": "enforce"}]),
        json!([{"provider_id": "", "capability": "browser.origin-reputation", "effect": "enforce"}]),
        json!([{"provider_id": "Provider One", "capability": "browser.origin-reputation", "effect": "enforce"}]),
        json!([{"provider_id": SHIELD, "effect": "enforce"}]),
        json!([{"provider_id": SHIELD, "capability": "mind_reading", "effect": "enforce"}]),
        json!([{"provider_id": SHIELD, "capability": "browser.origin-reputation", "effect": "block"}]),
        json!([{"provider_id": SHIELD, "capability": "browser.origin-reputation", "effect": 2}]),
        json!([{"provider_id": SHIELD, "capability": "browser.origin-reputation",
                "require_fresh_check": "yes"}]),
        json!([{"provider_id": SHIELD, "capability": "browser.origin-reputation"}]),
        json!([{"provider_id": SHIELD, "capability": "browser.origin-reputation", "effect": "enforce",
                "quieted_reason_codes": []}]),
        json!([
            {"provider_id": SHIELD, "capability": "browser.origin-reputation", "effect": "enforce"},
            {"provider_id": SHIELD, "capability": "browser.origin-reputation", "effect": "observe"}
        ]),
    ];
    for entries in bad {
        assert!(
            ManagedProviderSettings::from_settings(&settings(entries.clone()), false).is_err(),
            "{entries} was accepted"
        );
    }
    let too_many: Vec<Value> = (0..=MAX_MANAGED_PROVIDER_ENTRIES)
        .map(|index| {
            json!({"provider_id": format!("provider.fixture-{index}"),
                   "capability": "browser.origin-reputation", "effect": "enforce"})
        })
        .collect();
    assert!(
        ManagedProviderSettings::from_settings(&settings(Value::Array(too_many)), false).is_err()
    );
    assert_eq!(
        ManagedProviderSettings::from_settings(&Map::new(), true).unwrap(),
        ManagedProviderSettings {
            entries: BTreeMap::new(),
            locked: true,
        }
    );
}

#[test]
fn an_installed_policy_locks_through_locked_settings() {
    let policy = parse_managed_policy(&json!({
        "schemaVersion": POLICY_SCHEMA_VERSION,
        "settings": {"provider_integrations": [
            {"provider_id": SHIELD, "capability": "browser.origin-reputation", "effect": "enforce"}
        ]},
        "lockedSettings": ["provider_integrations"],
    }))
    .unwrap();
    let managed = ManagedProviderSettings::from_policy(&policy).unwrap();
    assert!(managed.is_locked());
    assert_eq!(
        managed.entry(SHIELD, Cap::OriginReputation),
        Some(ManagedCapabilitySetting {
            effect: Some(Level::Enforce),
            require_fresh_check: None,
        })
    );

    let unlocked = parse_managed_policy(&json!({
        "schemaVersion": POLICY_SCHEMA_VERSION,
        "settings": {"provider_integrations": []},
    }))
    .unwrap();
    assert!(!ManagedProviderSettings::from_policy(&unlocked)
        .unwrap()
        .is_locked());
}

fn digest(n: u64) -> String {
    format!("{n:064x}")
}

fn store_with_danger() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    ensure_provider_integration_schema(&connection).unwrap();
    put_connection(
        &connection,
        &ProviderConnection {
            provider_id: SHIELD.to_owned(),
            manifest_digest: digest(7),
            state: State::Connected,
            opt_in_facts: Vec::new(),
            connected_at_ms: 1_000,
            updated_at_ms: 1_000,
            last_verified_at_ms: Some(1_000),
        },
    )
    .unwrap();
    put_signal(
        &connection,
        &ProviderSignalV1 {
            version: PROVIDER_SIGNAL_V1_VERSION,
            provider_id: SHIELD.to_owned(),
            capability: Cap::OriginReputation,
            subject: ProviderSubjectV1 {
                kind: ProviderSubjectKindV1::Origin,
                digest: digest(1),
            },
            verdict: Verdict::Danger,
            reason_codes: vec!["phishing".to_owned()],
            observed_at_ms: NOW - 1_000,
            expires_at_ms: NOW + 60_000,
            inventory: ProviderInventoryV1::None,
            state: ProviderSignalStateV1::Fresh,
        },
    )
    .unwrap();
    connection
}

fn run(
    connection: &Connection,
    subject: u64,
    baseline: BaselineDecision,
    managed: &ManagedProviderSettings,
) -> crate::provider_integration_decide::ProviderDecision {
    let digest = digest(subject);
    decide(
        connection,
        &mut NoiseLedger::new(),
        &DecideRequest {
            baseline,
            capability: Cap::OriginReputation,
            subject_digest: &digest,
            providers: &[DecideProvider {
                provider_id: SHIELD,
                verified: true,
            }],
            now_ms: NOW,
            managed,
        },
    )
    .unwrap()
}

#[test]
fn decide_applies_the_managed_setting() {
    let connection = store_with_danger();
    let none = ManagedProviderSettings::none();
    assert_eq!(run(&connection, 1, Allow, &none).decision, Review);

    let enforce = managed(
        json!([{"provider_id": SHIELD, "capability": "browser.origin-reputation", "effect": "enforce"}]),
        false,
    );
    assert_eq!(run(&connection, 1, Allow, &enforce).decision, Block);

    let fresh = managed(
        json!([{"provider_id": SHIELD, "capability": "browser.origin-reputation",
                "require_fresh_check": true}]),
        false,
    );
    let no_answer = run(&connection, 2, Allow, &fresh);
    assert_eq!(no_answer.decision, Review);
    assert_eq!(no_answer.fresh_check_required, vec![SHIELD.to_owned()]);
    assert_eq!(run(&connection, 2, Allow, &none).decision, Allow);
}

#[test]
fn a_local_setting_cannot_loosen_a_managed_floor_and_a_lock_wins() {
    let connection = store_with_danger();
    put_capability_setting(
        &connection,
        SHIELD,
        Cap::OriginReputation,
        local(Level::Observe, false),
    )
    .unwrap();
    assert_eq!(
        run(&connection, 1, Allow, &ManagedProviderSettings::none()).decision,
        Allow,
        "observe alone only records"
    );
    let floor = managed(
        json!([{"provider_id": SHIELD, "capability": "browser.origin-reputation", "effect": "enforce"}]),
        false,
    );
    assert_eq!(run(&connection, 1, Allow, &floor).decision, Block);

    put_capability_setting(
        &connection,
        SHIELD,
        Cap::OriginReputation,
        local(Level::Enforce, false),
    )
    .unwrap();
    let locked_observe = managed(
        json!([{"provider_id": SHIELD, "capability": "browser.origin-reputation", "effect": "observe"}]),
        true,
    );
    let decided = run(&connection, 1, Review, &locked_observe);
    assert_eq!(
        decided.decision, Review,
        "never weaker than Guard's own decision"
    );
    assert_eq!(run(&connection, 1, Allow, &locked_observe).decision, Allow);
}
