use guard_contracts::{
    ProviderCapabilityV1 as Cap, ProviderConnectionStateV1 as State,
    ProviderEffectLevelV1 as Level, ProviderInventoryV1, ProviderShareableFactV1 as Fact,
    ProviderSignalStateV1, ProviderSubjectKindV1, ProviderSubjectV1, ProviderVerdictV1 as V,
};
use rusqlite::Connection;

use super::*;

const SHIELD: &str = "provider.exampleshield";
const WATCH: &str = "provider.otherwatch";
const MINUTE: u64 = 60 * 1000;

fn store() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    ensure_provider_integration_schema(&connection).unwrap();
    connection
}

fn digest(seed: u64) -> String {
    format!("{seed:064x}")
}

fn connected(provider_id: &str) -> ProviderConnection {
    ProviderConnection {
        provider_id: provider_id.to_owned(),
        manifest_digest: digest(7),
        state: State::Connected,
        opt_in_facts: Vec::new(),
        connected_at_ms: 1_000,
        updated_at_ms: 1_000,
        last_verified_at_ms: Some(1_000),
    }
}

fn signal(provider_id: &str, subject: u64, verdict: V, codes: &[&str]) -> ProviderSignalV1 {
    ProviderSignalV1 {
        version: PROVIDER_SIGNAL_V1_VERSION,
        provider_id: provider_id.to_owned(),
        capability: Cap::OriginReputation,
        subject: ProviderSubjectV1 {
            kind: ProviderSubjectKindV1::Origin,
            digest: digest(subject),
        },
        verdict,
        reason_codes: codes.iter().map(|code| (*code).to_owned()).collect(),
        observed_at_ms: 10 * MINUTE,
        expires_at_ms: 20 * MINUTE,
        inventory: ProviderInventoryV1::ProviderSide,
        state: ProviderSignalStateV1::Fresh,
    }
}

#[test]
fn schema_is_idempotent_and_refuses_foreign_objects() {
    let connection = store();
    ensure_provider_integration_schema(&connection).unwrap();
    connection
        .execute_batch("create index idx_provider_signals_extra on provider_signals (verdict)")
        .unwrap();
    assert!(matches!(
        ensure_provider_integration_schema(&connection),
        Err(ProviderStoreError::Schema(_))
    ));
    connection
        .execute_batch("drop index idx_provider_signals_extra")
        .unwrap();
    ensure_provider_integration_schema(&connection).unwrap();
}

#[test]
fn schema_refuses_a_changed_table() {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch("create table provider_signals (provider_id text, url text)")
        .unwrap();
    assert!(ensure_provider_integration_schema(&connection).is_err());
    let tables: i64 = connection
        .query_row(
            "select count(*) from sqlite_master where name = 'provider_connections'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(tables, 0, "a failed check rolls back");
}

#[test]
fn connections_round_trip_and_change_state() {
    let connection = store();
    let mut record = connected(SHIELD);
    record.opt_in_facts = vec![Fact::TargetPathPrefix];
    put_connection(&connection, &record).unwrap();
    put_connection(&connection, &connected(WATCH)).unwrap();
    assert_eq!(
        provider_connection(&connection, SHIELD).unwrap(),
        Some(record)
    );
    assert!(set_connection_state(&connection, SHIELD, State::KeyInvalid, 2_000).unwrap());
    let stored = provider_connection(&connection, SHIELD).unwrap().unwrap();
    assert_eq!(stored.state, State::KeyInvalid);
    assert_eq!(stored.updated_at_ms, 2_000);
    assert_eq!(stored.connected_at_ms, 1_000);
    assert!(!set_connection_state(&connection, "provider.absent", State::Disabled, 2_000).unwrap());
    let ids: Vec<_> = provider_connections(&connection)
        .unwrap()
        .into_iter()
        .map(|record| record.provider_id)
        .collect();
    assert_eq!(ids, [SHIELD, WATCH]);
    assert_eq!(
        provider_connection(&connection, "provider.absent").unwrap(),
        None
    );
}

#[test]
fn connections_refuse_values_outside_the_contract() {
    let connection = store();
    for (record, reason) in [
        (
            ProviderConnection {
                provider_id: "Shield".to_owned(),
                ..connected(SHIELD)
            },
            "provider_id",
        ),
        (
            ProviderConnection {
                manifest_digest: "https://shop.example.test/".to_owned(),
                ..connected(SHIELD)
            },
            "manifest_digest",
        ),
        (
            ProviderConnection {
                state: State::NotConnected,
                ..connected(SHIELD)
            },
            "state",
        ),
        (
            ProviderConnection {
                opt_in_facts: vec![Fact::TargetOrigin],
                ..connected(SHIELD)
            },
            "opt_in_facts",
        ),
    ] {
        assert!(
            matches!(put_connection(&connection, &record), Err(ProviderStoreError::Invalid(r)) if r == reason),
            "{reason}"
        );
    }
    assert!(set_connection_state(&connection, SHIELD, State::NotConnected, 1).is_err());
    assert!(matches!(
        set_connection_state(&connection, "Shield", State::Disabled, 1),
        Err(ProviderStoreError::Invalid("provider_id"))
    ));
    assert!(provider_connections(&connection).unwrap().is_empty());
}

#[test]
fn capability_settings_default_to_tighten_and_need_a_connection() {
    let connection = store();
    let setting = CapabilitySetting {
        effect_level: Level::Enforce,
        require_fresh: true,
    };
    assert!(matches!(
        put_capability_setting(&connection, SHIELD, Cap::OriginReputation, setting),
        Err(ProviderStoreError::Invalid("not_connected"))
    ));
    assert!(matches!(
        put_capability_setting(&connection, "Shield", Cap::OriginReputation, setting),
        Err(ProviderStoreError::Invalid("provider_id"))
    ));
    put_connection(&connection, &connected(SHIELD)).unwrap();
    let defaults = capability_settings(&connection, SHIELD).unwrap();
    assert_eq!(defaults.len(), Cap::ALL.len());
    assert!(defaults.values().all(|value| *value
        == CapabilitySetting {
            effect_level: Level::Tighten,
            require_fresh: false
        }));
    put_capability_setting(&connection, SHIELD, Cap::OriginReputation, setting).unwrap();
    let settings = capability_settings(&connection, SHIELD).unwrap();
    assert_eq!(settings[&Cap::OriginReputation], setting);
    assert_eq!(
        settings[&Cap::ScriptIntegrity],
        CapabilitySetting::default()
    );
}

fn stored(connection: &Connection, signal: &ProviderSignalV1) -> u64 {
    match put_signal(connection, signal).unwrap() {
        PutSignalOutcome::Stored(revision) => revision,
        PutSignalOutcome::NotRetained => panic!("signal was not retained"),
    }
}

#[test]
fn revision_moves_only_when_the_answer_changes() {
    let connection = store();
    let first = signal(SHIELD, 1, V::Caution, &["new_domain", "phishing"]);
    let one = stored(&connection, &first);
    assert_eq!(stored(&connection, &at(first.clone(), 15)), one);
    assert_eq!(
        stored(
            &connection,
            &at(
                signal(
                    SHIELD,
                    1,
                    V::Caution,
                    &["phishing", "new_domain", "phishing"]
                ),
                16
            )
        ),
        one,
        "the same codes in another order are the same answer"
    );
    let two = stored(
        &connection,
        &at(signal(SHIELD, 1, V::Caution, &["lookalike_domain"]), 17),
    );
    assert!(two > one);
    let three = stored(
        &connection,
        &at(signal(SHIELD, 1, V::Danger, &["lookalike_domain"]), 18),
    );
    assert!(three > two);
    assert!(stored(&connection, &signal(SHIELD, 2, V::Danger, &[])) > three);
}

/// The same signal, observed at `minute` and valid for ten minutes after it.
fn at(signal: ProviderSignalV1, minute: u64) -> ProviderSignalV1 {
    ProviderSignalV1 {
        observed_at_ms: minute * MINUTE,
        expires_at_ms: (minute + 10) * MINUTE,
        ..signal
    }
}

#[test]
fn a_changed_answer_never_reuses_a_revision_after_its_row_is_gone() {
    let connection = store();
    let caution = signal(SHIELD, 1, V::Caution, &["new_domain"]);
    let first = stored(&connection, &caution);
    prune_expired_signals(&connection, u64::MAX / 2).unwrap();
    let after_prune = stored(&connection, &signal(SHIELD, 1, V::Danger, &["phishing"]));
    assert!(after_prune > first);
    put_connection(&connection, &connected(SHIELD)).unwrap();
    forget_provider(&connection, SHIELD).unwrap();
    assert!(stored(&connection, &caution) > after_prune);
}

#[test]
fn an_observation_older_than_a_full_cache_is_not_retained() {
    let connection = store();
    for subject in 0..MAX_SIGNALS_PER_PROVIDER as u64 {
        let mut row = signal(SHIELD, subject, V::Ok, &[]);
        row.observed_at_ms = 1_000 + subject;
        row.expires_at_ms = 1_000 + subject + MINUTE;
        stored(&connection, &row);
    }
    let mut old = signal(SHIELD, 999_999, V::Danger, &["phishing"]);
    old.observed_at_ms = 1;
    old.expires_at_ms = MINUTE;
    assert_eq!(
        put_signal(&connection, &old).unwrap(),
        PutSignalOutcome::NotRetained
    );
    assert!(
        signals_for_subject(&connection, Cap::OriginReputation, &digest(999_999))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn a_late_stale_observation_never_replaces_a_newer_answer() {
    let connection = store();
    let danger = signal(SHIELD, 1, V::Danger, &["phishing"]);
    let revision = stored(&connection, &danger);
    let mut stale = signal(SHIELD, 1, V::Ok, &[]);
    stale.observed_at_ms = danger.observed_at_ms - 1;
    assert_eq!(
        put_signal(&connection, &stale).unwrap(),
        PutSignalOutcome::NotRetained
    );
    let found = signals_for_subject(&connection, Cap::OriginReputation, &digest(1)).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].signal.verdict, V::Danger);
    assert_eq!(found[0].revision, revision);
    let mut changed = signal(SHIELD, 2, V::Caution, &["new_domain"]);
    changed.observed_at_ms = danger.observed_at_ms;
    assert_eq!(stored(&connection, &changed), revision + 1);
}

#[test]
fn a_dropped_observation_leaves_the_cache_and_counter_alone() {
    let connection = store();
    let mut last = 0;
    for subject in 0..MAX_SIGNALS_PER_PROVIDER as u64 {
        let mut row = signal(SHIELD, subject, V::Ok, &[]);
        row.observed_at_ms = 1_000 + subject;
        row.expires_at_ms = 1_000 + subject + MINUTE;
        last = stored(&connection, &row);
    }
    let mut old = signal(SHIELD, 999_999, V::Danger, &["phishing"]);
    old.observed_at_ms = 1;
    old.expires_at_ms = MINUTE;
    assert_eq!(
        put_signal(&connection, &old).unwrap(),
        PutSignalOutcome::NotRetained
    );
    let mut next = signal(SHIELD, 0, V::Danger, &["phishing"]);
    next.observed_at_ms = 1_000_000;
    next.expires_at_ms = 1_000_000 + MINUTE;
    assert_eq!(stored(&connection, &next), last + 1);
}

#[test]
fn schema_refuses_a_trigger_on_an_owned_table_whatever_its_name() {
    let connection = store();
    connection
        .execute_batch(
            "create trigger refresh_audit before insert on provider_signals \
             begin select raise(ignore); end",
        )
        .unwrap();
    assert!(matches!(
        ensure_provider_integration_schema(&connection),
        Err(ProviderStoreError::Schema(_))
    ));
}

#[test]
fn an_empty_field_in_a_stored_list_is_damage() {
    let connection = store();
    stored(&connection, &signal(SHIELD, 1, V::Danger, &["phishing"]));
    connection
        .execute(
            "update provider_signals set reason_codes = 'phishing,,new_domain'",
            [],
        )
        .unwrap();
    assert!(matches!(
        signals_for_subject(&connection, Cap::OriginReputation, &digest(1)),
        Err(ProviderStoreError::Schema(_))
    ));
    let mut record = connected(SHIELD);
    record.opt_in_facts = vec![Fact::TargetPathPrefix];
    put_connection(&connection, &record).unwrap();
    connection
        .execute(
            "update provider_connections set opt_in_facts = opt_in_facts || ','",
            [],
        )
        .unwrap();
    assert!(matches!(
        provider_connection(&connection, SHIELD),
        Err(ProviderStoreError::Schema(_))
    ));
}

#[test]
fn subject_reads_return_every_provider_including_stale_rows() {
    let connection = store();
    put_signal(&connection, &signal(WATCH, 1, V::Ok, &[])).unwrap();
    put_signal(&connection, &signal(SHIELD, 1, V::Danger, &["phishing"])).unwrap();
    let stale = ProviderSignalV1 {
        state: ProviderSignalStateV1::Stale,
        ..signal(SHIELD, 2, V::Caution, &[])
    };
    put_signal(&connection, &stale).unwrap();
    let other_capability = ProviderSignalV1 {
        capability: Cap::ScriptIntegrity,
        ..signal(SHIELD, 1, V::Caution, &[])
    };
    put_signal(&connection, &other_capability).unwrap();

    let found = signals_for_subject(&connection, Cap::OriginReputation, &digest(1)).unwrap();
    assert_eq!(found.len(), 2);
    assert_eq!(found[0].signal, signal(SHIELD, 1, V::Danger, &["phishing"]));
    assert_eq!(found[1].signal.provider_id, WATCH);
    let stale_found = signals_for_subject(&connection, Cap::OriginReputation, &digest(2)).unwrap();
    assert_eq!(stale_found[0].signal, stale);
    assert!(signals_for_subject(&connection, Cap::OriginReputation, "shop.example.test").is_err());
}

#[test]
fn signals_hold_digests_and_codes_only() {
    let connection = store();
    let url_subject = ProviderSignalV1 {
        subject: ProviderSubjectV1 {
            kind: ProviderSubjectKindV1::Origin,
            digest: "https://shop.example.test/checkout".to_owned(),
        },
        ..signal(SHIELD, 1, V::Danger, &[])
    };
    let free_text = signal(SHIELD, 1, V::Danger, &["Visit https://shop.example.test"]);
    for bad in [url_subject, free_text] {
        assert!(matches!(
            put_signal(&connection, &bad),
            Err(ProviderStoreError::Invalid(_))
        ));
    }
    put_connection(&connection, &connected(SHIELD)).unwrap();
    put_signal(
        &connection,
        &signal(SHIELD, 1, V::Danger, &["phishing", "new_domain"]),
    )
    .unwrap();
    for table in [
        "provider_connections",
        "provider_signals",
        "provider_capability_settings",
    ] {
        let mut statement = connection
            .prepare(&format!("select * from {table}"))
            .unwrap();
        let width = statement.column_count();
        let mut rows = statement.query([]).unwrap();
        while let Some(row) = rows.next().unwrap() {
            for index in 0..width {
                if let Ok(Some(text)) = row.get::<_, Option<String>>(index) {
                    assert!(
                        !text.contains("://") && !text.contains('/') && !text.contains(' '),
                        "{table} column {index} holds {text:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn a_damaged_row_is_an_error_not_a_missing_signal() {
    let connection = store();
    put_signal(&connection, &signal(SHIELD, 1, V::Danger, &["phishing"])).unwrap();
    connection
        .execute("update provider_signals set verdict = 'allow'", [])
        .unwrap();
    assert!(matches!(
        signals_for_subject(&connection, Cap::OriginReputation, &digest(1)),
        Err(ProviderStoreError::Schema(_))
    ));
    connection
        .execute(
            "update provider_signals set verdict = 'danger', reason_codes = 'Call Us'",
            [],
        )
        .unwrap();
    assert!(signals_for_subject(&connection, Cap::OriginReputation, &digest(1)).is_err());
}

#[test]
fn prune_keeps_recently_expired_rows_for_the_card() {
    let connection = store();
    put_signal(&connection, &signal(SHIELD, 1, V::Caution, &[])).unwrap();
    let expires = 20 * MINUTE;
    assert_eq!(
        prune_expired_signals(&connection, expires + EXPIRED_SIGNAL_GRACE_MS).unwrap(),
        0
    );
    assert_eq!(
        prune_expired_signals(&connection, expires + EXPIRED_SIGNAL_GRACE_MS + 1).unwrap(),
        1
    );
}

#[test]
fn forget_provider_drops_its_rows_only() {
    let connection = store();
    for provider in [SHIELD, WATCH] {
        put_connection(&connection, &connected(provider)).unwrap();
        put_capability_setting(
            &connection,
            provider,
            Cap::OriginReputation,
            CapabilitySetting::default(),
        )
        .unwrap();
        put_signal(&connection, &signal(provider, 1, V::Caution, &[])).unwrap();
    }
    assert!(forget_provider(&connection, SHIELD).unwrap());
    assert!(!forget_provider(&connection, SHIELD).unwrap());
    assert_eq!(provider_connection(&connection, SHIELD).unwrap(), None);
    let left = signals_for_subject(&connection, Cap::OriginReputation, &digest(1)).unwrap();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].signal.provider_id, WATCH);
    let settings: i64 = connection
        .query_row(
            "select count(*) from provider_capability_settings where provider_id = ?1",
            [SHIELD],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(settings, 0);
}

#[test]
fn each_provider_keeps_a_bounded_cache() {
    let connection = store();
    let extra = 3;
    for subject in 0..(MAX_SIGNALS_PER_PROVIDER as u64 + extra) {
        let mut row = signal(SHIELD, subject, V::Ok, &[]);
        row.observed_at_ms = subject;
        row.expires_at_ms = subject + MINUTE;
        put_signal(&connection, &row).unwrap();
    }
    put_signal(&connection, &signal(WATCH, 0, V::Ok, &[])).unwrap();
    let count = |provider: &str| -> i64 {
        connection
            .query_row(
                "select count(*) from provider_signals where provider_id = ?1",
                [provider],
                |row| row.get(0),
            )
            .unwrap()
    };
    assert_eq!(count(SHIELD), MAX_SIGNALS_PER_PROVIDER);
    assert_eq!(count(WATCH), 1);
    assert!(
        signals_for_subject(&connection, Cap::OriginReputation, &digest(0))
            .unwrap()
            .iter()
            .all(|stored| stored.signal.provider_id == WATCH)
    );
}
