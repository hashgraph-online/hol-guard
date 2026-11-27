use guard_command::provider_integration_compile::{CompiledProviderAuthV1, ProviderKeyCharsetV1};
use guard_contracts::{
    ProviderCapabilityV1 as Cap, ProviderConnectionStateV1 as State,
    ProviderEffectLevelV1 as Level, ProviderInventoryV1, ProviderSignalStateV1, ProviderSignalV1,
    ProviderSubjectKindV1, ProviderSubjectV1, ProviderVerdictV1 as V, PROVIDER_SIGNAL_V1_VERSION,
};
use rusqlite::Connection;
use zeroize::Zeroizing;

use super::*;
use crate::encrypted_secret_store::EncryptedFileSecretStore;
use crate::provider_integration_secret::{load_provider_key, store_provider_key, ProviderKey};
use crate::provider_integration_store::{
    capability_settings, ensure_provider_integration_schema, provider_connections,
    put_capability_setting, put_connection, put_signal, signals_for_subject, CapabilitySetting,
    ProviderConnection,
};

const SHIELD: &str = "provider.exampleshield";
const WATCH: &str = "provider.otherwatch";

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

fn signal(provider_id: &str) -> ProviderSignalV1 {
    ProviderSignalV1 {
        version: PROVIDER_SIGNAL_V1_VERSION,
        provider_id: provider_id.to_owned(),
        capability: Cap::OriginReputation,
        subject: ProviderSubjectV1 {
            kind: ProviderSubjectKindV1::Origin,
            digest: digest(1),
        },
        verdict: V::Danger,
        reason_codes: vec!["phishing".to_owned()],
        observed_at_ms: 600_000,
        expires_at_ms: 1_200_000,
        inventory: ProviderInventoryV1::ProviderSide,
        state: ProviderSignalStateV1::Fresh,
    }
}

/// Two connected providers, each with a key, a tightened setting and a cached signal, plus a
/// secret that is not a provider key.
fn populated_home() -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    let mut secrets = EncryptedFileSecretStore::new(home.path());
    let auth = CompiledProviderAuthV1 {
        header: "X-Api-Key".to_owned(),
        key_min_length: 24,
        key_max_length: 128,
        key_charset: ProviderKeyCharsetV1::Base64url,
    };
    let connection = Connection::open(home.path().join("guard.db")).unwrap();
    ensure_provider_integration_schema(&connection).unwrap();
    for provider in [SHIELD, WATCH] {
        let key = ProviderKey::new(Zeroizing::new("fixturekey".repeat(4)));
        store_provider_key(&mut secrets, provider, &key, &auth).unwrap();
        put_connection(&connection, &connected(provider)).unwrap();
        let setting = CapabilitySetting {
            effect_level: Level::Enforce,
            require_fresh: true,
        };
        put_capability_setting(&connection, provider, Cap::OriginReputation, setting).unwrap();
        put_signal(&connection, &signal(provider)).unwrap();
    }
    secrets.set_secret("pulse:enrollment", "unrelated").unwrap();
    home
}

#[test]
fn forgetting_the_device_deletes_every_key_connection_setting_and_signal() {
    let home = populated_home();

    let purge = purge_provider_integrations(home.path()).unwrap();

    assert_eq!(
        purge,
        ProviderPurge {
            keys_deleted: 2,
            providers_forgotten: 2,
        }
    );
    let mut secrets = EncryptedFileSecretStore::new(home.path());
    assert!(load_provider_key(&mut secrets, SHIELD).is_none());
    assert!(load_provider_key(&mut secrets, WATCH).is_none());
    assert_eq!(
        secrets.get_secret("pulse:enrollment").as_deref(),
        Some("unrelated"),
        "secrets other than provider keys stay"
    );
    let connection = Connection::open(home.path().join("guard.db")).unwrap();
    assert!(provider_connections(&connection).unwrap().is_empty());
    assert!(
        signals_for_subject(&connection, Cap::OriginReputation, &digest(1))
            .unwrap()
            .is_empty()
    );
    let settings_left: i64 = connection
        .query_row(
            "select count(*) from provider_capability_settings",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(settings_left, 0);
    // Settings read as defaults once the rows are gone, so nothing tightened survives.
    put_connection(&connection, &connected(SHIELD)).unwrap();
    assert!(capability_settings(&connection, SHIELD)
        .unwrap()
        .values()
        .all(|setting| *setting == CapabilitySetting::default()));
}

#[test]
fn a_second_purge_finds_nothing_left() {
    let home = populated_home();
    purge_provider_integrations(home.path()).unwrap();
    assert_eq!(
        purge_provider_integrations(home.path()).unwrap(),
        ProviderPurge::default()
    );
}

#[test]
fn a_home_without_a_store_or_provider_tables_is_left_as_it_is() {
    let empty = tempfile::tempdir().unwrap();
    assert_eq!(
        purge_provider_integrations(empty.path()).unwrap(),
        ProviderPurge::default()
    );
    assert!(
        !empty.path().join("guard.db").exists(),
        "the purge never creates a store"
    );

    let other = tempfile::tempdir().unwrap();
    let connection = Connection::open(other.path().join("guard.db")).unwrap();
    connection
        .execute_batch("create table unrelated (id integer primary key)")
        .unwrap();
    assert_eq!(
        purge_provider_integrations(other.path()).unwrap(),
        ProviderPurge::default()
    );
    let tables: i64 = connection
        .query_row(
            "select count(*) from sqlite_master where name like 'provider_%'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(tables, 0, "the purge never creates the provider tables");
}

#[test]
fn keys_go_even_when_the_store_cannot_be_opened() {
    let home = populated_home();
    std::fs::remove_file(home.path().join("guard.db")).unwrap();
    std::fs::write(
        home.path().join("guard.db"),
        b"not a sqlite database, padded past one header page",
    )
    .unwrap();
    assert_eq!(
        purge_provider_integrations(home.path()),
        Err(ProviderPurgeError::Store)
    );
    let mut secrets = EncryptedFileSecretStore::new(home.path());
    assert!(load_provider_key(&mut secrets, SHIELD).is_none());
    assert!(load_provider_key(&mut secrets, WATCH).is_none());
}
