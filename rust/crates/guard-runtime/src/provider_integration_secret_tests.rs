use std::fs;

use guard_command::provider_integration_compile::{CompiledProviderAuthV1, ProviderKeyCharsetV1};
use zeroize::Zeroizing;

use super::*;
use crate::encrypted_secret_store::EncryptedFileSecretStore;

const SHIELD: &str = "provider.exampleshield";
const WATCH: &str = "provider.otherwatch";
/// Synthetic: 32 base64url characters that never appear anywhere else.
const KEY: &str = "zQ7xK2mP9vL4nR8tW1yB6cD3fG5hJ0kA";

fn auth(charset: ProviderKeyCharsetV1) -> CompiledProviderAuthV1 {
    CompiledProviderAuthV1 {
        header: "X-Api-Key".to_owned(),
        key_min_length: 24,
        key_max_length: 128,
        key_charset: charset,
    }
}

fn key(text: &str) -> ProviderKey {
    ProviderKey::new(Zeroizing::new(text.to_owned()))
}

fn every_file_under(path: &std::path::Path) -> Vec<Vec<u8>> {
    let mut contents = Vec::new();
    for entry in fs::read_dir(path).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            contents.extend(every_file_under(&entry.path()));
        } else {
            contents.push(fs::read(entry.path()).unwrap());
        }
    }
    contents
}

#[test]
fn secret_id_follows_the_contract() {
    assert_eq!(
        provider_secret_id(SHIELD).as_deref(),
        Some("provider:provider.exampleshield:api-key")
    );
    for bad in [
        "exampleshield",
        "provider.",
        "provider.Shield",
        "provider.a/b",
        "provider.a:b",
    ] {
        assert_eq!(provider_secret_id(bad), None, "{bad}");
    }
}

#[test]
fn key_format_is_checked_against_the_manifest() {
    let base64url = auth(ProviderKeyCharsetV1::Base64url);
    assert_eq!(check_key_format(KEY, &base64url), Ok(()));
    assert_eq!(check_key_format(&format!("{KEY}=="), &base64url), Ok(()));
    assert_eq!(
        check_key_format(&format!("{KEY}==="), &base64url),
        Err(ProviderSecretError::KeyCharset)
    );
    assert_eq!(
        check_key_format("short", &base64url),
        Err(ProviderSecretError::KeyTooShort)
    );
    assert_eq!(
        check_key_format(&"a".repeat(129), &base64url),
        Err(ProviderSecretError::KeyTooLong)
    );
    assert_eq!(
        check_key_format("https://shop.example.test/key-page", &base64url),
        Err(ProviderSecretError::KeyCharset)
    );
    assert_eq!(
        check_key_format(&format!("{KEY}\n"), &base64url),
        Err(ProviderSecretError::KeyCharset)
    );
    let hex = auth(ProviderKeyCharsetV1::Hex);
    assert_eq!(check_key_format(&"0f".repeat(16), &hex), Ok(()));
    assert_eq!(
        check_key_format(KEY, &hex),
        Err(ProviderSecretError::KeyCharset)
    );
    let base64 = auth(ProviderKeyCharsetV1::Base64);
    assert_eq!(check_key_format("ab+/".repeat(8).as_str(), &base64), Ok(()));
    assert_eq!(
        check_key_format("ab-_".repeat(8).as_str(), &base64),
        Err(ProviderSecretError::KeyCharset)
    );
    let alphanumeric = auth(ProviderKeyCharsetV1::Alphanumeric);
    assert_eq!(
        check_key_format(&format!("{KEY}=="), &alphanumeric),
        Err(ProviderSecretError::KeyCharset)
    );
    let generous = CompiledProviderAuthV1 {
        key_max_length: u32::MAX,
        ..auth(ProviderKeyCharsetV1::Alphanumeric)
    };
    assert_eq!(
        check_key_format(&"a".repeat(PROVIDER_KEY_MAX_BYTES + 1), &generous),
        Err(ProviderSecretError::KeyTooLong)
    );
}

#[test]
fn keys_round_trip_and_disconnect_deletes_one() {
    let home = tempfile::tempdir().unwrap();
    let mut store = EncryptedFileSecretStore::new(home.path());
    let base64url = auth(ProviderKeyCharsetV1::Base64url);
    store_provider_key(&mut store, SHIELD, &key(KEY), &base64url).unwrap();
    store_provider_key(&mut store, WATCH, &key(&KEY.repeat(2)), &base64url).unwrap();
    assert_eq!(load_provider_key(&mut store, SHIELD).unwrap().expose(), KEY);
    delete_provider_key(&mut store, SHIELD);
    assert!(load_provider_key(&mut store, SHIELD).is_none());
    assert!(load_provider_key(&mut store, WATCH).is_some());
    assert!(load_provider_key(&mut store, "provider.Bad").is_none());
}

#[test]
fn a_refused_key_writes_nothing() {
    let home = tempfile::tempdir().unwrap();
    let mut store = EncryptedFileSecretStore::new(home.path());
    let base64url = auth(ProviderKeyCharsetV1::Base64url);
    assert_eq!(
        store_provider_key(&mut store, SHIELD, &key("this is a note, not a provider key"), &base64url),
        Err(ProviderSecretError::KeyCharset)
    );
    assert_eq!(
        store_provider_key(&mut store, "provider.Bad", &key(KEY), &base64url),
        Err(ProviderSecretError::ProviderIdInvalid)
    );
    assert!(load_provider_key(&mut store, SHIELD).is_none());
}

#[test]
fn the_key_never_shows_in_debug_errors_or_files() {
    let home = tempfile::tempdir().unwrap();
    let mut store = EncryptedFileSecretStore::new(home.path());
    let base64url = auth(ProviderKeyCharsetV1::Base64url);
    let held = key(KEY);
    store_provider_key(&mut store, SHIELD, &held, &base64url).unwrap();
    let loaded = load_provider_key(&mut store, SHIELD).unwrap();

    for text in [
        format!("{held:?}"),
        format!("{loaded:?}"),
        format!("{:?}", Some(&loaded)),
    ] {
        assert!(!text.contains(KEY), "{text}");
        assert!(!text.contains(&KEY[..8]), "{text}");
    }
    for refusal in [
        check_key_format(&format!("{KEY} "), &base64url).unwrap_err(),
        check_key_format(&KEY[..10], &base64url).unwrap_err(),
    ] {
        for text in [refusal.to_string(), format!("{refusal:?}")] {
            assert!(!text.contains(&KEY[..8]), "{text}");
        }
    }
    for contents in every_file_under(home.path()) {
        let needle = KEY.as_bytes();
        assert!(
            !contents
                .windows(needle.len())
                .any(|window| window == needle),
            "a file under the Guard home holds the key in the clear"
        );
    }
}

#[test]
fn forgetting_the_device_deletes_every_provider_key_and_nothing_else() {
    let home = tempfile::tempdir().unwrap();
    assert_eq!(delete_all_provider_keys(home.path()).unwrap(), 0);
    let mut store = EncryptedFileSecretStore::new(home.path());
    let base64url = auth(ProviderKeyCharsetV1::Base64url);
    store_provider_key(&mut store, SHIELD, &key(KEY), &base64url).unwrap();
    store_provider_key(&mut store, WATCH, &key(KEY), &base64url).unwrap();
    store.set_secret("pulse:enrollment", "unrelated").unwrap();
    store
        .set_secret("provider:not-a-provider:api-key", "unrelated")
        .unwrap();

    assert_eq!(delete_all_provider_keys(home.path()).unwrap(), 2);
    assert!(load_provider_key(&mut store, SHIELD).is_none());
    assert!(load_provider_key(&mut store, WATCH).is_none());
    assert_eq!(
        store.get_secret("pulse:enrollment").as_deref(),
        Some("unrelated")
    );
    assert_eq!(
        store
            .get_secret("provider:not-a-provider:api-key")
            .as_deref(),
        Some("unrelated")
    );
    assert!(home.path().join("secrets/key.bin").exists());
}
