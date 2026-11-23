use std::path::Path;

use base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::{json, Value};

use super::super::answer;
use super::Caller;
use crate::encrypted_secret_store::EncryptedFileSecretStore;
use crate::grok_executable_paths::strip_verbatim;
use crate::policy_integrity_resolver::{
    build_scoped_secret_ref, policy_integrity_secret_material, POLICY_INTEGRITY_KEY_REF,
};

/// Stores `[9; 32]` in `home`'s vault, as Python's encrypted-file store
/// writes it, and returns the key id derived from it.
fn store_key(home: &Path) -> String {
    let home = strip_verbatim(home.canonicalize().expect("home"));
    let key_ref = build_scoped_secret_ref(POLICY_INTEGRITY_KEY_REF, &home);
    let mut secrets = EncryptedFileSecretStore::new(&home);
    secrets
        .set_secret(&key_ref, &Base64UrlUnpadded::encode_string(&[9_u8; 32]))
        .expect("store key");
    policy_integrity_secret_material(&mut secrets, &home)
        .expect("material")
        .key_id
}

fn home_text(home: &Path) -> String {
    home.to_str().expect("utf-8 home").to_owned()
}

fn sign(vault_home: &str, caller: Caller<'_>) -> Value {
    let request =
        json!({"op": "sign", "vault_home": vault_home, "payload": {"issuer": "local-cli"}});
    answer(request, caller).expect("answer")
}

#[test]
fn the_helper_signs_with_the_named_home_vault_key() {
    let home = tempfile::tempdir().unwrap();
    let key_id = store_key(home.path());
    let envelope = sign(&home_text(home.path()), Caller::Helper)["envelope"].clone();
    assert_eq!(envelope["keyId"], json!(key_id));
    let sent_key = Base64UrlUnpadded::encode_string(&[9_u8; 32]);
    let verified = answer(
        json!({"op": "verify", "key": sent_key, "key_id": key_id, "envelope": envelope}),
        Caller::Helper,
    )
    .expect("answer");
    assert_eq!(verified["unsigned"]["issuer"], json!("local-cli"));
}

#[test]
fn the_resident_reads_its_own_vault_and_no_other() {
    let own = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    let key_id = store_key(own.path());
    store_key(other.path());
    let signed = sign(&home_text(own.path()), Caller::Resident(Some(own.path())));
    assert_eq!(signed["envelope"]["keyId"], json!(key_id));
    for caller in [Caller::Resident(Some(other.path())), Caller::Resident(None)] {
        let refused = sign(&home_text(own.path()), caller);
        assert_eq!(
            refused,
            json!({"error": "cloud_review_signing_key_unavailable"})
        );
    }
}

#[test]
fn a_vault_with_no_key_is_no_key() {
    let home = tempfile::tempdir().unwrap();
    let refused = sign(&home_text(home.path()), Caller::Helper);
    assert_eq!(
        refused,
        json!({"error": "cloud_review_signing_key_unavailable"})
    );
}

#[test]
fn a_vault_request_that_also_sends_a_key_or_a_relative_home_is_malformed() {
    let home = tempfile::tempdir().unwrap();
    store_key(home.path());
    let vault_home = home_text(home.path());
    for request in [
        json!({"op": "sign", "vault_home": vault_home, "key": "a2tr", "payload": {}}),
        json!({"op": "verify", "vault_home": vault_home, "key_id": "key-1", "envelope": {}}),
        json!({"op": "sign", "vault_home": "relative/home", "payload": {}}),
    ] {
        assert_eq!(
            answer(request, Caller::Helper),
            Err("exact_cloud_review_request_invalid".to_owned())
        );
    }
}
