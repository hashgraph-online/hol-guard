use super::tests::{call, home, identity, items, register};
use super::*;
use std::path::Path;

use crate::encrypted_secret_store::EncryptedFileSecretStore;
use crate::grok_executable_paths::strip_verbatim;
use crate::policy_integrity_resolver::{
    build_scoped_secret_ref, policy_integrity_secret_material, POLICY_INTEGRITY_KEY_REF,
};
use base64ct::{Base64UrlUnpadded, Encoding};

const NOW: &str = "2026-09-27T12:00:00+00:00";

/// Stores a key in `home`'s vault, as Python's encrypted-file store writes
/// it, and returns the key id the ledger derives from it.
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

#[test]
fn a_vault_key_job_is_signed_and_consumed_with_the_home_key() {
    let home = home();
    let key_id = store_key(home.path());
    register(home.path(), "job-1");
    let approve = json!({"job_id": "job-1", "issuer": "local-cli", "vault_key": true});
    assert_eq!(
        call(home.path(), "approve", NOW, approve).unwrap()["approved"],
        json!(true)
    );
    assert_eq!(
        items(home.path(), LOCAL_APPROVALS_KEY)[0]["keyId"],
        json!(key_id)
    );
    let consume = json!({"identity": identity("job-1"), "vault_key": true});
    assert_eq!(call(home.path(), "consume", NOW, consume), Ok(json!(true)));
}

#[test]
fn a_vault_key_request_that_also_names_a_key_is_refused() {
    let home = home();
    store_key(home.path());
    register(home.path(), "job-1");
    for extra in [
        json!({"integrity_key_b64": Base64UrlUnpadded::encode_string(b"other")}),
        json!({"integrity_key_id": "key-1"}),
    ] {
        let mut fields = json!({"job_id": "job-1", "issuer": "local-cli", "vault_key": true});
        for (name, value) in extra.as_object().unwrap() {
            fields[name] = value.clone();
        }
        assert_eq!(
            call(home.path(), "approve", NOW, fields),
            Err(INVALID.to_owned())
        );
    }
    assert!(items(home.path(), LOCAL_APPROVALS_KEY).is_empty());
}

#[test]
fn a_vault_key_request_without_a_stored_key_writes_no_grant() {
    let home = home();
    register(home.path(), "job-1");
    let approve = json!({"job_id": "job-1", "issuer": "local-cli", "vault_key": true});
    assert!(call(home.path(), "approve", NOW, approve).is_err());
    assert!(items(home.path(), LOCAL_APPROVALS_KEY).is_empty());
}

#[test]
fn a_grant_signed_with_the_vault_key_is_not_spent_with_another_key() {
    let home = home();
    store_key(home.path());
    register(home.path(), "job-1");
    let approve = json!({"job_id": "job-1", "issuer": "local-cli", "vault_key": true});
    call(home.path(), "approve", NOW, approve).unwrap();
    let consume = json!({
        "identity": identity("job-1"),
        "integrity_key_b64": Base64UrlUnpadded::encode_string(b"other-key"),
        "integrity_key_id": "key-1",
    });
    assert_eq!(call(home.path(), "consume", NOW, consume), Ok(json!(false)));
    assert_eq!(items(home.path(), LOCAL_APPROVALS_KEY).len(), 1);
}
