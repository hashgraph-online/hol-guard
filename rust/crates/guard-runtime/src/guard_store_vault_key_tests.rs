use std::path::Path;

use base64ct::{Base64UrlUnpadded, Encoding};
use guard_contracts::GuardStoreRequestV1;
use serde_json::{json, Map, Value};

use super::resolve;
use crate::encrypted_secret_store::EncryptedFileSecretStore;
use crate::grok_executable_paths::strip_verbatim;
use crate::policy_integrity_resolver::{
    build_scoped_secret_ref, policy_integrity_secret_material, POLICY_INTEGRITY_KEY_REF,
};

/// Stores `[9; 32]` in `home`'s vault and returns the key id derived from it.
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

fn request(home: &Path, args: Value) -> GuardStoreRequestV1 {
    let args: Map<String, Value> = serde_json::from_value(args).expect("args");
    GuardStoreRequestV1 {
        schema: "guard-store-request.v1".to_owned(),
        request_id: "r-1".to_owned(),
        store_path: home.join("guard.db").to_string_lossy().into_owned(),
        guard_home: home.to_string_lossy().into_owned(),
        method: "apply_signed_remote_exact_result".to_owned(),
        source: "local".to_owned(),
        busy_timeout_ms: 1000,
        args,
    }
}

#[test]
fn a_call_without_the_flag_is_left_alone() {
    let home = tempfile::tempdir().unwrap();
    let call = request(
        home.path(),
        json!({"integrity_key_b64": "a2tr", "integrity_key_id": "k"}),
    );
    assert!(matches!(resolve(&call, Some(home.path())), Ok(None)));
}

#[test]
fn the_resident_fills_in_its_own_vault_key() {
    let home = tempfile::tempdir().unwrap();
    let key_id = store_key(home.path());
    let call = request(home.path(), json!({"vault_key": true, "request_id": "q"}));
    let resolved = resolve(&call, Some(home.path()))
        .unwrap()
        .expect("resolved");
    assert_eq!(
        Value::Object(resolved.args),
        json!({
            "request_id": "q",
            "integrity_key_b64": Base64UrlUnpadded::encode_string(&[9_u8; 32]),
            "integrity_key_id": key_id,
        })
    );
}

#[test]
fn another_home_or_no_resident_home_sees_no_key() {
    let home = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    store_key(home.path());
    let call = request(home.path(), json!({"vault_key": true}));
    for resident in [Some(other.path()), None] {
        let resolved = resolve(&call, resident).unwrap().expect("resolved");
        assert!(resolved.args.is_empty());
    }
}

#[test]
fn an_empty_vault_sees_no_key() {
    let home = tempfile::tempdir().unwrap();
    let call = request(home.path(), json!({"vault_key": true}));
    let resolved = resolve(&call, Some(home.path()))
        .unwrap()
        .expect("resolved");
    assert!(resolved.args.is_empty());
}

#[test]
fn a_flag_beside_a_key_or_not_true_is_refused() {
    let home = tempfile::tempdir().unwrap();
    store_key(home.path());
    for args in [
        json!({"vault_key": true, "integrity_key_b64": "a2tr"}),
        json!({"vault_key": true, "integrity_key_id": "k"}),
        json!({"vault_key": false}),
        json!({"vault_key": "yes"}),
    ] {
        let call = request(home.path(), args);
        assert!(resolve(&call, Some(home.path())).is_err());
    }
}
