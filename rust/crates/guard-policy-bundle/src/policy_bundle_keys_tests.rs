use super::*;

fn key(id: &str, state: &str) -> Key {
    Key {
        key_id: id.to_owned(),
        public_key_pem: "pem".to_owned(),
        fingerprint: "fp".to_owned(),
        state: state.to_owned(),
        purpose: KEY_PURPOSE.to_owned(),
        workspace_id: Some("ws".to_owned()),
        valid_from: None,
        valid_until: None,
    }
}

#[test]
fn authority_requires_anchor_and_active_state() {
    let active = key("k", "active");
    let grace = key("k", "grace");
    assert_eq!(
        resolve_authorized("k", &[active.clone()], &[], Some("ws"), 0.0).unwrap_err(),
        "trusted_key_unavailable"
    );
    assert!(resolve_authorized("k", &[active.clone()], &[active.clone()], Some("ws"), 0.0).is_ok());
    assert_eq!(
        resolve_authorized("k", &[grace.clone()], &[grace], Some("ws"), 0.0).unwrap_err(),
        "signing_key_not_current"
    );
    assert_eq!(
        resolve_authorized("k", &[active.clone()], &[active], Some("other"), 0.0).unwrap_err(),
        "signing_key_workspace_mismatch"
    );
}

#[test]
fn merge_is_sorted_and_last_wins() {
    let merged = merge_keys(&[
        &[key("b", "active")],
        &[key("a", "active"), key("b", "grace")],
    ]);
    assert_eq!(merged.len(), 2);
    assert_eq!(merged[0].key_id, "a");
    assert_eq!(merged[1].state, "grace");
}

#[test]
fn wrapper_must_match_exactly() {
    let raw = serde_json::json!({"contractVersion": KEYRING_CONTRACT_VERSION, "purpose": KEY_PURPOSE, "workspaceId": "w", "keys": [], "extra": 1});
    assert_eq!(
        load_keys(&raw, true).unwrap_err(),
        "invalid_policy_bundle_verification_keyring:fields"
    );
    assert!(load_keys(&serde_json::json!({"keys": []}), false)
        .unwrap()
        .is_empty());
}
