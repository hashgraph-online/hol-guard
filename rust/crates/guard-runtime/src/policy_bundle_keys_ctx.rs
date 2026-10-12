//! Trust-root assembly for policy bundles: legacy anchor migration, the
//! verification context (trusted vs. pinned anchors), and the keyring that is
//! persisted after a bundle is accepted.

use serde_json::Value;

use crate::policy_bundle_keys::{
    load_keys, merge_keys, resolve_key, safe_load_keys, Key, KEY_PURPOSE,
};
use crate::policy_bundle_py::py_strip;
use crate::policy_bundle_time::replaced_timestamp;

pub(crate) const V2_CONTRACT: &str = "guard-policy-bundle.v2";

pub(crate) struct Context {
    pub trusted: Vec<Key>,
    pub anchored: Vec<Key>,
    pub managed_configured: bool,
}

fn restrictive_state(left: &str, right: &str) -> &'static str {
    if left == "revoked" || right == "revoked" {
        "revoked"
    } else if left == "grace" || right == "grace" {
        "grace"
    } else {
        "active"
    }
}

fn latest(candidates: &[&String], later_wins: bool) -> Option<String> {
    let mut best: Option<(&String, f64)> = None;
    for candidate in candidates {
        let stamp = replaced_timestamp(candidate).unwrap_or(0.0);
        let replace = match best {
            None => true,
            Some((_, current)) => {
                if later_wins {
                    stamp > current
                } else {
                    stamp < current
                }
            }
        };
        if replace {
            best = Some((candidate, stamp));
        }
    }
    best.map(|(value, _)| value.clone())
}

/// `migrate_legacy_policy_bundle_anchors`.
pub(crate) fn migrate_legacy(
    stored_keyring: &Value,
    sync_keys: &[Key],
    expected_workspace: Option<&str>,
) -> Vec<Key> {
    let Value::Object(stored) = stored_keyring else {
        return Vec::new();
    };
    if stored.len() != 2 || !stored.contains_key("keys") || !stored.contains_key("workspace_id") {
        return Vec::new();
    }
    let Some(expected) = expected_workspace.filter(|value| !value.is_empty()) else {
        return Vec::new();
    };
    if stored.get("workspace_id").and_then(Value::as_str) != Some(expected) {
        return Vec::new();
    }
    if !matches!(stored.get("keys"), Some(Value::Array(_))) {
        return Vec::new();
    }
    let legacy_keys = safe_load_keys(stored_keyring);
    if legacy_keys.is_empty()
        || legacy_keys
            .iter()
            .any(|key| key.purpose != "unscoped" || key.workspace_id.is_some())
    {
        return Vec::new();
    }
    let mut migrated = Vec::new();
    for legacy in &legacy_keys {
        let advertised = sync_keys.iter().find(|key| {
            key.key_id == legacy.key_id
                && key.fingerprint == legacy.fingerprint
                && key.purpose == KEY_PURPOSE
                && key.workspace_id.as_deref() == Some(expected)
        });
        let Some(advertised) = advertised else {
            continue;
        };
        let froms: Vec<&String> = [&legacy.valid_from, &advertised.valid_from]
            .into_iter()
            .flatten()
            .collect();
        let untils: Vec<&String> = [&legacy.valid_until, &advertised.valid_until]
            .into_iter()
            .flatten()
            .collect();
        migrated.push(Key {
            key_id: legacy.key_id.clone(),
            public_key_pem: legacy.public_key_pem.clone(),
            fingerprint: legacy.fingerprint.clone(),
            state: restrictive_state(&legacy.state, &advertised.state).to_owned(),
            purpose: KEY_PURPOSE.to_owned(),
            workspace_id: Some(expected.to_owned()),
            valid_from: latest(&froms, true),
            valid_until: latest(&untils, false),
        });
    }
    migrated
}

/// `_policy_bundle_verification_context_with_source` over already-loaded inputs.
pub(crate) fn verification_context(
    stored_keyring: &Value,
    sync_keys: &[Key],
    managed_configured: bool,
    managed_keys: &[Key],
    provenance_present: bool,
    expected_workspace: Option<&str>,
) -> Context {
    if managed_configured {
        return Context {
            trusted: merge_keys(&[managed_keys, sync_keys]),
            anchored: managed_keys.to_vec(),
            managed_configured: true,
        };
    }
    if provenance_present {
        return Context {
            trusted: merge_keys(&[sync_keys]),
            anchored: Vec::new(),
            managed_configured: false,
        };
    }
    let stored = safe_load_keys(stored_keyring);
    let migrated = migrate_legacy(stored_keyring, sync_keys, expected_workspace);
    Context {
        trusted: merge_keys(&[&stored, &migrated, sync_keys]),
        anchored: merge_keys(&[&stored, &migrated]),
        managed_configured: false,
    }
}

/// Keys advertised by a sync payload (`safe_load` of the optional field).
pub(crate) fn sync_keys(raw: &Value) -> Vec<Key> {
    if raw.is_null() {
        return Vec::new();
    }
    load_keys(raw, false).unwrap_or_default()
}

/// `persistable_policy_bundle_keyring`.
pub(crate) fn persistable(anchored: &[Key], bundle: &Value) -> Vec<Key> {
    let workspace = match bundle.get("workspaceId") {
        Some(Value::String(id)) if !py_strip(id).is_empty() => id.as_str(),
        _ => return Vec::new(),
    };
    let v2 = bundle.get("contractVersion").and_then(Value::as_str) == Some(V2_CONTRACT);
    let anchors: Vec<Key> = anchored
        .iter()
        .filter(|key| {
            key.purpose == KEY_PURPOSE
                && match key.workspace_id.as_deref() {
                    None => v2,
                    Some(id) => id == workspace,
                }
        })
        .cloned()
        .collect();
    let Some(Value::Object(verifier)) = bundle.get("verifier") else {
        return anchors;
    };
    if verifier.get("algorithm").and_then(Value::as_str) != Some("rsa-pss-sha256") {
        return anchors;
    }
    let key_id = match verifier.get("keyId") {
        Some(Value::String(id)) if !py_strip(id).is_empty() => py_strip(id),
        _ => return anchors,
    };
    match resolve_key(key_id, &anchors) {
        Some(signing) => merge_keys(&[&anchors, std::slice::from_ref(signing)]),
        None => anchors,
    }
}
