//! Policy bundle verification keys: wire parsing and validation, validity
//! windows, and authority resolution against pinned anchors.

use serde_json::{json, Value};

use crate::policy_bundle_crypto::{parse_public_key, KeyError};
use crate::policy_bundle_py::{py_strip, Obj};
use crate::policy_bundle_time::replaced_timestamp;
use sha2::{Digest, Sha256};

pub(crate) const KEY_PURPOSE: &str = "policy_bundle";
pub(crate) const KEYRING_CONTRACT_VERSION: &str = "guard-policy-keyring.v1";
const STATES: [&str; 3] = ["active", "grace", "revoked"];
const KEYRING_FIELDS: [&str; 4] = ["contractVersion", "purpose", "workspaceId", "keys"];
const KEY_FIELDS: [&str; 8] = [
    "fingerprintSha256",
    "keyId",
    "publicKeyPem",
    "state",
    "purpose",
    "workspaceId",
    "validFrom",
    "validUntil",
];
const REQUIRED_KEY_FIELDS: [&str; 6] = [
    "fingerprintSha256",
    "keyId",
    "publicKeyPem",
    "state",
    "purpose",
    "workspaceId",
];
const MINIMUM_RSA_BITS: usize = 2048;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Key {
    pub key_id: String,
    pub public_key_pem: String,
    pub fingerprint: String,
    pub state: String,
    pub purpose: String,
    pub workspace_id: Option<String>,
    pub valid_from: Option<String>,
    pub valid_until: Option<String>,
}

fn optional(value: &Option<String>) -> Value {
    value.as_ref().map_or(Value::Null, |text| json!(text))
}

impl Key {
    /// `PolicyBundleVerificationKey.to_dict()`.
    pub(crate) fn to_value(&self) -> Value {
        json!({
            "fingerprintSha256": self.fingerprint,
            "keyId": self.key_id,
            "purpose": self.purpose,
            "publicKeyPem": self.public_key_pem,
            "state": self.state,
            "validFrom": optional(&self.valid_from),
            "validUntil": optional(&self.valid_until),
            "workspaceId": optional(&self.workspace_id),
        })
    }

    /// Inverse of `to_value` for keys the Python shim already normalized.
    pub(crate) fn from_wire(value: &Value) -> Option<Key> {
        let item = value.as_object()?;
        let text = |name: &str| item.get(name).and_then(Value::as_str).map(str::to_owned);
        Some(Key {
            key_id: text("keyId")?,
            public_key_pem: text("publicKeyPem")?,
            fingerprint: text("fingerprintSha256")?,
            state: text("state")?,
            purpose: text("purpose")?,
            workspace_id: text("workspaceId"),
            valid_from: text("validFrom"),
            valid_until: text("validUntil"),
        })
    }
}

pub(crate) fn keys_from_wire(value: Option<&Value>) -> Vec<Key> {
    match value {
        Some(Value::Array(items)) => items.iter().filter_map(Key::from_wire).collect(),
        _ => Vec::new(),
    }
}

pub(crate) fn keys_to_value(keys: &[Key]) -> Value {
    Value::Array(keys.iter().map(Key::to_value).collect())
}

pub(crate) fn key_fingerprint(pem: &str) -> String {
    let normalized = py_strip(&pem.replace("\r\n", "\n")).to_owned();
    hex::encode(Sha256::digest(normalized.as_bytes()))
}

fn present_text(item: &Obj, name: &str) -> Option<String> {
    match item.get(name) {
        Some(Value::String(text)) if !py_strip(text).is_empty() => Some(text.clone()),
        _ => None,
    }
}

fn fail(field: &str) -> String {
    format!("invalid_policy_bundle_verification_key:{field}")
}

fn optional_window(item: &Obj, name: &str) -> Result<Option<String>, String> {
    match item.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) if !py_strip(text).is_empty() => Ok(Some(text.clone())),
        Some(_) => Err(fail(name)),
    }
}

fn checked_window(value: &Option<String>, name: &str) -> Result<(), String> {
    match value {
        Some(text) if replaced_timestamp(text).is_none() => Err(fail(name)),
        _ => Ok(()),
    }
}

/// `PolicyBundleVerificationKey.from_dict`.
pub(crate) fn key_from_dict(item: &Obj) -> Result<Key, String> {
    let key_id = present_text(item, "keyId").ok_or_else(|| fail("keyId"))?;
    let pem = present_text(item, "publicKeyPem").ok_or_else(|| fail("publicKeyPem"))?;
    let fingerprint =
        present_text(item, "fingerprintSha256").ok_or_else(|| fail("fingerprintSha256"))?;
    let state = match item.get("state") {
        Some(Value::String(state)) if STATES.contains(&state.as_str()) => state.clone(),
        _ => return Err(fail("state")),
    };
    let purpose = present_text(item, "purpose")
        .map(|text| py_strip(&text).to_owned())
        .unwrap_or_else(|| "unscoped".to_owned());
    let workspace = if item.contains_key("workspaceId") {
        item.get("workspaceId")
    } else {
        item.get("workspace_id")
    };
    let workspace_id = match workspace {
        Some(Value::String(text)) if !py_strip(text).is_empty() => Some(py_strip(text).to_owned()),
        _ => None,
    };
    let valid_from = optional_window(item, "validFrom")?;
    let valid_until = optional_window(item, "validUntil")?;
    checked_window(&valid_from, "validFrom")?;
    checked_window(&valid_until, "validUntil")?;
    if let (Some(from), Some(until)) = (&valid_from, &valid_until) {
        if replaced_timestamp(from) > replaced_timestamp(until) {
            return Err(fail("validity_window"));
        }
    }
    let normalized_pem = py_strip(&pem.replace("\r\n", "\n")).to_owned();
    let parsed = parse_public_key(&normalized_pem).map_err(|error| match error {
        KeyError::Pem => fail("publicKeyPem"),
        KeyError::Type => fail("publicKeyType"),
    })?;
    if parsed.bit_length() < MINIMUM_RSA_BITS {
        return Err(fail("keySize"));
    }
    let computed = key_fingerprint(&normalized_pem);
    if py_strip(&fingerprint) != computed {
        return Err(fail("fingerprint_mismatch"));
    }
    Ok(Key {
        key_id: py_strip(&key_id).to_owned(),
        public_key_pem: normalized_pem,
        fingerprint: computed,
        state,
        purpose,
        workspace_id,
        valid_from,
        valid_until,
    })
}

fn keyring_error(field: &str) -> String {
    format!("invalid_policy_bundle_verification_keyring:{field}")
}

/// `load_policy_bundle_verification_keys`.
pub(crate) fn load_keys(raw: &Value, require_contract: bool) -> Result<Vec<Key>, String> {
    let mut raw_keys = Some(raw);
    let mut wrapper_purpose = None;
    let mut wrapper_workspace: Option<&str> = None;
    if require_contract && !raw.is_object() {
        return Err(keyring_error("wrapper"));
    }
    if let Value::Object(wrapper) = raw {
        let present = ["contractVersion", "purpose", "workspaceId"]
            .iter()
            .any(|field| wrapper.contains_key(*field));
        let validate = require_contract || present;
        if validate {
            if wrapper.get("contractVersion").and_then(Value::as_str)
                != Some(KEYRING_CONTRACT_VERSION)
            {
                return Err(keyring_error("contractVersion"));
            }
            if wrapper.get("purpose").and_then(Value::as_str) != Some(KEY_PURPOSE) {
                return Err(keyring_error("purpose"));
            }
            wrapper_purpose = Some(KEY_PURPOSE);
            match wrapper.get("workspaceId") {
                Some(Value::String(id)) if !py_strip(id).is_empty() && py_strip(id) == id => {
                    wrapper_workspace = Some(id);
                }
                _ => return Err(keyring_error("workspaceId")),
            }
        }
        raw_keys = wrapper.get("keys");
        if validate && !matches!(raw_keys, Some(Value::Array(_))) {
            return Err(keyring_error("keys"));
        }
        if validate
            && (wrapper.len() != KEYRING_FIELDS.len()
                || !KEYRING_FIELDS
                    .iter()
                    .all(|field| wrapper.contains_key(*field)))
        {
            return Err(keyring_error("fields"));
        }
    }
    let Some(Value::Array(items)) = raw_keys else {
        return Ok(Vec::new());
    };
    let mut parsed: Vec<Key> = Vec::new();
    for entry in items {
        let Value::Object(item) = entry else {
            return Err("invalid_policy_bundle_verification_keys".to_owned());
        };
        if require_contract {
            if !item.keys().all(|name| KEY_FIELDS.contains(&name.as_str())) {
                return Err(keyring_error("key_fields"));
            }
            if !REQUIRED_KEY_FIELDS
                .iter()
                .all(|name| item.contains_key(*name))
            {
                return Err(keyring_error("key_fields"));
            }
        }
        let key = key_from_dict(item)?;
        if let Some(purpose) = wrapper_purpose {
            if item.get("purpose").and_then(Value::as_str) != Some(purpose)
                || key.purpose != purpose
            {
                return Err(keyring_error("key_purpose_mismatch"));
            }
        }
        if let Some(workspace) = wrapper_workspace {
            if item.get("workspaceId").and_then(Value::as_str) != Some(workspace)
                || key.workspace_id.as_deref() != Some(workspace)
            {
                return Err(keyring_error("key_workspace_mismatch"));
            }
        }
        if parsed.iter().any(|existing| existing.key_id == key.key_id) {
            return Err("invalid_policy_bundle_verification_keys:duplicate_key_id".to_owned());
        }
        parsed.push(key);
    }
    Ok(parsed)
}

pub(crate) fn safe_load_keys(raw: &Value) -> Vec<Key> {
    load_keys(raw, false).unwrap_or_default()
}

pub(crate) fn resolve_key<'a>(key_id: &str, keys: &'a [Key]) -> Option<&'a Key> {
    keys.iter().find(|key| key.key_id == key_id)
}

pub(crate) fn key_is_trusted(key: &Key, anchored: &[Key]) -> bool {
    anchored.iter().any(|item| {
        item.key_id == key.key_id
            && item.fingerprint == key.fingerprint
            && item.purpose == key.purpose
            && item.workspace_id == key.workspace_id
    })
}

/// `signing_key_is_current`; an unparsable or overflowing window is not current.
pub(crate) fn key_is_current(key: &Key, now: f64, require_active: bool) -> bool {
    if key.state == "revoked" || (require_active && key.state != "active") {
        return false;
    }
    if let Some(from) = &key.valid_from {
        match replaced_timestamp(from) {
            Some(valid_from) if now >= valid_from => {}
            _ => return false,
        }
    }
    match &key.valid_until {
        None => true,
        Some(until) => replaced_timestamp(until).is_some_and(|expiry| now <= expiry),
    }
}

/// `resolve_authorized_policy_bundle_signing_key`.
pub(crate) fn resolve_authorized<'a>(
    key_id: &str,
    trusted: &'a [Key],
    anchored: &'a [Key],
    expected_workspace: Option<&str>,
    now: f64,
) -> Result<&'a Key, &'static str> {
    if anchored.is_empty() {
        return Err("trusted_key_unavailable");
    }
    let (Some(advertised), Some(anchor)) =
        (resolve_key(key_id, trusted), resolve_key(key_id, anchored))
    else {
        return Err("untrusted_signing_key");
    };
    if advertised.fingerprint != anchor.fingerprint {
        return Err("untrusted_signing_key");
    }
    if anchor.purpose != KEY_PURPOSE {
        return Err("signing_key_purpose_mismatch");
    }
    let Some(expected) = expected_workspace else {
        return Err("wrong_workspace");
    };
    if anchor.workspace_id.as_deref() != Some(expected) {
        return Err("signing_key_workspace_mismatch");
    }
    if anchor.state == "revoked" {
        return Err("signing_key_revoked");
    }
    if !key_is_current(anchor, now, true) {
        return Err("signing_key_not_current");
    }
    Ok(anchor)
}

/// `merge_policy_bundle_trusted_keys`: later sources win, sorted by key id.
pub(crate) fn merge_keys(sources: &[&[Key]]) -> Vec<Key> {
    let mut merged: std::collections::BTreeMap<String, Key> = std::collections::BTreeMap::new();
    for source in sources {
        for key in *source {
            merged.insert(key.key_id.clone(), key.clone());
        }
    }
    merged.into_values().collect()
}

#[cfg(test)]
#[path = "policy_bundle_keys_tests.rs"]
mod tests;
