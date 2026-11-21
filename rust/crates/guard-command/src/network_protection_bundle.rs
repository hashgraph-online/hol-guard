//! Rust port of `network_protection_bundle.py` — verifying the signed network
//! protection bundle Guard Cloud issues per workspace.
//!
//! The bundle carries the workspace's URL allow and block rules together with
//! the known-bad hosts and URLs collected from threat intelligence feeds. The
//! native runtime enforces only the saved copy, so verification is what keeps
//! an unsigned, stale, rolled-back or foreign-workspace bundle out of
//! enforcement. It shares the supply-chain bundle's keyring and RSA-PSS
//! signing key, so the key types, the PEM reader and the signature seam come
//! from [`crate::supply_chain_bundle`].

use std::collections::HashSet;
use std::fmt;

use base64ct::{Base64, Encoding};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::inventory_fingerprints::python_compact_json;
use crate::supply_chain_bundle::{
    computed_key_fingerprint, load_rsa_public_key_der, load_supply_chain_verification_keys,
    now_seconds, parse_iso_timestamp, RsaPssVerify, SupplyChainVerificationKey,
};

/// `NETWORK_PROTECTION_CONTRACT_VERSION` (:28).
pub const NETWORK_PROTECTION_CONTRACT_VERSION: &str = "guard-network-protection-bundle.v1";
/// `PINNED_NETWORK_BUNDLE_KEY_FINGERPRINTS` (:32) — the production signing
/// key, trusted while no supply-chain keyring has been saved yet. A saved
/// keyring takes over once it exists, so rotation follows the keyring.
pub const PINNED_NETWORK_BUNDLE_KEY_FINGERPRINTS: &[&str] =
    &["4c8f2d81f564e4a5b108896b87599001bdaf30be8ae961769fe958590b3ebb52"];

const CLOCK_SKEW_SECONDS: f64 = 300.0;
const MAX_AGE_SECONDS: f64 = 7.0 * 24.0 * 60.0 * 60.0;
const RULE_ACTIONS: &[&str] = &["allow", "block"];
const RULE_MATCH_KINDS: &[&str] = &["domain", "url_prefix"];

/// `NetworkProtectionBundleError` (:40) — one class, as in Python, because
/// every caller treats any failure the same way: the bundle is not saved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkProtectionBundleError(pub String);

impl fmt::Display for NetworkProtectionBundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for NetworkProtectionBundleError {}

type BundleResult<T> = Result<T, NetworkProtectionBundleError>;

fn refuse(message: impl Into<String>) -> NetworkProtectionBundleError {
    NetworkProtectionBundleError(message.into())
}

/// `_require_string` (:44) — a present, non-empty string, untrimmed.
fn require_string(data: &Map<String, Value>, key: &str) -> BundleResult<String> {
    match data.get(key) {
        Some(Value::String(value)) if !value.is_empty() => Ok(value.clone()),
        _ => Err(refuse(format!(
            "Network protection bundle is missing {key}"
        ))),
    }
}

/// `_string_lists` (:51) — an object whose every value is a list of strings.
fn require_string_lists(bundle: &Map<String, Value>, key: &str) -> BundleResult<()> {
    let Some(Value::Object(groups)) = bundle.get(key) else {
        return Err(refuse(format!(
            "Network protection bundle {key} must be an object"
        )));
    };
    for group in groups.values() {
        let Value::Array(items) = group else {
            return Err(refuse(format!(
                "Network protection bundle {key} must map to string lists"
            )));
        };
        if !items.iter().all(|item| item.is_string()) {
            return Err(refuse(format!(
                "Network protection bundle {key} must map to string lists"
            )));
        }
    }
    Ok(())
}

/// `_validate_rules` (:60).
fn validate_rules(bundle: &Map<String, Value>) -> BundleResult<()> {
    let Some(Value::Array(rules)) = bundle.get("workspaceRules") else {
        return Err(refuse(
            "Network protection bundle workspaceRules must be a list",
        ));
    };
    for rule in rules {
        let valid = match rule {
            Value::Object(rule) => {
                let action = rule.get("action").and_then(Value::as_str);
                let match_kind = rule.get("matchKind").and_then(Value::as_str);
                let pattern = rule.get("pattern").and_then(Value::as_str);
                action.is_some_and(|value| RULE_ACTIONS.contains(&value))
                    && match_kind.is_some_and(|value| RULE_MATCH_KINDS.contains(&value))
                    && pattern.is_some_and(|value| !value.is_empty())
            }
            _ => false,
        };
        if !valid {
            return Err(refuse(
                "Network protection bundle has an invalid workspace rule",
            ));
        }
    }
    Ok(())
}

/// `canonical_network_protection_payload` (:75) — the bytes the cloud hashes
/// and signs. Unlike the supply-chain bundle this one is `ensure_ascii=True`,
/// so non-ASCII text is escaped before it is hashed.
pub fn canonical_network_protection_payload(bundle: &Map<String, Value>) -> Vec<u8> {
    python_compact_json(&Value::Object(bundle.clone())).into_bytes()
}

/// `network_bundle_version_timestamp` (:81) — `^network-(\d+)-[0-9a-f]{16}$`.
pub fn network_bundle_version_timestamp(bundle_version: &str) -> BundleResult<i64> {
    let malformed = || refuse("Network protection bundleVersion is malformed");
    let rest = bundle_version
        .strip_prefix("network-")
        .ok_or_else(malformed)?;
    let (digits, suffix) = rest.split_once('-').ok_or_else(malformed)?;
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(malformed());
    }
    if suffix.len() != 16
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(malformed());
    }
    digits.parse::<i64>().map_err(|_| malformed())
}

/// `_timestamp` (:88).
fn timestamp(bundle: &Map<String, Value>, key: &str) -> BundleResult<f64> {
    let value = require_string(bundle, key)?;
    parse_iso_timestamp(&value, key).map_err(|error| refuse(error.to_string()))
}

/// `_trusted_fingerprints` (:100) — a saved keyring anchors the signing key
/// once it exists, and only its unrevoked entries do; before then the pinned
/// production fingerprint is the only anchor.
fn trusted_fingerprints(trusted_keys: &[SupplyChainVerificationKey]) -> HashSet<String> {
    if trusted_keys.is_empty() {
        return PINNED_NETWORK_BUNDLE_KEY_FINGERPRINTS
            .iter()
            .map(|value| (*value).to_string())
            .collect();
    }
    trusted_keys
        .iter()
        .filter(|item| item.state != "revoked")
        .map(|item| item.fingerprint_sha256.clone())
        .collect()
}

/// `_verify_signature` (:107).
fn verify_signature(
    key: &SupplyChainVerificationKey,
    signature: &str,
    payload: &[u8],
    verifier: &dyn RsaPssVerify,
) -> BundleResult<()> {
    let public_key_der =
        load_rsa_public_key_der(&key.public_key_pem).map_err(|error| refuse(error.to_string()))?;
    // `base64.b64decode(signature, validate=True)` — no non-alphabet bytes.
    let signature_bytes =
        Base64::decode_vec(signature).map_err(|_| refuse("Signature is not valid base64"))?;
    verifier
        .verify(&public_key_der, payload, &signature_bytes)
        .map_err(|_| refuse("Network protection bundle signature verification failed"))
}

/// `verify_network_protection_response` (:129) — verify a bundle response and
/// return the form saved in `sync_state`.
///
/// Checks the payload hash over the canonical payload, the contract version,
/// the workspace, freshness, rollback against the saved bundle, that the
/// signing key is anchored to the trusted keyring (or the pinned production
/// key before any keyring is saved), and the RSA-PSS signature.
pub fn verify_network_protection_response(
    response: &Value,
    workspace_id: &str,
    trusted_keys: &[SupplyChainVerificationKey],
    cached_bundle_version: Option<&str>,
    now: Option<f64>,
    verifier: &dyn RsaPssVerify,
) -> BundleResult<Value> {
    let Value::Object(response) = response else {
        return Err(refuse(
            "Network protection bundle response must be an object",
        ));
    };
    let Some(Value::Object(bundle)) = response.get("bundle") else {
        return Err(refuse(
            "Network protection bundle response is missing bundle",
        ));
    };
    if response.get("signatureAlgorithm").and_then(Value::as_str) != Some("rsa-pss-sha256") {
        return Err(refuse(
            "Unsupported network protection bundle signature algorithm",
        ));
    }
    let canonical_payload = canonical_network_protection_payload(bundle);
    let payload_hash = require_string(response, "payloadHash")?;
    if hex::encode(Sha256::digest(&canonical_payload)) != payload_hash {
        return Err(refuse(
            "Network protection bundle payloadHash does not match its payload",
        ));
    }
    if bundle.get("contractVersion").and_then(Value::as_str)
        != Some(NETWORK_PROTECTION_CONTRACT_VERSION)
    {
        return Err(refuse(
            "Unsupported network protection bundle contract version",
        ));
    }
    if bundle.get("workspaceId").and_then(Value::as_str) != Some(workspace_id) {
        return Err(refuse(
            "Network protection bundle belongs to a different workspace",
        ));
    }
    validate_rules(bundle)?;
    require_string_lists(bundle, "threatUrls")?;
    require_string_lists(bundle, "threatHosts")?;
    let bundle_version = require_string(bundle, "bundleVersion")?;
    let version_timestamp = network_bundle_version_timestamp(&bundle_version)?;
    if let Some(cached) = cached_bundle_version {
        // A saved version Guard can no longer parse cannot anchor the check;
        // the fresh bundle is judged on its own merits instead.
        if let Ok(cached_timestamp) = network_bundle_version_timestamp(cached) {
            if version_timestamp < cached_timestamp {
                return Err(refuse(format!(
                    "Network protection bundle {bundle_version} is older than saved {cached}"
                )));
            }
        }
    }
    let current_time = now.unwrap_or_else(now_seconds);
    let generated_at = timestamp(bundle, "generatedAt")?;
    let expires_at = timestamp(bundle, "expiresAt")?;
    if current_time > expires_at + CLOCK_SKEW_SECONDS {
        return Err(refuse("Network protection bundle has expired"));
    }
    if current_time < generated_at - CLOCK_SKEW_SECONDS {
        return Err(refuse(
            "Network protection bundle generatedAt is in the future",
        ));
    }
    if current_time - generated_at > MAX_AGE_SECONDS {
        return Err(refuse("Network protection bundle is too old"));
    }
    let advertised = load_supply_chain_verification_keys(response.get("verificationKeys"))
        .map_err(|error| refuse(error.to_string()))?;
    let key_id = require_string(bundle, "keyId")?;
    let signing_key = advertised
        .iter()
        .find(|item| item.key_id == key_id)
        .ok_or_else(|| {
            refuse("Network protection bundle keyId is not in the advertised keyring")
        })?;
    if signing_key.fingerprint_sha256 != computed_key_fingerprint(signing_key) {
        return Err(refuse(
            "Verification key fingerprint does not match its public key",
        ));
    }
    if !trusted_fingerprints(trusted_keys).contains(&signing_key.fingerprint_sha256) {
        return Err(refuse(
            "Network protection bundle signing key is not trusted",
        ));
    }
    if signing_key.state == "revoked" {
        return Err(refuse(
            "A revoked key cannot sign the network protection bundle",
        ));
    }
    if signing_key.state == "grace" {
        let valid_until = signing_key
            .valid_until_timestamp()
            .map_err(|error| refuse(error.to_string()))?;
        if valid_until.is_some_and(|value| current_time > value) {
            return Err(refuse(
                "The network protection bundle signing key has expired",
            ));
        }
    }
    verify_signature(
        signing_key,
        &require_string(response, "signature")?,
        &canonical_payload,
        verifier,
    )?;
    Ok(json!({
        "bundle": Value::Object(bundle.clone()),
        "expiresAtEpoch": expires_at as i64,
        "payloadHash": payload_hash,
        "keyId": key_id,
    }))
}

#[cfg(test)]
#[path = "network_protection_bundle_tests.rs"]
mod tests;
