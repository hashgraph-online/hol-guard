//! Anchored Review-contract signature kinds of the `PolicyBundleAuthority` op.
//!
//! Guard Review admits a remote approval envelope or a decision-memory bundle
//! only when its signature verifies against a key the workspace has already
//! anchored. That is a verdict about key material, so Rust decides it: Python
//! reads the sync payloads, hands over the anchored keyring and the signed
//! document, and reports whichever code comes back.

use guard_contracts::write_canonical_json_utf8;
use serde_json::{json, Value};

use crate::policy_bundle_crypto::{parse_public_key, verify_pss, SaltMode};
use crate::policy_bundle_keys::{
    key_is_current, keys_to_value, load_keys, resolve_key, safe_load_keys, Key,
};
use crate::policy_bundle_op::{
    field, keys_field, number_field, object_document, optional_text, text_field, Fail, Handled,
};
use crate::policy_bundle_py::{non_empty, Obj};

/// The one algorithm both Review contracts sign with.
const SIGNATURE_ALGORITHM: &str = "rsa-pss-sha256";

/// The purpose a Review verification key must carry.
const REMOTE_APPROVAL_PURPOSE: &str = "remote_approval";

/// Fields that carry the signature or its own digest, and so are not part of
/// the material the signature covers.
const STRIPPED_FIELDS: [&str; 5] = [
    "payloadHash",
    "signature",
    "signatureAlgorithm",
    "verificationKeys",
    "bundleHash",
];

/// `base64.b64decode(value)`: CPython drops characters outside the alphabet and
/// ends the stream on a pad sequence, so a line-wrapped signature still decodes
/// and a short final quad is still an error.
pub(crate) fn lenient_base64_decode(value: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(value.len() / 4 * 3);
    let (mut carried, mut quad_pos, mut pads) = (0u8, 0u8, 0usize);
    for byte in value.bytes() {
        if byte == b'=' {
            pads += 1;
            if quad_pos >= 2 && usize::from(quad_pos) + pads >= 4 {
                return Some(out);
            }
            continue;
        }
        let digit = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => continue,
        };
        pads = 0;
        match quad_pos {
            0 => carried = digit << 2,
            1 => {
                out.push(carried | (digit >> 4));
                carried = (digit & 0x0f) << 4;
            }
            2 => {
                out.push(carried | (digit >> 2));
                carried = (digit & 0x03) << 6;
            }
            _ => out.push(carried | digit),
        }
        quad_pos = (quad_pos + 1) & 3;
    }
    (quad_pos == 0).then_some(out)
}

/// `_verification_keys_from_payload`: each advertised entry is loaded through
/// the same key contract as a stored keyring, so a malformed key is the
/// keyring's own typed failure rather than a Review contract code.
fn advertised_keys(value: Option<&Value>) -> Result<Vec<Key>, Fail> {
    let Some(Value::Array(items)) = value else {
        return Err(Fail::from("missing_verification_keys"));
    };
    if items.is_empty() {
        return Err(Fail::from("missing_verification_keys"));
    }
    let mut parsed = Vec::with_capacity(items.len());
    for item in items {
        if !item.is_object() {
            return Err(Fail::from("invalid_verification_key"));
        }
        let loaded = load_keys(&Value::Array(vec![item.clone()]), false).map_err(Fail::from)?;
        let [key] = loaded.as_slice() else {
            return Err(Fail::from("invalid_policy_bundle_verification_keys"));
        };
        parsed.push(key.clone());
    }
    Ok(parsed)
}

/// `_resolve_anchored_signing_key`: the advertised key names the material, the
/// anchored keyring decides whether it may sign.
fn anchored_signing_key<'a>(
    advertised: &[Key],
    anchored: &'a [Key],
    key_id: &str,
    expected_purpose: Option<&str>,
    expected_workspace: Option<&str>,
    now: f64,
) -> Result<&'a Key, Fail> {
    let Some(signing) = resolve_key(key_id, anchored) else {
        return Err(Fail::from("unknown_signing_key"));
    };
    let Some(advertised) = resolve_key(key_id, advertised) else {
        return Err(Fail::from("missing_signing_key"));
    };
    if advertised.fingerprint != signing.fingerprint {
        return Err(Fail::from("untrusted_signing_key"));
    }
    if let Some(purpose) = expected_purpose {
        if signing.purpose != purpose || advertised.purpose != purpose {
            return Err(Fail::from("signing_key_purpose_mismatch"));
        }
    }
    if let Some(workspace) = expected_workspace {
        let expected = Some(workspace);
        if signing.workspace_id.as_deref() != expected
            || advertised.workspace_id.as_deref() != expected
        {
            return Err(Fail::from("signing_key_workspace_mismatch"));
        }
    }
    if !key_is_current(signing, now, false) {
        return Err(Fail::from("expired_signing_key"));
    }
    Ok(signing)
}

/// The key id the payload names, in the order the contract reads it.
fn advertised_key_id(payload: &Obj) -> Option<&str> {
    non_empty(payload.get("issuerKeyId"))
        .or_else(|| non_empty(payload.get("keyId")))
        .or_else(|| match payload.get("verifier") {
            Some(Value::Object(verifier)) => non_empty(verifier.get("keyId")),
            _ => None,
        })
}

fn signed_material(payload: &Obj) -> Result<Vec<u8>, Fail> {
    let mut covered = payload.clone();
    for name in STRIPPED_FIELDS {
        covered.remove(name);
    }
    let mut bytes = Vec::new();
    write_canonical_json_utf8(&Value::Object(covered), &mut bytes).map_err(|_| Fail::Invalid)?;
    Ok(bytes)
}

fn verify_signed_payload(input: &Obj) -> Handled {
    if text_field(input, "signature_algorithm")? != SIGNATURE_ALGORITHM {
        return Err(Fail::from("invalid_signature_algorithm"));
    }
    let payload = object_document(input, "payload_chunks")?;
    let Some(signature) = non_empty(payload.get("signature")) else {
        return Err(Fail::from("missing_signature"));
    };
    let named = advertised_key_id(&payload);
    let advertised = advertised_keys(payload.get("verificationKeys"))?;
    let key_id = match (named, advertised.as_slice()) {
        (Some(text), _) => text.to_owned(),
        (None, [only]) => only.key_id.clone(),
        (None, _) => return Err(Fail::from("missing_signing_key_id")),
    };
    let anchored = keys_field(input, "anchored_keys")?;
    let signing = anchored_signing_key(
        &advertised,
        &anchored,
        &key_id,
        optional_text(input, "expected_purpose")?,
        optional_text(input, "expected_workspace_id")?,
        number_field(input, "now")?,
    )?;
    let Ok(public_key) = parse_public_key(&signing.public_key_pem) else {
        return Err(Fail::from("invalid_signing_key"));
    };
    let Some(signature_bytes) = lenient_base64_decode(signature) else {
        return Err(Fail::from("invalid_signature"));
    };
    let material = signed_material(&payload)?;
    if !verify_pss(&public_key, &signature_bytes, &material, SaltMode::Auto) {
        return Err(Fail::from("signature_mismatch"));
    }
    Ok(json!({ "verified": true }))
}

/// `validated_review_verification_keys_from_sync`: synced Review keys are
/// admitted only when the workspace already anchors the same material.
fn validate_sync_keys(input: &Obj) -> Handled {
    let raw = field(input, "raw")?;
    let Value::Array(items) = raw else {
        return Err(Fail::from("review_verification_keys_invalid"));
    };
    let keys = safe_load_keys(raw);
    if keys.is_empty() || keys.len() != items.len() {
        return Err(Fail::from("review_verification_keys_invalid"));
    }
    let anchored = keys_field(input, "anchored_keys")?;
    let workspace = text_field(input, "workspace_id")?;
    let now = number_field(input, "now")?;
    for key in &keys {
        if key.purpose != REMOTE_APPROVAL_PURPOSE {
            return Err(Fail::from("signing_key_purpose_mismatch"));
        }
        if key.workspace_id.as_deref() != Some(workspace) {
            return Err(Fail::from("signing_key_workspace_mismatch"));
        }
        if !anchored
            .iter()
            .any(|item| item.fingerprint == key.fingerprint)
        {
            return Err(Fail::from("unknown_signing_key"));
        }
        // A revoked key is never current, so one test covers both readings.
        if !key_is_current(key, now, false) {
            return Err(Fail::from("expired_signing_key"));
        }
    }
    Ok(json!({ "keys": keys_to_value(&keys) }))
}

pub(crate) fn handle(kind: &str, input: &Obj) -> Option<Handled> {
    Some(match kind {
        "verify_signed_review_payload" => verify_signed_payload(input),
        "validate_review_sync_keys" => validate_sync_keys(input),
        _ => return None,
    })
}
