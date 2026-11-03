//! Check one signed network protection bundle response for a caller that
//! holds no verifier.
//!
//! [`guard_command::network_protection_bundle`] owns the decision. This
//! operation only reads the caller's response and saved keyring onto that
//! module's types and reports what it answered, so the only network
//! protection bundle verifier in the product is the one here. On success it
//! returns the saved form without the bundle object itself, because the
//! caller must not rebuild the rest of it: the expiry epoch, payload hash
//! and key id it writes are the verifier's own.

use guard_command::network_protection_bundle::{
    verify_network_protection_response, NetworkProtectionBundleError,
};
use guard_command::supply_chain_bundle::{
    load_supply_chain_verification_keys, RingRsaPssVerify, SupplyChainVerificationKey,
};
use guard_contracts::{
    NetworkProtectionVerifyRequestV1, NetworkProtectionVerifyResultV1, MAX_NATIVE_REQUEST_BYTES,
    NETWORK_PROTECTION_VERIFY_RESULT_SCHEMA,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::borrow::Cow;

use crate::package_authority_op::request_digest_with_limit;

/// Per-collection cap for a response sent as `response_json`. The request
/// frame's own cap of 4,096 refuses real bundles, whose threat feeds hold
/// tens of thousands of entries; the field's string bound keeps the document
/// itself at a few megabytes.
const MAX_RESPONSE_JSON_COLLECTION_ITEMS: usize = 262_144;

/// Largest response file the resident reads. A production bundle is a few
/// megabytes today; this leaves room for its feeds to grow many times over.
const MAX_RESPONSE_FILE_BYTES: usize = 64 * 1024 * 1024;

/// Per-collection cap for a response read from a file, scaled with
/// [`MAX_RESPONSE_FILE_BYTES`] as the text cap is with its string bound.
const MAX_RESPONSE_FILE_COLLECTION_ITEMS: usize = 2_097_152;

pub(crate) fn evaluate_network_protection_verify_request(
    request: &NetworkProtectionVerifyRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest_with_limit(request, MAX_NATIVE_REQUEST_BYTES)
        .map_err(|_| "native_network_protection_verify_too_large".to_owned())?;

    let payload = match verify(request) {
        Ok(saved) => json!({ "outcome": "verified", "saved": without_bundle(saved) }),
        Err(error) => json!({ "outcome": "refused", "message": error.to_string() }),
    };

    crate::encode_response(&NetworkProtectionVerifyResultV1 {
        schema: NETWORK_PROTECTION_VERIFY_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: "ok".to_owned(),
        code: "ok".to_owned(),
        payload,
    })
}

/// Drop the bundle object from the verified form before it goes back.
///
/// A request may carry a response of up to [`MAX_NATIVE_REQUEST_BYTES`], while
/// a reply is held to a third of that, and the bundle is nearly the whole of
/// the response. Echoing it would make every large bundle answer
/// `native_response_too_large`, which reads as an unreachable verifier and
/// leaves the workspace on its stale bundle. The caller still holds the object
/// it sent, and `payloadHash` in the reply is this verifier's own hash over
/// exactly that object, so naming the bundle is enough; rebuilding it is not
/// a second decision.
fn without_bundle(mut saved: Value) -> Value {
    if let Some(map) = saved.as_object_mut() {
        map.remove("bundle");
    }
    saved
}

fn verify(
    request: &NetworkProtectionVerifyRequestV1,
) -> Result<Value, NetworkProtectionBundleError> {
    let response = response(request)?;
    let trusted = trusted_keys(request.trusted_keys.as_ref())?;
    verify_network_protection_response(
        &response,
        &request.workspace_id,
        &trusted,
        request.cached_bundle_version.as_deref(),
        request.now,
        &RingRsaPssVerify,
    )
}

/// The response the caller sent, from whichever field carries it.
///
/// A request that fills more than one is refused rather than resolved by
/// preference: they could differ, and the reply must speak to the one
/// response the caller saves.
fn response(
    request: &NetworkProtectionVerifyRequestV1,
) -> Result<Cow<'_, Value>, NetworkProtectionBundleError> {
    let sources = usize::from(!request.response.is_null())
        + usize::from(request.response_json.is_some())
        + usize::from(request.response_path.is_some());
    if sources > 1 {
        return Err(refusal(
            "Network protection bundle request carries the response twice",
        ));
    }
    if request.response_sha256.is_some() && request.response_path.is_none() {
        return Err(refusal(
            "Network protection bundle request names a digest without a file",
        ));
    }
    if let Some(path) = request.response_path.as_deref() {
        let bytes = read_response_file(path, request.response_sha256.as_deref())?;
        return parse_response(&bytes, MAX_RESPONSE_FILE_COLLECTION_ITEMS).map(Cow::Owned);
    }
    match request.response_json.as_deref() {
        Some(text) => {
            parse_response(text.as_bytes(), MAX_RESPONSE_JSON_COLLECTION_ITEMS).map(Cow::Owned)
        }
        None => Ok(Cow::Borrowed(&request.response)),
    }
}

/// Read the response file the caller wrote and hold it to the digest the
/// request carries.
///
/// The file is evidence, not authority: the verifier still checks the bundle
/// inside it end to end. The digest is what ties it to this request, whose
/// hash the reply is bound to, so a file that changed after the caller wrote
/// it is refused rather than verified in its new form. The shared stable
/// reader refuses links and anything but a regular file before it opens it,
/// so a FIFO swapped in for the file cannot stall the resident.
fn read_response_file(
    path: &str,
    expected: Option<&str>,
) -> Result<Vec<u8>, NetworkProtectionBundleError> {
    let Some(expected) = expected else {
        return Err(refusal(
            "Network protection bundle response file has no digest",
        ));
    };
    let bytes = match guard_secure_fs::read_stable(
        std::path::Path::new(path),
        MAX_RESPONSE_FILE_BYTES,
        false,
    ) {
        Ok(read) => read.bytes,
        Err(guard_secure_fs::SecureReadError::TooLarge) => {
            return Err(refusal(
                "Network protection bundle response file is too large",
            ))
        }
        Err(_) => {
            return Err(refusal(
                "Network protection bundle response file is unreadable",
            ))
        }
    };
    let actual = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
    if actual != expected {
        return Err(refusal(
            "Network protection bundle response file does not match its digest",
        ));
    }
    Ok(bytes)
}

fn parse_response(
    bytes: &[u8],
    collection_items: usize,
) -> Result<Value, NetworkProtectionBundleError> {
    crate::strict_json::parse_with_collection_limit(bytes, collection_items)
        .map_err(|_| refusal("Network protection bundle response is not valid JSON"))
}

fn refusal(message: &str) -> NetworkProtectionBundleError {
    NetworkProtectionBundleError(message.to_owned())
}

/// A keyring the resident cannot read is not an empty keyring, so a malformed
/// one refuses the bundle rather than silently falling back to the pinned
/// fingerprint, as the Python caller did when its keyring failed to load.
///
/// The shared loader answers an empty keyring for anything that is not a list
/// of entries, because a supply-chain caller that has saved nothing reaches it
/// the same way. Here an empty keyring is not neutral: it restores the pinned
/// production fingerprint as the only anchor, so a saved row that is present
/// but unreadable would quietly widen trust. Only an absent row may be empty.
fn trusted_keys(
    raw: Option<&Value>,
) -> Result<Vec<SupplyChainVerificationKey>, NetworkProtectionBundleError> {
    let readable = match raw {
        None | Some(Value::Null) => true,
        Some(Value::Array(_)) => true,
        Some(Value::Object(map)) => matches!(map.get("keys"), Some(Value::Array(_))),
        Some(_) => false,
    };
    if !readable {
        return Err(NetworkProtectionBundleError(
            "Saved network protection keyring is malformed".to_owned(),
        ));
    }
    load_supply_chain_verification_keys(raw)
        .map_err(|error| NetworkProtectionBundleError(error.to_string()))
}

#[cfg(test)]
#[path = "network_protection_verify_op_tests.rs"]
mod tests;
