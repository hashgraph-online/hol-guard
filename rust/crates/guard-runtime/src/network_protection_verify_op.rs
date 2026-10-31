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

use crate::package_authority_op::request_digest_with_limit;

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
    let trusted = trusted_keys(request.trusted_keys.as_ref())?;
    verify_network_protection_response(
        &request.response,
        &request.workspace_id,
        &trusted,
        request.cached_bundle_version.as_deref(),
        request.now,
        &RingRsaPssVerify,
    )
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
