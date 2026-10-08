#![forbid(unsafe_code)]

//! Authenticate aggregate origin evidence without retaining raw tool input.
//! This evidence is not an allow decision, retry capability, or execution grant.

use guard_contracts::NativeHookDecisionReceiptV1;
use guard_policy_snapshot::canonical_json_bytes;

use super::PolicySnapshotStore;

const ORIGIN_DOMAIN: &[u8] = b"hol-guard.native-review-origin.v1\0";
const INVALID_ORIGIN: &str = "native_workspace_review_origin_invalid";

fn authenticated_bytes(receipt: &NativeHookDecisionReceiptV1) -> Result<Vec<u8>, String> {
    let mut value = serde_json::to_value(receipt).map_err(|_| INVALID_ORIGIN.to_owned())?;
    value
        .as_object_mut()
        .ok_or_else(|| INVALID_ORIGIN.to_owned())?
        .remove("origin_authentication");
    canonical_json_bytes(&value).map_err(|_| INVALID_ORIGIN.to_owned())
}

fn authenticate_with_key(
    receipt: &mut NativeHookDecisionReceiptV1,
    key: &[u8; 32],
) -> Result<(), String> {
    let bytes = authenticated_bytes(receipt)?;
    receipt.origin_authentication =
        Some(hex::encode(crate::hmac_sha256(key, ORIGIN_DOMAIN, &bytes)));
    Ok(())
}

fn verify_with_key(receipt: &NativeHookDecisionReceiptV1, key: &[u8; 32]) -> Result<(), String> {
    let proof = receipt
        .origin_authentication
        .as_deref()
        .filter(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or_else(|| INVALID_ORIGIN.to_owned())?;
    let decoded = hex::decode(proof).map_err(|_| INVALID_ORIGIN.to_owned())?;
    let expected = crate::hmac_sha256(key, ORIGIN_DOMAIN, &authenticated_bytes(receipt)?);
    if !crate::constant_time_eq(&decoded, &expected) {
        return Err(INVALID_ORIGIN.to_owned());
    }
    Ok(())
}

pub(crate) fn authenticate(
    store: &PolicySnapshotStore,
    receipt: &mut NativeHookDecisionReceiptV1,
) -> Result<(), String> {
    authenticate_with_key(receipt, &store.verifier_key)
}

pub(crate) fn verify(
    store: &PolicySnapshotStore,
    receipt: &NativeHookDecisionReceiptV1,
) -> Result<(), String> {
    verify_with_key(receipt, &store.verifier_key)
}

#[cfg(test)]
#[path = "native_review_origin_tests.rs"]
mod tests;
