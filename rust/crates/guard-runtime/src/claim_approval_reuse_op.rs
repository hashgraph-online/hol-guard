//! `ClaimApprovalReuseDecisions` — resident op that claims a batch of
//! prevalidated policy/local-once reuse decisions under one SQLite
//! `BEGIN IMMEDIATE` transaction.
//!
//! IO op (unlike `ApprovalReuseDecide`): opens `store_path` and calls
//! `claim_reuse::claim_approval_reuse_decisions`. The integrity evidence
//! (refreshed state, key material, bundle identities) is shipped by the caller.

use guard_contracts::{
    ClaimApprovalReuseDecisionsRequestV1, ClaimApprovalReuseDecisionsResultV1,
    CLAIM_APPROVAL_REUSE_REQUEST_SCHEMA, CLAIM_APPROVAL_REUSE_RESULT_SCHEMA,
};
use guard_policy_snapshot::digest_bytes;
use serde_json::Value;

use super::context_digest_json::write_canonical_json_with_limit;

fn request_digest(request: &ClaimApprovalReuseDecisionsRequestV1) -> Result<String, &'static str> {
    let material =
        serde_json::to_value(request).map_err(|_| "native_claim_approval_reuse_invalid")?;
    let mut bytes = Vec::new();
    write_canonical_json_with_limit(&material, &mut bytes, usize::MAX)
        .map_err(|_| "native_claim_approval_reuse_invalid")?;
    Ok(format!("sha256:{}", digest_bytes(&bytes)))
}

pub(crate) fn evaluate_claim_approval_reuse_request(
    request: &ClaimApprovalReuseDecisionsRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request).map_err(str::to_owned)?;
    let result = evaluate(request);
    let (status, code, payload) = match result {
        Ok(payload) => ("ok".to_owned(), "ok".to_owned(), Some(payload)),
        Err(code) => ("error".to_owned(), code, None),
    };
    let result = ClaimApprovalReuseDecisionsResultV1 {
        schema: CLAIM_APPROVAL_REUSE_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status,
        code,
        payload,
    };
    crate::encode_response(&result)
}

fn decode_key(encoded: Option<&str>) -> Option<Vec<u8>> {
    use base64ct::{Base64UrlUnpadded, Encoding};
    Base64UrlUnpadded::decode_vec(encoded?).ok()
}

fn evaluate(request: &ClaimApprovalReuseDecisionsRequestV1) -> Result<Value, String> {
    if request.schema != CLAIM_APPROVAL_REUSE_REQUEST_SCHEMA {
        return Err("native_claim_approval_reuse_schema_mismatch".to_owned());
    }
    let now = guard_contracts::canonical_utc_timestamp(&request.now)
        .ok_or_else(|| "native_claim_approval_reuse_invalid".to_owned())?;
    let connection = rusqlite::Connection::open_with_flags(
        &request.store_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
    )
    .map_err(|_| "native_claim_approval_reuse_store_unavailable".to_owned())?;
    connection
        .busy_timeout(std::time::Duration::from_millis(5000))
        .map_err(|_| "native_claim_approval_reuse_store_unavailable".to_owned())?;
    let integrity_key = decode_key(request.integrity_key_b64.as_deref());
    let local_once_key = decode_key(request.local_once_integrity_key_b64.as_deref());
    let evidence = crate::claim_reuse::ClaimEvidence {
        integrity_state: request.integrity_state.as_ref(),
        integrity_key: integrity_key.as_deref(),
        integrity_key_id: request.integrity_key_id.as_deref(),
        local_once_key: local_once_key.as_deref(),
        local_once_key_id: request.local_once_integrity_key_id.as_deref(),
        policy_bundle_identities: request.policy_bundle_decision_identities.as_deref(),
    };
    let claimed = crate::claim_reuse::claim_approval_reuse_decisions(
        &connection,
        &request.decisions,
        &now,
        &evidence,
    )
    .map_err(|_| "native_claim_approval_reuse_store_error".to_owned())?;
    Ok(serde_json::json!({ "claimed": claimed }))
}
