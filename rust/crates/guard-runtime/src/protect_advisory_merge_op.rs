//! `ProtectAdvisoryMerge` — resident op that folds a cached-advisory verdict
//! into a package protect result through
//! `guard_command::protect_request::merge_cached_advisory`.
//!
//! Pure: the caller persists the receipt update and event the op returns.

use guard_command::protect_request::{merge_cached_advisory, CachedAdvisoryVerdict};
use guard_contracts::{
    ProtectAdvisoryMergeRequestV1, ProtectAdvisoryMergeResultV1, ProtectAdvisoryMergeV1,
    ProtectInstallEventV1, ProtectReceiptPolicyUpdateV1, MAX_NATIVE_REQUEST_BYTES,
    PROTECT_ADVISORY_MERGE_MAX_REQUEST_BYTES, PROTECT_ADVISORY_MERGE_REQUEST_SCHEMA,
    PROTECT_ADVISORY_MERGE_RESULT_SCHEMA,
};
use serde_json::Value;

const TOO_LARGE: &str = "native_protect_advisory_merge_too_large";
const INVALID: &str = "native_protect_advisory_merge_payload_invalid";

pub(crate) fn evaluate_protect_advisory_merge_op(
    request: &ProtectAdvisoryMergeRequestV1,
) -> Result<Vec<u8>, String> {
    // Digest within the frame limit so an over-bound request still gets a
    // typed refusal bound to it rather than an untyped transport error.
    let material = serde_json::to_value(request).map_err(|_| INVALID.to_owned())?;
    let mut canonical = Vec::new();
    crate::context_digest_json::write_canonical_json_with_limit(
        &material,
        &mut canonical,
        MAX_NATIVE_REQUEST_BYTES,
    )
    .map_err(|_| TOO_LARGE.to_owned())?;
    let oversized = canonical.len() > PROTECT_ADVISORY_MERGE_MAX_REQUEST_BYTES;
    let request_sha256 = format!("sha256:{}", guard_policy_snapshot::digest_bytes(&canonical));
    let result =
        |code: &str, merged: Option<ProtectAdvisoryMergeV1>| ProtectAdvisoryMergeResultV1 {
            schema: PROTECT_ADVISORY_MERGE_RESULT_SCHEMA.to_owned(),
            request_id: request.request_id.clone(),
            request_sha256: request_sha256.clone(),
            status: if code == "ok" { "ok" } else { "error" }.to_owned(),
            code: code.to_owned(),
            merged,
        };
    if oversized {
        return crate::encode_response(&result(TOO_LARGE, None));
    }
    let outcome = match evaluate(request) {
        Ok(merged) => result("ok", merged),
        Err(code) => result(code, None),
    };
    // The merged payload echoes the request's payload; a payload near the
    // request limit can outgrow the response limit. That is a typed refusal,
    // not an untyped transport error.
    match crate::encode_response(&outcome) {
        Err(reason) if reason == "native_response_too_large" && outcome.status == "ok" => {
            crate::encode_response(&result(TOO_LARGE, None))
        }
        encoded => encoded,
    }
}

fn evaluate(
    request: &ProtectAdvisoryMergeRequestV1,
) -> Result<Option<ProtectAdvisoryMergeV1>, &'static str> {
    if request.schema != PROTECT_ADVISORY_MERGE_REQUEST_SCHEMA {
        return Err("native_protect_advisory_merge_schema_mismatch");
    }
    let Value::Object(payload) = &request.payload else {
        return Err("native_protect_advisory_merge_payload_invalid");
    };
    if !matches!(request.cached.action.as_str(), "allow" | "review" | "block") {
        return Err("native_protect_advisory_merge_cached_invalid");
    }
    let cached = CachedAdvisoryVerdict {
        action: &request.cached.action,
        reason: &request.cached.reason,
        risk_signals: &request.cached.risk_signals,
        matched_advisories: &request.cached.matched_advisories,
    };
    let merged = merge_cached_advisory(
        payload,
        &cached,
        request.requested_dry_run,
        request.exit_code,
    )
    .map_err(|_| "native_protect_advisory_merge_payload_invalid")?;
    Ok(merged.map(|merged| ProtectAdvisoryMergeV1 {
        payload: Value::Object(merged.payload),
        exit_code: merged.exit_code,
        receipt_policy_update: merged
            .receipt_policy_update
            .map(|(receipt_id, action)| ProtectReceiptPolicyUpdateV1 { receipt_id, action }),
        event: merged
            .event
            .map(|(name, fields)| ProtectInstallEventV1 { name, fields }),
    }))
}

#[cfg(test)]
#[path = "protect_advisory_merge_op_tests.rs"]
mod tests;
