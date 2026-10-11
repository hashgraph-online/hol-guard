//! `RunnerAuthority` — resident op owning the `guard run` authority
//! transforms (see `guard_contracts::runner_authority`).
//!
//! Pure (no IO): every kind is a deterministic function of its arguments and
//! reuses the same authoritative-decision, action-lattice and approval-token
//! code the rest of the resident runs, so there is one rule set. Python ships
//! typed inputs, applies the returned patch and never recomputes an action,
//! reason or signature. Failures are typed `error` results; the caller must
//! treat them as a refusal to launch, never as an allow.

use guard_contracts::{
    RunnerAuthorityRequestV1, RunnerAuthorityResultV1, RUNNER_AUTHORITY_MAX_BYTES,
    RUNNER_AUTHORITY_REQUEST_SCHEMA, RUNNER_AUTHORITY_RESULT_SCHEMA,
};
use guard_policy_snapshot::digest_bytes;
use serde_json::Value;

use super::context_digest_json::write_canonical_json_with_limit;
use super::oci_bundle_op as oci;
use super::runner_authority_signature as signature;
use super::{
    cloud_receipt_payload as receipt, cloud_request_snapshot as snapshot,
    cloud_sync_privacy as privacy,
};
use super::{runner_authority_detector as detector, runner_authority_evaluation as evaluation};
use super::{
    runner_sync_policy as policy, runner_sync_signals as signals, runner_sync_url as sync_url,
};

pub(crate) const ERR_INVALID: &str = "native_runner_authority_invalid";
const ERR_SCHEMA: &str = "native_runner_authority_schema_mismatch";
const ERR_TOO_LARGE: &str = "native_runner_authority_request_too_large";
const ERR_RESPONSE_TOO_LARGE: &str = "native_runner_authority_response_too_large";
const ERR_KIND: &str = "native_runner_authority_unknown_kind";

/// Result of one kind: its payload, or a stable failure code.
pub(crate) type KindResult = Result<Value, &'static str>;

/// Digest of the canonical request, matching Python `_canonical_request_sha256`.
fn request_digest(request: &RunnerAuthorityRequestV1) -> Result<String, &'static str> {
    let material = serde_json::to_value(request).map_err(|_| ERR_INVALID)?;
    let mut canonical = Vec::with_capacity(4096);
    if write_canonical_json_with_limit(&material, &mut canonical, RUNNER_AUTHORITY_MAX_BYTES)
        .is_err()
    {
        return Err(if canonical.len() > RUNNER_AUTHORITY_MAX_BYTES {
            ERR_TOO_LARGE
        } else {
            ERR_INVALID
        });
    }
    if canonical.len() > RUNNER_AUTHORITY_MAX_BYTES {
        return Err(ERR_TOO_LARGE);
    }
    Ok(digest_bytes(&canonical))
}

pub(crate) fn dispatch(kind: &str, args: &Value) -> KindResult {
    match kind {
        "detector_authority" => detector::detector_authority(args),
        "detector_composition" => detector::detector_composition(args),
        "current_authority_actions" => detector::current_authority_actions(args),
        "request_overrides" => detector::request_overrides(args),
        "claim_partition" => detector::claim_partition(args),
        "apply_detector_result" => evaluation::apply_detector_result(args),
        "preclaim_failure" => evaluation::preclaim_failure(args),
        "claim_context_failure" => evaluation::claim_context_failure(args),
        "receipt_evidence_merge" => evaluation::receipt_evidence_merge(args),
        "authority_signature" => signature::authority_signature(args),
        "authority_gate" => signature::authority_gate(args),
        "policy_shadow_mismatch" => signature::policy_shadow_mismatch(args),
        "sync_url" => sync_url::sync_url(args),
        "pain_signal_batch" => signals::pain_signal_batch(args),
        "value_metrics" => signals::value_metrics(args),
        "completed_event_ids" => signals::completed_event_ids(args),
        "canonical_rollout" => policy::canonical_rollout(args),
        "downgrade_reference" => policy::downgrade_reference(args),
        "policy_simulation" => policy::policy_simulation(args),
        "cloud_scrub_texts" => privacy::cloud_scrub_texts(args),
        "cloud_review_event_display" => privacy::cloud_review_event_display(args),
        "cloud_sync_receipt_payloads" => receipt::cloud_sync_receipt_payloads(args),
        "cloud_request_payload" => snapshot::cloud_request_payload(args),
        "local_request_snapshot" => snapshot::local_request_snapshot(args),
        "local_request_snapshot_items" => snapshot::local_request_snapshot_items(args),
        "oci_bundle_evidence" => oci::oci_bundle_evidence(args),
        "oci_evidence_verdict" => oci::oci_evidence_verdict(args),
        "oci_bundle_digest" => oci::oci_bundle_digest(args),
        "oci_bundle_plan" => oci::oci_bundle_plan(args),
        _ => Err(ERR_KIND),
    }
}

fn evaluate(request: &RunnerAuthorityRequestV1) -> KindResult {
    if request.schema != RUNNER_AUTHORITY_REQUEST_SCHEMA {
        return Err(ERR_SCHEMA);
    }
    if request.guard_home.is_empty() {
        return Err(ERR_INVALID);
    }
    dispatch(&request.kind, &request.args)
}

pub(crate) fn evaluate_runner_authority(
    request: &RunnerAuthorityRequestV1,
) -> Result<Vec<u8>, String> {
    // Digest/size failures are this op's own typed error result, not a
    // transport error (which the resident would redact to invalid-json).
    let request_sha256 = match request_digest(request) {
        Ok(digest) => digest,
        Err(code) => {
            return crate::encode_response(&RunnerAuthorityResultV1 {
                schema: RUNNER_AUTHORITY_RESULT_SCHEMA.to_owned(),
                request_id: request.request_id.clone(),
                request_sha256: String::new(),
                status: "error".to_owned(),
                code: code.to_owned(),
                payload: None,
            });
        }
    };
    let (status, code, payload) = match evaluate(request) {
        Ok(payload) => ("ok".to_owned(), "ok".to_owned(), Some(payload)),
        Err(code) => ("error".to_owned(), code.to_owned(), None),
    };
    let encoded = crate::encode_response(&RunnerAuthorityResultV1 {
        schema: RUNNER_AUTHORITY_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256: request_sha256.clone(),
        status,
        code,
        payload,
    });
    // The request bound (4 MiB) is wider than the resident response bound
    // (2 MiB). A result past that bound is this op's own typed refusal, never
    // a bare transport error and never a partial answer.
    match encoded {
        Err(reason) if reason == "native_response_too_large" => {
            crate::encode_response(&RunnerAuthorityResultV1 {
                schema: RUNNER_AUTHORITY_RESULT_SCHEMA.to_owned(),
                request_id: request.request_id.clone(),
                request_sha256,
                status: "error".to_owned(),
                code: ERR_RESPONSE_TOO_LARGE.to_owned(),
                payload: None,
            })
        }
        other => other,
    }
}

#[cfg(test)]
#[path = "runner_authority_op_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "runner_sync_tests.rs"]
mod sync_tests;
