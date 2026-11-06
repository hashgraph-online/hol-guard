//! Verify pending review without storing consent or launching a program.

use crate::policy_store::PolicySnapshotStore;
use guard_contracts::{
    NativeBashReviewCheckPayloadV1, NativeBashReviewCheckRequestV1, NativeBashReviewCheckResultV1,
    NATIVE_BASH_LAUNCH_MAX_REQUEST_BYTES, NATIVE_BASH_REVIEW_CHECK_RESULT_SCHEMA,
};

pub(crate) fn check(
    request: &NativeBashReviewCheckRequestV1,
    store: &PolicySnapshotStore,
) -> Result<Vec<u8>, String> {
    let request_sha256 = crate::package_authority_op::request_digest_with_limit(
        request,
        NATIVE_BASH_LAUNCH_MAX_REQUEST_BYTES,
    )
    .map_err(|_| "native_bash_review_check_too_large".to_owned())?;
    let verified = verify(request, store);
    let result = NativeBashReviewCheckResultV1 {
        schema: NATIVE_BASH_REVIEW_CHECK_RESULT_SCHEMA.into(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: if verified.is_ok() { "ok" } else { "error" }.into(),
        code: verified.err().unwrap_or("ok").into(),
        payload: if verified.is_ok() {
            Some(NativeBashReviewCheckPayloadV1 {
                approval_request_id: request.approval_request_id.clone(),
                lineage_id: request.descriptor.review_lineage.lineage_id.clone(),
                artifact_hash: request.descriptor.artifact_hash.clone(),
            })
        } else {
            None
        },
    };
    crate::encode_response(&result)
}

#[cfg(target_os = "macos")]
fn verify(
    request: &NativeBashReviewCheckRequestV1,
    store: &PolicySnapshotStore,
) -> Result<(), &'static str> {
    if request.schema != guard_contracts::NATIVE_BASH_REVIEW_CHECK_REQUEST_SCHEMA
        || request.request_id.is_empty()
        || request.request_id.len() > 256
        || request.approval_request_id.is_empty()
        || request.approval_request_id.len() > 256
    {
        return Err("native_bash_review_check_invalid");
    }
    store
        .require_guard_home(&request.guard_home)
        .map_err(|_| "native_bash_review_check_scope_mismatch")?;
    store
        .require_store_path(&request.store_path)
        .map_err(|_| "native_bash_review_check_scope_mismatch")?;
    crate::native_bash_review_descriptor::validate(
        &request.descriptor,
        &request.harness,
        &request.command,
    )?;
    let journal =
        crate::policy_store::policy_store_approval::bash_journal::BashOperationJournal::open(
            store,
            &request.store_path,
            &request.descriptor.review_lineage.operation_id,
            &request.descriptor.artifact_hash,
        )
        .map_err(|_| "native_bash_review_check_store_unavailable")?;
    journal
        .verify_pending_request(
            &request.approval_request_id,
            &request.harness,
            &request.command,
            &request.descriptor,
        )
        .map_err(|_| "native_bash_review_check_unverified")
}

#[cfg(not(target_os = "macos"))]
fn verify(_: &NativeBashReviewCheckRequestV1, _: &PolicySnapshotStore) -> Result<(), &'static str> {
    Err("bash_execution_binding_unavailable_platform")
}
