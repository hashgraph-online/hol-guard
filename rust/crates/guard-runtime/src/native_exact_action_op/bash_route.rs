//! Store-fenced resident operations. Host delivery is a separate capability.

use crate::package_authority_op::request_digest_with_limit;
use crate::policy_store::PolicySnapshotStore;

/// Run by the actual tool's native sink, never by the resident operation table.
pub(crate) fn observe_host_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    use guard_contracts::{
        NativeBashHostRequestV1, NativeBashHostResultV1, NATIVE_BASH_HOST_REQUEST_SCHEMA,
        NATIVE_BASH_HOST_RESULT_SCHEMA,
    };
    if bytes.len() > NATIVE_BASH_LAUNCH_MAX_REQUEST_BYTES {
        return Err("native_bash_request_too_large".into());
    }
    let request: NativeBashHostRequestV1 =
        crate::strict_json::from_value(crate::strict_json::parse(bytes)?)
            .map_err(|_| "native_bash_host_request_invalid".to_owned())?;
    let request_sha256 = request_digest_with_limit(&request, NATIVE_BASH_LAUNCH_MAX_REQUEST_BYTES)
        .map_err(|_| "native_bash_request_too_large".to_owned())?;
    let mut result = NativeBashHostResultV1 {
        schema: NATIVE_BASH_HOST_RESULT_SCHEMA.into(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: "error".into(),
        code: "native_bash_host_request_invalid".into(),
        payload: None,
    };
    if request.schema == NATIVE_BASH_HOST_REQUEST_SCHEMA
        && !request.request_id.is_empty()
        && request.request_id.len() <= 256
        && request.budget_ms > 0
        && request.budget_ms <= NATIVE_BASH_PREPARE_MAX_BUDGET_MS
    {
        #[cfg(target_os = "macos")]
        {
            let deadline =
                std::time::Instant::now() + std::time::Duration::from_millis(request.budget_ms);
            match super::bash_host::observe_current(
                &request.capture,
                deadline,
                &std::sync::atomic::AtomicBool::new(false),
            ) {
                Ok(capture) => {
                    result.status = "ok".into();
                    result.code = "ok".into();
                    result.payload = Some(capture);
                }
                Err(_) => {
                    result.status = "unavailable".into();
                    result.code = "bash_host_observation_unavailable".into();
                }
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            result.status = "unavailable".into();
            result.code = "bash_execution_binding_unavailable_platform".into();
        }
    }
    crate::encode_response(&result)
}
use guard_contracts::{
    NativeBashExecuteRequestV1, NativeBashExecuteResultV1, NativeBashPrepareRequestV1,
    NativeBashPrepareResultV1, NativeBashPreparedV1, NATIVE_BASH_EXECUTE_MAX_TIMEOUT_MS,
    NATIVE_BASH_EXECUTE_REQUEST_SCHEMA, NATIVE_BASH_EXECUTE_RESULT_SCHEMA,
    NATIVE_BASH_LAUNCH_MAX_REQUEST_BYTES, NATIVE_BASH_PREPARE_MAX_BUDGET_MS,
    NATIVE_BASH_PREPARE_REQUEST_SCHEMA, NATIVE_BASH_PREPARE_RESULT_SCHEMA,
};

pub(crate) fn prepare_request(
    request: &NativeBashPrepareRequestV1,
    store: &PolicySnapshotStore,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest_with_limit(request, NATIVE_BASH_LAUNCH_MAX_REQUEST_BYTES)
        .map_err(|_| "native_bash_request_too_large".to_owned())?;
    let result = if request.schema != NATIVE_BASH_PREPARE_REQUEST_SCHEMA
        || request.request_id.is_empty()
        || request.request_id.len() > 256
        || request.budget_ms == 0
        || request.budget_ms > NATIVE_BASH_PREPARE_MAX_BUDGET_MS
        || request.capture.budget_ms == 0
    {
        Err("native_bash_prepare_request_invalid".to_owned())
    } else {
        prepare(request, store)
    };
    let (status, code, payload) = match result {
        Ok(payload) => {
            let value =
                serde_json::to_value(&payload).map_err(|_| "native_bash_response_invalid")?;
            if !crate::native_bash_reply_validation::prepared(&value) {
                return Err("native_bash_response_invalid".into());
            }
            ("ok", "ok".to_owned(), Some(payload))
        }
        Err(code) => (failure_status(&code), code, None),
    };
    crate::encode_response(&NativeBashPrepareResultV1 {
        schema: NATIVE_BASH_PREPARE_RESULT_SCHEMA.into(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.into(),
        code,
        payload,
    })
}

#[cfg(target_os = "macos")]
fn prepare(
    request: &NativeBashPrepareRequestV1,
    store: &PolicySnapshotStore,
) -> Result<NativeBashPreparedV1, String> {
    store.require_guard_home(&request.capture.guard_home)?;
    if !super::bash_grant::context_matches(&request.capture, &request.envelope) {
        return Err("native_bash_context_mismatch".into());
    }
    let fence = store.fence_for_launch(&request.envelope)?;
    let mut capture = request.capture.clone();
    capture.budget_ms = capture.budget_ms.min(request.budget_ms);
    let captured = super::bash_capture::capture_for_launch(&capture, fence.snapshot())?;
    let artifact_hash =
        super::bash_grant::binding(&captured.subject, fence.snapshot()).map_err(str::to_owned)?;
    fence.require_current()?;
    let assessment = captured
        .policy
        .ok_or_else(|| "native_bash_assessment_missing".to_owned())?;
    let review = super::bash_review::review(&assessment, &request.envelope, fence.snapshot())?;
    let dependency_artifact =
        super::bash_dependency_artifact::build(&captured.subject, &capture.harness)
            .map_err(str::to_owned)?;
    Ok(NativeBashPreparedV1 {
        subject: captured.subject,
        dependency_artifact,
        artifact_id: super::bash_grant::ARTIFACT.into(),
        artifact_hash,
        consent_required: !assessment.allows_without_consent(),
        assessment: assessment.decisions,
        review,
    })
}

#[cfg(not(target_os = "macos"))]
fn prepare(
    _: &NativeBashPrepareRequestV1,
    _: &PolicySnapshotStore,
) -> Result<NativeBashPreparedV1, String> {
    Err("bash_execution_binding_unavailable_platform".into())
}

fn failure_status(code: &str) -> &'static str {
    if code == "bash_current_policy_denied" {
        "denied"
    } else if code.starts_with("bash_") {
        "unavailable"
    } else {
        "error"
    }
}

pub(crate) fn execute_request(
    request: &NativeBashExecuteRequestV1,
    store: &PolicySnapshotStore,
    cancellation: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest_with_limit(request, NATIVE_BASH_LAUNCH_MAX_REQUEST_BYTES)
        .map_err(|_| "native_bash_request_too_large".to_owned())?;
    let mut result = NativeBashExecuteResultV1 {
        schema: NATIVE_BASH_EXECUTE_RESULT_SCHEMA.into(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: "error".into(),
        code: "native_bash_execute_request_invalid".into(),
        grant_claimed: false,
        dispatch_acknowledged: false,
        replayed: false,
        operation: None,
        review_lineage: None,
        payload: None,
    };
    if request.schema == NATIVE_BASH_EXECUTE_REQUEST_SCHEMA
        && !request.request_id.is_empty()
        && request.request_id.len() <= 256
        && request.timeout_ms > 0
        && request.timeout_ms <= NATIVE_BASH_EXECUTE_MAX_TIMEOUT_MS
        && request.capture.budget_ms > 0
        && guard_contracts::native_bash_operation_id_is_valid(&request.operation_id)
    {
        execute(request, store, &mut result, cancellation);
    }
    #[cfg(target_os = "macos")]
    if !reply_is_backed(request, store, &result) {
        return Err("native_bash_response_invocation_mismatch".into());
    }
    crate::encode_response(&result)
}

#[cfg(target_os = "macos")]
pub(super) fn reply_is_backed(
    request: &NativeBashExecuteRequestV1,
    store: &PolicySnapshotStore,
    result: &NativeBashExecuteResultV1,
) -> bool {
    let returned = result
        .operation
        .as_ref()
        .map(|value| (&value.operation_id, &value.artifact_hash))
        .or_else(|| {
            result
                .review_lineage
                .as_ref()
                .map(|value| (&value.operation_id, &value.artifact_hash))
        });
    let Some((id, hash)) = returned else {
        return true;
    };
    let Some(call) = request.tool_call_id.as_deref() else {
        return id == &request.operation_id;
    };
    let Ok(project) = std::fs::canonicalize(&request.capture.workspace) else {
        return false;
    };
    let Ok(journal) = crate::policy_store::policy_store_approval::bash_journal::BashOperationJournal::open_for_delivery(
        store, request.authorization.store_path(), &request.operation_id,
    ) else { return false };
    journal
        .reply_invocation_matches(
            &request.capture.harness,
            project.to_str().unwrap_or_default(),
            call,
            id,
            hash,
        )
        .unwrap_or(false)
}

#[cfg(target_os = "macos")]
fn execute(
    request: &NativeBashExecuteRequestV1,
    store: &PolicySnapshotStore,
    result: &mut NativeBashExecuteResultV1,
    cancellation: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
) {
    use std::time::{Duration, Instant};
    let deadline = Instant::now() + Duration::from_millis(request.timeout_ms);
    let cancellation = cancellation
        .unwrap_or_else(|| std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)));
    let registration = match store
        .bash_launches()
        .register_with_cancellation(&request.operation_id, cancellation)
    {
        Ok(registration) => registration,
        Err(reason) => {
            if reason == "native_bash_operation_active"
                && request.tool_call_id.is_some()
                && record_busy_call(request, store).is_err()
            {
                result.code = "native_bash_busy_observation_unavailable".into();
                return;
            }
            result.code = reason;
            return;
        }
    };
    match super::bash_grant::execute_authorized(
        &request.capture,
        &request.envelope,
        store,
        &request.authorization,
        (&request.operation_id, request.tool_call_id.as_deref()),
        deadline,
        &registration.cancelled,
    ) {
        Ok(launch) => {
            result.grant_claimed = launch.grant_claimed;
            result.dispatch_acknowledged = launch.dispatch_acknowledged;
            result.replayed = launch.replayed;
            result.operation = Some(launch.operation);
            if launch.replayed {
                result.status = "recorded".into();
                result.code = if result.operation.as_ref().is_some_and(|operation| {
                    operation.state == guard_contracts::NativeBashOperationStateV1::Completed
                }) {
                    "native_bash_already_completed_output_not_retained"
                } else {
                    "native_bash_operation_in_progress_or_uncertain"
                }
                .into();
                return;
            }
            result.status = if launch.dispatch_acknowledged {
                "ok"
            } else {
                "error"
            }
            .into();
            result.code = if launch.dispatch_acknowledged {
                "ok"
            } else {
                "native_bash_launch_not_dispatched"
            }
            .into();
            let Some(output) = launch.output else {
                return;
            };
            result.payload = Some(guard_contracts::NativeBashCompletedV1 {
                exit_code: output.exit_code,
                stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
                output_limited: output.output_limited,
                timed_out: output.timed_out,
                cancelled: output.cancelled,
            });
        }
        Err(failure) => {
            result.review_lineage = failure.review_lineage.map(|lineage| *lineage);
            result.grant_claimed = failure.grant_claimed;
            result.dispatch_acknowledged = failure.dispatch_acknowledged;
            result.operation = failure.operation.map(|operation| *operation);
            result.code = if let Some(code) = failure.code {
                code
            } else if failure.grant_claimed {
                "native_bash_launch_failed_after_claim"
            } else if failure.dispatch_acknowledged || result.operation.is_some() {
                "native_bash_launch_failed_after_authorization"
            } else {
                match failure.error.kind() {
                    std::io::ErrorKind::TimedOut => "native_bash_launch_deadline_exceeded",
                    std::io::ErrorKind::Interrupted => "native_bash_launch_cancelled",
                    std::io::ErrorKind::PermissionDenied => "native_bash_launch_not_authorized",
                    _ => "native_bash_launch_unavailable",
                }
            }
            .into();
        }
    }
}

#[cfg(target_os = "macos")]
fn record_busy_call(
    request: &NativeBashExecuteRequestV1,
    store: &PolicySnapshotStore,
) -> Result<(), String> {
    let fence = store.fence_for_launch(&request.envelope)?;
    let captured = super::bash_capture::capture_for_launch(&request.capture, fence.snapshot())?;
    let hash =
        super::bash_grant::binding(&captured.subject, fence.snapshot()).map_err(str::to_owned)?;
    fence.require_current()?;
    let project = std::fs::canonicalize(&request.capture.workspace)
        .map_err(|_| "native_bash_busy_project_unavailable")?;
    let journal =
        crate::policy_store::policy_store_approval::bash_journal::BashOperationJournal::open(
            store,
            request.authorization.store_path(),
            &request.operation_id,
            &hash,
        )?;
    journal
        .record_busy_call(
            &request.capture.harness,
            project
                .to_str()
                .ok_or("native_bash_busy_project_unavailable")?,
            request
                .tool_call_id
                .as_deref()
                .ok_or("native_bash_busy_call_unavailable")?,
        )
        .map_err(|_| "native_bash_busy_observation_unavailable".into())
}

#[cfg(not(target_os = "macos"))]
fn execute(
    _: &NativeBashExecuteRequestV1,
    _: &PolicySnapshotStore,
    result: &mut NativeBashExecuteResultV1,
    _: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
) {
    result.status = "unavailable".into();
    result.code = "bash_execution_binding_unavailable_platform".into();
}
