//! Activity is a transient observation, not a grant or completion receipt.

use crate::policy_store::PolicySnapshotStore;
use guard_contracts::{
    NativeBashActivityRequestV1, NativeBashActivityResultV1, NATIVE_BASH_ACTIVITY_REQUEST_SCHEMA,
    NATIVE_BASH_ACTIVITY_RESULT_SCHEMA,
};

pub(crate) fn evaluate(
    request: &NativeBashActivityRequestV1,
    store: &PolicySnapshotStore,
) -> Result<Vec<u8>, String> {
    let request_sha256 = crate::package_authority_op::request_digest_with_limit(request, 16 * 1024)
        .map_err(|_| "native_bash_activity_request_too_large")?;
    store.require_guard_home(&request.guard_home)?;
    let mut result = NativeBashActivityResultV1 {
        schema: NATIVE_BASH_ACTIVITY_RESULT_SCHEMA.into(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: "error".into(),
        code: "native_bash_activity_request_invalid".into(),
        payload: None,
    };
    if request.schema == NATIVE_BASH_ACTIVITY_REQUEST_SCHEMA
        && !request.request_id.is_empty()
        && request.request_id.len() <= 256
        && guard_contracts::native_bash_operation_id_is_valid(&request.operation_id)
    {
        #[cfg(target_os = "macos")]
        match store.bash_launches().activity(&request.operation_id) {
            Ok((active, cancellation_requested)) => {
                result.status = "ok".into();
                result.code = "ok".into();
                result.payload = Some(guard_contracts::NativeBashActivityV1 {
                    operation_id: request.operation_id.clone(),
                    active,
                    cancellation_requested,
                });
            }
            Err(code) => result.code = code,
        }
        #[cfg(not(target_os = "macos"))]
        {
            result.status = "unavailable".into();
            result.code = "bash_execution_binding_unavailable_platform".into();
        }
    }
    crate::encode_response(&result)
}
