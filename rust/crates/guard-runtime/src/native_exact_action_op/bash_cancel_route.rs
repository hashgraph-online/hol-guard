//! Cancellation signals active execution; it never mints or refunds consent.
use guard_contracts::{
    NativeBashCancelRequestV1, NativeBashCancelResultV1, NATIVE_BASH_CANCEL_REQUEST_SCHEMA,
    NATIVE_BASH_CANCEL_RESULT_SCHEMA,
};

use crate::package_authority_op::request_digest_with_limit;
use crate::policy_store::PolicySnapshotStore;

pub(crate) fn cancel_request(
    request: &NativeBashCancelRequestV1,
    store: &PolicySnapshotStore,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest_with_limit(request, 16 * 1024)
        .map_err(|_| "native_bash_cancel_request_too_large")?;
    store.require_guard_home(&request.guard_home)?;
    let mut result = NativeBashCancelResultV1 {
        schema: NATIVE_BASH_CANCEL_RESULT_SCHEMA.into(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: "error".into(),
        code: "native_bash_cancel_request_invalid".into(),
        cancel_requested: false,
    };
    if request.schema == NATIVE_BASH_CANCEL_REQUEST_SCHEMA
        && !request.request_id.is_empty()
        && request.request_id.len() <= 256
        && guard_contracts::native_bash_operation_id_is_valid(&request.operation_id)
    {
        #[cfg(target_os = "macos")]
        {
            match store.bash_launches().cancel(&request.operation_id) {
                Ok(signalled) => {
                    result.cancel_requested = signalled;
                    result.status = "ok".into();
                    result.code = if signalled {
                        "native_bash_cancellation_requested"
                    } else {
                        "native_bash_operation_not_running"
                    }
                    .into();
                }
                Err(reason) => result.code = reason,
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
